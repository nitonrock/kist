"""Scoped read APIs and bounded caches; async SQL is native, crypto is offloaded."""
from __future__ import annotations

import asyncio
import math
import threading
import time
import uuid
from concurrent.futures import Future
from typing import Any

import psycopg

from kist.core import (
    ENVELOPE_VERSION,
    KEY_MODE_PASSWORD,
    SCHEMA_VERSION,
    DecryptionError,
    InvalidEnvelopeError,
    Kist,
    KistError,
    SchemaVersionError,
    _KeyBundle,
    _validate_secret_key,
    decrypt_envelope,
    safe_async_db_connect,
    safe_db_connect,
)

_MISSING = object()
_SELECT_MANY_SQL = """
    SELECT id, lookup_token, key_bundle_id, crypto_version,
           secret_version, encrypted_blob
    FROM kist_secrets
    WHERE profile_id = %s AND lookup_token = ANY(%s::bytea[])
"""
_BUNDLE_SQL = """SELECT id, access_mode, bundle_version, wrapped_bundle, wrapper_revision
    FROM kist_key_bundles WHERE profile_id = %s"""


def _names(keys):
    if isinstance(keys, (str, bytes)):
        raise TypeError("keys must be an iterable of names, not a string.")
    return list(dict.fromkeys(_validate_secret_key(key) for key in keys))


def _finish(names, values, default):
    result = {}
    for key in names:
        if key in values:
            result[key] = values[key]
        elif default is ...:
            raise KeyError(key)
        else:
            result[key] = default
    return result


def _decode_rows(reader, bundle, tokens, rows):
    values = {}
    for row in rows:
        token = bytes(row[1])
        if token not in tokens:
            raise DecryptionError("Unexpected lookup token in bulk result.")
        key, value = reader._decode_row(bundle, row, tokens[token])
        if key in values:
            raise DecryptionError("Duplicate decrypted secret names.")
        values[key] = value
    return values


def _unlock(reader, row):
    bundle_id, mode, version, blob = row[:4]
    if mode != KEY_MODE_PASSWORD or version != 1:
        raise InvalidEnvelopeError("Unsupported key access mode or bundle version.")
    blob = bytes(blob)
    if len(blob) < 5 or blob[4] != ENVELOPE_VERSION:
        raise InvalidEnvelopeError("Database key bundles require envelope v1.")
    bundle_id = uuid.UUID(str(bundle_id))
    raw = decrypt_envelope(blob, reader._require_password(), reader._bundle_context(bundle_id))
    if len(raw) != 68 or not raw.startswith(b"KKB1"):
        raise DecryptionError("Invalid key bundle payload.")
    return _KeyBundle(bundle_id, raw[4:36], raw[36:68])


def _identity(reader, row):
    return (reader.db_url, reader.scope, reader.profile_name, reader.organization_id,
            reader.project_id, reader.profile_id, reader.password, str(row[0]),
            row[1], row[2], bytes(row[3]), row[4])


def _ttl(value):
    if isinstance(value, bool):
        raise ValueError("TTL must be finite and positive.")
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise ValueError("TTL must be finite and positive.")
    return value


def get_many(reader, keys, default=...):
    names = _names(keys)
    if not names:
        return {}
    reader._ensure_scope()
    values = {}
    with safe_db_connect(reader._require_database()) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            reader._check_schema(cursor)
            bundle = reader._load_bundle(cursor)
            if bundle is not None:
                tokens = {reader._lookup_token(bundle, key): key for key in names}
                cursor.execute(
                    _SELECT_MANY_SQL,
                    (reader.profile_id, list(tokens)),
                )
                values = _decode_rows(reader, bundle, tokens, cursor.fetchall())
    return _finish(names, values, default)


class _SessionReader(Kist):
    def _load_bundle(self, cursor, *, create=False):
        if create:
            raise KistError("Read sessions cannot create key bundles.")
        cursor.execute(_BUNDLE_SQL, (self.profile_id,))
        row = cursor.fetchone()
        identity = None if row is None else _identity(self, row)
        if (identity is not None and self._cached is not None
                and identity == self._identity and time.monotonic() < self._expires):
            return self._cached
        self._cached = self._identity = None
        self._expires = 0.0
        if row is None:
            return None
        bundle = _unlock(self, row)
        self._cached, self._identity = bundle, identity
        self._expires = time.monotonic() + self._ttl
        return bundle


def _copy_reader(source, cls=Kist):
    reader = cls(profile_name=source.profile_name, password=source.password,
                 db_url=source.db_url, scope=source.scope)
    reader.organization_id = source.organization_id
    reader.project_id = source.project_id
    reader.profile_id = source.profile_id
    return reader


class ReadSession:
    def __init__(self, source, unlock_ttl_seconds=30):
        self._ttl = _ttl(unlock_ttl_seconds)
        self._reader = _copy_reader(source, _SessionReader)
        self._reader._ttl = self._ttl
        self._reader._cached = self._reader._identity = None
        self._reader._expires = 0.0
        self._lock = threading.RLock()
        self._closed = False

    def _check(self):
        if self._closed:
            raise KistError("Read session is closed.")

    def get(self, key):
        with self._lock:
            self._check()
            return self._reader.get(key)

    def get_many(self, keys, default=...):
        with self._lock:
            self._check()
            return self._reader.get_many(keys, default=default)

    def clear(self):
        with self._lock:
            self._reader._cached = self._reader._identity = None
            self._reader._expires = 0.0

    def close(self):
        with self._lock:
            self.clear()
            self._reader.password = None
            self._closed = True

    def __enter__(self):
        with self._lock:
            self._check()
        return self

    def __exit__(self, *exc):
        self.close()


class AsyncKist:
    """Native async database reads. Only pure cryptographic work uses to_thread.

    An instance belongs to one event loop. Constructor arguments match Kist.
    It intentionally exposes read APIs only; it does not imply async write APIs.
    """
    def __init__(self, *args, kist=None, **kwargs):
        if kist is not None and (args or kwargs):
            raise TypeError("Pass either kist= or Kist constructor arguments.")
        self._sync = kist if kist is not None else Kist(*args, **kwargs)
        self._scope_lock = asyncio.Lock()

    def __getattr__(self, name):
        if name in {"profile_name", "scope", "password", "db_url", "organization_id",
                    "project_id", "profile_id", "_require_database"}:
            return getattr(self._sync, name)
        raise AttributeError(name)

    async def _check_schema(cls, cursor: psycopg.AsyncCursor[Any]) -> None:
        await cursor.execute("SELECT to_regclass('kist_schema')")
        if (await cursor.fetchone())[0] is None:
            raise SchemaVersionError('Initialize the v1 schema explicitly with init_db().')
        await cursor.execute('SELECT version FROM kist_schema WHERE singleton = TRUE')
        row = await cursor.fetchone()
        if row is None or row[0] != SCHEMA_VERSION:
            raise SchemaVersionError('Unsupported Kist schema version.')

    async def get_or_create_scope(self) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
        async with await safe_async_db_connect(self._require_database()) as connection:
            async with connection.cursor() as cursor:
                await self._check_schema(cursor)
                await cursor.execute('INSERT INTO kist_organizations (id, slug) VALUES (%s, %s)\n                    ON CONFLICT (slug) DO UPDATE SET slug = EXCLUDED.slug RETURNING id', (uuid.uuid4(), self.scope.organization))
                org = uuid.UUID(str((await cursor.fetchone())[0]))
                await cursor.execute('INSERT INTO kist_projects (id, organization_id, slug) VALUES (%s, %s, %s)\n                    ON CONFLICT (organization_id, slug) DO UPDATE SET slug = EXCLUDED.slug RETURNING id', (uuid.uuid4(), org, self.scope.project))
                project = uuid.UUID(str((await cursor.fetchone())[0]))
                await cursor.execute('INSERT INTO kist_profiles (id, project_id, profile_name) VALUES (%s, %s, %s)\n                    ON CONFLICT (project_id, profile_name) DO UPDATE\n                    SET profile_name = EXCLUDED.profile_name RETURNING id', (uuid.uuid4(), project, self.profile_name))
                profile = uuid.UUID(str((await cursor.fetchone())[0]))
        self._sync.organization_id, self._sync.project_id, self._sync.profile_id = (org, project, profile)
        return (org, project, profile)

    async def _ensure_scope(self):
        async with self._scope_lock:
            if (self.organization_id is None or self.project_id is None
                    or self.profile_id is None):
                await self.get_or_create_scope()

    async def _load_bundle(self, cursor):
        await cursor.execute(_BUNDLE_SQL, (self.profile_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return await asyncio.to_thread(_unlock, self._sync, row)

    async def get(self, key):
        key = _validate_secret_key(key)
        return (await self.get_many([key]))[key]

    async def get_many(self, keys, default=...):
        names = _names(keys)
        if not names:
            return {}
        await self._ensure_scope()
        values = {}
        async with await safe_async_db_connect(self._sync._require_database()) as connection:
            async with connection.cursor() as cursor:
                await cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                await self._check_schema(cursor)
                bundle = await self._load_bundle(cursor)
                if bundle is not None:
                    tokens = {self._sync._lookup_token(bundle, key): key for key in names}
                    await cursor.execute(
                        _SELECT_MANY_SQL,
                        (self.profile_id, list(tokens)),
                    )
                    rows = await cursor.fetchall()
                    values = await asyncio.to_thread(_decode_rows, self._sync, bundle, tokens, rows)
        return _finish(names, values, default)

    def session(self, *, unlock_ttl_seconds=30):
        return AsyncReadSession(self._sync, unlock_ttl_seconds)


class AsyncReadSession(AsyncKist):
    def __init__(self, source, unlock_ttl_seconds=30):
        self._ttl = _ttl(unlock_ttl_seconds)
        super().__init__(kist=_copy_reader(source))
        self._read_lock = asyncio.Lock()
        self._closed = False
        self._cached = self._identity = None
        self._expires = 0.0

    async def _load_bundle(self, cursor):
        await cursor.execute(_BUNDLE_SQL, (self.profile_id,))
        row = await cursor.fetchone()
        identity = None if row is None else _identity(self._sync, row)
        if (identity is not None and self._cached is not None
                and identity == self._identity and time.monotonic() < self._expires):
            return self._cached
        self._cached = self._identity = None
        self._expires = 0.0
        if row is None:
            return None
        # The worker returns a value only; it never publishes into session state.
        bundle = await asyncio.to_thread(_unlock, self._sync, row)
        self._cached, self._identity = bundle, identity
        self._expires = time.monotonic() + self._ttl
        return bundle

    async def get_many(self, keys, default=...):
        async with self._read_lock:
            if self._closed:
                raise KistError("Read session is closed.")
            return await super().get_many(keys, default=default)

    async def clear(self):
        async with self._read_lock:
            self._cached = self._identity = None
            self._expires = 0.0

    async def close(self):
        async with self._read_lock:
            self._cached = self._identity = None
            self._expires = 0.0
            self._sync.password = None
            self._closed = True

    async def __aenter__(self):
        if self._closed:
            raise KistError("Read session is closed.")
        return self

    async def __aexit__(self, *exc):
        task = asyncio.create_task(self.close())
        task.add_done_callback(_observe)
        await asyncio.shield(task)


def _observe(task):
    if not task.cancelled():
        task.exception()


def _cached_value(value, key, default):
    if value is _MISSING:
        if default is ...:
            raise KeyError(key)
        return default
    return value


class SyncCache:
    def __init__(self, policy):
        _ttl(policy.ttl_seconds)
        if type(policy.max_entries) is not int or policy.max_entries <= 0:
            raise ValueError("max_entries must be positive.")
        self.policy = policy
        self.entries = {}
        self.flights = {}
        self.generation = 0
        self.lock = threading.Lock()

    def get(self, key, default, load):
        with self.lock:
            cached = self.entries.get(key)
            if cached is not None:
                if cached[0] > time.monotonic():
                    return _cached_value(cached[1], key, default)
                self.entries.pop(key, None)
            future = self.flights.get(key)
            leader = future is None
            if leader:
                future = Future()
                self.flights[key] = future
            generation = self.generation
        if not leader:
            return _cached_value(future.result(), key, default)
        try:
            try:
                value = load(key)
            except KeyError:
                value = _MISSING
            with self.lock:
                if self.policy.enabled and generation == self.generation:
                    if len(self.entries) >= self.policy.max_entries:
                        self.entries.pop(next(iter(self.entries)))
                    self.entries[key] = (time.monotonic() + self.policy.ttl_seconds, value)
            future.set_result(value)
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self.lock:
                if self.flights.get(key) is future:
                    self.flights.pop(key, None)
        return _cached_value(value, key, default)

    def invalidate(self, key=None):
        with self.lock:
            self.generation += 1
            if key is None:
                self.entries.clear()
                self.flights.clear()
            else:
                self.entries.pop(key, None)
                self.flights.pop(key, None)


class AsyncCache:
    """One event loop per instance. Loader is an async callable with native SQL."""
    def __init__(self, policy):
        _ttl(policy.ttl_seconds)
        if type(policy.max_entries) is not int or policy.max_entries <= 0:
            raise ValueError("max_entries must be positive.")
        self.policy = policy
        self.entries = {}
        self.flights = {}
        self.generation = 0
        self.pending = set()
        self.closed = False

    async def get(self, key, default, load):
        if self.closed:
            raise KistError("Async cache is closed.")
        cached = self.entries.get(key)
        if cached is not None:
            if cached[0] > time.monotonic():
                return _cached_value(cached[1], key, default)
            self.entries.pop(key, None)
        task = self.flights.get(key)
        if task is None:
            task = asyncio.create_task(self._load(key, load, self.generation))
            self.flights[key] = task
            self.pending.add(task)
            task.add_done_callback(self.pending.discard)
            task.add_done_callback(_observe)
        return _cached_value(await asyncio.shield(task), key, default)

    async def _load(self, key, load, generation):
        try:
            try:
                value = await load(key)
            except KeyError:
                value = _MISSING
            if self.policy.enabled and generation == self.generation and not self.closed:
                if len(self.entries) >= self.policy.max_entries:
                    self.entries.pop(next(iter(self.entries)))
                self.entries[key] = (time.monotonic() + self.policy.ttl_seconds, value)
            return value
        finally:
            if self.flights.get(key) is asyncio.current_task():
                self.flights.pop(key, None)

    def invalidate(self, key=None):
        self.generation += 1
        if key is None:
            self.entries.clear()
            self.flights.clear()
        else:
            self.entries.pop(key, None)
            self.flights.pop(key, None)

    async def close(self):
        self.closed = True
        self.invalidate()
        tasks = tuple(self.pending)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
