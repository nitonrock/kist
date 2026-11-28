"""Missing database-secret parity; no database or real crypto required."""
import asyncio
import threading
import traceback
import uuid
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from kist import ReadError, SecretNotFoundError, core
from kist import runtime_reads as reads

_PRIVATE_NAME = "vendor.private.api_key"
_KINDS = ["sync", "sync_session", "async", "async_session"]


class Cursor:
    def __init__(self, values):
        self.values = values
        self.showing_limit = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def execute(self, query, *args, **kwargs):
        self.showing_limit = query == "SHOW statement_timeout"
        return self

    def fetchone(self):
        if self.showing_limit:
            return ("0",)
        return next(iter(self.values.items()), None)

    def fetchall(self):
        return list(self.values.items())


class AsyncCursor(Cursor):
    async def execute(self, *args, **kwargs):
        return super().execute(*args, **kwargs)

    async def fetchone(self):
        return super().fetchone()

    async def fetchall(self):
        return super().fetchall()


class Opened:
    def __init__(self, cursor):
        self.raw_cursor = cursor
        self.closed = False

    def cursor(self):
        return self.raw_cursor


class Manager:
    def __init__(self, opened):
        self.opened = opened

    def __enter__(self):
        return self.opened

    def __exit__(self, *args):
        self.opened.closed = True
        return False

    async def __aenter__(self):
        return self.opened

    async def __aexit__(self, *args):
        self.opened.closed = True
        return False


@pytest.fixture
def setup(monkeypatch):
    source = core.Kist.__new__(core.Kist)
    source.profile_name = "default"
    source.password = "unit-test-password"
    source.db_url = "postgresql://localhost/unit_tests"
    source.scope = core.KistScope()
    source.organization_id, source.project_id, source.profile_id = [uuid.uuid4() for _ in range(3)]
    source._scope_init_lock = threading.RLock()
    config = SimpleNamespace(bundle=object(), values={}, failure=None, connections=[], loads=0)

    def schema(*args):
        pass

    async def async_schema(*args):
        pass

    def load(*args):
        config.loads += 1
        if config.failure is not None:
            raise config.failure
        return config.bundle

    async def async_load(*args):
        return load()

    def connect(url):
        connection = Opened(Cursor(config.values))
        config.connections.append(connection)
        return Manager(connection)

    async def async_connect(url):
        connection = Opened(AsyncCursor(config.values))
        config.connections.append(connection)
        return Manager(connection)

    monkeypatch.setattr(core, "safe_db_connect", connect)
    monkeypatch.setattr(reads, "safe_db_connect", connect)
    monkeypatch.setattr(reads, "safe_async_db_connect", async_connect)
    monkeypatch.setattr(core.Kist, "_check_schema", schema)
    monkeypatch.setattr(reads.AsyncKist, "_check_schema", async_schema)
    monkeypatch.setattr(core.Kist, "_load_bundle", load)
    monkeypatch.setattr(reads._SessionReader, "_load_bundle", load)
    monkeypatch.setattr(reads.AsyncKist, "_load_bundle", async_load)
    monkeypatch.setattr(reads.AsyncReadSession, "_load_bundle", async_load)
    monkeypatch.setattr(core.Kist, "_lookup_token", lambda self, bundle, key: key.encode())
    monkeypatch.setattr(core.Kist, "_decode_row", lambda self, bundle, row, key: row)
    monkeypatch.setattr(reads, "_decode_rows", lambda reader, bundle, tokens, rows: dict(rows))
    return source, config


def invoke(kind, source, action):
    if kind.startswith("async"):
        async def run():
            context = source.async_session() if kind.endswith("session") else nullcontext(source.as_async())
            async with context as reader:
                return await action(reader)
        return asyncio.run(run())
    context = source.session() if kind.endswith("session") else nullcontext(source)
    with context as reader:
        return action(reader)


@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize("bulk", [False, True])
@pytest.mark.parametrize("bundle_present", [False, True])
@pytest.mark.parametrize("timeout", [None, 5])
def test_missing_secret_has_one_safe_type(setup, kind, bulk, bundle_present, timeout):
    source, config = setup
    if not bundle_present:
        config.bundle = None
    with pytest.raises(SecretNotFoundError) as caught:
        invoke(kind, source, lambda reader: reader.get_many([_PRIVATE_NAME], timeout=timeout)
               if bulk else reader.get(_PRIVATE_NAME, timeout=timeout))
    error = caught.value
    assert isinstance(error, KeyError)
    assert isinstance(error, core.KistError)
    assert isinstance(error, ReadError)
    assert not isinstance(error, core.MissingKeyError)
    assert error.reason_code == "secret_not_found"
    assert error.phase == "query"
    assert error.sqlstate is None
    assert not error.retryable
    assert error.elapsed_seconds >= 0
    assert _PRIVATE_NAME not in str(error)
    assert _PRIVATE_NAME not in repr(error.args)
    assert _PRIVATE_NAME not in repr(vars(error))
    assert _PRIVATE_NAME not in "".join(traceback.format_exception(error))
    assert error.__context__ is None
    assert error.__cause__ is None
    assert config.connections and all(connection.closed for connection in config.connections)


@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize("bulk", [False, True])
def test_missing_password_is_not_missing_secret_or_default(setup, kind, bulk):
    source, config = setup
    source.password = None
    config.bundle = None
    with pytest.raises(core.MissingKeyError) as caught:
        invoke(kind, source, lambda reader: reader.get_many([_PRIVATE_NAME], default=None)
               if bulk else reader.get(_PRIVATE_NAME))
    assert not isinstance(caught.value, KeyError)
    assert not isinstance(caught.value, SecretNotFoundError)
    assert config.connections == []
    assert config.loads == 0


@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize("timeout", [None, 5])
def test_empty_bulk_needs_no_password_or_database(setup, kind, timeout):
    source, config = setup
    source.password = source.db_url = None
    assert invoke(kind, source, lambda reader: reader.get_many([], timeout=timeout)) == {}
    assert config.connections == []


@pytest.mark.parametrize("kind", _KINDS)
def test_bulk_default_preserves_stored_none(setup, kind):
    source, config = setup
    config.values = {"present": None}
    default = object()
    assert invoke(kind, source, lambda reader: reader.get_many(
        ["present", _PRIVATE_NAME, "present"], default=default)) == {
            "present": None, _PRIVATE_NAME: default}


@pytest.mark.parametrize("kind", _KINDS)
def test_uninitialised_profile_respects_explicit_default(setup, kind):
    source, config = setup
    config.bundle = None
    assert invoke(kind, source, lambda reader: reader.get_many([_PRIVATE_NAME], default=None)) == {
        _PRIVATE_NAME: None}


@pytest.mark.parametrize("kind", _KINDS)
def test_wrong_password_failure_is_not_a_default(setup, kind):
    source, config = setup
    original = core.DecryptionError("incorrect password or invalid ciphertext")
    config.failure = original
    with pytest.raises(core.DecryptionError) as caught:
        invoke(kind, source, lambda reader: reader.get_many([_PRIVATE_NAME], default=None))
    assert caught.value is original


@pytest.mark.parametrize("kind", _KINDS)
def test_unrelated_keyerror_is_not_relabelled(setup, kind):
    source, config = setup
    original = KeyError("caller iterator failure")

    def keys():
        raise original
        yield "unreachable"

    with pytest.raises(KeyError) as caught:
        invoke(kind, source, lambda reader: reader.get_many(keys(), default=None))
    assert caught.value is original
    assert not isinstance(caught.value, SecretNotFoundError)
    assert config.connections == []


@pytest.mark.parametrize("cls", [core.Kist, reads._SessionReader])
def test_session_snapshot_never_reresolves_missing_password(setup, monkeypatch, cls):
    source, _ = setup
    source.password = None
    resolve = MagicMock(side_effect=AssertionError("Unexpected password resolution"))
    monkeypatch.setattr(core, "get_profile_password", resolve)
    copy = reads._copy_reader(source, cls)
    assert copy.password is None
    assert copy.db_url == source.db_url
    assert copy.profile_id == source.profile_id
    assert copy._scope_init_lock is not source._scope_init_lock
    resolve.assert_not_called()
