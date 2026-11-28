"""Runtime read parity tests. No live database required."""
import asyncio
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from kist import SecretNotFoundError, core
from kist import runtime_reads as rr


def policy(enabled=True):
    return SimpleNamespace(enabled=enabled, ttl_seconds=30.0, max_entries=128)


def backend():
    value = core.Kist.__new__(core.Kist)
    value.profile_name = "default"
    value.scope = core.KistScope()
    value.password = "unit-test-password"
    value.db_url = "postgresql://localhost/unit_tests"
    value.organization_id, value.project_id, value.profile_id = [uuid.uuid4() for _ in range(3)]
    value._scope_init_lock = threading.RLock()
    return value


def test_sync_negative_defaults_and_errors():
    cache = rr.SyncCache(policy())
    load = MagicMock(side_effect=KeyError("missing"))
    assert cache.get("missing", 1, load) == 1
    assert cache.get("missing", 2, load) == 2
    with pytest.raises(KeyError):
        cache.get("missing", ..., load)
    assert load.call_count == 1
    cache.invalidate()
    load.side_effect = RuntimeError("database unavailable")
    for _ in range(2):
        with pytest.raises(RuntimeError):
            cache.get("missing", None, load)
    assert load.call_count == 3


def test_sync_singleflight_and_invalidation():
    cache = rr.SyncCache(policy())
    entered, release, joined = threading.Event(), threading.Event(), threading.Event()
    load = MagicMock()
    def slow(key):
        entered.set()
        assert release.wait(5)
        return 7
    load.side_effect = slow
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(cache.get, "key", ..., load)
        assert entered.wait(5)
        flight = cache.flights["key"]
        original = flight.result
        def result(*args, **kwargs):
            joined.set()
            return original(*args, **kwargs)
        flight.result = result
        second = pool.submit(cache.get, "key", ..., load)
        try:
            assert joined.wait(5)
            cache.invalidate("key")
        finally:
            release.set()
        assert first.result(5) == second.result(5) == 7
    assert load.call_count == 1
    assert "key" not in cache.entries


def test_completion_ttl_and_bound(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(rr.time, "monotonic", lambda: clock[0])
    p = policy()
    p.max_entries = 1
    cache = rr.SyncCache(p)
    def slow(key):
        clock[0] = 100.0
        return 1
    cache.get("a", ..., slow)
    assert cache.entries["a"][0] == 130.0
    cache.get("b", ..., lambda key: 2)
    assert list(cache.entries) == ["b"]
    clock[0] = 131.0
    assert cache.get("b", ..., lambda key: 3) == 3


def test_async_negative_and_failures():
    async def run():
        cache = rr.AsyncCache(policy())
        load = AsyncMock(side_effect=KeyError("missing"))
        assert await cache.get("missing", 1, load) == 1
        assert await cache.get("missing", 2, load) == 2
        with pytest.raises(KeyError):
            await cache.get("missing", ..., load)
        assert load.await_count == 1
        cache.invalidate()
        load.side_effect = RuntimeError("database unavailable")
        for _ in range(2):
            with pytest.raises(RuntimeError):
                await cache.get("missing", None, load)
        assert load.await_count == 3
        await cache.close()
    asyncio.run(run())


def test_async_singleflight_cancellation_and_invalidation():
    async def run():
        cache = rr.AsyncCache(policy())
        entered, release = asyncio.Event(), asyncio.Event()
        async def slow(key):
            entered.set()
            await release.wait()
            return 7
        load = AsyncMock(side_effect=slow)
        first = asyncio.create_task(cache.get("a", ..., load))
        await entered.wait()
        second = asyncio.create_task(cache.get("a", ..., load))
        await asyncio.sleep(0)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        cache.invalidate("a")
        release.set()
        assert await second == 7
        assert load.await_count == 1
        assert not cache.entries
        await cache.close()
    asyncio.run(run())


def test_async_close_cancels_pending_load():
    async def run():
        cache = rr.AsyncCache(policy())
        entered = asyncio.Event()
        async def load(key):
            entered.set()
            await asyncio.Event().wait()
        caller = asyncio.create_task(cache.get("a", ..., load))
        await entered.wait()
        await cache.close()
        with pytest.raises(asyncio.CancelledError):
            await caller
        assert not cache.entries
    asyncio.run(run())


def fake_decode(reader, bundle, tokens, rows):
    return {tokens[bytes(row[1])]: row[2] for row in rows}


def test_sync_bulk_one_load_and_empty(monkeypatch):
    reader = backend()
    cursor, connection = MagicMock(), MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor
    connect = MagicMock()
    connect.return_value.__enter__.return_value = connection
    monkeypatch.setattr(rr, "safe_db_connect", connect)
    reader._check_schema = MagicMock()
    reader._load_bundle = MagicMock(return_value=object())
    reader._lookup_token = lambda bundle, key: key.encode()
    monkeypatch.setattr(rr, "_decode_rows", fake_decode)
    cursor.fetchall.return_value = [(1, b"a", 10), (2, b"b", 20)]
    assert reader.get_many([]) == {}
    connect.assert_not_called()
    assert reader.get_many(["a", "b", "a"]) == {"a": 10, "b": 20}
    reader._load_bundle.assert_called_once_with(cursor)
    assert cursor.execute.call_args.args[1] == (reader.profile_id, [b"a", b"b"])
    with pytest.raises(TypeError):
        reader.get_many("a")


def test_async_bulk_uses_native_sql_and_crypto_only_workers(monkeypatch):
    async def run():
        reader = backend()
        reader._lookup_token = lambda bundle, key: key.encode()
        client = rr.AsyncKist(kist=reader)
        client._check_schema = AsyncMock()
        cursor, connection = MagicMock(), MagicMock()
        cursor.execute, cursor.fetchone, cursor.fetchall = AsyncMock(), AsyncMock(), AsyncMock()
        cursor.fetchone.return_value = (uuid.uuid4(), "password-wrap-v1", 1, b"wrapped", 1)
        cursor.fetchall.return_value = [(1, b"a", 10)]
        connection.cursor.return_value.__aenter__ = AsyncMock(return_value=cursor)
        connection.cursor.return_value.__aexit__ = AsyncMock(return_value=False)
        manager = MagicMock()
        manager.__aenter__ = AsyncMock(return_value=connection)
        manager.__aexit__ = AsyncMock(return_value=False)
        connect = AsyncMock(return_value=manager)
        monkeypatch.setattr(rr, "safe_async_db_connect", connect)
        monkeypatch.setattr(rr, "safe_db_connect", MagicMock(side_effect=AssertionError("sync SQL")))
        monkeypatch.setattr(rr, "_unlock", lambda reader, row: object())
        monkeypatch.setattr(rr, "_decode_rows", fake_decode)
        original = asyncio.to_thread
        workers = []
        async def worker(func, *args):
            workers.append(func)
            return await original(func, *args)
        monkeypatch.setattr(rr.asyncio, "to_thread", worker)
        assert await client.get_many([]) == {}
        connect.assert_not_awaited()
        assert await client.get_many(["a", "a"]) == {"a": 10}
        assert workers == [rr._unlock, rr._decode_rows]
        assert cursor.execute.await_count == 3
        assert connect.await_count == 1
    asyncio.run(run())


def test_bulk_missing_and_integrity():
    # Pure record validation is shared by the sync and async batch readers.
    reader = backend()
    bundle = object()
    reader._decode_row = MagicMock(return_value=("a", None))
    assert rr._decode_rows(reader, bundle, {b"a": "a"}, [(1, b"a")]) == {"a": None}
    with pytest.raises(core.DecryptionError):
        rr._decode_rows(reader, bundle, {b"a": "a"}, [(1, b"other")])
    with pytest.raises(core.DecryptionError):
        rr._decode_rows(reader, bundle, {b"a": "a"}, [(1, b"a"), (2, b"a")])
    assert rr._finish(["a"], {}, None) == {"a": None}
    with pytest.raises(SecretNotFoundError):
        rr._finish(["a", "b"], {}, ...)


def test_sync_session_revision_ttl_and_close(monkeypatch):
    reader = backend()
    monkeypatch.setattr(rr, "_copy_reader", lambda source, cls=core.Kist: _clone(source, cls))
    calls = []
    monkeypatch.setattr(rr, "_unlock", lambda source, row: calls.append(row[4]) or object())
    cursor = MagicMock()
    row = [uuid.uuid4(), "password-wrap-v1", 1, b"wrapped", 1]
    cursor.fetchone.side_effect = lambda: tuple(row)
    monkeypatch.setattr(core.Kist, "get", lambda self, key: self._load_bundle(cursor))
    clock = [0.0]
    monkeypatch.setattr(rr.time, "monotonic", lambda: clock[0])
    with rr.ReadSession(reader, 30) as session:
        first = session.get("a")
        assert session.get("b") is first
        assert len(calls) == 1
        row[4] = 2
        session.get("a")
        assert len(calls) == 2
        clock[0] = 31.0
        session.get("a")
        assert len(calls) == 3
        session.clear()
        session.get("a")
        assert len(calls) == 4
    assert session._reader._cached is None
    with pytest.raises(core.KistError):
        session.get("a")


def _clone(source, cls):
    target = cls.__new__(cls)
    target.__dict__.update(source.__dict__)
    return target


def test_async_session_revision_ttl_and_close(monkeypatch):
    async def run():
        monkeypatch.setattr(rr, "_copy_reader", lambda source, cls=core.Kist: _clone(source, cls))
        client = rr.AsyncReadSession(backend(), 30)
        cursor = MagicMock()
        cursor.execute = AsyncMock()
        row = [uuid.uuid4(), "password-wrap-v1", 1, b"wrapped", 1]
        cursor.fetchone = AsyncMock(side_effect=lambda: tuple(row))
        calls = []
        monkeypatch.setattr(rr, "_unlock", lambda source, row: calls.append(row[4]) or object())
        async def read(self, keys, default=...):
            return await self._load_bundle(cursor)
        monkeypatch.setattr(rr.AsyncKist, "get_many", read)
        clock = [0.0]
        monkeypatch.setattr(rr.time, "monotonic", lambda: clock[0])
        async with client:
            first = await client.get_many(["a"])
            assert await client.get_many(["b"]) is first
            assert len(calls) == 1
            row[4] = 2
            await client.get_many(["a"])
            assert len(calls) == 2
            clock[0] = 31.0
            await client.get_many(["a"])
            assert len(calls) == 3
            await client.clear()
            await client.get_many(["a"])
            assert len(calls) == 4
        assert client._cached is None
        with pytest.raises(core.KistError):
            await client.get_many(["a"])
    asyncio.run(run())


@pytest.mark.parametrize("ttl", [0, -1, float("inf"), float("nan"), True])
def test_ttl_validation(ttl):
    with pytest.raises(ValueError):
        rr.ReadSession(backend(), ttl)
    with pytest.raises(ValueError):
        rr.AsyncReadSession(backend(), ttl)


def test_native_async_scope_initialization(monkeypatch):
    async def run():
        source = backend()
        source.organization_id = source.project_id = source.profile_id = None
        client = rr.AsyncKist(kist=source)
        ids = [uuid.uuid4() for _ in range(3)]
        cursor = MagicMock()
        cursor.execute = AsyncMock()
        cursor.fetchone = AsyncMock(side_effect=[("kist_schema",), (1,), *[(value,) for value in ids]])
        connection = MagicMock()
        connection.cursor.return_value.__aenter__ = AsyncMock(return_value=cursor)
        connection.cursor.return_value.__aexit__ = AsyncMock(return_value=False)
        manager = MagicMock()
        manager.__aenter__ = AsyncMock(return_value=connection)
        manager.__aexit__ = AsyncMock(return_value=False)
        connect = AsyncMock(return_value=manager)
        monkeypatch.setattr(rr, "safe_async_db_connect", connect)
        monkeypatch.setattr(core, "safe_db_connect", MagicMock(side_effect=AssertionError("sync SQL")))
        await asyncio.gather(client._ensure_scope(), client._ensure_scope())
        assert [source.organization_id, source.project_id, source.profile_id] == ids
        assert cursor.execute.await_count == 5
        assert connect.await_count == 1
    asyncio.run(run())


def test_cancelled_unlock_cannot_publish_after_session_close(monkeypatch):
    async def run():
        monkeypatch.setattr(rr, "_copy_reader", lambda source, cls=core.Kist: _clone(source, cls))
        session = rr.AsyncReadSession(backend())
        started, release, finished = threading.Event(), threading.Event(), threading.Event()
        cursor = MagicMock()
        cursor.execute = AsyncMock()
        cursor.fetchone = AsyncMock(return_value=(uuid.uuid4(), "password-wrap-v1", 1, b"wrapped", 1))
        def unlock(reader, row):
            started.set()
            assert release.wait(5)
            finished.set()
            return object()
        monkeypatch.setattr(rr, "_unlock", unlock)
        async def read(self, keys, default=...):
            return await self._load_bundle(cursor)
        monkeypatch.setattr(rr.AsyncKist, "get_many", read)
        task = asyncio.create_task(session.get_many(["a"]))
        assert await asyncio.to_thread(started.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        try:
            await session.close()
            assert session._cached is None
        finally:
            release.set()
        assert await asyncio.to_thread(finished.wait, 5)
        await asyncio.sleep(0)
        assert session._cached is None
    asyncio.run(run())


def test_standalone_async_ttl_context_and_native_loader():
    from kist.stores import AsyncTTLSecretStore
    async def run():
        native = SimpleNamespace(get=AsyncMock(return_value=7))
        async with AsyncTTLSecretStore(kist=backend(), async_kist=native) as store:
            assert await store.get("a") == 7
            assert await store.get("a") == 7
            assert native.get.await_count == 1
        assert store._runtime_cache.closed
    asyncio.run(run())
