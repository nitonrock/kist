"""Deterministic cooperative read-budget and ownership regressions."""
import asyncio
import inspect

import pytest

from kist import _read_budget as budget
from kist._read_policy import _ReadDeadline, _ReadTimeoutError
from kist.core import Kist, KistError
from kist.runtime_reads import AsyncKist, AsyncReadSession, ReadSession


@pytest.fixture
def clock(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(budget, "_ReadDeadline", lambda timeout: _ReadDeadline(
        timeout, clock=lambda: now[0]))
    return now


def test_nested_delegation_keeps_deadline(clock):
    with budget._operation(10):
        first = budget._DEADLINE.get()
        clock[0] = 4
        with budget._operation(None):
            assert budget._DEADLINE.get() is first
            assert budget._remaining("query") == 6
    assert budget._DEADLINE.get() is None


def test_child_cannot_extend_parent(clock):
    with budget._operation(10):
        clock[0] = 4
        with budget._operation(100):
            assert budget._remaining("query") == 6


def test_child_can_shorten_parent(clock):
    with budget._operation(10):
        with budget._operation(2):
            assert budget._remaining("query") == 2
        assert budget._remaining("query") == 10


@pytest.mark.parametrize("value", [0, -1, True, float("inf"), float("nan"), "1"])
def test_invalid_budget_never_runs_body(value):
    called = []

    @budget._budgeted
    def operation():
        called.append(True)

    with pytest.raises(ValueError):
        operation(timeout=value)
    assert not called
    assert budget._DEADLINE.get() is None


def test_expired_call_is_not_started(clock):
    called = []
    with pytest.raises(_ReadTimeoutError) as caught:
        with budget._operation(1):
            clock[0] = 2
            budget._call("query", called.append, True)
    assert not called
    assert caught.value.phase == "query"
    assert isinstance(caught.value, (KistError, TimeoutError))
    assert budget._DEADLINE.get() is None


def test_late_crypto_result_is_rejected(clock):
    def crypto():
        clock[0] = 2
        return "plaintext"

    with pytest.raises(_ReadTimeoutError) as caught:
        with budget._operation(1):
            budget._call("key_unlock", crypto)
    assert caught.value.phase == "key_unlock"
    assert "plaintext" not in str(caught.value)


def test_original_failure_is_not_masked(clock):
    def fail():
        clock[0] = 2
        raise ValueError("original")

    with pytest.raises(ValueError, match="original"):
        with budget._operation(1):
            budget._call("query", fail)
    assert budget._DEADLINE.get() is None


class Connection:
    def __init__(self, clock, *, late_connect=False, late_cleanup=False, failure=False):
        self.clock = clock
        self.late_connect = late_connect
        self.late_cleanup = late_cleanup
        self.failure = failure
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True
        if self.late_cleanup:
            self.clock[0] = 2
        if self.failure:
            raise ValueError("cleanup failed")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.__exit__(*args)

    def connect(self, url):
        if self.late_connect:
            self.clock[0] = 2
        return self

    async def async_connect(self, url):
        return self.connect(url)


def test_late_connection_is_closed(clock):
    connection = Connection(clock, late_connect=True)
    with pytest.raises(_ReadTimeoutError) as caught:
        with budget._operation(1):
            with budget._connection(connection.connect, "unused"):
                pytest.fail("expired connection must not reach caller")
    assert connection.closed
    assert caught.value.phase == "connect"


def test_cleanup_is_in_budget(clock):
    connection = Connection(clock, late_cleanup=True)
    with pytest.raises(_ReadTimeoutError) as caught:
        with budget._operation(1):
            with budget._connection(connection.connect, "unused"):
                pass
    assert connection.closed
    assert caught.value.phase == "cleanup"


def test_cleanup_failure_is_not_masked(clock):
    connection = Connection(clock, late_cleanup=True, failure=True)
    with pytest.raises(ValueError, match="cleanup failed"):
        with budget._operation(1):
            with budget._connection(connection.connect, "unused"):
                pass
    assert connection.closed


class Lock:
    def __init__(self, acquired=True):
        self.acquired = acquired
        self.released = False
        self.timeout = None

    def acquire(self, **kwargs):
        self.timeout = kwargs.get("timeout")
        return self.acquired

    def release(self):
        self.released = True


def test_lock_receives_remaining_budget(clock):
    lock = Lock()
    with budget._operation(10):
        clock[0] = 4
        with budget._lock(lock, "cache_wait"):
            assert lock.timeout == 6
    assert lock.released


def test_failed_lock_not_released(clock):
    lock = Lock(False)
    with pytest.raises(_ReadTimeoutError) as caught:
        with budget._operation(1):
            with budget._lock(lock, "scope_wait"):
                pytest.fail("unacquired lock")
    assert not lock.released
    assert caught.value.phase == "scope_wait"


def test_lock_released_on_failure(clock):
    lock = Lock()
    with pytest.raises(ValueError):
        with budget._operation(1):
            with budget._lock(lock, "cache_wait"):
                raise ValueError("operation")
    assert lock.released


def test_async_late_crypto_result_is_rejected(clock):
    async def run():
        async def crypto():
            clock[0] = 2
            return "plaintext"

        with budget._operation(1):
            await budget._await("key_unlock", crypto)

    with pytest.raises(_ReadTimeoutError) as caught:
        asyncio.run(run())
    assert caught.value.phase == "key_unlock"


def test_async_late_connection_is_closed(clock):
    connection = Connection(clock, late_connect=True)

    async def run():
        with budget._operation(1):
            async with budget._async_connection(connection.async_connect, "unused"):
                pytest.fail("expired connection")

    with pytest.raises(_ReadTimeoutError):
        asyncio.run(run())
    assert connection.closed


def test_async_lock_timeout_does_not_release_owner():
    async def run():
        lock = asyncio.Lock()
        await lock.acquire()
        try:
            with pytest.raises(_ReadTimeoutError) as caught:
                with budget._operation(0.01):
                    async with budget._async_lock(lock, "scope_wait"):
                        pytest.fail("held lock")
            assert caught.value.phase == "scope_wait"
            assert lock.locked()
        finally:
            lock.release()
        async with budget._async_lock(lock, "scope_wait"):
            assert lock.locked()

    asyncio.run(run())


def test_async_cancellation_is_preserved():
    async def run():
        lock = asyncio.Lock()
        await lock.acquire()

        async def waiting():
            with budget._operation(100):
                async with budget._async_lock(lock, "scope_wait"):
                    pytest.fail("held lock")

        task = asyncio.create_task(waiting())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert lock.locked()
        lock.release()

    asyncio.run(run())


def test_async_task_budgets_are_isolated(clock):
    async def run():
        ready = asyncio.Event()

        async def first():
            with budget._operation(1):
                ready.set()
                await asyncio.sleep(0)
                assert budget._remaining("query") == 1

        async def second():
            await ready.wait()
            with budget._operation(10):
                assert budget._remaining("query") == 10

        await asyncio.gather(first(), second())
        assert budget._DEADLINE.get() is None

    asyncio.run(run())


@pytest.mark.parametrize("cls", [Kist, ReadSession, AsyncKist, AsyncReadSession])
@pytest.mark.parametrize("method", ["get", "get_many"])
def test_public_timeout_is_keyword_only(cls, method):
    parameter = inspect.signature(getattr(cls, method)).parameters["timeout"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is None


def test_core_get_forwards_budget(monkeypatch):
    import kist.runtime_reads as reads

    seen = []
    monkeypatch.setattr(reads, "get_one", lambda reader, key, **kw: seen.append(kw) or 7)
    reader = object.__new__(Kist)
    assert reader.get("example", timeout=2) == 7
    assert seen == [{"timeout": 2}]


def test_core_bulk_forwards_budget(monkeypatch):
    import kist.runtime_reads as reads

    seen = []
    monkeypatch.setattr(reads, "get_many", lambda reader, keys, **kw: seen.append(kw) or {})
    reader = object.__new__(Kist)
    assert reader.get_many([], timeout=2) == {}
    assert seen == [{"default": ..., "timeout": 2}]


def test_sync_empty_bulk_still_validates_budget():
    import kist.runtime_reads as reads

    with pytest.raises(ValueError):
        reads.get_many(object(), [], timeout=0)
    assert reads.get_many(object(), [], timeout=1) == {}


def test_async_empty_bulk_still_validates_budget():
    async def run():
        reader = object.__new__(AsyncKist)
        with pytest.raises(ValueError):
            await reader.get_many([], timeout=0)
        assert await reader.get_many([], timeout=1) == {}

    asyncio.run(run())


def test_sync_scope_uses_one_budget(clock, monkeypatch):
    from types import SimpleNamespace

    import kist.runtime_reads as reads

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def execute(self, *args):
            assert budget._remaining("query") == 4
            clock[0] = 11

    class DB(Connection):
        def cursor(self):
            return Cursor()

    connection = DB(clock)

    def scope():
        clock[0] = 6

    reader = SimpleNamespace(_ensure_scope=scope, _require_database=lambda: "unused",
                             _require_password=lambda: "unit-test-password")
    monkeypatch.setattr(reads, "safe_db_connect", connection.connect)
    with pytest.raises(_ReadTimeoutError) as caught:
        reads.get_many(reader, ["example"], timeout=10)
    assert caught.value.phase == "query"
    assert connection.closed


def test_sync_session_wait_is_inside_budget(clock):
    from types import SimpleNamespace

    session = object.__new__(ReadSession)
    session._lock = Lock()
    session._closed = False
    seen = []

    def read(key):
        seen.append(budget._remaining("query"))
        return 7

    session._reader = SimpleNamespace(get=read)
    assert session.get("example", timeout=3) == 7
    assert seen == [3]
    assert session._lock.timeout == 3
    assert session._lock.released


def test_async_session_wait_is_inside_budget():
    async def run():
        session = object.__new__(AsyncReadSession)
        session._read_lock = asyncio.Lock()
        session._closed = False
        await session._read_lock.acquire()
        try:
            with pytest.raises(_ReadTimeoutError) as caught:
                await session.get("example", timeout=0.01)
            assert caught.value.phase == "cache_wait"
            assert session._read_lock.locked()
        finally:
            session._read_lock.release()
        assert await session.get_many([], timeout=1) == {}

    asyncio.run(run())


def test_async_scope_uses_one_budget(clock, monkeypatch):
    from types import SimpleNamespace

    import kist.runtime_reads as reads

    class Cursor:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def execute(self, *args):
            assert budget._remaining("query") == 4
            clock[0] = 11

    class DB(Connection):
        def cursor(self):
            return Cursor()

    connection = DB(clock)
    reader = object.__new__(AsyncKist)
    reader._sync = SimpleNamespace(_require_database=lambda: "unused",
                                   _require_password=lambda: "unit-test-password")

    async def scope():
        clock[0] = 6

    reader._ensure_scope = scope
    monkeypatch.setattr(reads, "safe_async_db_connect", connection.async_connect)

    async def run():
        await reader.get_many(["example"], timeout=10)

    with pytest.raises(_ReadTimeoutError) as caught:
        asyncio.run(run())
    assert caught.value.phase == "query"
    assert connection.closed


def test_late_async_unlock_is_not_cached(clock, monkeypatch):
    import kist.runtime_reads as reads

    class Cursor:
        async def execute(self, *args):
            pass

        async def fetchone(self):
            return ("bundle",)

    session = object.__new__(AsyncReadSession)
    session._sync = object()
    session._cached = session._identity = None
    session._expires = 0
    session._ttl = 30
    session._sync = type("Reader", (), {"profile_id": "profile"})()
    monkeypatch.setattr(reads, "_identity", lambda *args: "identity")

    def unlock(*args):
        clock[0] = 2
        return object()

    monkeypatch.setattr(reads, "_unlock", unlock)

    async def run():
        with budget._operation(1):
            await session._load_bundle(Cursor())

    with pytest.raises(_ReadTimeoutError) as caught:
        asyncio.run(run())
    assert caught.value.phase == "key_unlock"
    assert session._cached is None
    assert session._identity is None
    assert session._expires == 0
