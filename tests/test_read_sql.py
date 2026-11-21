"""Statement budgets: deterministic policy and cursor ownership regressions."""
import asyncio
from contextlib import asynccontextmanager, contextmanager

import pytest
from psycopg.errors import QueryCanceled

from kist import _read_budget as budget
from kist import _read_sql as sql
from kist._read_policy import _ReadDeadline, _ReadTimeoutError


@pytest.fixture
def clock(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(budget, "_ReadDeadline", lambda timeout: _ReadDeadline(
        timeout, clock=lambda: now[0]))
    return now


@pytest.mark.parametrize(("value", "expected"), [
    ("0", 0), ("15ms", 15), ("1s", 1000), ("2min", 120000),
    ("1h", 3600000), ("1d", 86400000), (" 20 ms ", 20),
])
def test_parse_limit(value, expected):
    assert sql._parse_limit(value) == expected


@pytest.mark.parametrize("value", ["-1", "secret", "1; SELECT 1", "1fortnight"])
def test_reject_unrecognised_limit(value):
    with pytest.raises(ValueError, match="Unsupported PostgreSQL"):
        sql._parse_limit(value)


@pytest.mark.parametrize(("base", "expected", "owned"), [
    (0, 1000, True), (100, 100, False), (1000, 1000, False), (2000, 1000, True),
])
def test_preserve_stricter_server_limit(clock, base, expected, owned):
    with budget._operation(1):
        assert sql._limit(base) == (expected, owned)


def test_remaining_budget_not_original_budget(clock):
    with budget._operation(10):
        clock[0] = 8
        assert sql._limit(0) == (2000, True)


def test_submillisecond_budget_never_disables_limit(clock):
    with budget._operation(0.00001):
        assert sql._limit(0) == (1, True)


def test_huge_budget_does_not_overflow(clock):
    with budget._operation(1e308):
        assert sql._limit(0) == (sql._MAX_MS, False)


class Cursor:
    def __init__(self, clock, limit="0"):
        self.clock = clock
        self.limit = limit
        self.statements = []
        self.cancel = False
        self.fail_early = False

    def execute(self, query, *args, **kwargs):
        self.statements.append(query)
        if query == "work" and self.cancel:
            if not self.fail_early:
                self.clock[0] = 2
            raise QueryCanceled("driver detail must not escape our timeout")
        return self

    def fetchone(self):
        return (self.limit,)

    def fetchall(self):
        return [(7,)]


class AsyncCursor(Cursor):
    async def execute(self, *args, **kwargs):
        return super().execute(*args, **kwargs)

    async def fetchone(self):
        return super().fetchone()

    async def fetchall(self):
        return super().fetchall()


def test_sync_refreshes_each_statement(clock):
    raw = Cursor(clock)
    with budget._operation(10):
        cursor = sql._StatementCursor(raw)
        assert cursor.execute("first") is cursor
        clock[0] = 4
        cursor.execute("second")
        assert cursor.fetchone() == ("0",)
        assert cursor.fetchall() == [(7,)]
    assert raw.statements == ["SHOW statement_timeout",
                              "SET LOCAL statement_timeout = 10000", "first",
                              "SET LOCAL statement_timeout = 6000", "second"]


def test_timeout_has_no_driver_context(clock):
    raw = Cursor(clock)
    raw.cancel = True
    with pytest.raises(_ReadTimeoutError) as caught:
        with budget._operation(1):
            sql._StatementCursor(raw).execute("work")
    assert caught.value.phase == "query"
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert "driver detail" not in str(caught.value)
    assert budget._DEADLINE.get() is None


def test_early_cancel_is_not_relabelled(clock):
    raw = Cursor(clock)
    raw.cancel = raw.fail_early = True
    with pytest.raises(QueryCanceled):
        with budget._operation(1):
            sql._StatementCursor(raw).execute("work")


def test_operator_timeout_is_not_relabelled_even_after_deadline(clock):
    raw = Cursor(clock, limit="10ms")
    raw.cancel = True
    with pytest.raises(QueryCanceled):
        with budget._operation(1):
            sql._StatementCursor(raw).execute("work")


def test_expired_work_never_starts(clock):
    raw = Cursor(clock)
    with pytest.raises(_ReadTimeoutError):
        with budget._operation(1):
            clock[0] = 2
            sql._StatementCursor(raw).execute("work")
    assert raw.statements == []


def test_async_refreshes_each_statement(clock):
    raw = AsyncCursor(clock)

    async def run():
        with budget._operation(10):
            cursor = sql._AsyncStatementCursor(raw)
            assert await cursor.execute("first") is cursor
            clock[0] = 4
            await cursor.execute("second")
            assert await cursor.fetchone() == ("0",)
            assert await cursor.fetchall() == [(7,)]

    asyncio.run(run())
    assert raw.statements == ["SHOW statement_timeout",
                              "SET LOCAL statement_timeout = 10000", "first",
                              "SET LOCAL statement_timeout = 6000", "second"]


def test_async_server_timeout_has_no_context(clock):
    raw = AsyncCursor(clock)
    raw.cancel = True

    async def run():
        with budget._operation(1):
            await sql._AsyncStatementCursor(raw).execute("work")

    with pytest.raises(_ReadTimeoutError) as caught:
        asyncio.run(run())
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert caught.value.phase == "query"


def test_async_driver_timeout_is_not_our_timeout():
    async def failure():
        raise TimeoutError("driver timeout")

    async def run():
        with budget._operation(1):
            await sql._AsyncStatementCursor(None)._run(failure)

    with pytest.raises(TimeoutError, match="driver timeout") as caught:
        asyncio.run(run())
    assert not isinstance(caught.value, _ReadTimeoutError)


def test_async_deadline_requests_cancellation():
    cancelled = []

    async def blocked():
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    async def run():
        with budget._operation(0.01):
            await sql._AsyncStatementCursor(None)._run(blocked)

    with pytest.raises(_ReadTimeoutError) as caught:
        asyncio.run(run())
    assert cancelled == [True]
    assert caught.value.__context__ is None


def test_external_async_cancellation_remains_cancelled():
    async def run():
        started = asyncio.Event()

        async def blocked():
            started.set()
            await asyncio.Event().wait()

        async def operation():
            with budget._operation(10):
                await sql._AsyncStatementCursor(None)._run(blocked)

        task = asyncio.create_task(operation())
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled()

    asyncio.run(run())


class Connection:
    def __init__(self, cursor):
        self.raw = cursor
        self.closed = False

    @contextmanager
    def cursor(self):
        try:
            yield self.raw
        finally:
            self.closed = True


class AsyncConnection(Connection):
    @asynccontextmanager
    async def cursor(self):
        try:
            yield self.raw
        finally:
            self.closed = True


def test_unbudgeted_cursor_has_no_extra_queries(clock):
    connection = Connection(Cursor(clock))
    with budget._operation(None):
        with sql._cursor(connection) as cursor:
            assert cursor is connection.raw
            cursor.execute("work")
    assert connection.closed
    assert connection.raw.statements == ["work"]


def test_unbudgeted_async_cursor_has_no_extra_queries(clock):
    connection = AsyncConnection(AsyncCursor(clock))

    async def run():
        with budget._operation(None):
            async with sql._async_cursor(connection) as cursor:
                assert cursor is connection.raw
                await cursor.execute("work")

    asyncio.run(run())
    assert connection.closed
    assert connection.raw.statements == ["work"]


def test_cursor_context_is_closed_on_timeout(clock):
    raw = Cursor(clock)
    raw.cancel = True
    connection = Connection(raw)
    with pytest.raises(_ReadTimeoutError):
        with budget._operation(1):
            with sql._cursor(connection) as cursor:
                cursor.execute("work")
    assert connection.closed
