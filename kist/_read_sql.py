"""Transaction-local statement budgets for Kist-owned read cursors.

Server statement limits do not bound a stalled synchronous network transport.
Async driver awaits additionally request cancellation at the remaining deadline;
cancellation acknowledgement and connection cleanup can still overrun it.
"""
from __future__ import annotations

import asyncio
import math
import re
from contextlib import asynccontextmanager, contextmanager

from psycopg.errors import QueryCanceled

from kist._read_budget import _check, _expired, _remaining

_MAX_MS = 2_147_483_647
_UNITS = {None: 1, "ms": 1, "s": 1000, "min": 60_000, "h": 3_600_000, "d": 86_400_000}


def _parse_limit(value):
    match = re.fullmatch(r"([0-9]+)\s*(ms|s|min|h|d)?", value.strip())
    if match is None:
        raise ValueError("Unsupported PostgreSQL statement timeout setting.")
    return int(match[1]) * _UNITS[match[2]]


def _limit(base):
    remaining = _remaining("query")
    if remaining is None:
        raise RuntimeError("Statement cursor requires an active finite budget.")
    # Check before multiplying: very large finite user budgets must not overflow.
    requested = _MAX_MS if remaining >= _MAX_MS / 1000 else max(1, math.ceil(remaining * 1000))
    chosen = min(base, requested) if base else requested
    # A stricter pre-existing timeout remains a driver error, not our timeout.
    owned = (not base or requested < base) and remaining <= _MAX_MS / 1000
    return chosen, owned


def _deadline_passed():
    from kist._read_policy import _ReadTimeoutError

    try:
        _check("query")
    except _ReadTimeoutError:
        return True
    return False


class _StatementCursor:
    def __init__(self, cursor):
        self._cursor = cursor
        self._base = None
        self._owned = False

    def __getattr__(self, name):
        return getattr(self._cursor, name)

    def _run(self, function, *args, owned=False, **kwargs):
        _check("query")
        timed_out = False
        try:
            result = function(*args, **kwargs)
        except QueryCanceled:
            if not owned or not _deadline_passed():
                raise
            timed_out = True
        # Raise outside except so the public timeout retains no driver context.
        if timed_out:
            raise _expired("query") from None
        _check("query")
        return result

    def execute(self, *args, **kwargs):
        if self._base is None:
            self._run(self._cursor.execute, "SHOW statement_timeout")
            self._base = _parse_limit(self._run(self._cursor.fetchone)[0])
        milliseconds, owned = _limit(self._base)
        # Only an internally generated positive integer is interpolated.
        # SET/SHOW avoid taking a SELECT snapshot before SET TRANSACTION.
        self._run(self._cursor.execute, f"SET LOCAL statement_timeout = {milliseconds}",
                  owned=self._owned)
        self._owned = owned
        self._run(self._cursor.execute, *args, owned=owned, **kwargs)
        return self

    def fetchone(self):
        return self._run(self._cursor.fetchone, owned=self._owned)

    def fetchall(self):
        return self._run(self._cursor.fetchall, owned=self._owned)


class _AsyncStatementCursor:
    def __init__(self, cursor):
        self._cursor = cursor
        self._base = None
        self._owned = False

    def __getattr__(self, name):
        return getattr(self._cursor, name)

    async def _run(self, function, *args, owned=False, **kwargs):
        guard = asyncio.timeout(_remaining("query"))
        timed_out = False
        try:
            async with guard:
                result = await function(*args, **kwargs)
        except TimeoutError:
            if not guard.expired():
                raise
            timed_out = True
        except QueryCanceled:
            if not owned or not _deadline_passed():
                raise
            timed_out = True
        # External CancelledError is deliberately not caught or translated.
        if timed_out:
            raise _expired("query") from None
        _check("query")
        return result

    async def execute(self, *args, **kwargs):
        if self._base is None:
            await self._run(self._cursor.execute, "SHOW statement_timeout")
            row = await self._run(self._cursor.fetchone)
            self._base = _parse_limit(row[0])
        milliseconds, owned = _limit(self._base)
        await self._run(self._cursor.execute, f"SET LOCAL statement_timeout = {milliseconds}",
                        owned=self._owned)
        self._owned = owned
        await self._run(self._cursor.execute, *args, owned=owned, **kwargs)
        return self

    async def fetchone(self):
        return await self._run(self._cursor.fetchone, owned=self._owned)

    async def fetchall(self):
        return await self._run(self._cursor.fetchall, owned=self._owned)


@contextmanager
def _cursor(connection):
    with connection.cursor() as cursor:
        if _remaining("query") is None:
            yield cursor
        else:
            yield _StatementCursor(cursor)


@asynccontextmanager
async def _async_cursor(connection):
    async with connection.cursor() as cursor:
        if _remaining("query") is None:
            yield cursor
        else:
            yield _AsyncStatementCursor(cursor)
