"""Cooperative per-call budgets for read paths; not a SQL cancellation layer."""
from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from functools import wraps

from kist._read_policy import _ReadDeadline, _ReadTimeoutError
from kist.read_errors import ReadError, _redact
from kist.read_trace import _end_call, _owned, _start_call, _timed

_DEADLINE: ContextVar[_ReadDeadline | None] = ContextVar("kist_read_deadline", default=None)


def _check(phase):
    deadline = _DEADLINE.get()
    if deadline is not None:
        deadline.check(phase)


def _remaining(phase):
    deadline = _DEADLINE.get()
    return None if deadline is None else deadline.remaining(phase)


def _expired(phase):
    deadline = _DEADLINE.get()
    if deadline is None:
        raise RuntimeError("No active read deadline.")
    return _ReadTimeoutError(phase=phase, elapsed_seconds=deadline.elapsed_seconds)


@contextmanager
def _operation(timeout):
    parent = _DEADLINE.get()
    # Nested API delegation keeps the same deadline, including session waits.
    if parent is not None and timeout is None:
        _check("read")
        yield
        _check("read")
        return
    deadline = _ReadDeadline(timeout)
    if parent is not None:
        remaining = parent.remaining("read")
        if remaining is not None:
            deadline = _ReadDeadline(min(timeout, remaining))
    token = _DEADLINE.set(deadline)
    call = _start_call() if parent is None else None
    try:
        yield
        _check("read")
    finally:
        _end_call(call)
        _DEADLINE.reset(token)


def _budgeted(function):
    @wraps(function)
    def wrapped(*args, timeout=None, **kwargs):
        with _operation(timeout):
            failure = None
            try:
                with _redact("read"):
                    return function(*args, **kwargs)
            except ReadError as error:
                failure = error
            failure.__context__ = failure.__cause__ = None
            raise failure from None
    return wrapped


def _async_budgeted(function):
    @wraps(function)
    async def wrapped(*args, timeout=None, **kwargs):
        with _operation(timeout):
            failure = None
            try:
                with _redact("read"):
                    return await function(*args, **kwargs)
            except ReadError as error:
                failure = error
            failure.__context__ = failure.__cause__ = None
            raise failure from None
    return wrapped


def _call(phase, function, *args, **kwargs):
    with _timed(phase):
        _check(phase)
        failure = None
        try:
            with _redact(phase):
                result = function(*args, **kwargs)
        except ReadError as error:
            failure = error
        if failure is not None:
            failure.__context__ = failure.__cause__ = None
            raise failure from None
        _check(phase)
        return result


async def _await(phase, function, *args, **kwargs):
    with _timed(phase):
        _check(phase)
        failure = None
        try:
            with _redact(phase):
                result = await function(*args, **kwargs)
        except ReadError as error:
            failure = error
        if failure is not None:
            failure.__context__ = failure.__cause__ = None
            raise failure from None
        _check(phase)
        return result


@contextmanager
def _connection(connect, db_url):
    _check("connect")
    with _timed("connect"), _redact("connect"):
        connection = connect(db_url)
    # Enter ownership before checking a connection that arrived after expiry.
    with _redact("cleanup"):
        with _owned(connection) as opened:
            with _redact("read"):
                _check("connect")
                yield opened
    _check("cleanup")


@asynccontextmanager
async def _async_connection(connect, db_url):
    _check("connect")
    with _timed("connect"), _redact("connect"):
        connection = await connect(db_url)
    with _redact("cleanup"):
        async with _owned(connection) as opened:
            with _redact("read"):
                _check("connect")
                yield opened
    _check("cleanup")


@contextmanager
def _lock(lock, phase):
    # Time only the wait for the lock, not the period it is held.
    with _timed(phase):
        remaining = _remaining(phase)
        if remaining is None:
            acquired = lock.acquire()
        else:
            acquired = lock.acquire(timeout=min(remaining, threading.TIMEOUT_MAX))
        if not acquired:
            raise _expired(phase) from None
    try:
        _check(phase)
        yield
    finally:
        lock.release()


@asynccontextmanager
async def _async_lock(lock, phase):
    with _timed(phase):
        remaining = _remaining(phase)
        if remaining is None:
            await lock.acquire()
        else:
            try:
                await asyncio.wait_for(lock.acquire(), remaining)
            except TimeoutError:
                raise _expired(phase) from None
    try:
        _check(phase)
        yield
    finally:
        lock.release()
