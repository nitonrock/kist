"""Sanitised public failures from database-backed read APIs.

Only controlled metadata is copied out of a driver exception. This does not
sanitise arbitrary tracebacks with local-variable capture or PostgreSQL logs.
"""
from __future__ import annotations

import math
import re
from contextlib import contextmanager

import psycopg

from kist.core import KistError

_PHASES = frozenset({
    "read", "scope_wait", "scope_init", "connection_acquire", "connect",
    "schema_check", "derivation_wait", "key_unlock", "query", "decrypt",
    "cache_wait", "cleanup",
})
_MESSAGES = {
    "read_deadline_exceeded": "Read deadline exceeded",
    "database_authentication_failed": "Database authentication failed",
    "database_permission_denied": "Database permission denied",
    "database_connection_failed": "Database connection failed",
    "database_query_cancelled": "Database statement cancelled",
    "database_serialization_failure": "Database transaction could not be serialised",
    "database_deadlock": "Database transaction encountered a deadlock",
    "database_unavailable": "Database is temporarily unavailable",
    "database_operation_failed": "Database operation failed",
}
# A hint to the application, never an automatic retry or a no-side-effects claim.
_RETRYABLE = frozenset({"database_serialization_failure", "database_deadlock"})


def _phase(value):
    if not isinstance(value, str) or value not in _PHASES:
        raise ValueError("Unknown read phase.")
    return value


def _sqlstate(value):
    return value if type(value) is str and re.fullmatch(r"[0-9A-Z]{5}", value) else None


class ReadError(KistError):
    """Base for structured database-read failures and read deadlines.

    phase is a checkpoint, not proof of the root cause. retryable is advisory.
    All messages use fixed vocabulary; raw driver diagnostics are not stored.
    """

    def __init__(self, *, phase, elapsed_seconds, reason_code, sqlstate=None):
        self.phase = _phase(phase)
        if type(reason_code) is not str or reason_code not in _MESSAGES:
            raise ValueError("Unknown read failure reason.")
        if (type(elapsed_seconds) not in (int, float)
                or not math.isfinite(elapsed_seconds) or elapsed_seconds < 0):
            raise ValueError("Read elapsed time must be finite and nonnegative.")
        self.elapsed_seconds = float(elapsed_seconds)
        self.reason_code = reason_code
        self.sqlstate = _sqlstate(sqlstate)
        self.retryable = reason_code in _RETRYABLE
        super().__init__(f"{_MESSAGES[reason_code]} during {self.phase}.")


class ReadDatabaseError(ReadError):
    """A sanitised psycopg failure from a database-backed read boundary."""


class ReadTimeoutError(ReadError, TimeoutError):
    """A read-owned deadline; still catchable as KistError and TimeoutError."""

    def __init__(self, *, phase, elapsed_seconds):
        super().__init__(phase=phase, elapsed_seconds=elapsed_seconds,
                         reason_code="read_deadline_exceeded")


def _elapsed():
    from kist._read_budget import _DEADLINE

    deadline = _DEADLINE.get()
    return 0.0 if deadline is None else deadline.elapsed_seconds


def _database_failure(error, phase):
    state = _sqlstate(error.sqlstate)
    if state is not None and state.startswith("28"):
        reason = "database_authentication_failed"
    elif state == "42501":
        reason = "database_permission_denied"
    elif state == "57014":
        reason = "database_query_cancelled"
    elif state == "40001":
        reason = "database_serialization_failure"
    elif state == "40P01":
        reason = "database_deadlock"
    elif state in {"53300", "57P03"}:
        reason = "database_unavailable"
    elif phase == "connect" or (state is not None and state.startswith("08")):
        reason = "database_connection_failed"
    else:
        reason = "database_operation_failed"
    return ReadDatabaseError(phase=phase, elapsed_seconds=_elapsed(),
                             reason_code=reason, sqlstate=state)


def _connection_failure(error):
    from kist._read_budget import _DEADLINE

    # Public read decorators also create a context for timeout=None.
    # CLI/write/admin connections outside such a context keep their old errors.
    if _DEADLINE.get() is None:
        return None
    return _database_failure(error, "connect")


@contextmanager
def _redact(phase):
    failure = None
    try:
        yield
    except psycopg.Error as error:
        from kist._read_budget import _DEADLINE

        if _DEADLINE.get() is None:
            raise
        failure = _database_failure(error, phase)
    # Public read boundaries clear contextlib-assigned exception context too.
    if failure is not None:
        raise failure from None
