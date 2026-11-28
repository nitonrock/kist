"""Opt-in phase timings for database-backed reads.

Use trace_reads() around one or more reads to see where time went. Records hold
only phase names, numbers, and a fixed outcome vocabulary: never secret names,
SQL, URLs, or exception text. Nothing is recorded, and little work is done,
when no trace is active.

Timings are diagnostics, not guarantees. A phase's seconds measure the time
Kist spent waiting in or calling that phase; they do not stop SQL, key
derivation, or cleanup, and they do not add a stronger deadline.
"""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

import psycopg

from kist.read_errors import ReadDatabaseError, ReadTimeoutError

_MAX_RECORDS = 1000
_OUTCOMES = frozenset({"ok", "timeout", "database_error", "error", "cancelled"})
_clock = time.perf_counter


def _now():
    return _clock()


@dataclass(frozen=True)
class PhaseTiming:
    """One timed phase.

    call numbers each top-level read within a trace, starting at 1. depth is 0
    for a top-level phase and greater when a phase ran inside another one, so
    nested records overlap with their parents and must not be summed together.
    """

    call: int
    phase: str
    depth: int
    seconds: float
    outcome: str


class ReadTrace:
    """Bounded, thread-safe collection of PhaseTiming records."""

    def __init__(self):
        self._lock = threading.Lock()
        self._records = []
        self._calls = 0
        self.dropped = 0

    @property
    def records(self):
        with self._lock:
            return tuple(self._records)

    def totals(self, call=None):
        """Seconds per phase, counting top-level records only (no double count)."""
        totals = {}
        for record in self.records:
            if record.depth == 0 and (call is None or record.call == call):
                totals[record.phase] = totals.get(record.phase, 0.0) + record.seconds
        return totals

    def _next_call(self):
        with self._lock:
            self._calls += 1
            return self._calls

    def _add(self, record):
        with self._lock:
            if len(self._records) >= _MAX_RECORDS:
                self.dropped += 1
            else:
                self._records.append(record)


_TRACE: ContextVar[ReadTrace | None] = ContextVar("kist_read_trace", default=None)
_DEPTH: ContextVar[int] = ContextVar("kist_read_trace_depth", default=0)
_CALL: ContextVar[int] = ContextVar("kist_read_trace_call", default=0)


@contextmanager
def trace_reads():
    """Collect phase timings for reads made inside the block.

    Reads made in the same thread or asyncio task, including worker threads
    started by Kist with a copied context, are recorded. A nested trace_reads()
    replaces the outer one for its duration.
    """
    trace = ReadTrace()
    token = _TRACE.set(trace)
    try:
        yield trace
    finally:
        _TRACE.reset(token)


def _outcome(error):
    if error is None:
        return "ok"
    if isinstance(error, ReadTimeoutError):
        return "timeout"
    if isinstance(error, (ReadDatabaseError, psycopg.Error)):
        return "database_error"
    return "error" if isinstance(error, Exception) else "cancelled"


def _record(trace, phase, depth, seconds, error):
    trace._add(PhaseTiming(_CALL.get(), phase, depth, max(0.0, seconds), _outcome(error)))


class _Timed:
    __slots__ = ("phase", "trace", "depth", "start", "token")

    def __init__(self, phase):
        self.phase = phase
        self.trace = _TRACE.get()

    def __enter__(self):
        if self.trace is not None:
            self.depth = _DEPTH.get()
            self.token = _DEPTH.set(self.depth + 1)
            self.start = _now()
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self.trace is not None:
            seconds = _now() - self.start
            _DEPTH.reset(self.token)
            _record(self.trace, self.phase, self.depth, seconds, exc)
        return False


def _timed(phase):
    return _Timed(phase)


def _start_call():
    trace = _TRACE.get()
    return None if trace is None else _CALL.set(trace._next_call())


def _end_call(token):
    if token is not None:
        _CALL.reset(token)


class _Owned:
    """Time only the exit of a connection context, as the cleanup phase."""

    def __init__(self, connection):
        self._connection = connection

    def _finish(self, trace, depth, start, error):
        _record(trace, "cleanup", depth, _now() - start, error)

    def __enter__(self):
        return self._connection.__enter__()

    def __exit__(self, *exc):
        trace = _TRACE.get()
        if trace is None:
            return self._connection.__exit__(*exc)
        depth, start, failure = _DEPTH.get(), _now(), None
        try:
            return self._connection.__exit__(*exc)
        except BaseException as error:
            failure = error
            raise
        finally:
            self._finish(trace, depth, start, failure)

    async def __aenter__(self):
        return await self._connection.__aenter__()

    async def __aexit__(self, *exc):
        trace = _TRACE.get()
        if trace is None:
            return await self._connection.__aexit__(*exc)
        depth, start, failure = _DEPTH.get(), _now(), None
        try:
            return await self._connection.__aexit__(*exc)
        except BaseException as error:
            failure = error
            raise
        finally:
            self._finish(trace, depth, start, failure)


def _owned(connection):
    return _Owned(connection)
