"""Opt-in read phase timings. No database and no real crypto required."""
import asyncio
import contextvars
import threading
from unittest.mock import MagicMock

import psycopg
import pytest

from kist import PhaseTiming, ReadTrace, read_trace, trace_reads
from kist import _read_budget as budget
from kist._read_policy import _ReadDeadline
from kist.read_errors import _PHASES, ReadDatabaseError, ReadTimeoutError

_PRIVATE_NAME = "vendor.private.api_key"


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    value = Clock()
    monkeypatch.setattr(read_trace, "_clock", value)
    return value


def test_nothing_is_recorded_without_a_trace(clock):
    assert budget._call("query", lambda: 5) == 5
    with trace_reads() as trace:
        pass
    assert trace.records == ()
    assert read_trace._TRACE.get() is None


def test_call_records_phase_seconds_and_ok(clock):
    with trace_reads() as trace:
        assert budget._call("query", lambda: clock.advance(0.25) or "value") == "value"
    (record,) = trace.records
    assert (record.phase, record.depth, record.seconds, record.outcome) == ("query", 0, 0.25, "ok")
    assert record.call == 0
    assert trace.totals() == {"query": 0.25}


def test_nested_phases_are_marked_and_not_double_counted(clock):
    def outer():
        clock.advance(1.0)
        budget._call("query", clock.advance, 0.5)
        clock.advance(1.0)

    with trace_reads() as trace:
        budget._call("schema_check", outer)
    inner, parent = trace.records
    assert (inner.phase, inner.depth, inner.seconds) == ("query", 1, 0.5)
    assert (parent.phase, parent.depth, parent.seconds) == ("schema_check", 0, 2.5)
    assert trace.totals() == {"schema_check": 2.5}


def test_unlock_wrapping_derivation_reports_one_top_level_total(clock):
    def unlock():
        budget._call("key_unlock", clock.advance, 0.75)

    with trace_reads() as trace:
        budget._call("key_unlock", unlock)
    assert [record.depth for record in trace.records] == [1, 0]
    assert trace.totals() == {"key_unlock": 0.75}


def test_outcome_vocabulary(clock):
    def raises(error):
        def run():
            raise error
        return run

    with trace_reads() as trace:
        with pytest.raises(KeyError):
            budget._call("decrypt", raises(KeyError("x")))
        with pytest.raises(psycopg.OperationalError):
            budget._call("query", raises(psycopg.OperationalError("raw")))
        token = budget._DEADLINE.set(_ReadDeadline(5, clock=clock))
        try:
            with pytest.raises(ReadDatabaseError):
                budget._call("query", raises(psycopg.OperationalError("wrapped")))
            clock.advance(10)
            with pytest.raises(ReadTimeoutError):
                budget._call("query", lambda: 1)
        finally:
            budget._DEADLINE.reset(token)
    assert [record.outcome for record in trace.records] == [
        "error", "database_error", "database_error", "timeout"]
    assert {record.outcome for record in trace.records} <= read_trace._OUTCOMES


def test_cancellation_is_classified_without_being_swallowed(clock):
    async def stalls():
        raise asyncio.CancelledError

    async def run():
        with trace_reads() as trace:
            with pytest.raises(asyncio.CancelledError):
                await budget._await("query", stalls)
        return trace

    (record,) = asyncio.run(run()).records
    assert record.outcome == "cancelled"


def test_async_await_records_and_offloaded_worker_nests(clock):
    def work():
        budget._call("decrypt", clock.advance, 0.5)
        return "done"

    async def run():
        with trace_reads() as trace:
            assert await budget._await("decrypt", asyncio.to_thread, work) == "done"
        return trace

    trace = asyncio.run(run())
    assert [(record.depth, record.phase) for record in trace.records] == [
        (1, "decrypt"), (0, "decrypt")]
    assert trace.totals() == {"decrypt": 0.5}


def test_sync_connection_records_connect_and_cleanup(clock):
    opened = object()
    manager = MagicMock()
    manager.__enter__.return_value = opened

    def exit_slowly(*args):
        clock.advance(0.5)
        return False

    manager.__exit__.side_effect = exit_slowly

    def connect(url):
        clock.advance(2.0)
        return manager

    with trace_reads() as trace:
        with budget._connection(connect, "unused") as connection:
            assert connection is opened
            clock.advance(10.0)
    assert [(record.phase, record.seconds, record.outcome) for record in trace.records] == [
        ("connect", 2.0, "ok"), ("cleanup", 0.5, "ok")]


def test_async_connection_records_connect_and_cleanup(clock):
    opened = object()

    class Manager:
        async def __aenter__(self):
            return opened

        async def __aexit__(self, *args):
            clock.advance(0.5)
            return False

    async def connect(url):
        clock.advance(2.0)
        return Manager()

    async def run():
        with trace_reads() as trace:
            async with budget._async_connection(connect, "unused") as connection:
                assert connection is opened
                clock.advance(10.0)
        return trace

    assert [(r.phase, r.seconds, r.outcome) for r in asyncio.run(run()).records] == [
        ("connect", 2.0, "ok"), ("cleanup", 0.5, "ok")]


def test_connection_failures_and_cleanup_failures_are_attributed(clock):
    def refuse(url):
        raise psycopg.OperationalError("down")

    with trace_reads() as trace:
        with pytest.raises(psycopg.OperationalError):
            with budget._connection(refuse, "unused"):
                pytest.fail("not reached")
    assert [(r.phase, r.outcome) for r in trace.records] == [("connect", "database_error")]

    manager = MagicMock()
    manager.__enter__.return_value = object()
    manager.__exit__.side_effect = psycopg.OperationalError("close failed")
    with trace_reads() as trace:
        with pytest.raises(psycopg.OperationalError):
            with budget._connection(lambda url: manager, "unused"):
                pass
    assert [(r.phase, r.outcome) for r in trace.records] == [
        ("connect", "ok"), ("cleanup", "database_error")]


def test_body_failure_is_not_blamed_on_cleanup(clock):
    manager = MagicMock()
    manager.__enter__.return_value = object()
    manager.__exit__.return_value = False
    with trace_reads() as trace:
        with pytest.raises(KeyError):
            with budget._connection(lambda url: manager, "unused"):
                raise KeyError("body")
    assert trace.records[-1].phase == "cleanup"
    assert trace.records[-1].outcome == "ok"


def test_lock_records_wait_not_hold_time(clock):
    lock = threading.RLock()
    with trace_reads() as trace:
        with budget._lock(lock, "cache_wait"):
            clock.advance(5.0)
    (record,) = trace.records
    assert (record.phase, record.seconds) == ("cache_wait", 0.0)


def test_async_lock_records_wait_phase_and_timeout(clock):
    async def run():
        lock = asyncio.Lock()
        with trace_reads() as trace:
            async with budget._async_lock(lock, "scope_wait"):
                pass
            await lock.acquire()
            token = budget._DEADLINE.set(_ReadDeadline(0.01))
            try:
                with pytest.raises(ReadTimeoutError):
                    async with budget._async_lock(lock, "scope_wait"):
                        pytest.fail("not reached")
            finally:
                budget._DEADLINE.reset(token)
                lock.release()
        return trace

    assert [(r.phase, r.outcome) for r in asyncio.run(run()).records] == [
        ("scope_wait", "ok"), ("scope_wait", "timeout")]


def test_reads_get_call_numbers_and_delegation_shares_one(clock):
    @budget._budgeted
    def inner():
        return budget._call("query", lambda: 1)

    @budget._budgeted
    def outer():
        return inner()

    @budget._budgeted
    def outer_with_own_timeout():
        return inner(timeout=5)

    with trace_reads() as trace:
        assert inner() == 1
        assert outer() == 1
        assert outer_with_own_timeout() == 1
    assert [record.call for record in trace.records] == [1, 2, 3]
    assert read_trace._CALL.get() == 0
    assert trace.totals(call=2) == {"query": 0.0}


def test_trace_is_bounded_and_counts_drops(clock):
    with trace_reads() as trace:
        for _ in range(read_trace._MAX_RECORDS + 7):
            budget._call("query", lambda: None)
    assert len(trace.records) == read_trace._MAX_RECORDS
    assert trace.dropped == 7


def test_concurrent_threads_record_safely(clock):
    def work():
        for _ in range(50):
            budget._call("query", int)

    with trace_reads() as trace:
        threads = [threading.Thread(target=contextvars.copy_context().run, args=(work,))
                   for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert len(trace.records) == 200


def test_records_are_immutable_and_contain_no_names_or_text(clock):
    def fails():
        raise psycopg.OperationalError(f"password=hunter2 {_PRIVATE_NAME}")

    with trace_reads() as trace:
        budget._call("query", lambda: _PRIVATE_NAME)
        with pytest.raises(psycopg.OperationalError):
            budget._call("query", fails)
    text = repr(trace.records) + repr(vars(trace).keys())
    assert _PRIVATE_NAME not in text
    assert "hunter2" not in text
    assert all(record.phase in _PHASES for record in trace.records)
    assert set(PhaseTiming.__dataclass_fields__) == {"call", "phase", "depth", "seconds", "outcome"}
    with pytest.raises(AttributeError):
        trace.records[0].seconds = 1.0


def test_nested_trace_replaces_outer_and_exit_restores(clock):
    with trace_reads() as outer:
        with trace_reads() as inner:
            budget._call("query", int)
        budget._call("decrypt", int)
    assert [record.phase for record in inner.records] == ["query"]
    assert [record.phase for record in outer.records] == ["decrypt"]
    assert read_trace._DEPTH.get() == 0
    assert isinstance(outer, ReadTrace)
