"""Public read errors: structured metadata without driver diagnostic retention."""
import asyncio
import traceback

import psycopg
import pytest

from kist import ReadDatabaseError, ReadError, ReadTimeoutError, core
from kist import _read_budget as budget
from kist._read_policy import _ReadTimeoutError
from kist.read_errors import _database_failure

_SECRET = "diagnostic-password-and-private-secret-name"


def fault(state=None, cls=psycopg.Error):
    return type("DriverFault", (cls,), {"sqlstate": state})(_SECRET)


def assert_safe(error):
    assert _SECRET not in str(error)
    assert _SECRET not in repr(vars(error))
    assert _SECRET not in "".join(traceback.format_exception(error))
    assert error.__cause__ is None
    assert error.__context__ is None


@pytest.mark.parametrize(("state", "reason", "retryable"), [
    ("28P01", "database_authentication_failed", False),
    ("28000", "database_authentication_failed", False),
    ("42501", "database_permission_denied", False),
    ("57014", "database_query_cancelled", False),
    ("40001", "database_serialization_failure", True),
    ("40P01", "database_deadlock", True),
    ("53300", "database_unavailable", False),
    ("57P03", "database_unavailable", False),
    ("08006", "database_connection_failed", False),
    ("42P01", "database_operation_failed", False),
    (None, "database_operation_failed", False),
])
def test_sqlstate_classification(state, reason, retryable):
    error = _database_failure(fault(state), "query")
    assert isinstance(error, (ReadError, core.KistError))
    assert error.reason_code == reason
    assert error.sqlstate == state
    assert error.retryable is retryable
    assert error.phase == "query"
    assert_safe(error)


@pytest.mark.parametrize("state", [_SECRET, "bad", "28p01", 42501, object()])
def test_untrusted_sqlstate_is_not_retained(state):
    error = _database_failure(fault(state), "query")
    assert error.sqlstate is None
    assert error.reason_code == "database_operation_failed"
    assert_safe(error)


def test_public_timeout_alias_preserves_catches():
    assert _ReadTimeoutError is ReadTimeoutError
    error = ReadTimeoutError(phase="query", elapsed_seconds=1)
    assert isinstance(error, ReadError)
    assert isinstance(error, core.KistError)
    assert isinstance(error, TimeoutError)
    assert error.sqlstate is None
    assert not error.retryable
    assert str(error) == "Read deadline exceeded during query."


@pytest.mark.parametrize("phase", ["query", "schema_check", "scope_init", "cleanup"])
def test_phase_boundary_has_no_driver_context(phase):
    def failure():
        raise fault("42501")

    with pytest.raises(ReadDatabaseError) as caught:
        with budget._operation(None):
            budget._call(phase, failure)
    assert caught.value.phase == phase
    assert_safe(caught.value)
    assert budget._DEADLINE.get() is None


def test_non_read_boundary_preserves_driver_error():
    original = fault("42501")

    def failure():
        raise original

    with pytest.raises(psycopg.Error) as caught:
        budget._call("query", failure)
    assert caught.value is original


@pytest.mark.parametrize("original", [ValueError("input"), KeyError("missing"),
                                     core.MissingKeyError("password"),
                                     core.DecryptionError("crypto")])
def test_non_driver_errors_preserved(original):
    def failure():
        raise original

    with pytest.raises(type(original)) as caught:
        with budget._operation(1):
            budget._call("query", failure)
    assert caught.value is original


def test_existing_structured_error_not_rewrapped():
    original = ReadTimeoutError(phase="query", elapsed_seconds=1)

    @budget._budgeted
    def operation():
        raise original

    with pytest.raises(ReadTimeoutError) as caught:
        operation()
    assert caught.value is original


def test_async_phase_and_cancellation():
    async def failure():
        raise fault("42501")

    async def cancelled():
        raise asyncio.CancelledError

    async def run():
        with pytest.raises(ReadDatabaseError) as caught:
            with budget._operation(None):
                await budget._await("schema_check", failure)
        assert caught.value.phase == "schema_check"
        assert_safe(caught.value)
        with pytest.raises(asyncio.CancelledError):
            with budget._operation(1):
                await budget._await("query", cancelled)
        assert budget._DEADLINE.get() is None

    asyncio.run(run())


class Connection:
    def __init__(self, fail_cleanup=False):
        self.fail_cleanup = fail_cleanup
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True
        if self.fail_cleanup:
            raise fault("08006")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return self.__exit__(*args)


def test_connection_acquisition_is_connect_phase():
    def connect(url):
        raise fault("28P01")

    @budget._budgeted
    def operation():
        with budget._connection(connect, "unused"):
            pytest.fail("unreachable")

    with pytest.raises(ReadDatabaseError) as caught:
        operation()
    assert caught.value.phase == "connect"
    assert caught.value.reason_code == "database_authentication_failed"
    assert_safe(caught.value)


def test_cleanup_failure_is_cleanup_phase():
    connection = Connection(fail_cleanup=True)
    @budget._budgeted
    def operation():
        with budget._connection(lambda url: connection, "unused"):
            pass

    with pytest.raises(ReadDatabaseError) as caught:
        operation()
    assert connection.closed
    assert caught.value.phase == "cleanup"
    assert_safe(caught.value)


def test_body_driver_failure_does_not_become_cleanup_failure():
    connection = Connection()
    @budget._budgeted
    def operation():
        with budget._connection(lambda url: connection, "unused"):
            raise fault("42501")

    with pytest.raises(ReadDatabaseError) as caught:
        operation()
    assert connection.closed
    assert caught.value.phase == "read"
    assert_safe(caught.value)


def test_async_connection_phases():
    async def run():
        connection = Connection(fail_cleanup=True)

        async def connect(url):
            return connection

        @budget._async_budgeted
        async def operation():
            async with budget._async_connection(connect, "unused"):
                pass

        with pytest.raises(ReadDatabaseError) as caught:
            await operation()
        assert connection.closed
        assert caught.value.phase == "cleanup"
        assert_safe(caught.value)

    asyncio.run(run())


def test_sync_connect_classifies_before_legacy_redaction(monkeypatch):
    def connect(*args, **kwargs):
        raise fault("28P01", psycopg.OperationalError)

    monkeypatch.setattr(core, "enforce_ssl_url", lambda url: url)
    monkeypatch.setattr(core, "_connection_kwargs", lambda url, kw: kw)
    monkeypatch.setattr(psycopg, "connect", connect)
    with pytest.raises(ReadDatabaseError) as caught:
        with budget._operation(None):
            core.safe_db_connect("postgresql://example.invalid/db")
    assert caught.value.sqlstate == "28P01"
    assert caught.value.phase == "connect"
    assert_safe(caught.value)
    with pytest.raises(psycopg.OperationalError) as legacy:
        core.safe_db_connect("postgresql://example.invalid/db")
    assert not isinstance(legacy.value, ReadError)
    assert _SECRET not in str(legacy.value)


def test_async_connect_classifies_before_legacy_redaction(monkeypatch):
    async def connect(*args, **kwargs):
        raise fault("28P01", psycopg.OperationalError)

    monkeypatch.setattr(core, "enforce_ssl_url", lambda url: url)
    monkeypatch.setattr(core, "_connection_kwargs", lambda url, kw: kw)
    monkeypatch.setattr(psycopg.AsyncConnection, "connect", connect)

    async def run():
        with pytest.raises(ReadDatabaseError) as caught:
            with budget._operation(None):
                await core.safe_async_db_connect("postgresql://example.invalid/db")
        assert caught.value.sqlstate == "28P01"
        assert caught.value.phase == "connect"
        assert_safe(caught.value)
        with pytest.raises(psycopg.OperationalError):
            await core.safe_async_db_connect("postgresql://example.invalid/db")

    asyncio.run(run())


@pytest.mark.parametrize("async_mode", [False, True])
def test_public_decorator_fallback_is_sanitised(async_mode):
    @budget._budgeted
    def sync():
        raise fault(None)

    @budget._async_budgeted
    async def native():
        raise fault(None)

    with pytest.raises(ReadDatabaseError) as caught:
        if async_mode:
            asyncio.run(native())
        else:
            sync()
    assert caught.value.phase == "read"
    assert_safe(caught.value)
