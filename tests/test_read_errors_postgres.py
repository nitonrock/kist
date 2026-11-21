"""Real server SQLSTATE redaction at public sync/native-async read boundaries."""
import asyncio
import os
import uuid

import pytest

from kist import ReadDatabaseError, ReadTimeoutError, core
from kist import runtime_reads as reads
from kist.core import Kist, KistScope

_MARKER = "private-read-diagnostic"
_STATEMENTS = {
    "42501": "DO $$ BEGIN RAISE EXCEPTION USING ERRCODE = '42501', "
             "MESSAGE = 'private-read-diagnostic'; END $$",
    "57014": "DO $$ BEGIN RAISE EXCEPTION USING ERRCODE = '57014', "
             "MESSAGE = 'private-read-diagnostic'; END $$",
}


@pytest.fixture
def store():
    url = os.getenv("KIST_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set KIST_TEST_DATABASE_URL to a disposable PostgreSQL database.")
    reader = Kist(profile_name="default", password="read-error-test-password",
                  db_url=url, scope=KistScope(organization="kist-read-error-tests",
                                            project=uuid.uuid4().hex))
    reader.init_db()
    reader.set("example.value", 7)
    try:
        yield reader
    finally:
        reader.delete_profile()


def check(error, state, opened):
    assert error.sqlstate == state
    assert error.phase == "schema_check"
    assert error.reason_code == ("database_permission_denied" if state == "42501"
                                 else "database_query_cancelled")
    assert not isinstance(error, ReadTimeoutError)
    assert error.__context__ is None
    assert error.__cause__ is None
    assert _MARKER not in str(error)
    assert _MARKER not in repr(vars(error))
    assert opened and all(connection.closed for connection in opened)


@pytest.mark.parametrize("state", ["42501", "57014"])
@pytest.mark.parametrize("timeout", [None, 2])
@pytest.mark.parametrize("native_async", [False, True])
def test_postgres_public_read_error_and_recovery(store, monkeypatch, state, timeout, native_async):
    opened = []
    if not native_async:
        original = core.safe_db_connect

        def connect(url):
            connection = original(url)
            opened.append(connection)
            return connection

        def fail_schema(self, cursor):
            cursor.execute(_STATEMENTS[state])

        with monkeypatch.context() as patch:
            patch.setattr(core, "safe_db_connect", connect)
            patch.setattr(Kist, "_check_schema", fail_schema)
            with pytest.raises(ReadDatabaseError) as caught:
                store.get("example.value", timeout=timeout)
        check(caught.value, state, opened)
        assert store.get("example.value", timeout=2) == 7
        return

    original = reads.safe_async_db_connect

    async def connect(url):
        connection = await original(url)
        opened.append(connection)
        return connection

    async def fail_schema(self, cursor):
        await cursor.execute(_STATEMENTS[state])

    async def run():
        client = store.as_async()
        with monkeypatch.context() as patch:
            patch.setattr(reads, "safe_async_db_connect", connect)
            patch.setattr(reads.AsyncKist, "_check_schema", fail_schema)
            with pytest.raises(ReadDatabaseError) as caught:
                await client.get("example.value", timeout=timeout)
        check(caught.value, state, opened)
        assert await client.get("example.value", timeout=2) == 7

    asyncio.run(run())
