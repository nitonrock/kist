"""Opt-in tests. KIST_TEST_DATABASE_URL must point to a disposable test DB."""
import asyncio
import os
import uuid
from unittest.mock import MagicMock

import pytest

from kist import core
from kist import runtime_reads as rr
from kist.core import DecryptionError, Kist, KistScope


@pytest.fixture
def db():
    url = os.getenv("KIST_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set KIST_TEST_DATABASE_URL to a disposable PostgreSQL database.")
    scope = KistScope(organization="kist-runtime-tests", project=uuid.uuid4().hex)
    store = Kist(profile_name="default", password="runtime-test-password", db_url=url, scope=scope)
    store.init_db()
    store.set("database.host", "localhost")
    store.set("database.port", 5432)
    store.set("nullable", None)
    try:
        yield store
    finally:
        store.delete_profile()


def test_postgres_sync_batch_and_session(db, monkeypatch):
    derive = MagicMock(wraps=core._derive_aes_key)
    monkeypatch.setattr(core, "_derive_aes_key", derive)
    assert db.get_many(["database.host", "database.port"]) == {
        "database.host": "localhost", "database.port": 5432}
    assert derive.call_count == 1
    with db.session() as session:
        assert session.get_many(["database.host", "database.port"])["database.port"] == 5432
        assert session.get("nullable") is None
        assert derive.call_count == 2
    assert db.get_many(["absent"], default=None) == {"absent": None}


def test_postgres_async_native_sql_and_session(db, monkeypatch):
    async def run():
        # Fresh scope IDs exercise native async scope creation too.
        source = Kist(profile_name=db.profile_name, password=db.password,
                      db_url=db.db_url, scope=db.scope)
        client = source.as_async()
        derive = MagicMock(wraps=core._derive_aes_key)
        monkeypatch.setattr(core, "_derive_aes_key", derive)
        blocked = MagicMock(side_effect=AssertionError("Synchronous database operation"))
        with monkeypatch.context() as patch:
            patch.setattr(core, "safe_db_connect", blocked)
            patch.setattr(rr, "safe_db_connect", blocked)
            assert await client.get_many(["database.host", "database.port"]) == {
                "database.host": "localhost", "database.port": 5432}
            assert derive.call_count == 1
            async with client.session() as session:
                assert await session.get("database.host") == "localhost"
                assert await session.get("nullable") is None
                assert derive.call_count == 2
            assert await client.get_many(["absent"], default=None) == {"absent": None}
    asyncio.run(run())


def test_rewrap_and_rotation_invalidate_sessions(db):
    with db.session() as session:
        assert session.get("database.port") == 5432
        db.rewrap_profile_password("replacement-password")
        with pytest.raises(DecryptionError):
            session.get("database.port")
    with db.session() as session:
        assert session.get("database.port") == 5432
        db.rotate_profile_keys("rotated-password")
        with pytest.raises(DecryptionError):
            session.get("database.port")


def test_async_rewrap_invalidates_session(db):
    async def run():
        async with db.async_session() as session:
            assert await session.get("database.port") == 5432
            # The test mutation is synchronous; async read operations remain native.
            db.rewrap_profile_password("replacement-password")
            with pytest.raises(DecryptionError):
                await session.get("database.port")
    asyncio.run(run())


# Database-budget faults use a fallback server timeout to avoid an indefinite
# hang if the implementation regresses. The tighter per-read budget must win.
@pytest.mark.parametrize("session_mode", [False, True])
@pytest.mark.parametrize("bulk", [False, True])
def test_postgres_sync_read_lock_timeout_and_recovery(db, monkeypatch, session_mode, bulk):
    from contextlib import nullcontext

    from kist._read_policy import _ReadTimeoutError

    original = core.safe_db_connect
    opened = []

    def connect(url):
        connection = original(url, options="-c statement_timeout=6000")
        opened.append(connection)
        return connection

    context = db.session() if session_mode else nullcontext(db)
    with context as reader:
        assert reader.get("database.port") == 5432
        with original(db.db_url) as blocker:
            blocker.execute("LOCK TABLE kist_secrets IN ACCESS EXCLUSIVE MODE")
            with monkeypatch.context() as patch:
                patch.setattr(core, "safe_db_connect", connect)
                patch.setattr(rr, "safe_db_connect", connect)
                with pytest.raises(_ReadTimeoutError) as caught:
                    if bulk:
                        reader.get_many(["database.port"], timeout=2)
                    else:
                        reader.get("database.port", timeout=2)
            assert caught.value.phase == "query"
            assert caught.value.__context__ is None
            assert opened and all(connection.closed for connection in opened)
        # The same reader/session must remain usable after rollback and closure.
        assert reader.get("database.port", timeout=2) == 5432


@pytest.mark.parametrize("session_mode", [False, True])
@pytest.mark.parametrize("bulk", [False, True])
def test_postgres_async_read_lock_timeout_and_recovery(db, monkeypatch, session_mode, bulk):
    from kist._read_policy import _ReadTimeoutError

    original = core.safe_async_db_connect
    opened = []

    async def connect(url):
        connection = await original(url, options="-c statement_timeout=6000")
        opened.append(connection)
        return connection

    async def run():
        client = db.as_async()
        reader = client.session() if session_mode else client
        try:
            assert await reader.get("database.port") == 5432
            # Only the fault injector is synchronous, not the read under test.
            with core.safe_db_connect(db.db_url) as blocker:
                blocker.execute("LOCK TABLE kist_secrets IN ACCESS EXCLUSIVE MODE")
                with monkeypatch.context() as patch:
                    patch.setattr(rr, "safe_async_db_connect", connect)
                    with pytest.raises(_ReadTimeoutError) as caught:
                        if bulk:
                            await reader.get_many(["database.port"], timeout=2)
                        else:
                            await reader.get("database.port", timeout=2)
                assert caught.value.phase == "query"
                assert caught.value.__context__ is None
                assert opened and all(connection.closed for connection in opened)
            assert await reader.get("database.port", timeout=2) == 5432
        finally:
            if session_mode:
                await reader.close()

    asyncio.run(run())


def test_postgres_sync_scope_lock_timeout_and_recovery(db, monkeypatch):
    from kist._read_policy import _ReadTimeoutError

    fresh = Kist(profile_name=db.profile_name, password=db.password,
                 db_url=db.db_url, scope=db.scope)
    original = core.safe_db_connect
    opened = []

    def connect(url):
        connection = original(url, options="-c statement_timeout=6000")
        opened.append(connection)
        return connection

    with original(db.db_url) as blocker:
        blocker.execute("UPDATE kist_organizations SET slug = slug WHERE id = %s",
                        (db.organization_id,))
        with monkeypatch.context() as patch:
            patch.setattr(core, "safe_db_connect", connect)
            with pytest.raises(_ReadTimeoutError) as caught:
                fresh.get("database.port", timeout=1)
        assert caught.value.phase == "query"
        assert fresh.profile_id is None
        assert opened and all(connection.closed for connection in opened)
    assert fresh.get("database.port", timeout=2) == 5432


def test_postgres_async_scope_lock_timeout_and_recovery(db, monkeypatch):
    from kist._read_policy import _ReadTimeoutError

    original = core.safe_async_db_connect
    opened = []

    async def connect(url):
        connection = await original(url, options="-c statement_timeout=6000")
        opened.append(connection)
        return connection

    async def run():
        fresh = Kist(profile_name=db.profile_name, password=db.password,
                     db_url=db.db_url, scope=db.scope).as_async()
        with core.safe_db_connect(db.db_url) as blocker:
            blocker.execute("UPDATE kist_organizations SET slug = slug WHERE id = %s",
                            (db.organization_id,))
            with monkeypatch.context() as patch:
                patch.setattr(rr, "safe_async_db_connect", connect)
                with pytest.raises(_ReadTimeoutError) as caught:
                    await fresh.get("database.port", timeout=1)
            assert caught.value.phase == "query"
            assert fresh.profile_id is None
            assert not fresh._scope_lock.locked()
            assert opened and all(connection.closed for connection in opened)
        assert await fresh.get("database.port", timeout=2) == 5432

    asyncio.run(run())


def test_postgres_sync_sleep_timeout_and_recovery(db):
    from kist._read_budget import _connection, _operation
    from kist._read_policy import _ReadTimeoutError
    from kist._read_sql import _cursor

    connection = core.safe_db_connect(db.db_url, options="-c statement_timeout=6000")
    with pytest.raises(_ReadTimeoutError) as caught:
        with _operation(0.1):
            with _connection(lambda url: connection, db.db_url) as owned:
                with _cursor(owned) as cursor:
                    cursor.execute("SELECT pg_sleep(2)")
    assert caught.value.phase == "query"
    assert caught.value.__context__ is None
    assert connection.closed
    assert db.get("database.port", timeout=2) == 5432


def test_postgres_async_sleep_timeout_and_recovery(db):
    from kist._read_budget import _async_connection, _operation
    from kist._read_policy import _ReadTimeoutError
    from kist._read_sql import _async_cursor

    async def run():
        connection = await core.safe_async_db_connect(
            db.db_url, options="-c statement_timeout=6000")

        async def connect(url):
            return connection

        with pytest.raises(_ReadTimeoutError) as caught:
            with _operation(0.1):
                async with _async_connection(connect, db.db_url) as owned:
                    async with _async_cursor(owned) as cursor:
                        await cursor.execute("SELECT pg_sleep(2)")
        assert caught.value.phase == "query"
        assert caught.value.__context__ is None
        assert connection.closed
        assert await db.as_async().get("database.port", timeout=2) == 5432

    asyncio.run(run())


@pytest.mark.parametrize("native_async", [False, True])
def test_postgres_stricter_operator_statement_limit_is_preserved(db, native_async):
    from psycopg.errors import QueryCanceled

    from kist._read_budget import _operation
    from kist._read_sql import _async_cursor, _cursor

    if not native_async:
        with core.safe_db_connect(db.db_url, options="-c statement_timeout=25") as connection:
            with pytest.raises(QueryCanceled):
                with _operation(2):
                    with _cursor(connection) as cursor:
                        cursor.execute("SELECT pg_sleep(1)")
            connection.rollback()
            assert connection.execute("SHOW statement_timeout").fetchone()[0] == "25ms"
        return

    async def run():
        async with await core.safe_async_db_connect(
                db.db_url, options="-c statement_timeout=25") as connection:
            with pytest.raises(QueryCanceled):
                with _operation(2):
                    async with _async_cursor(connection) as cursor:
                        await cursor.execute("SELECT pg_sleep(1)")
            await connection.rollback()
            cursor = await connection.execute("SHOW statement_timeout")
            assert (await cursor.fetchone())[0] == "25ms"

    asyncio.run(run())


def test_postgres_external_async_cancellation_closes_connection(db):
    from kist._read_budget import _async_connection, _operation
    from kist._read_sql import _async_cursor

    async def run():
        connection = await core.safe_async_db_connect(
            db.db_url, options="-c statement_timeout=6000")
        started = asyncio.Event()

        async def connect(url):
            return connection

        async def operation():
            with _operation(5):
                async with _async_connection(connect, db.db_url) as owned:
                    async with _async_cursor(owned) as cursor:
                        started.set()
                        await cursor.execute("SELECT pg_sleep(10)")

        task = asyncio.create_task(operation())
        await started.wait()
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled()
        assert connection.closed
        assert await db.as_async().get("database.port", timeout=2) == 5432

    asyncio.run(run())
