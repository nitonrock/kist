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
