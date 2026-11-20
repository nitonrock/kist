"""Regression tests for runtime store diagnostic safety."""
import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from kist.core import KistError, MissingKeyError
from kist.stores import AsyncTTLSecretStore, DynamicSecretStore, TTLSecretStore

KEY = "example-private-service.password"
VALUE = "example-secret-value"
PASSWORD = "example-profile-password"


def backend():
    return SimpleNamespace(
        profile_name="default", profile_id="example-profile-id",
        db_url="postgresql://example.invalid/kist", password=PASSWORD,
        get=MagicMock(return_value=VALUE),
    )


def assert_safe_logs(caplog):
    assert caplog.records, "Exercise logging, not just an empty capture"
    for record in caplog.records:
        assert KEY not in record.getMessage()
        assert VALUE not in record.getMessage()
        assert PASSWORD not in record.getMessage()
        assert KEY not in repr(record.args)
        assert VALUE not in repr(record.args)
        assert PASSWORD not in repr(record.args)


def test_sync_store_logs_do_not_include_secret_names(caplog):
    caplog.set_level(logging.DEBUG, logger="kist.stores")
    source = backend()
    store = TTLSecretStore(kist=source)
    assert store.get(KEY) == VALUE
    store.invalidate(KEY)
    dynamic = DynamicSecretStore(kist=source)
    dynamic._handle_notification({"profile_name": "default", "secret_key": KEY})
    assert_safe_logs(caplog)


def test_async_store_logs_do_not_include_secret_names(caplog):
    caplog.set_level(logging.DEBUG, logger="kist.stores")

    async def run():
        source = backend()
        native = SimpleNamespace(get=AsyncMock(return_value=VALUE))
        async with AsyncTTLSecretStore(kist=source, async_kist=native) as store:
            assert await store.get(KEY) == VALUE
            await store.invalidate(KEY)
            await store._handle_notification(
                {"profile_name": "default", "secret_key": KEY}
            )

    asyncio.run(run())
    assert_safe_logs(caplog)


def test_missing_password_is_not_a_missing_secret():
    error = MissingKeyError("A profile password is required.")
    assert isinstance(error, KistError)
    assert not isinstance(error, KeyError)


def test_sync_missing_password_is_not_defaulted_or_negative_cached():
    source = backend()
    source.get.side_effect = MissingKeyError("A profile password is required.")
    store = TTLSecretStore(kist=source)
    for _ in range(2):
        with pytest.raises(MissingKeyError):
            store.get(KEY, default=None)
    assert source.get.call_count == 2
    assert KEY not in store._cache


def test_async_missing_password_is_not_defaulted_or_negative_cached():
    async def run():
        source = backend()
        native = SimpleNamespace(
            get=AsyncMock(side_effect=MissingKeyError("A profile password is required."))
        )
        async with AsyncTTLSecretStore(kist=source, async_kist=native) as store:
            for _ in range(2):
                with pytest.raises(MissingKeyError):
                    await store.get(KEY, default=None)
            assert native.get.await_count == 2
            assert KEY not in store._cache

    asyncio.run(run())
