import asyncio
import json
import logging
import time
from unittest.mock import MagicMock

import pytest

from kist import (
    AsyncDynamicSecretStore,
    AsyncDynamicStore,
    DynamicSecretStore,
    DynamicStore,
    Kist,
    TTLSecretStore,
    TTLStore,
)


@pytest.fixture
def mock_kist():
    mock = MagicMock(spec=Kist)
    mock.get.return_value = "initial_secret_value"
    mock.db_url = "postgresql://mock"
    mock.profile_id = 1
    mock.profile_name = "test_profile"
    return mock


def test_ttl_cache_hit_and_expiration(mock_kist):
    store = TTLSecretStore(ttl_seconds=0.1, kist=mock_kist)

    # First call fetches from Kist
    val1 = store.get("db.password")
    assert val1 == "initial_secret_value"
    assert mock_kist.get.call_count == 1

    # Immediate second call hits cache
    mock_kist.get.return_value = "updated_secret_value"
    val2 = store.get("db.password")
    assert val2 == "initial_secret_value"
    assert mock_kist.get.call_count == 1

    # Wait for TTL expiration
    time.sleep(0.12)
    val3 = store.get("db.password")
    assert val3 == "updated_secret_value"
    assert mock_kist.get.call_count == 2


def test_ttl_get_secret_alias_and_default(mock_kist):
    store = TTLSecretStore(ttl_seconds=10, kist=mock_kist)
    assert store.get_secret("db.password") == "initial_secret_value"

    mock_kist.get.side_effect = KeyError("Not found")
    assert store.get("missing.key", default="fallback") == "fallback"
    with pytest.raises(KeyError):
        store.get("missing.key")


def test_ttl_invalidate_and_context_manager(mock_kist):
    with TTLSecretStore(ttl_seconds=60, kist=mock_kist) as store:
        store.get("key1")
        store.get("key2")
        assert len(store._cache) == 2

        store.invalidate("key1")
        assert "key1" not in store._cache
        assert "key2" in store._cache

        store.invalidate()
        assert len(store._cache) == 0


def test_dynamic_store_cache_and_invalidation():
    mock_kist = MagicMock(spec=Kist)
    mock_kist.get.return_value = "secret_123"
    mock_kist.db_url = "postgresql://mock"
    mock_kist.profile_id = 42
    mock_kist.profile_name = "production"

    store = DynamicSecretStore(
        profile_name="production",
        auto_start=False,
        kist=mock_kist,
    )

    val1 = store.get("api.token")
    assert val1 == "secret_123"
    assert mock_kist.get.call_count == 1

    # Second lookup returns from cache
    mock_kist.get.return_value = "secret_456"
    val2 = store.get("api.token")
    assert val2 == "secret_123"
    assert mock_kist.get.call_count == 1

    # Invalidate via notification payload matching profile & key
    mock_notify = MagicMock()
    mock_notify.payload = json.dumps({
        "profile_name": "production",
        "profile_id": 42,
        "secret_key": "api.token",
    })
    store._handle_notification(mock_notify)

    # Next lookup should fetch fresh value from Kist
    val3 = store.get("api.token")
    assert val3 == "secret_456"
    assert mock_kist.get.call_count == 2


def test_notification_ignores_unrelated_profiles():
    mock_kist = MagicMock(spec=Kist)
    mock_kist.get.return_value = "secret_123"
    mock_kist.db_url = "postgresql://mock"
    mock_kist.profile_id = 42
    mock_kist.profile_name = "production"

    store = DynamicSecretStore(
        profile_name="production",
        auto_start=False,
        kist=mock_kist,
    )
    store.get("api.token")
    assert "api.token" in store._cache

    # Notification for a different profile
    mock_notify = MagicMock()
    mock_notify.payload = json.dumps({
        "profile_name": "staging",
        "profile_id": 99,
        "secret_key": "api.token",
    })
    store._handle_notification(mock_notify)

    # Cache should remain intact
    assert "api.token" in store._cache


def test_dynamic_store_lifecycle():
    mock_kist = MagicMock(spec=Kist)
    mock_kist.db_url = "postgresql://mock"
    mock_kist.profile_id = 42
    mock_kist.profile_name = "production"

    store = DynamicSecretStore(
        profile_name="production",
        auto_start=False,
        kist=mock_kist,
    )
    store._cache["foo"] = "bar"
    store.close()
    assert len(store._cache) == 0
    assert store._stop_event.is_set()


@pytest.mark.asyncio
async def test_async_store_cache_and_invalidation():
    mock_kist = MagicMock(spec=Kist)
    mock_kist.get.return_value = {"nested": "value", "count": 42}
    mock_kist.db_url = "postgresql://mock"
    mock_kist.profile_id = 10
    mock_kist.profile_name = "async_prod"

    store = AsyncDynamicSecretStore(
        profile_name="async_prod",
        auto_start=False,
        kist=mock_kist,
    )

    val1 = await store.get("config.json")
    assert val1 == {"nested": "value", "count": 42}
    assert mock_kist.get.call_count == 1

    # Cache hit
    mock_kist.get.return_value = {"nested": "new"}
    val2 = await store.get_secret("config.json")
    assert val2 == {"nested": "value", "count": 42}
    assert mock_kist.get.call_count == 1

    # Invalidate via notification
    mock_notify = MagicMock()
    mock_notify.payload = json.dumps({
        "profile_name": "async_prod",
        "profile_id": 10,
        "secret_key": "config.json",
    })
    await store._handle_notification(mock_notify)

    val3 = await store.get("config.json")
    assert val3 == {"nested": "new"}
    assert mock_kist.get.call_count == 2

    await store.close()


@pytest.mark.asyncio
async def test_async_context_manager():
    mock_kist = MagicMock(spec=Kist)
    mock_kist.get.return_value = {"nested": "value", "count": 42}
    mock_kist.db_url = "postgresql://mock"
    mock_kist.profile_id = 10
    mock_kist.profile_name = "async_prod"

    async with AsyncDynamicSecretStore(profile_name="async_prod", auto_start=False, kist=mock_kist) as store:
        val = await store.get("key")
        assert val == {"nested": "value", "count": 42}
        assert len(store._cache) == 1

    assert len(store._cache) == 0


def test_store_aliases_exist():
    assert DynamicStore is DynamicSecretStore
    assert TTLStore is TTLSecretStore
    assert AsyncDynamicStore is AsyncDynamicSecretStore


def test_logging_does_not_leak_secret_value(caplog):
    secret_val = "ultra_sensitive_plaintext_payload_xyz"
    mock_kist = MagicMock(spec=Kist)
    mock_kist.get.return_value = secret_val
    mock_kist.profile_name = "prod"

    with caplog.at_level(logging.DEBUG, logger="kist.stores"):
        store = TTLSecretStore(ttl_seconds=60, kist=mock_kist, profile_name="prod")
        # Miss & Cache
        val = store.get("db.secret_key")
        assert val == secret_val
        # Hit
        val2 = store.get("db.secret_key")
        assert val2 == secret_val
        # Invalidation
        store.invalidate("db.secret_key")

    # Verify logs were generated
    assert len(caplog.records) > 0
    # Verify secret_key name is in logs
    assert any("db.secret_key" in record.message for record in caplog.records)
    # Strictly verify the sensitive secret payload is NEVER in any log message
    for record in caplog.records:
        assert secret_val not in record.message
