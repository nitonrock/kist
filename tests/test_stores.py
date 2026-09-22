import os
import json
import time
import asyncio
import unittest
from unittest.mock import MagicMock, patch

from kist import (
    Kist,
    DynamicSecretStore,
    TTLSecretStore,
    AsyncDynamicSecretStore,
    DynamicStore,
    TTLStore,
    AsyncDynamicStore,
)


class TestTTLSecretStore(unittest.TestCase):
    def setUp(self):
        self.mock_kist = MagicMock(spec=Kist)
        self.mock_kist.get.return_value = "initial_secret_value"
        self.mock_kist.db_url = "postgresql://mock"
        self.mock_kist.profile_id = 1
        self.mock_kist.profile_name = "test_profile"

    def test_ttl_cache_hit_and_expiration(self):
        store = TTLSecretStore(ttl_seconds=0.1, kist=self.mock_kist)

        # First call fetches from Kist
        val1 = store.get("db.password")
        self.assertEqual(val1, "initial_secret_value")
        self.assertEqual(self.mock_kist.get.call_count, 1)

        # Immediate second call hits cache
        self.mock_kist.get.return_value = "updated_secret_value"
        val2 = store.get("db.password")
        self.assertEqual(val2, "initial_secret_value")
        self.assertEqual(self.mock_kist.get.call_count, 1)

        # Wait for TTL expiration
        time.sleep(0.12)
        val3 = store.get("db.password")
        self.assertEqual(val3, "updated_secret_value")
        self.assertEqual(self.mock_kist.get.call_count, 2)

    def test_ttl_get_secret_alias_and_default(self):
        store = TTLSecretStore(ttl_seconds=10, kist=self.mock_kist)
        self.assertEqual(store.get_secret("db.password"), "initial_secret_value")

        self.mock_kist.get.side_effect = KeyError("Not found")
        self.assertEqual(store.get("missing.key", default="fallback"), "fallback")
        with self.assertRaises(KeyError):
            store.get("missing.key")

    def test_ttl_invalidate_and_context_manager(self):
        with TTLSecretStore(ttl_seconds=60, kist=self.mock_kist) as store:
            store.get("key1")
            store.get("key2")
            self.assertEqual(len(store._cache), 2)

            store.invalidate("key1")
            self.assertNotIn("key1", store._cache)
            self.assertIn("key2", store._cache)

            store.invalidate()
            self.assertEqual(len(store._cache), 0)


class TestDynamicSecretStore(unittest.TestCase):
    def setUp(self):
        self.mock_kist = MagicMock(spec=Kist)
        self.mock_kist.get.return_value = "secret_123"
        self.mock_kist.db_url = "postgresql://mock"
        self.mock_kist.profile_id = 42
        self.mock_kist.profile_name = "production"

    def test_dynamic_store_cache_and_invalidation(self):
        store = DynamicSecretStore(
            profile_name="production",
            auto_start=False,
            kist=self.mock_kist,
        )

        val1 = store.get("api.token")
        self.assertEqual(val1, "secret_123")
        self.assertEqual(self.mock_kist.get.call_count, 1)

        # Second lookup returns from cache
        self.mock_kist.get.return_value = "secret_456"
        val2 = store.get("api.token")
        self.assertEqual(val2, "secret_123")
        self.assertEqual(self.mock_kist.get.call_count, 1)

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
        self.assertEqual(val3, "secret_456")
        self.assertEqual(self.mock_kist.get.call_count, 2)

    def test_notification_ignores_unrelated_profiles(self):
        store = DynamicSecretStore(
            profile_name="production",
            auto_start=False,
            kist=self.mock_kist,
        )
        store.get("api.token")
        self.assertIn("api.token", store._cache)

        # Notification for a different profile
        mock_notify = MagicMock()
        mock_notify.payload = json.dumps({
            "profile_name": "staging",
            "profile_id": 99,
            "secret_key": "api.token",
        })
        store._handle_notification(mock_notify)

        # Cache should remain intact
        self.assertIn("api.token", store._cache)

    def test_dynamic_store_lifecycle(self):
        store = DynamicSecretStore(
            profile_name="production",
            auto_start=False,
            kist=self.mock_kist,
        )
        store._cache["foo"] = "bar"
        store.close()
        self.assertEqual(len(store._cache), 0)
        self.assertTrue(store._stop_event.is_set())


class TestAsyncDynamicSecretStore(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mock_kist = MagicMock(spec=Kist)
        self.mock_kist.get.return_value = {"nested": "value", "count": 42}
        self.mock_kist.db_url = "postgresql://mock"
        self.mock_kist.profile_id = 10
        self.mock_kist.profile_name = "async_prod"

    async def test_async_store_cache_and_invalidation(self):
        store = AsyncDynamicSecretStore(
            profile_name="async_prod",
            auto_start=False,
            kist=self.mock_kist,
        )

        val1 = await store.get("config.json")
        self.assertEqual(val1, {"nested": "value", "count": 42})
        self.assertEqual(self.mock_kist.get.call_count, 1)

        # Cache hit
        self.mock_kist.get.return_value = {"nested": "new"}
        val2 = await store.get_secret("config.json")
        self.assertEqual(val2, {"nested": "value", "count": 42})
        self.assertEqual(self.mock_kist.get.call_count, 1)

        # Invalidate via notification
        mock_notify = MagicMock()
        mock_notify.payload = json.dumps({
            "profile_name": "async_prod",
            "profile_id": 10,
            "secret_key": "config.json",
        })
        await store._handle_notification(mock_notify)

        val3 = await store.get("config.json")
        self.assertEqual(val3, {"nested": "new"})
        self.assertEqual(self.mock_kist.get.call_count, 2)

        await store.close()

    async def test_async_context_manager(self):
        async with AsyncDynamicSecretStore(profile_name="async_prod", auto_start=False, kist=self.mock_kist) as store:
            val = await store.get("key")
            self.assertEqual(val, {"nested": "value", "count": 42})
            self.assertEqual(len(store._cache), 1)

        self.assertEqual(len(store._cache), 0)


class TestStoreAliases(unittest.TestCase):
    def test_aliases_exist(self):
        self.assertIs(DynamicStore, DynamicSecretStore)
        self.assertIs(TTLStore, TTLSecretStore)
        self.assertIs(AsyncDynamicStore, AsyncDynamicSecretStore)


if __name__ == "__main__":
    unittest.main()
