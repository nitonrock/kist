"""Runtime secret stores with bounded, opt-in plaintext caching."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

from psycopg import sql

from kist.core import Kist, get_profile_password, safe_async_db_connect, safe_db_connect

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CachePolicy:
    """Plaintext cache policy. Defaults to enabled with 30s TTL."""

    enabled: bool = True
    ttl_seconds: float = 30.0
    max_entries: int = 128
    clear_on_disconnect: bool = True


def _notification_matches(payload: dict[str, Any], profile_name: str, profile_id: Any | None) -> bool:
    """Match every supplied identifier; do not use ambiguous OR matching."""
    payload_name = payload.get("profile_name")
    payload_id = payload.get("profile_id")
    if payload_name is None and payload_id is None:
        return False
    if payload_name is not None and str(payload_name) != str(profile_name):
        return False
    if payload_id is not None and profile_id is not None and str(payload_id) != str(profile_id):
        return False
    return True


class TTLSecretStore:
    """Bounded TTL cache over a Kist database store."""

    def __init__(
        self,
        ttl_seconds: float = 30.0,
        profile_name: str | None = None,
        password: str | None = None,
        db_url: str | None = None,
        kist: Kist | None = None,
        cache_policy: CachePolicy | None = None,
    ) -> None:
        self.profile_name = profile_name or os.getenv("KIST_PROFILE", "default")
        self.kist = kist or Kist(
            profile_name=self.profile_name,
            password=password or get_profile_password(self.profile_name),
            db_url=db_url,
        )
        self.policy = cache_policy or CachePolicy(enabled=True, ttl_seconds=ttl_seconds)
        if self.policy.ttl_seconds <= 0 or self.policy.max_entries <= 0:
            raise ValueError("Cache TTL and maximum entries must be positive.")
        from kist.runtime_reads import SyncCache
        self._runtime_cache = SyncCache(self.policy)
        self._cache = self._runtime_cache.entries

    def get(self, key: str, default: Any=...) -> Any:
        logger.debug('Lookup for secret key %r (profile: %s)', key, self.profile_name)
        return self._runtime_cache.get(key, default, self.kist.get)

    def get_secret(self, key: str, default: Any = ...) -> Any:
        return self.get(key, default)

    def invalidate(self, key: str | None=None) -> None:
        logger.debug('Invalidation for secret key %r (profile: %s)', key, self.profile_name)
        self._runtime_cache.invalidate(key)

    clear = invalidate

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.invalidate()


class DynamicSecretStore(TTLSecretStore):
    """Opt-in cache invalidated by authenticated PostgreSQL notification access."""

    def __init__(
        self,
        profile_name: str | None = None,
        password: str | None = None,
        db_url: str | None = None,
        channel: str = "kist_secret_updated",
        auto_start: bool = False,
        kist: Kist | None = None,
        cache_policy: CachePolicy | None = None,
    ) -> None:
        super().__init__(
            profile_name=profile_name,
            password=password,
            db_url=db_url,
            kist=kist,
            cache_policy=cache_policy or CachePolicy(enabled=True),
        )
        self.db_url = db_url or self.kist.db_url
        self.channel = channel
        self._stop_event = threading.Event()
        self._listener_thread: threading.Thread | None = None
        if auto_start:
            self.start()

    def start(self) -> None:
        if not self.db_url:
            raise RuntimeError("A database URL is required for dynamic invalidation.")
        if self._listener_thread and self._listener_thread.is_alive():
            return
        self._stop_event.clear()
        logger.debug("Starting notification listener thread for profile %s on channel %s", self.profile_name, self.channel)
        self._listener_thread = threading.Thread(target=self._listen_for_updates, name=f"kist-listener-{self.profile_name}", daemon=True)
        self._listener_thread.start()

    def _listen_for_updates(self) -> None:
        while not self._stop_event.is_set():
            try:
                with safe_db_connect(self.db_url, autocommit=True) as conn:
                    conn.execute(sql.SQL("LISTEN {}").format(sql.Identifier(self.channel)))
                    logger.debug("Notification listener connected on channel %s (profile: %s)", self.channel, self.profile_name)
                    while not self._stop_event.is_set():
                        for notification in conn.notifies(timeout=0.5):
                            self._handle_notification(notification.payload)
            except Exception as exc:
                if self.policy.clear_on_disconnect:
                    self.invalidate()
                    logger.debug("Cleared cache on disconnect for profile: %s", self.profile_name)
                if not self._stop_event.is_set():
                    logger.warning("Notification listener disconnected for profile %s; reconnecting in 2.0s (%s)", self.profile_name, type(exc).__name__)
                    time.sleep(2.0)

    def _handle_notification(self, raw_payload: Any) -> None:
        try:
            if hasattr(raw_payload, "payload"):
                raw_payload = raw_payload.payload
            payload = json.loads(raw_payload) if isinstance(raw_payload, (str, bytes)) else raw_payload
            if not isinstance(payload, dict) or not _notification_matches(payload, self.profile_name, self.kist.profile_id):
                return
            key = payload.get("secret_key")
            logger.debug("Notification received on channel %s; invalidating key %r for profile: %s", self.channel, key, self.profile_name)
            self.invalidate(key if isinstance(key, str) else None)
        except Exception as exc:
            logger.warning("Failed to process notification payload for profile %s; invalidating cache (%s)", self.profile_name, type(exc).__name__)
            self.invalidate()

    def close(self) -> None:
        self._stop_event.set()
        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=1.0)
        self._listener_thread = None
        self.invalidate()
        logger.debug("Closed notification listener for profile: %s", self.profile_name)

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class AsyncDynamicSecretStore:
    """Async variant with bounded, opt-in cache and explicit listener lifecycle."""

    def __init__(
        self,
        profile_name: str | None = None,
        password: str | None = None,
        db_url: str | None = None,
        channel: str = "kist_secret_updated",
        auto_start: bool = False,
        kist: Kist | None = None,
        cache_policy: CachePolicy | None = None,
        async_kist: Any | None = None,
    ) -> None:
        self.profile_name = profile_name or os.getenv("KIST_PROFILE", "default")
        self.kist = kist or Kist(
            profile_name=self.profile_name,
            password=password or get_profile_password(self.profile_name),
            db_url=db_url,
        )
        self.db_url = db_url or self.kist.db_url
        self.channel = channel
        self.policy = cache_policy or CachePolicy(enabled=True)
        from kist.runtime_reads import AsyncCache, AsyncKist
        self._runtime_cache = AsyncCache(self.policy)
        self._cache = self._runtime_cache.entries
        self._async_kist = async_kist if async_kist is not None else AsyncKist(kist=self.kist)
        self._listener_task: asyncio.Task | None = None
        self._closing = False
        if auto_start:
            try:
                self._listener_task = asyncio.get_running_loop().create_task(self._listen_for_updates())
            except RuntimeError:
                pass

    async def start(self) -> None:
        if self._runtime_cache.closed:
            raise RuntimeError("Async store is closed; create a new instance.")
        if not self.db_url:
            raise RuntimeError("A database URL is required for dynamic invalidation.")
        if self._listener_task and not self._listener_task.done():
            return
        self._closing = False
        logger.debug("Starting async notification listener for profile %s on channel %s", self.profile_name, self.channel)
        self._listener_task = asyncio.get_running_loop().create_task(self._listen_for_updates())

    async def get(self, key: str, default: Any=...) -> Any:
        logger.debug('Lookup for secret key %r (profile: %s)', key, self.profile_name)
        return await self._runtime_cache.get(key, default, self._async_kist.get)

    async def get_secret(self, key: str, default: Any = ...) -> Any:
        return await self.get(key, default)

    async def invalidate(self, key: str | None=None) -> None:
        logger.debug('Invalidation for secret key %r (profile: %s)', key, self.profile_name)
        self._runtime_cache.invalidate(key)

    async def _listen_for_updates(self) -> None:
        while not self._closing:
            try:
                async with await safe_async_db_connect(self.db_url, autocommit=True) as conn:
                    await conn.execute(sql.SQL("LISTEN {}").format(sql.Identifier(self.channel)))
                    logger.debug("Async notification listener connected on channel %s (profile: %s)", self.channel, self.profile_name)
                    async for notification in conn.notifies():
                        if self._closing:
                            break
                        await self._handle_notification(notification.payload)
            except asyncio.CancelledError:
                logger.debug("Async notification listener cancelled for profile: %s", self.profile_name)
                break
            except Exception as exc:
                if self.policy.clear_on_disconnect:
                    await self.invalidate()
                    logger.debug("Cleared cache on disconnect for profile: %s", self.profile_name)
                if not self._closing:
                    logger.warning("Async notification listener disconnected for profile %s; reconnecting in 2.0s (%s)", self.profile_name, type(exc).__name__)
                    await asyncio.sleep(2.0)

    async def _handle_notification(self, raw_payload: Any) -> None:
        try:
            if hasattr(raw_payload, "payload"):
                raw_payload = raw_payload.payload
            payload = json.loads(raw_payload) if isinstance(raw_payload, (str, bytes)) else raw_payload
            if not isinstance(payload, dict) or not _notification_matches(payload, self.profile_name, self.kist.profile_id):
                return
            key = payload.get("secret_key")
            logger.debug("Notification received on channel %s; invalidating key %r for profile: %s", self.channel, key, self.profile_name)
            await self.invalidate(key if isinstance(key, str) else None)
        except Exception as exc:
            logger.warning("Failed to process notification payload for profile %s; invalidating cache (%s)", self.profile_name, type(exc).__name__)
            await self.invalidate()

    async def _finish_close(self) -> None:
        self._closing = True
        if self._listener_task and not self._listener_task.done():
            self._listener_task.cancel()
            await asyncio.gather(self._listener_task, return_exceptions=True)
        self._listener_task = None
        await self._runtime_cache.close()

    async def close(self) -> None:
        from kist.runtime_reads import _observe
        task = getattr(self, "_runtime_close_task", None)
        if task is None:
            self._closing = True
            task = asyncio.create_task(self._finish_close())
            self._runtime_close_task = task
            task.add_done_callback(_observe)
        await asyncio.shield(task)

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()


DynamicStore = DynamicSecretStore
TTLStore = TTLSecretStore
AsyncDynamicStore = AsyncDynamicSecretStore

__all__ = [
    "CachePolicy",
    "DynamicSecretStore",
    "TTLSecretStore",
    "AsyncDynamicSecretStore",
    "DynamicStore",
    "TTLStore",
    "AsyncDynamicStore",
]


class AsyncTTLSecretStore(AsyncDynamicSecretStore):
    """Async TTL store; notification listening is disabled."""

    def __init__(self, ttl_seconds: float = 30.0, **kwargs: Any) -> None:
        policy = kwargs.pop("cache_policy", None)
        kwargs.pop("auto_start", None)
        super().__init__(auto_start=False, cache_policy=(policy if policy is not None
                         else CachePolicy(ttl_seconds=ttl_seconds)), **kwargs)

    async def __aenter__(self):
        if self._runtime_cache.closed:
            raise RuntimeError("Async TTL store is closed.")
        return self

    async def start(self) -> None:
        raise RuntimeError("Use AsyncDynamicSecretStore for notification listening.")


__all__.append("AsyncTTLSecretStore")
