import os
import json
import time
import threading
import asyncio
from typing import Any, Optional
import psycopg
from psycopg import sql

from kist.core import Kist, get_profile_password, safe_db_connect, safe_async_db_connect, enforce_ssl_url


class DynamicSecretStore:
    """
    Push-Based Invalidation Secret Store using PostgreSQL LISTEN / NOTIFY.

    Maintains an in-memory cache of secrets for sub-millisecond lookups while
    running a background listener thread that invalidates cache entries immediately
    when secret update notifications are broadcast on PostgreSQL.
    """

    def __init__(
        self,
        profile_name: Optional[str] = None,
        master_password: Optional[str] = None,
        db_url: Optional[str] = None,
        channel: str = "kist_secret_updated",
        auto_start: bool = True,
        kist: Optional[Kist] = None,
    ):
        self.profile_name = profile_name or os.getenv("KIST_PROFILE", "default")
        self.db_url = db_url or os.getenv("KIST_DATABASE_URL")
        self.channel = channel

        if kist is not None:
            self.kist = kist
        else:
            self.kist = Kist(
                profile_name=self.profile_name,
                master_password=master_password or get_profile_password(self.profile_name, auto_generate=False),
            )

        if not self.db_url and self.kist.db_url:
            self.db_url = self.kist.db_url

        self._cache: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._listener_thread: Optional[threading.Thread] = None

        if auto_start and self.db_url:
            self.start()

    def start(self):
        """Starts the background PostgreSQL notification listener thread."""
        if self._listener_thread and self._listener_thread.is_alive():
            return

        self._stop_event.clear()
        self._listener_thread = threading.Thread(
            target=self._listen_for_updates,
            name=f"kist-listener-{self.profile_name}",
            daemon=True,
        )
        self._listener_thread.start()

    def get(self, key: str, default: Any = ...) -> Any:
        """
        Retrieves a secret by its dot-notation key path.
        Returns from in-memory cache if present; otherwise fetches from PostgreSQL and caches.
        """
        with self._lock:
            if key in self._cache:
                return self._cache[key]

        try:
            val = self.kist.get(key)
        except KeyError:
            if default is not ...:
                return default
            raise

        with self._lock:
            self._cache[key] = val
        return val

    def get_secret(self, key: str, default: Any = ...) -> Any:
        """Alias for get()."""
        return self.get(key, default=default)

    def invalidate(self, key: Optional[str] = None):
        """Invalidates a single cached key, or the entire memory cache if key is None."""
        with self._lock:
            if key is not None:
                self._cache.pop(key, None)
            else:
                self._cache.clear()

    def _listen_for_updates(self):
        """Listens to PostgreSQL NOTIFY events to invalidate local cache in real time."""
        while not self._stop_event.is_set():
            try:
                with safe_db_connect(self.db_url, autocommit=True) as conn:
                    conn.execute(sql.SQL("LISTEN {}").format(sql.Identifier(self.channel)))
                    while not self._stop_event.is_set():
                        for notification in conn.notifies(timeout=0.5):
                            self._handle_notification(notification)
                            if self._stop_event.is_set():
                                break
            except Exception:
                # Invalidate cache defensively on connection drop/error and wait before retrying
                with self._lock:
                    self._cache.clear()
                if not self._stop_event.is_set():
                    time.sleep(2.0)

    def _handle_notification(self, notification):
        """Parses notification payload and evicts matching keys from local cache."""
        try:
            payload = json.loads(notification.payload)
            target_profile = payload.get("profile_name")
            target_id = payload.get("profile_id")

            # Check if this notification applies to our profile
            matches_name = target_profile == self.profile_name if target_profile else True
            matches_id = target_id == self.kist.profile_id if (target_id and self.kist.profile_id) else True

            if matches_name or matches_id:
                secret_key = payload.get("secret_key")
                with self._lock:
                    if secret_key is not None:
                        self._cache.pop(secret_key, None)
                    else:
                        self._cache.clear()
        except Exception:
            # Fallback: on malformed JSON payload, clear entire cache defensively
            with self._lock:
                self._cache.clear()

    def close(self):
        """Stops the background listener thread and clears the memory cache."""
        self._stop_event.set()
        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=1.0)
            self._listener_thread = None
        with self._lock:
            self._cache.clear()

    def __enter__(self):
        if self.db_url and not (self._listener_thread and self._listener_thread.is_alive()):
            self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class TTLSecretStore:
    """
    Time-To-Live (TTL) In-Memory Secret Store.

    Caches decrypted secrets in memory with a configurable expiration time (TTL).
    When a key expires or is accessed for the first time, it re-fetches the latest
    value from PostgreSQL.
    """

    def __init__(
        self,
        ttl_seconds: float = 60.0,
        profile_name: Optional[str] = None,
        master_password: Optional[str] = None,
        db_url: Optional[str] = None,
        kist: Optional[Kist] = None,
    ):
        self.ttl = float(ttl_seconds)
        self.profile_name = profile_name or os.getenv("KIST_PROFILE", "default")

        if kist is not None:
            self.kist = kist
        else:
            self.kist = Kist(
                profile_name=self.profile_name,
                master_password=master_password or get_profile_password(self.profile_name, auto_generate=False),
                db_url=db_url,
            )

        self._cache: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str, default: Any = ...) -> Any:
        """
        Retrieves a secret by its dot-notation key path.
        Returns cached value if present and within TTL; otherwise queries PostgreSQL.
        """
        now = time.time()
        with self._lock:
            if key in self._cache:
                cached_at, value = self._cache[key]
                if now - cached_at < self.ttl:
                    return value

        try:
            fresh_value = self.kist.get(key)
        except KeyError:
            if default is not ...:
                return default
            raise

        with self._lock:
            self._cache[key] = (now, fresh_value)
        return fresh_value

    def get_secret(self, key: str, default: Any = ...) -> Any:
        """Alias for get()."""
        return self.get(key, default=default)

    def invalidate(self, key: Optional[str] = None):
        """Evicts a single key or the entire cache."""
        with self._lock:
            if key is not None:
                self._cache.pop(key, None)
            else:
                self._cache.clear()

    def clear(self):
        """Clears all cached secrets."""
        self.invalidate()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()


class AsyncDynamicSecretStore:
    """
    Asynchronous Push-Based Invalidation Secret Store for asyncio / FastAPI applications.

    Maintains an in-memory cache and listens to PostgreSQL NOTIFY events asynchronously.
    """

    def __init__(
        self,
        profile_name: Optional[str] = None,
        master_password: Optional[str] = None,
        db_url: Optional[str] = None,
        channel: str = "kist_secret_updated",
        auto_start: bool = True,
        kist: Optional[Kist] = None,
    ):
        self.profile_name = profile_name or os.getenv("KIST_PROFILE", "default")
        self.db_url = db_url or os.getenv("KIST_DATABASE_URL")
        self.channel = channel

        if kist is not None:
            self.kist = kist
        else:
            self.kist = Kist(
                profile_name=self.profile_name,
                master_password=master_password or get_profile_password(self.profile_name, auto_generate=False),
            )

        if not self.db_url and self.kist.db_url:
            self.db_url = self.kist.db_url

        self._cache: dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self._listener_task: Optional[asyncio.Task] = None
        self._closing = False

        if auto_start and self.db_url:
            try:
                loop = asyncio.get_running_loop()
                self._listener_task = loop.create_task(self._listen_for_updates())
            except RuntimeError:
                pass

    async def start(self):
        """Starts the async background notification listener task."""
        if self._listener_task and not self._listener_task.done():
            return
        self._closing = False
        loop = asyncio.get_running_loop()
        self._listener_task = loop.create_task(self._listen_for_updates())

    async def get(self, key: str, default: Any = ...) -> Any:
        """Retrieves a secret asynchronously from memory cache or database."""
        async with self._lock:
            if key in self._cache:
                return self._cache[key]

        try:
            val = await asyncio.to_thread(self.kist.get, key)
        except KeyError:
            if default is not ...:
                return default
            raise

        async with self._lock:
            self._cache[key] = val
        return val

    async def get_secret(self, key: str, default: Any = ...) -> Any:
        """Alias for get()."""
        return await self.get(key, default=default)

    async def invalidate(self, key: Optional[str] = None):
        """Invalidates a single cached key or the entire cache."""
        async with self._lock:
            if key is not None:
                self._cache.pop(key, None)
            else:
                self._cache.clear()

    async def _listen_for_updates(self):
        """Listens for PostgreSQL NOTIFY events using psycopg async connection."""
        while not self._closing:
            try:
                async with await safe_async_db_connect(self.db_url, autocommit=True) as aconn:
                    await aconn.execute(sql.SQL("LISTEN {}").format(sql.Identifier(self.channel)))
                    async for notification in aconn.notifies():
                        if self._closing:
                            break
                        self._handle_notification(notification)
            except asyncio.CancelledError:
                break
            except Exception:
                async with self._lock:
                    self._cache.clear()
                if not self._closing:
                    await asyncio.sleep(2.0)

    def _handle_notification(self, notification):
        """Handles notification payload and invalidates matching keys."""
        try:
            payload = json.loads(notification.payload)
            target_profile = payload.get("profile_name")
            target_id = payload.get("profile_id")

            matches_name = target_profile == self.profile_name if target_profile else True
            matches_id = target_id == self.kist.profile_id if (target_id and self.kist.profile_id) else True

            if matches_name or matches_id:
                secret_key = payload.get("secret_key")
                if secret_key is not None:
                    self._cache.pop(secret_key, None)
                else:
                    self._cache.clear()
        except Exception:
            self._cache.clear()

    async def close(self):
        """Closes the async listener task and clears cache."""
        self._closing = True
        if self._listener_task and not self._listener_task.done():
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None
        async with self._lock:
            self._cache.clear()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


# Convenient aliases
DynamicStore = DynamicSecretStore
TTLStore = TTLSecretStore
AsyncDynamicStore = AsyncDynamicSecretStore

__all__ = [
    "DynamicSecretStore",
    "TTLSecretStore",
    "AsyncDynamicSecretStore",
    "DynamicStore",
    "TTLStore",
    "AsyncDynamicStore",
]
