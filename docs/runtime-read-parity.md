# Runtime read parity patch

This replaces both earlier draft installers. Apply to a clean 0.2.12/main worktree,
not on top of either previous draft. No version bump, release tag or remote writes.

## API

```python
from kist.core import Kist
from kist.runtime_reads import AsyncKist
from kist.stores import TTLSecretStore, AsyncTTLSecretStore

kist = Kist(...)
values = kist.get_many(["database.host", "database.port"])
with kist.session(unlock_ttl_seconds=30) as session:
    values = session.get_many(["database.host", "database.password"])
    other = session.get("other")

async_kist = kist.as_async()  # Or AsyncKist(...) with Kist constructor arguments.
values = await async_kist.get_many(["database.host", "database.port"])
async with async_kist.session(unlock_ttl_seconds=30) as session:
    values = await session.get_many(["database.host", "database.password"])
    other = await session.get("other")
# Convenience: async with kist.async_session(...) as session:

store = TTLSecretStore(kist=kist, ttl_seconds=30)
value = store.get("optional", default=None)
async with AsyncTTLSecretStore(kist=kist, ttl_seconds=30) as store:
    value = await store.get("optional", default=None)
```

AsyncKist exposes read APIs, not async mutations. `get_many` is available on Kist,
AsyncKist and both read sessions, not on the TTL wrappers (neither sync nor async).
Single-flight and negative caching are automatic in TTL/dynamic stores. Reuse one
store instance across requests; caches/flights are local to that instance/process.
Async objects belong to one event loop. Do not concurrently mutate credentials or
scope on a shared Kist object. Use independent readers for independent lifecycles.
AsyncDynamicSecretStore supports `async_kist=` injection of a native async reader
with async get(key), in addition to the existing synchronous configuration holder.
Custom synchronous-only get implementations are not silently offloaded anymore.

## Guarantees and limits

All async SQL, including lazy scope creation, schema checks, bundle fetches, record
fetches and transaction cleanup, uses psycopg native async operations. Worker
threads receive no connection/cursor. Only bundle decrypt/Argon2 and pure batch
record authentication/decryption use asyncio.to_thread. Small lookup HMACs remain
on the event loop. Cancellation cannot terminate an already-running crypto worker;
it cannot publish into session/cache state. No global crypto-concurrency bound is
added: independent sessions/processes can still run Argon2 concurrently.

Every batch validates names, deduplicates in request order, loads one bundle and
reads only requested records in a repeatable-read transaction. Empty batches do
not connect. Missing names raise in request order unless default= is explicit.
Defaults never suppress authentication/integrity/database failures. No existing
get() behavior or ciphertext/KDF format is changed.

A fresh reader may create scope rows on another connection before its read
transaction. This existing behavior is preserved in sync and async; this is not
the separate SELECT-only-read proposal. Synchronous lazy scope creation is locked;
async lazy scope creation is coordinated per AsyncKist instance.

Sessions capture credentials/scope, serialize reads and cache one unlocked bundle.
Each read checks bundle identity, revision and exact wrapped bytes. Rewrap/rotation
therefore forces another authenticated unlock. Sessions do not cache secret
values or share one snapshot across calls. Expiry is checked lazily; it does not
promise memory erasure at the deadline. clear()/close() discard Python references,
not guaranteed zeroization. Context manager use is strongly recommended.

Negative entries use the same TTL and entry limit as values; absence is distinct
from None and caller defaults. TTL begins when loading completes. Invalidation
detaches in-flight loads and prevents stale cache reinsertion; existing waiters may
still receive their earlier result. A conservative store-wide generation prevents
all in-flight cache insertions after any invalidation. Disabling retention does
not disable single-flight. Single-flight is not a DB timeout.

Async waiter cancellation does not cancel a shared cache load. Closing an async
store cancels/drains its loads and clears cache state. Async session context exit
shields its cleanup from caller cancellation. Direct close() must be awaited to
completion. Closed async stores are terminal; construct a new instance to restart.

Notification handling itself is unchanged. LISTEN/NOTIFY startup/reconnect
freshness gaps and production readiness are not solved by this patch.

## Apply and validate

The implementation is already present in this worktree. Review the tracked diff and new files before staging. Do not run an installer or reapply an earlier draft.

Run Ruff, new unit tests, existing tests and optional PostgreSQL tests. Use only a
disposable database for KIST_TEST_DATABASE_URL: tests create schema tables and
scope rows. Scope/profile cleanup leaves organization/project rows. DB integration
checks include bytea-array adaptation, native async scope/reads, one derivation per
batch, session reuse, and rewrap/rotation invalidation. More adversarial concurrent
writer/snapshot/cancellation integration coverage is recommended before release.
Private cache internals changed: timestamps now contain absolute expiry times.
Existing tests depending on old internals or fake sync backends in async stores
may need adjustment; async tests should inject a native async reader explicitly.
