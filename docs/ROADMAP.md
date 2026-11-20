# Runtime reliability roadmap

Status: planning and source audit. Nothing below is a claim of implemented functionality.

This programme preserves all 14 requests from the runtime consumer feedback. Release numbers are provisional delivery targets; split blocks when needed rather than dropping requirements or weakening acceptance criteria. Keep the package version unchanged until release preparation.

## Delivery blocks

| Target | Scope |
| --- | --- |
| 0.3.1 | Read budgets, typed errors, phase diagnostics, bounded health checks, missing-key consistency |
| 0.3.2 | Connection reuse, bounded acquisition, concurrent-reader semantics, derivation admission control |
| 0.3.3 | Cache-waiter deadlines and prefix reads |
| 0.3.4 | Revision revalidation, refresh-ahead, bulk/warm store operations, separate positive/negative TTLs |
| 0.3.5 | Dynamic-store freshness, connectivity, reconnect backoff, polling |
| Every block | Metrics, README, changelog, compatibility and concurrency documentation |

## Requirements and acceptance

All requirements are planned pending audit. Add implementation PR links and released versions as work lands. A partial implementation does not close the requirement.

| ID | Requirement | Acceptance criteria |
| --- | --- | --- |
| 1 | Per-call read budget | One monotonic budget covers waits and read phases; test stalled queries, connection failures, cancellation and recovery. Document caller-return versus underlying-work termination guarantees, including key derivation. |
| 2 | Typed errors with sanitised cause | Distinguish timeout, unavailability, authentication and decryption; preserve safe provenance and structured reason/phase fields; test redaction and compatibility. Retryability must not be inferred from a broad driver exception alone. |
| 3 | Phase timings and health checks | Debug timings identify acquisition, connection, schema, unlock, query, decryption and cleanup as applicable. Health checks have their own budget and explicitly distinguish database liveness from profile readiness. |
| 4 | Missing-key consistency | Separate missing-secret semantics from the existing MissingKeyError, which means missing profile password. Preserve password errors as failures, never defaults or negative-cache entries. Define consistent secret-not-found behaviour across single, bulk, session and cache APIs, with compatibility tests. |
| 5 | Connection reuse | Repeated session reads reuse connections; acquisition is bounded; lifecycle and reuse checks are defined; failed or unresolved cancelled operations cannot return an unsafe connection for reuse. |
| 6 | Concurrent session reads | Define supported sharing and ordering. Test a stalled read alongside independent reads, bounded contention and recovery; removing a lock alone is not acceptance. |
| 7 | Prefix reads | Document prefix boundaries, flat/subtree result shape, empty results and snapshot consistency. Test sync/async parity without exposing plaintext names to database columns or logs. |
| 8 | Derivation admission control | Shared process-wide sync/async limit with configurable capacity and deadline-aware admission; narrowly translate derivation allocation failures; document per-process versus host-wide limits. |
| 9 | Cache-waiter deadlines | Each follower has an independent wait budget; follower timeout does not cancel work needed by others; leaders are bounded and in-flight state is cleared on every terminal path. |
| 10 | Cheap revalidation | Revision checks need no password derivation or key unlock; relevant changes update revisions atomically; define scope and concurrent-update semantics; test supported pooler mode. |
| 11 | Store refresh and bulk operations | Refresh-ahead, get_many/warm and separate found/missing TTLs share defined single-flight semantics; test refresh failure, shutdown, stampedes and explicit stale-serving policy. |
| 12 | Dynamic-store hardening | Preserve existing TTL expiry; define maximum freshness age and bounded refresh reads, connectivity status, bounded reconnect backoff and a polling alternative. Test lost notifications, disconnected listeners, listener shutdown/restart, recovery and pooled deployment behaviour. |
| 13 | Metrics | Framework-neutral hooks/counters for reads, failures, waits, unlocks, cache outcomes and retries if implemented; bounded labels and no secrets or plaintext secret names; document callback failure behaviour. |
| 14 | Stability and operations docs | Document public API/versioning policy, thread/task/fork safety, ownership and shutdown. Keep README and changelog current. Explain database operator responsibility for availability objectives; do not imply a library-provided SLA. |

## Implementation rules

- Audit current source and reproduce reported behaviour before changing it; consumer reports are not a completed source audit.
- Maintain sync/async API parity and native async database I/O. Thread offloading is allowed only for unavoidable blocking non-database operations.
- Preserve envelope-format compatibility, encrypted-name storage and credential redaction.
- Prefer additive 0.3.x changes. Explicitly review changed defaults or breaking contracts rather than hiding them in patch releases.
- Do not silently add retries or stale-secret serving.
- Connection reuse and unlocked-material reuse have separate ownership and security lifecycles.

## Definition of done

For each block: public contract, deterministic regression tests, relevant live PostgreSQL and fault-injection tests, cancellation/resource-cleanup coverage, sync/async parity, README examples and limitations, changelog entry, and updated requirement status with PR links and released version. Run lint, whitespace checks, release-consistency tests, applicable suites and distribution builds. Never claim tests ran when they did not.

## Initial work

1. Audit runtime reads, connection wrappers, exceptions, caches and existing tests.
2. Write the read-budget and safe-error contracts; identify blockers to a genuine wall-clock guarantee.
3. Implement bounded-read foundations in reviewable PRs, then prioritise reusable connections.
4. Update README links and current limitations alongside the audit; do not document proposed APIs as available.
