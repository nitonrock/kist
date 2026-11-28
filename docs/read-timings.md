# Read phase timings (unreleased)

`trace_reads()` shows where time went inside database-backed reads. It is
opt-in, adds no public parameter to any read method, and does nothing when no
trace is active.

```python
from kist import Kist, trace_reads

store = Kist(profile_name="payments")
with trace_reads() as trace:
    store.get("provider.api_key", timeout=2.0)

for record in trace.records:
    print(record.call, record.phase, record.depth, record.seconds, record.outcome)
print(trace.totals())
```

The same block works around `await` calls on `AsyncKist`, `ReadSession`, and
`AsyncReadSession`.

## What is recorded

Each `PhaseTiming` is a frozen record of: `call` (1-based number of the
top-level read within this trace), `phase`, `depth`, `seconds`, and `outcome`.
Phases use the existing vocabulary: `scope_wait`, `scope_init`, `connect`,
`schema_check`, `key_unlock`, `query`, `decrypt`, `cache_wait`, and `cleanup`.
`connection_acquire` and `derivation_wait` are reserved for later blocks and
are not recorded yet.

Outcomes are `ok`, `timeout`, `database_error`, `error`, and `cancelled`
(a non-`Exception` such as asyncio cancellation). They classify the phase's own
result. A body failure is not blamed on `cleanup`.

Records contain no secret names, values, SQL, URLs, passwords, or exception
text. `trace.dropped` counts records beyond the 1000-record bound.

## Reading the numbers

Records are written when a phase finishes, so a parent appears after its
children. `depth` is 0 for a top-level phase and higher when it ran inside
another one; for example, a `key_unlock` call can wrap the derivation step
inside it. Nested records overlap their parent, so do not add all records
together. `trace.totals()` sums depth-0 records per phase and optionally filters
by `call`.

`connect` covers establishing the connection. `cleanup` covers only the exit of
the connection context (commit/rollback/close), not the time the connection was
in use. `cache_wait` and `scope_wait` cover only the wait to acquire a lock, not
the time it is held. Query time includes the extra statement-budget round trips
(`SHOW`/`SET LOCAL`) that Kist issues before each statement, so it can exceed
the application's own SQL time.

## Limits

- Timings are diagnostics, not guarantees. They do not stop SQL, key
  derivation, or cleanup, and they do not make deadlines stronger.
- Seconds use a monotonic clock in the Python process. They exclude time spent
  before a call enters a phase and are not server-side measurements.
- A trace follows the thread or task context. Kist's own worker threads inherit
  it. Threads or tasks you start yourself record only if they run in a copy of
  the context (`contextvars.copy_context().run`).
- A nested `trace_reads()` replaces the outer trace for its duration.
- Phase records are not metrics. Requirement 13 (hooks and counters) is
  separate work, and no callback is invoked from here.
- Failed reads still raise the same typed errors, which do not yet carry the
  timing table.
- No version, dependency minimum, ciphertext format, or release tag changes.
  Health checks (the other half of requirement 3) are not implemented here.
