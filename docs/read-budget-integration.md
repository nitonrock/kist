# Cooperative read-budget integration (unreleased)

This patch wires the internal monotonic budget into `get()` and `get_many()`
on `Kist`, `AsyncKist`, `ReadSession`, and `AsyncReadSession`.

```python
value = reader.get("example", timeout=2.0)
values = reader.get_many(["example", "other"], timeout=2.0)
value = await async_reader.get("example", timeout=2.0)
```

`timeout` is keyword-only, in seconds, and must be a finite positive real
number or `None`. Booleans are rejected. `None` preserves unbounded operation.
An empty bulk request still validates the budget before returning `{}`.
Session reads accept the budget per call, not on session construction.
Dynamic-store/cache APIs are not extended by this patch.

## What this guarantees

A single monotonic deadline is carried through internal API delegation.
The budget starts before name validation and session/scope lock acquisition.
Scope initialization does not get a new budget when it opens another connection.
Synchronous and asynchronous session/scope lock acquisition receive the remaining
budget. Checkpoints reject expired work before a phase, or reject a successful
result after a phase has overrun. Successful cleanup is checked before returning.
Connections acquired after expiry are entered into their ownership context and
closed before a timeout is returned. Late unlock results are checked before
publication into a session's unlock cache.

A timeout is catchable as both `KistError` and `TimeoutError`. Its `phase`,
`elapsed_seconds`, `reason_code`, and conservative `retryable=False` fields come
from the existing internal timeout type. There is no new stable named public
exception in this patch. The error message does not interpolate a key, password,
connection URL, SQL, or decrypted value.

Existing operation failures and cleanup failures are not replaced by timeout
errors. External asyncio cancellation is not converted into a read timeout.

## What this does not guarantee

This is a cooperative soft budget, NOT a maximum wall-clock duration.
In particular, this patch does not interrupt connection establishment, SQL,
fetches, cryptographic work, user-provided key iteration, or cleanup.
An overrun can only be reported when the active operation yields control back
to a checkpoint. A stuck operation can therefore still prevent return.
Existing driver connection defaults remain unchanged. No statement_timeout,
server-side cancellation, hard read deadline, connection pool, Argon2 admission
control, complete driver-error taxonomy, or new health-check API is added.
Missing-key/password semantics remain unchanged.

If a caller cancels while crypto is running in `asyncio.to_thread`, the worker
may continue; this patch does not add an abandoned-worker admission mechanism.
The worker computes only; it does not publish into the async session cache.
A later failure can leave an already-unlocked session bundle cached within its
existing TTL; this patch does not redefine session cache invalidation policy.

The current phase is the checkpoint that detected expiry, not a claim that it
was the sole cause of delay. A timeout during cleanup can be reported after
scope-row creation has committed, so timeout does not imply zero side effects.

## Release status and validation

This is a reviewable integration increment, not completion of the agreed 0.3.1
bounded-read release gate. No version, ciphertext format, or release tag changes.

The installer was prepared from the supplied core.py, runtime_reads.py, and
read-policy source, with exact SHA-256 preconditions. It changes only two
existing source files and adds a helper, tests, and this document.

The 40 included test cases passed in an isolated harness with psycopg and
Argon2id dependencies stubbed. That validates deterministic control flow and
ownership checks, not live driver or crypto behaviour. The project's test suite,
Ruff, and live PostgreSQL cancellation/cleanup coverage still require local/CI
validation. Do not present the isolated harness as full Kist validation.
