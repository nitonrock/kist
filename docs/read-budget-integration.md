# Read budgets and database cancellation (unreleased)

`get()` and `get_many()` accept keyword-only `timeout=` on `Kist`, `AsyncKist`,
`ReadSession`, and `AsyncReadSession`. The unit is seconds: use a finite positive
real number, or `None` for the previous unbounded behaviour. Booleans are rejected.
Empty bulk requests still validate the value. Sessions receive the budget per
read, not at construction. Dynamic-store/cache APIs are not extended here.

```python
value = reader.get("example", timeout=2.0)
values = reader.get_many(["example", "other"], timeout=2.0)
value = await async_reader.get("example", timeout=2.0)
```

## One deadline, with database enforcement

The existing monotonic deadline starts before name validation and session/scope
lock acquisition. Internal single-to-bulk delegation and scope initialization
reuse it, even when scope initialization opens another connection.
Session/scope lock acquisition receives the remaining budget.

For a finite budget, Kist-owned normal cursors now read the initial
`statement_timeout` using `SHOW`, then install a transaction-local statement
limit before each application statement. The value is recalculated from the
remaining budget, rounded up to at least 1 millisecond, and capped at PostgreSQL's
signed 32-bit millisecond maximum. A pre-existing nonzero statement limit is
never increased. Other server limits, including lock_timeout, are unchanged.
The extra SHOW/SET round trips have overhead; connection reuse is not added here.

SHOW/SET are used rather than a SELECT set_config() call so that configuring
the statement limit does not introduce a SELECT before the existing
SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY command.
A normal successful transaction resets SET LOCAL on commit; an unsuccessful
one resets it on rollback. Connections remain owned by the existing connection
context and close when that context exits.

When timeout=None, the original cursor is used: no timeout configuration queries
or async query timeout guards are added. Write paths outside a budgeted read
continue to use the original cursor too.

Native-async cursor execute/fetch awaits additionally use asyncio.timeout with
the remaining deadline, including timeout-configuration commands. This requests
driver cancellation when an await exceeds the budget. Driver cancellation
acknowledgement may take longer. External CancelledError is not translated.

## Timeout attribution and errors

The existing internal timeout is catchable as KistError and TimeoutError, with
phase, elapsed_seconds, reason_code, and conservative retryable=False fields.
No stable named public exception is introduced. A database timeout uses the
query phase; it can occur during scope initialization or the read transaction.

A server QueryCanceled is translated only when the read installed a strictly
tighter statement limit than the original server limit (or the original limit
was disabled), and the monotonic read deadline has expired. An operator timeout
that was already smaller or equal remains a driver error. An early external
server cancellation remains a driver error. If an external server cancellation
coincides with expiry of a read-owned limit, the two cannot be distinguished by
SQLSTATE alone and are reported as a read timeout. No localized message parsing
is used. For a huge budget beyond the server maximum, a cancellation at the
clamped limit is not attributed to expiry of that larger budget.

An async timeout is translated only when its own timeout guard expired, rather
than catching an unrelated TimeoutError raised by the driver.
Translated errors are raised outside the driver exception handler and retain
no driver exception in __context__ or __cause__. Their messages do not interpolate
SQL, credentials, connection URLs, or secret names. This is not a complete driver
error taxonomy: unclassified driver failures retain their previous behaviour.
Existing operation and cleanup failures are not replaced by a deadline error.

## Limits: not a hard wall-clock deadline

This is NOT a maximum end-to-end call duration. In particular:

- Connection establishment remains cooperative, with existing driver defaults.
- A server statement timer measures server work, not client transport time;
  a synchronous socket stall or response-transfer stall is not interrupted.
- Initial synchronous SHOW/SET setup is not protected by a new client timer.
- Async cancellation acknowledgement and transaction cleanup can overrun the
  budget. Repeated cancellation and hostile-network recovery are not established
  by these tests, especially across driver/libpq versions.
- Argon2/decryption workers and user-provided key iteration are not interrupted.
  An async crypto worker can continue after caller cancellation; admission control
  for abandoned work is still absent.
- Successful late results are rejected at existing checkpoints. Late unlock
  results are checked before async session-cache publication, but the existing
  TTL cache policy is not otherwise changed.
- Scope creation may have committed before a later timeout. Timeout is not proof
  of zero side effects. No automatic retry is introduced.

PostgreSQL may log cancelled statements according to its own logging policy;
application-side exception redaction does not control server logs.

## Tests and release status

The existing PostgreSQL integration module now contains 19 collected test cases:
the original 4, plus 15 new fault cases covering table-lock waits across sync,
native-async, single, bulk, and session reads; scope-row contention; pg_sleep;
stricter operator statement limits; and external async cancellation. Tests assert
connection closure and successful subsequent reads; the async scope test also
checks release of the scope lock. Operator limits are checked after rollback.
The existing explicit CI step runs this entire module, so no workflow selector
change is needed. These tests require KIST_TEST_DATABASE_URL pointing to a
disposable PostgreSQL database. Never run them against production.

An isolated dependency-stubbed harness passed 83 tests across the supplied
read-policy/integration tests and the 31 new deterministic SQL-budget cases.
The 19 PostgreSQL cases were collected and skipped there: no database, real
psycopg, or real Argon2 work was exercised. Ruff, the complete Kist suite, and
live PostgreSQL results still need local/CI validation.

This increment does not complete the 0.3.1 release gate: connection/crypto/cleanup
limits, full typed failures, diagnostics/health checks, and consistent missing-key
behaviour still require their agreed implementation and validation. No package
version, ciphertext format, dependency minimum, or release tag is changed.
