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

ReadTimeoutError is now a named public exception, inheriting ReadError,
KistError, and TimeoutError. It retains phase, elapsed_seconds, reason_code,
retryable=False, and adds sqlstate=None. The former private name is an alias.

Read-owned server cancellations retain the existing conservative attribution:
the read installed a strictly tighter limit (or the server limit was disabled)
and the monotonic deadline has expired. A pre-existing smaller/equal operator
limit or an early external server cancellation is not a read deadline.
Simultaneous external cancellation and expiry of a read-owned limit cannot be
distinguished by SQLSTATE alone. Huge budgets clamped to the server maximum
are not treated as expired merely because that smaller server cap was reached.

At public database-backed read boundaries, other driver failures are now
ReadDatabaseError with controlled metadata, including reason_code and SQLSTATE.
Thus an operator or early server cancellation is database_query_cancelled,
not ReadTimeoutError. Direct private SQL helpers still expose their original
driver errors. This is an intentional unreleased public error-contract change.
See read-errors.md for the mapping, catch examples, and compatibility limits.

Async timeout attribution still requires expiry of the read's own timeout guard.
Public error boundaries clear driver context/cause; this does not protect
traceback-local capture or PostgreSQL logs. Existing non-driver errors and
external asyncio cancellation are preserved. No hard end-to-end deadline or
complete non-database error taxonomy is implied.

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
The explicit CI step now runs this module and the 8-case read-error module
(27 cases total). These tests require KIST_TEST_DATABASE_URL pointing to a
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
