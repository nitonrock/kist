# Public database read errors (unreleased)

Database-backed get()/get_many() calls on Kist, native AsyncKist, and their read
sessions expose these public imports:

```python
from kist import ReadDatabaseError, ReadError, ReadTimeoutError
```

ReadError inherits KistError. ReadDatabaseError represents a driver failure;
ReadTimeoutError additionally inherits builtin TimeoutError. The old internal
_ReadTimeoutError name remains an alias, so existing timeout catches still work.

```python
try:
    value = store.get("example.value", timeout=2.0)
except ReadTimeoutError as error:
    logger.warning("Read deadline: phase=%s elapsed=%.3f",
                   error.phase, error.elapsed_seconds)
    raise
except ReadDatabaseError as error:
    logger.warning("Read failure: reason=%s phase=%s sqlstate=%s",
                   error.reason_code, error.phase, error.sqlstate)
    raise
```

Do not log secret values, configuration objects, raw driver diagnostics, or
tracebacks with local-variable capture. This patch does not install logging
handlers or emit telemetry automatically.

## Contract and compatibility boundary

Both error types expose phase, elapsed_seconds, reason_code, retryable, and
sqlstate (a validated five-character SQLSTATE or None). The text uses controlled
vocabulary, never a driver message, SQL statement, secret name, or database URL.
Elapsed time is measured since entry to the read context, including timeout=None.
Phase is a checkpoint, not a root-cause verdict or a per-phase duration trace.
A driver error escaping a less-specific boundary uses the fallback read phase.

Database-driver failures at these public read boundaries now raise
ReadDatabaseError rather than psycopg.Error. This is an intentional unreleased
API change: code catching driver classes for public reads should switch to
ReadDatabaseError and inspect reason_code/sqlstate. It applies with and without
an explicit finite budget. Direct private SQL helpers retain their internal
error behaviour; they are not the public read-error contract.

Ordinary write/CLI/admin connections outside a read context retain their prior
exception behaviour. If a user callback performs a write inside a read context,
it inherits that context; the isolation guarantee is not for such reentrant use.
Missing-key, missing-password, malformed-envelope, decryption, input-validation,
and schema-version exceptions are unchanged in this patch. They are not all
subclasses of ReadError. Missing-key consistency and health checks remain work
for the subsequent block, not implied features of this base error class.

## Classification

Only SQLSTATE and the boundary phase are used, never driver-message parsing:

| SQLSTATE | reason_code | retryable |
| --- | --- | --- |
| class 28 | database_authentication_failed | false |
| 42501 | database_permission_denied | false |
| 57014 | database_query_cancelled | false |
| 40001 | database_serialization_failure | true |
| 40P01 | database_deadlock | true |
| 53300, 57P03 | database_unavailable | false |
| class 08, or unclassified connect failure | database_connection_failed | false |
| other | database_operation_failed | false |

Authentication metadata is preserved before the existing connection wrappers
replace a raw OperationalError with a generic redacted error. No claim of
invalid-password detection is made if the driver does not provide SQLSTATE.
An operator timeout or early server cancellation is a database_query_cancelled
error at a public boundary, not a read deadline. Existing read-owned timeout
attribution and its simultaneous-cancellation ambiguity remain unchanged.

retryable is only an advisory hint for serialization failures and deadlocks.
There is no automatic retry, no guaranteed success on retry, and no assertion
that earlier scope initialization had no side effects. Any retry needs its own
application policy and a fresh per-call budget.

## Redaction and failure handling

Public boundaries clear driver exception context and cause, including context
that contextlib can attach while unwinding connection ownership. Ordinary
formatted public exception chains therefore omit the original driver diagnostic.
The structured fields and args do not store the raw exception or diagnostics.
This is not a memory-erasure guarantee: traceback frames, local-variable-capturing
crash reporters, caller source lines, process memory, and PostgreSQL logs can
still contain sensitive information. Application logging policy still matters.

Existing ReadError instances preserve their type, phase, and identity through
nested delegation, while their exception chaining is cleared at read boundaries.
External asyncio cancellation is not converted into a read failure.
A cleanup driver failure is surfaced as a sanitised cleanup failure, not hidden
as a deadline. It can supersede the original operation failure during unwinding.
No connection pooling or stronger cancellation/cleanup timing guarantee is added.

## Validation and scope

The new deterministic module has 36 cases, including metadata classification,
connection SQLSTATE retention, no-context/cause assertions at public boundaries,
legacy connection behaviour, and cancellation preservation.
Eight new opt-in PostgreSQL cases exercise real permission/cancellation SQLSTATEs
raised by controlled DO blocks, on sync/native-async reads, with/without budgets.
They assert connection closure and subsequent successful reads. These are server
fault-injection tests, not deployment role grants or real bad-password tests.
The existing explicit PostgreSQL CI step is extended to run them alongside the
previous 19 cases: 27 total.

An isolated harness passed 88 tests across the supplied policy/integration tests
and the new error tests, with 8 PostgreSQL cases skipped. psycopg/Argon2 dependencies
and unrelated package initialisation were stubbed; this is not full Kist, real
crypto, import-graph, or live PostgreSQL validation. Ruff, the full project suite,
and both PostgreSQL CI jobs must still be checked locally/in CI.

No version, ciphertext format, dependency minimum, or release-tag changes.
No health-check API, successful-read trace callback, or missing-key redesign is
introduced by this database-error slice. It does not complete the 0.3.1 gate.
