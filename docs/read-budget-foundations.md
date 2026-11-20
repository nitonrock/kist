# Read-budget foundations

Status: internal primitives only; public reads are unchanged.

`kist._read_policy` supplies one cooperative monotonic budget and an internal
exception catchable as both KistError and TimeoutError. It is not a supported
public import. No package-root exports are added.

A timeout is None (disabled), or a finite positive real number of seconds.
Booleans, strings, zero, negative and non-finite values are rejected. The budget
begins at construction; checking a later phase never restarts it. At or after
expiry, checks raise with an allowlisted phase, elapsed time and stable reason.
The helper has no driver cause and makes no automatic retry decision.

## Integration contract for the next patch

Create one budget at public read entry and carry it through scope/session waits,
connection acquisition, scope initialisation, schema checks, bundle unlock,
query execution, record decryption and cleanup. Map each database operation to
the remaining budget. Never renew it per statement or recursive helper call.

The helper alone does not enforce a timeout: it cannot interrupt a blocking
connect, DNS resolution, SQL operation, lock wait or running crypto worker.
SQL cancellation, connection disposal and cleanup bounds need separate code
and fault-injection tests. Do not advertise a hard wall-clock deadline before
those paths are implemented and verified. Missing-password and integrity errors
must never be converted into absent secrets or negative-cache entries.

Sync and native async reads must share semantics. Async database work stays
native async; an already-running crypto worker has a distinct lifetime from its
cancelled waiter. No public timeout argument or full error taxonomy is introduced
by this foundations patch.

## CI correction

The PostgreSQL job explicitly runs tests/test_runtime_read_postgres.py in addition
to its existing selection. The existing -k expression does not select the four
runtime integration tests. The job-level disposable database environment applies
to the new step as well. No database URL or credential is added by this patch.
