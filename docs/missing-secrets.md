# Missing database secrets (unreleased)

Database-backed get()/get_many() on Kist, AsyncKist, ReadSession, and
AsyncReadSession now use the same missing-secret error:

```python
from kist import Kist, MissingKeyError, SecretNotFoundError

store = Kist(profile_name="payments")
try:
    value = store.get("provider.api_key", timeout=2.0)
except SecretNotFoundError:
    # The requested secret is absent; decide whether that is acceptable.
    raise
except MissingKeyError:
    # Password material is unavailable; this is not a missing secret.
    raise
```

## Contract

SecretNotFoundError inherits ReadError (and therefore KistError) and KeyError.
It exposes reason_code="secret_not_found", phase="query", elapsed_seconds,
sqlstate=None, and retryable=False. The message and args contain generic text,
not the requested secret name. It does not provide a .key field.

Existing except KeyError catches still work. Code inspecting KeyError.args[0]
for the missing name must change: it now contains the sanitised message instead.
The caller already has the requested names; Kist does not copy them into its
error object. This does not prevent traceback-local capture, caller logging,
or configuration/secret exposure elsewhere in an application.

An absent key bundle and an absent secret row use the same error. A missing
bundle is not created by a read. A configured password cannot be verified
against a nonexistent bundle; SecretNotFoundError in that case is not proof
that the supplied password was correct or that any ciphertext was authenticated.

## Missing values and defaults

| Call | Absent secret | Stored JSON null |
| --- | --- | --- |
| get(name) | SecretNotFoundError | None |
| get_many(names), no default | SecretNotFoundError | name maps to None |
| get_many(names, default=value) | name maps to value | name maps to None |
| get_many([]) | empty dict; no password/DB access | not applicable |

Explicit Ellipsis remains the strict/default-omitted sentinel, not a fallback
value. Bulk reads preserve input-order deduplication. A strict bulk error does
not return a partial result. This patch adds no single-read default parameter.

A nonempty read checks password presence after input validation and before
scope initialization/database access. Missing material keeps the existing
MissingKeyError; a bulk default never suppresses it. In particular, a profile
with neither a key bundle nor a configured password is a credential failure,
not a successful default lookup. This intentionally changes previous error
precedence when password and database configuration are both missing.
Empty bulk reads still validate timeout and inputs before returning {}.

Wrong passwords against an existing bundle remain DecryptionError. Database,
permission, schema, crypto, cancellation, and validation failures are not
converted into an absent-secret/default result. Arbitrary KeyError from an
input iterator or decoder is not blanket-translated either: only known absent
bundle/row branches and the bulk finisher create SecretNotFoundError.

## Sessions

Session copies now snapshot explicit source state, including password=None,
without re-reading environment variables or password files. Each copied reader
gets its own scope-init lock. This avoids silently reacquiring a password from
the environment when the source currently has no password material.
The source is already a configured Kist reader; the internal copy does not rerun
constructor configuration discovery or validation. This does not promise safe
concurrent mutation of a source reader's configuration.

The existing connection-context return-value fix is preserved. No connection
pool, cache algorithm, worker admission mechanism, or stronger deadline is added.
Dynamic-store/cache and offline FileKist missing-key APIs are outside this patch
and can still expose plain KeyError. This contract is for the four database
read API forms above, not every Kist lookup surface.

## Validation

There are 66 new deterministic cases covering all four API forms, strict bulk,
defaults, stored null, absent bundles, missing/wrong passwords, empty input,
non-missing KeyError, redaction, and session snapshots. Two existing budget-test
fakes gain an explicit _require_password method; the existing bulk parity test
now checks the named type instead of matching a plaintext key in the message.
No parity assertion about native SQL or crypto-only workers is removed.

Eight opt-in PostgreSQL cases cover no-bundle and absent-row states across all
four API forms, defaults/null, recovery after absence, and missing-password
separation. The explicit PostgreSQL CI step now runs 35 cases: 19 runtime,
8 database-error, and 8 missing-secret cases. Use only a disposable DB.

An isolated dependency-stubbed harness passed 136 tests, with eight PostgreSQL
cases skipped and one unrelated standalone TTL-store parity case deselected.
This includes 18 existing parity cases. psycopg/Argon2 and unrelated package
initialisation were stubbed; real crypto, full imports, Ruff, the complete Kist
suite, and live PostgreSQL behaviour still need local/CI validation.

No version, ciphertext format, dependency minimum, or release tag changes.
Phase tracing and health checks remain subsequent work; this is not completion
of the 0.3.1 release gate.
