# Kist data format, version 1

This document specifies every byte Kist writes: encrypted Git files, `kist share` files, and the PostgreSQL tables. It is the reference for compatibility. When this document and the code disagree, that is a bug; please report it.

## Compatibility promise

- **Every Kist 1.x release opens every file and database written in format version 1.** Kist has written version 1 since 0.1.3: releases 0.1.3, 0.1.5, 0.1.6, 0.2.0, 0.2.4 and 0.2.8, installed from PyPI, all open the frozen samples below. (0.1.0 used an earlier, incompatible layout.)
- Format version 1 is frozen. A change to anything below (layout, algorithms, contexts, labels) needs a new version number; Kist 1.x then keeps reading version 1, and always refuses unknown versions instead of guessing.
- The frozen samples in [`tests/vectors/format_v1.json`](tests/vectors/format_v1.json) enforce this. Every release must open them, and [`tests/test_format_v1.py`](tests/test_format_v1.py) opens them with Kist and with an independent decoder written from this document. The samples are never regenerated: a test pins their SHA-256.

Not covered by the promise: Python APIs whose name starts with `_`, command output wording, and the layout of `kist status`.

## Notation

- Integers are unsigned and big-endian.
- `||` is byte concatenation; `0x00` is a single zero byte.
- `AES-256-GCM(key, nonce, plaintext, aad)` returns ciphertext followed by the 16-byte tag (as in [`cryptography`'s `AESGCM`](https://cryptography.io/en/latest/hazmat/primitives/aead/)).
- Nonces, salts and keys come from the operating system's secure random generator (`os.urandom`).

## Canonical context

Every encryption is bound to a **context**: a JSON object of strings that says what the ciphertext is for. A ciphertext only opens with the exact same context, so an encrypted file cannot be moved to another path, profile, project or database row.

The context is encoded canonically:

```text
context_bytes = UTF-8(JSON with keys sorted, no spaces, separators "," and ":", non-ASCII escaped)
```

In Python: `json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)`.

Context values never contain secret values. They may contain organization, project, profile and repository names, file paths and secret names (database name index only); keep those free of confidential information.

Names (organization, project, profile) are 1 to 100 characters after trimming, not `.` or `..`, and contain no `/`, `\` or NUL.

## Password envelope

Git files, share files and database key bundles all use this envelope. A random 32-byte **data key** encrypts the content; a key derived from the profile password **wraps** the data key.

### Layout

| Offset | Size | Field | Value in version 1 |
|---:|---:|---|---|
| 0 | 4 | magic | `KIST` (`4b 49 53 54`) |
| 4 | 1 | version | `1` |
| 5 | 1 | cipher | `1` = AES-256-GCM |
| 6 | 1 | key derivation | `1` = Argon2id |
| 7 | 1 | flags | `0` |
| 8 | 4 | Argon2 memory, KiB | default 65536 (64 MiB) |
| 12 | 4 | Argon2 iterations | default 2 |
| 16 | 2 | Argon2 lanes | default 4 |
| 18 | 16 | salt | random |
| 34 | 12 | wrap nonce | random |
| 46 | 32 | context hash | SHA-256(`context_bytes`) |
| 78 | 48 | wrapped data key | 32-byte key + 16-byte tag |
| 126 | 12 | content nonce | random |
| 138 | n + 16 | content ciphertext | plaintext length n, plus tag |

The first 78 bytes are the **header**. The smallest valid envelope (empty content) is 154 bytes.

### Encryption

```text
data_key     = random(32)
header       = magic || version || cipher || kdf || flags || memory || iterations || lanes
               || salt || wrap_nonce || SHA-256(context_bytes)
wrapping_key = Argon2id(password as UTF-8, salt, memory, iterations, lanes, length 32)
wrapped      = AES-256-GCM(wrapping_key, wrap_nonce, data_key,
                           "kist-wrap-v1" || 0x00 || header || context_bytes)
ciphertext   = AES-256-GCM(data_key, content_nonce, plaintext,
                           "kist-content-v1" || 0x00 || header || wrapped || context_bytes)
envelope     = header || wrapped || content_nonce || ciphertext
```

The whole header, including the Argon2 settings and the context hash, is authenticated twice: changing any byte makes decryption fail.

### Decryption

A reader must, in this order:

1. Check the magic, and that version, cipher, key derivation and flags are exactly `1, 1, 1, 0`. Anything else is an unsupported envelope; do not try other interpretations.
2. Check the Argon2 settings against reader limits, so that a hostile file cannot make the reader allocate huge memory: memory 19456 to 262144 KiB, iterations 1 to 10, lanes 1 to 16, memory at least 8 × lanes.
3. Compare the context hash with SHA-256 of the expected context (constant-time). A mismatch means the file belongs to another path, profile or scope.
4. Derive the wrapping key, unwrap the data key, decrypt the content. Any authentication failure means a wrong password or modified bytes; report it without detail.

Passwords are non-empty UTF-8 strings of at most 1 MiB.

## Git secret files

Files matching Kist's Git attributes (`secrets*.yaml`, `secrets*.yml`, `**/secrets/**/*.yaml`, `**/secrets/**/*.yml`) are stored in Git as one password envelope. The plaintext is the whole file, byte for byte.

**Profile from the file name:** `secrets.yaml` (or `.yml`) → profile `default`; `secrets_<name>.yaml` → `<name>`; any other matching file → its name without the extension (`secrets/team_a.yml` → `team_a`).

**Context:**

```json
{
  "format": "kist-git-v1",
  "organization": "<KIST_ORG_ID, default local>",
  "project": "<KIST_PROJECT_ID, default default>",
  "profile": "<profile from the file name>",
  "repository": "<KIST_REPOSITORY_ID, default local-repository>",
  "path": "<path relative to the repository root, with / separators>"
}
```

Consequences:

- Renaming or moving a file, or changing one of these settings, needs a decrypt and re-encrypt (Kist's Git filter does it on the next `git add`).
- Encryption is randomised. To keep `git status` quiet, the clean filter reuses the envelope already in the index or `HEAD` when it holds exactly the same plaintext under the current password.

## Share files

`kist share` writes one password envelope to a file (default `~/<name>.kist`, mode 600). The plaintext is the file's content; the context deliberately leaves out the path and scope, so that a colleague with the same profile password can open it from anywhere:

```json
{"format": "kist-share-v1", "profile": "<profile>"}
```

## PostgreSQL storage

Schema version 1 is recorded in table `kist_schema` (`version = 1`). Organizations, projects and profiles are rows with random UUIDs; the database contexts below use those UUIDs, so ciphertext cannot be moved between databases, profiles or rows.

### Key bundle (`kist_key_bundles`)

One row per profile, with `access_mode = "password-wrap-v1"` and `bundle_version = 1`. Column `wrapped_bundle` is a password envelope of a 68-byte payload:

```text
payload = "KKB1" || content_key (32 random bytes) || index_key (32 random bytes)
```

with the context:

```json
{
  "format": "kist-db-key-bundle-v1",
  "organization_id": "<uuid>", "project_id": "<uuid>", "profile_id": "<uuid>",
  "bundle_id": "<kist_key_bundles.id>", "bundle_version": "1",
  "access_mode": "password-wrap-v1"
}
```

The password is derived once per bundle load; individual secrets then use the fast content key.

### Name index

Secret names are never stored in clear. Column `lookup_token` (32 bytes) is:

```text
lookup_token = HMAC-SHA256(index_key, context_bytes of
  {"format": "kist-name-index-v1", "organization_id": "<uuid>", "project_id": "<uuid>",
   "profile_id": "<uuid>", "secret_key": "<secret name, e.g. database.password>"})
```

Secret names are 1 to 255 characters, contain no NUL, and are dot-separated segments that are neither empty nor padded with spaces.

### Secret records (`kist_secrets`)

Column `encrypted_blob`:

```text
encrypted_blob = "KSTR" || 0x01 || nonce (12) || AES-256-GCM(content_key, nonce, payload,
                                                             "KSTR" || 0x01 || context_bytes)
payload        = UTF-8 JSON {"key": "<secret name>", "value": <any JSON value>}
```

with the context:

```json
{
  "format": "kist-db-record-v1",
  "organization_id": "<uuid>", "project_id": "<uuid>", "profile_id": "<uuid>",
  "row_id": "<kist_secrets.id>", "bundle_id": "<key_bundle_id>",
  "lookup_token": "<lookup_token as lowercase hex>",
  "secret_version": "<secret_version as decimal>", "crypto_version": "1"
}
```

A reader must also check that the decrypted payload has exactly the keys `key` and `value`, that the name is valid, and that recomputing the lookup token from the decrypted name gives the row's `lookup_token` (constant-time). Duplicate JSON keys and non-finite numbers are rejected.

Each write increments `secret_version`. The version is bound to the ciphertext, but an attacker who can write to the database can still restore an older row as a whole: in format version 1, **old versions can be put back** without warning, and nothing proves that the set of rows is complete.

## Local password files

Not encrypted, but part of the contract because rotation and CI rely on them:

- `~/.kist/pwd_<profile>`: the profile password, UTF-8, surrounding whitespace ignored. The file and `~/.kist` must be owned by the user and not accessible to group or others; symbolic links are refused.
- `~/.kist/pwd_<profile>.old-<YYYYmmdd-HHMMSS>`: retired passwords kept by `kist profile rotate`, tried (newest first) only to read older content, never to encrypt.
- `~/.kist/env` and `~/.kist/env_<profile>`: settings, `KEY=value` lines; see the README.

## Visible metadata

Encryption hides content, not everything around it. Visible to anyone with the Git repository or the database:

- file names and paths, and therefore profile names;
- approximate content size (ciphertext is 154 bytes plus the plaintext length);
- when files or rows change, and how many rows each profile has;
- the Argon2 settings;
- in the database: organization, project and profile names and their UUIDs.
