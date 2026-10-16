# Agent Guidelines for Kist

These guidelines provide high-signal architectural invariants, development workflows, and coding conventions for AI agents and contributors working in this repository.

---

## 1. Development Toolchain & Commands

- **Environment & Package Manager:** Always use `uv`. Never invoke bare `pip` or system `python`.
  - Install dependencies: `uv sync`
  - Install CLI tool globally: `uv tool install kist`
  - Run full test suite: `uv run pytest`
  - Run targeted test: `uv run pytest tests/test_kist.py -k <test_name>`
  - Run package build: `uv build`
  - Check distribution package: `uv run twine check dist/*` (or `twine check dist/*`)

---

## 2. Core Architecture & Cryptographic Invariants

Kist is a security-critical secrets management library providing Git clean/smudge filters, CLI synchronization, and PostgreSQL zero-knowledge storage.

### A. Two-Tier KEK / DEK Envelope Model
- **Database Storage (`kist-db-v1`):**
  - Master passwords (via Argon2id) derive a **Key Encryption Key (KEK)** used *only* to wrap/unwrap a 256-bit Key Bundle (`content_key` DEK + `index_key` blind index key) in `kist_key_bundles`.
  - Individual secret values in `kist_secrets` are encrypted using the random Data Encryption Key (`content_key`) via **AES-256-GCM**.
  - **Invariant:** Never execute Argon2id derivations on individual secret read/write calls (`store.get()` / `store.set()`). Key bundles are unwrapped once upon store initialization.
- **Git File Storage (`kist-git-v1`):**
  - Direct file-level envelope encryption using Argon2id password-derived KEK over YAML payload.

### B. Zero-Knowledge Database Schema & Blind Indexing
- **No Plaintext Key Names:** Plaintext secret names (e.g. `stripe.api_key`, `db.password`) must **never** be stored in database columns or query logs.
- **Lookup Tokens (`kist-name-index-v1`):** Lookups query deterministic 32-byte digests computed via `HMAC-SHA256(bundle.index_key, _canonical_aad(context))`.
- **Integrity Cross-Verification:** Upon retrieval and payload decryption, verify token consistency using `hmac.compare_digest` to prevent token substitution attacks.

### C. Authenticated Additional Data (AAD) Context Binding
- Always bind canonical context dictionaries using `_canonical_aad(dict)` to AES-256-GCM ciphertext to prevent cross-scope, cross-organization, cross-project, or cross-profile payload swapping.

### D. Safe Separation of Concerns
- **`kist init`:** Purely local Git lifecycle operation (`.gitattributes`, `.gitignore`, filter configuration). Must remain completely decoupled from network or database connectivity.
- **`kist init-db`:** Dedicated DDL schema initialization command requiring database credentials and connectivity.

---

## 3. Scope & Defaults Conventions

- **`KIST_ENV` vs `KIST_PROFILE`:**
  - `KIST_ENV` governs operational security policy (e.g. TLS/SSL verification enforcement in `production` vs local `development`).
  - `KIST_PROFILE` defines the logical secret scope, database partition (`kist_profiles`), and key resolution (`KIST_PASSWORD_<PROFILE>`).
- **Default Resolution:**
  - Calling `Kist()` with zero arguments resolves `profile_name` from `os.getenv("KIST_PROFILE", "default")`.
  - Running `kist lock` / `kist unlock` without a positional file argument automatically targets `secrets/<profile>.yaml`, `secrets_<profile>.yaml`, or `secrets.yaml`.

---

## 4. Coding & Contribution Rules

- **Minimal Public API:** Keep the core entry points clean: `Kist`, `KistScope`, `TTLSecretStore`, `DynamicSecretStore`.
- **Test Integrity:**
  - Never bypass, weaken, mock out, or mark tests as `@pytest.mark.skip` unless strictly requiring external live services (e.g. live external PostgreSQL).
  - All new features and bug fixes must be covered by deterministic unit tests in `tests/test_kist.py` or store tests in `tests/test_stores.py`.
- **Formatting & Style:**
  - Follow existing PEP 8 conventions, standard library typing hints, and descriptive exception handling (`KistError`, `KistDecryptionError`, `KistNotFoundError`).
