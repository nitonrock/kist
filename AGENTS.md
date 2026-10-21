# Agent Guidelines for Kist

High-signal invariants, workflows and conventions for AI agents and contributors. Kist is security-critical: when in doubt, fail closed and add a test.

---

## 1. Toolchain & commands

- **Always use `uv`.** Never invoke bare `pip` or system `python` for development.
  - Install dependencies: `uv sync --group dev`
  - Unit tests (no database): `uv run pytest -q --ignore=tests/test_ci_projects_e2e.py -k "not database and not cli_delete_secret and not cli_profile_delete"`
  - PostgreSQL tests: start one with `docker compose up -d`, then
    ```bash
    export KIST_TEST_DATABASE_URL=postgresql://kist:kist@127.0.0.1:5432/kist
    KIST_ENV=development KIST_TLS_MODE=disable KIST_DATABASE_URL=$KIST_TEST_DATABASE_URL \
      uv run pytest -q --ignore=tests/test_ci_projects_e2e.py -k "database or cli_delete_secret or cli_profile_delete"
    ```
  - CI (`.github/workflows/tests.yml`) runs exactly these two steps. `tests/test_ci_projects_e2e.py` needs local sibling projects and is never run in CI.
  - Build: `uv build`; check the distribution: `uvx twine check dist/*`

---

## 2. Cryptographic invariants

### A. Two envelope formats, one password per profile
- **Database (`kist-db-v1`):** the profile password (Argon2id) derives a KEK that only wraps a key bundle (`content_key` + `index_key`) in `kist_key_bundles`. Secret values in `kist_secrets` are AES-256-GCM under `content_key`.
  - Never run Argon2id per secret read/write; bundles are unwrapped once per store.
- **Git files (`kist-git-v1`):** the whole file is one envelope, Argon2id KEK over the YAML bytes. Comments and formatting are preserved; YAML is never parsed by the filter.
- **Offline files:** `kist export` writes the same Git envelope; `Kist.from_file()` / `FileKist` read it without a database.
- **Shared copies (`kist-share-v1`):** `kist share` encrypts a file for the profile only (context = format + profile, no repository or path), so a person can open it anywhere with `kist show`. Never write a shared copy inside the source repository.

### B. Zero-knowledge storage
- Plaintext secret names never reach database columns or logs. Lookups use `HMAC-SHA256(index_key, _canonical_aad(context))`, verified with `hmac.compare_digest` after decryption.
- Git envelopes hide key names too (deliberately unlike sops): names alone leak vendors, environments and customers.

### C. Context binding (AAD)
- Every ciphertext is bound with `_canonical_aad(dict)`. Git context = format, `KIST_ORG_ID`, `KIST_PROJECT_ID`, profile, `KIST_REPOSITORY_ID`, repository-relative path. Moving a file or changing scope requires re-encryption (`git add --renormalize`).
- The v1 header stores SHA-256 of the AAD; use it to match paths (diff driver, guard) without decrypting.

### D. Git filter behaviour
- **clean** never stages plaintext: no password means refuse. An already-encrypted file is passed through only if it is bound to this path. If the plaintext is unchanged, reuse the staged/committed envelope (stable ciphertext); `KIST_FRESH_ENCRYPTION=1` and rotation force fresh encryption.
- **clean password check:** refuse to re-encrypt a file when the resolved password opens neither its staged nor its committed version (nor does a retired password of the profile). It prevents a wrong password (typically a generic `KIST_PASSWORD`) from silently re-encrypting a file. Rotation sets `KIST_ALLOW_PASSWORD_CHANGE=1`; never bypass the check elsewhere.
- **merge** (`merge=kist`, `kist --merge %O %A %B %P %L`) decrypts the three versions into an owner-only temporary directory (`$XDG_RUNTIME_DIR` when available), runs `git merge-file`, and writes the result encrypted into `%A`. Conflicts become plaintext markers in the checked-out file only. Without a password it reports a conflict and leaves `%A` untouched.
- **Settings files:** `kist_setting(name, profile)` resolves each `KIST_*` setting independently: environment variable, then `~/.kist/env_<profile>`, then `~/.kist/env`, then the built-in default. Profile files accept only `KIST_ORG_ID`, `KIST_PROJECT_ID`, `KIST_REPOSITORY_ID`, `KIST_DATABASE_URL`; `env` also accepts `KIST_ENV`, `KIST_TLS_MODE`, `KIST_USE_RETIRED_PASSWORDS` (machine-wide policy). Files are parsed (never executed), must be owner-only like password files, and refuse unknown names, passwords and `KIST_PROFILE`. Always pass the profile when reading a scope or database URL, so the profile file applies.
- **Filter command:** `kist init` records the absolute path of the running `kist` (project `.venv` or global install, kept unresolved so `uv tool` upgrades stay valid; `--kist-path` overrides). IDEs launched from the desktop lack the shell `PATH`.
- **smudge** leaves the file encrypted ("locked", like git-crypt) when no password opens it; content that is not a Kist envelope is always refused.
- **textconv** (`diff=kist`, `kist --textconv`) prints plaintext only where a password opens the blob, otherwise a placeholder with a fingerprint. Never set `diff.kist.cachetextconv` (it would cache plaintext in Git notes).
- The pre-commit guard (`kist pre-commit-guard`, `--all-files` in CI) checks added, copied, modified and renamed files. Every file under the built-in secret names or routed through `filter=kist` by `.gitattributes` must be a well-formed envelope (header checked without a password) bound to its path.
- Local protections can be bypassed by whoever controls the clone (filter override, a clone without `kist init`); only the required CI guard or a server-side hook enforces. `git commit --no-verify` skips the hook but not the clean filter.

### E. Password lookup (`get_profile_password`)
1. `KIST_PASSWORD_<PROFILE>` (or exact-case `KIST_PASSWORD_<profile>`)
2. `KIST_PASSWORD` when `KIST_PROFILE` names this profile
3. `~/.kist/pwd_<profile>` (0600, directory 0700)
4. `KIST_PASSWORD` when `KIST_PROFILE` is unset

A generic password must never override another profile's own password. `kist lock --all` ignores the generic password unless `KIST_PROFILE` is set. Retired passwords (`pwd_<p>.old-<ts>`, `KIST_RETIRED_PASSWORDS_<P>`) are for decryption only.

### F. Separation of concerns
- `kist init` is purely local (attributes, filters, diff and merge drivers, hook) and upgrades old attribute rules in place. No network, no database.
- `kist status` is read-only and is the single place for setup checks (filter command and version, drivers, password sources, whether each committed file opens). Other user-facing commands only print a one-line hint from `setup_hint()`; repairs go through `kist init`.
- `kist init-db` is the only DDL command.

---

## 3. Terminology & scope

- Say **password** (profile password), not "key" or "master password". "Key" is reserved for secret names and internal data keys.
- `KIST_ENV` governs security policy (TLS enforcement); `KIST_PROFILE` selects the logical profile.
- Profile from a path: `secrets/<p>.yaml`, `secrets_<p>.yaml`, any depth below a `secrets/` folder; `secrets.yaml` is `default`.
- `Kist()` without arguments uses `KIST_PROFILE` or `default`.

---

## 4. Code & tests

- **Public API stays small:** `Kist`, `KistScope`, `FileKist`, `TTLSecretStore`, `DynamicSecretStore`, `AsyncDynamicSecretStore`, plus the documented helpers in `kist/__init__.py`.
- **Exceptions:** subclass `KistError` (`MissingKeyError`, `InvalidEnvelopeError`, `DecryptionError`, `InsecureKeyStoreError`, `ConcurrentWriteError`, `SchemaVersionError`). Messages must say what to check, never include secret values.
- **Tests:**
  - Every feature and fix needs a deterministic test, in the module matching the area (`test_git_diff.py`, `test_safety.py`, `test_ci_lock.py`, `test_rotate.py`, `test_export.py`, `test_file_store.py`, `test_stores.py`, `test_kist.py`). Bug fixes get a regression test that fails before the fix.
  - Tests needing PostgreSQL must have `database` in their name and skip without `KIST_TEST_DATABASE_URL`.
  - Git behaviour is tested end-to-end with real `git` and `python -m kist` as the filter.
  - Never weaken, mock out or skip security tests.
- Use only obviously fake example secrets (`example-…`, `*.invalid`) in tests and docs.

---

## 5. Releases & repository hygiene

- Bump `version` in `pyproject.toml` together with the README PyPI badge and the `kist==` pins in `resources/` (`tests/test_release_consistency.py` enforces it); run `uv lock`.
- Tag with `git push origin vX.Y.Z` (one tag), never `--tags`.
- Commits are authored by the maintainer: no `Co-authored-by:` trailers for AI agents or tools.
- Never commit real secrets, plaintext secret files or `~/.kist` contents.
