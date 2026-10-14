<p align="center">
  <img src="ressources/kist.png" alt="Kist" width="500" />
</p>

<h1 align="center">Kist</h1>

<p align="center">
  <strong>Keep It Simple and Trusted.</strong><br />
  Git-governed encrypted secret storage for Python applications.
</p>

<p align="center">
  <a href="#status">Status</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#git-workflow">Git workflow</a> ·
  <a href="#cicd-integration--gitops">CI/CD & GitOps</a> ·
  <a href="#security-boundaries">Security boundaries</a> ·
  <a href="#license">License</a>
</p>

> **Alpha software — Kist 0.1.1.** Kist is suitable for evaluation and controlled self-hosted deployments. Its API, database schema, and encrypted-envelope format may evolve before a stable release. Review the code, test recovery procedures, and do not treat a local Git hook as an organisational security control.

Kist is a Python library and CLI for teams that want secret changes reviewed in Git, stored encrypted in PostgreSQL, and retrieved by Python applications—without operating a separate Vault cluster.

Kist means **Keep It Simple and Trusted**.

It is built for teams that want encrypted secrets and a reviewable Git workflow
without turning secret storage into a second full-time infrastructure project.
The model stays deliberately small: a profile password, authenticated
encryption, PostgreSQL, and clear operational boundaries.

## What Kist does

- Encrypts JSON-compatible secret values with **Argon2id-derived AES-256-GCM** keys.
- Stores encrypted values in PostgreSQL, scoped by organisation, project, and profile.
- Locks nested YAML mappings into dot-separated secret keys while preserving JSON-compatible types.
- Unlocks a profile back into readable YAML when the correct password is available.
- Uses Git clean/smudge filters to keep selected YAML secret files encrypted in Git while exposing plaintext only in the authorised working tree.
- Provides an optional local pre-commit guard that detects plaintext in configured Kist secret paths and common credential patterns.
- Integrates with CI/CD pipelines (**GitHub Actions**, **GitLab CI/CD**, **Bitbucket Pipelines**) for automated PR leak scanning and continuous secret synchronization (GitOps).
- Supports bounded in-memory caches and PostgreSQL `LISTEN` / `NOTIFY` invalidation through the optional runtime store helpers.

## What Kist does not do

Kist 0.1.0 deliberately stays small:

- It does **not** provide the sharks surrounding the island in the image above (you will have to supply your own biological perimeter defense).
- It is **not** a replacement for HashiCorp Vault, a cloud secret manager, or a full identity and governance platform.
- It does **not** include Kist Guard, cloud KMS, HSM, or managed key-release support yet.
- It does **not** protect a secret after an authorised application has decrypted it.
- It does **not** make a local Git hook impossible to bypass (`git commit --no-verify` will always remain an effective way to shoot oneself in the foot).
- It does **not** replace key backup, password-sharing procedures, CI access policy, incident response, or the people responsible for operating them.

Kist reduces moving parts in a secret workflow; it does not replace operational judgement, incident response, or the uncomfortable meeting after a leaked credential.
## Status

Kist is currently an **alpha** project.

The 0.1.0 release supports only the `password-v1` encryption mode:

```text
profile password + random salt
    ↓ Argon2id
Key Encryption Key (KEK)
    ↓ wraps (AES-256-GCM)
Random Data Key (DEK) / Key Bundle
    ↓ encrypts (AES-256-GCM)
Encrypted Kist Envelope
    ↓
PostgreSQL (`kist_secrets`) or Git (`secrets/*.yaml`)
```

Planned but **not included** in 0.1.0:

```text
KMS data-encryption keys
Kist Guard integration
Cloud KMS providers
Managed hosting
Key rotation and migration tooling
```

## Installation

Install from PyPI with `uv` or `pip`:

```bash
uv add kist
```

```bash
pip install kist
```

Check that the package and CLI are available:

```bash
python -c "import kist; print(kist.__version__)"
python -m kist --help
kist --help
```

## Quick start

### 1. Configure Kist

For local development, configure PostgreSQL and a profile password. Never commit these values to Git.

```bash
export KIST_ENV=development
export KIST_TLS_MODE=disable

export KIST_DATABASE_URL='postgresql://kist_user:replace-me@127.0.0.1:5432/kist'
export KIST_PASSWORD='replace-with-a-long-random-password'

# Optional scope values.
export KIST_ORG_ID='local'
export KIST_PROJECT_ID='default'
export KIST_PROFILE='default'
```

For a remote production PostgreSQL service, use TLS with certificate verification:

```bash
export KIST_ENV=production
export KIST_TLS_MODE=verify-full
export PGSSLROOTCERT='/run/secrets/postgres-ca.pem'

export KIST_DATABASE_URL='postgresql://kist_user:replace-me@db.example.internal:5432/kist?sslmode=verify-full'
export KIST_PASSWORD='provided-by-your-runtime-secret-injection-mechanism'
```

`sslmode=require` encrypts transport but does not verify the database server identity. Prefer `verify-full` for remote production databases.

#### Understanding `KIST_ENV` vs `KIST_PROFILE`

To maintain clarity and prevent misconfiguration, Kist separates runtime operational policy from secret partitioning:

| Variable | Dimension | Purpose & Behavior | Typical Values |
|---|---|---|---|
| `KIST_ENV` | **Operational Mode** | Controls transport security and connection safeguards (e.g. enforcing strict TLS and certificate validation on PostgreSQL connections in `production`). Does not change keys or secret partitions. | `development`, `staging`, `production` (default: `development`) |
| `KIST_PROFILE` | **Cryptographic Partition** | Defines the active secret scope, key bundle, and database partition in `kist_profiles`. Determines default password lookup (`KIST_PASSWORD_<PROFILE>`), default file paths (`secrets/<profile>.yaml`), and zero-knowledge blind indexing. | `default`, `team_a`, `billing`, `production` (default: `default`) |

**Common Combinations:**
- **Local development on a team profile:** `KIST_ENV=development KIST_PROFILE=team_a` (permits local non-TLS Postgres while scoping secrets to `team_a`).
- **Production service deployment:** `KIST_ENV=production KIST_PROFILE=team_a` (strictly enforces database TLS while decrypting `team_a` secrets).

### 2. Initialise the database schema

Schema setup is explicit. Run it using the CLI:

```bash
kist init-db
```

Or programmatically in Python:

```python
from kist import Kist

# Initialize the v1 schema
store = Kist()
store.init_db()
```

A normal runtime application should ideally have only the database permissions required to read and write Kist data; it should not need DDL permissions to create or alter tables.

### 3. Lock secrets into PostgreSQL

Lock your default profile's YAML secrets into PostgreSQL using the CLI:

```bash
kist lock
```

Or specify an explicit file path:

```bash
kist lock secrets/default.yaml
```

### 4. Retrieve secrets in Python

```python
from kist import Kist

# Automatically resolves credentials, active profile, and database URL from environment variables
store = Kist()

# Retrieve a value
api_key = store.get("example.api_key")
print(api_key)
```

Output:

```text
example-value
```

You can also set values programmatically:

```python
store.set("example.api_key", "example-value")
```

Or target another profile explicitly (e.g. in multi-profile services or administrative scripts):

```python
billing_store = Kist(profile_name="billing")
stripe_key = billing_store.get("stripe.api_key")
```

The public 0.1.0 API is intentionally small:

```python
from kist import (
    DecryptionError,
    InvalidEnvelopeError,
    Kist,
    KistError,
    KistScope,
    MissingKeyError,
)
```

## How it works

### Password-v1 envelopes

Kist stores an encrypted binary envelope, not a plaintext secret value.

```text
profile password + random salt
    ↓ Argon2id
Key Encryption Key (KEK)
    ↓ wraps (AES-256-GCM)
Random Data Key (DEK) / Key Bundle
    ↓ encrypts (AES-256-GCM)
Encrypted payload (JSON serialised value + context)
```

Each envelope contains, conceptually:

| Component | Purpose | Secret? |
|---|---|---:|
| Magic/version fields | Identifies the Kist format and supported algorithms | No |
| Argon2id parameters | Allows the same password-derived KEK to be recreated | No |
| Salt | Makes each password-key derivation distinct | No |
| Nonce | Makes every AES-GCM encryption distinct | No |
| Wrapped Key Bundle | Stores the encrypted DEK and index key (KEK-wrapped) | Protected |
| Ciphertext and authentication tag | Stores the protected secret value (DEK-encrypted) | Protected, but safe to store |
| Context commitment | Binds the envelope to its intended scope and identity | No |

For a comprehensive beginner-friendly explanation of Kist's cryptographic architecture, envelope model, and threat defenses, see [KIST_ENCRYPTION_101.md](KIST_ENCRYPTION_101.md).

The **salt** is used before encryption to derive a key from a password. The **nonce** is used for every AES-GCM encryption. Both are stored with the ciphertext; neither is a secret. The important rule is that Kist uses a fresh nonce for every encryption under a key.

### Authenticated context

Kist binds each database value to authenticated context that includes:

```text
organisation ID
project ID
profile ID
profile name
logical secret key
secret version
```

That means an encrypted value should not successfully decrypt if it is copied to a different profile, secret key, scope, or version.

For example, ciphertext created for:

```text
local/default/production/database.password/version-4
```

cannot simply be relabelled as:

```text
local/default/production/payment.api_key/version-4
```

and accepted by Kist. The authentication check fails closed.

### YAML lock and unlock

Kist accepts nested YAML mappings and flattens them into dot-separated keys.

```yaml
# secrets/production.yaml
sql:
  pg:
    host: db.internal
    port: 5432
    ssl_enabled: true
third_party:
  stripe:
    api_key: sk_example_value
```

This becomes values similar to:

```text
sql.pg.host                    → "db.internal"
sql.pg.port                    → 5432
sql.pg.ssl_enabled             → true
third_party.stripe.api_key     → "sk_example_value"
```

JSON-compatible types are preserved. Kist uses `yaml.safe_load`; YAML roots must be mappings and mapping keys must be non-empty strings without dots.

Lock YAML secrets into PostgreSQL (defaults to the active profile's secret file, such as `secrets/default.yaml` or `secrets/<profile>.yaml` when `KIST_PROFILE` is set):

```bash
kist lock
```

Or lock an explicit file:

```bash
kist lock secrets/production.yaml
```

Explicitly specify or override a profile:

```bash
kist --profile production lock
```

> **Defense-in-Depth Safety:** By default, `kist lock` verifies that the active profile matches the target file basename (e.g. `--profile production` expects `production.yaml` or `secrets/production.yaml`). Accidental mismatches are blocked to prevent cross-profile data corruption.
> To explicitly load a differently named file for custom workflows, use `--allow-mismatch` or `--force`:
> ```bash
> kist --profile production lock secrets/custom_seed.yaml --allow-mismatch
> ```

Prune database values that no longer appear in the YAML source:

```bash
kist lock secrets/production.yaml --prune
```

> **Destructive Flag Protection:** In interactive terminals, `--prune` prompts for explicit user confirmation before permanently deleting obsolete database rows. In automated pipelines or scripted workflows, supply `--force` or `--yes` to proceed without interactive confirmation.

Reconstruct a profile as YAML:

```bash
kist unlock secrets/production.yaml
```

> **Writer model & concurrency:** Kist serializes concurrent profile writes (such as overlapping CI deployment runs) using PostgreSQL transaction-level advisory locks (`pg_advisory_xact_lock`), and protects programmatic single-key updates (`kist.set`) with row-level locks (`SELECT ... FOR UPDATE`) and automatic retry loops.

### Runtime cache invalidation

When Kist changes a value, it sends a PostgreSQL notification on the `kist_secret_updated` channel. `DynamicSecretStore` and `AsyncDynamicSecretStore` can listen for these events and clear the affected in-memory cache entry.

```text
Git/deployment writer updates Kist database
    ↓
PostgreSQL NOTIFY
    ↓
running application cache invalidates the affected key
    ↓
next read decrypts the current stored value
```

This is cache invalidation, not secret telepathy: each application still needs its configured database access and profile password to retrieve a value.

## Git workflow

Kist integrates with Git clean/smudge filters for selected YAML secret files.

```text
authorised working tree       Git index / repository
-----------------------       ----------------------
plaintext secrets.yaml
        │
        ├── git add ── clean filter ──> encrypted Kist envelope
        │
        └── git checkout <── smudge filter <── encrypted Kist envelope
                                      │
                                      └── plaintext working-tree file
```

### Initialise a repository

Inside a Git work tree:

```bash
kist init
```

Kist configures local clean/smudge filters, appends missing Kist rules to `.gitattributes`, adds `.kist/` to `.gitignore`, and installs a local pre-commit guard when safe to do so.

Expected Kist attribute rules include:

```gitattributes
secrets*.yaml filter=kist
secrets*.yml filter=kist
secrets/*.yaml filter=kist
secrets/*.yml filter=kist
```

Kist will not silently overwrite an unrelated pre-commit hook. Review the hook first, then use the explicit force option only when appropriate.

### Multi-team repositories and per-developer defaults

In shared repositories where multiple teams or services maintain separate secret files (for example, `secrets/team_a.yaml` and `secrets/team_b.yaml`), Kist allows each developer to set their own active default profile without hardcoding team settings into Git:

#### 1. Automatic Git Filter Routing
Git clean/smudge filters automatically infer the target profile from the file path (e.g., `secrets/team_a.yaml` → `team_a`). Developers only need the cryptographic credentials for their own team; other teams' secret files safely remain as encrypted ciphertext blobs in the local working tree without blocking commits or checkouts.

#### 2. Configure Per-Developer Defaults
Each developer sets their active default profile locally (e.g., via directory-level `.envrc` / `direnv`, an untracked `.env.local`, or shell profile):

```bash
# For Team A members:
export KIST_PROFILE=team_a
export KIST_PASSWORD_TEAM_A='team-a-master-password'  # or run: kist profile create team_a

# For Team B members:
export KIST_PROFILE=team_b
export KIST_PASSWORD_TEAM_B='team-b-master-password'  # or run: kist profile create team_b
```

#### 3. Seamless Daily Workflow
With `KIST_PROFILE` configured:
- **CLI Commands:** Running `kist lock` or `kist unlock` without file arguments automatically targets `secrets/<profile>.yaml` (e.g., `secrets/team_a.yaml`).
- **Safety Checks:** `kist lock` detects and blocks accidental cross-team operations if run against another team's file without explicit `--profile` or `--allow-mismatch` flags, preventing cross-profile corruption.
- **Python Runtime:** Calling `store = Kist()` with zero arguments automatically resolves the developer's default team partition and credentials.

### Check and repair local setup

```bash
kist diagnose
kist fix
kist fix --apply
kist status
```

`kist fix` is a dry run. `kist fix --apply` repairs only local Git integration. It does not create profile keys, restage files, or modify encrypted secret values.

### Local hook limits

The local pre-commit guard blocks likely plaintext credentials and plaintext files in Kist-managed secret paths before a normal commit. It is useful fast feedback, but it is **not an absolute Git leak guard**.

Any developer who controls a local clone can bypass a client-side hook, for example with:

```bash
git commit --no-verify
```

Treat local hooks as a seatbelt, not an indestructible force field.

For organisation-wide enforcement:

1. Run an equivalent secret scanner in required CI.
2. Protect production/default branches.
3. Require merge requests and passing security checks.
4. Restrict who can modify CI configuration and security policy.
5. Where you administer the Git server, consider a server-side pre-receive scanner that rejects pushes before refs are updated.

## CI/CD integration & GitOps

Kist turns Git into a secure, reviewable control plane for application secrets (**GitOps for Secrets**) while keeping raw credentials strictly outside of unencrypted Git history and log streams.

```text
┌───────────────────────────────┐     Pull Request     ┌────────────────────────────────────┐
│ Developer pushes branch       │ ───────────────────> │ CI Server: PR Leak Guard           │
│ (secrets encrypted by filter) │                      │ - Verifies valid Kist envelopes    │
└───────────────────────────────┘                      │ - Blocks unencrypted files/tokens  │
                                                       └─────────────────┬──────────────────┘
                                                                         │ Approved & Merged
                                                                         ▼
┌───────────────────────────────┐     PostgreSQL       ┌────────────────────────────────────┐
│ Application Runtime Containers│ <─────────────────── │ CI/CD Server: Secret Sync          │
│ - DynamicSecretStore caches   │    LISTEN/NOTIFY     │ - Runs `kist lock secrets.yaml`    │
│ - Instant auto-invalidation   │                      │ - Updates database ciphertext      │
└───────────────────────────────┘                      └────────────────────────────────────┘
```

### 1. Server-side PR leak protection

While local pre-commit hooks provide fast feedback for developers, server-side CI checks guarantee that no unencrypted secret file or exposed credential ever merges into protected branches (e.g., `main`, `staging`).

In Pull Requests / Merge Requests, CI verifies that all tracked `secrets*.yaml` files are valid `kist-v1` binary envelopes:

```yaml
- name: Verify Secret Envelope Encryption
  run: |
    python - << 'EOF'
    import sys
    from pathlib import Path
    from kist.core import is_kist_envelope

    secret_files = list(Path('.').glob('secrets*.yaml')) + list(Path('.').glob('secrets*.yml'))
    for file_path in secret_files:
        if file_path.is_file() and file_path.stat().st_size > 0:
            if not is_kist_envelope(file_path.read_bytes()):
                print(f"🚨 Plaintext secret leak detected in {file_path}!", file=sys.stderr)
                sys.exit(1)
    print("✅ All secret files verified as encrypted Kist envelopes.")
    EOF
```

### 2. Automated secret deployment & live reload

When a reviewed PR merges to `main`, CI securely synchronizes the updated secrets to your centralized PostgreSQL database:

```bash
# In CI with KIST_DATABASE_URL and KIST_PASSWORD_PRODUCTION configured:
kist --profile production lock secrets/production.yaml
```

When secrets are locked into PostgreSQL, Kist emits a `NOTIFY kist_secret_updated` event. Applications running `DynamicSecretStore` or `AsyncDynamicSecretStore` receive the signal in real time and automatically refresh cached values without container restarts or downtime.

### 3. Production-ready CI templates

Standalone, copy-paste templates are available in the [`ressources/`](ressources/) directory:

- **GitHub Actions** ([`ressources/github/`](ressources/github/)):
  - [`leak-guard.yml`](ressources/github/leak-guard.yml): PR scan and leak prevention.
  - [`deploy.yml`](ressources/github/deploy.yml): PostgreSQL secret sync on merge to `main`.
- **GitLab CI/CD** ([`ressources/gitlab/`](ressources/gitlab/)):
  - [`.gitlab-ci.yml`](ressources/gitlab/.gitlab-ci.yml): Multi-stage pipeline with security scanning, secret sync, and deployment.
- **Bitbucket Pipelines** ([`ressources/bitbucket/`](ressources/bitbucket/)):
  - [`bitbucket-pipelines.yml`](ressources/bitbucket/bitbucket-pipelines.yml): Step definitions for PR leak guard and automated deployment.

For detailed setup instructions and variable configuration, see the [CI/CD Resources Guide](ressources/README.md).

## Password resolution and local profile keys

For any profile named `<name>`, Kist resolves the required password in the following order of precedence:

1. **Profile-Specific Environment Variable**: `KIST_PASSWORD_<NAME_UPPERCASE>` (e.g., `KIST_PASSWORD_PRODUCTION`, `KIST_PASSWORD_STAGING`, `KIST_PASSWORD_DEFAULT`)
2. **Global Fallback Environment Variable**: `KIST_PASSWORD` (used across profiles if no specific variable is defined)
3. **Local Key File**: `~/.kist/pwd_<name>` (e.g., `~/.kist/pwd_production`, `~/.kist/pwd_staging`, `~/.kist/pwd_default`)

### Managing multiple profiles with the CLI

When running CLI commands with the `--profile` flag, Kist automatically resolves the corresponding profile password:

```bash
# 1. Using profile-specific environment variables (recommended for CI/CD & Cloud)
export KIST_PASSWORD_PRODUCTION='super-secret-random-production-key'
export KIST_PASSWORD_STAGING='staging-specific-random-key'

kist --profile production lock secrets/production.yaml
kist --profile staging status

# 2. Using local key files (recommended for local development)
kist profile create development
kist profile create staging

kist --profile staging status
```

Create a local profile password explicitly:

```bash
kist profile create production
```

Kist intentionally does **not** generate profile keys implicitly during normal operations. A surprise key is a fine way to create a surprise recovery problem.

On POSIX systems, Kist uses owner-only protections for local key material:

```text
~/.kist/                 0700
~/.kist/pwd_<profile>    0600
```

Keep local profile keys out of Git, backups with broad access, screenshots, and chat messages. Prefer runtime-injected environment variables or a purpose-built secret delivery mechanism for deployed applications.

## Python runtime stores

Kist includes optional bounded in-memory cache wrappers in `kist.stores`.

```python
from kist.stores import TTLSecretStore

store = TTLSecretStore(
    profile_name="production",
    ttl_seconds=30,
)

api_key = store.get("third_party.stripe.api_key")
```

For PostgreSQL notification-driven invalidation:

```python
from kist.stores import DynamicSecretStore

store = DynamicSecretStore(
    profile_name="production",
    auto_start=True,
)

try:
    api_key = store.get("third_party.stripe.api_key")
finally:
    store.close()
```

For asynchronous applications:

```python
from kist.stores import AsyncDynamicSecretStore

async def use_secrets() -> None:
    async with AsyncDynamicSecretStore(
        profile_name="production",
    ) as store:
        api_key = await store.get("third_party.stripe.api_key")
```

### Caching warning

Caching makes reads faster by retaining **plaintext** in process memory for a bounded period. Use it only when that trade-off is acceptable for your application. Set an explicit cache policy or disable caching if you need every read to go back through Kist.

## Security boundaries

Kist is deliberately explicit about what it protects and what it does not.

### Kist helps protect against

- Accidental storage of plaintext secret values in the Kist PostgreSQL tables.
- Accidental storage of configured Kist YAML files as plaintext Git blobs when filters are installed and used normally.
- Undetected modification or substitution of encrypted values across authenticated Kist scope/context.
- Simple reuse of a database dump or Git blob without the corresponding profile password.
- Stale in-process cache values after a Kist update, when notification invalidation is configured and connected.

### Kist does not protect against

- A compromised authorised application process that can legitimately retrieve a secret.
- Malware, debug tooling, crash dumps, or hostile dependencies reading application memory.
- A leaked profile password.
- A developer intentionally bypassing or removing a local Git hook.
- A Git server, CI system, database administrator, or operating-system administrator compromised at a higher trust level.
- Deletion, rollback, availability failures, or backup loss unless your infrastructure handles them.
- Business-sensitive metadata in logical secret names, project names, or environment variables.

Do not put plaintext secret values, bearer tokens, passwords, or private keys into:

```text
Git commit messages
CI logs
issue trackers
URLs or query strings
KMS/encryption context
error messages
screenshots
```

## Database model

Kist organizes PostgreSQL storage into an isolated, zero-knowledge relational hierarchy:

```text
kist_organizations
    └── kist_projects
            └── kist_profiles
                    ├── kist_key_bundles (wrapped content & index keys)
                    └── kist_secrets     (HMAC lookup tokens & encrypted payloads)
```

- **`kist_key_bundles`**: Stores the randomly generated 256-bit `content_key` and `index_key`, wrapped with the Argon2id-derived profile password (KEK).
- **`kist_secrets`**:
  - `lookup_token`: 32-byte HMAC-SHA256 hash of the secret name (zero plaintext secret names in the database).
  - `encrypted_blob`: AES-256-GCM encrypted payload containing `{"key": ..., "value": ...}` bound to scope, bundle ID, and version via authenticated additional data (AAD).
  - `secret_version`: Monotonically incremented version number preventing rollback and transplantation attacks.
  - `updated_at`: Timestamp of the latest mutation.

The database stores encrypted values and wrapped keys, never profile passwords or plaintext secret names. The profile password remains external to PostgreSQL.

For production, use separate roles:

```text
migration/setup role
→ creates or migrates schema

runtime application role
→ reads/writes only required Kist data
→ does not have broad DDL permissions
```

## Troubleshooting

### `MissingKeyError` or “No encryption key configured”

Set the relevant profile environment variable:

```bash
export KIST_PASSWORD_PRODUCTION='...'
```

or create an explicit local key:

```bash
kist profile create production
```

### PostgreSQL connection fails

Check that the URL points to a running PostgreSQL server and that local TLS settings are intentional:

```bash
pg_isready -h 127.0.0.1 -p 5432
```

For a local non-TLS development server:

```bash
export KIST_ENV=development
export KIST_TLS_MODE=disable
```

For production remote PostgreSQL, use `verify-full` and provide a trusted CA certificate.

### Git checkout refuses to decrypt a secret file

Check that the correct profile password is available and that the repository/path/scope context matches the one used when the file was encrypted:

```bash
kist status
kist diagnose
```

Kist fails closed when the password, encrypted content, profile, scope, or path does not match.

### Kist pre-commit guard blocks a commit

First, assume the warning is useful. Check the staged content:

```bash
git diff --cached
```

If a real credential was staged in plaintext, remove it, rotate it if needed, and use the approved Kist workflow. If you believe it is a false positive, adjust policy deliberately rather than treating `--no-verify` as a normal workflow.

## Development and release notes

Kist 0.1.0 is designed to be understandable before it is expansive. If you find a security issue, report it privately through the repository’s security-advisory process rather than opening a public issue with exploit details.

Before using Kist for sensitive production workloads, review:

- profile-password generation, storage, backup, and rotation;
- PostgreSQL authentication, authorisation, network exposure, and backups;
- TLS verification for remote database connections;
- CI/server-side secret scanning and protected branch policy;
- runtime process security and logging;
- recovery procedures after a lost profile password or leaked credential.

## License

Kist is licensed under the [Apache License, Version 2.0](LICENCE).

Apache-2.0 is a permissive license: you may use, modify, redistribute, and use Kist commercially, subject to the license terms and preservation of applicable notices. It includes an explicit patent grant from contributors.

Cryptographic primitives (AES-256-GCM AEAD and Argon2id KDF) are powered by the standard Python Cryptographic Authority ([`cryptography`](https://github.com/pyca/cryptography)) library.

See [LICENCE](LICENCE) and [NOTICE](NOTICE).

---

<p align="center">
  <strong>Keep It Simple and Trusted.</strong><br />
  Encrypt the value. Review the change. Protect the boundary. Keep the drama for production incidents you did not have.
</p>
