<p align="center">
  <img src="ressources/kist.png" alt="Kist" width="500" />
</p>


**Kist is a Self-Sufficient, Multi-Profile Secrets Manager & Absolute Git Leak Guard**

Kist is an automated, zero-overhead secrets management engine built for modern engineering teams. It bridges the gap between **GitOps convenience** (editing human-readable YAML configuration files) and **production-grade security** (centralized PostgreSQL storage with Fernet encryption, dynamic in-memory caching, and zero plaintext in Git).

---

## 📖 Table of Contents

- [Philosophy & Key Concepts](#-philosophy--key-concepts)
- [How Kist Works](#-how-kist-works)
  - [Hierarchical Flattening & Type Preservation](#hierarchical-flattening--type-preservation)
  - [Dual-Context Salt Strategy](#dual-context-salt-strategy)
  - [Zero-Downtime Secret Propagation](#zero-downtime-secret-propagation)
- [Installation](#-installation)
- [CLI Reference & Workflows](#-cli-reference--workflows)
  - [1. Initialize Repository & Arm Leak Guard (`kist init`)](#1-initialize-repository--arm-leak-guard-kist-init)
  - [2. Inspect Status & Sync Health (`kist status`)](#2-inspect-status--sync-health-kist-status)
  - [3. Auto-Repair & Fix Environment (`kist fix`)](#3-auto-repair--fix-environment-kist-fix)
  - [4. Multi-Profile Secrets & Password Resolution](#4-multi-profile-secrets--password-resolution)
  - [5. Storing Secrets into Database (`kist lock`)](#5-storing-secrets-into-database-kist-lock)
  - [6. Extracting Secrets from Database (`kist unlock`)](#6-extracting-secrets-from-database-kist-unlock)
  - [7. Git Clean & Smudge Filters](#7-git-clean--smudge-filters)
- [Using Kist in Your Application (Python Library)](#-using-kist-in-your-application-python-library)
  - [Core `Kist` Client](#core-kist-client)
  - [In-Memory Dynamic Store (`DynamicSecretStore`)](#in-memory-dynamic-store-dynamicsecretstore)
  - [Asynchronous Dynamic Store (`AsyncDynamicSecretStore`)](#asynchronous-dynamic-store-asyncdynamicsecretstore)
  - [FastAPI Production Integration](#fastapi-production-integration)
  - [TTL Caching Store (`TTLSecretStore`)](#ttl-caching-store-ttlsecretstore)
- [CI/CD Pipelines & Leak Prevention](#-cicd-pipelines--leak-prevention)
- [Database Schema Reference](#-database-schema-reference)
- [Troubleshooting](#-troubleshooting)

---

## 🧠 Philosophy & Key Concepts

Traditional secrets management often forces teams into one of two extremes:
1. **Cumbersome External Vaults**: Heavy infrastructure (e.g., dedicated Vault clusters, complex IAM federation, network latency, and high operational overhead).
2. **Insecure Git Practices**: Plaintext `.env` files, unencrypted configs accidentally committed to Git, or static `.git-crypt` setups that do not synchronize with runtime databases.

**Kist provides a lightweight, unified alternative:**
- **Zero Additional Services**: Leverages PostgreSQL—which your stack already runs—as the central encrypted secret store.
- **Native Git Filter Integration**: Transparently encrypts secrets during `git add` (`clean` filter) and decrypts them during `git checkout` (`smudge` filter).
- **Hardened Git Leak Guard**: A pre-commit hook and CI/CD scanner inspect staged blobs and hard-abort if unencrypted plaintext secrets are about to be committed.
- **Hierarchical Dot-Notation with Type Preservation**: Write structured, nested YAML files (`secrets_production.yaml`) that flatten into dot-delimited keys (`database.postgres.port: 5432`) while retaining native data types (integers, booleans, floats, arrays, nulls).
- **Real-Time Push Invalidation**: When a secret is rotated with `kist lock`, PostgreSQL emits `pg_notify` events to instantly invalidate in-memory caches across all running microservice replicas without restarts.

---

## ⚙️ How Kist Works

```
┌────────────────────────────────────────────────────────────────────────┐
│                             Developer / CI                             │
│                                                                        │
│   secrets_prod.yaml (Plaintext in local working tree)                  │
│          │                                                             │
│          ├─────────► [git add] ──► Git Clean Filter ──► [Salt + Fernet]│
│          │                         (Random 16B Salt)    in Git Repo    │
│          │                                                             │
│          └─────────► [kist lock] ──► Flatten + Fernet Encrypt          │
│                      (--prune)                                         │
└──────────────────────────────────────────────┬─────────────────────────┘
                                               │
                                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        PostgreSQL Database                             │
│                                                                        │
│   kist_profiles (profile_name, crypto_salt)                            │
│   kist (profile_id, secret_key, encrypted_blob)                        │
│                                                                        │
│   ──► Emits NOTIFY kist_secret_updated ──────────────────┐             │
└──────────────────────────────────────────────────────────┼─────────────┘
                                                           │
                                                           ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    Application Replicas (FastAPI / Flask)              │
│                                                                        │
│   DynamicSecretStore (Memory Cache <0.01ms)                            │
│   Background thread listening to PostgreSQL LISTEN                     │
│   Instant cache invalidation on rotation (Zero Downtime)               │
└────────────────────────────────────────────────────────────────────────┘
```

### Hierarchical Flattening & Type Preservation
Kist allows teams to organize secrets logically in YAML hierarchies while preserving native data types:

```yaml
# secrets_production.yaml
sql:
  pg:
    user: "master_user"
    port: 5432
    ssl_enabled: true
    timeout: 5.5
third_party:
  stripe:
    live_token: "sk_live_123456789"
```

When locked, Kist flattens this tree into dot-notation database keys with JSON serialization to preserve numbers, booleans, and nested structures:
- `sql.pg.user` &rarr; `"master_user"`
- `sql.pg.port` &rarr; `5432` (integer preserved)
- `sql.pg.ssl_enabled` &rarr; `true` (boolean preserved)
- `third_party.stripe.live_token` &rarr; `"sk_live_123456789"`

### Dual-Context Salt Strategy & Memory-Hard KDF
- **Argon2id Key Derivation**: Kist derives 256-bit cryptographic Fernet keys using **Argon2id** ($m=64\text{ MB}, t=2, p=4$). Argon2id provides state-of-the-art memory hardness, completely neutralizing GPU, ASIC, and FPGA parallel dictionary and brute-force cracking attacks.
- **Production Context (with Database)**: When `KIST_DATABASE_URL` is configured, Kist generates a unique cryptographically secure 16-byte random salt per profile in `kist_profiles`.
- **Local Context (Git Filters & Envelope Prepending)**: When staging and pulling files, Kist generates a fresh 16-byte random salt (`os.urandom(16)`) and prepends it to the ciphertext header (`[16 bytes salt + Fernet ciphertext]`). This completely eliminates rainbow table precomputation attacks while keeping Git operations 100% offline and decoupled from database access.
- **Strict POSIX Permissions**: Auto-generated credentials in `~/.kist/` are created with `0700` (`drwx------`) directory permissions and `0600` (`-rw-------`) file permissions to prevent local privilege escalation or world-readable key exposures.
- **Enforced TLS/SSL Transport Security**: All PostgreSQL connections automatically enforce TLS/SSL encryption (`sslmode=require` by default, or `verify-full`). Insecure connection modes (`disable`, `allow`, `prefer`) are strictly disallowed and upgraded to prevent man-in-the-middle attacks across networks.

### Zero-Downtime Secret Propagation
Static caches require restarting containers or polling databases periodically. Kist's `DynamicSecretStore` uses PostgreSQL `LISTEN / NOTIFY` to push invalidation signals to applications the millisecond `kist lock` runs.

---

## 📦 Installation

Install Kist using `pip` or `uv`:

```bash
# Using uv (recommended)
uv add kist

# Or using pip
pip install kist
```

---

## 🛠️ CLI Reference & Workflows

### 1. Initialize Repository & Arm Leak Guard (`kist init`)

Run `kist init` inside your Git repository root:

```bash
kist init
```

This command automatically:
1. Configures Git clean/smudge filters (`filter.kist.clean`, `filter.kist.smudge`).
2. Creates `.gitattributes` mapping `secrets*.yaml` and `secrets*.yml` to the Kist filter.
3. Appends `.kist/` (local profile password directory) to `.gitignore`.
4. Installs a virtualenv-resilient `.git/hooks/pre-commit` hook to prevent plaintext secret leaks.

---

### 2. Inspect Status & Sync Health (`kist status`)

Run `kist status` at any time to verify your environment health across Git filters, local profiles, staging encryption, and database synchronization:

```bash
kist status
```

Example Output:
```text
📦 Kist Status Overview
==================================================

🛡️  Git Pipeline & Hooks:
  ✔ Git clean filter configured
  ✔ Git smudge filter configured
  ✔ .gitattributes configured (secrets*.yaml)
  ✔ .gitignore protects .kist/
  ✔ Pre-commit leak guard installed & active

🔑 Secret Profiles Detected:
  • Profile 'default' (secrets.yaml)
    - Password: Found via ~/.kist/pwd_default
    - Git Staging: Clean / unstaged working copy
    - DB Sync: 4 secrets synced (Last updated: 2026-09-18 10:30)

  • Profile 'production' (secrets/secrets_production.yaml)
    - Password: Found via env $KIST_PASSWORD_PRODUCTION
    - Git Staging: Clean (Encrypted blob in index)
    - DB Sync: 8 secrets synced (Last updated: 2026-09-18 10:45)

  • Profile 'staging' (secrets/secrets_staging.yaml)
    - Password: ⚠️  MISSING (Set KIST_PASSWORD_STAGING)
    - DB Sync: Not configured / uninitialized

🗄️  Database:
  ✔ postgresql://user:***@localhost:5432/secrets_db (Connected)
```

---

### 3. Auto-Repair & Fix Environment (`kist fix`)

Run `kist fix` whenever you clone a repository, switch branches, encounter staging desynchronization, or find unencrypted plaintext warnings in `kist status`:

```bash
kist fix
```

This command automatically:
1. **Repairs Git Plumbing**: Ensures Git clean/smudge filters, `.gitattributes`, `.gitignore`, and the pre-commit leak guard hook are active.
2. **Generates Missing Profile Keys**: Inspects all discovered YAML secret files and auto-generates master keys in `~/.kist/pwd_<profile>` for any profile lacking credentials.
3. **Repairs Staging Index**: Detects unencrypted plaintext secret files or out-of-sync entries in the Git staging index and cleanly re-stages them through the encryption filter.

Example Output:
```text
🔧 Kist Auto-Repair & Environment Sync
==================================================

🛠️  1. Repairing Git Configuration & Plumbing:
⚙️ Hooking Kist filters directly into your native local Git pipeline...
🏆 Initialization Complete! The Leak Guard is armed.

🔑 2. Verifying Secret Profile Passwords:
  ✔ Profile 'default': Key found in ~/.kist/pwd_default
  ✔ Profile 'production': Key found in environment variable ($KIST_PASSWORD_PRODUCTION)

🛡️  3. Inspecting & Repairing Git Staging Index:
  ⚠️  Found unencrypted plaintext for 'secrets.yaml' in Git index. Re-staging...
  ✔ Staged 'secrets.yaml' encrypted via Kist clean filter.

==================================================
🎉 Repair Complete! Your Git filters, profile keys, and staging index are now healthy.
```

---

### 4. Multi-Profile Secrets & Password Resolution

Kist determines the profile name directly from the file name:
- `secrets.yaml` &rarr; Profile: `default`
- `secrets_production.yaml` &rarr; Profile: `production`
- `secrets_staging.yaml` &rarr; Profile: `staging`
- `secrets_team_a.yaml` &rarr; Profile: `team_a`

#### Password Resolution Order:
1. Environment Variable:
   - For `default`: `KIST_PASSWORD_DEFAULT` or `KIST_PASSWORD`
   - For `<profile>`: `KIST_PASSWORD_<PROFILE>` (e.g. `KIST_PASSWORD_PRODUCTION`) or `KIST_PASSWORD`
2. Local Key File: `~/.kist/pwd_<profile>`
3. Auto-Generation: If neither is found, Kist generates a cryptographically secure token, saves it to `~/.kist/pwd_<profile>`, and prints it to stdout.

---

### 5. Storing Secrets into Database (`kist lock`)

Flattens a local YAML file, encrypts each leaf node with Fernet, writes the records to the `kist` table in PostgreSQL, and emits real-time notifications to all connected applications.

> **💡 Flexible Path & Name Resolution**: You don't need to specify exact subfolder paths (e.g., `secrets/`) or extensions (`.yaml`). Kist automatically locates files in `secrets/` or the project root. For example, `kist lock secrets_production`, `kist lock secrets_production.yaml`, and `kist lock secrets/secrets_production.yaml` all work identically!

```bash
export KIST_DATABASE_URL="postgresql://user:password@localhost:5432/secrets_db?sslmode=require"
export KIST_PASSWORD_PRODUCTION="your_secure_passphrase"

kist lock secrets_production
```

#### Pruning Obsolete Secrets (`--prune` / `-p`)
If you removed keys from your YAML file and want them automatically deleted from PostgreSQL:

```bash
kist lock secrets_production --prune
```

Output:
```text
🔒 Locked 8 secrets into DB for profile 'production'. (Pruned 2 obsolete secrets)
```

---

### 6. Extracting Secrets from Database (`kist unlock`)

Fetches all encrypted secrets for the corresponding profile from PostgreSQL, decrypts them, reconstructs the nested YAML hierarchy with data types preserved, and prints the result:

```bash
kist unlock secrets_production
```

Output:
```yaml
sql:
  pg:
    user: master_user
    port: 5432
    ssl_enabled: true
third_party:
  stripe:
    live_token: sk_live_123456789
```

---

### 7. Git Clean & Smudge Filters

Kist integrates with Git's native filter pipeline:
- **`clean`** (`kist --clean %f`): Reads plaintext from stdin, generates a fresh 16-byte random salt, encrypts it, and writes the `[salt + ciphertext]` blob to Git staging.
- **`smudge`** (`kist --smudge %f`): Reads the encrypted blob from repository object storage, extracts the salt, decrypts it, and populates the plaintext working tree.

---

## 🐍 Using Kist in Your Application (Python Library)

### Core `Kist` Client

Use the `Kist` class for direct database retrieval:

```python
import os
from kist import Kist

# Initialize client (derives profile key from environment or ~/.kist/)
kist = Kist(
    profile_name=os.getenv("KIST_PROFILE", "production"),
    master_password=os.getenv("KIST_PASSWORD")
)

# Fetch decrypted secret by dot-notation path (types preserved!)
db_port = kist.get("sql.pg.port")        # Returns int 5432
ssl_on = kist.get("sql.pg.ssl_enabled")  # Returns bool True
api_key = kist.get("third_party.stripe.live_token")
```

---

### In-Memory Dynamic Store (`DynamicSecretStore`)

`DynamicSecretStore` caches secrets in memory for `<0.01ms` lookups and uses a background thread listening for PostgreSQL `LISTEN` notifications to invalidate cached keys instantly when secrets rotate.

```python
from kist import DynamicSecretStore

# Automatically derives connection params from environment:
# KIST_DATABASE_URL, KIST_PROFILE, KIST_PASSWORD
store = DynamicSecretStore()

# 1. First lookup: Fetches from PostgreSQL, decrypts, and populates memory cache
db_password = store.get("sql.pg.pwd")

# 2. Subsequent lookups: Sub-millisecond in-memory cache hit
db_password = store.get("sql.pg.pwd")

# Clean shutdown
store.close()
```

---

### Asynchronous Dynamic Store (`AsyncDynamicSecretStore`)

For asynchronous Python applications (FastAPI, Litestar, Sanic, asyncio), `AsyncDynamicSecretStore` provides non-blocking async reads and an async notification listener:

```python
from kist import AsyncDynamicSecretStore

async def main():
    async with AsyncDynamicSecretStore(profile_name="production") as store:
        db_user = await store.get("sql.pg.user")
        print(f"User: {db_user}")
```

---

### FastAPI Production Integration

Here is a complete, production-ready example using FastAPI's lifespan context and dependency injection:

```python
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException
from kist import DynamicSecretStore

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize the real-time secrets listener on startup
    app.state.secrets = DynamicSecretStore(
        profile_name=os.getenv("KIST_PROFILE", "production"),
        db_url=os.getenv("KIST_DATABASE_URL"),
        master_password=os.getenv("KIST_PASSWORD"),
    )
    yield
    # Clean shutdown of background listener thread
    app.state.secrets.close()

app = FastAPI(title="Secure API Service", lifespan=lifespan)

def get_secret_store() -> DynamicSecretStore:
    return app.state.secrets

@app.get("/api/db-config")
def get_db_config(secrets: DynamicSecretStore = Depends(get_secret_store)):
    try:
        db_user = secrets.get("sql.pg.user")
        db_port = secrets.get("sql.pg.port")
        # Rotated database credentials propagate instantly without restarting the server!
        return {"status": "ok", "db_user": db_user, "db_port": db_port}
    except KeyError as e:
        raise HTTPException(status_code=500, detail=str(e))
```

---

### TTL Caching Store (`TTLSecretStore`)

For simpler deployments where a dedicated listener thread is not needed, `TTLSecretStore` caches secrets in memory and automatically re-fetches and decrypts them after a configurable duration:

```python
from kist import TTLSecretStore

# Cache secrets in memory with a 60-second expiration TTL
store = TTLSecretStore(ttl_seconds=60)

db_password = store.get("sql.pg.pwd")
```

---

## 🚀 CI/CD Pipelines & Leak Prevention

Kist provides ready-to-use CI/CD templates for the 3 main Git providers in the `ressources/` folder:

| Provider | Path | Capabilities |
| :--- | :--- | :--- |
| **GitHub Actions** | `ressources/github/deploy.yml`<br>`ressources/github/leak-guard.yml` | Push-to-DB sync (`kist lock`) + PR Plaintext Leak Guard |
| **GitLab CI/CD** | `ressources/gitlab/.gitlab-ci.yml` | Multi-stage test and deploy pipelines |
| **Bitbucket Pipelines** | `ressources/bitbucket/bitbucket-pipelines.yml` | Pull request validation and production synchronization |

---

## 🗄️ Database Schema Reference

Kist requires only standard PostgreSQL tables with no specialized extensions or foreign data wrappers:

```sql
CREATE TABLE IF NOT EXISTS kist_profiles (
    id SERIAL PRIMARY KEY,
    profile_name VARCHAR(100) UNIQUE NOT NULL,
    crypto_salt BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kist (
    id SERIAL PRIMARY KEY,
    profile_id INT REFERENCES kist_profiles(id) ON DELETE CASCADE,
    secret_key VARCHAR(255) NOT NULL,
    encrypted_blob BYTEA NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT unique_profile_secret UNIQUE (profile_id, secret_key)
);

CREATE INDEX IF NOT EXISTS idx_kist_profile_lookup ON kist(profile_id, secret_key);
```

---

## 🔍 Troubleshooting

- **`🚨 Plaintext Leak Detected` on `git commit`**:
  Run `kist status` to check whether the profile's password is set or whether `kist init` was run.
- **`❌ Missing encryption password key for profile`**:
  Set the environment variable (e.g., `export KIST_PASSWORD_PRODUCTION="your-secret"`) or ensure `~/.kist/pwd_<profile>` exists.
- **`❌ Cryptographic failure. Password configuration incorrect`**:
  Verify that the password provided matches the one used to encrypt the profile's secrets.
