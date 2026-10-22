<p align="center">
  <img src="https://raw.githubusercontent.com/nitonrock/kist/main/resources/kist.png" alt="Kist" width="500" />
</p>

<h1 align="center">Kist</h1>

<p align="center">
  <strong>Keep It Simple and Trusted.</strong><br />
  Git-governed encrypted secret storage for Python applications.
</p>

<p align="center">
  <a href="https://pypi.org/project/kist/"><img src="https://img.shields.io/badge/pypi-v0.2.8-blue?logo=pypi&amp;logoColor=white" alt="PyPI" /></a>
  <a href="https://pypi.org/project/kist/"><img src="https://img.shields.io/pypi/pyversions/kist?logo=python&amp;logoColor=white" alt="Python versions" /></a>
  <a href="https://github.com/nitonrock/kist/actions/workflows/tests.yml"><img src="https://github.com/nitonrock/kist/actions/workflows/tests.yml/badge.svg" alt="Tests" /></a>
  <a href="https://github.com/nitonrock/kist/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License" /></a>
</p>

<p align="center">
  <a href="#status">Status</a> ·
  <a href="#hello-kist-in-60-seconds">60-second demo</a> ·
  <a href="#how-kist-compares">Comparison</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#git-workflow">Git workflow</a> ·
  <a href="#cicd-integration--gitops">CI/CD & GitOps</a> ·
  <a href="#offline-and-embedded-systems">Offline & embedded</a> ·
  <a href="#rotating-a-profile-password">Password rotation</a> ·
  <a href="#security-boundaries">Security boundaries</a> ·
  <a href="#license">License</a>
</p>

> **Alpha software.** Kist is suitable for evaluation and controlled self-hosted deployments. Its API, database schema, and encrypted-envelope format may evolve before a stable release. Review the code, test recovery procedures, and do not treat a local Git hook as an organisational security control.

Kist is a Python library and CLI for teams that want secret changes reviewed in Git, stored encrypted in PostgreSQL, and retrieved by Python applications—without operating a separate Vault cluster.

Kist means **Keep It Simple and Trusted**: your Git, your PostgreSQL, your passwords. No third party ever holds your secrets ([why](#why-your-own-postgresql)).

## What Kist does

- **Encrypted secrets in Git.** YAML secret files are encrypted automatically on `git add` and readable only where the profile password is present. Changes go through pull requests like any code, and `git diff` shows them in plaintext wherever the password is present.
- **A runtime store in your PostgreSQL.** Python apps read secrets with `Kist().get()` and pick up changes live without a restart.
- **Multi-team isolation.** Each team or environment gets its own profile (`secrets/payments.yaml`, `secrets/production.yaml`) with its own password and data keys, scoped by organisation and project. One profile's password opens nothing else, in Git or in PostgreSQL.
- **Offline and embedded use.** `kist export` ships ciphertext into firmware or containers; `Kist.from_file()` reads it on the device with no database.
- **Password rotation.** One command re-encrypts everything under fresh keys; old commits still open through retired passwords.
- **Leak guard.** A pre-commit hook and CI templates (GitHub, GitLab, Bitbucket) catch plaintext before it lands.

## Hello Kist in 60 seconds

```bash
# 1. Start a throwaway PostgreSQL (docker-compose.yml is in this repo)
docker compose up -d

# 2. Install Kist and point it at the database
uv tool install kist
export KIST_ENV=development KIST_TLS_MODE=disable
export KIST_DATABASE_URL='postgresql://kist:kist@127.0.0.1:5432/kist'

# 3. Create a profile password and the schema
kist profile create default
kist init-db

# 4. Enable Git encryption in your repo (run before staging any secret file)
kist init

# 5. Write a secret, lock it into PostgreSQL, and commit it encrypted
mkdir -p secrets && printf 'example:\n  api_key: example-value\n' > secrets/default.yaml
kist lock
git add secrets/default.yaml   # the clean filter stores an encrypted Kist envelope
git commit -m "Add encrypted secrets"
```

```python
from kist import Kist

print(Kist().get("example.api_key"))  # example-value
```

Your working copy of `secrets/default.yaml` stays readable; Git only stores ciphertext. Check with `git show :secrets/default.yaml | head -c 4`, which prints `KIST`.

The full setup, including production TLS, is in [Quick start](#quick-start).

## How Kist compares

| | **Kist** | **sops** | **git-crypt** | **python-dotenv** | **HashiCorp Vault** | **Infisical / Doppler** |
|--|--|--|--|--|--|--|
| Changes go through Git review & history | ✅ encrypted in commits + CI leak guard | ✅ | ✅ | ❌ plaintext `.env`, usually gitignored | ❌ | ⚠️ via integrations |
| Readable diffs | ✅ full plaintext locally with the password (`git diff`, `git log -p`, merges); ⚠️ binary on GitHub/GitLab, by design: even key names reveal too much ([why](#readable-diffs)) | ✅ key names visible, values encrypted | ⚠️ plaintext locally when unlocked, binary on GitHub | n/a | n/a | n/a |
| Secret names hidden in the repository | ✅ whole file encrypted, by design | ❌ key names stay in cleartext | ✅ | ❌ | n/a | n/a |
| Transparent Git workflow | ✅ clean/smudge filters | ⚠️ explicit `sops edit` | ✅ clean/smudge filters | ❌ | ❌ | ❌ |
| Runtime retrieval API (Python) | ✅ `Kist().get()` | ⚠️ decrypt file at startup | ❌ file only | ✅ plaintext env | ✅ client libs | ✅ SDKs |
| Live reload without restart | ✅ PostgreSQL `LISTEN/NOTIFY` | ❌ | ❌ | ❌ | ⚠️ leases / agent | ✅ |
| Offline / embedded devices | ✅ `kist export` file + `Kist.from_file()`; password from TPM via `systemd-creds` | ✅ decrypt with an age/PGP key; ⚠️ cloud KMS needs network | ⚠️ whole repo + shared key on the device | ❌ plaintext file on the device | ❌ needs the Vault server | ⚠️ encrypted fallback snapshot (Doppler) |
| Password / key rotation | ✅ one command across PostgreSQL + Git; old commits open via retired passwords | ✅ `sops rotate` per file | ❌ not supported | n/a | ✅ | ✅ managed |
| Where your secrets live | Your Git + your PostgreSQL | Your Git (+ cloud KMS if used) | Your Git | Your disk | Your Vault cluster | Vendor cloud (or self-hosted server) |
| Extra infrastructure | PostgreSQL (you likely have it) | None (+ KMS optional) | None | None | Vault cluster | SaaS or self-hosted server |
| Encryption | Argon2id → AES-256-GCM, scope-bound AAD | AES-256-GCM, age / PGP / cloud KMS | AES-256-CTR, GPG | None | AES-256-GCM | AES-256-GCM |
| Multi-team / multi-profile isolation | ✅ per-profile passwords, path-based routing | ⚠️ via `.sops.yaml` rules | ⚠️ multiple keys | ❌ | ✅ policies | ✅ projects/envs |
| Anti-transplant / rollback protection | ✅ context + version bound | ⚠️ MAC per file | ❌ | ❌ | n/a | n/a |
| Cloud KMS / HSM | 🔜 planned | ✅ | ❌ | ❌ | ✅ | ✅ |
| Per-person access | ❌ one shared password per profile; 🔜 optional per-member delivery ([planned](#kist-and-sops-candidly)) | ✅ one key per person (age, PGP, KMS) | ✅ GPG users | ❌ | ✅ | ✅ |
| File formats | ⚠️ YAML only | ✅ YAML, JSON, ENV, INI, binary | ✅ any file | `.env` | n/a | n/a |
| Fine-grained access policies & audit | ❌ (use Git + DB roles) | ❌ | ❌ | ❌ | ✅ | ✅ |
| Best fit | Python teams wanting GitOps secrets + runtime store, no Vault | Polyglot config files, KMS-backed | Small repos, few trusted devs | Local dev only | Enterprise, dynamic secrets | Teams wanting a managed UI |

**Choose Kist when** you want secret changes reviewed in Git, served at runtime from the
PostgreSQL you already run, refreshed live, and shipped as an encrypted file to
offline or embedded devices—without operating a Vault cluster.

Kist and sops make opposite choices on purpose. sops keeps key names readable so pull
requests show *which* secret changed; Kist encrypts the whole file, because names such as
`stripe.live_secret_key`, `aws.prod_root` or `vpn.customer_acme` already reveal your vendors,
environments and customers to anyone who can read the repository. Kist shows readable diffs
only where the profile password is present ([Readable diffs](#readable-diffs)).

**Choose something else when** you need cloud KMS today, dynamic credentials, or central
access policies and audit logs.

### Kist and sops, candidly

[sops](https://github.com/getsops/sops) is the de facto standard for encrypted files in Git: started at Mozilla in 2015, a [CNCF Sandbox project](https://www.cncf.io/projects/sops/) since 2023, with many maintainers and integrations. Kist is young, has one maintainer and has had no external security review. For a security tool, that matters.

**Where Kist is better**

- **Secret names stay hidden.** sops encrypts values only; ["keys are stored in cleartext"](https://pkg.go.dev/github.com/getsops/sops/v3). Kist encrypts the whole file, comments included.
- **Transparent editing.** Edit the file in any editor and `git add` encrypts it. With sops you go through `sops edit` or `sops set`, because editing the encrypted file directly breaks its integrity check ([sops issue #52](https://github.com/getsops/sops/issues/52)).
- **Merges.** Kist's merge driver merges the decrypted text and shows normal conflict markers. Merging sops files is a known pain point ([sops issue #1117](https://github.com/getsops/sops/issues/1117)).
- **Runtime store.** Kist also serves secrets at runtime from PostgreSQL, with live reload. sops is a file tool: you decrypt at deploy time.
- **Guards built in:** leak guard in pre-commit and CI, password consistency check on commit, files bound to their path, `kist status`.
- **No key infrastructure:** one password per profile, no age or PGP keys to manage, works offline.

**Where Kist is weaker**

- **Shared passwords, not per-person keys.** Everyone with access to a profile holds the same password. Removing someone means rotating it and handing the new one to the others. sops encrypts each file for several people's keys, so you add or remove one person at a time.
- **No cloud KMS.** sops works with AWS KMS, GCP KMS, Azure Key Vault, HuaweiCloud KMS, age and PGP ([sops README](https://github.com/getsops/sops)), so access can follow your cloud permissions and their audit logs.
- **Ecosystem.** Flux decrypts sops natively, and it is the only encryption provider Flux supports ([Flux docs](https://fluxcd.io/flux/components/kustomize/kustomizations/)). Kist ships CI templates (GitLab, GitHub, Bitbucket) but no GitOps or infrastructure-tool integrations (Flux, Argo CD, Terraform…), and its runtime library is Python only.
- **Formats.** Kist handles YAML only; sops also handles JSON, ENV, INI and binary files.
- **Reviews on GitHub/GitLab.** sops pull requests show which key changed; Kist's show a binary file. That is deliberate (names reveal too much), but reviewers lose information.
- **Running a program with its secrets.** `sops exec-env` starts a command with secrets as environment variables; Kist has no equivalent for non-Python programs yet.

**Planned: optional per-member access, without a KMS**

The shared password stays the default: it is simple, and handing it to a team through your own channel (a team dotfiles repository, a CI variable) is a legitimate choice. For teams that prefer not to pass passwords around, a later version may deliver the profile password to each member automatically, locked with their public key ([age](https://github.com/FiloSottile/age) or SSH):

- **Opt-in, per profile.** Profiles without a members list work exactly as today, and the password keeps opening everything.
- **Same encryption.** The members list only delivers the profile password; secret files keep their format, so there is nothing to migrate.
- **Same write protection.** Only someone holding the profile password can create a file Kist accepts. Encrypting files directly to public keys would lose that: [anyone who knows the public keys can replace a file with a valid new one](https://words.filippo.io/age-authentication/).
- **Honest limits.** A removed member keeps what they could already read (old commits, values they saw), so the secrets themselves must still be changed, as today. Without a server, nothing records who decrypted what. Only a KMS or a central service provides those.

## Why your own PostgreSQL

Kist does not ask you to sign up for anything. Ciphertext lives in your Git repository and in a PostgreSQL database you already run. Keys live with the people and machines you trust. This is deliberate, for two reasons.

**Keep it simple.** Most teams already operate PostgreSQL: they back it up, monitor it, restrict access to it and know how to restore it. Reusing it means no new cluster to run, no extra agent, and no new vendor to evaluate. That is the first half of the name.

**Keep it trusted.** Secrets are never better protected than by those who own them. Handing them to a third party does not remove the risk; it moves it somewhere you can neither see nor control. A hosted secret manager or CI platform holds the credentials of thousands of customers, which makes it one of the most valuable targets on the internet. When it is breached, every customer rotates at once, on someone else's timeline. With Kist, your secrets are only as exposed as your own infrastructure, and only your own incident response decides what happens next.

Bringing your own database also means:

- **No lock-in.** The schema is documented in [Database model](#database-model), and the envelope format is open. You can leave whenever you like.
- **No outbound dependency.** Secret retrieval keeps working when a vendor has an outage, changes its pricing or shuts down.
- **Defence in depth.** The database never sees plaintext or secret names, only AES-256-GCM ciphertext and HMAC-blinded keys. A stolen database dump is useless without the profile passwords.

The trade-off is honest: you own backups, key custody and access control. Kist keeps those jobs small; it does not make them disappear.

## What Kist does not do

- It does **not** provide the sharks surrounding the island in the image above. Bring your own perimeter defence.
- It is **not** a replacement for Vault, a cloud secret manager or an identity platform.
- It does **not** support cloud KMS or HSM yet.
- It does **not** protect a secret once an authorised application has decrypted it.
- It does **not** stop someone determined to commit plaintext: switching off Kist's filter for one command is still an effective way to shoot oneself in the foot. Only the required CI guard catches it.

Kist reduces moving parts; it does not replace operational judgement, backups or the uncomfortable meeting after a leaked credential.

## Status

Kist is currently an **alpha** project.

The current release supports one encryption mode, password-wrapped keys, in **format version 1** (see [How it works](#how-it-works) for the envelope model).

**Format promise:** format version 1 is frozen and specified byte by byte in [FORMAT.md](https://github.com/nitonrock/kist/blob/main/FORMAT.md). Every Kist 1.x release will open every file and database written in it; Kist has written it since 0.1.3. A future format gets a new version number, and Kist 1.x keeps reading version 1. Frozen test vectors enforce this on every release.

Planned for future releases:

```text
KMS data-encryption keys
Kist Guard integration
Cloud KMS providers
Managed hosting
Migration tooling between key modes (password → KMS/TPM)
Optional per-member delivery of profile passwords (public keys, no KMS)
```

## Installation

### 1. Add to your project

Install from PyPI with `uv`:

```bash
uv add kist
```

### 2. Install globally on your workstation (recommended for Git integration)

To ensure Git clean/smudge filters and pre-commit hooks execute reliably across all IDEs (PyCharm, VS Code, Git GUI clients) and shells without requiring an active virtualenv:

```bash
uv tool install kist
```

## Quick start

### 1. Configure Kist

For local development, configure PostgreSQL and a profile password. Never commit these values to Git.

#### Setting up profile passwords

You can either generate local password files or inject passwords via environment variables:

**Option A: Generate a secure local profile password (recommended for local development)**

Generate a cryptographically secure random password and store it securely in `~/.kist/` with owner-only permissions (`0600`):

```bash
# Generate password for the default profile (~/.kist/pwd_default)
kist profile create default

# Generate password for a specific profile (~/.kist/pwd_team_a)
kist profile create team_a
```

When a local password file exists in `~/.kist/`, Kist resolves it automatically—no password environment variables required.

**Option B: Set environment variables (recommended for CI/CD and containers)**

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

#### Keeping settings in `~/.kist` instead of environment variables

Like passwords in `~/.kist/pwd_<profile>`, the other settings can live in files next to them. That matters for IDEs started from the desktop menu, which do not read `~/.zshrc` or `~/.bashrc` and so never see exported variables.

```text
~/.kist/
├── pwd_team_a      # password of profile team_a
├── env             # settings for all profiles on this machine
└── env_team_a      # settings for profile team_a only
```

`~/.kist/env`:

```sh
# Kist settings for this machine
KIST_ENV=development
KIST_TLS_MODE=disable
KIST_DATABASE_URL=postgresql://kist:kist@127.0.0.1:5432/kist
KIST_ORG_ID=nitonrock
KIST_PROJECT_ID=markets
```

`~/.kist/env_team_a` (only what differs for this profile):

```sh
KIST_PROJECT_ID=project-a
KIST_REPOSITORY_ID=app-config
```

Each setting is looked up on its own, first match wins:

1. the environment variable with the same name (CI and one-off overrides);
2. `~/.kist/env_<profile>`;
3. `~/.kist/env`;
4. Kist's built-in default (`local`, `default`, `local-repository`, no database).

With the files above, profile `team_a` gets `KIST_ORG_ID=nitonrock` (from `env`), `KIST_PROJECT_ID=project-a` (from `env_team_a`, overriding `env`) and `KIST_REPOSITORY_ID=app-config`. A profile without its own file uses `env` entirely.

| Setting | `env_<profile>` | `env` |
|---|---|---|
| `KIST_ORG_ID`, `KIST_PROJECT_ID`, `KIST_REPOSITORY_ID`, `KIST_DATABASE_URL` | yes | yes |
| `KIST_ENV`, `KIST_TLS_MODE`, `KIST_USE_RETIRED_PASSWORDS` | no: one policy per machine | yes |
| `KIST_PROFILE`, passwords, `KIST_DIR` | no | no |

Rules:

- **Format:** one `KIST_NAME=value` per line; blank lines and lines starting with `#` are ignored; optional `export ` prefix and surrounding quotes. No inline comments, so values may contain `#`. The file is parsed, never run as shell code, and an unknown name is an error, not silently ignored.
- **Owner-only:** like password files, each file must be a regular file you own with mode 600 (`chmod 600 ~/.kist/env`), in an owner-only `~/.kist`. Otherwise Kist refuses it: `KIST_DATABASE_URL` contains the database password.
- **Passwords stay in `pwd_<profile>`,** and `KIST_PROFILE` stays an environment variable: a forgotten machine-wide default profile would apply in every project.
- **Identifiers must match everywhere.** `KIST_ORG_ID`, `KIST_PROJECT_ID` and `KIST_REPOSITORY_ID` are part of what each file is encrypted for and of the database scope. They are not secret (the encrypted file holds only a hash of them), but if your laptop, a colleague's and CI use different values, files and database rows do not open. CI still sets them as variables.
- **`kist status` shows each value and where it came from,** with the database password masked:

```text
- team_a: secrets/secrets_team_a.yml; password source: local password file (~/.kist/pwd_team_a); opens committed version: OK
    KIST_ORG_ID=nitonrock (~/.kist/env)
    KIST_PROJECT_ID=project-a (~/.kist/env_team_a)
    KIST_REPOSITORY_ID=app-config (~/.kist/env_team_a)
    KIST_DATABASE_URL=postgresql://kist:***@127.0.0.1:5432/kist (~/.kist/env)
```

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

### 3. Enable Git encryption with `kist init`

Run this once per repository, **before** you `git add` any secret file:

```bash
kist init
```

`kist init` registers the Kist clean/smudge filters, adds the `secrets*.yaml` rules to `.gitattributes`, ignores `.kist/`, and installs the pre-commit leak guard. From then on, `git add secrets/<profile>.yaml` stores an encrypted envelope while your working copy stays plaintext. Without it, Git commits secret files in plaintext.

Each developer must run `kist init` after cloning, because Git filter configuration lives in the local `.git/config` and is never shared through the repository. See [Git workflow](#git-workflow) for details, and `kist diagnose` if a file is not being encrypted.

### 4. Lock secrets into PostgreSQL

Lock your default profile's YAML secrets into PostgreSQL using the CLI:

```bash
kist lock
```

Or specify an explicit file path:

```bash
kist lock secrets/default.yaml
```

### 5. Retrieve secrets in Python

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

You can also set or delete values programmatically:

```python
# Set a secret value
store.set("example.api_key", "example-value")

# Delete a secret value (returns True if deleted, False if not found)
store.delete("example.api_key")
```

Or target another profile explicitly (e.g. in multi-profile services or administrative scripts):

```python
billing_store = Kist(profile_name="billing")
stripe_key = billing_store.get("stripe.api_key")
```

The public API is intentionally small:

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

For a comprehensive beginner-friendly explanation of Kist's cryptographic architecture, envelope model, and threat defenses, see [KIST_ENCRYPTION_101.md](https://github.com/nitonrock/kist/blob/main/KIST_ENCRYPTION_101.md). The exact byte layout is in [FORMAT.md](https://github.com/nitonrock/kist/blob/main/FORMAT.md).

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

JSON-compatible types are preserved. Kist supports standard YAML anchors and merge keys (`<<: *anchor`) to eliminate boilerplate across configurations, while actively validating against duplicate keys within the same block. YAML roots must be mappings and mapping keys must be non-empty strings without dots.

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

Delete an individual secret key from PostgreSQL:

```bash
# Delete a secret (prompts for confirmation in interactive terminals):
kist delete stripe.api_key

# Bypass confirmation prompts in scripts or automated pipelines:
kist delete stripe.api_key --force
```

Delete an entire profile partition or manage local password files:

```bash
# Permanently delete a profile partition and all its encrypted secrets in PostgreSQL:
kist profile delete preview_env

# Delete database partition and also remove local password file (~/.kist/pwd_preview_env):
kist profile delete preview_env --delete-password --force

# Remove local password file without modifying the database:
kist profile remove-password preview_env
```

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

Inside a Git work tree, and again after every fresh clone:

```bash
kist init
```

Kist configures local clean/smudge filters and the diff and merge drivers, appends missing Kist rules to `.gitattributes`, adds `.kist/` to `.gitignore`, and installs a local pre-commit guard when safe to do so.

Expected Kist attribute rules include:

```gitattributes
secrets*.yaml filter=kist diff=kist merge=kist
secrets*.yml filter=kist diff=kist merge=kist
**/secrets/**/*.yaml filter=kist diff=kist merge=kist
**/secrets/**/*.yml filter=kist diff=kist merge=kist
```

Run `kist init` again in repositories set up by older versions: it upgrades the existing rules in place.

`kist init` records the **absolute path** of the `kist` that runs it, so Git finds it even in an IDE started from the desktop menu, which does not read your shell's `PATH`:

```console
$ kist init
Git filter command: /home/you/project/.venv/bin/kist (project virtual environment)
```

- **From the project's `.venv`** (the usual case when `kist` is a project dependency): Git uses the version the project pins. The path survives `uv sync`. If `.venv` is deleted, Git operations on secret files fail with "clean filter 'kist' failed" (nothing is stored in plaintext) until you run `uv sync`.
- **From the global install** (`uv tool install kist`): `~/.local/bin/kist`, which stays valid across `uv tool install --force` upgrades.
- **From a virtual environment outside the repository:** recorded with a warning, because deleting that environment breaks this repository.
- `kist init --kist-path PATH` chooses explicitly. The setting lives in `.git/config`, local to each clone, never committed.

### Readable diffs

`git diff`, `git log -p` and `git show` show the plaintext YAML change wherever the profile password is present, while the repository only ever stores ciphertext:

```console
$ git log -p -1 -- secrets/device.yaml
@@ -1,2 +1,2 @@
 cloud:
-  api_key: example-one
+  api_key: example-two
```

- **Without the password**, the diff shows a placeholder with a short fingerprint instead of failing, so a change is still visible: `[kist: encrypted content 936e812039c9; no password for profile 'payments' opens it]`.
- **Old commits** written before a password rotation are decrypted with the retired passwords.
- **Renamed files** decrypt across the rename with `git log -p --follow`.
- **On GitHub or GitLab**, pull requests show binary changes, by design: decryption only happens on machines that hold the password. Unlike sops, Kist does not leave key names in cleartext, because the names alone (`stripe.live_secret_key`, `vpn.customer_acme`) tell an outsider which vendors, environments and customers you have.

Kist does not set `diff.kist.cachetextconv`, so decrypted text is never cached in Git notes.

### Merging secret files

When two branches change the same secret file, the `merge=kist` driver decrypts the three versions (common ancestor, yours, theirs) into a private temporary directory, merges them line by line with `git merge-file`, and encrypts the result again. Changes to different lines merge cleanly. A real conflict shows up as normal conflict markers in your checked-out file:

```yaml
<<<<<<< ours
db_password: example-ours
=======
db_password: example-theirs
>>>>>>> theirs
```

Edit the file, then `git add` and commit as usual; Git stores only ciphertext. Without the profile password, the merge reports a conflict and keeps your version untouched. The temporary files live in `$XDG_RUNTIME_DIR` (memory-backed, owner-only on Linux) when available and are deleted right after the merge.

### Locked files, stable ciphertext and renames

- **Locked files.** When no password opens a file at checkout, Kist leaves it encrypted in the working tree instead of failing, as git-crypt does. Applications reading it fail; commits, checkouts and diffs keep working. In multi-team repositories each developer sees plaintext only for their own profiles. Content that is not a Kist envelope is still refused.
- **Stable ciphertext.** Encryption is randomised, so `git add` reuses the existing envelope when the plaintext has not changed. Untouched files never show up as modified and commits contain only real changes. Password rotation always re-encrypts; set `KIST_FRESH_ENCRYPTION=1` to force it manually.
- **Renames.** Each envelope is bound to its path. After `git mv`, re-encrypt for the new path with `git add --renormalize <new-path>`; the pre-commit guard blocks the commit until you do.
- **Password check.** Before re-encrypting a changed file, Kist checks that the password it found also opens the version already in Git. If not (typically a `KIST_PASSWORD` meant for another profile), `git add` stops with "the password for profile 'team_a' (from KIST_PASSWORD) does not open the version already in Git", instead of silently switching the file to another password. Content that only a retired password opens is accepted, and moves to the current password. `kist profile rotate` changes passwords on purpose; `KIST_ALLOW_PASSWORD_CHANGE=1` allows it for one command. The check costs nothing extra in the normal case: the previous version is decrypted anyway to keep ciphertext stable.

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

`kist fix` is a dry run. `kist fix --apply` repairs only local Git integration. It does not create profile passwords, restage files, or modify encrypted secret values.

`kist status` is read-only and shows everything in one place:

```text
Git filter command: /home/you/project/.venv/bin/kist (kist 0.2.8, project virtual environment): OK
Git clean filter: OK
Git smudge filter: OK
Git diff driver: OK
Git merge driver: OK
...
Profiles:
- team_a: secrets/secrets_team_a.yml; password source: local password file (~/.kist/pwd_team_a); opens committed version: OK
```

It warns when the recorded `kist` is missing or a different version than the one you run, and when no password opens a committed file. Other commands (`kist lock`, `kist export`, …) print a one-line hint when this clone's setup is missing or broken; repairs go through `kist init`, which is safe to re-run.

### Sending a secret file to someone

Files in your working copy are plaintext, so attaching one to an email sends readable secrets. Use `kist share` instead:

```bash
kist share secrets/secrets_team_a.yml                 # writes ~/secrets_team_a.yml.kist
kist share secrets/secrets_team_a.yml -o ~/Desktop/team_a.kist
```

- It encrypts the file **as you see it now** (uncommitted edits included, with a note) with the profile's usual password.
- The copy is **portable**: repository files are encrypted for their exact path and repository, a shared copy only for the profile, so it opens anywhere.
- It refuses to write inside the repository, where the copy could be committed by mistake, and never overwrites without `--force`.

The recipient runs:

```bash
kist show secrets_team_a.yml.kist                          # prints it; nothing written to disk
kist show secrets_team_a.yml.kist -o secrets/secrets_team_a.yml --force   # into their own repository
```

They need the profile password, sent through another channel than the file. `kist show` finds the profile from the file name, `~/.kist/pwd_*` or `KIST_PASSWORD_*`, or takes `--profile`. It also prints envelopes taken from this repository (for example with `git show HEAD:<file>`). For devices and offline builds, use `kist export`, which keeps the exact committed envelope.

### Local hook limits

The local pre-commit guard blocks likely plaintext credentials and plaintext files in Kist-managed secret paths before a normal commit. Every file under the Kist secret names, or routed through `filter=kist` by `.gitattributes`, must be a well-formed envelope for its path. It is useful fast feedback, but it is **not an absolute Git leak guard**.

What actually happens, tested:

| Attempt | Result |
|--|--|
| `git commit --no-verify` | Skips the hook (the credential scan of other files), but the clean filter still encrypts secret files. |
| `git -c filter.kist.clean=cat commit …` | Commits plaintext: the filter is overridden for one command. |
| A clone where `kist init` never ran, with plaintext pasted into `secrets/` | Commits plaintext: Git ignores a filter it does not know. |

No local tool can prevent the last two: Git never runs repository-provided code in a clone without local configuration, and whoever controls a machine controls its Git. Treat local protections as a seatbelt, not an indestructible force field.

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
│ (secrets encrypted by filter) │                      │ - kist pre-commit-guard --all-files│
└───────────────────────────────┘                      │ - Blocks unencrypted files/tokens  │
                                                       └─────────────────┬──────────────────┘
                                                                         │ Approved & Merged
                                                                         ▼
┌───────────────────────────────┐     PostgreSQL       ┌────────────────────────────────────┐
│ Application Runtime Containers│ <─────────────────── │ CI/CD Server: Secret Sync          │
│ - DynamicSecretStore caches   │    LISTEN/NOTIFY     │ - Runs `kist lock --all`           │
│ - Instant auto-invalidation   │                      │ - Updates database ciphertext      │
└───────────────────────────────┘                      └────────────────────────────────────┘
```

### 1. Server-side PR leak protection

Local hooks give fast feedback; the same check in CI guarantees that no plaintext secret file, likely credential or moved envelope reaches a protected branch, even from a developer without the hook:

```bash
kist pre-commit-guard --all-files
```

It needs no secrets, only the non-secret `KIST_ORG_ID`, `KIST_PROJECT_ID` (and `KIST_REPOSITORY_ID` if you set it), which must match the values developers commit with.

### 2. Lock every profile into PostgreSQL on merge

CI checkouts have no Kist filter, so secret files arrive encrypted. `kist lock` decrypts them in memory; `--all` does it for every tracked secret file whose profile has a password in the job:

```console
$ kist lock --all
locked   secrets/production.yaml -> acme/gateway/production (12 secrets)
locked   secrets/payments.yaml -> acme/gateway/payments (4 secrets)
skipped  secrets/eu/staging.yaml (no KIST_PASSWORD_STAGING in this job)
2 locked, 1 skipped, 0 failed.
```

- **Multi-team:** give each pipeline or environment only the `KIST_PASSWORD_<PROFILE>` variables it may use; the other profiles are skipped. `--only <profile>` restricts a job to one profile, `--require-all` fails when a password is missing, and `--prune` deletes keys removed from the YAML.
- **Wrong password or scope** fails the job with a message naming the variables to check.

When secrets are locked, Kist emits `NOTIFY kist_secret_updated`; applications using `DynamicSecretStore` or `AsyncDynamicSecretStore` refresh their cache without a restart.

### 3. Production-ready CI templates

Standalone, copy-paste templates are available in the [`resources/`](https://github.com/nitonrock/kist/tree/main/resources) directory:

- **GitHub Actions** ([`resources/github/`](https://github.com/nitonrock/kist/tree/main/resources/github)):
  - [`leak-guard.yml`](https://github.com/nitonrock/kist/blob/main/resources/github/leak-guard.yml): PR scan and leak prevention.
  - [`deploy.yml`](https://github.com/nitonrock/kist/blob/main/resources/github/deploy.yml): PostgreSQL secret sync on merge to `main`.
- **GitLab CI/CD** ([`resources/gitlab/`](https://github.com/nitonrock/kist/tree/main/resources/gitlab)):
  - [`.gitlab-ci.yml`](https://github.com/nitonrock/kist/blob/main/resources/gitlab/.gitlab-ci.yml): Multi-stage pipeline with security scanning, secret sync, and deployment.
- **Bitbucket Pipelines** ([`resources/bitbucket/`](https://github.com/nitonrock/kist/tree/main/resources/bitbucket)):
  - [`bitbucket-pipelines.yml`](https://github.com/nitonrock/kist/blob/main/resources/bitbucket/bitbucket-pipelines.yml): Step definitions for PR leak guard and automated deployment.

For detailed setup instructions and variable configuration, see the [CI/CD Resources Guide](https://github.com/nitonrock/kist/blob/main/resources/README.md).

## Password resolution and local profile passwords

For any profile named `<name>`, Kist resolves the required password in the following order of precedence:

1. **Profile-specific variable**: `KIST_PASSWORD_<NAME_UPPERCASE>` (e.g. `KIST_PASSWORD_PRODUCTION`); the exact-case spelling `KIST_PASSWORD_<name>` is accepted too.
2. **`KIST_PASSWORD`, when `KIST_PROFILE` names this profile.**
3. **Local password file**: `~/.kist/pwd_<name>` (e.g. `~/.kist/pwd_production`).
4. **`KIST_PASSWORD`, when `KIST_PROFILE` is not set**, as a last resort.

`KIST_PASSWORD` is the password of the active profile only: it never overrides another profile's own variable or password file. That matters in multi-profile repositories, where an exported `KIST_PASSWORD` would otherwise make the Git filter encrypt every profile with the same password. `kist lock --all` ignores it unless `KIST_PROFILE` is set, and uses it for that profile only.

### Managing multiple profiles with the CLI

When running CLI commands with the `--profile` flag, Kist automatically resolves the corresponding profile password:

```bash
# 1. Using profile-specific environment variables (recommended for CI/CD & Cloud)
export KIST_PASSWORD_PRODUCTION='super-secret-random-production-key'
export KIST_PASSWORD_STAGING='staging-specific-random-key'

kist --profile production lock secrets/production.yaml
kist --profile staging status

# 2. Using local password files (recommended for local development)
kist profile create development
kist profile create staging

kist --profile staging status
```

Create a local profile password explicitly:

```bash
kist profile create production
```

Kist intentionally does **not** generate profile passwords implicitly during normal operations. A surprise password is a fine way to create a surprise recovery problem.

On POSIX systems, Kist uses owner-only protections for local password material:

```text
~/.kist/                 0700
~/.kist/pwd_<profile>    0600
```

Keep local profile passwords out of Git, backups with broad access, screenshots, and chat messages. Prefer runtime-injected environment variables or a purpose-built secret delivery mechanism for deployed applications.

## Rotating a profile password

Rotate when someone with access leaves, on a schedule, or after a suspected leak:

```bash
kist profile rotate production --dry-run   # validate the current password and show the plan
kist profile rotate production             # asks for confirmation; --yes in scripts
git commit -m "rotate production profile password"
```

One command updates everything Kist controls, in an order that never leaves you without a working key:

| Step | What happens |
|--|--|
| 1. Check | The current password must open the profile in PostgreSQL and in Git. Secret files must have no uncommitted changes, so the rotation commit contains only re-encryption. |
| 2. Stage the new password | A new random password is written to `~/.kist/pwd_<profile>.new` (0600) before anything else changes. |
| 3. PostgreSQL | In **one transaction**, Kist generates new data keys (content and index keys), re-encrypts every secret, increments every record version and wraps the new data keys with the new password. Either everything is rotated or nothing is. Listeners receive a `key_bundle_rotated` notification. |
| 4. Local password | The new password replaces `~/.kist/pwd_<profile>`. The old one is kept as `pwd_<profile>.old-<timestamp>`. |
| 5. Git | `git add --renormalize` re-encrypts the profile's secret files with the new password and stages them for review. Nothing is committed for you. |

The command then prints a checklist of what Kist cannot reach: CI/CD secrets, environment variables, other developers, running services, exported device bundles and TPM-sealed credentials.

| Option | Use |
|--|--|
| `--dry-run` | Show the plan and verify the current password; change nothing |
| `--yes` | Skip the prompt (required when not interactive) |
| `--new-password-stdin` | Use your own password instead of a generated one, e.g. `pass show kist/prod \| kist profile rotate prod --yes --new-password-stdin` |
| `--rewrap-only` | Only re-protect the existing keys with the new password. Faster, but anyone who already obtained the keys keeps access. Prefer a full rotation. |
| `--skip-db` / `--skip-git` | Limit the rotation to one side |
| `--git-only` | Recovery: if the database and password file were rotated but Git failed, re-encrypt the Git files with the current password |
| `--show-password` | Print the new password once (interactive terminals only) |

### Password history: old commits keep working

Rotation keeps each old password as a **retired password** (`~/.kist/pwd_<profile>.old-<timestamp>`, owner-only). Retired passwords are used **only to read** older content: when you check out an old commit, `git bisect`, or rebuild an old release. Kist tries the current password first, then retired passwords from newest to oldest. New content is always encrypted with the current password.

```bash
git checkout v1.4.0            # files from before the rotation still open
# kist: secrets/device.yaml: opened with retired password pwd_device.old-20261018-101500 (older content).

kist profile retired-passwords production                     # list
kist profile retired-passwords production --delete --keep 1   # forget all but the newest
```

- **CI and build machines** without local password files can provide retired passwords with `KIST_RETIRED_PASSWORDS_<PROFILE>` (one per line), for example to rebuild an old firmware release.
- **Turn it off** with `KIST_USE_RETIRED_PASSWORDS=off`, for instance on machines that should only ever read current content.
- **Deleting a retired password** makes commits encrypted only with it unreadable on that machine. That is the intended way to retire access to old history, short of deleting it.
- Each retired password that is tried costs one Argon2id derivation, so keep the list short.

Kist does not rewrite Git history to re-encrypt old commits. It would force-push every branch and tag and break every clone, yet anyone who had the old password and a copy of the repository could still read the old values. Password history gives the convenience without that cost; changing leaked values is what actually limits exposure.

What rotation does **not** do:

- **It does not rewrite history.** Old Git commits and old database backups still open with the old password (see [Password history](#password-history-old-commits-keep-working)). After a leak, also change the secret values themselves (new API keys and so on), and treat the old password as compromised.
- **It does not reach other machines.** Running services fail closed on their next database read until they receive the new password. Plan a short rollout: rotate, update CI and deployment secrets, restart services.

From Python:

```python
from kist import Kist

store = Kist("production")                 # current password
store.rotate_profile_keys(new_password)    # new keys, every secret re-encrypted
store.rewrap_profile_password(new_password)  # or: rewrap only
```

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

## Offline and embedded systems

Devices, air-gapped hosts and CI jobs that cannot reach PostgreSQL can read secrets straight from the encrypted envelope that Git stores, with no database involved.

Export the committed blob at build time. It is ciphertext, so it is safe to ship in an image:

```bash
kist export secrets/device.yaml -o dist/device.kist --verify --strict
```

| Option | Effect |
|--|--|
| `-o FILE` / `-o -` | Destination (default `<profile>.kist`), or stdout for pipelines |
| `--rev REV` | Export from a tag or commit, e.g. `--rev v1.4.0` (default `HEAD`) |
| `--staged` | Export the staged version instead of a commit |
| `--verify` | Decrypt in memory with the profile password to prove the export works; needs the key on the build host |
| `--strict` | Fail if the working copy has uncommitted changes (recommended in CI) |

`kist export` reads the blob with `git cat-file`, so plaintext is never written. It refuses files that are not committed or not Kist-encrypted. Without Kist installed, `git show HEAD:secrets/device.yaml > dist/device.kist` produces the same file.

### Reading on the device


```python
from kist import Kist

with Kist.from_file("/etc/app/device.kist", git_path="secrets/device.yaml") as store:
    api_key = store.get("cloud.api_key")
    port = store.get("mqtt.port", 8883)
```

- `git_path` is the repository-relative path at commit time. It is authenticated, together with the profile, `KIST_ORG_ID`, `KIST_PROJECT_ID` and `KIST_REPOSITORY_ID` (from the environment or `~/.kist/env*`). An envelope moved to another path, profile or scope fails to decrypt.
- The profile defaults to the one Git used (`secrets/device.yaml` → `device`). The password comes from the usual lookup: `KIST_PASSWORD_DEVICE`, `KIST_PASSWORD`, or `~/.kist`.
- Argon2id runs once per load, not per `get()`. Values stay in memory only. Call `reload()` after an update; `close()` (or leaving the `with` block) drops them.
- The store is read-only and has no live reload. Plaintext working copies are refused.

### Practical examples

The pattern is the same everywhere: **CI exports ciphertext, the device holds the key.** The build pipeline never needs the profile password, so a compromised build runner cannot leak plaintext. Run `--verify` only where the key is legitimately present.

Use one profile per device class (`secrets/gateway.yaml`, `secrets/sensor.yaml`) so that a compromised unit only exposes its own class.

#### Embedded Linux fleet with the password sealed in the TPM

On systemd 250 or later, `systemd-creds` can seal the profile password to the device's TPM 2.0, so it never sits in plaintext on disk. Kist needs no TPM code for this.

Provision each device once:

```bash
# Read the password from stdin, seal it to this device's TPM, keep only the sealed file
systemd-creds encrypt --with-key=tpm2 --name=kist-password - \
  /etc/credstore.encrypted/kist-password.cred
```

Service unit `/etc/systemd/system/gateway.service`:

```ini
[Service]
ExecStart=/usr/bin/python3 -m gateway
LoadCredentialEncrypted=kist-password:/etc/credstore.encrypted/kist-password.cred
DynamicUser=yes
```

Application:

```python
import os
from pathlib import Path
from kist import Kist

password = (Path(os.environ["CREDENTIALS_DIRECTORY"]) / "kist-password").read_text().strip()

with Kist.from_file("/usr/share/gateway/gateway.kist",
                    git_path="secrets/gateway.yaml",
                    password=password) as secrets:
    mqtt_password = secrets.get("mqtt.password")
    cloud_token = secrets.get("cloud.token")
```

systemd decrypts the credential into a private, in-memory directory that only this service can read. A cloned SD card is useless on another board, because the TPM will not unseal it. Add `--tpm2-pcrs=7` when encrypting to also bind it to the device's Secure Boot state.

Try it on any Linux machine with systemd 250+ and a TPM 2.0, without writing a unit file:

```bash
sudo systemd-run --wait --pipe -p DynamicUser=yes \
  -p LoadCredentialEncrypted=kist-password:/etc/credstore.encrypted/kist-password.cred \
  /opt/gateway/bin/python -m gateway
```

Verified on openSUSE with TPM 2.0 and Kist 0.2.0:

| Check | Result |
|--|--|
| Service runs as a throwaway `DynamicUser` and reads secrets via `Kist.from_file()` | Works |
| Same service without `LoadCredentialEncrypted=` | Cannot read anything (`CREDENTIALS_DIRECTORY` absent) |
| Password on disk | Only the sealed `.cred` file; no plaintext anywhere |
| Credential loaded under another name | Refused by systemd: `Embedded credential name 'kist-password' does not match filename 'other', refusing` (status `243/CREDENTIALS`) |

Files the service needs (Python, the `.kist` file) must live outside `/home` and `/tmp`: `DynamicUser=yes` gives the service a private `/tmp` and a read-only `/home`, and the throwaway user cannot enter your home folder anyway.

#### Firmware build in GitHub Actions

Export from the release tag so that every image is reproducible and traceable to a reviewed commit:

```yaml
# .github/workflows/firmware.yml
on:
  push:
    tags: ["v*"]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.13"   # Kist requires Python 3.11+
      - run: pip install kist
      # No KIST_PASSWORD here: CI handles ciphertext only.
      - run: kist export secrets/gateway.yaml -o rootfs/usr/share/gateway/gateway.kist --rev "$GITHUB_REF_NAME"
      - run: ./build-image.sh rootfs/   # Yocto, Buildroot, mkosi, RAUC bundle…
      - uses: actions/upload-artifact@v7
        with:
          name: gateway-${{ github.ref_name }}
          path: out/*.img
```

#### Yocto / BitBake recipe

Copy the exported file next to your application's recipe (`files/gateway.kist`) and add this to the recipe or a `.bbappend`:

```bitbake
SRC_URI += "file://gateway.kist"

do_install:append() {
    # Use ${WORKDIR} instead of ${UNPACKDIR} on Yocto releases before 5.1
    install -D -m 0644 ${UNPACKDIR}/gateway.kist ${D}${datadir}/gateway/gateway.kist
}

FILES:${PN} += "${datadir}/gateway/gateway.kist"
```

A standalone recipe that only ships this file also needs `S = "${UNPACKDIR}"` on Yocto 5.1 and later.

Ciphertext in the image is fine. Keep the profile password out of the image and provision it per device, as shown above.

#### Edge container with Docker secrets

Bake the envelope into the image and inject the password only at run time:

```dockerfile
FROM python:3.13-slim
RUN pip install --no-cache-dir kist
COPY dist/edge.kist /app/edge.kist
COPY app/ /app/
CMD ["python", "/app/main.py"]
```

```yaml
# compose.yaml on the edge host
services:
  edge:
    image: registry.example.com/edge:1.4.0
    secrets: [kist_password_edge]
secrets:
  kist_password_edge:
    file: /etc/edge/kist_password    # chmod 600, provisioned per host; the container user must be able to read it
```

```python
from pathlib import Path
from kist import Kist

password = Path("/run/secrets/kist_password_edge").read_text().strip()
secrets = Kist.from_file("/app/edge.kist", git_path="secrets/edge.yaml", password=password)
```

#### Air-gapped server

Export on a connected machine, carry the file across, and check it on arrival:

```bash
# Connected side
kist export secrets/plant.yaml -o plant.kist --rev v2.3.0 --strict
sha256sum plant.kist > plant.kist.sha256    # transfer both, e.g. on removable media

# Air-gapped side
sha256sum -c plant.kist.sha256
sudo install -m 0644 plant.kist /etc/plant/plant.kist
```

The checksum catches corruption in transit, and Kist's authenticated encryption rejects any tampering. Neither replaces your site's media-transfer policy.

#### Integration tests without a database

Test jobs can read real, reviewed configuration without a PostgreSQL service:

```python
# conftest.py
import pytest
from kist import Kist

@pytest.fixture(scope="session")
def secrets():
    with Kist.from_file("build/ci.kist", git_path="secrets/ci.yaml") as store:
        yield store
```

```bash
kist export secrets/ci.yaml -o build/ci.kist && KIST_PASSWORD_CI="$CI_KEY" pytest
```

Native hardware-backed keys (TPM 2.0, secure elements) are planned through `kist/kms`. Until then, seal the profile password with `systemd-creds` (see above) or protect it as you would any root credential.

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

or create an explicit local password:

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

### `git add` says the password does not open the version already in Git

The password Kist found for that profile is not the one the file was encrypted with. `kist status` shows the source for each profile (`KIST_PASSWORD_<PROFILE>`, `KIST_PASSWORD` with `KIST_PROFILE`, or `~/.kist/pwd_<profile>`). Usually a generic `KIST_PASSWORD` or `KIST_PROFILE` is set for another profile: unset it or set the right `KIST_PASSWORD_<PROFILE>`. To change the password on purpose, use `kist profile rotate <profile>`.

### Git says "clean filter 'kist' failed" or the filter command is not found

The `kist` recorded by `kist init` is gone, typically a deleted project `.venv`. Run `uv sync` (or re-run `kist init` from the `kist` you want Git to use). `kist status` shows the recorded path and its version. Nothing is stored in plaintext while the filter is missing.

### Kist pre-commit guard blocks a commit

First, assume the warning is useful. Check the staged content:

```bash
git diff --cached
```

If a real credential was staged in plaintext, remove it, rotate it if needed, and use the approved Kist workflow. If you believe it is a false positive, adjust policy deliberately rather than treating `--no-verify` as a normal workflow.

## Development and release notes

Releases are built and published by GitHub Actions ([`release.yml`](https://github.com/nitonrock/kist/blob/main/.github/workflows/release.yml)) when a version tag is pushed, using [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/): no PyPI token exists to leak. Each file carries a signed [attestation](https://docs.pypi.org/attestations/) linking it to this repository and workflow. To check a release before installing it:

```bash
uvx pypi-attestations verify pypi --repository https://github.com/nitonrock/kist pypi:kist-0.2.7-py3-none-any.whl
```

Releases up to 0.2.6 were uploaded manually and have no attestation.

Kist is designed to be understandable before it is expansive. If you find a security issue, report it privately through the repository’s security-advisory process rather than opening a public issue with exploit details.

Before using Kist for sensitive production workloads, review:

- profile-password generation, storage, backup, and rotation;
- PostgreSQL authentication, authorisation, network exposure, and backups;
- TLS verification for remote database connections;
- CI/server-side secret scanning and protected branch policy;
- runtime process security and logging;
- recovery procedures after a lost profile password or leaked credential.

## License

Kist is licensed under the [Apache License, Version 2.0](https://github.com/nitonrock/kist/blob/main/LICENSE).

Apache-2.0 is a permissive license: you may use, modify, redistribute, and use Kist commercially, subject to the license terms and preservation of applicable notices. It includes an explicit patent grant from contributors.

Cryptographic primitives (AES-256-GCM AEAD and Argon2id KDF) are powered by the standard Python Cryptographic Authority ([`cryptography`](https://github.com/pyca/cryptography)) library.

See [LICENSE](https://github.com/nitonrock/kist/blob/main/LICENSE) and [NOTICE](https://github.com/nitonrock/kist/blob/main/NOTICE).

---

<p align="center">
  <strong>Keep It Simple and Trusted.</strong><br />
  Encrypt the value. Review the change. Protect the boundary. Keep the drama for production incidents you did not have.
</p>
