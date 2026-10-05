# CI/CD Integration Resources for Kist

This directory contains production-ready CI/CD pipeline configuration templates for integrating **Kist** into major Git repository providers (**GitHub Actions**, **GitLab CI/CD**, and **Bitbucket Pipelines**).

---

## 🌟 Why Use Kist with CI/CD?

Kist turns Git into a secure, reviewable control plane for application secrets (GitOps for Secrets) while keeping raw credentials strictly outside of unencrypted Git history and log streams.

Integrating Kist into your CI/CD pipelines delivers two core capabilities:

1. **🛡️ Server-Side PR / Merge Request Leak Guard**:
   - Automatically scans every Pull Request / Merge Request.
   - Verifies that all `secrets*.yaml` files are fully encrypted `kist-v1` binary envelopes before merging.
   - Enforces organizational security policy even if a developer didn't install local Git hooks.

2. **🚀 Automated Secret Synchronization & Deployment**:
   - On merge to `main`, CI securely unlocks the reviewed Git-encrypted secret files and locks them into your centralized PostgreSQL database (`kist lock secrets_production.yaml`).
   - Applications running `DynamicSecretStore` or `AsyncDynamicSecretStore` immediately receive PostgreSQL `LISTEN/NOTIFY` cache invalidation signals, hot-reloading new secrets without downtime.

---

## 📁 Directory Structure

```text
ressources/
├── github/
│   ├── deploy.yml         # Deploy & sync secrets to PostgreSQL on main branch push
│   └── leak-guard.yml     # PR scanning to prevent plaintext secrets from merging
├── gitlab/
│   └── .gitlab-ci.yml     # Multi-stage GitLab CI pipeline (leak guard & DB sync)
└── bitbucket/
    └── bitbucket-pipelines.yml  # Bitbucket Pipelines configuration (PR guard & deploy)
```

---

## 🚀 Setup by Provider

### 1. GitHub Actions (`ressources/github/`)

- Copy the workflow templates into your repository:
  ```bash
  mkdir -p .github/workflows
  cp ressources/github/leak-guard.yml .github/workflows/
  cp ressources/github/deploy.yml .github/workflows/
  ```
- **Configure GitHub Repository Secrets** (`Settings -> Secrets and variables -> Actions`):
  - `KIST_DATABASE_URL`: PostgreSQL connection string (e.g. `postgresql://user:pass@db.example.com:5432/kist?sslmode=require`).
  - `KIST_PASSWORD_PRODUCTION`: Profile password for `production` (or `KIST_PASSWORD_STAGING` for staging).

---

### 2. GitLab CI/CD (`ressources/gitlab/`)

- Copy `.gitlab-ci.yml` to the root of your GitLab repository:
  ```bash
  cp ressources/gitlab/.gitlab-ci.yml .gitlab-ci.yml
  ```
- **Configure GitLab CI/CD Variables** (`Settings -> CI/CD -> Variables`):
  - Set `KIST_DATABASE_URL` and `KIST_PASSWORD_PRODUCTION`.
  - Mark them as **Masked** and **Protected** so they are restricted to protected branches (`main`) and never appear in job logs.

---

### 3. Bitbucket Pipelines (`ressources/bitbucket/`)

- Copy `bitbucket-pipelines.yml` to the root of your Bitbucket repository:
  ```bash
  cp ressources/bitbucket/bitbucket-pipelines.yml bitbucket-pipelines.yml
  ```
- **Configure Bitbucket Repository Variables** (`Repository settings -> Repository variables`):
  - Add `KIST_DATABASE_URL` and `KIST_PASSWORD_PRODUCTION`.
  - Check **Secured** to mask variable values in build logs.

---

## 🔒 Security Best Practices for CI/CD

- **Strict TLS**: Always append `?sslmode=require` (or `sslmode=verify-full`) to `KIST_DATABASE_URL` in CI secrets.
- **Least-Privilege Database Users**: Use a database role for CI that only possesses `SELECT`, `INSERT`, and `UPDATE` on the `kist` tables, without broad DDL/superuser privileges.
- **Masked Variables**: Ensure profile passwords and connection strings are masked in CI output.
- **Fail Closed**: In CI, Kist fails closed with exit code `1` if a required profile key or database URL is missing or invalid.
