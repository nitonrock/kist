# CI/CD Integration Resources for Kist

This directory contains standalone CI/CD pipeline configuration templates for integrating **Kist** into the major Git repository providers:

---

## 📁 Directory Structure

```
ressources/
├── github/
│   ├── deploy.yml         # Deploy & sync secrets to PostgreSQL on main branch
│   └── leak-guard.yml     # PR scanning to prevent plaintext secrets from merging
├── gitlab/
│   └── .gitlab-ci.yml     # Multi-stage GitLab CI pipeline (leak guard & DB sync)
└── bitbucket/
    └── bitbucket-pipelines.yml  # Bitbucket Pipelines configuration
```

---

## 🚀 Quick Start by Provider

### 1. GitHub Actions (`ressources/github/`)
- Copy `deploy.yml` and `leak-guard.yml` into `.github/workflows/` in your repository.
- Configure repository secrets: `KIST_DATABASE_URL` (enforcing `?sslmode=require`), `KIST_PASSWORD_PRODUCTION`, `KIST_PASSWORD_STAGING`.

### 2. GitLab CI/CD (`ressources/gitlab/`)
- Copy `.gitlab-ci.yml` to the root of your GitLab repository.
- Configure masked and protected CI/CD variables: `KIST_DATABASE_URL` (enforcing `?sslmode=require`), `KIST_PASSWORD_PRODUCTION`, `KIST_PASSWORD_STAGING`.

### 3. Bitbucket Pipelines (`ressources/bitbucket/`)
- Copy `bitbucket-pipelines.yml` to the root of your Bitbucket repository.
- Configure secured repository variables: `KIST_DATABASE_URL` (enforcing `?sslmode=require`), `KIST_PASSWORD_PRODUCTION`, `KIST_PASSWORD_STAGING`.
