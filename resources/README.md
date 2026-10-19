# CI/CD templates for Kist

Copy-paste pipelines for GitHub Actions, GitLab CI/CD and Bitbucket Pipelines. Each one does two things:

1. **Leak guard on every pull/merge request**: `kist pre-commit-guard --all-files` blocks plaintext secret files, likely credentials and envelopes moved without re-encryption, even when a developer has no local hook. It needs no secrets.
2. **Lock on merge**: `kist lock --all` decrypts every tracked secret file in memory and locks it into PostgreSQL, for each profile whose password the job has. Other profiles are skipped, so one repository can serve several teams. Applications using `DynamicSecretStore` reload through PostgreSQL `NOTIFY`.

```text
resources/
├── github/
│   ├── leak-guard.yml           # pull requests
│   └── deploy.yml               # lock + deploy on main
├── gitlab/
│   ├── .gitlab-ci.yml           # leak guard, lock, deploy
│   └── set-variables.sh         # create all secret variables in one go (glab)
└── bitbucket/
    └── bitbucket-pipelines.yml  # pull requests, lock + deploy on main
```

## What goes where

Only two kinds of values are secret. Everything else belongs in the pipeline file, under version control.

| Variable | Secret? | Where |
|--|--|--|
| `KIST_DATABASE_URL` | yes | CI secret variable |
| `KIST_PASSWORD_<PROFILE>` | yes | CI secret variable, one per profile the pipeline may lock |
| `KIST_ORG_ID`, `KIST_PROJECT_ID`, `KIST_REPOSITORY_ID` | no | pipeline file; **must match the values developers commit with**, or files will not decrypt |
| `KIST_ENV`, `KIST_TLS_MODE` | no | pipeline file |

`KIST_TLS_MODE=require` (or `verify-full` with a `PGSSLROOTCERT` file) also means the database URL needs no `?sslmode=…` query.

## GitLab CI/CD

```bash
cp resources/gitlab/.gitlab-ci.yml .gitlab-ci.yml
```

### Variable settings

For `KIST_DATABASE_URL` and every `KIST_PASSWORD_<PROFILE>` (Settings > CI/CD > Variables):

| Setting | Choose | Why |
|--|--|--|
| Visibility | **Masked**, or **Masked and hidden** | Masked values are redacted from job logs. Hidden also stops anyone reading them back in the UI; it can only be chosen when creating the variable. |
| Protect variable | **On** | Only pipelines on protected branches and tags (e.g. `main`) receive it. The leak guard needs no secrets, so merge requests still work. |
| Expand variable reference | **Off** | Expansion treats `$` in the value as a reference to another variable, which would corrupt a password containing `$`. With expansion off, a masked value may contain any character, including `?`, `%` and `@`; with it on, GitLab restricts masked values to letters, digits and `_ : @ - + . ~ = /`. GitLab recommends turning it off for masked variables. |

Masked values must be a single line of at least 8 characters without spaces; Kist-generated passwords qualify. See [GitLab CI/CD variables](https://docs.gitlab.com/ci/variables/).

Project variables reach every job automatically: do not re-declare them in `.gitlab-ci.yml` (`KIST_DATABASE_URL: $KIST_DATABASE_URL` is what makes expansion look necessary).

### Setting them all in one go

With the [GitLab CLI](https://docs.gitlab.com/cli/) (`glab auth login` once), from your clone of the project:

```bash
resources/gitlab/set-variables.sh production payments staging
```

It prompts for `KIST_DATABASE_URL` without echoing it, takes each profile password from `~/.kist/pwd_<profile>` (or prompts), and creates or updates every variable as Masked, Protected and not expanded (`HIDDEN=1` for Masked and hidden). Values are passed on standard input, never on the command line.

For several projects, set the variables once on the **group** (`glab variable set … -g <group>`); every project in the group inherits them.

### Multi-team pipelines

Each job only locks the profiles it has passwords for. To keep teams apart, give a password an **Environment scope** (for example `KIST_PASSWORD_PAYMENTS` scoped to `payments`) and add a job with `environment: payments` running `kist lock --all --only payments --require-all`; the template contains a commented example.

## GitHub Actions

```bash
mkdir -p .github/workflows
cp resources/github/leak-guard.yml resources/github/deploy.yml .github/workflows/
gh secret set KIST_DATABASE_URL
gh secret set KIST_PASSWORD_PRODUCTION < ~/.kist/pwd_production
```

GitHub only passes secrets that are listed in the workflow, so add one `KIST_PASSWORD_<PROFILE>` line per profile under `env:` in `deploy.yml`. Use an environment (`environment: production`) with required reviewers to protect them.

## Bitbucket Pipelines

```bash
cp resources/bitbucket/bitbucket-pipelines.yml bitbucket-pipelines.yml
```

Add `KIST_DATABASE_URL` and each `KIST_PASSWORD_<PROFILE>` as **Secured** repository or deployment variables; they reach every step automatically.

## Good practice

- **Least-privilege database role** for CI: `SELECT`, `INSERT`, `UPDATE`, `DELETE` on the Kist tables, no DDL. Run `kist init-db` once yourself, not in CI.
- **Pin the Kist version** in the pipeline (the templates do) and upgrade deliberately.
- **Fail closed**: a wrong password or scope fails the job; `--require-all` also fails when a password is missing.
