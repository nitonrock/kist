# Kist threat model

What Kist protects, from whom, and where it stops. Each scenario says what happens, what protects you, and what you have to do yourself. The byte-level details behind these statements are in [FORMAT.md](FORMAT.md); to report a vulnerability, see [SECURITY.md](SECURITY.md).

## In one paragraph

Kist keeps secrets encrypted wherever they are stored or sent: Git history, the database, backups, shared files. There they are protected with AES-256-GCM under keys only profile password holders can unlock, and bound to their path, profile and scope, so they can be neither read nor quietly moved. Once someone with the password opens them, on a laptop or in an application, they are ordinary plaintext on that machine, and protecting that machine is up to you.

## What is protected

| Asset | Where it lives in clear | Where it lives encrypted |
|---|---|---|
| Secret values (database passwords, API tokens…) | Working tree of developers with the password; application memory and caches; output of `kist show` and `kist unlock` | Git history (whole-file envelopes); `kist_secrets` rows; `kist share` files; backups of both |
| Secret names (`database.password`) | Working tree; application code | Git (inside the file); database (inside the record, found through an HMAC token) |
| Profile passwords | `~/.kist/pwd_<profile>`; `KIST_PASSWORD_*` variables on laptops, CI and servers; team dotfiles | Nowhere: they are the root of trust |
| Data keys and key bundles | Process memory while in use | Inside every envelope; `kist_key_bundles` |

Visible to anyone with the repository or the database, by design: file paths and profile names, organization and project names, approximate sizes, when things change, and the number of rows per profile ([FORMAT.md, visible metadata](FORMAT.md#visible-metadata)).

## Assumptions

- Profile passwords are strong. `kist profile create` generates 256-bit passwords; Kist also accepts any non-empty password from a variable, and a short human-chosen one is the weakest link (Argon2id with 64 MiB slows guessing, it does not make a weak password strong).
- The machines that hold passwords (laptops, CI runners, application servers) are not compromised.
- The `cryptography`, `psycopg` and `PyYAML` libraries, Python and Git behave as documented.

## Who could attack, and what they get

| Who | What they have | What they get | What stops them |
|---|---|---|---|
| Anyone who obtains the repository (leak, public fork, Git host breach) | Git history | Ciphertext, paths, profile names, change history | Encryption; no password in the repository |
| Git host or CI administrator | Repository; CI variables | Repository: ciphertext only. CI variables: the passwords stored there | Only what you store in CI. The leak guard needs no password |
| Database administrator or stolen dump | All Kist tables | Ciphertext, HMAC tokens, scope names, row counts. **Can delete or restore old rows** | Encryption and per-row binding. Nothing against putting old rows back or deleting rows |
| Network attacker between application and PostgreSQL | Traffic | With the default TLS mode `require`: can impersonate the server, see ciphertext, serve old rows. With `verify-full`: nothing | `KIST_TLS_MODE=verify-full` and a CA certificate. TLS can't be disabled when `KIST_ENV` is production |
| Contributor without the password (opens pull requests) | Write access to branches | Can replace a secret file with an older genuine version of the same file, or delete it. **Can't** forge content, or move another file's envelope to this path | Encryption and path binding; review; the CI guard |
| Team member with the password | The password | Everything in that profile, including all history | Nothing technical: this is the trust you grant |
| Departing team member | The password, and copies of the secrets | Everything they could read, forever, including history encrypted with retired passwords | Rotation protects future content only; see below |
| Malware, a coding assistant or any process running as your user | Your files and environment | `~/.kist/pwd_*`, the plaintext working tree, `KIST_PASSWORD_*` of your processes | Nothing in Kist; operating-system isolation only |
| A hostile repository you clone | Its `.gitattributes`, its envelopes | Nothing: envelopes it didn't encrypt with your password stay locked, and Kist caps Argon2 cost so a crafted file can't exhaust memory | Git never runs repository code without local configuration; reader limits |
| Supply chain (PyPI, dependencies) | Code that runs in your filter or application | Everything that code's process can read | Releases with attestations ([SECURITY.md](SECURITY.md#verifying-releases)); pin and review dependencies |

## Scenarios

### A laptop is stolen or lost

**What happens:** the thief has the working tree, where secret files are in **plaintext** (that is how Git filters work), and `~/.kist`, which holds the passwords in clear.
**What protects you:** only full-disk encryption and the screen lock. Kist adds nothing here.
**What to do:** require disk encryption. After a loss, treat every profile on that laptop as leaked: rotate its password (`kist profile rotate`) **and** change the real credentials inside the files.

### Someone switches off the filter, or commits from a clone without `kist init`

**What happens:** `git -c filter.kist.clean=cat commit` commits plaintext; so does a clone where `kist init` never ran, because Git ignores a filter it doesn't know. `git commit --no-verify` is not enough: the filter still encrypts.
**What protects you:** only the required CI guard (`kist pre-commit-guard --all-files`), which rejects any secret file that is not a valid envelope for its path.
**What to do:** make the guard a required check on protected branches. If plaintext was pushed anyway, rewrite history **and** change the leaked credentials: rewriting alone is not enough once a push has happened.

### A coding assistant or other tool reads your files

**What happens:** anything running as your user can read `~/.kist` and the plaintext working tree. Kist can't tell an assistant from you.
**What protects you:** nothing in Kist. File permissions only stop *other* users.
**What to do:** run assistants in a container or a separate user account without `~/.kist` when the profile matters; give them a working tree where secret files stay locked (no password for that profile).

### A teammate swaps a secret file or puts back an old one

**What happens:** copying `secrets/a.yml`'s envelope over `secrets/b.yml` fails: each envelope is bound to its path, profile and scope. Putting back an **older envelope of the same file** succeeds: it is genuine content, just old.
**What protects you:** the binary change appears in the pull request, and readable diffs (`git diff` with the password) show what changed.
**What to do:** review secret file changes like code; protect branches.

### Someone leaves the team

**What happens:** they keep the password and everything it opened, including history. `kist profile rotate` re-encrypts the current files with a new password, but old commits stay readable with the old password, which they have.
**What protects you:** nothing can take back what was already readable.
**What to do:** rotate the profile password **and** change every real credential in that profile (database passwords, API tokens). The second step is the one that actually removes access.

### The team dotfiles repository leaks

**What happens:** if the dotfiles hold the profile passwords, whoever reads that repository reads every profile of that team, past and present.
**What protects you:** only the access control on the dotfiles repository.
**What to do:** treat the dotfiles repository as a secret store: private, few members, one per team rather than one for all, reviewed access. Its access list *is* your secret access list.

### A CI job or pipeline is abused

**What happens:** a job that runs `kist lock` has `KIST_PASSWORD_<PROFILE>` in its environment. Anyone who can change that job's script on a branch where the variable is available can print or send it.
**What protects you:** your CI platform's variable protection.
**What to do:** expose password variables only to protected branches and to the lock job; give each pipeline only the profiles it needs (`kist lock --only`). The guard job needs no password at all.

### The database is copied, altered or intercepted

**What happens:** a dump gives ciphertext, HMAC tokens and scope names, not values or secret names. Someone with write access can delete rows or put back old ones; Kist doesn't detect this. Without `verify-full`, a network attacker can do the same in transit.
**What protects you:** encryption, per-row binding (a row can't be moved to another row, profile or database), constant-time token checks.
**What to do:** back up and restrict the database like any other; set `KIST_TLS_MODE=verify-full` with `sslrootcert`; keep the database role minimal.

### An application server is compromised

**What happens:** the server has the profile password in its environment and plaintext values in memory (and in caches, if enabled). The attacker has that profile.
**What protects you:** nothing in Kist; this is outside its boundary.
**What to do:** one profile per application or environment, so a breach is limited to one; prefer short cache lifetimes; change the credentials after an incident.

### You send a file with `kist share`

**What happens:** the file is encrypted with the profile password, without path or scope, so anyone with that password can open it, wherever the file ends up. It doesn't name a recipient and doesn't prove who sent it, beyond "someone with the password".
**What protects you:** encryption; the file is written outside the repository, mode 600.
**What to do:** send it to people who already have the password; delete it when done.

## Known limits

These are properties of format version 1, not bugs:

- **Old versions can be put back.** Someone who can write to the repository or the database can replace a secret with an older genuine version; Kist opens it without warning. It cannot forge new content or move content to another file or row. Kist also can't prove that a set of files or rows is complete (a deletion goes unnoticed).
- **No sender authentication beyond the password:** every password holder can write valid content for that profile.
- **No revocation of the past:** rotation protects future content; history stays readable with retired passwords.
- **Plaintext in use:** in the working tree, in application memory and caches. Python can't reliably erase memory, and Kist doesn't try.
- **Visible metadata:** paths, profile and scope names, sizes and timing.
- **Default database TLS doesn't verify the server** (`require`); `verify-full` must be configured.
- **Local protections can be bypassed** by anyone who controls the machine; only required CI checks enforce anything.

## Checklist

- [ ] Generated passwords (`kist profile create`), never human-chosen ones.
- [ ] Full-disk encryption on every laptop with a password.
- [ ] `kist pre-commit-guard --all-files` as a required check on protected branches.
- [ ] Password variables in CI only for protected branches and the lock job.
- [ ] `KIST_TLS_MODE=verify-full` with a CA certificate in production.
- [ ] Dotfiles repository with passwords: private, small, one per team.
- [ ] After a departure or a loss: rotate the profile **and** change the real credentials.
- [ ] Verify releases before installing ([SECURITY.md](SECURITY.md#verifying-releases)).
