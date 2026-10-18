"""``kist profile rotate``: replace a profile password everywhere Kist controls.

Order of operations, chosen so that a failure never loses the only copy of a key:

1. Check: the current password opens the database key bundle, every Git
   secret file of the profile is a readable plaintext working copy, and Git
   can re-encrypt them.
2. Write the new password to ``~/.kist/pwd_<profile>.new`` (0600) *before*
   changing anything else.
3. Database: replace the content/index keys and re-encrypt every secret in a
   single transaction (or only rewrap the key bundle with ``--rewrap-only``).
4. Local password file: keep the old one as ``pwd_<profile>.old-<timestamp>`` and
   move the new one into place.
5. Git: ``git add --renormalize`` re-encrypts the profile's secret files with
   the new password and stages them for review; nothing is committed.

Anything outside Kist's reach (CI secrets, environment variables, other
developers, exported device files, TPM-sealed credentials) is reported as a
checklist at the end.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from kist.core import (
    DecryptionError,
    Kist,
    decrypt_with_password_history,
    git_context,
    KistError,
    KistScope,
    MissingKeyError,
    _validate_profile_name,
    generate_password,
    get_profile_password,
    is_kist_envelope,
    profile_from_path,
    profile_password_path,
    profile_password_source,
    read_secure_local_password,
    write_secure_local_password,
)

__all__ = ["RotationPlan", "RotationResult", "plan_rotation", "rotate_profile"]


@dataclass
class RotationPlan:
    profile: str
    password_source: str
    database: bool
    database_secrets: Optional[int]
    git_root: Optional[str]
    git_files: list[str] = field(default_factory=list)
    rewrap_only: bool = False


@dataclass
class RotationResult:
    plan: RotationPlan
    database_rotated: bool = False
    database_secrets: int = 0
    git_restaged: list[str] = field(default_factory=list)
    local_key_path: Optional[Path] = None
    old_key_backup: Optional[Path] = None
    checklist: list[str] = field(default_factory=list)


def _git(args: list[str], *, cwd: Optional[str] = None, env: Optional[dict[str, str]] = None,
         input_bytes: Optional[bytes] = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", *args], cwd=cwd, env=env, input=input_bytes,
                              capture_output=True, check=False)
    except FileNotFoundError as exc:
        raise KistError("git is not installed or not on PATH.") from exc


def _git_root() -> Optional[str]:
    try:
        top = _git(["rev-parse", "--show-toplevel"])
    except KistError:
        return None
    return top.stdout.decode().strip() if top.returncode == 0 else None


def find_profile_git_files(profile: str, root: str) -> list[str]:
    """Tracked files routed through the Kist filter that belong to ``profile``."""
    listed = _git(["ls-files", "-z"], cwd=root)
    if listed.returncode != 0:
        raise KistError("Could not list tracked files.")
    paths = [p for p in listed.stdout.decode().split("\0") if p]
    if not paths:
        return []
    attrs = _git(["check-attr", "-z", "--stdin", "filter"], cwd=root, input_bytes="\0".join(paths).encode() + b"\0")
    fields = attrs.stdout.decode().split("\0")
    selected = []
    for i in range(0, len(fields) - 2, 3):
        path, _, value = fields[i], fields[i + 1], fields[i + 2]
        if value == "kist":
            try:
                if profile_from_path(path) == profile:
                    selected.append(path)
            except KistError:
                continue
    return sorted(selected)


def _committed_plaintext(root: str, spec: str, profile: str, path: str, password: str) -> Optional[bytes]:
    blob = _git(["cat-file", "blob", spec], cwd=root)
    if blob.returncode != 0:
        return None
    if not is_kist_envelope(blob.stdout):
        raise KistError(f"{path} is stored unencrypted in {spec.split(':')[0] or 'the index'}; fix that before rotating.")
    try:
        return decrypt_with_password_history(blob.stdout, profile, git_context(profile, path), password)[0]
    except DecryptionError as exc:
        raise DecryptionError(f"The current password does not open {path} in Git.") from exc


def _check_git_files(root: str, files: list[str], profile: str, password: Optional[str]) -> None:
    """Compare decrypted content, not ciphertext: Kist envelopes are randomised,
    so Git's own modified/unmodified view can report false changes.

    With ``password=None`` (recovery), only check that working copies are plaintext.
    """
    pending = []
    for path in files:
        working = (Path(root) / path).read_bytes()
        if is_kist_envelope(working):
            raise KistError(f"{path} is still encrypted in the working tree (checkout failed?). "
                            "Fix it with 'kist diagnose' before rotating.")
        if password is None:
            continue
        head = _committed_plaintext(root, f"HEAD:{path}", profile, path, password)
        index = _committed_plaintext(root, f":{path}", profile, path, password)
        if head is None or index != head or working != head:
            pending.append(path)
    if pending:
        raise KistError("Uncommitted changes in " + ", ".join(pending) + ". Commit or discard them first, "
                        "so the rotation commit contains only re-encryption.")


def plan_rotation(profile: str, *, scope: Optional[KistScope] = None, db_url: Optional[str] = None,
                  use_database: Optional[bool] = None, use_git: bool = True,
                  rewrap_only: bool = False) -> tuple[RotationPlan, str]:
    """Inspect what would be rotated and validate the current password. Changes nothing."""
    profile = _validate_profile_name(profile)
    source = profile_password_source(profile)
    current = get_profile_password(profile)
    if not current or source is None:
        raise MissingKeyError(f"No current password found for profile {profile!r}.")

    configured_db = db_url if db_url is not None else os.getenv("KIST_DATABASE_URL")
    database = bool(configured_db) if use_database is None else use_database
    if database and not configured_db:
        raise KistError("KIST_DATABASE_URL is not configured; use --skip-db to rotate Git files only.")
    count: Optional[int] = None
    if database:
        store = Kist(profile, current, configured_db, scope)
        try:
            count = store.secret_count()
        except DecryptionError as exc:
            raise DecryptionError("The current password does not open this profile in the database.") from exc
        if count is None:
            database = False  # profile has never been locked into this database

    root = _git_root() if use_git else None
    files = find_profile_git_files(profile, root) if root else []
    if root and files:
        _check_git_files(root, files, profile, current)
    return RotationPlan(profile, source, database, count, root, files, rewrap_only), current


def _stage_new_password(profile: str, new_password: str) -> Path:
    staged = profile_password_path(profile).with_name(f"pwd_{profile}.new")
    write_secure_local_password(staged, new_password, overwrite=True)
    return staged


def _install_new_password(profile: str, staged: Path, current: str) -> tuple[Path, Path]:
    """Move the new password into place and always keep the old one as a retired password.

    The old password is saved even when it came from an environment variable, so
    older Git commits stay readable through the Password history.
    """
    target = profile_password_path(profile)
    backup = target.with_name(f"pwd_{profile}.old-{time.strftime('%Y%m%d-%H%M%S')}")
    suffix = 1
    while backup.exists():
        backup = backup.with_name(f"{backup.name.split('~')[0]}~{suffix}")
        suffix += 1
    write_secure_local_password(backup, current, overwrite=False)
    if target.exists():
        target.unlink()
    os.replace(staged, target)
    return target, backup


def _renormalize(root: str, files: list[str], profile: str, new_password: str) -> None:
    env = dict(os.environ)
    env[f"KIST_PASSWORD_{profile.upper()}"] = new_password
    done = _git(["add", "--renormalize", "--", *files], cwd=root, env=env)
    if done.returncode != 0:
        raise KistError("git add --renormalize failed: " + done.stderr.decode(errors="replace").strip())
    for path in files:
        blob = _git(["cat-file", "blob", f":{path}"], cwd=root)
        if blob.returncode != 0 or not is_kist_envelope(blob.stdout):
            raise KistError(f"{path} was not re-encrypted; refusing to continue.")


def build_checklist(result: RotationResult) -> list[str]:
    plan, items = result.plan, []
    if plan.password_source.startswith("KIST_PASSWORD"):
        items.append(f"Your shell sets {plan.password_source}, which overrides the password file: update or unset it now.")
    items.append("Update the profile password in CI/CD secrets and any deployment environment.")
    items.append("Share the new password with other developers through your approved channel; "
                 "after pulling, they replace ~/.kist/pwd_" + plan.profile + " and run 'git checkout -- .'.")
    if plan.database:
        items.append("Restart or reconfigure running services: they cannot open the rotated profile with the old password.")
    if result.git_restaged:
        items.append("Review and commit the re-encrypted files: git commit -m \"rotate " + plan.profile + " profile password\"")
        items.append("Re-export embedded/offline bundles (kist export) and re-seal device credentials (systemd-creds, TPM).")
    items.append("Old Git commits and database backups still open with the OLD password. "
                 "If you rotate because of a leak, also rotate the secret values themselves.")
    if result.old_key_backup:
        items.append(f"Old password kept as a retired password ({result.old_key_backup.name}): older commits and "
                     f"'kist export --rev' keep working. Remove it with 'kist profile retired-passwords "
                     f"{plan.profile} --delete' once nothing needs old revisions.")
    return items


def rotate_profile(profile: str, *, new_password: Optional[str] = None, scope: Optional[KistScope] = None,
                   db_url: Optional[str] = None, use_database: Optional[bool] = None, use_git: bool = True,
                   rewrap_only: bool = False, write_local_key: bool = True,
                   log: Callable[[str], None] = lambda _m: None) -> RotationResult:
    plan, current = plan_rotation(profile, scope=scope, db_url=db_url, use_database=use_database,
                                  use_git=use_git, rewrap_only=rewrap_only)
    if not plan.database and not plan.git_files:
        raise KistError(f"Nothing to rotate for profile {plan.profile!r}: no database profile and no Git secret files.")
    new_password = new_password or generate_password()
    if new_password == current:
        raise KistError("The new password must differ from the current one.")
    result = RotationResult(plan)

    staged = _stage_new_password(plan.profile, new_password) if write_local_key else None
    try:
        if plan.database:
            store = Kist(plan.profile, current, db_url if db_url is not None else os.getenv("KIST_DATABASE_URL"), scope)
            if rewrap_only:
                store.rewrap_profile_password(new_password)
                log("Database: key bundle rewrapped with the new password (data keys unchanged).")
            else:
                result.database_secrets = store.rotate_profile_keys(new_password)
                log(f"Database: new data keys generated, {result.database_secrets} secrets re-encrypted.")
            result.database_rotated = True
    except BaseException:
        if staged:
            staged.unlink(missing_ok=True)
        raise

    if staged:
        result.local_key_path, result.old_key_backup = _install_new_password(plan.profile, staged, current)
        log(f"Local password: {result.local_key_path} updated (old password kept as {result.old_key_backup}).")

    if plan.git_files and plan.git_root:
        try:
            _renormalize(plan.git_root, plan.git_files, plan.profile, new_password)
        except KistError as exc:
            hint = (f"Database and password file already use the new password. Finish with: "
                    f"kist profile rotate {plan.profile} --git-only")
            raise KistError(f"{exc}\n{hint}") from exc
        result.git_restaged = list(plan.git_files)
        log(f"Git: re-encrypted and staged {len(plan.git_files)} file(s).")

    result.checklist = build_checklist(result)
    return result


def restage_git_with_current_key(profile: str) -> list[str]:
    """Recovery path: re-encrypt Git files with whatever password is now current.

    Used when a rotation changed the database and password file but Git failed: the
    index then still holds envelopes for the old password, so committed content
    cannot be compared with the new one. Review the staged diff before committing.
    """
    profile = _validate_profile_name(profile)
    password = get_profile_password(profile)
    if not password:
        raise MissingKeyError(f"No current password found for profile {profile!r}.")
    root = _git_root()
    if not root:
        raise KistError("Not inside a Git work tree.")
    files = find_profile_git_files(profile, root)
    _check_git_files(root, files, profile, None)
    if files:
        _renormalize(root, files, profile, password)
    return files


def read_password_file(path: str) -> str:
    return read_secure_local_password(Path(path))
