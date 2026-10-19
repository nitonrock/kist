"""CI helpers: lock Kist files straight from a Git checkout, one or many profiles."""

from __future__ import annotations

import os
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from kist.core import (
    DecryptionError,
    KistError,
    MissingKeyError,
    decrypt_with_password_history,
    get_profile_password,
    git_context,
    is_kist_envelope,
    profile_from_path,
)


def _git(args: list[str], input_bytes: Optional[bytes] = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", *args], capture_output=True, check=False, input=input_bytes)


def repo_relative(path: str) -> str:
    """Canonical repository-relative path, as used in the Git encryption context."""
    listed = _git(["ls-files", "--full-name", "--", path])
    name = listed.stdout.decode().strip().splitlines() if listed.returncode == 0 else []
    if name:
        return name[0]
    prefix = _git(["rev-parse", "--show-prefix"])
    base = prefix.stdout.decode().strip() if prefix.returncode == 0 else ""
    return os.path.normpath(os.path.join(base, path)).replace("\\", "/")


def read_yaml_for_lock(path: str, profile: str, password: Optional[str]) -> str:
    """Return the YAML text of a secret file, decrypting it if it is a Kist envelope.

    CI checkouts have no Kist filter configured, so files arrive encrypted; the
    envelope is opened with the profile password (and retired passwords) for the
    file's repository path and the KIST_ORG_ID / KIST_PROJECT_ID / KIST_REPOSITORY_ID
    in effect when it was committed.
    """
    data = Path(path).read_bytes()
    if not is_kist_envelope(data):
        return data.decode("utf-8")
    if not password:
        raise MissingKeyError(f"{path} is encrypted and no password is configured for profile {profile!r}.")
    relative = repo_relative(path)
    try:
        plaintext, _ = decrypt_with_password_history(data, profile, git_context(profile, relative), password)
    except DecryptionError as exc:
        raise DecryptionError(
            f"{relative}: cannot decrypt for profile {profile!r} ({exc}). Check the password and that "
            "KIST_ORG_ID, KIST_PROJECT_ID and KIST_REPOSITORY_ID match the values used when it was committed."
        ) from exc
    return plaintext.decode("utf-8")


def tracked_secret_files() -> list[str]:
    """Tracked files routed through the Kist filter, repository-relative."""
    top = _git(["rev-parse", "--show-toplevel"])
    if top.returncode != 0:
        raise KistError("Not inside a Git repository.")
    root = top.stdout.decode().strip()
    listed = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=False, cwd=root)
    paths = [p for p in listed.stdout.decode().split("\0") if p]
    if not paths:
        return []
    attrs = subprocess.run(["git", "check-attr", "-z", "--stdin", "filter"], capture_output=True, check=False,
                           cwd=root, input="\0".join(paths).encode() + b"\0")
    fields = attrs.stdout.decode().split("\0")
    selected = [fields[i] for i in range(0, len(fields) - 2, 3) if fields[i + 2] == "kist"]
    return [os.path.join(root, p) for p in sorted(selected)]


@dataclass
class LockAllResult:
    locked: list[tuple[str, str, int, int]]   # (path, profile, locked, pruned)
    skipped: list[tuple[str, str]]            # (path, profile) without a password
    failed: list[tuple[str, str, str]]        # (path, profile, error)


def lock_all(lock: Callable[[str, str, str, bool], tuple[int, int]], prune: bool = False,
             profiles: Optional[set[str]] = None) -> LockAllResult:
    """Lock every tracked Kist file whose profile has a password in this environment.

    ``lock(profile, password, yaml_text, prune)`` performs the database write.
    Profiles without a password are skipped, so one pipeline can serve many teams:
    each job only receives the KIST_PASSWORD_<PROFILE> variables it is allowed to use.
    """
    by_profile: dict[str, list[str]] = defaultdict(list)
    for path in tracked_secret_files():
        try:
            by_profile[profile_from_path(path)].append(path)
        except KistError:
            continue
    result = LockAllResult([], [], [])
    for profile in sorted(by_profile):
        if profiles is not None and profile not in profiles:
            continue
        paths = by_profile[profile]
        if len(paths) > 1:
            names = ", ".join(repo_relative(p) for p in paths)
            result.failed.append((names, profile, "several files map to this profile; lock them one by one"))
            continue
        path = paths[0]
        relative = repo_relative(path)
        password = get_profile_password(profile)
        if not password:
            result.skipped.append((relative, profile))
            continue
        try:
            text = read_yaml_for_lock(path, profile, password)
            locked, pruned = lock(profile, password, text, prune)
            result.locked.append((relative, profile, locked, pruned))
        except (KistError, UnicodeDecodeError) as exc:
            result.failed.append((relative, profile, str(exc)))
    return result


def print_lock_all(result: LockAllResult, organization: str, project: str) -> None:
    for path, profile, locked, pruned in result.locked:
        extra = f", pruned {pruned}" if pruned else ""
        print(f"locked   {path} -> {organization}/{project}/{profile} ({locked} secrets{extra})")
    for path, profile in result.skipped:
        print(f"skipped  {path} (no KIST_PASSWORD_{profile.upper()} in this job)")
    for path, profile, error in result.failed:
        print(f"FAILED   {path} [{profile}]: {error}", file=sys.stderr)
    print(f"{len(result.locked)} locked, {len(result.skipped)} skipped, {len(result.failed)} failed.")
