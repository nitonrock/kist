"""``kist share`` / ``kist show``: send a secret file to a person, encrypted.

A repository file is encrypted for its exact place (organization, project,
profile, repository ID and path), which is what stops envelopes being moved
around inside Git. A shared copy must open anywhere, so ``kist share`` encrypts
it for the profile only, with the same profile password. The recipient reads it
with ``kist show``; nothing is decrypted to disk unless they ask for ``-o``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from kist.core import (
    DecryptionError,
    KistError,
    MissingKeyError,
    _canonical_aad,
    _validate_profile_name,
    decrypt_with_password_history,
    encrypt_envelope,
    get_kist_dir,
    get_profile_password,
    git_context,
    is_kist_envelope,
    profile_from_path,
)

__all__ = ["SHARE_FORMAT", "ShareResult", "share_context", "share_file", "show_file"]

SHARE_FORMAT = "kist-share-v1"
SHARE_SUFFIX = ".kist"


def share_context(profile: str) -> dict[str, str]:
    return {"format": SHARE_FORMAT, "profile": _validate_profile_name(profile)}


def _context_hash(context: dict[str, str]) -> bytes:
    return hashlib.sha256(_canonical_aad(context)).digest()


def _git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False)
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, b"", b"")


def _toplevel(directory: Path) -> Path | None:
    result = _git(["rev-parse", "--show-toplevel"], cwd=directory)
    if result.returncode != 0:
        return None
    return Path(result.stdout.decode().strip()).resolve()


def _repo_path(file: Path) -> tuple[Path | None, str | None]:
    top = _toplevel(file.parent if file.parent.exists() else Path.cwd())
    if top is None:
        return None, None
    try:
        return top, file.resolve().relative_to(top).as_posix()
    except ValueError:
        return None, None


def _write_private(path: Path, data: bytes, force: bool) -> None:
    if path.exists() and not force:
        raise KistError(f"{path} already exists; pass --force to overwrite it.")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.chmod(path, 0o600)


def _repository_plaintext(data: bytes, profile: str, git_path: str | None) -> tuple[bytes, str]:
    """Plaintext of a repository envelope (a file left encrypted at checkout)."""
    from kist.git import resolve_envelope_path

    candidates = []
    if git_path is not None:
        candidates.append((git_path, profile))
    resolved = resolve_envelope_path(data)
    if resolved is not None:
        candidates.append(resolved)
    for path, candidate_profile in candidates:
        context = git_context(candidate_profile, path)
        if hmac.compare_digest(data[46:78], _context_hash(context)):
            plaintext, _ = decrypt_with_password_history(
                data, candidate_profile, context, get_profile_password(candidate_profile))
            return plaintext, candidate_profile
    raise KistError("this encrypted file does not belong to a path in this repository.")


@dataclass(frozen=True)
class ShareResult:
    output: Path
    profile: str
    uncommitted: bool


def share_file(file: str, output: str | None = None, *, profile_name: str | None = None,
               force: bool = False) -> ShareResult:
    """Encrypt ``file`` as you see it now into a portable envelope for sending."""
    source = Path(file)
    if not source.is_file():
        raise KistError(f"{file}: no such file.")
    profile = _validate_profile_name(profile_name or profile_from_path(source.name))
    password = get_profile_password(profile)
    if not password:
        raise MissingKeyError(f"No password for profile '{profile}'; cannot share {file}.")
    top, git_path = _repo_path(source)
    data = source.read_bytes()
    if is_kist_envelope(data):
        plaintext, _ = _repository_plaintext(data, profile, git_path)
    else:
        plaintext = data
    target = Path(output).expanduser() if output else Path.home() / f"{source.name}{SHARE_SUFFIX}"
    target_top = _toplevel(target.parent) if target.parent.exists() else None
    if top is not None and target_top is not None and target_top == top:
        raise KistError(f"{target} is inside this repository, where it could be committed by mistake; "
                        "choose a destination outside it (default: your home directory).")
    envelope = encrypt_envelope(plaintext, password, share_context(profile))
    _write_private(target, envelope, force)
    uncommitted = False
    if top is not None and git_path is not None:
        status = _git(["status", "--porcelain", "--", git_path], cwd=top)
        uncommitted = bool(status.stdout.strip())
    return ShareResult(output=target, profile=profile, uncommitted=uncommitted)


def _candidate_profiles(file: Path, explicit: str | None) -> list[str]:
    names: list[str] = []
    if explicit:
        names.append(explicit)
    stem = file.name[:-len(SHARE_SUFFIX)] if file.name.endswith(SHARE_SUFFIX) else file.name
    try:
        names.append(profile_from_path(stem))
    except KistError:
        pass
    kist_dir = Path(get_kist_dir())
    if kist_dir.is_dir():
        names.extend(p.name.removeprefix("pwd_") for p in sorted(kist_dir.glob("pwd_*")))
    names.extend(name[len("KIST_PASSWORD_"):].lower() for name in sorted(os.environ)
                 if name.startswith("KIST_PASSWORD_"))
    valid: list[str] = []
    for name in names:
        try:
            name = _validate_profile_name(name)
        except KistError:
            continue
        if name not in valid:
            valid.append(name)
    return valid


def show_file(file: str, *, profile_name: str | None = None) -> tuple[bytes, str]:
    """Decrypt a shared (or repository) envelope in memory: (plaintext, profile)."""
    source = Path(file)
    if not source.is_file():
        raise KistError(f"{file}: no such file.")
    data = source.read_bytes()
    if not is_kist_envelope(data):
        raise KistError(f"{file} is not Kist-encrypted (it is already readable).")
    for profile in _candidate_profiles(source, profile_name):
        context = share_context(profile)
        if not hmac.compare_digest(data[46:78], _context_hash(context)):
            continue
        password = get_profile_password(profile)
        try:
            plaintext, _ = decrypt_with_password_history(data, profile, context, password)
        except MissingKeyError:
            raise MissingKeyError(f"{file} is for profile '{profile}', but no password for it is set here "
                                  f"(~/.kist/pwd_{profile} or KIST_PASSWORD_{profile.upper()}).") from None
        except DecryptionError:
            raise DecryptionError(f"{file} is for profile '{profile}', but the password found here does not "
                                  "open it.") from None
        return plaintext, profile
    _, git_path = _repo_path(source)
    try:
        profile = profile_name or profile_from_path(git_path or source.name)
        return _repository_plaintext(data, profile, git_path)
    except DecryptionError:
        raise DecryptionError(f"{file} belongs to this repository, but no password here opens it.") from None
    except KistError:
        pass
    raise KistError(f"cannot tell which profile {file} is for; pass --profile NAME.")


def write_shown(plaintext: bytes, output: str, *, force: bool = False) -> Path:
    target = Path(output).expanduser()
    _write_private(target, plaintext, force)
    return target
