"""Git integration for Kist.

Local hooks are developer ergonomics, not a complete enforcement boundary.
Deploy Kist Guard or an equivalent required CI/server-side secret scanner for
organization-wide enforcement.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import BinaryIO, Optional, TextIO

from kist.core import (
    DecryptionError,
    InvalidEnvelopeError,
    KistError,
    MissingKeyError,
    decrypt_envelope,
    decrypt_with_password_history,
    encrypt_envelope,
    get_profile_password,
    git_context,
    is_kist_envelope,
    profile_from_path,
    retired_profile_passwords,
)
from kist.core import _canonical_aad

HIGH_CONFIDENCE_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
]

SENSITIVE_KEY_ASSIGNMENT = re.compile(
    r"""(?i)\b\w*(?:api[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|db[_-]?password|aws_secret_access_key)\b\s*[:=]\s*([\x27"]?)([^\s\x27"]{8,})\1"""
)

SENSITIVE_KEY_PATTERNS = [
    SENSITIVE_KEY_ASSIGNMENT,
    *HIGH_CONFIDENCE_PATTERNS,
]

PLACEHOLDER_SUBSTRINGS = (
    "example", "placeholder", "dummy", "sample", "test", "mock",
    "changeme", "change_me", "replace_me", "your_", "fake",
    "sk_test", "sk_example", "xxx", "todo",
)

IGNORED_KEYWORDS = {
    "none", "null", "nil", "undefined", "true", "false",
    "str", "int", "string", "bytes", "optional", "any",
}

SUSPICIOUS_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".toml", ".env", ".ini", ".conf", ".cfg",
    ".py", ".js", ".ts", ".sh", ".tf", ".tfvars", ".properties", ".xml",
}

# `secrets*.yaml` matches at any depth; `**/secrets/**/*.yaml` covers every file below
# any `secrets/` folder, matching what the leak guard protects.
KIST_ATTRIBUTE_PATTERNS = ("secrets*.yaml", "secrets*.yml", "**/secrets/**/*.yaml", "**/secrets/**/*.yml")
KIST_ATTRIBUTE_RULES = tuple(f"{pattern} filter=kist diff=kist" for pattern in KIST_ATTRIBUTE_PATTERNS)
LEGACY_ATTRIBUTE_RULES = {
    "secrets*.yaml filter=kist": KIST_ATTRIBUTE_RULES[0],
    "secrets*.yml filter=kist": KIST_ATTRIBUTE_RULES[1],
    "secrets/*.yaml filter=kist": KIST_ATTRIBUTE_RULES[2],
    "secrets/*.yml filter=kist": KIST_ATTRIBUTE_RULES[3],
    "secrets/*.yaml filter=kist diff=kist": KIST_ATTRIBUTE_RULES[2],
    "secrets/*.yml filter=kist diff=kist": KIST_ATTRIBUTE_RULES[3],
}
KIST_HOOK_MARKER = "# kist-managed-hook-v1"

KIST_HOOK_SCRIPT = (
    "#!/usr/bin/env sh\n"
    f"{KIST_HOOK_MARKER}\n\n"
    "# 1. Check if kist is already in PATH\n"
    "if command -v kist >/dev/null 2>&1; then\n"
    '    exec kist pre-commit-guard "$@"\n'
    "# 2. Check local virtual environments\n"
    'elif [ -x ".venv/bin/kist" ]; then\n'
    '    exec .venv/bin/kist pre-commit-guard "$@"\n'
    'elif [ -x "venv/bin/kist" ]; then\n'
    '    exec venv/bin/kist pre-commit-guard "$@"\n'
    'elif [ -x ".venv/Scripts/kist.exe" ]; then\n'
    '    exec .venv/Scripts/kist.exe pre-commit-guard "$@"\n'
    'elif [ -x "venv/Scripts/kist.exe" ]; then\n'
    '    exec venv/Scripts/kist.exe pre-commit-guard "$@"\n'
    "# 3. Fallback to package manager runners\n"
    "elif command -v uv >/dev/null 2>&1; then\n"
    '    exec uv run kist pre-commit-guard "$@"\n'
    "elif command -v poetry >/dev/null 2>&1; then\n"
    '    exec poetry run kist pre-commit-guard "$@"\n'
    "else\n"
    '    echo "kist: command not found. Activate your virtualenv or install kist globally (uv tool install kist)." >&2\n'
    "    exit 1\n"
    "fi\n"
)


def _stream_filepath() -> str:
    """Recover the Git-provided filename safely from the current process arguments."""
    for flag in ("--clean", "--smudge", "--textconv"):
        if flag in sys.argv:
            index = sys.argv.index(flag)
            if index + 1 < len(sys.argv):
                return sys.argv[index + 1]
    return "<unknown-kist-path>"


def _envelope_matches(envelope: bytes, profile_name: str, path: str) -> bool:
    """True when the envelope header was written for this exact path and scope."""
    return hmac.compare_digest(envelope[46:78], hashlib.sha256(_canonical_aad(git_context(profile_name, path))).digest())


def git_clean_stream(
    profile_name: str,
    password: Optional[str] = None,
    in_stream: Optional[TextIO | BinaryIO] = None,
    out_stream: Optional[BinaryIO] = None,
    filepath: Optional[str] = None,
) -> None:
    """Encrypt a Kist-managed working-tree file and write a v1 envelope to Git.

    A file that is still encrypted (left locked at checkout because no password
    opened it) is passed through unchanged, if it was written for this path.
    """
    in_stream = in_stream or sys.stdin.buffer
    out_stream = out_stream or sys.stdout.buffer
    data = in_stream.read()
    if not data:
        return
    raw = data.encode("utf-8") if isinstance(data, str) else data
    target_path = filepath or _stream_filepath()
    if is_kist_envelope(raw):
        if not _envelope_matches(raw, profile_name, target_path):
            raise InvalidEnvelopeError(
                f"{target_path} contains a Kist envelope for a different path or scope; refusing to stage it."
            )
        out_stream.write(raw)
        return

    password = password or get_profile_password(profile_name)
    if not password:
        raise MissingKeyError(
            f"No password configured for profile {profile_name!r}; refusing to stage plaintext."
        )
    context = git_context(profile_name, target_path)
    previous = _unchanged_envelope(raw, password, context, target_path)
    out_stream.write(previous if previous is not None else encrypt_envelope(raw, password, context))


def _unchanged_envelope(plaintext: bytes, password: str, context: dict[str, str], path: str) -> Optional[bytes]:
    """Return the staged/committed envelope when it already holds exactly this plaintext.

    Encryption is randomised, so without this every `git status`/`git add` of an
    untouched file would produce new ciphertext: false "modified" files and noisy
    commits. Only the current password is tried, so rotation always re-encrypts.
    """
    if os.getenv("KIST_FRESH_ENCRYPTION", "").lower() in {"1", "true", "yes", "on"}:
        return None
    for rev in (f":{path}", f"HEAD:{path}"):
        result = subprocess.run(["git", "cat-file", "blob", rev], capture_output=True, check=False)
        blob = result.stdout
        if result.returncode != 0 or not is_kist_envelope(blob):
            continue
        try:
            if hmac.compare_digest(decrypt_envelope(blob, password, context), plaintext):
                return blob
        except KistError:
            continue
    return None


def git_smudge_stream(
    profile_name: str,
    password: Optional[str] = None,
    in_stream: Optional[BinaryIO] = None,
    out_stream: Optional[TextIO] = None,
    filepath: Optional[str] = None,
) -> None:
    """Decrypt a Kist-managed Git blob for the working tree.

    Without a password that opens it, the blob is left encrypted ("locked", as
    git-crypt does): no plaintext is produced and applications reading the file
    fail. Content that is not a Kist envelope is always refused.
    """
    in_stream = in_stream or sys.stdin.buffer
    out_stream = out_stream or sys.stdout
    envelope = in_stream.read()
    if not envelope:
        return
    if not is_kist_envelope(envelope):
        raise InvalidEnvelopeError("Protected Git file is not a valid Kist v1 envelope.")

    target_path = filepath or _stream_filepath()
    password = password or get_profile_password(profile_name)
    try:
        plaintext, retired = decrypt_with_password_history(
            envelope, profile_name, git_context(profile_name, target_path), password)
        text = plaintext.decode("utf-8")
    except (MissingKeyError, DecryptionError, UnicodeDecodeError) as exc:
        print(f"kist: {target_path}: left encrypted ({exc})", file=sys.stderr)
        buffer = getattr(out_stream, "buffer", None)
        if buffer is not None:
            out_stream.flush()
            buffer.write(envelope)
        else:
            out_stream.write(envelope.decode("latin-1"))
        return
    if retired:
        print(f"kist: {target_path}: opened with retired password {retired} (older content).", file=sys.stderr)
    out_stream.write(text)


def _git_lines(*args: str, cwd: Optional[str] = None) -> list[str]:
    result = subprocess.run(["git", *args], capture_output=True, check=False, cwd=cwd)
    if result.returncode != 0:
        return []
    return [item for item in result.stdout.decode("utf-8", "surrogateescape").split("\0") if item]


def _kist_filtered(paths: list[str], cwd: Optional[str]) -> list[str]:
    """Keep only paths whose Git attributes route them through the Kist filter."""
    if not paths:
        return []
    result = subprocess.run(["git", "check-attr", "-z", "--stdin", "filter"], input="\0".join(paths).encode() + b"\0",
                            capture_output=True, check=False, cwd=cwd)
    if result.returncode != 0:
        return [path for path in paths if _is_targeted_secret(path)]
    fields = result.stdout.decode("utf-8", "surrogateescape").split("\0")
    return [fields[i] for i in range(0, len(fields) - 2, 3) if fields[i + 2] == "kist"]


def _candidate_paths(history: bool) -> tuple[Optional[str], list[str]]:
    top = _git_lines("rev-parse", "--show-toplevel")
    root = top[0].strip() if top else None
    if history:
        paths = sorted(set(_git_lines("log", "--all", "--format=", "--name-only", "-z", cwd=root)))
    else:
        paths = _git_lines("ls-files", "-z", "--cached", "--others", "--exclude-standard", cwd=root)
    return root, _kist_filtered(paths, root)


def resolve_envelope_path(envelope: bytes) -> Optional[tuple[str, str]]:
    """Find the (path, profile) an envelope was encrypted for.

    The v1 header stores SHA-256 of the authenticated context (which includes the
    repository-relative path), so candidate paths can be matched without decrypting.
    Current files are tried first, then every path in the repository history.
    """
    if not is_kist_envelope(envelope):
        return None
    wanted = envelope[46:78]
    for history in (False, True):
        _, paths = _candidate_paths(history)
        for path in paths:
            try:
                profile = profile_from_path(path)
                aad = _canonical_aad(git_context(profile, path))
            except KistError:
                continue
            if hmac.compare_digest(hashlib.sha256(aad).digest(), wanted):
                return path, profile
    return None


def git_textconv(blob_path: str, out_stream: Optional[TextIO] = None) -> None:
    """Git diff driver: print the plaintext of a Kist blob, or a safe placeholder.

    Never fails the diff: when no password can open the blob, a placeholder with
    a short fingerprint is printed so changed ciphertext still shows as a change.
    """
    out_stream = out_stream or sys.stdout
    data = Path(blob_path).read_bytes()
    if not is_kist_envelope(data):
        out_stream.write(data.decode("utf-8", "replace"))
        return
    fingerprint = hashlib.sha256(data).hexdigest()[:12]
    resolved = resolve_envelope_path(data)
    if resolved is None:
        out_stream.write(f"[kist: encrypted content {fingerprint}; scope or path not recognised here]\n")
        return
    path, profile = resolved
    try:
        plaintext, _ = decrypt_with_password_history(data, profile, git_context(profile, path), get_profile_password(profile))
        out_stream.write(plaintext.decode("utf-8"))
    except (KistError, UnicodeDecodeError):
        out_stream.write(f"[kist: encrypted content {fingerprint}; no password for profile {profile!r} opens it]\n")


def _run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def _is_git_repo() -> bool:
    return subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], capture_output=True, check=False).returncode == 0


def _append_missing_lines(path: Path, lines: tuple[str, ...], heading: str) -> bool:
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    existing_set = set(existing)
    missing = [line for line in lines if line not in existing_set]
    if not missing:
        return False
    with path.open("a", encoding="utf-8") as handle:
        if existing and existing[-1].strip():
            handle.write("\n")
        handle.write(f"# {heading}\n")
        handle.write("\n".join(missing))
        handle.write("\n")
    return True


def _upgrade_legacy_attributes(path: Path) -> bool:
    """Add `diff=kist` to rules written by older `kist init` versions, in place."""
    if not path.exists():
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    upgraded = [LEGACY_ATTRIBUTE_RULES.get(line.strip(), line) for line in lines]
    if upgraded == lines:
        return False
    path.write_text("\n".join(upgraded) + "\n", encoding="utf-8")
    return True


def _install_hook(hook_path: Path, *, force: bool = False) -> bool:
    if hook_path.exists():
        content = hook_path.read_text(encoding="utf-8")
        if content == KIST_HOOK_SCRIPT:
            return False
        if KIST_HOOK_MARKER in content:
            hook_path.write_text(KIST_HOOK_SCRIPT, encoding="utf-8")
            os.chmod(hook_path, 0o755)
            return True
        if not force:
            raise KistError(
                f"Refusing to overwrite existing hook {hook_path}. Use `kist init --print-hook` "
                "or `kist init --force-hook` after reviewing the existing hook."
            )
        backup = hook_path.with_name(f"{hook_path.name}.pre-kist-backup")
        if backup.exists():
            raise KistError(f"Refusing to overwrite hook because backup already exists: {backup}")
        hook_path.replace(backup)

    hook_path.write_text(KIST_HOOK_SCRIPT, encoding="utf-8")
    os.chmod(hook_path, 0o755)
    return True


def run_git_setup(*, force_hook: bool = False, install_hook: bool = True) -> None:
    """Configure Git filters without overwriting unrelated repository configuration."""
    if not _is_git_repo():
        raise KistError("Not inside a Git repository. Initialize Git explicitly before running `kist init` (run `git init`).")

    subprocess.run(["git", "config", "filter.kist.clean", "kist --clean %f"], check=True)
    subprocess.run(["git", "config", "filter.kist.smudge", "kist --smudge %f"], check=True)
    subprocess.run(["git", "config", "filter.kist.required", "true"], check=True)
    subprocess.run(["git", "config", "diff.kist.textconv", "kist --textconv"], check=True)

    attributes_changed = _upgrade_legacy_attributes(Path(".gitattributes"))
    attributes_changed = _append_missing_lines(Path(".gitattributes"), KIST_ATTRIBUTE_RULES, "Kist encrypted-secret filters") or attributes_changed
    ignore_changed = _append_missing_lines(Path(".gitignore"), (".kist/",), "Kist local profile passwords")

    hook_changed = False
    if install_hook:
        hook_changed = _install_hook(Path(".git") / "hooks" / "pre-commit", force=force_hook)

    changes = []
    if attributes_changed:
        changes.append(".gitattributes")
    if ignore_changed:
        changes.append(".gitignore")
    if hook_changed:
        changes.append("pre-commit hook")
    print("Kist Git filters configured." + (f" Updated: {', '.join(changes)}." if changes else ""))
    print("Next step: Run 'kist init-db' to initialize your database schema if not already configured.")
    if shutil.which("kist") is None:
        print("Tip: Install kist globally ('uv tool install kist') for seamless Git commits in IDEs and non-activated shells.")


def print_hook() -> None:
    print(KIST_HOOK_SCRIPT, end="")


def _is_targeted_secret(path: str) -> bool:
    normalized = path.replace("\\", "/")
    name = os.path.basename(normalized)
    if not name.endswith((".yaml", ".yml")):
        return False
    return name.startswith("secrets") or normalized.startswith("secrets/") or "/secrets/" in normalized


def _should_scan_plaintext(path: str, blob: bytes) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix in SUSPICIOUS_EXTENSIONS:
        return True
    return b"-----BEGIN " in blob or b"api_key" in blob.lower() or b"secret" in blob.lower()


def _has_likely_credential(text: str, file_path: str = "") -> bool:
    norm_path = file_path.replace("\\", "/").lower()
    is_test_file = (
        norm_path.startswith("tests/")
        or "/tests/" in norm_path
        or norm_path.startswith("test/")
        or "/test/" in norm_path
    )

    for pattern in HIGH_CONFIDENCE_PATTERNS:
        if pattern.search(text):
            if not is_test_file:
                return True

    if is_test_file:
        return False

    for match in SENSITIVE_KEY_ASSIGNMENT.finditer(text):
        val = match.group(2)
        if any(c in val for c in "()[]{}<>"):
            continue
        val_lower = val.lower()
        if any(sub in val_lower for sub in PLACEHOLDER_SUBSTRINGS):
            continue
        if val_lower in IGNORED_KEYWORDS:
            continue
        return True

    return False


def run_leak_guard() -> int:
    """Block plaintext Kist files and likely credentials in every staged text file."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print("kist: unable to inspect staged Git changes.", file=sys.stderr)
        return 1

    staged_files = [item.strip() for item in result.stdout.splitlines() if item.strip()]
    for file_path in staged_files:
        blob_result = subprocess.run(["git", "show", f":{file_path}"], capture_output=True, check=False)
        if blob_result.returncode != 0:
            print(f"kist: unable to inspect staged file: {file_path}", file=sys.stderr)
            return 1
        blob = blob_result.stdout
        if not blob:
            continue

        encrypted = is_kist_envelope(blob)
        if _is_targeted_secret(file_path):
            if not encrypted:
                print(f"kist: blocked plaintext protected secret file: {file_path}", file=sys.stderr)
                return 1
            try:
                bound_here = _envelope_matches(blob, profile_from_path(file_path), file_path)
            except KistError:
                bound_here = True
            if not bound_here:
                print(f"kist: blocked {file_path}: encrypted for another path or scope (moved or copied?). "
                      f"Re-encrypt it for its new path: git add --renormalize {file_path}", file=sys.stderr)
                return 1
            continue

        if encrypted or not _should_scan_plaintext(file_path, blob):
            continue

        text = blob.decode("utf-8", errors="ignore")
        if _has_likely_credential(text, file_path):
            print(f"kist: blocked likely plaintext credential in staged file: {file_path}", file=sys.stderr)
            print("kist: rotate exposed credentials if this value is real, then use an approved secret workflow.", file=sys.stderr)
            return 1
    return 0
