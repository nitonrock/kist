import os
import sys
import re
import subprocess
from typing import Optional, BinaryIO, TextIO
from kist.core import (
    get_profile_password,
    derive_fernet_key,
)

# Heuristic patterns for sensitive credentials in unencrypted staged files
SENSITIVE_KEY_PATTERNS = [
    re.compile(r"""(?i)\b(api[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|db[_-]?password|aws_secret_access_key)\s*[:=]\s*['"]?[A-Za-z0-9_\-\+\/]{8,}"""),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
]

# File extensions checked for sensitive content heuristics
SUSPICIOUS_EXTENSIONS = (".yaml", ".yml", ".json", ".toml", ".env", ".ini", ".conf", ".cfg")
EXCLUDED_HEURISTIC_PATHS = ("tests/", "test/", "ressources/", "resources/", "docs/", "scrapbook/")


def git_clean_stream(
    profile_name: str,
    master_password: Optional[str] = None,
    in_stream: Optional[TextIO] = None,
    out_stream: Optional[BinaryIO] = None,
):
    """
    Git Clean Filter:
    Reads plaintext YAML from stdin, generates a fresh random 16-byte salt,
    encrypts the content with Fernet (Argon2id KDF), and writes [salt (16 bytes) + ciphertext] to stdout.
    Fails closed if master password is not configured.
    """
    if in_stream is None:
        in_stream = sys.stdin
    if out_stream is None:
        out_stream = sys.stdout.buffer

    if not master_password:
        master_password = get_profile_password(profile_name, auto_generate=False)

    if not master_password:
        print(
            f"❌ Kist Error: Missing encryption password for profile '{profile_name}'. "
            f"Set KIST_PASSWORD_{profile_name.upper()} or create ~/.kist/pwd_{profile_name}.",
            file=sys.stderr,
        )
        sys.exit(1)

    plaintext = in_stream.read()
    if plaintext.strip():
        # Generate fresh, unique random 16-byte salt
        salt = os.urandom(16)
        fernet = derive_fernet_key(master_password, salt)
        encrypted_data = fernet.encrypt(plaintext.encode("utf-8"))
        # Output prepended salt + fernet ciphertext
        out_stream.write(salt + encrypted_data)


def git_smudge_stream(
    profile_name: str,
    master_password: Optional[str] = None,
    in_stream: Optional[BinaryIO] = None,
    out_stream: Optional[TextIO] = None,
):
    """
    Git Smudge Filter:
    Reads [salt (16 bytes) + ciphertext] from repository object storage,
    derives the decryption key using the embedded salt (Argon2id KDF), and writes plaintext to stdout.
    """
    if in_stream is None:
        in_stream = sys.stdin.buffer
    if out_stream is None:
        out_stream = sys.stdout

    data = in_stream.read()
    if not data:
        return

    if not master_password:
        master_password = get_profile_password(profile_name, auto_generate=False)

    if not master_password:
        # If no password found, passthrough raw data without crashing Git
        if hasattr(out_stream, "buffer"):
            out_stream.buffer.write(data)
        else:
            sys.stdout.buffer.write(data)
        return

    # Modern prepended-salt format (16 bytes salt + Fernet token)
    if len(data) > 16:
        salt = data[:16]
        ciphertext = data[16:]
        try:
            fernet = derive_fernet_key(master_password, salt)
            plaintext = fernet.decrypt(ciphertext).decode("utf-8")
            out_stream.write(plaintext)
            return
        except Exception:
            pass

    # Fallback: passthrough unmodifiable bytes
    if hasattr(out_stream, "buffer"):
        out_stream.buffer.write(data)
    else:
        sys.stdout.buffer.write(data)


def run_git_setup():
    """Sets up local repository configurations to bypass git-crypt entirely."""
    is_git_repo = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        check=False,
    ).returncode == 0

    if not is_git_repo:
        subprocess.run(["git", "init"], check=True)

    print("⚙️ Hooking Kist filters directly into your native local Git pipeline...")

    subprocess.run(["git", "config", "filter.kist.clean", "kist --clean %f"], check=True)
    subprocess.run(["git", "config", "filter.kist.smudge", "kist --smudge %f"], check=True)
    subprocess.run(["git", "config", "filter.kist.required", "true"], check=True)

    with open(".gitattributes", "w") as f:
        f.write("secrets*.yaml filter=kist\n")
        f.write("secrets*.yml filter=kist\n")
        f.write("secrets/*.yaml filter=kist\n")
        f.write("secrets/*.yml filter=kist\n")

    # Ensure .kist is ignored in .gitignore
    gitignore_path = ".gitignore"
    kist_ignored = False
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r") as f:
            if ".kist" in f.read():
                kist_ignored = True
    if not kist_ignored:
        with open(gitignore_path, "a") as f:
            f.write("\n# Kist local profile keys\n.kist/\n")

    hook_dir = ".git/hooks"
    os.makedirs(hook_dir, exist_ok=True)
    hook_path = os.path.join(hook_dir, "pre-commit")
    with open(hook_path, "w") as hook_file:
        hook_file.write("#!/usr/bin/env sh\n")
        hook_file.write("# Kist automated pre-commit leak guard\n")
        hook_file.write("if command -v kist >/dev/null 2>&1; then\n")
        hook_file.write("    kist pre-commit-guard\n")
        hook_file.write("elif [ -f .venv/bin/kist ]; then\n")
        hook_file.write("    .venv/bin/kist pre-commit-guard\n")
        hook_file.write("else\n")
        hook_file.write("    python3 -c \"import sys; from kist import run_leak_guard; sys.exit(run_leak_guard())\"\n")
        hook_file.write("fi\n")

    os.chmod(hook_path, 0o755)
    print("🏆 Initialization Complete! The Leak Guard is armed.")


def run_leak_guard() -> int:
    """
    Scans all staged files targeted for commit.
    1. Ensures secrets files match the encrypted envelope format (16 bytes salt + Fernet token).
    2. Runs heuristic detection on other staged config/data files for plaintext credentials.
    Hard aborts (returns 1) if plaintext leaks or unencrypted sensitive keys are detected.
    """
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    staged_files = [f.strip() for f in result.stdout.split("\n") if f.strip()]

    for file_path in staged_files:
        norm_path = file_path.replace("\\", "/")
        filename = os.path.basename(norm_path)

        # 1. Inspect targeted Kist secret files
        is_targeted_secret = (
            (filename.startswith("secrets") and (filename.endswith(".yaml") or filename.endswith(".yml")))
            or norm_path.startswith("secrets/")
        )

        content_res = subprocess.run(["git", "show", f":{file_path}"], capture_output=True, check=False)
        blob = content_res.stdout
        if not blob:
            continue

        is_encrypted = len(blob) > 16 and blob[16:].startswith(b"gAAAAA")

        if is_targeted_secret:
            if not is_encrypted:
                print("\n=======================================================", file=sys.stderr)
                print("🚨 CRITICAL SECURITY FAULT: Plaintext Secret Leak Detected!", file=sys.stderr)
                print(f"👉 Target File: '{file_path}' is staged in plaintext without Kist encryption.", file=sys.stderr)
                print("💡 Action Required: Configure Git filters via 'kist init' and set profile password.", file=sys.stderr)
                print("=======================================================\n", file=sys.stderr)
                return 1
            continue

        # 2. Content Heuristics for other unencrypted staged configuration / data files
        is_excluded = any(norm_path.startswith(prefix) for prefix in EXCLUDED_HEURISTIC_PATHS) or norm_path.startswith(".")
        if not is_excluded and not is_encrypted and any(norm_path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            try:
                text_content = blob.decode("utf-8", errors="ignore")
                for pat in SENSITIVE_KEY_PATTERNS:
                    if pat.search(text_content):
                        print("\n=======================================================", file=sys.stderr)
                        print("🚨 CRITICAL SECURITY FAULT: Unencrypted Sensitive Credential Detected!", file=sys.stderr)
                        print(f"👉 Staged File: '{file_path}' contains unencrypted secret/key patterns.", file=sys.stderr)
                        print("💡 Action Required: Rename file to 'secrets*.yaml' or use Kist to encrypt secrets.", file=sys.stderr)
                        print("=======================================================\n", file=sys.stderr)
                        return 1
            except Exception:
                pass

    return 0
