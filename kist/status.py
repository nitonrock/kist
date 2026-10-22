"""Read-only Kist status reporting with redacted operational output."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path

from kist.core import (
    KistError,
    decrypt_with_password_history,
    get_profile_password,
    git_context,
    is_kist_envelope,
    kist_setting_with_source,
    mask_db_url,
    safe_db_connect,
)
from kist.git import KIST_HOOK_MARKER, describe_kist_location, describe_password_source


def _git_value(key: str) -> str:
    result = subprocess.run(["git", "config", "--get", key], capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def _inside_git_repo() -> bool:
    return subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], capture_output=True, check=False).returncode == 0


def _repo_root() -> Path | None:
    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=False)
    return Path(result.stdout.strip()) if result.returncode == 0 and result.stdout.strip() else None


def _package_version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("kist")
    except PackageNotFoundError:
        return "unknown"


def _discover_profiles() -> dict[str, str]:
    profiles: dict[str, str] = {}
    candidate_paths: set[Path] = set()
    candidate_paths.update(Path(".").glob("secrets*.yaml"))
    candidate_paths.update(Path(".").glob("secrets*.yml"))
    if Path("secrets").is_dir():
        candidate_paths.update(Path("secrets").glob("*.yaml"))
        candidate_paths.update(Path("secrets").glob("*.yml"))
        candidate_paths.update(Path("secrets").glob("**/*.yaml"))
        candidate_paths.update(Path("secrets").glob("**/*.yml"))

    for path in sorted(candidate_paths):
        base = path.name.removesuffix(".yaml").removesuffix(".yml")
        profile = "default" if base == "secrets" else base.removeprefix("secrets_")
        profiles[profile] = path.as_posix()

    return profiles


def _key_source(profile: str) -> str:
    """Where the password for ``profile`` comes from, using Kist's real lookup order."""
    source = describe_password_source(profile)
    if source == "no password found":
        return "MISSING"
    if source.startswith("~/"):
        return f"local password file ({source})"
    return f"environment ({source})"


def filter_command_executable(command: str) -> tuple[list[str], str | None]:
    """Split a configured filter command into the part before the Kist flag, and its executable path."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return [], None
    prefix: list[str] = []
    for token in tokens:
        if token.startswith("--"):
            break
        prefix.append(token)
    if not prefix:
        return [], None
    executable = prefix[0]
    if "/" in executable or "\\" in executable:
        found = executable if Path(executable).is_file() else None
    else:
        found = shutil.which(executable)
    return prefix, found


def _command_version(prefix: list[str]) -> str | None:
    try:
        result = subprocess.run([*prefix, "--version"], capture_output=True, text=True, check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    words = result.stdout.split()
    return words[-1] if result.returncode == 0 and words else None


def _filter_command_report(clean: str) -> tuple[str, bool]:
    """One status line for the recorded filter command, and whether it is healthy."""
    prefix, found = filter_command_executable(clean)
    if not prefix:
        return "MISSING (run kist init)", False
    if found is None:
        return (f"NOT FOUND: {prefix[0]} (run `uv sync` if it was the project .venv, or re-run kist init)", False)
    shown = " ".join(shlex.quote(part) for part in prefix)
    bare = "/" not in prefix[0] and "\\" not in prefix[0]
    location, warn = ("found on PATH", False) if bare else describe_kist_location(Path(prefix[0]), _repo_root())
    version = _command_version(prefix)
    running = _package_version()
    details = [f"kist {version}" if version else "version unknown", location]
    healthy = True
    notes = []
    if bare:
        notes.append("bare command: IDEs started from the desktop may not find it; re-run kist init to record an absolute path")
    if warn:
        notes.append("deleting that environment breaks Git operations on secret files")
    if version and running != "unknown" and version != running:
        notes.append(f"this kist is {running}; re-run kist init to align")
        healthy = False
    line = f"{shown} ({', '.join(details)})"
    return (line + (" WARNING: " + "; ".join(notes) if notes else ": OK")), healthy


def _committed_check(path: str, profile: str) -> str:
    """Whether the profile password opens the committed version of ``path``."""
    result = subprocess.run(["git", "cat-file", "blob", f"HEAD:{path}"], capture_output=True, check=False)
    if result.returncode != 0:
        return "not committed yet"
    if not is_kist_envelope(result.stdout):
        return "COMMITTED IN PLAINTEXT"
    password = get_profile_password(profile)
    if not password:
        return "not checked (no password)"
    try:
        _, retired = decrypt_with_password_history(result.stdout, profile, git_context(profile, path), password)
    except KistError:
        return "FAILED: no password for this profile opens the committed file"
    return f"OK (with retired password {retired})" if retired else "OK"


SETTING_DEFAULTS = {"KIST_ORG_ID": "local", "KIST_PROJECT_ID": "default", "KIST_REPOSITORY_ID": "local-repository"}


def _setting_line(name: str, profile: str | None) -> str:
    value, source = kist_setting_with_source(name, profile)
    if name == "KIST_DATABASE_URL":
        shown = mask_db_url(value) if value else "not set"
    else:
        shown = value if value else SETTING_DEFAULTS.get(name, "not set")
    return f"{name}={shown} ({source})"


def _settings_report(profile: str) -> list[str]:
    """Where each identifier and the database URL come from for ``profile``."""
    try:
        return [_setting_line(name, profile) for name in
                ("KIST_ORG_ID", "KIST_PROJECT_ID", "KIST_REPOSITORY_ID", "KIST_DATABASE_URL")]
    except KistError as exc:
        return [f"SETTINGS ERROR: {exc}"]


def setup_hint() -> str | None:
    """One-line hint when this clone's Kist Git setup is missing or broken; None when fine.

    Cheap and read-only, for other commands to print. `kist status` has the details.
    """
    root = _repo_root()
    if root is None:
        return None
    attributes = root / ".gitattributes"
    try:
        if "filter=kist" not in attributes.read_text(encoding="utf-8"):
            return None
    except OSError:
        return None
    clean = _git_value("filter.kist.clean")
    if not clean:
        return "Kist Git filters are not configured in this clone; run `kist init` (details: `kist status`)."
    prefix, found = filter_command_executable(clean)
    if found is None:
        return (f"Kist Git filter command not found ({prefix[0] if prefix else clean}); run `uv sync` or "
                "`kist init` (details: `kist status`).")
    if not _git_value("merge.kist.driver"):
        return "Kist merge driver missing in this clone; run `kist init` (details: `kist status`)."
    return None


def run_status() -> int:
    """Inspect status only; never connects to the database unless explicitly configured."""
    print("Kist status")
    print("=" * 50)
    healthy = True
    in_repo = _inside_git_repo()

    if not in_repo:
        print("Git: not inside a repository")
        healthy = False
    else:
        clean_value = _git_value("filter.kist.clean")
        clean = bool(clean_value)
        smudge = bool(_git_value("filter.kist.smudge"))
        textconv = bool(_git_value("diff.kist.textconv"))
        merge = bool(_git_value("merge.kist.driver"))
        attrs_text = Path(".gitattributes").read_text(encoding="utf-8") if Path(".gitattributes").exists() else ""
        attrs = "filter=kist" in attrs_text
        attrs_merge = "merge=kist" in attrs_text
        ignored = Path(".gitignore").exists() and ".kist/" in Path(".gitignore").read_text(encoding="utf-8")
        hook = Path(".git") / "hooks" / "pre-commit"
        hook_ok = hook.exists() and KIST_HOOK_MARKER in hook.read_text(encoding="utf-8", errors="replace")
        if clean:
            line, command_ok = _filter_command_report(clean_value)
            print(f"Git filter command: {line}")
        else:
            command_ok = False
        print(f"Git clean filter: {'OK' if clean else 'MISSING'}")
        print(f"Git smudge filter: {'OK' if smudge else 'MISSING'}")
        print(f"Git diff driver: {'OK' if textconv else 'MISSING (run kist init for readable diffs)'}")
        print(f"Git merge driver: {'OK' if merge and attrs_merge else 'MISSING (run kist init)'}")
        print(f"Git attributes: {'OK' if attrs else 'MISSING'}")
        print(f"Local password ignore rule: {'OK' if ignored else 'MISSING'}")
        print(f"Kist pre-commit hook: {'OK' if hook_ok else 'MISSING OR THIRD-PARTY'}")
        healthy = healthy and clean and smudge and attrs and ignored and command_ok

    print("\nProfiles:")
    profiles = _discover_profiles()
    if not profiles:
        print("None discovered")
    for profile, path in sorted(profiles.items()):
        location = path or "no matching YAML file"
        source = _key_source(profile)
        line = f"- {profile}: {location}; password source: {source}"
        if source == "MISSING":
            healthy = False
        elif in_repo:
            committed = _committed_check(path, profile)
            line += f"; opens committed version: {committed}"
            if committed.startswith(("FAILED", "COMMITTED IN PLAINTEXT")):
                healthy = False
        print(line)
        settings = _settings_report(profile)
        if settings[0].startswith("SETTINGS ERROR"):
            healthy = False
        for item in settings:
            print(f"    {item}")

    print("\nMachine settings:")
    try:
        for name in ("KIST_ENV", "KIST_TLS_MODE"):
            value, source = kist_setting_with_source(name)
            print(f"- {name}={value or ('development' if name == 'KIST_ENV' else 'auto')} ({source})")
        database_url, database_source = kist_setting_with_source("KIST_DATABASE_URL")
    except KistError as exc:
        print(f"SETTINGS ERROR: {exc}")
        database_url, database_source = None, "default"
        healthy = False

    print("\nDatabase:")
    if not database_url:
        print("Not configured (Git-only mode)")
    else:
        print(f"Configured: {mask_db_url(database_url)} ({database_source})")
        try:
            with safe_db_connect(database_url, connect_timeout=3) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            print("Connectivity: OK")
        except Exception as exc:
            print(f"Connectivity: FAILED ({type(exc).__name__})")
            healthy = False

    print("\nNote: local Git hooks can be bypassed. Use required CI/server-side protection for organization-wide enforcement.")
    return 0 if healthy else 1
