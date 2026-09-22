"""Read-only Kist status reporting with redacted operational output."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from kist.core import KIST_DATABASE_URL, get_kist_dir, mask_db_url, safe_db_connect
from kist.git import KIST_HOOK_MARKER


def _git_value(key: str) -> str:
    result = subprocess.run(["git", "config", "--get", key], capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def _inside_git_repo() -> bool:
    return subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], capture_output=True, check=False).returncode == 0


def _discover_profiles() -> dict[str, str | None]:
    profiles: dict[str, str | None] = {}
    candidates: list[Path] = []
    candidates.extend(Path(".").glob("secrets*.yaml"))
    candidates.extend(Path(".").glob("secrets*.yml"))
    if Path("secrets").is_dir():
        candidates.extend(Path("secrets").glob("*.yaml"))
        candidates.extend(Path("secrets").glob("*.yml"))

    for path in candidates:
        base = path.name.removesuffix(".yaml").removesuffix(".yml")
        profile = "default" if base == "secrets" else base.removeprefix("secrets_")
        profiles[profile] = str(path)

    key_dir = Path(get_kist_dir())
    if key_dir.is_dir():
        for key_path in key_dir.glob("pwd_*"):
            profiles.setdefault(key_path.name[len("pwd_"):], None)
    return profiles


def _key_source(profile: str) -> str:
    env_key = "KIST_PASSWORD_DEFAULT" if profile == "default" else f"KIST_PASSWORD_{profile.upper()}"
    if os.getenv(env_key):
        return f"environment ({env_key})"
    if os.getenv("KIST_PASSWORD"):
        return "environment (KIST_PASSWORD)"
    if (Path(get_kist_dir()) / f"pwd_{profile}").exists():
        return "local key file"
    return "MISSING"


def run_status() -> int:
    """Inspect status only; never connects to the database unless explicitly configured."""
    print("Kist status")
    print("=" * 50)
    healthy = True

    if not _inside_git_repo():
        print("Git: not inside a repository")
        healthy = False
    else:
        clean = bool(_git_value("filter.kist.clean"))
        smudge = bool(_git_value("filter.kist.smudge"))
        attrs = Path(".gitattributes").exists() and "filter=kist" in Path(".gitattributes").read_text(encoding="utf-8")
        ignored = Path(".gitignore").exists() and ".kist/" in Path(".gitignore").read_text(encoding="utf-8")
        hook = Path(".git") / "hooks" / "pre-commit"
        hook_ok = hook.exists() and KIST_HOOK_MARKER in hook.read_text(encoding="utf-8", errors="replace")
        print(f"Git clean filter: {'OK' if clean else 'MISSING'}")
        print(f"Git smudge filter: {'OK' if smudge else 'MISSING'}")
        print(f"Git attributes: {'OK' if attrs else 'MISSING'}")
        print(f"Local key ignore rule: {'OK' if ignored else 'MISSING'}")
        print(f"Kist pre-commit hook: {'OK' if hook_ok else 'MISSING OR THIRD-PARTY'}")
        healthy = healthy and clean and smudge and attrs and ignored

    print("\nProfiles:")
    profiles = _discover_profiles()
    if not profiles:
        print("None discovered")
    for profile, path in sorted(profiles.items()):
        location = path or "no matching YAML file"
        source = _key_source(profile)
        print(f"- {profile}: {location}; key source: {source}")
        if source == "MISSING":
            healthy = False

    print("\nDatabase:")
    if not KIST_DATABASE_URL:
        print("Not configured (Git-only mode)")
    else:
        print(f"Configured: {mask_db_url(KIST_DATABASE_URL)}")
        try:
            with safe_db_connect(KIST_DATABASE_URL, connect_timeout=3) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            print("Connectivity: OK")
        except Exception as exc:
            print(f"Connectivity: FAILED ({type(exc).__name__})")
            healthy = False

    print("\nNote: local Git hooks can be bypassed. Use required CI/server-side protection for organization-wide enforcement.")
    return 0 if healthy else 1
