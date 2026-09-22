"""Read-only diagnosis and explicit repair operations for Kist."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from kist.core import KistError
from kist.git import KIST_ATTRIBUTE_RULES, KIST_HOOK_MARKER, run_git_setup


def _inside_git_repo() -> bool:
    return subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], capture_output=True, check=False).returncode == 0


def _missing_attribute_rules() -> list[str]:
    path = Path(".gitattributes")
    existing = set(path.read_text(encoding="utf-8").splitlines()) if path.exists() else set()
    return [rule for rule in KIST_ATTRIBUTE_RULES if rule not in existing]


def _hook_state() -> str:
    hook = Path(".git") / "hooks" / "pre-commit"
    if not hook.exists():
        return "missing"
    content = hook.read_text(encoding="utf-8", errors="replace")
    return "kist" if KIST_HOOK_MARKER in content else "third-party"


def run_diagnose() -> int:
    """Report configuration gaps without changing Git, files, index, or credentials."""
    print("Kist diagnostics")
    print("=" * 50)
    if not _inside_git_repo():
        print("FAIL: not inside a Git repository. Initialize Git explicitly, then run `kist init`.")
        return 1

    findings = 0
    checks = {
        "filter.kist.clean": "git config --get filter.kist.clean",
        "filter.kist.smudge": "git config --get filter.kist.smudge",
    }
    for label, command in checks.items():
        result = subprocess.run(command.split(), capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            print(f"OK: {label} configured")
        else:
            findings += 1
            print(f"WARN: {label} missing")

    missing_rules = _missing_attribute_rules()
    if missing_rules:
        findings += 1
        print("WARN: .gitattributes is missing Kist rules:")
        for rule in missing_rules:
            print(f"  - {rule}")
    else:
        print("OK: .gitattributes contains all Kist rules")

    gitignore = Path(".gitignore")
    ignored = gitignore.exists() and ".kist/" in gitignore.read_text(encoding="utf-8")
    if ignored:
        print("OK: .kist/ is ignored")
    else:
        findings += 1
        print("WARN: .kist/ is not ignored")

    hook_state = _hook_state()
    if hook_state == "kist":
        print("OK: Kist pre-commit hook installed")
    elif hook_state == "missing":
        findings += 1
        print("WARN: no pre-commit hook installed")
    else:
        findings += 1
        print("WARN: a non-Kist pre-commit hook exists; it will not be overwritten automatically")

    if findings:
        print("\nSuggested next step: review the output, then run `kist fix --apply`.")
        return 1
    print("\nKist local integration appears healthy.")
    return 0


def run_fix(*, apply: bool = False, force_hook: bool = False) -> int:
    """Show or apply a limited repair plan; never generates profile keys or restages files."""
    if not _inside_git_repo():
        print("kist: not inside a Git repository; refusing to initialize one automatically.")
        return 1

    if not apply:
        print("Kist repair plan (dry run)")
        print("=" * 50)
        print("- Configure required local Git clean/smudge filters")
        if _missing_attribute_rules():
            print("- Append missing Kist filter entries to .gitattributes")
        if not (Path(".gitignore").exists() and ".kist/" in Path(".gitignore").read_text(encoding="utf-8")):
            print("- Append .kist/ to .gitignore")
        state = _hook_state()
        if state == "missing":
            print("- Install a Kist pre-commit hook")
        elif state == "third-party":
            print("- Existing third-party hook detected; no replacement unless --force-hook is supplied")
        print("\nNo files, Git configuration, staging state, or credentials were changed.")
        print("Run `kist fix --apply` to apply the safe plan.")
        return 0

    try:
        run_git_setup(force_hook=force_hook, install_hook=True)
    except KistError as exc:
        print(f"kist: repair not applied: {exc}")
        return 1

    print("Kist repair completed. No profile keys were generated and no files were restaged.")
    return 0
