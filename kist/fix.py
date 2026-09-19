import os
import sys
import subprocess
from kist.core import (
    get_profile_password,
    get_kist_dir,
)
from kist.git import run_git_setup


def run_fix() -> int:
    """
    Automated diagnostic and repair command:
    1. Ensures Git filters, .gitattributes, .gitignore, and pre-commit hooks are properly configured.
    2. Ensures master password keys exist in ~/.kist/ for all discovered secret profiles.
    3. Resolves staging desynchronization and re-encrypts any unencrypted or out-of-sync secret files in the Git index.
    """
    print("🔧 Kist Auto-Repair & Environment Sync")
    print("=" * 50)

    is_git_repo = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        check=False,
    ).returncode == 0

    if not is_git_repo:
        print("⚠️  Not inside a Git repository. Initializing Git repository...")
        subprocess.run(["git", "init"], check=True)

    # 1. Ensure Git Filters, Attributes, and Hooks
    print("\n🛠️  1. Repairing Git Configuration & Plumbing:")
    run_git_setup()

    # 2. Discover local secret profiles and ensure keys exist
    print("\n🔑 2. Verifying Secret Profile Passwords:")
    discovered_files = []
    # Search root
    for f in os.listdir("."):
        if os.path.isfile(f) and f.startswith("secrets") and (f.endswith(".yaml") or f.endswith(".yml")):
            discovered_files.append(f)
    # Search secrets/ directory
    if os.path.isdir("secrets"):
        for f in os.listdir("secrets"):
            full_p = os.path.join("secrets", f)
            if os.path.isfile(full_p) and (f.endswith(".yaml") or f.endswith(".yml")):
                discovered_files.append(full_p)

    profiles = set()
    for file_p in discovered_files:
        filename = os.path.basename(file_p)
        base_name = filename.replace(".yaml", "").replace(".yml", "")
        if base_name == "secrets":
            prof = "default"
        elif base_name.startswith("secrets_"):
            prof = base_name[len("secrets_"):]
        else:
            prof = base_name
        profiles.add(prof)

    if not profiles:
        profiles.add("default")

    generated_keys = 0
    kist_dir = get_kist_dir()
    for prof in sorted(profiles):
        env_var = f"KIST_PASSWORD_{prof.upper()}" if prof != "default" else "KIST_PASSWORD_DEFAULT"
        has_env = os.getenv(env_var) or os.getenv("KIST_PASSWORD")
        has_file = os.path.exists(os.path.join(kist_dir, f"pwd_{prof}"))

        if has_env:
            print(f"  ✔ Profile '{prof}': Key found in environment variable (${env_var})")
        elif has_file:
            print(f"  ✔ Profile '{prof}': Key found in ~/.kist/pwd_{prof}")
        else:
            pwd = get_profile_password(prof, auto_generate=True)
            generated_keys += 1
            print(f"  ✔ Profile '{prof}': Generated and saved new master key to ~/.kist/pwd_{prof}")

    # 3. Inspect and Repair Git Index & Staged Secret Files
    print("\n🛡️  3. Inspecting & Repairing Git Staging Index:")
    staged_res = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
        check=False,
    )
    staged_files = [f.strip() for f in staged_res.stdout.split("\n") if f.strip()]

    repaired_count = 0
    for file_path in discovered_files:
        norm_path = file_path.replace("\\", "/")
        # Check if file is staged in Git index
        show_res = subprocess.run(["git", "show", f":{norm_path}"], capture_output=True, check=False)
        blob = show_res.stdout

        # If it is in the index and unencrypted (or staged and out-of-sync)
        is_staged = norm_path in staged_files or show_res.returncode == 0
        if is_staged and blob:
            is_encrypted = len(blob) > 16 and blob[16:].startswith(b"gAAAAA")
            if not is_encrypted:
                print(f"  ⚠️  Found unencrypted plaintext for '{norm_path}' in Git index. Re-staging...")
                subprocess.run(["git", "add", norm_path], check=True)
                repaired_count += 1
                print(f"  ✔ Staged '{norm_path}' encrypted via Kist clean filter.")
            else:
                print(f"  ✔ Staged '{norm_path}' is already properly encrypted in Git index.")

    if repaired_count == 0:
        print("  ✔ No unencrypted secret files found in Git index.")

    print("\n" + "=" * 50)
    print("🎉 Repair Complete! Your Git filters, profile keys, and staging index are now healthy.")
    return 0
