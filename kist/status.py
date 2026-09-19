import os
import subprocess
from urllib.parse import urlsplit, urlunsplit
import psycopg
from kist.core import KIST_DATABASE_URL, safe_db_connect, mask_db_url, get_kist_dir


def run_status() -> int:
    """Inspects and reports Git hooks, local secret files, password resolution, and DB sync status."""
    print("📦 Kist Status Overview")
    print("=" * 50)

    # 1. Git Pipeline & Hooks
    print("\n🛡️  Git Pipeline & Hooks:")
    is_git_repo = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        check=False,
    ).returncode == 0

    if not is_git_repo:
        print("  ⚠️  Not inside a Git repository")
    else:
        # Check filters
        clean_cfg = subprocess.run(
            ["git", "config", "--get", "filter.kist.clean"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        smudge_cfg = subprocess.run(
            ["git", "config", "--get", "filter.kist.smudge"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()

        if clean_cfg:
            print("  ✔ Git clean filter configured")
        else:
            print("  ⚠️  Git clean filter NOT configured (Run 'kist fix')")

        if smudge_cfg:
            print("  ✔ Git smudge filter configured")
        else:
            print("  ⚠️  Git smudge filter NOT configured (Run 'kist fix')")

        # Check .gitattributes
        gitattrs_ok = False
        if os.path.exists(".gitattributes"):
            with open(".gitattributes", "r") as f:
                content = f.read()
                if "filter=kist" in content:
                    gitattrs_ok = True
        if gitattrs_ok:
            print("  ✔ .gitattributes configured (secrets*.yaml)")
        else:
            print("  ⚠️  .gitattributes missing or missing filter=kist (Run 'kist fix')")

        # Check .gitignore
        kist_ignored = False
        if os.path.exists(".gitignore"):
            with open(".gitignore", "r") as f:
                if ".kist" in f.read():
                    kist_ignored = True
        if kist_ignored:
            print("  ✔ .gitignore protects .kist/")
        else:
            print("  ⚠️  .gitignore does NOT ignore .kist/ (Run 'kist fix')")

        # Check pre-commit hook
        hook_path = os.path.join(".git", "hooks", "pre-commit")
        if os.path.exists(hook_path) and os.access(hook_path, os.X_OK):
            with open(hook_path, "r") as f:
                hook_content = f.read()
            if "run_leak_guard" in hook_content or "kist" in hook_content:
                print("  ✔ Pre-commit leak guard installed & active")
            else:
                print("  ⚠️  Pre-commit hook exists but does not call Kist leak guard (Run 'kist fix')")
        else:
            print("  ⚠️  Pre-commit leak guard NOT installed (Run 'kist fix')")

    # 2. Secret Profiles & Local Files
    print("\n🔑 Secret Profiles Detected:")
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

    # Check profiles in ~/.kist/
    kist_profiles_in_dir = []
    kist_dir = get_kist_dir()
    if os.path.isdir(kist_dir):
        for f in os.listdir(kist_dir):
            if f.startswith("pwd_"):
                kist_profiles_in_dir.append(f[len("pwd_"):])

    profile_map = {}
    for file_p in discovered_files:
        filename = os.path.basename(file_p)
        base_name = filename.replace(".yaml", "").replace(".yml", "")
        if base_name == "secrets":
            prof = "default"
        elif base_name.startswith("secrets_"):
            prof = base_name[len("secrets_"):]
        else:
            prof = base_name
        profile_map[prof] = file_p

    for prof in kist_profiles_in_dir:
        if prof not in profile_map:
            profile_map[prof] = None

    # Connect to DB if possible to gather stats
    db_profile_stats = {}
    db_connected = False
    db_err = None
    masked_db_url = None

    if KIST_DATABASE_URL:
        masked_db_url = mask_db_url(KIST_DATABASE_URL)

        try:
            with safe_db_connect(KIST_DATABASE_URL, connect_timeout=3) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT table_name FROM information_schema.tables 
                        WHERE table_schema = 'public' AND table_name IN ('kist_profiles', 'kist');
                        """
                    )
                    existing_tables = [r[0] for r in cur.fetchall()]
                    if "kist_profiles" in existing_tables and "kist" in existing_tables:
                        cur.execute(
                            """
                            SELECT p.profile_name, count(k.id), max(k.updated_at)
                            FROM kist_profiles p
                            LEFT JOIN kist k ON p.id = k.profile_id
                            GROUP BY p.profile_name;
                            """
                        )
                        for r in cur.fetchall():
                            db_profile_stats[r[0]] = {"count": r[1], "last_updated": r[2]}
                db_connected = True
        except Exception as e:
            db_err = str(e)
            db_connected = False

    if not profile_map and not db_profile_stats:
        print("  (No secret files or profiles found)")
    else:
        all_profiles = sorted(set(list(profile_map.keys()) + list(db_profile_stats.keys())))
        for prof in all_profiles:
            file_p = profile_map.get(prof)
            label = f"• Profile '{prof}'"
            if file_p:
                label += f" ({file_p})"
            print(f"  {label}")

            # Password check
            env_var = f"KIST_PASSWORD_{prof.upper()}" if prof != "default" else "KIST_PASSWORD_DEFAULT"
            if os.getenv(env_var):
                print(f"    - Password: Found via env ${env_var}")
            elif os.getenv("KIST_PASSWORD"):
                print(f"    - Password: Found via env $KIST_PASSWORD")
            elif os.path.exists(os.path.join(kist_dir, f"pwd_{prof}")):
                print(f"    - Password: Found via ~/.kist/pwd_{prof}")
            else:
                hint_var = f"Set {env_var}" if prof != "default" else "Set KIST_PASSWORD_DEFAULT or KIST_PASSWORD"
                print(f"    - Password: ⚠️  MISSING ({hint_var})")

            # Git staging check
            if is_git_repo and file_p:
                check_staged = subprocess.run(
                    ["git", "diff", "--cached", "--name-only", "--", file_p],
                    capture_output=True,
                    text=True,
                    check=False,
                ).stdout.strip()
                if check_staged:
                    blob_check = subprocess.run(
                        ["git", "show", f":{file_p}"],
                        capture_output=True,
                        check=False,
                    ).stdout
                    is_encrypted = len(blob_check) > 16 and blob_check[16:].startswith(b"gAAAAA")
                    if is_encrypted:
                        print("    - Git Staging: Clean (Encrypted blob in index)")
                    else:
                        print("    - Git Staging: 🚨 UNENCRYPTED PLAINTEXT IN INDEX! (Run 'kist fix')")
                else:
                    is_tracked = subprocess.run(
                        ["git", "ls-files", file_p],
                        capture_output=True,
                        text=True,
                        check=False,
                    ).stdout.strip()
                    if is_tracked:
                        print("    - Git Staging: Clean / unstaged working copy")
                    else:
                        print("    - Git Staging: Untracked")

            # DB Sync check
            if KIST_DATABASE_URL:
                if db_connected:
                    if prof in db_profile_stats:
                        st = db_profile_stats[prof]
                        cnt = st["count"]
                        dt = st["last_updated"]
                        dt_str = dt.strftime("%Y-%m-%d %H:%M") if dt else "N/A"
                        print(f"    - DB Sync: {cnt} secrets synced (Last updated: {dt_str})")
                    else:
                        print("    - DB Sync: Not configured / uninitialized")
                else:
                    print("    - DB Sync: Unable to check (DB unreachable)")
            else:
                print("    - DB Sync: Local Git Filter mode (KIST_DATABASE_URL not set)")
            print()

    # 3. Database Summary
    print("🗄️  Database:")
    if KIST_DATABASE_URL:
        if db_connected:
            print(f"  ✔ {masked_db_url} (Connected)")
        else:
            print(f"  ❌ {masked_db_url} (Connection failed: {db_err})")
    else:
        print("  • Not configured (Local Git Filter mode active)")

    print()
    return 0
