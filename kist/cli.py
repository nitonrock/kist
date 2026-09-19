import sys
import argparse
import os
from kist.core import (
    Kist,
    get_profile_and_password,
    resolve_secret_file_path,
)
from kist.git import (
    run_git_setup,
    run_leak_guard,
    git_clean_stream,
    git_smudge_stream,
)
from kist.status import run_status
from kist.fix import run_fix


def main():
    """Package console entry point script router layout."""
    parser = argparse.ArgumentParser(description="Kist: Complete Multi-Profile Secrets Management Engine")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    subparsers.add_parser("init", help="Configure local repository Git hooks and attributes maps")
    subparsers.add_parser("status", help="Inspect Git hook configuration, profile keys, and DB sync state")
    subparsers.add_parser("fix", help="Diagnose and repair Git filters, profile keys, and staging encryption state")
    subparsers.add_parser("pre-commit-guard", help="Scan staged changes to block unencrypted secret commits")

    lock_parser = subparsers.add_parser("lock", help="Flatten and secure a local tree YAML file into PostgreSQL rows")
    lock_parser.add_argument("file", type=str, help="Target yaml file path or profile name")
    lock_parser.add_argument("--prune", "-p", action="store_true", help="Delete secrets in the database that are no longer in the YAML file")

    unlock_parser = subparsers.add_parser("unlock", help="Reconstruct structured YAML configs from PostgreSQL storage")
    unlock_parser.add_argument("file", type=str, help="Target yaml file path or profile name")

    parser.add_argument("--clean", type=str, metavar="FILE", help="Execute Git clean filter on stdin")
    parser.add_argument("--smudge", type=str, metavar="FILE", help="Execute Git smudge filter on stdin")

    args = parser.parse_args()

    if args.clean:
        profile_name, master_password = get_profile_and_password(args.clean)
        git_clean_stream(profile_name=profile_name, master_password=master_password)
        sys.exit(0)

    if args.smudge:
        profile_name, master_password = get_profile_and_password(args.smudge)
        git_smudge_stream(profile_name=profile_name, master_password=master_password)
        sys.exit(0)

    if args.command == "init":
        run_git_setup()
        sys.exit(0)
    elif args.command == "status":
        sys.exit(run_status())
    elif args.command == "fix":
        sys.exit(run_fix())
    elif args.command == "pre-commit-guard":
        sys.exit(run_leak_guard())

    if args.command in ("lock", "unlock"):
        target_input = args.file
        target_file = resolve_secret_file_path(target_input)

        if args.command == "lock":
            if not os.path.isfile(target_file):
                print(f"❌ Error: Secret file '{target_input}' not found (checked '{target_file}').", file=sys.stderr)
                sys.exit(1)
            profile_name, master_password = get_profile_and_password(target_file)
            kist_inst = Kist(profile_name=profile_name, master_password=master_password)
            with open(target_file, "r") as f:
                content = f.read()
            kist_inst.lock_yaml(content, prune=getattr(args, "prune", False))
            sys.exit(0)

        elif args.command == "unlock":
            profile_name, master_password = get_profile_and_password(target_file)
            kist_inst = Kist(profile_name=profile_name, master_password=master_password)
            print(kist_inst.unlock_yaml())
            sys.exit(0)

    parser.print_help()
    sys.exit(0)
