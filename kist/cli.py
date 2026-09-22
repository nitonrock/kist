"""Command-line entry point for Kist."""

from __future__ import annotations

import argparse
import os
import sys

from kist.core import Kist, KistError, KistScope, create_profile_key, get_profile_and_password, resolve_secret_file_path
from kist.fix import run_diagnose, run_fix
from kist.git import git_clean_stream, git_smudge_stream, print_hook, run_git_setup, run_leak_guard
from kist.status import run_status


def _require_tty_for_key_display() -> None:
    if not sys.stdout.isatty():
        raise KistError("Refusing to print a newly generated profile key to non-interactive stdout.")


def _scope_from_args(args: argparse.Namespace) -> KistScope:
    base = KistScope.from_environment()
    return KistScope(organization=args.org or base.organization, project=args.project or base.project).validated()


def main() -> None:
    parser = argparse.ArgumentParser(description="Kist: Git-native encrypted configuration and secret hygiene tooling")
    parser.add_argument("--org", help="Organization namespace; defaults to KIST_ORG_ID or local")
    parser.add_argument("--project", help="Project namespace; defaults to KIST_PROJECT_ID or default")
    parser.add_argument("--clean", type=str, metavar="FILE", help="Git clean filter entry point")
    parser.add_argument("--smudge", type=str, metavar="FILE", help="Git smudge filter entry point")
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="Configure non-destructive local Git integration")
    init_parser.add_argument("--force-hook", action="store_true")
    init_parser.add_argument("--no-hook", action="store_true")
    init_parser.add_argument("--print-hook", action="store_true")
    subparsers.add_parser("status", help="Inspect Kist configuration without modifying it")
    subparsers.add_parser("diagnose", help="Read-only diagnostics and repair recommendations")
    fix_parser = subparsers.add_parser("fix", help="Apply explicit, non-credential repair actions")
    fix_parser.add_argument("--apply", action="store_true")
    fix_parser.add_argument("--force-hook", action="store_true")
    subparsers.add_parser("pre-commit-guard", help="Scan staged changes for plaintext secrets")

    profile_parser = subparsers.add_parser("profile", help="Explicit profile-key lifecycle operations")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command")
    create_parser = profile_subparsers.add_parser("create", help="Create a local profile key")
    create_parser.add_argument("name", type=str)
    create_parser.add_argument("--rotate", action="store_true")

    lock_parser = subparsers.add_parser("lock", help="Flatten and encrypt a YAML file into PostgreSQL")
    lock_parser.add_argument("file", type=str)
    lock_parser.add_argument("--prune", "-p", action="store_true")
    unlock_parser = subparsers.add_parser("unlock", help="Reconstruct YAML from encrypted PostgreSQL values")
    unlock_parser.add_argument("file", type=str)

    args = parser.parse_args()
    try:
        if args.clean:
            profile_name, password = get_profile_and_password(args.clean)
            git_clean_stream(profile_name=profile_name, master_password=password)
            return
        if args.smudge:
            profile_name, password = get_profile_and_password(args.smudge)
            git_smudge_stream(profile_name=profile_name, master_password=password)
            return
        if args.command == "init":
            if args.print_hook:
                print_hook()
            else:
                run_git_setup(force_hook=args.force_hook, install_hook=not args.no_hook)
            return
        if args.command == "status":
            sys.exit(run_status())
        if args.command == "diagnose":
            sys.exit(run_diagnose())
        if args.command == "fix":
            sys.exit(run_fix(apply=args.apply, force_hook=args.force_hook))
        if args.command == "pre-commit-guard":
            sys.exit(run_leak_guard())
        if args.command == "profile" and args.profile_command == "create":
            _require_tty_for_key_display()
            password = create_profile_key(args.name, rotate=args.rotate)
            print("A new profile key was created. Store it in an approved key manager now; it will not be displayed again.")
            print(password)
            return
        if args.command in {"lock", "unlock"}:
            target_file = resolve_secret_file_path(args.file)
            profile_name, password = get_profile_and_password(target_file)
            kist = Kist(profile_name=profile_name, master_password=password, scope=_scope_from_args(args))
            if args.command == "lock":
                if not os.path.isfile(target_file):
                    raise KistError(f"Secret file not found: {target_file}")
                with open(target_file, "r", encoding="utf-8") as handle:
                    locked_count, pruned_count = kist.lock_yaml(handle.read(), prune=args.prune)
                print(f"Locked {locked_count} secrets for {kist.scope.organization}/{kist.scope.project}/{profile_name}." + (f" Pruned {pruned_count}." if pruned_count else ""))
            else:
                print(kist.unlock_yaml(), end="")
            return
        parser.print_help()
    except KistError as exc:
        print(f"kist: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("kist: interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
