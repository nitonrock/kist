"""Command-line entry point for Kist."""

from __future__ import annotations

import argparse
import os
import sys

from kist.core import (
    Kist,
    KistError,
    KistScope,
    create_profile_key,
    get_profile_and_password,
    get_profile_password,
    remove_profile_key,
    resolve_secret_file_path,
)
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
    parser.add_argument("--profile", help="Explicit profile name override")
    parser.add_argument("--clean", type=str, metavar="FILE", help="Git clean filter entry point")
    parser.add_argument("--smudge", type=str, metavar="FILE", help="Git smudge filter entry point")
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="Configure non-destructive local Git integration")
    init_parser.add_argument("--force-hook", action="store_true")
    init_parser.add_argument("--no-hook", action="store_true")
    init_parser.add_argument("--print-hook", action="store_true")
    subparsers.add_parser("init-db", help="Initialize the Kist PostgreSQL database schema")
    subparsers.add_parser("status", help="Inspect Kist configuration without modifying it")
    subparsers.add_parser("diagnose", help="Read-only diagnostics and repair recommendations")
    fix_parser = subparsers.add_parser("fix", help="Apply explicit, non-credential repair actions")
    fix_parser.add_argument("--apply", action="store_true")
    fix_parser.add_argument("--force-hook", action="store_true")
    subparsers.add_parser("pre-commit-guard", help="Scan staged changes for plaintext secrets")

    profile_parser = subparsers.add_parser("profile", help="Explicit profile-key lifecycle operations")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command")
    create_parser = profile_subparsers.add_parser("create", help="Create a local profile key")
    create_parser.add_argument("name", type=str, help="Profile name")
    create_parser.add_argument("--rotate", action="store_true")

    delete_prof_parser = profile_subparsers.add_parser("delete", aliases=["rm"], help="Delete a profile and all its secrets from PostgreSQL")
    delete_prof_parser.add_argument("name", type=str, help="Profile name")
    delete_prof_parser.add_argument("--delete-key", "-k", action="store_true", help="Also delete local key file")
    delete_prof_parser.add_argument("--force", "-f", action="store_true", help="Bypass confirmation prompt")
    delete_prof_parser.add_argument("--yes", "-y", action="store_true", help="Automatically confirm prompts")

    rm_key_parser = profile_subparsers.add_parser("remove-key", aliases=["delete-key"], help="Remove local key file (~/.kist/pwd_<name>)")
    rm_key_parser.add_argument("name", type=str, help="Profile name")
    rm_key_parser.add_argument("--force", "-f", action="store_true", help="Bypass confirmation prompt")
    rm_key_parser.add_argument("--yes", "-y", action="store_true", help="Automatically confirm prompts")

    delete_parser = subparsers.add_parser("delete", aliases=["rm"], help="Delete a secret key from PostgreSQL")
    delete_parser.add_argument("key", type=str, help="Secret key to delete")
    delete_parser.add_argument("--profile", default=argparse.SUPPRESS, help="Explicit profile name override")
    delete_parser.add_argument("--force", "-f", action="store_true", help="Bypass confirmation prompt")
    delete_parser.add_argument("--yes", "-y", action="store_true", help="Automatically confirm prompts")

    lock_parser = subparsers.add_parser("lock", help="Flatten and encrypt a YAML file into PostgreSQL")
    lock_parser.add_argument("file", nargs="?", default=None, help="YAML secret file (defaults to active profile secrets file)")
    lock_parser.add_argument("--profile", default=argparse.SUPPRESS, help="Explicit profile name override")
    lock_parser.add_argument("--prune", "-p", action="store_true", help="Delete database secrets absent from YAML")
    lock_parser.add_argument("--allow-mismatch", action="store_true", help="Allow profile name to mismatch target file name")
    lock_parser.add_argument("--force", "-f", action="store_true", help="Force execution and bypass mismatch/destructive prompts")
    lock_parser.add_argument("--yes", "-y", action="store_true", help="Automatically confirm prompts")

    unlock_parser = subparsers.add_parser("unlock", help="Reconstruct YAML from encrypted PostgreSQL values")
    unlock_parser.add_argument("file", nargs="?", default=None, help="YAML secret file or destination (defaults to active profile secrets file)")
    unlock_parser.add_argument("--profile", default=argparse.SUPPRESS, help="Explicit profile name override")
    unlock_parser.add_argument("--allow-mismatch", action="store_true", help="Allow profile name to mismatch target file name")
    unlock_parser.add_argument("--force", "-f", action="store_true", help="Force execution and bypass mismatch checks")

    export_parser = subparsers.add_parser(
        "export", help="Copy a committed encrypted secret file out of Git for embedded/offline builds")
    export_parser.add_argument("file", help="Secret file in this repository, e.g. secrets/device.yaml")
    export_parser.add_argument("-o", "--output", default=None, help="Destination (default: <profile>.kist; '-' for stdout)")
    export_parser.add_argument("--rev", default="HEAD", help="Git revision to export from (default: HEAD)")
    export_parser.add_argument("--staged", action="store_true", help="Export the staged (index) version instead of a commit")
    export_parser.add_argument("--verify", action="store_true", help="Decrypt in memory with the profile key to check the export")
    export_parser.add_argument("--profile", default=None, help="Profile override (default: derived from file name)")
    export_parser.add_argument("--repository-id", default=None, help="KIST_REPOSITORY_ID used at commit time, for --verify")
    export_parser.add_argument("--strict", action="store_true", help="Fail if the working copy differs from the exported revision")

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
        if args.command == "init-db":
            kist = Kist(profile_name=args.profile or "default", scope=_scope_from_args(args))
            kist.init_db()
            print("Kist database schema initialized successfully.")
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
        if args.command == "profile" and args.profile_command in {"delete", "rm"}:
            bypass_prompt = getattr(args, "force", False) or getattr(args, "yes", False)
            if not bypass_prompt and sys.stdin.isatty():
                try:
                    prompt = (
                        f"Warning: Permanently delete profile '{args.name}' and all its secrets in database?\n"
                        f"Continue? [y/N]: "
                    )
                    response = input(prompt).strip().lower()
                    if response not in ("y", "yes"):
                        print("kist: profile deletion cancelled.", file=sys.stderr)
                        sys.exit(1)
                except (EOFError, KeyboardInterrupt):
                    print("\nkist: profile deletion cancelled.", file=sys.stderr)
                    sys.exit(130)

            kist = Kist(profile_name=args.name, scope=_scope_from_args(args))
            deleted = kist.delete_profile(args.name)
            msg = f"Deleted profile '{args.name}' for {kist.scope.organization}/{kist.scope.project} from database." if deleted else f"Profile '{args.name}' not found in database."
            if getattr(args, "delete_key", False):
                key_removed = remove_profile_key(args.name)
                msg += " Removed local key file." if key_removed else " Local key file not found."
            print(msg)
            return
        if args.command == "profile" and args.profile_command in {"remove-key", "delete-key"}:
            bypass_prompt = getattr(args, "force", False) or getattr(args, "yes", False)
            if not bypass_prompt and sys.stdin.isatty():
                try:
                    prompt = f"Warning: Remove local key file for profile '{args.name}'? [y/N]: "
                    response = input(prompt).strip().lower()
                    if response not in ("y", "yes"):
                        print("kist: key removal cancelled.", file=sys.stderr)
                        sys.exit(1)
                except (EOFError, KeyboardInterrupt):
                    print("\nkist: key removal cancelled.", file=sys.stderr)
                    sys.exit(130)

            if remove_profile_key(args.name):
                print(f"Removed local key file for profile '{args.name}'.")
            else:
                print(f"Local key file for profile '{args.name}' not found.", file=sys.stderr)
                sys.exit(1)
            return
        if args.command in {"delete", "rm"}:
            explicit_profile = getattr(args, "profile", None)
            profile_name = explicit_profile or os.getenv("KIST_PROFILE", "default")
            password = get_profile_password(profile_name)
            bypass_prompt = getattr(args, "force", False) or getattr(args, "yes", False)
            if not bypass_prompt and sys.stdin.isatty():
                try:
                    prompt = (
                        f"Warning: Deleting '{args.key}' from database may cause drift from Git secret files.\n"
                        f"Continue? [y/N]: "
                    )
                    response = input(prompt).strip().lower()
                    if response not in ("y", "yes"):
                        print("kist: delete operation cancelled.", file=sys.stderr)
                        sys.exit(1)
                except (EOFError, KeyboardInterrupt):
                    print("\nkist: delete operation cancelled.", file=sys.stderr)
                    sys.exit(130)

            kist = Kist(profile_name=profile_name, master_password=password, scope=_scope_from_args(args))
            if kist.delete(args.key):
                print(f"Deleted secret '{args.key}' for {kist.scope.organization}/{kist.scope.project}/{profile_name}.")
            else:
                print(f"Secret '{args.key}' not found for {kist.scope.organization}/{kist.scope.project}/{profile_name}.", file=sys.stderr)
                sys.exit(1)
            return
        if args.command == "export":
            from kist.export import export_envelope
            result = export_envelope(args.file, args.output, revision=args.rev, staged=args.staged,
                                     verify=args.verify, profile_name=args.profile,
                                     repository_id=args.repository_id, strict=args.strict)
            if result.working_tree_differs:
                message = (f"{result.git_path} has uncommitted changes; exported the {result.revision} version.")
                print(f"kist: warning: {message}", file=sys.stderr)
            target = "stdout" if result.output is None else str(result.output)
            print(f"Exported {result.git_path} ({result.revision}, profile '{result.profile}', "
                  f"{result.size} bytes, encrypted) to {target}.", file=sys.stderr)
            if result.verified_keys is not None:
                print(f"Verified: decrypts to {result.verified_keys} secrets.", file=sys.stderr)
            print(f"Read on device: Kist.from_file(<path>, git_path={result.git_path!r})", file=sys.stderr)
            return
        if args.command in {"lock", "unlock"}:
            explicit_profile = getattr(args, "profile", None)
            active_profile = explicit_profile or os.getenv("KIST_PROFILE", "default")

            if getattr(args, "file", None):
                target_file = resolve_secret_file_path(args.file)
                inferred_profile, inferred_password = get_profile_and_password(target_file)
            else:
                target_file = resolve_secret_file_path(None, profile=active_profile)
                inferred_profile, inferred_password = get_profile_and_password(target_file)

            if explicit_profile:
                profile_name = explicit_profile
                password = get_profile_password(profile_name)
                allow_mismatch = getattr(args, "allow_mismatch", False) or getattr(args, "force", False)
                if profile_name != inferred_profile and not allow_mismatch:
                    raise KistError(
                        f"Error: Profile/file mismatch detected.\n"
                        f"Profile '{profile_name}' does not match target file '{args.file or target_file}'.\n"
                        f"To prevent accidental data corruption or pruning, this operation is blocked."
                    )
            else:
                profile_name = inferred_profile
                password = inferred_password or get_profile_password(profile_name)

            kist = Kist(profile_name=profile_name, master_password=password, scope=_scope_from_args(args))
            if args.command == "lock":
                if not os.path.isfile(target_file):
                    raise KistError(f"Secret file not found: {target_file}")

                if getattr(args, "prune", False):
                    bypass_prompt = getattr(args, "force", False) or getattr(args, "yes", False)
                    if not bypass_prompt and sys.stdin.isatty():
                        try:
                            prompt = (
                                f"Warning: --prune will permanently delete database secrets "
                                f"for profile '{profile_name}'. Continue? [y/N]: "
                            )
                            response = input(prompt).strip().lower()
                            if response not in ("y", "yes"):
                                print("kist: prune operation cancelled.", file=sys.stderr)
                                sys.exit(1)
                        except (EOFError, KeyboardInterrupt):
                            print("\nkist: prune operation cancelled.", file=sys.stderr)
                            sys.exit(130)

                with open(target_file, "r", encoding="utf-8") as handle:
                    locked_count, pruned_count = kist.lock_yaml(handle.read(), prune=args.prune)
                print(f"Locked {locked_count} secrets for {kist.scope.organization}/{kist.scope.project}/{profile_name}." + (f" Pruned {pruned_count}." if pruned_count else ""))
            else:
                print(kist.unlock_yaml(), end="")
            return
        parser.print_help()
    except KistError as exc:
        msg = str(exc)
        if msg.startswith("Error:"):
            print(msg, file=sys.stderr)
        else:
            print(f"kist: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("kist: interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
