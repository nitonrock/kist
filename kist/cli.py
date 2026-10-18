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


def _run_retired_keys(args: argparse.Namespace) -> None:
    from kist.core import key_history_enabled, retired_profile_key_files, _validate_profile_name
    profile = _validate_profile_name(args.name)
    files = retired_profile_key_files(profile)
    env_name = f"KIST_RETIRED_PASSWORDS_{profile.upper()}"
    env_count = len([l for l in os.getenv(env_name, "").splitlines() if l.strip()])
    if not args.delete:
        state = "on" if key_history_enabled() else "off (KIST_KEY_HISTORY)"
        print(f"Retired keys for profile '{profile}' (key history {state}), newest first:")
        for path in files:
            print(f"  {path}")
        if env_count:
            print(f"  {env_count} from {env_name}")
        if not files and not env_count:
            print("  none")
        return
    doomed = files[max(args.keep, 0):]
    if not doomed:
        print("Nothing to delete.")
        return
    if not args.yes:
        if not sys.stdin.isatty():
            raise KistError("Refusing to delete keys without confirmation; pass --yes in non-interactive use.")
        print("Commits encrypted only with these keys will no longer open on this machine:")
        for path in doomed:
            print(f"  {path}")
        if input("Delete them? [y/N]: ").strip().lower() not in ("y", "yes"):
            print("kist: cancelled.", file=sys.stderr)
            sys.exit(1)
    for path in doomed:
        path.unlink()
    print(f"Deleted {len(doomed)} retired key(s) for profile '{profile}'.")


def _run_rotate(args: argparse.Namespace) -> None:
    from kist.rotate import plan_rotation, restage_git_with_current_key, rotate_profile

    if args.git_only:
        files = restage_git_with_current_key(args.name)
        print(f"Re-encrypted and staged {len(files)} file(s) with the current key for profile '{args.name}'.")
        for path in files:
            print(f"  {path}")
        return

    scope = _scope_from_args(args)
    use_db = False if args.skip_db else None
    plan, _ = plan_rotation(args.name, scope=scope, use_database=use_db, use_git=not args.skip_git,
                            rewrap_only=args.rewrap_only)
    mode = "rewrap key bundle only" if args.rewrap_only else "generate new keys and re-encrypt every secret"
    print(f"Rotation plan for profile '{plan.profile}' ({scope.organization}/{scope.project}):")
    print(f"  Current key:  from {'~/.kist/pwd_' + plan.profile if plan.password_source == 'file' else plan.password_source} (verified)")
    if plan.database:
        print(f"  PostgreSQL:   {plan.database_secrets} secrets, {mode}")
    else:
        print("  PostgreSQL:   skipped" if args.skip_db else "  PostgreSQL:   no data for this profile")
    if plan.git_files:
        print(f"  Git:          re-encrypt and stage {len(plan.git_files)} file(s): {', '.join(plan.git_files)}")
    else:
        print("  Git:          skipped" if args.skip_git else "  Git:          no secret files for this profile")
    print(f"  Local key:    write new ~/.kist/pwd_{plan.profile}, keep the old one as a backup")
    if args.dry_run:
        print("Dry run: nothing changed.")
        return
    if not plan.database and not plan.git_files:
        raise KistError(f"Nothing to rotate for profile '{plan.profile}'.")

    new_password = None
    if args.new_password_stdin:
        new_password = sys.stdin.readline().rstrip("\n")
        if not new_password:
            raise KistError("No password received on stdin.")
    if not args.yes:
        if not sys.stdin.isatty() or args.new_password_stdin:
            raise KistError("Refusing to rotate without confirmation; pass --yes in non-interactive use.")
        try:
            answer = input("Rotate now? Running services will need the new password. [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nkist: rotation cancelled.", file=sys.stderr)
            sys.exit(130)
        if answer not in ("y", "yes"):
            print("kist: rotation cancelled.", file=sys.stderr)
            sys.exit(1)
    if args.show_password:
        _require_tty_for_key_display()

    result = rotate_profile(args.name, new_password=new_password, scope=scope, use_database=use_db,
                            use_git=not args.skip_git, rewrap_only=args.rewrap_only, log=print)
    if args.show_password:
        print("New profile password (shown once):")
        print(get_profile_password(args.name, allow_env=False))
    print("\nRotation complete. Still to do:")
    for i, item in enumerate(result.checklist, 1):
        print(f"  {i}. {item}")


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

    rotate_parser = profile_subparsers.add_parser(
        "rotate", help="Rotate a profile password: new keys in PostgreSQL, re-encrypted Git files, new local key")
    rotate_parser.add_argument("name", type=str, help="Profile name")
    rotate_parser.add_argument("--dry-run", action="store_true", help="Show what would change and validate the current key")
    rotate_parser.add_argument("--yes", "-y", action="store_true", help="Do not ask for confirmation (required when not interactive)")
    rotate_parser.add_argument("--rewrap-only", action="store_true",
                               help="Only rewrap the database key bundle; keep data keys (faster, weaker)")
    rotate_parser.add_argument("--skip-db", action="store_true", help="Do not touch PostgreSQL")
    rotate_parser.add_argument("--skip-git", action="store_true", help="Do not re-encrypt Git secret files")
    rotate_parser.add_argument("--git-only", action="store_true",
                               help="Recovery: re-encrypt Git files with the current key, change nothing else")
    rotate_parser.add_argument("--new-password-stdin", action="store_true",
                               help="Read the new password from stdin instead of generating one")
    rotate_parser.add_argument("--show-password", action="store_true",
                               help="Print the new password once (interactive terminals only)")

    retired_parser = profile_subparsers.add_parser(
        "retired-keys", help="List or delete retired keys kept by rotation (used to read older content)")
    retired_parser.add_argument("name", type=str, help="Profile name")
    retired_parser.add_argument("--delete", action="store_true", help="Delete retired key files for this profile")
    retired_parser.add_argument("--keep", type=int, default=0, metavar="N",
                                help="With --delete, keep the N most recent retired keys")
    retired_parser.add_argument("--yes", "-y", action="store_true", help="Do not ask for confirmation")

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
        if args.command == "profile" and args.profile_command == "retired-keys":
            _run_retired_keys(args)
            return
        if args.command == "profile" and args.profile_command == "rotate":
            _run_rotate(args)
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
