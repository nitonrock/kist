"""Readable `git diff` / `git log -p` for Kist files, locked checkouts and stable envelopes."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from kist import run_git_setup

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

DEVICE_PW = "device-example-password-0123456789abcd"
PAY_PW = "payments-example-password-0123456789ab"
KIST = f'"{sys.executable}" -m kist'


def git(*args, check=True, env=None):
    return subprocess.run(["git", *args], check=check, capture_output=True, text=True, errors="replace", env=env)


def blob(spec):
    return subprocess.run(["git", "cat-file", "blob", spec], check=True, capture_output=True).stdout


def env_without(*profiles):
    env = dict(os.environ)
    for profile in profiles:
        env.pop(f"KIST_PASSWORD_{profile.upper()}", None)
    return env


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("KIST_DIR", str(tmp_path / ".kist"))
    for name in list(os.environ):
        if name.startswith(("KIST_PASSWORD", "KIST_RETIRED")) or name in {
                "KIST_ORGANIZATION", "KIST_PROJECT", "KIST_REPOSITORY_ID", "KIST_FRESH_ENCRYPTION"}:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", DEVICE_PW)
    monkeypatch.setenv("KIST_PASSWORD_PAYMENTS", PAY_PW)
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.chdir(root)
    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "test")
    run_git_setup(install_hook=False)
    git("config", "filter.kist.clean", f"{KIST} --clean %f")
    git("config", "filter.kist.smudge", f"{KIST} --smudge %f")
    git("config", "diff.kist.textconv", f"{KIST} --textconv")
    git("config", "merge.kist.driver", f"{KIST} --merge %O %A %B %P %L")
    (root / "secrets").mkdir()
    (root / "secrets" / "device.yaml").write_text("cloud:\n  api_key: example-one\n")
    (root / "secrets" / "payments.yaml").write_text("stripe:\n  key: example-pay-one\n")
    git("add", "-A")
    git("commit", "-q", "-m", "a")
    return root


def edit(root, path, old, new):
    file = root / path
    file.write_text(file.read_text().replace(old, new))


def test_init_configures_diff_driver(repo):
    assert git("config", "diff.kist.textconv").stdout.strip()
    assert "secrets*.yaml filter=kist diff=kist" in (repo / ".gitattributes").read_text()
    assert git("check-attr", "diff", "--", "secrets/device.yaml").stdout.strip().endswith("kist")


def test_git_diff_and_log_show_plaintext_changes(repo):
    edit(repo, "secrets/device.yaml", "example-one", "example-two")
    diff = git("diff").stdout
    assert "-  api_key: example-one" in diff and "+  api_key: example-two" in diff
    git("commit", "-q", "-am", "b")
    log = git("log", "-p", "-1").stdout
    assert "-  api_key: example-one" in log and "+  api_key: example-two" in log
    assert "Binary files" not in log
    assert blob("HEAD:secrets/device.yaml").startswith(b"KIST")


def test_diff_without_password_shows_placeholder_and_does_not_fail(repo):
    edit(repo, "secrets/payments.yaml", "pay-one", "pay-two")
    git("commit", "-q", "-am", "b")
    proc = git("log", "-p", "-1", env=env_without("payments", "device"))
    assert proc.returncode == 0
    assert "no password for profile 'payments' opens it" in proc.stdout
    assert "example-pay" not in proc.stdout
    assert "+[kist: encrypted content" in proc.stdout       # fingerprints differ, so the change shows


def test_multi_team_developer_sees_only_own_profile(repo):
    edit(repo, "secrets/device.yaml", "example-one", "example-two")
    edit(repo, "secrets/payments.yaml", "pay-one", "pay-two")
    git("commit", "-q", "-am", "b")
    out = git("log", "-p", "-1", env=env_without("payments")).stdout
    assert "+  api_key: example-two" in out
    assert "example-pay" not in out
    assert "no password for profile 'payments'" in out


def test_unchanged_file_keeps_its_envelope(repo):
    blob = git("rev-parse", ":secrets/device.yaml").stdout
    os.utime(repo / "secrets" / "device.yaml")
    (repo / ".git" / "index").unlink()
    git("reset", "-q")
    assert git("status", "--porcelain").stdout == ""
    git("add", "-A")
    assert git("rev-parse", ":secrets/device.yaml").stdout == blob


def test_fresh_encryption_can_be_forced(repo, monkeypatch):
    blob = git("rev-parse", ":secrets/device.yaml").stdout
    monkeypatch.setenv("KIST_FRESH_ENCRYPTION", "1")
    git("add", "--renormalize", "secrets/device.yaml")
    assert git("rev-parse", ":secrets/device.yaml").stdout != blob


def test_locked_checkout_leaves_ciphertext_and_stays_clean(repo):
    (repo / "secrets" / "payments.yaml").unlink()
    proc = git("checkout", "--", "secrets/payments.yaml", env=env_without("payments"))
    assert "left encrypted" in proc.stderr
    assert (repo / "secrets" / "payments.yaml").read_bytes().startswith(b"KIST")
    blob = git("rev-parse", ":secrets/payments.yaml").stdout
    git("add", "-A", env=env_without("payments"))           # no password needed, nothing changes
    assert git("rev-parse", ":secrets/payments.yaml").stdout == blob
    assert git("status", "--porcelain", env=env_without("payments")).stdout == ""


def test_plaintext_blob_is_still_refused_at_checkout(repo):
    plain = subprocess.run(["git", "hash-object", "-w", "--no-filters", "--stdin"], input="cloud: {}\n",
                           capture_output=True, text=True, check=True).stdout.strip()
    git("update-index", "--cacheinfo", f"100644,{plain},secrets/device.yaml")
    (repo / "secrets" / "device.yaml").unlink()
    assert git("checkout", "--", "secrets/device.yaml", check=False).returncode != 0


def test_envelope_copied_to_another_path_is_refused(repo):
    envelope = blob(":secrets/payments.yaml")
    assert envelope.startswith(b"KIST")
    (repo / "secrets" / "secrets_payments.yaml").write_bytes(envelope)
    proc = git("add", "secrets/secrets_payments.yaml", check=False)
    assert proc.returncode != 0
    assert "different path or scope" in proc.stderr


def test_nested_secret_folders_are_encrypted(repo):
    (repo / "secrets" / "eu").mkdir()
    (repo / "secrets" / "eu" / "device.yaml").write_text("cloud:\n  region: example-eu\n")
    git("add", "secrets/eu/device.yaml")
    assert blob(":secrets/eu/device.yaml").startswith(b"KIST")


def test_legacy_attributes_are_upgraded_in_place(repo):
    (repo / ".gitattributes").write_text("secrets/*.yaml filter=kist\nsecrets*.yml filter=kist\n")
    run_git_setup(install_hook=False)
    text = (repo / ".gitattributes").read_text()
    assert "secrets/*.yaml filter=kist\n" not in text
    assert text.count("**/secrets/**/*.yaml filter=kist diff=kist") == 1
    assert text.count("secrets*.yml filter=kist diff=kist") == 1


def test_leak_guard_blocks_moved_envelope_until_renormalized(repo):
    git("mv", "secrets/device.yaml", "secrets/secrets_device.yaml")
    guard = subprocess.run([sys.executable, "-m", "kist", "pre-commit-guard"], capture_output=True, text=True)
    assert guard.returncode == 1
    assert "git add --renormalize secrets/secrets_device.yaml" in guard.stderr
    git("add", "--renormalize", "secrets/secrets_device.yaml")
    guard = subprocess.run([sys.executable, "-m", "kist", "pre-commit-guard"], capture_output=True, text=True)
    assert guard.returncode == 0, guard.stderr


def test_log_follow_decrypts_across_rename(repo):
    git("mv", "secrets/device.yaml", "secrets/secrets_device.yaml")
    git("add", "--renormalize", "secrets/secrets_device.yaml")
    git("commit", "-q", "-m", "mv")
    edit(repo, "secrets/secrets_device.yaml", "example-one", "example-two")
    git("commit", "-q", "-am", "c")
    log = git("log", "-p", "--follow", "--", "secrets/secrets_device.yaml").stdout
    assert "+  api_key: example-two" in log
    assert "+  api_key: example-one" in log                 # the original commit, at the old path


def test_init_decrypts_encrypted_working_files_when_password_available(repo, monkeypatch):
    """1. Encrypted file with the correct available profile password: decrypted on disk.
    8. Comments and formatting survive byte-for-byte.
    11. Git index and history remain unchanged.
    """
    custom_yaml = (
        "# Top level comment\n"
        "cloud:\n"
        "  # Service API key\n"
        "  api_key: example-secret-val\n"
        "\n"
        "  region: us-east-1\n"
    )
    (repo / "secrets" / "device.yaml").write_text(custom_yaml)
    git("add", "secrets/device.yaml")
    git("commit", "-q", "-m", "add device secret")
    head_before = git("rev-parse", "HEAD").stdout.strip()
    index_before = git("rev-parse", ":secrets/device.yaml").stdout.strip()

    # Simulate fresh clone or locked state: working file contains stored ciphertext blob
    envelope_data = blob(":secrets/device.yaml")
    assert envelope_data.startswith(b"KIST")
    (repo / "secrets" / "device.yaml").write_bytes(envelope_data)

    monkeypatch.setenv("KIST_PASSWORD_DEVICE", DEVICE_PW)
    run_git_setup(install_hook=False)

    decrypted_text = (repo / "secrets" / "device.yaml").read_text()
    assert decrypted_text == custom_yaml
    # Index and history remain unchanged
    assert git("rev-parse", "HEAD").stdout.strip() == head_before
    assert git("rev-parse", ":secrets/device.yaml").stdout.strip() == index_before


def test_init_already_plaintext_unchanged_and_not_rewritten(repo, monkeypatch):
    """2. Already-plaintext file, including local edits: unchanged byte-for-byte and not rewritten."""
    local_edit = "# Local uncommitted edits\ncloud:\n  api_key: local-draft\n"
    target = repo / "secrets" / "device.yaml"
    target.write_text(local_edit)
    mtime_before = target.stat().st_mtime_ns

    monkeypatch.setenv("KIST_PASSWORD_DEVICE", DEVICE_PW)
    run_git_setup(install_hook=False)

    assert target.read_text() == local_edit
    assert target.stat().st_mtime_ns == mtime_before


def test_init_encrypted_file_without_password_unchanged(repo, monkeypatch):
    """3. Encrypted file without an available password: unchanged, initialization continues."""
    envelope_data = blob(":secrets/device.yaml")
    target = repo / "secrets" / "device.yaml"
    target.write_bytes(envelope_data)

    monkeypatch.delenv("KIST_PASSWORD_DEVICE", raising=False)
    monkeypatch.delenv("KIST_PASSWORD", raising=False)
    run_git_setup(install_hook=False)

    assert target.read_bytes() == envelope_data


def test_init_incorrect_password_or_corrupted_envelope_warns_and_continues(repo, monkeypatch, capsys):
    """4. Incorrect password or corrupted envelope: unchanged, warning reported, other files still processed."""
    device_envelope = blob(":secrets/device.yaml")
    corrupt_envelope = device_envelope[:120] + b"\xff" * 40 + device_envelope[160:]
    (repo / "secrets" / "corrupt.yaml").write_bytes(corrupt_envelope)
    (repo / "secrets" / "device.yaml").write_bytes(device_envelope)

    monkeypatch.setenv("KIST_PASSWORD_CORRUPT", "some-password")
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", DEVICE_PW)

    run_git_setup(install_hook=False)
    err = capsys.readouterr().err
    assert "corrupt.yaml: decryption failed; leaving file encrypted" in err

    # Corrupt file remains untouched ciphertext
    assert (repo / "secrets" / "corrupt.yaml").read_bytes() == corrupt_envelope
    # Valid file is still decrypted
    assert "example-one" in (repo / "secrets" / "device.yaml").read_text()


def test_init_multiple_profiles_partial_passwords(repo, monkeypatch):
    """5. Multiple profiles with only some passwords available: only accessible files decrypted."""
    (repo / "secrets" / "device.yaml").write_bytes(blob(":secrets/device.yaml"))
    (repo / "secrets" / "payments.yaml").write_bytes(blob(":secrets/payments.yaml"))

    monkeypatch.setenv("KIST_PASSWORD_DEVICE", DEVICE_PW)
    monkeypatch.delenv("KIST_PASSWORD_PAYMENTS", raising=False)
    monkeypatch.delenv("KIST_PASSWORD", raising=False)

    run_git_setup(install_hook=False)

    assert "example-one" in (repo / "secrets" / "device.yaml").read_text()
    assert (repo / "secrets" / "payments.yaml").read_bytes().startswith(b"KIST")


def test_init_repeated_initialization_idempotent(repo, monkeypatch):
    """6. Repeated initialization: no further changes to already-decrypted files."""
    (repo / "secrets" / "device.yaml").write_bytes(blob(":secrets/device.yaml"))
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", DEVICE_PW)

    run_git_setup(install_hook=False)
    target = repo / "secrets" / "device.yaml"
    assert "example-one" in target.read_text()
    mtime_first = target.stat().st_mtime_ns

    run_git_setup(install_hook=False)
    assert "example-one" in target.read_text()
    assert target.stat().st_mtime_ns == mtime_first


def test_init_password_becomes_available_between_runs(repo, monkeypatch):
    """7. A password becomes available between initialization runs: the next run decrypts the corresponding file."""
    (repo / "secrets" / "device.yaml").write_bytes(blob(":secrets/device.yaml"))
    (repo / "secrets" / "payments.yaml").write_bytes(blob(":secrets/payments.yaml"))

    # Run 1: only DEVICE_PW is available
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", DEVICE_PW)
    monkeypatch.delenv("KIST_PASSWORD_PAYMENTS", raising=False)
    monkeypatch.delenv("KIST_PASSWORD", raising=False)
    run_git_setup(install_hook=False)

    assert "example-one" in (repo / "secrets" / "device.yaml").read_text()
    assert (repo / "secrets" / "payments.yaml").read_bytes().startswith(b"KIST")

    # Run 2: PAY_PW becomes available
    monkeypatch.setenv("KIST_PASSWORD_PAYMENTS", PAY_PW)
    run_git_setup(install_hook=False)

    assert "example-one" in (repo / "secrets" / "device.yaml").read_text()
    assert "example-pay-one" in (repo / "secrets" / "payments.yaml").read_text()


def test_init_working_tree_ciphertext_differs_from_committed_version(repo, monkeypatch):
    """9. Current working-file ciphertext differs from the indexed or committed version:
    the working-file content is what gets decrypted.
    """
    from kist.core import encrypt_envelope, git_context

    different_plaintext = b"cloud:\n  api_key: working-tree-uncommitted-version\n"
    context = git_context("device", "secrets/device.yaml")
    different_envelope = encrypt_envelope(different_plaintext, DEVICE_PW, context)

    (repo / "secrets" / "device.yaml").write_bytes(different_envelope)
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", DEVICE_PW)

    run_git_setup(install_hook=False)

    assert (repo / "secrets" / "device.yaml").read_bytes() == different_plaintext


def test_init_concurrent_modification_safeguard(repo, monkeypatch, capsys):
    """10. Write failure or concurrent file modification: no partial overwrite or loss of the original content."""
    original_envelope = blob(":secrets/device.yaml")
    target = repo / "secrets" / "device.yaml"
    target.write_bytes(original_envelope)

    # Simulate modification during init by altering file right after first read
    real_read_bytes = Path.read_bytes
    reads_count = 0

    def mock_read_bytes(self):
        nonlocal reads_count
        data = real_read_bytes(self)
        if self == target:
            reads_count += 1
            if reads_count == 2:
                # Second read (verification check before replace): return modified bytes
                return original_envelope + b"# concurrent modification"
        return data

    monkeypatch.setattr(Path, "read_bytes", mock_read_bytes)
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", DEVICE_PW)

    run_git_setup(install_hook=False)
    err = capsys.readouterr().err
    assert "file changed during initialization; skipping" in err
    assert target.read_bytes() == original_envelope


def test_init_symlinks_ignored(repo, monkeypatch):
    """Do not follow symlinks or modify files outside scope."""
    outside_file = repo.parent / "outside_secrets.yaml"
    outside_file.write_bytes(blob(":secrets/device.yaml"))
    symlink_path = repo / "secrets" / "symlink_device.yaml"
    symlink_path.symlink_to(outside_file)

    monkeypatch.setenv("KIST_PASSWORD_SYMLINK_DEVICE", DEVICE_PW)
    run_git_setup(install_hook=False)

    assert symlink_path.is_symlink()
    assert outside_file.read_bytes().startswith(b"KIST")


def test_init_refresh_preserves_staged_and_unstaged_changes(repo, monkeypatch):
    from kist.git import decrypt_working_secret_files

    head_before = git("rev-parse", "HEAD").stdout
    (repo / "staged.txt").write_text("staged example\n")
    git("add", "staged.txt")
    (repo / "staged.txt").write_text("unstaged example\n")
    index_before = git("ls-files", "--stage", "-z").stdout
    target = repo / "secrets" / "device.yaml"
    target.write_bytes(blob(":secrets/device.yaml"))

    monkeypatch.setenv("KIST_PROFILE", "payments")
    result = decrypt_working_secret_files(repo)

    assert "secrets/device.yaml" in result
    assert target.read_bytes() == b"cloud:\n  api_key: example-one\n"
    assert git("status", "--porcelain", "--", "secrets/").stdout == ""
    assert git("ls-files", "--stage", "-z").stdout == index_before
    assert git("rev-parse", "HEAD").stdout == head_before
    assert blob(":staged.txt") == b"staged example\n"
    assert (repo / "staged.txt").read_bytes() == b"unstaged example\n"


def test_refresh_metadata_never_passes_positional_paths(tmp_path, monkeypatch):
    from types import SimpleNamespace

    import kist.git as git_module

    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=1, stderr=b"")

    monkeypatch.setattr(git_module.subprocess, "run", run)
    git_module._refresh_index_metadata(tmp_path)
    assert calls[0][0] == ["git", "update-index", "--refresh"]
    assert calls[0][1]["cwd"] == tmp_path


def test_init_does_not_refresh_when_no_file_was_decrypted(repo, monkeypatch):
    import kist.git as git_module

    def unexpected_refresh(root):
        pytest.fail("Plaintext files must not trigger an index refresh")

    monkeypatch.setattr(git_module, "_refresh_index_metadata", unexpected_refresh)
    assert git_module.decrypt_working_secret_files(repo) == []

@pytest.mark.parametrize("local_changes", [False, True])
def test_init_fresh_clone_immediately_clean_without_staging(repo, monkeypatch, local_changes):
    clone = repo.parent / "fresh-clone"
    git("clone", "--quiet", str(repo), str(clone))
    monkeypatch.chdir(clone)
    device = clone / "secrets/device.yaml"
    payments = clone / "secrets/payments.yaml"
    assert device.read_bytes().startswith(b"KIST")
    assert payments.read_bytes().startswith(b"KIST")
    monkeypatch.delenv("KIST_PASSWORD_PAYMENTS", raising=False)
    monkeypatch.delenv("KIST_PASSWORD", raising=False)
    if local_changes:
        (clone / "draft.txt").write_text("staged draft\n")
        git("add", "draft.txt")
        (clone / "draft.txt").write_text("unstaged draft\n")
    index_before = git("ls-files", "--stage", "-z").stdout
    result = subprocess.run(
        [sys.executable, "-c",
         "from kist import run_git_setup; run_git_setup(install_hook=False)"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    status = git("status", "--porcelain=v2", "--untracked-files=no").stdout
    assert "secrets/device.yaml" not in status
    assert "secrets/payments.yaml" not in status
    assert device.read_bytes() == b"cloud:\n  api_key: example-one\n"
    assert payments.read_bytes().startswith(b"KIST")
    assert git("ls-files", "--stage", "-z").stdout == index_before
    if local_changes:
        assert "draft.txt" in status
        assert blob(":draft.txt") == b"staged draft\n"
        assert (clone / "draft.txt").read_bytes() == b"unstaged draft\n"
    run_git_setup(install_hook=False)
    assert "secrets/" not in git("status", "--porcelain=v2").stdout
    assert git("ls-files", "--stage", "-z").stdout == index_before


def test_init_checkout_preserves_staged_secret_and_local_plaintext_edit(repo):
    from kist.git import decrypt_working_secret_files

    target = repo / "secrets/device.yaml"
    staged = b"cloud:\n  api_key: staged-example-value\n"
    target.write_bytes(staged)
    git("add", "secrets/device.yaml")
    target.write_bytes(blob(":secrets/device.yaml"))
    other = repo / "secrets/payments.yaml"
    edited = b"stripe:\n  key: local-uncommitted-example\n"
    other.write_bytes(edited)
    before = git("ls-files", "--stage", "-z").stdout
    decrypt_working_secret_files(repo)
    status = git("status", "--porcelain=v2").stdout
    assert target.read_bytes() == staged
    assert other.read_bytes() == edited
    assert git("ls-files", "--stage", "-z").stdout == before
    assert "secrets/payments.yaml" in status
    assert not list((repo / "secrets").glob(".kist-init-backup-*"))


def test_init_checkout_failure_retains_original_ciphertext(repo, monkeypatch):
    import kist.git as git_module

    target = repo / "secrets/device.yaml"
    original = blob(":secrets/device.yaml")
    target.write_bytes(original)
    before = git("ls-files", "--stage", "-z").stdout
    real_run = subprocess.run

    def run(command, **kwargs):
        if command[:2] == ["git", "checkout-index"]:
            return subprocess.CompletedProcess(command, 1, b"", b"test failure")
        return real_run(command, **kwargs)

    monkeypatch.setattr(git_module.subprocess, "run", run)
    git_module.decrypt_working_secret_files(repo)
    assert target.read_bytes() == original
    assert git("ls-files", "--stage", "-z").stdout == before
    assert not list((repo / "secrets").glob(".kist-init-backup-*"))

