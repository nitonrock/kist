"""Readable `git diff` / `git log -p` for Kist files, locked checkouts and stable envelopes."""

import os
import shutil
import subprocess
import sys

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
