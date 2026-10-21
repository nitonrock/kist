"""0.2.5 safety features: merge driver, password check, strict guard, filter path, status, share/show."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from kist import run_git_setup
from kist.core import encrypt_envelope, git_context, is_kist_envelope
from kist.git import kist_command, run_leak_guard
from kist.share import share_file, show_file
from kist.status import run_status, setup_hint

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

DEVICE_PW = "device-example-password-0123456789abcd"
OTHER_PW = "other-example-password-0123456789abcde"
KIST = f'"{sys.executable}" -m kist'


def git(*args, check=True, env=None):
    return subprocess.run(["git", *args], check=check, capture_output=True, text=True, errors="replace", env=env)


def blob(spec):
    return subprocess.run(["git", "cat-file", "blob", spec], check=True, capture_output=True).stdout


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("KIST_DIR", str(tmp_path / ".kist"))
    for name in list(os.environ):
        if name.startswith(("KIST_PASSWORD", "KIST_RETIRED")) or name in {
                "KIST_ORGANIZATION", "KIST_PROJECT", "KIST_REPOSITORY_ID", "KIST_FRESH_ENCRYPTION",
                "KIST_ALLOW_PASSWORD_CHANGE", "KIST_PROFILE"}:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", DEVICE_PW)
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.chdir(root)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "test")
    run_git_setup(install_hook=False)
    git("config", "filter.kist.clean", f"{KIST} --clean %f")
    git("config", "filter.kist.smudge", f"{KIST} --smudge %f")
    git("config", "diff.kist.textconv", f"{KIST} --textconv")
    git("config", "merge.kist.driver", f"{KIST} --merge %O %A %B %P %L")
    (root / "secrets").mkdir()
    (root / "secrets" / "device.yaml").write_text("# device secrets\na: one\nb: two\nc: three\nd: four\ne: five\n")
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    return root


def edit(root, old, new, path="secrets/device.yaml"):
    file = root / path
    file.write_text(file.read_text().replace(old, new))


# --- merge driver -----------------------------------------------------------

def test_init_adds_merge_driver_and_attribute(repo):
    assert git("check-attr", "merge", "--", "secrets/device.yaml").stdout.strip().endswith("kist")
    assert "--merge %O %A %B %P %L" in git("config", "merge.kist.driver").stdout


def test_merge_of_different_lines_is_clean_and_stays_encrypted(repo):
    git("checkout", "-q", "-b", "feature")
    edit(repo, "a: one", "a: ONE")
    git("commit", "-q", "-am", "feature")
    git("checkout", "-q", "main")
    edit(repo, "e: five", "e: FIVE")
    git("commit", "-q", "-am", "main")
    result = git("merge", "-q", "--no-edit", "feature", check=False)
    assert result.returncode == 0, result.stderr
    text = (repo / "secrets" / "device.yaml").read_text()
    assert "a: ONE" in text and "e: FIVE" in text and "<<<<<<<" not in text
    assert is_kist_envelope(blob("HEAD:secrets/device.yaml"))
    assert git("status", "--porcelain").stdout.strip() == ""


def test_merge_conflict_shows_plaintext_markers(repo):
    git("checkout", "-q", "-b", "feature")
    edit(repo, "c: three", "c: theirs")
    git("commit", "-q", "-am", "feature")
    git("checkout", "-q", "main")
    edit(repo, "c: three", "c: ours")
    git("commit", "-q", "-am", "main")
    result = git("merge", "--no-edit", "feature", check=False)
    assert result.returncode != 0
    text = (repo / "secrets" / "device.yaml").read_text()
    assert "<<<<<<< ours" in text and "c: ours" in text and "c: theirs" in text and ">>>>>>> theirs" in text
    assert "# device secrets" in text
    # Resolve and commit: the stored version is encrypted again.
    (repo / "secrets" / "device.yaml").write_text(text.split("<<<<<<<")[0] + "c: resolved\nd: four\ne: five\n")
    git("add", "secrets/device.yaml")
    git("commit", "-q", "--no-edit")
    assert is_kist_envelope(blob("HEAD:secrets/device.yaml"))


def test_merge_without_password_reports_conflict(repo, tmp_path, monkeypatch, capsys):
    from kist.git import git_merge
    files = []
    for name in ("base", "ours", "theirs"):
        path = tmp_path / name
        path.write_bytes(blob("HEAD:secrets/device.yaml"))
        files.append(str(path))
    before = Path(files[1]).read_bytes()
    monkeypatch.delenv("KIST_PASSWORD_DEVICE")
    assert git_merge(*files, "secrets/device.yaml") == 1
    assert "no password for profile 'device'" in capsys.readouterr().err
    assert Path(files[1]).read_bytes() == before


# --- password consistency check --------------------------------------------

def test_commit_with_a_different_password_is_refused(repo):
    edit(repo, "a: one", "a: changed")
    env = dict(os.environ, KIST_PASSWORD_DEVICE=OTHER_PW)
    result = git("add", "secrets/device.yaml", check=False, env=env)
    assert result.returncode != 0
    assert "does not open the version already in Git" in result.stderr
    assert "KIST_PASSWORD_DEVICE" in result.stderr
    assert DEVICE_PW not in result.stderr and OTHER_PW not in result.stderr


def test_password_change_allowed_explicitly(repo):
    edit(repo, "a: one", "a: changed")
    env = dict(os.environ, KIST_PASSWORD_DEVICE=OTHER_PW, KIST_ALLOW_PASSWORD_CHANGE="1")
    git("add", "secrets/device.yaml", env=env)
    git("commit", "-q", "-m", "new password", env=env)
    assert is_kist_envelope(blob("HEAD:secrets/device.yaml"))


def test_retired_password_content_moves_to_current_password(repo, monkeypatch):
    # The committed file opens only with a password that has since been retired.
    monkeypatch.setenv("KIST_RETIRED_PASSWORDS_DEVICE", DEVICE_PW)
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", OTHER_PW)
    edit(repo, "a: one", "a: changed")
    git("add", "secrets/device.yaml")
    assert is_kist_envelope(blob(":secrets/device.yaml"))


def test_normal_edit_with_right_password_still_works(repo):
    edit(repo, "a: one", "a: changed")
    git("add", "secrets/device.yaml")
    git("commit", "-q", "-m", "edit")
    assert "a: changed" in git("show", "HEAD:secrets/device.yaml", "--textconv").stdout


# --- strict guard -----------------------------------------------------------

def test_guard_blocks_plaintext_under_custom_attribute_pattern(repo, capsys):
    with open(".gitattributes", "a") as handle:
        handle.write("config/*.private filter=kist diff=kist\n")
    Path("config").mkdir()
    Path("config/app.private").write_bytes(b"token = abc\n")
    # Stage the plaintext without the filter, as an unconfigured clone would.
    sha = subprocess.run(["git", "hash-object", "-w", "--no-filters", "config/app.private"],
                         check=True, capture_output=True, text=True).stdout.strip()
    git("update-index", "--add", "--cacheinfo", f"100644,{sha},config/app.private")
    assert run_leak_guard() == 1
    assert "config/app.private" in capsys.readouterr().err


def test_guard_blocks_malformed_envelope(repo, capsys):
    envelope = bytearray(encrypt_envelope(b"a: 1\n", DEVICE_PW, git_context("device", "secrets/device.yaml")))
    envelope[4] = 9  # unsupported version
    Path("bad.bin").write_bytes(bytes(envelope))
    sha = subprocess.run(["git", "hash-object", "-w", "--no-filters", "bad.bin"],
                         check=True, capture_output=True, text=True).stdout.strip()
    git("update-index", "--cacheinfo", f"100644,{sha},secrets/device.yaml")
    assert run_leak_guard() == 1
    assert "not a valid Kist envelope" in capsys.readouterr().err


# --- absolute filter path ---------------------------------------------------

def _fake_kist(directory: Path, venv: bool) -> Path:
    bin_dir = directory / "bin"
    bin_dir.mkdir(parents=True)
    if venv:
        (directory / "pyvenv.cfg").write_text("home = /usr\n")
    executable = bin_dir / "kist"
    executable.write_text("#!/bin/sh\necho 'kist 0.0.0'\n")
    executable.chmod(0o755)
    return executable


def test_init_records_project_venv(repo, monkeypatch):
    executable = _fake_kist(repo / ".venv", venv=True)
    monkeypatch.setattr(sys, "argv", [str(executable), "init"])
    command, location, warn = kist_command()
    assert command == executable.as_posix() and location == "project virtual environment" and not warn


def test_init_records_global_install(repo, tmp_path, monkeypatch):
    executable = _fake_kist(tmp_path / "local", venv=False)
    monkeypatch.setattr(sys, "argv", [str(executable), "init"])
    command, location, warn = kist_command()
    assert command == executable.as_posix() and location == "global install" and not warn


def test_init_warns_for_venv_outside_repository(repo, tmp_path, monkeypatch):
    executable = _fake_kist(tmp_path / "elsewhere-venv", venv=True)
    monkeypatch.setattr(sys, "argv", [str(executable), "init"])
    _, location, warn = kist_command()
    assert warn and "outside this repository" in location


def test_init_writes_absolute_path_into_git_config(repo, monkeypatch, capsys):
    executable = _fake_kist(repo / ".venv", venv=True)
    monkeypatch.setattr(sys, "argv", [str(executable), "init"])
    run_git_setup(install_hook=False)
    assert git("config", "filter.kist.clean").stdout.strip() == f"{executable.as_posix()} --clean %f"
    assert git("config", "merge.kist.driver").stdout.strip().startswith(executable.as_posix())
    assert "project virtual environment" in capsys.readouterr().out


def test_kist_path_must_be_executable(repo):
    from kist.core import KistError
    with pytest.raises(KistError):
        kist_command(str(repo / "missing" / "kist"))


# --- status and hint --------------------------------------------------------

def test_status_reports_missing_filter_command(repo, capsys):
    git("config", "filter.kist.clean", "/nonexistent/.venv/bin/kist --clean %f")
    assert run_status() == 1
    out = capsys.readouterr().out
    assert "NOT FOUND: /nonexistent/.venv/bin/kist" in out and "uv sync" in out
    assert "filter command not found" in setup_hint()


def test_status_flags_committed_file_that_no_password_opens(repo, monkeypatch, capsys):
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", OTHER_PW)
    run_status()
    out = capsys.readouterr().out
    assert "device: secrets/device.yaml; password source: environment (KIST_PASSWORD_DEVICE)" in out
    assert "opens committed version: FAILED" in out


def test_status_ok_for_committed_file(repo, capsys):
    run_status()
    assert "opens committed version: OK" in capsys.readouterr().out


def test_setup_hint_for_unconfigured_clone(repo):
    git("config", "--unset", "filter.kist.clean")
    assert "not configured in this clone" in setup_hint()


def test_setup_hint_silent_when_configured(repo):
    assert setup_hint() is None


# --- share / show -----------------------------------------------------------

def test_share_and_show_roundtrip(repo, tmp_path):
    result = share_file("secrets/device.yaml")
    assert result.output == tmp_path / "device.yaml.kist"
    data = result.output.read_bytes()
    assert is_kist_envelope(data) and b"device secrets" not in data
    assert oct(result.output.stat().st_mode & 0o777) == "0o600"
    plaintext, profile = show_file(str(result.output))
    assert profile == "device" and plaintext.startswith(b"# device secrets")


def test_shared_file_opens_outside_any_repository(repo, tmp_path, monkeypatch):
    result = share_file("secrets/device.yaml", str(tmp_path / "for-alice.kist"))
    elsewhere = tmp_path / "alice"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("KIST_REPOSITORY_ID", "another-repository")
    plaintext, profile = show_file(str(result.output), profile_name="device")
    assert profile == "device" and b"a: one" in plaintext


def test_share_finds_profile_from_local_password_file(repo, tmp_path, monkeypatch):
    result = share_file("secrets/device.yaml", str(tmp_path / "renamed.kist"))
    kist_dir = tmp_path / ".kist"
    kist_dir.mkdir(mode=0o700, exist_ok=True)
    (kist_dir / "pwd_device").write_text(DEVICE_PW)
    (kist_dir / "pwd_device").chmod(0o600)
    monkeypatch.delenv("KIST_PASSWORD_DEVICE")
    plaintext, profile = show_file(str(result.output))
    assert profile == "device" and b"a: one" in plaintext


def test_share_includes_uncommitted_edits_and_says_so(repo):
    edit(repo, "a: one", "a: draft")
    result = share_file("secrets/device.yaml")
    assert result.uncommitted
    assert b"a: draft" in show_file(str(result.output))[0]


def test_share_refuses_destination_inside_repository(repo):
    from kist.core import KistError
    with pytest.raises(KistError, match="inside this repository"):
        share_file("secrets/device.yaml", "device.kist")


def test_share_refuses_to_overwrite(repo, tmp_path):
    from kist.core import KistError
    share_file("secrets/device.yaml")
    with pytest.raises(KistError, match="already exists"):
        share_file("secrets/device.yaml")
    share_file("secrets/device.yaml", force=True)


def test_show_with_wrong_password_fails_without_leaking(repo, monkeypatch):
    from kist.core import KistError
    result = share_file("secrets/device.yaml")
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", OTHER_PW)
    with pytest.raises(KistError, match="does not open it"):
        show_file(str(result.output))


def test_show_reads_a_repository_envelope(repo, tmp_path):
    exported = tmp_path / "head.bin"
    exported.write_bytes(blob("HEAD:secrets/device.yaml"))
    plaintext, profile = show_file(str(exported), profile_name="device")
    assert profile == "device" and b"a: one" in plaintext


def test_show_refuses_plaintext(repo):
    from kist.core import KistError
    with pytest.raises(KistError, match="already readable"):
        show_file("secrets/device.yaml")


def test_cli_share_and_show(repo, tmp_path):
    env = dict(os.environ)
    shared = subprocess.run([sys.executable, "-m", "kist", "share", "secrets/device.yaml"],
                            capture_output=True, text=True, env=env)
    assert shared.returncode == 0, shared.stderr
    assert "kist show device.yaml.kist" in shared.stdout
    shown = subprocess.run([sys.executable, "-m", "kist", "show", str(tmp_path / "device.yaml.kist")],
                           capture_output=True, text=True, env=env)
    assert shown.returncode == 0 and "a: one" in shown.stdout
