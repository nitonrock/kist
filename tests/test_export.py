"""Tests for `kist export` (embedded/offline build export)."""

import os
import shutil
import subprocess
import sys

import pytest

from kist import FileKist, main
from kist.core import KistError
from kist.export import export_envelope

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

PASSWORD = "export-example-password-0123456789abcd"
YAML = "cloud:\n  api_key: example-value\nmqtt:\n  port: 8883\n"


def git(*args, **kwargs):
    return subprocess.run(["git", *args], check=True, capture_output=True, **kwargs)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("KIST_DIR", str(tmp_path / ".kist"))
    for name in list(os.environ):
        if name.startswith("KIST_PASSWORD") or name in {"KIST_ORGANIZATION", "KIST_PROJECT", "KIST_REPOSITORY_ID"}:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", PASSWORD)
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.chdir(root)
    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "test")
    from kist import run_git_setup
    run_git_setup(install_hook=False)
    cmd = f'"{sys.executable}" -m kist'
    git("config", "filter.kist.clean", f"{cmd} --clean %f")
    git("config", "filter.kist.smudge", f"{cmd} --smudge %f")
    (root / "secrets").mkdir()
    (root / "secrets" / "device.yaml").write_text(YAML)
    git("add", "secrets/device.yaml")
    git("commit", "-q", "-m", "secrets")
    return root


def test_export_default_output_and_read_back(repo):
    result = export_envelope("secrets/device.yaml")
    assert result.output.name == "device.kist"
    assert result.git_path == "secrets/device.yaml"
    assert result.profile == "device"
    data = result.output.read_bytes()
    assert data.startswith(b"KIST")
    assert b"example-value" not in data
    assert FileKist(result.output, git_path=result.git_path).get("cloud.api_key") == "example-value"


def test_export_from_subdirectory_uses_repo_relative_path(repo, tmp_path):
    os.chdir(repo / "secrets")
    out = tmp_path / "build" / "fw" / "dev.kist"
    result = export_envelope("device.yaml", str(out))
    assert result.git_path == "secrets/device.yaml"
    assert out.is_file()
    assert oct(out.stat().st_mode & 0o777) == "0o644"


def test_export_verify(repo, tmp_path):
    result = export_envelope("secrets/device.yaml", str(tmp_path / "d.kist"), verify=True)
    assert result.verified_keys == 2


def test_verify_fails_with_wrong_key(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", "a-different-password-0123456789abcd")
    with pytest.raises(Exception, match="(?i)password|ciphertext"):
        export_envelope("secrets/device.yaml", str(tmp_path / "d.kist"), verify=True)


def test_export_older_revision(repo, tmp_path):
    (repo / "secrets" / "device.yaml").write_text("cloud:\n  api_key: rotated-value\n")
    git("add", "secrets/device.yaml")
    git("commit", "-q", "-m", "rotate")
    old = export_envelope("secrets/device.yaml", str(tmp_path / "old.kist"), revision="HEAD~1")
    new = export_envelope("secrets/device.yaml", str(tmp_path / "new.kist"))
    assert FileKist(old.output, git_path=old.git_path).get("cloud.api_key") == "example-value"
    assert FileKist(new.output, git_path=new.git_path).get("cloud.api_key") == "rotated-value"


def test_uncommitted_changes_warn_or_fail_strict(repo, tmp_path):
    (repo / "secrets" / "device.yaml").write_text("cloud:\n  api_key: local-edit-value\n")
    result = export_envelope("secrets/device.yaml", str(tmp_path / "d.kist"))
    assert result.working_tree_differs is True
    out = tmp_path / "strict.kist"
    with pytest.raises(KistError, match="uncommitted"):
        export_envelope("secrets/device.yaml", str(out), strict=True)
    assert not out.exists()


def test_export_staged(repo, tmp_path):
    (repo / "secrets" / "device.yaml").write_text("cloud:\n  api_key: staged-value\n")
    git("add", "secrets/device.yaml")
    result = export_envelope("secrets/device.yaml", str(tmp_path / "s.kist"), staged=True)
    assert result.revision == "index"
    assert FileKist(result.output, git_path=result.git_path).get("cloud.api_key") == "staged-value"


def test_uncommitted_file_is_rejected(repo):
    (repo / "secrets" / "new.yaml").write_text("a: 1\n")
    with pytest.raises(KistError, match="not in HEAD"):
        export_envelope("secrets/new.yaml")


def test_plaintext_blob_is_rejected(repo):
    (repo / "config.yaml").write_text("not: encrypted\n")  # no kist filter rule
    git("add", "config.yaml")
    git("commit", "-q", "-m", "plain")
    with pytest.raises(KistError, match="not Kist-encrypted"):
        export_envelope("config.yaml")


def test_outside_repository_is_rejected(repo, tmp_path):
    outside = tmp_path / "outside.yaml"
    outside.write_text("a: 1\n")
    with pytest.raises(KistError, match="outside"):
        export_envelope(str(outside))


def test_not_a_git_repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    with pytest.raises(KistError, match="Git work tree"):
        export_envelope("secrets/device.yaml")


def test_cli_export(repo, tmp_path, monkeypatch, capsys):
    out = tmp_path / "cli.kist"
    monkeypatch.setattr(sys, "argv", ["kist", "export", "secrets/device.yaml", "-o", str(out), "--verify"])
    main()
    err = capsys.readouterr().err
    assert "Exported secrets/device.yaml" in err
    assert "Verified: decrypts to 2 secrets." in err
    assert "git_path='secrets/device.yaml'" in err
    assert out.read_bytes().startswith(b"KIST")


def test_cli_export_strict_exit_code(repo, tmp_path, monkeypatch, capsys):
    (repo / "secrets" / "device.yaml").write_text("cloud:\n  api_key: local-edit-value\n")
    monkeypatch.setattr(sys, "argv", ["kist", "export", "secrets/device.yaml", "-o", str(tmp_path / "x.kist"), "--strict"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    assert "uncommitted" in capsys.readouterr().err


def test_cli_export_to_stdout(repo):
    proc = subprocess.run([sys.executable, "-m", "kist", "export", "secrets/device.yaml", "-o", "-"],
                          capture_output=True, check=True)
    assert proc.stdout.startswith(b"KIST")
    assert b"example-value" not in proc.stdout
