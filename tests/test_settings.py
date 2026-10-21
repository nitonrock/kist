"""~/.kist/env and ~/.kist/env_<profile>: lookup order, validation, and use in Git and the database."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from kist import run_git_setup
from kist.core import (
    InsecureKeyStoreError,
    Kist,
    KistError,
    KistScope,
    enforce_ssl_url,
    git_context,
    is_kist_envelope,
    kist_setting,
    kist_setting_with_source,
)
from kist.status import run_status

SETTINGS = ("KIST_ORG_ID", "KIST_PROJECT_ID", "KIST_REPOSITORY_ID", "KIST_DATABASE_URL", "KIST_ENV",
            "KIST_TLS_MODE", "KIST_USE_RETIRED_PASSWORDS", "KIST_PROFILE", "KIST_FRESH_ENCRYPTION",
            "KIST_ALLOW_PASSWORD_CHANGE")
PASSWORD = "settings-example-password-0123456789ab"


@pytest.fixture
def kist_dir(tmp_path, monkeypatch):
    directory = tmp_path / ".kist"
    directory.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("KIST_DIR", str(directory))
    for name in list(os.environ):
        if name in SETTINGS or name.startswith(("KIST_PASSWORD", "KIST_RETIRED")):
            monkeypatch.delenv(name, raising=False)
    return directory


def write(directory: Path, name: str, text: str, mode: int = 0o600) -> Path:
    path = directory / name
    path.write_text(text)
    path.chmod(mode)
    return path


# --- lookup order -------------------------------------------------------------

def test_profile_file_overrides_machine_file_per_setting(kist_dir):
    write(kist_dir, "env", "KIST_ORG_ID=nitonrock\nKIST_PROJECT_ID=markets\n")
    write(kist_dir, "env_ma_jpn", "KIST_PROJECT_ID=japan\nKIST_REPOSITORY_ID=trading-config\n")
    assert kist_setting_with_source("KIST_ORG_ID", "ma_jpn") == ("nitonrock", "~/.kist/env")
    assert kist_setting_with_source("KIST_PROJECT_ID", "ma_jpn") == ("japan", "~/.kist/env_ma_jpn")
    assert kist_setting_with_source("KIST_REPOSITORY_ID", "ma_jpn") == ("trading-config", "~/.kist/env_ma_jpn")
    # Another profile without its own file uses ~/.kist/env entirely.
    assert kist_setting_with_source("KIST_PROJECT_ID", "other") == ("markets", "~/.kist/env")
    assert kist_setting_with_source("KIST_REPOSITORY_ID", "other") == (None, "default")


def test_environment_variable_wins_over_both_files(kist_dir, monkeypatch):
    write(kist_dir, "env", "KIST_PROJECT_ID=markets\n")
    write(kist_dir, "env_ma_jpn", "KIST_PROJECT_ID=japan\n")
    monkeypatch.setenv("KIST_PROJECT_ID", "from-ci")
    assert kist_setting_with_source("KIST_PROJECT_ID", "ma_jpn") == ("from-ci", "environment")


def test_empty_environment_variable_falls_through(kist_dir, monkeypatch):
    write(kist_dir, "env_ma_jpn", "KIST_PROJECT_ID=japan\n")
    monkeypatch.setenv("KIST_PROJECT_ID", "")
    assert kist_setting("KIST_PROJECT_ID", "ma_jpn") == "japan"


def test_no_files_means_built_in_defaults(kist_dir):
    assert KistScope.from_environment("ma_jpn") == KistScope("local", "default")
    assert git_context("ma_jpn", "secrets/secrets_ma_jpn.yml")["repository"] == "local-repository"


def test_missing_kist_directory_is_fine(tmp_path, monkeypatch):
    monkeypatch.setenv("KIST_DIR", str(tmp_path / "absent"))
    for name in SETTINGS:
        monkeypatch.delenv(name, raising=False)
    assert kist_setting("KIST_ORG_ID", "ma_jpn") is None


# --- file format and safety ----------------------------------------------------

def test_comments_quotes_and_export_prefix(kist_dir):
    write(kist_dir, "env", "# machine settings\n\nexport KIST_ORG_ID=nitonrock\nKIST_PROJECT_ID = \"my project\"\n"
                           "KIST_DATABASE_URL='postgresql://kist:p#ss@127.0.0.1:5432/kist'\n")
    assert kist_setting("KIST_ORG_ID") == "nitonrock"
    assert kist_setting("KIST_PROJECT_ID") == "my project"
    assert kist_setting("KIST_DATABASE_URL") == "postgresql://kist:p#ss@127.0.0.1:5432/kist"


def test_file_must_be_owner_only(kist_dir):
    write(kist_dir, "env", "KIST_ORG_ID=nitonrock\n", mode=0o644)
    with pytest.raises(InsecureKeyStoreError, match="chmod 600"):
        kist_setting("KIST_ORG_ID")


def test_symlinked_file_is_refused(kist_dir, tmp_path):
    target = write(tmp_path, "elsewhere", "KIST_ORG_ID=evil\n")
    (kist_dir / "env").symlink_to(target)
    with pytest.raises(OSError):
        kist_setting("KIST_ORG_ID")


def test_passwords_are_refused_in_settings_files(kist_dir):
    write(kist_dir, "env_ma_jpn", "KIST_PASSWORD_MA_JPN=nope\n")
    with pytest.raises(KistError, match="pwd_<profile>"):
        kist_setting("KIST_ORG_ID", "ma_jpn")


def test_unknown_and_profile_names_are_refused(kist_dir):
    write(kist_dir, "env", "KIST_PROFILE=ma_jpn\n")
    with pytest.raises(KistError, match="KIST_PROFILE cannot be set"):
        kist_setting("KIST_ORG_ID")
    write(kist_dir, "env", "NOT_KIST=1\n")
    with pytest.raises(KistError, match="expected KIST_NAME=value"):
        kist_setting("KIST_ORG_ID")


def test_machine_settings_are_refused_in_profile_files(kist_dir):
    write(kist_dir, "env_ma_jpn", "KIST_TLS_MODE=disable\n")
    with pytest.raises(KistError, match="KIST_TLS_MODE cannot be set in env_ma_jpn"):
        kist_setting("KIST_ORG_ID", "ma_jpn")


def test_machine_env_file_controls_production_tls_policy(kist_dir):
    write(kist_dir, "env", "KIST_ENV=production\n")
    with pytest.raises(KistError, match="TLS cannot be disabled in production"):
        enforce_ssl_url("postgresql://kist@127.0.0.1:5432/kist?sslmode=disable")


# --- used by the database client and the Git filters ---------------------------

def test_kist_uses_profile_database_url_and_scope(kist_dir):
    write(kist_dir, "env", "KIST_DATABASE_URL=postgresql://kist:machine@127.0.0.1:5432/kist\nKIST_ORG_ID=acme\n")
    write(kist_dir, "env_ma_jpn", "KIST_DATABASE_URL=postgresql://kist:profile@10.0.0.5:5432/kist\n"
                                  "KIST_PROJECT_ID=japan\n")
    store = Kist(profile_name="ma_jpn", password=PASSWORD)
    assert "10.0.0.5" in store.db_url
    assert store.scope == KistScope("acme", "japan")
    other = Kist(profile_name="other", password=PASSWORD)
    assert "127.0.0.1" in other.db_url and other.scope == KistScope("acme", "default")


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_filters_use_settings_files_without_environment(kist_dir, tmp_path, monkeypatch):
    """The IDE case: no KIST_* variables at all, everything from ~/.kist."""
    write(kist_dir, "pwd_ma_jpn", PASSWORD)
    write(kist_dir, "env", "KIST_ORG_ID=nitonrock\n")
    write(kist_dir, "env_ma_jpn", "KIST_PROJECT_ID=japan\nKIST_REPOSITORY_ID=trading-config\n")
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.chdir(root)
    kist = f'"{sys.executable}" -m kist'

    def git(*args, env=None):
        return subprocess.run(["git", *args], capture_output=True, text=True, env=env, check=False)

    git("init", "-q", "-b", "main")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "test")
    run_git_setup(install_hook=False)
    git("config", "filter.kist.clean", f"{kist} --clean %f")
    git("config", "filter.kist.smudge", f"{kist} --smudge %f")
    git("config", "diff.kist.textconv", f"{kist} --textconv")
    (root / "secrets").mkdir()
    (root / "secrets" / "secrets_ma_jpn.yml").write_text("# Japan\ndb_password: example-1\n")
    minimal = {"HOME": str(tmp_path), "KIST_DIR": str(kist_dir), "PATH": os.environ["PATH"]}
    assert git("add", "-A", env=minimal).returncode == 0
    assert git("commit", "-q", "-m", "init", env=minimal).returncode == 0
    stored = subprocess.run(["git", "cat-file", "blob", "HEAD:secrets/secrets_ma_jpn.yml"],
                            capture_output=True, check=True).stdout
    assert is_kist_envelope(stored)
    context = git_context("ma_jpn", "secrets/secrets_ma_jpn.yml")
    assert (context["organization"], context["project"], context["repository"]) == (
        "nitonrock", "japan", "trading-config")
    shown = git("show", "--textconv", "HEAD:secrets/secrets_ma_jpn.yml", env=minimal)
    assert "db_password: example-1" in shown.stdout
    # With other identifiers the same password no longer opens the file.
    wrong = dict(minimal, KIST_PROJECT_ID="markets")
    assert "example-1" not in git("show", "--textconv", "HEAD:secrets/secrets_ma_jpn.yml", env=wrong).stdout


def test_status_shows_sources(kist_dir, tmp_path, monkeypatch, capsys):
    write(kist_dir, "pwd_ma_jpn", PASSWORD)
    write(kist_dir, "env", "KIST_ORG_ID=nitonrock\nKIST_DATABASE_URL=postgresql://kist:hidden-db-pw@127.0.0.1:9/kist\n")
    write(kist_dir, "env_ma_jpn", "KIST_PROJECT_ID=japan\n")
    project = tmp_path / "project"
    (project / "secrets").mkdir(parents=True)
    (project / "secrets" / "secrets_ma_jpn.yml").write_text("a: 1\n")
    monkeypatch.chdir(project)
    run_status()
    out = capsys.readouterr().out
    assert "KIST_ORG_ID=nitonrock (~/.kist/env)" in out
    assert "KIST_PROJECT_ID=japan (~/.kist/env_ma_jpn)" in out
    assert "KIST_REPOSITORY_ID=local-repository (default)" in out
    assert "hidden-db-pw" not in out and "(~/.kist/env)" in out
