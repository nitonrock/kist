"""Tests for profile password rotation (kist profile rotate).

Tests whose names contain "database" need KIST_TEST_DATABASE_URL (a disposable
PostgreSQL); the rest only need git.
"""

import os
import shutil
import stat
import subprocess
import sys
import uuid

import pytest

from kist import Kist, KistScope, main
from kist.core import DecryptionError, KistError, decrypt_envelope, git_context, safe_db_connect
from kist.rotate import find_profile_git_files, plan_rotation, restage_git_with_current_key, rotate_profile

OLD = "old-rotation-password-0123456789abcdef"
NEW = "new-rotation-password-0123456789abcdef"
YAML = "cloud:\n  api_key: example-value\nmqtt:\n  port: 8883\n"
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def git(*args, check=True, **kwargs):
    return subprocess.run(["git", *args], check=check, capture_output=True, **kwargs)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    kist_dir = tmp_path / ".kist"
    monkeypatch.setenv("KIST_DIR", str(kist_dir))
    for name in list(os.environ):
        if name.startswith("KIST_PASSWORD") or name in {"KIST_ORGANIZATION", "KIST_PROJECT", "KIST_REPOSITORY_ID"}:
            monkeypatch.delenv(name, raising=False)
    kist_dir.mkdir(mode=0o700)
    for profile in ("device", "other"):
        path = kist_dir / f"pwd_{profile}"
        path.write_text(OLD)
        path.chmod(0o600)
    return tmp_path


@pytest.fixture
def repo(home, monkeypatch):
    root = home / "repo"
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
    (root / "secrets" / "other.yaml").write_text("x: 1\n")
    (root / "README.md").write_text("hello\n")
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    return root


def index_plaintext(path, password, profile="device"):
    blob = git("cat-file", "blob", f":{path}").stdout
    return decrypt_envelope(blob, password, git_context(profile, path))


def key_file(home, profile="device"):
    return home / ".kist" / f"pwd_{profile}"


@pytest.fixture
def db_url(monkeypatch):
    url = os.getenv("KIST_TEST_DATABASE_URL")
    if not url:
        pytest.skip("No disposable PostgreSQL test URL configured")
    return url


@pytest.fixture
def scope(db_url, monkeypatch):
    s = KistScope("rot-" + uuid.uuid4().hex[:12], "test")
    monkeypatch.setenv("KIST_ORGANIZATION", s.organization)
    monkeypatch.setenv("KIST_PROJECT", s.project)
    monkeypatch.setenv("KIST_DATABASE_URL", db_url)
    Kist("device", OLD, db_url, s).init_db()
    yield s
    with safe_db_connect(db_url) as connection:
        connection.execute("DELETE FROM kist_organizations WHERE slug = %s", (s.organization,))


def rows(db_url, store):
    with safe_db_connect(db_url) as connection:
        return connection.execute("""SELECT id, lookup_token, secret_version, encrypted_blob
            FROM kist_secrets WHERE profile_id = %s ORDER BY id""", (store.profile_id,)).fetchall()


# --------------------------------------------------------------------------- database layer

def test_database_rotate_keys_reencrypts_everything(db_url, scope):
    store = Kist("device", OLD, db_url, scope)
    store.lock_yaml(YAML)
    before = rows(db_url, store)
    with safe_db_connect(db_url) as c:
        rev_before = c.execute("SELECT wrapper_revision FROM kist_key_bundles WHERE profile_id = %s",
                               (store.profile_id,)).fetchone()[0]

    assert store.rotate_profile_keys(NEW) == 2
    after = rows(db_url, store)

    assert [r[0] for r in after] == [r[0] for r in before]                # same records
    assert all(a[2] == b[2] + 1 for a, b in zip(after, before))           # versions bumped
    assert all(a[1] != b[1] for a, b in zip(after, before))               # new lookup tokens (new index key)
    assert all(a[3] != b[3] for a, b in zip(after, before))               # new ciphertext
    with safe_db_connect(db_url) as c:
        assert c.execute("SELECT wrapper_revision FROM kist_key_bundles WHERE profile_id = %s",
                         (store.profile_id,)).fetchone()[0] == rev_before + 1

    fresh = Kist("device", NEW, db_url, scope)
    assert fresh.get("cloud.api_key") == "example-value"
    assert fresh.get("mqtt.port") == 8883
    with pytest.raises(DecryptionError):
        Kist("device", OLD, db_url, scope).get("cloud.api_key")


def test_database_rotation_is_atomic(db_url, scope):
    store = Kist("device", OLD, db_url, scope)
    store.lock_yaml(YAML)
    before = rows(db_url, store)
    with safe_db_connect(db_url) as c:  # corrupt one record
        c.execute("UPDATE kist_secrets SET encrypted_blob = %s WHERE id = %s",
                  (bytes(before[1][3])[:-1] + b"\x00", before[1][0]))
    with pytest.raises(DecryptionError):
        store.rotate_profile_keys(NEW)
    after = rows(db_url, store)
    assert [r[2] for r in after] == [r[2] for r in before]                # nothing re-encrypted
    assert bytes(after[0][3]) == bytes(before[0][3])
    assert Kist("device", OLD, db_url, scope).secret_count() == 2  # old key still opens the profile


def test_database_old_records_cannot_be_replayed(db_url, scope):
    store = Kist("device", OLD, db_url, scope)
    store.lock_yaml(YAML)
    old_row = rows(db_url, store)[0]
    store.rotate_profile_keys(NEW)
    with safe_db_connect(db_url) as c:  # attacker restores a record from an old backup
        c.execute("UPDATE kist_secrets SET lookup_token = %s, secret_version = %s, encrypted_blob = %s WHERE id = %s",
                  (old_row[1], old_row[2], old_row[3], old_row[0]))
    with pytest.raises(Exception):
        Kist("device", NEW, db_url, scope).unlock_yaml()


def test_database_rotate_rejects_same_password_and_missing_bundle(db_url, scope):
    store = Kist("device", OLD, db_url, scope)
    with pytest.raises(KistError, match="No profile key bundle"):
        store.rotate_profile_keys(NEW)
    store.set("a", 1)
    with pytest.raises(KistError, match="must differ"):
        store.rotate_profile_keys(OLD)


def test_database_secret_count(db_url, scope):
    store = Kist("device", OLD, db_url, scope)
    assert store.secret_count() is None
    store.lock_yaml(YAML)
    assert store.secret_count() == 2
    with pytest.raises(DecryptionError):
        Kist("device", "wrong-password-0123456789abcdefgh", db_url, scope).secret_count()


def test_database_rotation_notifies_listeners(db_url, scope):
    store = Kist("device", OLD, db_url, scope)
    store.lock_yaml(YAML)
    with safe_db_connect(db_url, autocommit=True) as listener:
        listener.execute("LISTEN kist_secret_updated")
        store.rotate_profile_keys(NEW)
        events = [n.payload for n in listener.notifies(timeout=2, stop_after=1)]
    assert any('"event":"key_bundle_rotated"' in e for e in events)


# --------------------------------------------------------------------------- Git layer

@needs_git
def test_git_only_rotation(repo, home):
    result = rotate_profile("device", use_database=False, new_password=NEW)
    assert result.git_restaged == ["secrets/device.yaml"]
    assert index_plaintext("secrets/device.yaml", NEW).decode() == YAML
    with pytest.raises(DecryptionError):
        index_plaintext("secrets/device.yaml", OLD)
    # other profile untouched, working copy unchanged
    assert "secrets/other.yaml" not in git("diff", "--cached", "--name-only").stdout.decode()
    assert (repo / "secrets" / "device.yaml").read_text() == YAML
    # key file replaced, old one kept, both owner-only
    assert key_file(home).read_text() == NEW
    assert result.old_key_backup.read_text() == OLD
    for path in (key_file(home), result.old_key_backup):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not (home / ".kist" / "pwd_device.new").exists()
    # history still needs the old key
    old_blob = git("cat-file", "blob", "HEAD:secrets/device.yaml").stdout
    assert decrypt_envelope(old_blob, OLD, git_context("device", "secrets/device.yaml")).decode() == YAML
    assert any("OLD password" in item for item in result.checklist)


@needs_git
def test_generated_password_is_strong_and_new(repo, home):
    rotate_profile("device", use_database=False)
    new = key_file(home).read_text()
    assert new != OLD and len(new) >= 32
    assert index_plaintext("secrets/device.yaml", new).decode() == YAML


@needs_git
@needs_git
def test_cli_git_only_recovery(repo, home, monkeypatch, capsys):
    key_file(home).write_text(NEW)  # as if DB + key file rotated but Git failed
    monkeypatch.setattr(sys, "argv", ["kist", "profile", "rotate", "device", "--git-only"])
    main()
    assert "Re-encrypted and staged 1 file(s)" in capsys.readouterr().out
    assert index_plaintext("secrets/device.yaml", NEW).decode() == YAML


@needs_git
def test_find_profile_files_only_matches_kist_filter_and_profile(repo):
    (repo / "secrets_device.yaml").write_text("y: 2\n")
    git("add", "secrets_device.yaml")
    git("commit", "-q", "-m", "more")
    assert find_profile_git_files("device", str(repo)) == ["secrets/device.yaml", "secrets_device.yaml"]
    assert find_profile_git_files("other", str(repo)) == ["secrets/other.yaml"]


@needs_git
@pytest.mark.parametrize("stage", [False, True])
def test_uncommitted_changes_block_rotation(repo, home, stage):
    (repo / "secrets" / "device.yaml").write_text(YAML + "extra: 1\n")
    if stage:
        git("add", "secrets/device.yaml")
    with pytest.raises(KistError, match="Uncommitted changes"):
        rotate_profile("device", use_database=False, new_password=NEW)
    assert key_file(home).read_text() == OLD


@needs_git
def test_touched_but_identical_file_is_not_dirty(repo, home):
    path = repo / "secrets" / "device.yaml"
    path.write_text(path.read_text())  # new mtime, same content: Git may call it modified
    rotate_profile("device", use_database=False, new_password=NEW)
    assert index_plaintext("secrets/device.yaml", NEW).decode() == YAML


@needs_git
def test_wrong_current_password_is_refused(repo, home):
    key_file(home).write_text("not-the-right-password-0123456789ab")
    with pytest.raises(DecryptionError, match="does not open"):
        plan_rotation("device", use_database=False)


@needs_git
def test_env_password_source_is_flagged(repo, home, monkeypatch):
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", OLD)
    result = rotate_profile("device", use_database=False, new_password=NEW)
    assert any("KIST_PASSWORD_DEVICE" in item for item in result.checklist)


@needs_git
def test_nothing_to_rotate(home, tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.chdir(empty)
    git("init", "-q")
    with pytest.raises(KistError, match="Nothing to rotate"):
        rotate_profile("device", use_database=False, new_password=NEW)


@needs_git
def test_git_failure_after_key_change_gives_recovery_path(repo, home, monkeypatch):
    import kist.rotate as rot
    real = rot._renormalize
    monkeypatch.setattr(rot, "_renormalize", lambda *a, **k: (_ for _ in ()).throw(KistError("boom")))
    with pytest.raises(KistError, match="--git-only"):
        rotate_profile("device", use_database=False, new_password=NEW)
    assert key_file(home).read_text() == NEW  # key already switched
    monkeypatch.setattr(rot, "_renormalize", real)
    # Recovery: the index still holds the OLD envelope; re-encrypt with the current (new) key.
    assert restage_git_with_current_key("device") == ["secrets/device.yaml"]
    assert index_plaintext("secrets/device.yaml", NEW).decode() == YAML


# --------------------------------------------------------------------------- full flow and CLI

@needs_git
def test_database_full_rotation_db_git_and_key(repo, home, db_url, scope):
    Kist("device", OLD, db_url, scope).lock_yaml(YAML)
    result = rotate_profile("device", new_password=NEW, scope=scope)
    assert result.database_rotated and result.database_secrets == 2
    assert result.git_restaged == ["secrets/device.yaml"]
    assert Kist("device", None, db_url, scope).get("cloud.api_key") == "example-value"  # reads new key file
    assert index_plaintext("secrets/device.yaml", NEW).decode() == YAML


@needs_git
def test_database_failure_leaves_everything_unchanged(repo, home, db_url, scope, monkeypatch):
    Kist("device", OLD, db_url, scope).lock_yaml(YAML)
    monkeypatch.setattr(Kist, "rotate_profile_keys", lambda self, pw: (_ for _ in ()).throw(KistError("db down")))
    with pytest.raises(KistError, match="db down"):
        rotate_profile("device", new_password=NEW, scope=scope)
    assert key_file(home).read_text() == OLD
    assert not (home / ".kist" / "pwd_device.new").exists()
    assert git("diff", "--cached", "--name-only").stdout == b""
    assert Kist("device", OLD, db_url, scope).get("mqtt.port") == 8883


@needs_git
def test_database_rewrap_only(repo, home, db_url, scope):
    store = Kist("device", OLD, db_url, scope)
    store.lock_yaml(YAML)
    before = rows(db_url, store)
    rotate_profile("device", new_password=NEW, scope=scope, rewrap_only=True)
    after = rows(db_url, store)
    assert [bytes(r[3]) for r in after] == [bytes(r[3]) for r in before]  # records untouched
    assert Kist("device", NEW, db_url, scope).get("mqtt.port") == 8883


@needs_git
def test_cli_rotate_dry_run_and_yes(repo, home, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["kist", "profile", "rotate", "device", "--skip-db", "--dry-run"])
    main()
    out = capsys.readouterr().out
    assert "secrets/device.yaml" in out and "Dry run: nothing changed." in out
    assert key_file(home).read_text() == OLD

    monkeypatch.setattr(sys, "argv", ["kist", "profile", "rotate", "device", "--skip-db", "--yes"])
    main()
    out = capsys.readouterr().out
    assert "Rotation complete" in out and "git commit" in out
    assert key_file(home).read_text() != OLD
    assert NEW not in out and key_file(home).read_text() not in out  # password never printed


@needs_git
def test_cli_rotate_requires_confirmation_when_not_interactive(repo, home):
    proc = subprocess.run([sys.executable, "-m", "kist", "profile", "rotate", "device", "--skip-db"],
                          stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "--yes" in proc.stderr
    assert key_file(home).read_text() == OLD


@needs_git
def test_cli_rotate_new_password_stdin(repo, home):
    proc = subprocess.run([sys.executable, "-m", "kist", "profile", "rotate", "device", "--skip-db", "--yes",
                           "--new-password-stdin"], input=NEW + "\n", capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert key_file(home).read_text() == NEW


def test_profile_create_rotate_points_to_new_command(home, monkeypatch):
    from kist.core import create_profile_key
    with pytest.raises(KistError, match="kist profile rotate"):
        create_profile_key("device", rotate=True)
