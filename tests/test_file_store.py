"""Tests for the offline FileKist backend (no PostgreSQL required)."""

import io
import os
import shutil
import subprocess
import sys

import pytest

from kist import FileKist, Kist, KistScope, git_clean_stream
from kist.core import DecryptionError, InvalidEnvelopeError, KistError, MissingKeyError

PASSWORD = "file-store-example-password-0123456789"
GIT_PATH = "secrets/device.yaml"
YAML = """\
cloud:
  api_key: example-value
  endpoint: https://iot.example.invalid
mqtt:
  port: 8883
  tls: true
features: [ota, telemetry]
"""


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("KIST_DIR", str(tmp_path / ".kist"))
    for name in list(os.environ):
        if name.startswith("KIST_PASSWORD") or name in {
            "KIST_ORGANIZATION", "KIST_PROJECT", "KIST_REPOSITORY_ID", "KIST_PROFILE"
        }:
            monkeypatch.delenv(name, raising=False)


def make_envelope(plaintext=YAML, git_path=GIT_PATH, password=PASSWORD, profile="device"):
    out = io.BytesIO()
    git_clean_stream(profile, password, io.StringIO(plaintext), out, git_path)
    return out.getvalue()


@pytest.fixture
def envelope_file(tmp_path):
    path = tmp_path / "device.kist"
    path.write_bytes(make_envelope())
    return path


def test_reads_nested_values(envelope_file):
    store = FileKist(envelope_file, git_path=GIT_PATH, master_password=PASSWORD)
    assert store.profile_name == "device"
    assert store.get("cloud.api_key") == "example-value"
    assert store["mqtt.port"] == 8883
    assert store.get("mqtt.tls") is True
    assert store.get("features") == ["ota", "telemetry"]
    assert "cloud.endpoint" in store
    assert store.keys() == sorted(["cloud.api_key", "cloud.endpoint", "features", "mqtt.port", "mqtt.tls"])
    assert len(store) == 5


def test_kist_from_file_classmethod(envelope_file):
    store = Kist.from_file(envelope_file, git_path=GIT_PATH, master_password=PASSWORD)
    assert isinstance(store, FileKist)
    assert store.get_secret("cloud.api_key") == "example-value"


def test_missing_key_and_default(envelope_file):
    store = FileKist(envelope_file, git_path=GIT_PATH, master_password=PASSWORD)
    with pytest.raises(KeyError):
        store.get("cloud.nope")
    assert store.get("cloud.nope", None) is None
    assert store.get("cloud.nope", "fallback") == "fallback"


def test_password_from_environment(envelope_file, monkeypatch):
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", PASSWORD)
    assert FileKist(envelope_file, git_path=GIT_PATH).get("cloud.api_key") == "example-value"


def test_missing_password_fails_closed(envelope_file):
    with pytest.raises(MissingKeyError):
        FileKist(envelope_file, git_path=GIT_PATH).get("cloud.api_key")


def test_wrong_password_fails(envelope_file):
    with pytest.raises(DecryptionError):
        FileKist(envelope_file, git_path=GIT_PATH, master_password="wrong-password-0123456789abcdef").get("cloud.api_key")


def test_tampered_envelope_fails(envelope_file):
    data = bytearray(envelope_file.read_bytes())
    data[-1] ^= 0x01
    envelope_file.write_bytes(bytes(data))
    with pytest.raises(DecryptionError):
        FileKist(envelope_file, git_path=GIT_PATH, master_password=PASSWORD).get("cloud.api_key")


@pytest.mark.parametrize("kwargs", [
    {"git_path": "secrets/other.yaml", "profile_name": "device"},   # path transplant
    {"git_path": GIT_PATH, "profile_name": "production"},           # profile transplant
    {"git_path": GIT_PATH, "scope": KistScope("other-org", "default")},
    {"git_path": GIT_PATH, "repository_id": "another-repo"},
])
def test_context_binding_rejects_transplants(envelope_file, kwargs):
    with pytest.raises(DecryptionError):
        FileKist(envelope_file, master_password=PASSWORD, **kwargs).get("cloud.api_key")


def test_scope_and_repository_must_match_commit_time(tmp_path, monkeypatch):
    monkeypatch.setenv("KIST_ORGANIZATION", "acme")
    monkeypatch.setenv("KIST_REPOSITORY_ID", "acme/firmware")
    path = tmp_path / "device.kist"
    path.write_bytes(make_envelope())
    assert FileKist(path, git_path=GIT_PATH, master_password=PASSWORD).get("mqtt.port") == 8883
    monkeypatch.delenv("KIST_REPOSITORY_ID")
    with pytest.raises(DecryptionError):
        FileKist(path, git_path=GIT_PATH, master_password=PASSWORD).get("mqtt.port")
    store = FileKist(path, git_path=GIT_PATH, master_password=PASSWORD, repository_id="acme/firmware")
    assert store.get("mqtt.port") == 8883


def test_plaintext_file_is_refused(tmp_path):
    path = tmp_path / "device.yaml"
    path.write_text(YAML)
    with pytest.raises(InvalidEnvelopeError, match="git show"):
        FileKist(path, git_path=GIT_PATH, master_password=PASSWORD).get("cloud.api_key")


def test_missing_file(tmp_path):
    with pytest.raises(KistError, match="not found"):
        FileKist(tmp_path / "absent.kist", git_path=GIT_PATH, master_password=PASSWORD, lazy=False)


def test_duplicate_yaml_keys_rejected(tmp_path):
    path = tmp_path / "device.kist"
    path.write_bytes(make_envelope("a: 1\na: 2\n"))
    with pytest.raises(KistError, match="Duplicate"):
        FileKist(path, git_path=GIT_PATH, master_password=PASSWORD).get("a")


def test_yaml_merge_keys_supported(tmp_path):
    path = tmp_path / "device.kist"
    path.write_bytes(make_envelope("base: &b {host: h, port: 1}\nprod:\n  <<: *b\n  port: 2\n"))
    store = FileKist(path, git_path=GIT_PATH, master_password=PASSWORD)
    assert store.get("prod.host") == "h"
    assert store.get("prod.port") == 2


def test_empty_yaml(tmp_path):
    path = tmp_path / "device.kist"
    path.write_bytes(make_envelope("# nothing yet\n"))
    assert len(FileKist(path, git_path=GIT_PATH, master_password=PASSWORD)) == 0


def test_default_profile_derivation(tmp_path):
    path = tmp_path / "secrets.yaml"
    path.write_bytes(make_envelope(git_path="secrets.yaml", profile="default"))
    store = FileKist(path, git_path="secrets.yaml", master_password=PASSWORD)
    assert store.profile_name == "default"
    assert store.get("mqtt.port") == 8883


def test_lazy_eager_reload_and_close(envelope_file):
    lazy = FileKist(envelope_file, git_path=GIT_PATH, master_password=PASSWORD)
    assert "not loaded" in repr(lazy)
    eager = FileKist(envelope_file, git_path=GIT_PATH, master_password=PASSWORD, lazy=False)
    assert "loaded" in repr(eager) and "not loaded" not in repr(eager)

    envelope_file.write_bytes(make_envelope("cloud:\n  api_key: rotated-value\n"))
    assert eager.get("cloud.api_key") == "example-value"  # in-memory until reload
    eager.reload()
    assert eager.get("cloud.api_key") == "rotated-value"

    with FileKist(envelope_file, git_path=GIT_PATH, master_password=PASSWORD, lazy=False) as store:
        assert store.get("cloud.api_key") == "rotated-value"
    assert "not loaded" in repr(store)


def test_argon2_runs_once_per_load(envelope_file, monkeypatch):
    import kist.file_store as fs
    calls = []
    real = fs.decrypt_envelope
    monkeypatch.setattr(fs, "decrypt_envelope", lambda *a, **k: calls.append(1) or real(*a, **k))
    store = FileKist(envelope_file, git_path=GIT_PATH, master_password=PASSWORD)
    for _ in range(5):
        store.get("cloud.api_key")
    assert len(calls) == 1


def test_no_database_access(envelope_file, monkeypatch):
    import kist.core as core
    monkeypatch.setattr(core, "safe_db_connect", lambda *a, **k: pytest.fail("database used"))
    monkeypatch.setenv("KIST_DATABASE_URL", "postgresql://unreachable.invalid/kist")
    assert FileKist(envelope_file, git_path=GIT_PATH, master_password=PASSWORD).get("mqtt.port") == 8883


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_end_to_end_with_git_filter(tmp_path, monkeypatch):
    """kist init -> git add -> git show HEAD:<path> -> FileKist."""
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)
    monkeypatch.setenv("KIST_PASSWORD_DEVICE", PASSWORD)
    run = lambda *cmd: subprocess.run(cmd, check=True, capture_output=True, text=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "test@example.invalid")
    run("git", "config", "user.name", "test")
    from kist import run_git_setup
    run_git_setup()
    # Point the filter at this interpreter so the test doesn't depend on PATH.
    kist_cmd = f'"{sys.executable}" -m kist'
    run("git", "config", "filter.kist.clean", f"{kist_cmd} --clean %f")
    run("git", "config", "filter.kist.smudge", f"{kist_cmd} --smudge %f")
    (repo / "secrets").mkdir()
    (repo / GIT_PATH).write_text(YAML)
    run("git", "add", GIT_PATH)
    run("git", "commit", "-q", "--no-verify", "-m", "add secrets")

    blob = subprocess.run(["git", "show", f"HEAD:{GIT_PATH}"], check=True, capture_output=True).stdout
    assert blob.startswith(b"KIST")
    exported = tmp_path / "firmware" / "device.kist"
    exported.parent.mkdir()
    exported.write_bytes(blob)

    store = FileKist(exported, git_path=GIT_PATH)
    assert store.get("cloud.api_key") == "example-value"
