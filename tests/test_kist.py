import io
import json
import os
import struct
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg
import pytest
import yaml

from kist import (
    Kist,
    create_profile_password,
    decrypt_envelope,
    encrypt_envelope,
    enforce_ssl_url,
    generate_password,
    get_kist_dir,
    get_profile_and_password,
    get_profile_password,
    git_clean_stream,
    git_context,
    git_smudge_stream,
    is_kist_envelope,
    main,
    mask_db_url,
    remove_profile_password,
    resolve_secret_file_path,
    run_fix,
    run_git_setup,
    run_leak_guard,
    run_status,
    safe_async_db_connect,
    safe_db_connect,
    write_secure_local_password,
)
from kist.core import (
    ENVELOPE_VERSION,
    HEADER_SIZE,
    KEY_MODE_PASSWORD,
    SCHEMA_VERSION,
    SQL_SCHEMA,
    Argon2Policy,
    ConcurrentWriteError,
    DecryptionError,
    InsecureKeyStoreError,
    InvalidEnvelopeError,
    KistError,
    KistScope,
    MissingKeyError,
    _ROW_MAGIC,
    _json_bytes,
    _strict_json,
    _UniqueSafeLoader,
    read_secure_local_password,
)
from kist.kms import (
    KMSKeyReference,
    KMSProviderError,
    LocalKMSProvider,
    WrappedDataKey,
    get_kms_provider,
)


class MockDB:
    """In-memory mock database for PostgreSQL operations in Kist."""

    def __init__(self):
        self.orgs = {}
        self.projects = {}
        self.profiles = {}
        self.bundles = {}
        self.secrets = {}
        self.last_result = []
        self.advisory_locks = []
        self.notifications = []
        self.fail_next_execute = None

    def execute(self, query, params=None):
        if self.fail_next_execute:
            exc = self.fail_next_execute
            self.fail_next_execute = None
            raise exc

        q = " ".join(str(query).split())
        params = list(params) if params else []
        if "to_regclass" in q:
            self.last_result = [("kist_schema",)]
        elif "SELECT version FROM kist_schema" in q:
            self.last_result = [(1,)]
        elif "INSERT INTO kist_organizations" in q:
            uid, slug = params[0], params[1]
            if slug not in self.orgs:
                self.orgs[slug] = uid
            self.last_result = [(self.orgs[slug],)]
        elif "INSERT INTO kist_projects" in q:
            uid, org_id, slug = params[0], params[1], params[2]
            key = (org_id, slug)
            if key not in self.projects:
                self.projects[key] = uid
            self.last_result = [(self.projects[key],)]
        elif "INSERT INTO kist_profiles" in q:
            uid, proj_id, name = params[0], params[1], params[2]
            key = (proj_id, name)
            if key not in self.profiles:
                self.profiles[key] = uid
            self.last_result = [(self.profiles[key],)]
        elif "SELECT id, access_mode, bundle_version, wrapped_bundle FROM kist_key_bundles" in q:
            prof_id = params[0]
            match = None
            for p_id, b in self.bundles.items():
                if str(p_id) == str(prof_id):
                    match = b
                    break
            if match:
                self.last_result = [(match["id"], match["access_mode"], match["bundle_version"], match["wrapped_bundle"])]
            else:
                self.last_result = []
        elif "INSERT INTO kist_key_bundles" in q:
            bid, prof_id, mode, blob = params[0], params[1], params[2], params[3]
            self.bundles[str(prof_id)] = {"id": bid, "access_mode": mode, "bundle_version": 1, "wrapped_bundle": bytes(blob)}
            self.last_result = []
        elif "UPDATE kist_key_bundles" in q:
            wrapped, bid, prof_id = params[0], params[1], params[2]
            for p_id, b in self.bundles.items():
                if str(p_id) == str(prof_id):
                    b["wrapped_bundle"] = bytes(wrapped)
            self.last_result = []
        elif "SELECT id, lookup_token, key_bundle_id, crypto_version, secret_version, encrypted_blob FROM kist_secrets" in q:
            prof_id = params[0]
            if len(params) > 1:
                token = bytes(params[1])
                match = None
                for (p_id, t), s in self.secrets.items():
                    if str(p_id) == str(prof_id) and t == token:
                        match = s
                        break
                if match:
                    self.last_result = [(match["id"], match["lookup_token"], match["bundle_id"], match["crypto_version"], match["version"], match["blob"])]
                else:
                    self.last_result = []
            else:
                self.last_result = [
                    (s["id"], s["lookup_token"], s["bundle_id"], s["crypto_version"], s["version"], s["blob"])
                    for (p_id, _), s in self.secrets.items() if str(p_id) == str(prof_id)
                ]
        elif "INSERT INTO kist_secrets" in q:
            row_id, prof_id, token, bid, version, blob = params[0], params[1], bytes(params[2]), params[3], params[4], bytes(params[5])
            self.secrets[(str(prof_id), token)] = {
                "id": row_id, "lookup_token": token, "bundle_id": bid, "crypto_version": 1, "version": version, "blob": blob
            }
            self.last_result = []
        elif "UPDATE kist_secrets" in q:
            blob, version, row_id, prof_id = bytes(params[0]), params[1], params[2], params[3]
            for (p_id, token), s in self.secrets.items():
                if str(p_id) == str(prof_id) and s["id"] == row_id:
                    s["blob"] = blob
                    s["version"] = version
                    break
            self.last_result = []
        elif "DELETE FROM kist_secrets" in q:
            row_id, prof_id = params[0], params[1]
            for k in list(self.secrets.keys()):
                if self.secrets[k]["id"] == row_id and str(k[0]) == str(prof_id):
                    del self.secrets[k]
            self.last_result = []
        elif "pg_advisory_xact_lock" in q:
            self.advisory_locks.append(params[0] if params else None)
            self.last_result = [(None,)]
        elif "pg_notify" in q:
            self.notifications.append((params[0], params[1]) if params else ())
            self.last_result = [(None,)]
        elif "SELECT id FROM kist_organizations WHERE slug" in q:
            slug = params[0]
            if slug in self.orgs:
                self.last_result = [(self.orgs[slug],)]
            else:
                self.last_result = []
        elif "SELECT id FROM kist_projects WHERE organization_id" in q:
            org_id, slug = params[0], params[1]
            key = (org_id, slug)
            if key in self.projects:
                self.last_result = [(self.projects[key],)]
            else:
                self.last_result = []
        elif "SELECT id FROM kist_profiles WHERE project_id" in q:
            proj_id, name = params[0], params[1]
            key = (proj_id, name)
            if key in self.profiles:
                self.last_result = [(self.profiles[key],)]
            else:
                self.last_result = []
        elif "DELETE FROM kist_profiles" in q:
            prof_id = params[0]
            for k in list(self.profiles.keys()):
                if str(self.profiles[k]) == str(prof_id):
                    del self.profiles[k]
            self.bundles = {p: b for p, b in self.bundles.items() if str(p) != str(prof_id)}
            self.secrets = {k: s for k, s in self.secrets.items() if str(k[0]) != str(prof_id)}
            self.last_result = []
        elif "DELETE FROM kist_organizations" in q:
            org_id = params[0]
            self.orgs = {k: v for k, v in self.orgs.items() if v != org_id}
            self.last_result = []
        else:
            self.last_result = []

    def fetchone(self):
        if self.last_result:
            return self.last_result.pop(0)
        return None

    def fetchall(self):
        res = list(self.last_result)
        self.last_result = []
        return res


class MockConnection:
    def __init__(self, db: MockDB):
        self.db = db

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def cursor(self):
        return self

    def execute(self, query, params=None):
        self.db.execute(query, params)
        return self

    def fetchone(self):
        return self.db.fetchone()

    def fetchall(self):
        return self.db.fetchall()


@pytest.fixture
def mock_db():
    return MockDB()


@pytest.fixture
def kist_env(tmp_path, monkeypatch):
    kist_dir = tmp_path / ".kist"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("KIST_DIR", str(kist_dir))
    return {"home": tmp_path, "kist_dir": kist_dir}


PASSWORD = "test-profile-password-not-for-production"
CONTEXT = {"format": "test", "profile": "production"}


@pytest.fixture(scope="module")
def envelope():
    return encrypt_envelope(b"database:\n  password: example\n", PASSWORD, CONTEXT)


# --- Core envelope and serialization tests from test_core.py ---

def test_v1_round_trip(envelope):
    assert envelope[4] == 1
    assert decrypt_envelope(envelope, PASSWORD, CONTEXT) == b"database:\n  password: example\n"


def test_wrong_password(envelope):
    with pytest.raises(DecryptionError):
        decrypt_envelope(envelope, "wrong-password", CONTEXT)


def test_wrong_context(envelope):
    with pytest.raises(DecryptionError):
        decrypt_envelope(envelope, PASSWORD, {**CONTEXT, "profile": "other"})


@pytest.mark.parametrize("offset", [34, 46, 78, 126, -1])
def test_tamper(envelope, offset):
    corrupted = bytearray(envelope)
    corrupted[offset] ^= 1
    with pytest.raises((InvalidEnvelopeError, DecryptionError)):
        decrypt_envelope(bytes(corrupted), PASSWORD, CONTEXT)


def test_randomized(envelope):
    assert envelope != encrypt_envelope(b"database:\n  password: example\n", PASSWORD, CONTEXT)


def test_unsupported_format(envelope):
    changed = bytearray(envelope)
    changed[4] = 255
    with pytest.raises(InvalidEnvelopeError):
        decrypt_envelope(bytes(changed), PASSWORD, CONTEXT)


def test_kdf_limit(envelope):
    changed = bytearray(envelope)
    changed[8:12] = struct.pack(">I", 2 ** 32 - 1)
    with pytest.raises(InvalidEnvelopeError):
        decrypt_envelope(bytes(changed), PASSWORD, CONTEXT)


@pytest.mark.parametrize("value", [None, True, 42, 1.25, "é", [], {}, {"nested": [None, 1]}])
def test_json_types(value):
    assert _strict_json(_json_bytes(value)) == value


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1: "bad"}, (1, 2), b"bytes"])
def test_non_json_types(value):
    with pytest.raises(KistError):
        _json_bytes(value)


def test_mapping_round_trip():
    value = {"database": {"password": "x", "options": {}}, "list": [1, {"a": 2}], "null": None}
    assert Kist.unflatten(Kist.flatten(value)) == value


@pytest.mark.parametrize("value", [{"a": None, "a.b": 1}, {"a.b": 1, "a": {}}, {"a": {}, "a.b": 2}])
def test_path_conflicts(value):
    with pytest.raises(KistError):
        Kist.unflatten(value)


def test_duplicate_yaml():
    with pytest.raises(KistError, match="Duplicate YAML key"):
        yaml.load("a: 1\na: 2\n", Loader=_UniqueSafeLoader)


def test_yaml_merge_keys():
    yaml_text = """
credentials: &credentials
  username: admin
  password: secret_password

database:
  <<: *credentials
  host: db.internal
  port: 5432

analytics:
  <<: *credentials
  username: custom_analyst
  host: analytics.internal
"""
    data = yaml.load(yaml_text, Loader=_UniqueSafeLoader)
    assert data["database"] == {
        "username": "admin",
        "password": "secret_password",
        "host": "db.internal",
        "port": 5432,
    }
    assert data["analytics"] == {
        "username": "custom_analyst",
        "password": "secret_password",
        "host": "analytics.internal",
    }
    flattened = Kist.flatten(data)
    assert flattened["database.username"] == "admin"
    assert flattened["database.password"] == "secret_password"
    assert flattened["database.host"] == "db.internal"
    assert flattened["database.port"] == 5432
    assert flattened["analytics.username"] == "custom_analyst"
    assert flattened["analytics.password"] == "secret_password"
    assert flattened["analytics.host"] == "analytics.internal"


def test_yaml_merge_keys_with_explicit_duplicate_rejected():
    yaml_text = """
base: &base
  username: admin

service:
  <<: *base
  host: a
  host: b
"""
    with pytest.raises(KistError, match="Duplicate YAML key"):
        yaml.load(yaml_text, Loader=_UniqueSafeLoader)


def test_normalized_collision():
    with pytest.raises(KistError):
        Kist.flatten({"a": 1, " a ": 2})


def test_recursive_mapping():
    value = {}
    value["loop"] = value
    with pytest.raises(KistError):
        Kist.flatten(value)


def test_password_file(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX credential files only")
    tmp_path.chmod(0o700)
    path = tmp_path / "pwd_production"
    write_secure_local_password(path, PASSWORD)
    assert read_secure_local_password(path) == PASSWORD
    with pytest.raises(KistError):
        write_secure_local_password(path, "replacement")
    write_secure_local_password(path, "replacement", overwrite=True)
    assert read_secure_local_password(path) == "replacement"
    path.chmod(0o644)
    with pytest.raises(InsecureKeyStoreError):
        read_secure_local_password(path)


def test_url_masking():
    assert mask_db_url("postgresql://alice:password@localhost/db?token=secret#hidden") == "postgresql://localhost/db"
    assert mask_db_url("postgresql://myuser:mypass@db.prod.internal:5432/secrets_db") == "postgresql://db.prod.internal:5432/secrets_db"
    assert mask_db_url("") == ""
    assert mask_db_url(None) == ""


def test_production_tls(monkeypatch):
    monkeypatch.setenv("KIST_TLS_MODE", "disable")
    with pytest.raises(KistError):
        enforce_ssl_url("postgresql://localhost/db", production=True)


def test_unknown_version_two_rejected(envelope):
    changed = bytearray(envelope)
    changed[4] = 2
    with pytest.raises(InvalidEnvelopeError):
        decrypt_envelope(bytes(changed), PASSWORD, CONTEXT)


def test_format_identifiers():
    assert SCHEMA_VERSION == 1
    assert ENVELOPE_VERSION == 1
    assert KEY_MODE_PASSWORD == "password-wrap-v1"
    assert _ROW_MAGIC == b"KSTR\x01"
    assert "kist_v2_" not in SQL_SCHEMA
    assert "crypto_version = 1" in SQL_SCHEMA
    assert "version = 1" in SQL_SCHEMA
    assert not hasattr(Kist, "_reject_legacy")


def test_truncated_envelope(envelope):
    with pytest.raises(InvalidEnvelopeError):
        decrypt_envelope(envelope[:HEADER_SIZE + 16], PASSWORD, CONTEXT)


@pytest.fixture
def database_store():
    url = os.getenv("KIST_TEST_DATABASE_URL")
    if not url:
        pytest.skip("No disposable PostgreSQL test URL configured")
    scope = KistScope("test-" + uuid.uuid4().hex, "test")
    store = Kist("production", PASSWORD, url, scope)
    store.init_db()
    store.get_or_create_scope()
    try:
        yield store
    finally:
        with safe_db_connect(url) as connection:
            connection.execute("DELETE FROM kist_organizations WHERE id = %s", (store.organization_id,))


def test_database_roundtrip_and_rewrap(database_store):
    store = database_store
    assert store.set("database.password", "secret-value") == 1
    assert store.set("database.password", "replacement") == 2
    assert store.get("database.password") == "replacement"
    assert store.lock_yaml("market_data:\n  api_key: abc123\n", prune=True) == (1, 1)
    assert yaml.safe_load(store.unlock_yaml()) == {"market_data": {"api_key": "abc123"}}
    old_reader = Kist("production", PASSWORD, store.db_url, store.scope)
    store.rewrap_profile_password("new-profile-password")
    assert store.get("market_data.api_key") == "abc123"
    with pytest.raises(DecryptionError):
        old_reader.get("market_data.api_key")
    assert store.delete("market_data.api_key") is True
    assert store.delete("market_data.api_key") is False


def test_database_first_write_concurrency(database_store):
    from concurrent.futures import ThreadPoolExecutor
    store = database_store
    def write(index):
        independent = Kist("production", PASSWORD, store.db_url, store.scope)
        return independent.set("concurrent.key", index)
    with ThreadPoolExecutor(max_workers=4) as executor:
        versions = list(executor.map(write, range(8)))
    assert sorted(versions) == list(range(1, 9))
    assert store.get("concurrent.key") in range(8)


# --- Password Generation & Management ---

def test_generate_password():
    pwd1 = generate_password()
    pwd2 = generate_password()
    assert len(pwd1) > 20
    assert pwd1 != pwd2


def test_get_kist_dir(monkeypatch):
    monkeypatch.setenv("HOME", "/custom/home")
    monkeypatch.delenv("KIST_DIR", raising=False)
    assert get_kist_dir() == "/custom/home/.kist"

    monkeypatch.setenv("KIST_DIR", "/override/dir")
    assert get_kist_dir() == "/override/dir"


def test_get_profile_password_from_env_specific(kist_env, monkeypatch):
    monkeypatch.setenv("KIST_PASSWORD_ALPHA", "custom_alpha_secret")
    pwd = get_profile_password("alpha")
    assert pwd == "custom_alpha_secret"
    assert not (kist_env["kist_dir"] / "pwd_alpha").exists()


def test_get_profile_password_from_env_default(kist_env, monkeypatch):
    monkeypatch.setenv("KIST_PASSWORD_DEFAULT", "custom_default_secret")
    pwd = get_profile_password("default")
    assert pwd == "custom_default_secret"
    assert not (kist_env["kist_dir"] / "pwd_default").exists()


def test_get_profile_password_from_env_fallback(kist_env, monkeypatch):
    monkeypatch.delenv("KIST_PASSWORD_BETA", raising=False)
    monkeypatch.setenv("KIST_PASSWORD", "global_secret")
    pwd = get_profile_password("beta")
    assert pwd == "global_secret"
    assert not (kist_env["kist_dir"] / "pwd_beta").exists()


def test_create_and_read_profile_password_from_kist_folder(kist_env):
    created_pwd = create_profile_password("gamma")
    assert len(created_pwd) > 20
    pwd_file = kist_env["kist_dir"] / "pwd_gamma"
    assert pwd_file.exists()

    loaded_pwd = get_profile_password("gamma")
    assert loaded_pwd == created_pwd


def test_implicit_auto_generate_disabled(kist_env):
    with pytest.raises(KistError):
        get_profile_password("delta", auto_generate=True)


def test_get_profile_and_password_resolution(kist_env):
    create_profile_password("default")
    create_profile_password("staging")

    prof_def, pwd_def = get_profile_and_password("secrets.yaml")
    assert prof_def == "default"
    assert pwd_def is not None

    prof_stg, pwd_stg = get_profile_and_password("secrets_staging.yaml")
    assert prof_stg == "staging"
    assert pwd_stg is not None

    prof_raw, _ = get_profile_and_password("secrets_my_team")
    assert prof_raw == "my_team"

    prof_sub, _ = get_profile_and_password("secrets/secrets_team_b.yaml")
    assert prof_sub == "team_b"


def test_resolve_secret_file_path_direct_and_extension(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(exist_ok=True)

    (secrets_dir / "secrets_team_c.yaml").write_text("a: 1\n", encoding="utf-8")
    (tmp_path / "secrets_root.yaml").write_text("b: 2\n", encoding="utf-8")

    assert resolve_secret_file_path("secrets_root") == "secrets_root.yaml"
    assert resolve_secret_file_path("secrets_root.yaml") == "secrets_root.yaml"

    assert resolve_secret_file_path("secrets_team_c") == "secrets/secrets_team_c.yaml"
    assert resolve_secret_file_path("secrets_team_c.yaml") == "secrets/secrets_team_c.yaml"
    assert resolve_secret_file_path("secrets/secrets_team_c.yaml") == "secrets/secrets_team_c.yaml"


def test_envelope_encryption_and_decryption():
    plaintext = b"sensitive_secret_payload"
    password = "strong_password_test"
    ctx = {"profile": "prod", "env": "cloud"}

    envelope = encrypt_envelope(plaintext, password, ctx)
    assert is_kist_envelope(envelope)
    assert len(envelope) > 78

    # Decrypt success
    decrypted = decrypt_envelope(envelope, password, ctx)
    assert decrypted == plaintext

    # Decrypt failure with wrong password
    with pytest.raises(DecryptionError):
        decrypt_envelope(envelope, "wrong_password", ctx)

    # Decrypt failure with wrong context (AAD mismatch)
    wrong_ctx = {"profile": "prod", "env": "local"}
    with pytest.raises(DecryptionError):
        decrypt_envelope(envelope, password, wrong_ctx)


def test_git_clean_and_smudge_stream_roundtrip():
    plaintext = "database:\n  host: 127.0.0.1\n  port: 5432\n  ssl: true\n"
    password = "my_git_password_123"

    # 1. Clean (Encrypt)
    in_clean = io.StringIO(plaintext)
    out_clean = io.BytesIO()
    git_clean_stream("production", password=password, in_stream=in_clean, out_stream=out_clean, filepath="secrets_production.yaml")

    encrypted_bytes = out_clean.getvalue()
    assert is_kist_envelope(encrypted_bytes)

    # Re-encrypting produces fresh salt and different ciphertext
    in_clean2 = io.StringIO(plaintext)
    out_clean2 = io.BytesIO()
    git_clean_stream("production", password=password, in_stream=in_clean2, out_stream=out_clean2, filepath="secrets_production.yaml")
    encrypted_bytes2 = out_clean2.getvalue()
    assert encrypted_bytes != encrypted_bytes2

    # 2. Smudge (Decrypt)
    in_smudge = io.BytesIO(encrypted_bytes)
    out_smudge = io.StringIO()
    git_smudge_stream("production", password=password, in_stream=in_smudge, out_stream=out_smudge, filepath="secrets_production.yaml")

    assert out_smudge.getvalue() == plaintext


def test_leak_guard_detects_plaintext_and_permits_encrypted():
    with patch("subprocess.run") as mock_run:
        mock_diff = MagicMock()
        mock_diff.stdout = "secrets.yaml\n"
        mock_diff.returncode = 0

        # Content is plaintext
        mock_show_plain = MagicMock()
        mock_show_plain.stdout = b"api_key: plain_text_secret\n"
        mock_show_plain.returncode = 0

        # git check-attr unavailable: the guard falls back to the built-in secret names
        mock_attr = MagicMock()
        mock_attr.stdout = b""
        mock_attr.returncode = 1

        mock_run.side_effect = [mock_diff, mock_attr, mock_show_plain]
        with patch("sys.stderr", new_callable=io.StringIO):
            code = run_leak_guard()
        assert code == 1

        # Staged file with valid envelope
        ctx = git_context("default", "secrets.yaml")
        valid_envelope = encrypt_envelope(b"api_key: encrypted\n", "password", ctx)
        mock_show_encrypted = MagicMock()
        mock_show_encrypted.stdout = valid_envelope
        mock_show_encrypted.returncode = 0

        mock_run.side_effect = [mock_diff, mock_attr, mock_show_encrypted]
        code2 = run_leak_guard()
        assert code2 == 0

        # Staged Python package file inside secrets/ directory (e.g. secrets/__init__.py)
        mock_diff_py = MagicMock()
        mock_diff_py.stdout = "secrets/__init__.py\n"
        mock_diff_py.returncode = 0

        mock_show_py = MagicMock()
        mock_show_py.stdout = b"# package initialization\n__all__ = []\n"
        mock_show_py.returncode = 0

        mock_run.side_effect = [mock_diff_py, mock_attr, mock_show_py]
        code3 = run_leak_guard()
        assert code3 == 0


def test_is_targeted_secret():
    from kist.git import _is_targeted_secret

    # Must match secret YAML/YML files
    assert _is_targeted_secret("secrets.yaml") is True
    assert _is_targeted_secret("secrets.yml") is True
    assert _is_targeted_secret("secrets_production.yaml") is True
    assert _is_targeted_secret("secrets_team_a.yml") is True
    assert _is_targeted_secret("secrets/default.yaml") is True
    assert _is_targeted_secret("secrets/team_a.yml") is True
    assert _is_targeted_secret("secrets/subdir/prod.yaml") is True
    assert _is_targeted_secret("path/to/secrets/team_b.yaml") is True

    # Must NOT match non-YAML files even inside secrets/ folder
    assert _is_targeted_secret("secrets/__init__.py") is False
    assert _is_targeted_secret("secrets/config.py") is False
    assert _is_targeted_secret("secrets/README.md") is False
    assert _is_targeted_secret("secrets/keys.json") is False
    assert _is_targeted_secret("secrets/schema.sql") is False


def test_leak_guard_ignores_code_calls_and_placeholders_and_detects_secrets():
    from kist.git import _has_likely_credential

    # False positives that must NOT trigger
    assert not _has_likely_credential('api_key = store.get("example.api_key")', "README.md")
    assert not _has_likely_credential("api_key: sk_example_value", "README.md")
    assert not _has_likely_credential('api_key = os.getenv("API_KEY")', "app.py")
    assert not _has_likely_credential('api_key = os.environ["API_KEY"]', "app.py")
    assert not _has_likely_credential('api_key: str = ""', "types.py")
    assert not _has_likely_credential("api_key: <your_key_here>", "docs.md")
    assert not _has_likely_credential("db_password: dummy_password_value", "config.yaml")

    # True positives that MUST trigger
    assert _has_likely_credential('stripe_api_key = "sk_live_98234729384729384"', "app.py")
    assert _has_likely_credential("API_KEY=98234729384729384", ".env")
    assert _has_likely_credential('db_password: "real_production_secret_pass"', "config.yaml")
    assert _has_likely_credential("AKIAIOSFODNN7EXAMPLE", "deploy.tf")
    assert _has_likely_credential("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...", "server.key")


def test_flatten_and_unflatten_nested_and_types():
    kist_inst = Kist(profile_name="types_test", password="pwd", db_url="")
    data = {
        "server": {
            "port": 8080,
            "debug": True,
            "timeout": 2.5,
            "tags": ["prod", "us-east"],
            "admin": None,
        },
        "name": "myapp",
    }

    flat = kist_inst.flatten(data)
    assert flat["server.port"] == 8080
    assert flat["server.debug"] is True
    assert flat["server.timeout"] == 2.5
    assert flat["server.tags"] == ["prod", "us-east"]
    assert flat["server.admin"] is None
    assert flat["name"] == "myapp"

    unflat = kist_inst.unflatten(flat)
    assert unflat == data


# --- Database Operations with Mock DB ---

def test_lock_yaml_type_preservation_and_prune(mock_db):
    with patch("psycopg.connect", side_effect=lambda *a, **kw: MockConnection(mock_db)):
        kist_inst = Kist(profile_name="test_prof", password="password", db_url="postgresql://mock")

        yaml_content = """
        db:
          host: localhost
          port: 5432
          enabled: true
        """
        # Initial lock: 3 secrets added, 0 pruned
        locked_cnt, pruned_cnt = kist_inst.lock_yaml(yaml_content, prune=True)
        assert locked_cnt == 3
        assert pruned_cnt == 0
        assert len(mock_db.advisory_locks) > 0

        # Second lock with fewer keys and prune=True: 2 kept, 1 pruned
        yaml_content2 = """
        db:
          host: localhost
          port: 5432
        """
        locked_cnt2, pruned_cnt2 = kist_inst.lock_yaml(yaml_content2, prune=True)
        assert locked_cnt2 == 2
        assert pruned_cnt2 == 1


def test_kist_set_and_get_lifecycle(mock_db):
    with patch("psycopg.connect", side_effect=lambda *a, **kw: MockConnection(mock_db)):
        kist_inst = Kist(profile_name="prod", password="secret_password", db_url="postgresql://mock")

        # Set key
        version1 = kist_inst.set("app.api_key", "secret-value-123")
        assert version1 == 1

        # Update key
        version2 = kist_inst.set("app.api_key", "secret-value-456")
        assert version2 == 2

        # Get key
        retrieved = kist_inst.get("app.api_key")
        assert retrieved == "secret-value-456"

        # Missing key raises KeyError
        with pytest.raises(KeyError):
            kist_inst.get("nonexistent.key")


def test_kist_set_retry_on_serialization_failure(mock_db):
    first_attempt = True

    class FlakyMockConnection(MockConnection):
        def execute(self, query, params=None):
            nonlocal first_attempt
            if first_attempt and "SET TRANSACTION" in str(query):
                first_attempt = False
                raise psycopg.errors.SerializationFailure("could not serialize access")
            return super().execute(query, params)

    with patch("psycopg.connect", side_effect=lambda *a, **kw: FlakyMockConnection(mock_db)):
        kist_inst = Kist(profile_name="prod", password="secret_password", db_url="postgresql://mock")
        version = kist_inst.set("app.api_key", "secret-value-123", max_retries=3)
        assert version == 1
        assert not first_attempt


def test_kist_set_exhausted_retries_raises_concurrent_write_error(mock_db):
    class AlwaysFailingMockConnection(MockConnection):
        def execute(self, query, params=None):
            if "SET TRANSACTION" in str(query):
                raise psycopg.errors.SerializationFailure("serialization error")
            return super().execute(query, params)

    with patch("psycopg.connect", side_effect=lambda *a, **kw: AlwaysFailingMockConnection(mock_db)):
        kist_inst = Kist(profile_name="prod", password="secret_password", db_url="postgresql://mock")
        with pytest.raises(ConcurrentWriteError):
            kist_inst.set("app.api_key", "secret-value-123", max_retries=2)


def test_unlock_yaml_type_reconstruction(mock_db):
    with patch("psycopg.connect", side_effect=lambda *a, **kw: MockConnection(mock_db)):
        kist_inst = Kist(profile_name="test_prof", password="password", db_url="postgresql://mock")

        yaml_content = """
        app:
          env: production
          port: 5432
          ssl: true
        """
        kist_inst.lock_yaml(yaml_content)

        unlocked_yaml = kist_inst.unlock_yaml()
        loaded = yaml.safe_load(unlocked_yaml)
        assert loaded["app"]["env"] == "production"
        assert loaded["app"]["port"] == 5432
        assert loaded["app"]["ssl"] is True


def test_kist_delete_and_rewrap_with_mock_db(mock_db):
    with patch("psycopg.connect", side_effect=lambda *a, **kw: MockConnection(mock_db)):
        kist_inst = Kist(profile_name="prod", password="old_password", db_url="postgresql://mock")

        kist_inst.set("market_data.api_key", "secret_key_abc")
        assert kist_inst.get("market_data.api_key") == "secret_key_abc"

        # Rewrap with new password
        kist_inst.rewrap_profile_password("new_password")
        assert kist_inst.get("market_data.api_key") == "secret_key_abc"

        # Reader with old password fails decryption
        old_reader = Kist(profile_name="prod", password="old_password", db_url="postgresql://mock")
        with pytest.raises(DecryptionError):
            old_reader.get("market_data.api_key")

        # Delete key
        assert kist_inst.delete("market_data.api_key") is True
        assert kist_inst.delete("market_data.api_key") is False


def test_status_scopes_to_repository_files_only(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    kist_dir = tmp_path / ".kist"
    kist_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("KIST_DIR", str(kist_dir))

    # Create several global keys that have no corresponding YAML in this repository
    (kist_dir / "pwd_unrelated_team").write_text("key1")
    (kist_dir / "pwd_legacy_profile").write_text("key2")
    (kist_dir / "pwd_production").write_text("key3")

    # Create secrets folder with repo-specific secret file
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    (secrets_dir / "production.yaml").write_text("api_key: encrypted")
    (secrets_dir / "staging.yaml").write_text("api_key: encrypted")

    # Run status in mock git repo environment
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "true"
        (tmp_path / ".gitattributes").write_text("filter=kist\n")
        (tmp_path / ".gitignore").write_text(".kist/\n")
        (tmp_path / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
        (tmp_path / ".git" / "hooks" / "pre-commit").write_text("# kist-managed-hook-v1\n")

        run_status()

    captured = capsys.readouterr().out
    # Check that unrelated profiles from ~/.kist are NOT in output
    assert "unrelated_team" not in captured
    assert "legacy_profile" not in captured
    assert "no matching YAML file" not in captured

    # Check that repo files are present with accurate key source
    assert "production: secrets/production.yaml; password source: local password file" in captured
    assert "staging: secrets/staging.yaml; password source: MISSING" in captured


def test_run_fix_workflow(capsys):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        run_fix(apply=True)
    out = capsys.readouterr().out
    assert "Kist repair completed" in out


def test_run_diagnose_workflow(capsys):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "filter=kist"
        from kist.fix import run_diagnose
        run_diagnose()
    out = capsys.readouterr().out
    assert "Kist diagnostics" in out


def test_print_hook(capsys):
    from kist.git import print_hook
    print_hook()
    out = capsys.readouterr().out
    assert "#!/usr/bin/env sh" in out
    assert "kist pre-commit-guard" in out
    assert ".venv/bin/kist" in out
    assert "uv run kist" in out


def test_run_git_setup_installs_filters_attributes_and_hooks(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    git_dir = tmp_path / ".git"
    (git_dir / "hooks").mkdir(parents=True, exist_ok=True)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        run_git_setup(install_hook=True)

    assert (tmp_path / ".gitattributes").exists()
    assert (tmp_path / ".gitignore").exists()
    hook_file = git_dir / "hooks" / "pre-commit"
    assert hook_file.exists()
    content = hook_file.read_text()
    assert content.startswith("#!/usr/bin/env sh")
    assert ".venv/bin/kist" in content
    assert "uv run kist" in content
    captured = capsys.readouterr()
    assert "Run 'kist init-db'" in captured.out


def test_run_git_setup_updates_older_kist_hook(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    git_dir = tmp_path / ".git"
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    old_hook = hooks_dir / "pre-commit"
    old_hook.write_text("#!/usr/bin/env sh\n# kist-managed-hook-v1\nexec kist pre-commit-guard\n")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        run_git_setup(install_hook=True)

    content = old_hook.read_text()
    assert ".venv/bin/kist" in content
    assert "uv run kist" in content
    captured = capsys.readouterr()
    assert "pre-commit hook" in captured.out


def test_enforce_ssl_url():
    assert enforce_ssl_url("postgresql://localhost/db") == "postgresql://localhost/db?sslmode=require"
    assert enforce_ssl_url("postgresql://localhost/db?sslmode=disable") == "postgresql://localhost/db?sslmode=disable"
    assert enforce_ssl_url(None) is None


def test_safe_db_connect_enforces_ssl_and_masks_errors():
    url = "postgresql://admin:supersecret@db.internal:5432/production"
    with patch("psycopg.connect") as mock_connect:
        safe_db_connect(url)
        called_url = mock_connect.call_args[0][0]
        assert "sslmode=require" in called_url

        # Connection error masking
        mock_connect.side_effect = psycopg.OperationalError("connection refused")
        with pytest.raises(psycopg.OperationalError) as exc_info:
            safe_db_connect(url)
        assert "supersecret" not in str(exc_info.value)
        assert "db.internal:5432/production" in str(exc_info.value)


# --- KMS Tests ---

def test_kms_local_provider_roundtrip(tmp_path):
    kek = os.urandom(32)
    provider = LocalKMSProvider(kek=kek)
    key_ref = KMSKeyReference(provider="local", key_id="master-key-01")
    plaintext = b"super_secret_data_key_32_bytes!!"
    context = {"tenant": "test-corp", "env": "prod"}

    wrapped = provider.wrap_key(
        plaintext_key=plaintext,
        key_reference=key_ref,
        encryption_context=context,
    )
    assert wrapped.provider == "local"
    assert wrapped.key_reference.key_id == "master-key-01"
    assert wrapped.ciphertext != plaintext

    decrypted = provider.unwrap_key(wrapped)
    assert decrypted == plaintext

    # Wrong context
    wrong_wrapped = WrappedDataKey(
        provider="local",
        key_reference=key_ref,
        ciphertext=wrapped.ciphertext,
        encryption_context={"tenant": "other-corp", "env": "prod"},
    )
    with pytest.raises(KMSProviderError):
        provider.unwrap_key(wrong_wrapped)


def test_kms_provider_factory():
    kek = os.urandom(32)
    local_p = get_kms_provider("local", kek=kek)
    assert isinstance(local_p, LocalKMSProvider)

    with pytest.raises(KMSProviderError):
        get_kms_provider("unknown-provider")


# --- CLI Lock and Mismatch Tests ---

def test_cli_lock_profile_mismatch_rejected(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    staging_file = secrets_dir / "staging.yaml"
    staging_file.write_text("db.host: localhost\n")

    monkeypatch.setattr(sys, "argv", ["kist", "--profile", "production", "lock", "secrets/staging.yaml"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Error: Profile/file mismatch detected." in captured.err
    assert "Profile 'production' does not match target file 'secrets/staging.yaml'." in captured.err
    assert "To prevent accidental data corruption or pruning, this operation is blocked." in captured.err


def test_cli_lock_profile_mismatch_allowed_with_flag(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KIST_PASSWORD", "test_secret_key_123")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    custom_seed = secrets_dir / "custom_seed.yaml"
    custom_seed.write_text("db.host: localhost\n")

    monkeypatch.setattr(
        sys,
        "argv",
        ["kist", "--profile", "production", "lock", "secrets/custom_seed.yaml", "--allow-mismatch"],
    )

    with patch.object(Kist, "lock_yaml", return_value=(1, 0)) as mock_lock:
        main()
        mock_lock.assert_called_once()
        captured = capsys.readouterr()
        assert "Locked 1 secrets for local/default/production." in captured.out


def test_cli_lock_profile_mismatch_allowed_with_force(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KIST_PASSWORD", "test_secret_key_123")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    custom_seed = secrets_dir / "custom_seed.yaml"
    custom_seed.write_text("db.host: localhost\n")

    monkeypatch.setattr(
        sys,
        "argv",
        ["kist", "--profile", "production", "lock", "secrets/custom_seed.yaml", "--force"],
    )

    with patch.object(Kist, "lock_yaml", return_value=(1, 0)) as mock_lock:
        main()
        mock_lock.assert_called_once()
        captured = capsys.readouterr()
        assert "Locked 1 secrets for local/default/production." in captured.out


def test_cli_lock_matching_profile_succeeds(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KIST_PASSWORD", "test_secret_key_123")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    prod_file = secrets_dir / "production.yaml"
    prod_file.write_text("db.host: localhost\n")

    monkeypatch.setattr(
        sys,
        "argv",
        ["kist", "--profile", "production", "lock", "secrets/production.yaml"],
    )

    with patch.object(Kist, "lock_yaml", return_value=(2, 0)) as mock_lock:
        main()
        mock_lock.assert_called_once()
        captured = capsys.readouterr()
        assert "Locked 2 secrets for local/default/production." in captured.out


def test_cli_lock_prune_interactive_cancelled(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KIST_PASSWORD", "test_secret_key_123")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    prod_file = secrets_dir / "production.yaml"
    prod_file.write_text("db.host: localhost\n")

    monkeypatch.setattr(sys, "argv", ["kist", "lock", "secrets/production.yaml", "--prune"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "prune operation cancelled" in captured.err


def test_cli_lock_prune_interactive_confirmed(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KIST_PASSWORD", "test_secret_key_123")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    prod_file = secrets_dir / "production.yaml"
    prod_file.write_text("db.host: localhost\n")

    monkeypatch.setattr(sys, "argv", ["kist", "lock", "secrets/production.yaml", "--prune"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")

    with patch.object(Kist, "lock_yaml", return_value=(2, 1)) as mock_lock:
        main()
        mock_lock.assert_called_once_with("db.host: localhost\n", prune=True)
        captured = capsys.readouterr()
        assert "Locked 2 secrets for local/default/production. Pruned 1." in captured.out


def test_cli_lock_prune_force_bypasses_interactive_prompt(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KIST_PASSWORD", "test_secret_key_123")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    prod_file = secrets_dir / "production.yaml"
    prod_file.write_text("db.host: localhost\n")

    monkeypatch.setattr(sys, "argv", ["kist", "lock", "secrets/production.yaml", "--prune", "--force"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: (_ for _ in ()).throw(AssertionError("Should not prompt")))

    with patch.object(Kist, "lock_yaml", return_value=(2, 1)) as mock_lock:
        main()
        mock_lock.assert_called_once_with("db.host: localhost\n", prune=True)
        captured = capsys.readouterr()
        assert "Locked 2 secrets for local/default/production. Pruned 1." in captured.out


def test_cli_init_db_invokes_store_init_db(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["kist", "init-db"])
    with patch.object(Kist, "init_db") as mock_init_db:
        main()
        mock_init_db.assert_called_once()
        captured = capsys.readouterr()
        assert "Kist database schema initialized successfully." in captured.out


def test_cli_init_db_with_scope_flags(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["kist", "--org", "myorg", "--project", "myproj", "--profile", "staging", "init-db"],
    )
    with patch.object(Kist, "init_db") as mock_init_db:
        main()
        mock_init_db.assert_called_once()
        captured = capsys.readouterr()
        assert "Kist database schema initialized successfully." in captured.out


def test_resolve_secret_file_path_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(exist_ok=True)

    (secrets_dir / "default.yaml").write_text("a: 1\n", encoding="utf-8")
    assert resolve_secret_file_path() == "secrets/default.yaml"

    (secrets_dir / "team_a.yaml").write_text("b: 2\n", encoding="utf-8")
    monkeypatch.setenv("KIST_PROFILE", "team_a")
    assert resolve_secret_file_path() == "secrets/team_a.yaml"

    (tmp_path / "secrets_team_b.yaml").write_text("c: 3\n", encoding="utf-8")
    assert resolve_secret_file_path(profile="team_b") == "secrets_team_b.yaml"


def test_cli_lock_defaults_to_active_profile(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KIST_PASSWORD", "test_secret_key_123")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)

    # 1. Default profile with secrets/default.yaml
    (secrets_dir / "default.yaml").write_text("db.host: localhost\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["kist", "lock"])

    with patch.object(Kist, "lock_yaml", return_value=(1, 0)) as mock_lock:
        main()
        mock_lock.assert_called_once_with("db.host: localhost\n", prune=False)
        captured = capsys.readouterr()
        assert "Locked 1 secrets for local/default/default." in captured.out

    # 2. Team profile via KIST_PROFILE
    monkeypatch.setenv("KIST_PROFILE", "team_a")
    (secrets_dir / "team_a.yaml").write_text("team.key: secret\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["kist", "lock"])

    with patch.object(Kist, "lock_yaml", return_value=(1, 0)) as mock_lock:
        main()
        mock_lock.assert_called_once_with("team.key: secret\n", prune=False)
        captured = capsys.readouterr()
        assert "Locked 1 secrets for local/default/team_a." in captured.out

    # 3. Explicit --profile flag without file argument
    (secrets_dir / "team_b.yaml").write_text("team.b: value\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["kist", "--profile", "team_b", "lock"])

    with patch.object(Kist, "lock_yaml", return_value=(1, 0)) as mock_lock:
        main()
        mock_lock.assert_called_once_with("team.b: value\n", prune=False)
        captured = capsys.readouterr()
        assert "Locked 1 secrets for local/default/team_b." in captured.out


def test_cli_lock_missing_default_file_raises_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KIST_PASSWORD", "test_secret_key_123")
    monkeypatch.setattr(sys, "argv", ["kist", "lock"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Secret file not found: secrets.yaml" in captured.err or "Secret file not found: secrets/default.yaml" in captured.err


def test_cli_unlock_defaults_to_active_profile(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KIST_PASSWORD", "test_secret_key_123")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    (secrets_dir / "default.yaml").write_text("a: 1\n", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["kist", "unlock"])

    with patch.object(Kist, "unlock_yaml", return_value="a: 1\n") as mock_unlock:
        main()
        mock_unlock.assert_called_once()
        captured = capsys.readouterr()
        assert "a: 1\n" in captured.out


def test_kist_version():
    from pathlib import Path
    import tomllib
    import kist

    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with pyproject_path.open("rb") as f:
        expected_version = tomllib.load(f)["project"]["version"]
    assert kist.__version__ == expected_version


def test_kist_class_defaults_to_kist_profile_env(monkeypatch):
    monkeypatch.setenv("KIST_PROFILE", "team_a")
    k = Kist()
    assert k.profile_name == "team_a"


def test_remove_profile_password(tmp_path, monkeypatch):
    kist_dir = tmp_path / ".kist"
    monkeypatch.setenv("KIST_DIR", str(kist_dir))
    with patch("sys.stdout.isatty", return_value=True):
        create_profile_password("test_del_prof")
    key_path = kist_dir / "pwd_test_del_prof"
    assert key_path.exists()

    assert remove_profile_password("test_del_prof") is True
    assert not key_path.exists()
    assert remove_profile_password("test_del_prof") is False


def test_kist_delete_profile_in_db(mock_db):
    with patch("psycopg.connect", side_effect=lambda *a, **kw: MockConnection(mock_db)):
        kist_inst = Kist(profile_name="team_x", password="pwd", db_url="postgresql://mock")
        kist_inst.set("db.password", "secret")
        assert kist_inst.get("db.password") == "secret"

        assert kist_inst.delete_profile("team_x") is True
        assert kist_inst.delete_profile("team_x") is False

        with pytest.raises(KeyError):
            kist_inst.get("db.password")


def test_cli_delete_secret(mock_db, monkeypatch, capsys):
    with patch("psycopg.connect", side_effect=lambda *a, **kw: MockConnection(mock_db)):
        kist_inst = Kist(profile_name="default", password="pwd", db_url="postgresql://mock")
        kist_inst.set("stripe.api_key", "sk_live_123")
        monkeypatch.setenv("KIST_PASSWORD", "pwd")

        monkeypatch.setattr(sys, "argv", ["kist", "delete", "stripe.api_key", "--force"])
        main()
        captured = capsys.readouterr()
        assert "Deleted secret 'stripe.api_key' for local/default/default." in captured.out

        with pytest.raises(SystemExit) as exc_info:
            monkeypatch.setattr(sys, "argv", ["kist", "delete", "stripe.api_key", "--force"])
            main()
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Secret 'stripe.api_key' not found" in captured.err


def test_cli_profile_delete(mock_db, tmp_path, monkeypatch, capsys):
    kist_dir = tmp_path / ".kist"
    monkeypatch.setenv("KIST_DIR", str(kist_dir))
    with patch("sys.stdout.isatty", return_value=True):
        create_profile_password("team_y")

    with patch("psycopg.connect", side_effect=lambda *a, **kw: MockConnection(mock_db)):
        kist_inst = Kist(profile_name="team_y", password="pwd", db_url="postgresql://mock")
        kist_inst.set("k", "v")

        monkeypatch.setattr(sys, "argv", ["kist", "profile", "delete", "team_y", "--delete-password", "--force"])
        main()
        captured = capsys.readouterr()
        assert "Deleted profile 'team_y' for local/default from database." in captured.out
        assert "Removed local password file." in captured.out
        assert not (kist_dir / "pwd_team_y").exists()


def test_cli_profile_remove_key(tmp_path, monkeypatch, capsys):
    kist_dir = tmp_path / ".kist"
    monkeypatch.setenv("KIST_DIR", str(kist_dir))
    with patch("sys.stdout.isatty", return_value=True):
        create_profile_password("key_only")

    monkeypatch.setattr(sys, "argv", ["kist", "profile", "remove-password", "key_only", "--force"])
    main()
    captured = capsys.readouterr()
    assert "Removed local password file for profile 'key_only'." in captured.out
    assert not (kist_dir / "pwd_key_only").exists()

    with pytest.raises(SystemExit) as exc_info:
        monkeypatch.setattr(sys, "argv", ["kist", "profile", "remove-password", "key_only", "--force"])
        main()
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Local password file for profile 'key_only' not found." in captured.err


def test_cli_version_flag(capsys, monkeypatch):
    from importlib.metadata import version

    from kist.cli import main

    monkeypatch.setattr(sys, "argv", ["kist", "--version"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"kist {version('kist')}"


# --- Password lookup: a generic KIST_PASSWORD never overrides another profile's own password ---

def _clear_password_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("KIST_PASSWORD") or name == "KIST_PROFILE":
            monkeypatch.delenv(name, raising=False)


def test_local_file_beats_generic_password(kist_env, monkeypatch):
    _clear_password_env(monkeypatch)
    create_profile_password("jpn")
    own = (kist_env["kist_dir"] / "pwd_jpn").read_text().strip()
    monkeypatch.setenv("KIST_PASSWORD", "generic-password-for-another-profile")
    assert get_profile_password("jpn") == own
    assert get_profile_password("no_file_profile") == "generic-password-for-another-profile"


def test_generic_password_belongs_to_kist_profile(kist_env, monkeypatch):
    _clear_password_env(monkeypatch)
    create_profile_password("usa")
    monkeypatch.setenv("KIST_PROFILE", "usa")
    monkeypatch.setenv("KIST_PASSWORD", "usa-password-from-env")
    assert get_profile_password("usa") == "usa-password-from-env"      # explicit env beats the file
    assert get_profile_password("jpn") is None                           # never borrowed by other profiles


def test_profile_specific_variable_accepts_exact_case(kist_env, monkeypatch):
    _clear_password_env(monkeypatch)
    monkeypatch.setenv("KIST_PASSWORD_ma_jpn", "exact-case-password")
    assert get_profile_password("ma_jpn") == "exact-case-password"
    monkeypatch.setenv("KIST_PASSWORD_MA_JPN", "upper-case-password")
    assert get_profile_password("ma_jpn") == "upper-case-password"
