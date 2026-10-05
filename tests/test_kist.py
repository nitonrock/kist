import io
import json
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg
import pytest
import yaml

from kist import (
    Kist,
    create_profile_key,
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
    ConcurrentWriteError,
    DecryptionError,
    InsecureKeyStoreError,
    InvalidEnvelopeError,
    KistError,
    KistScope,
    MissingKeyError,
)
from kist.kms import (
    KMSKeyReference,
    KMSProviderError,
    LocalKMSProvider,
    WrappedDataKey,
    get_kms_provider,
)


@pytest.fixture
def kist_env(tmp_path, monkeypatch):
    kist_dir = tmp_path / ".kist"
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("KIST_DIR", str(kist_dir))
    return {"home": tmp_path, "kist_dir": kist_dir}


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
    created_pwd = create_profile_key("gamma")
    assert len(created_pwd) > 20
    pwd_file = kist_env["kist_dir"] / "pwd_gamma"
    assert pwd_file.exists()

    loaded_pwd = get_profile_password("gamma")
    assert loaded_pwd == created_pwd


def test_implicit_auto_generate_disabled(kist_env):
    with pytest.raises(KistError):
        get_profile_password("delta", auto_generate=True)


def test_get_profile_and_password_resolution(kist_env):
    create_profile_key("default")
    create_profile_key("staging")

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
    password = "strong_master_password_test"
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
    git_clean_stream("production", master_password=password, in_stream=in_clean, out_stream=out_clean, filepath="secrets_production.yaml")

    encrypted_bytes = out_clean.getvalue()
    assert is_kist_envelope(encrypted_bytes)

    # Re-encrypting produces fresh salt and different ciphertext
    in_clean2 = io.StringIO(plaintext)
    out_clean2 = io.BytesIO()
    git_clean_stream("production", master_password=password, in_stream=in_clean2, out_stream=out_clean2, filepath="secrets_production.yaml")
    encrypted_bytes2 = out_clean2.getvalue()
    assert encrypted_bytes != encrypted_bytes2

    # 2. Smudge (Decrypt)
    in_smudge = io.BytesIO(encrypted_bytes)
    out_smudge = io.StringIO()
    git_smudge_stream("production", master_password=password, in_stream=in_smudge, out_stream=out_smudge, filepath="secrets_production.yaml")

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

        mock_run.side_effect = [mock_diff, mock_show_plain]
        with patch("sys.stderr", new_callable=io.StringIO):
            code = run_leak_guard()
        assert code == 1

        # Staged file with valid envelope
        ctx = git_context("default", "secrets.yaml")
        valid_envelope = encrypt_envelope(b"api_key: encrypted\n", "password", ctx)
        mock_show_encrypted = MagicMock()
        mock_show_encrypted.stdout = valid_envelope
        mock_show_encrypted.returncode = 0

        mock_run.side_effect = [mock_diff, mock_show_encrypted]
        code2 = run_leak_guard()
        assert code2 == 0


def test_flatten_and_unflatten_nested_and_types():
    kist_inst = Kist(profile_name="types_test", master_password="pwd", db_url="")
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


@patch("psycopg.connect")
def test_lock_yaml_type_preservation_and_prune(mock_connect):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    prof_id = uuid.uuid4()

    # Mock get_or_create_scope queries
    mock_cursor.fetchone.side_effect = [
        (org_id,),   # org
        (proj_id,),  # project
        (prof_id,),  # profile
        None,        # secret_version key 1
        None,        # secret_version key 2
        None,        # secret_version key 3
    ]

    kist_inst = Kist(profile_name="test_prof", master_password="password", db_url="postgresql://mock")

    # Mock existing keys for pruning: old_key is obsolete
    mock_cursor.fetchall.return_value = [("db.host",), ("old_key",)]

    yaml_content = """
    db:
      host: localhost
      port: 5432
      enabled: true
    """
    locked_cnt, pruned_cnt = kist_inst.lock_yaml(yaml_content, prune=True)
    assert locked_cnt == 3
    assert pruned_cnt == 1

    executed_queries = [str(call[0][0]) for call in mock_cursor.execute.call_args_list if call[0]]
    assert any("pg_advisory_xact_lock" in q for q in executed_queries)


@patch("psycopg.connect")
def test_kist_set_and_get_lifecycle(mock_connect):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    prof_id = uuid.uuid4()

    # Scope resolution (org, proj, prof) then row lookup in _next_secret_version (None -> 1)
    mock_cursor.fetchone.side_effect = [
        (org_id,),
        (proj_id,),
        (prof_id,),
        None,
    ]

    kist_inst = Kist(profile_name="prod", master_password="secret_password", db_url="postgresql://mock")
    version = kist_inst.set("app.api_key", "secret-value-123")
    assert version == 1

    executed_queries = [str(call[0][0]) for call in mock_cursor.execute.call_args_list if call[0]]
    assert any("FOR UPDATE" in q for q in executed_queries)

    # Now test get
    encrypted_blob = encrypt_envelope(
        b'"secret-value-123"',
        kist_inst.master_password,
        kist_inst._db_context("app.api_key", 1),
    )
    mock_cursor.fetchone.side_effect = [
        (encrypted_blob, 1, "password-v1"),
    ]

    retrieved = kist_inst.get("app.api_key")
    assert retrieved == "secret-value-123"


@patch("psycopg.connect")
def test_kist_set_retry_on_unique_violation(mock_connect):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    prof_id = uuid.uuid4()

    mock_cursor.fetchone.side_effect = [
        (org_id,),
        (proj_id,),
        (prof_id,),
        None,   # attempt 1: no row -> version 1
        (1,),   # attempt 2: found row version 1 -> version 2
    ]

    call_count = 0
    def execute_side_effect(*args, **kwargs):
        nonlocal call_count
        query = args[0] if args else ""
        if "INSERT INTO kist (" in str(query):
            call_count += 1
            if call_count == 1:
                raise psycopg.errors.UniqueViolation("duplicate key value")
        return MagicMock()

    mock_cursor.execute.side_effect = execute_side_effect

    kist_inst = Kist(profile_name="prod", master_password="secret_password", db_url="postgresql://mock")
    version = kist_inst.set("app.api_key", "secret-value-123", max_retries=3)
    assert version == 2
    assert call_count == 2


@patch("psycopg.connect")
def test_kist_set_exhausted_retries_raises_concurrent_write_error(mock_connect):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    prof_id = uuid.uuid4()

    mock_cursor.fetchone.side_effect = [
        (org_id,),
        (proj_id,),
        (prof_id,),
        None,
        None,
        None,
    ]

    def execute_side_effect(*args, **kwargs):
        query = args[0] if args else ""
        if "INSERT INTO kist (" in str(query):
            raise psycopg.errors.UniqueViolation("duplicate key value")
        return MagicMock()

    mock_cursor.execute.side_effect = execute_side_effect

    kist_inst = Kist(profile_name="prod", master_password="secret_password", db_url="postgresql://mock")
    with pytest.raises(ConcurrentWriteError):
        kist_inst.set("app.api_key", "secret-value-123", max_retries=2)


@patch("psycopg.connect")
def test_unlock_yaml_type_reconstruction(mock_connect):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value.__enter__.return_value = mock_conn
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    prof_id = uuid.uuid4()

    mock_cursor.fetchone.side_effect = [
        (org_id,),
        (proj_id,),
        (prof_id,),
    ]

    kist_inst = Kist(profile_name="test_prof", master_password="password", db_url="postgresql://mock")

    env_val = encrypt_envelope(b'"production"', kist_inst.master_password, kist_inst._db_context("app.env", 1))
    port_val = encrypt_envelope(b"5432", kist_inst.master_password, kist_inst._db_context("app.port", 1))
    ssl_val = encrypt_envelope(b"true", kist_inst.master_password, kist_inst._db_context("app.ssl", 1))

    mock_cursor.fetchall.return_value = [
        ("app.env", env_val, 1, "password-v1"),
        ("app.port", port_val, 1, "password-v1"),
        ("app.ssl", ssl_val, 1, "password-v1"),
    ]

    unlocked_yaml = kist_inst.unlock_yaml()
    loaded = yaml.safe_load(unlocked_yaml)
    assert loaded["app"]["env"] == "production"
    assert loaded["app"]["port"] == 5432
    assert loaded["app"]["ssl"] is True


def test_run_git_setup_creates_shell_pre_commit_hook(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    git_dir = tmp_path / ".git"
    git_dir.mkdir(parents=True, exist_ok=True)
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        run_git_setup(force_hook=True)

        gitattrs = (tmp_path / ".gitattributes").read_text()
        assert "secrets*.yaml filter=kist" in gitattrs

        hook_path = hooks_dir / "pre-commit"
        assert hook_path.exists()
        hook_content = hook_path.read_text()
        assert "#!/usr/bin/env sh" in hook_content
        assert "kist pre-commit-guard" in hook_content


def test_run_status_output_structure(capsys):
    exit_code = run_status()
    assert exit_code == 0
    captured = capsys.readouterr()
    output = captured.out
    assert "Kist status" in output
    assert "Git clean filter" in output
    assert "Profiles:" in output
    assert "Database:" in output


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
    assert "production: secrets/production.yaml; key source: local key file" in captured
    assert "staging: secrets/staging.yaml; key source: MISSING" in captured


def test_run_fix_workflow(capsys):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        exit_code = run_fix()
        assert exit_code == 0
        captured = capsys.readouterr()
        output = captured.out
        assert "Kist repair plan" in output


def test_key_file_posix_permissions(kist_env):
    pwd = create_profile_key("secure_profile")
    kist_dir = kist_env["kist_dir"]
    assert kist_dir.exists()
    pwd_file = kist_dir / "pwd_secure_profile"
    assert pwd_file.exists()

    if os.name != "nt":
        dir_stat = os.stat(str(kist_dir))
        file_stat = os.stat(str(pwd_file))
        assert (dir_stat.st_mode & 0o777) == 0o700
        assert (file_stat.st_mode & 0o777) == 0o600


def test_mask_db_url():
    url = "postgresql://myuser:secretpassword123@db.prod.internal:5432/secrets_db"
    masked = mask_db_url(url)
    assert "secretpassword123" not in masked
    assert "myuser:***@db.prod.internal:5432/secrets_db" in masked

    no_pwd = "postgresql://localhost/mydb"
    assert mask_db_url(no_pwd) == no_pwd


def test_enforce_ssl_url():
    # Default missing sslmode to require
    url1 = "postgresql://user:pass@db.example.com:5432/secrets_db"
    enforced1 = enforce_ssl_url(url1)
    assert "sslmode=require" in enforced1

    # In development, disable is allowed
    url2 = "postgresql://user:pass@db.example.com:5432/secrets_db?sslmode=disable"
    assert "sslmode=disable" in enforce_ssl_url(url2, production=False)

    # In production, disable is rejected
    with pytest.raises(KistError):
        enforce_ssl_url(url2, production=True)

    url3 = "postgresql://user:pass@db.example.com:5432/secrets_db?sslmode=require&connect_timeout=5"
    enforced3 = enforce_ssl_url(url3)
    assert "sslmode=require" in enforced3
    assert "connect_timeout=5" in enforced3

    url4 = "postgresql://user:pass@db.example.com:5432/secrets_db?sslmode=verify-full&sslrootcert=/etc/ssl/ca.crt"
    enforced4 = enforce_ssl_url(url4)
    assert "sslmode=verify-full" in enforced4
    assert "sslrootcert=%2Fetc%2Fssl%2Fca.crt" in enforced4

    assert enforce_ssl_url(None) is None
    assert enforce_ssl_url("") == ""


@patch("psycopg.connect")
def test_safe_db_connect_enforces_ssl_and_masks_errors(mock_connect):
    url = "postgresql://admin:supersecret@db.internal:5432/production"
    safe_db_connect(url)
    mock_connect.assert_called_once()
    called_url = mock_connect.call_args[0][0]
    assert "sslmode=require" in called_url

    # Connection error masking
    mock_connect.side_effect = psycopg.OperationalError("connection refused")
    with pytest.raises(psycopg.OperationalError) as exc_info:
        safe_db_connect(url)
    assert "supersecret" not in str(exc_info.value)
    assert "admin:***@db.internal:5432/production" in str(exc_info.value)


def test_local_kms_provider_lifecycle():
    kek = os.urandom(32)
    provider = LocalKMSProvider(kek)
    key_ref = KMSKeyReference(provider="local", key_id="test-key-1")
    ctx = {"organization_id": "org1", "project_id": "proj1", "profile_id": "prof1"}

    dek, wrapped = provider.generate_data_key(key_reference=key_ref, encryption_context=ctx)
    assert len(dek) == 32
    assert wrapped.provider == "local"
    assert wrapped.key_reference == key_ref

    unwrapped = provider.unwrap_key(wrapped)
    assert unwrapped == dek


def test_kms_registry_provider():
    kek = os.urandom(32)
    provider = get_kms_provider("local", kek=kek)
    assert isinstance(provider, LocalKMSProvider)

    with pytest.raises(KMSProviderError):
        get_kms_provider("aws-kms")

    with pytest.raises(KMSProviderError):
        get_kms_provider("unknown-provider")


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
    # If input is called, it would fail
    monkeypatch.setattr("builtins.input", lambda prompt: (_ for _ in ()).throw(AssertionError("Should not prompt")))

    with patch.object(Kist, "lock_yaml", return_value=(2, 1)) as mock_lock:
        main()
        mock_lock.assert_called_once_with("db.host: localhost\n", prune=True)
        captured = capsys.readouterr()
        assert "Locked 2 secrets for local/default/production. Pruned 1." in captured.out
