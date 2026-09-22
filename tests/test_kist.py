import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg
import yaml

from kist import (
    Kist,
    create_profile_key,
    decrypt_envelope,
    derive_fernet_key,
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
    DecryptionError,
    InsecureKeyStoreError,
    InvalidEnvelopeError,
    KistError,
    KistScope,
    MissingKeyError,
)


class TestKistPasswordGeneratorAndStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.kist_dir = os.path.join(self.temp_dir, ".kist")
        self.env_patcher = patch.dict(os.environ, {"HOME": self.temp_dir, "KIST_DIR": self.kist_dir}, clear=False)
        self.env_patcher.start()

    def tearDown(self):
        self.env_patcher.stop()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_generate_password(self):
        pwd1 = generate_password()
        pwd2 = generate_password()
        self.assertTrue(len(pwd1) > 20)
        self.assertNotEqual(pwd1, pwd2)

    def test_get_kist_dir(self):
        with patch.dict(os.environ, {"HOME": "/custom/home", "KIST_DIR": ""}, clear=True):
            self.assertEqual(get_kist_dir(), "/custom/home/.kist")
        with patch.dict(os.environ, {"KIST_DIR": "/override/dir"}, clear=True):
            self.assertEqual(get_kist_dir(), "/override/dir")

    def test_get_profile_password_from_env_specific(self):
        with patch.dict(os.environ, {"KIST_PASSWORD_ALPHA": "custom_alpha_secret", "KIST_DIR": self.kist_dir}):
            pwd = get_profile_password("alpha")
            self.assertEqual(pwd, "custom_alpha_secret")
            self.assertFalse(os.path.exists(os.path.join(self.kist_dir, "pwd_alpha")))

    def test_get_profile_password_from_env_default(self):
        with patch.dict(os.environ, {"KIST_PASSWORD_DEFAULT": "custom_default_secret", "KIST_DIR": self.kist_dir}):
            pwd = get_profile_password("default")
            self.assertEqual(pwd, "custom_default_secret")
            self.assertFalse(os.path.exists(os.path.join(self.kist_dir, "pwd_default")))

    def test_get_profile_password_from_env_fallback(self):
        with patch.dict(os.environ, {"KIST_PASSWORD": "global_secret", "KIST_DIR": self.kist_dir}, clear=True):
            pwd = get_profile_password("beta")
            self.assertEqual(pwd, "global_secret")
            self.assertFalse(os.path.exists(os.path.join(self.kist_dir, "pwd_beta")))

    def test_create_and_read_profile_password_from_kist_folder(self):
        created_pwd = create_profile_key("gamma")
        self.assertTrue(len(created_pwd) > 20)
        pwd_file = Path(self.kist_dir) / "pwd_gamma"
        self.assertTrue(pwd_file.exists())

        with patch.dict(os.environ, {"KIST_DIR": self.kist_dir}, clear=True):
            loaded_pwd = get_profile_password("gamma")
            self.assertEqual(loaded_pwd, created_pwd)

    def test_implicit_auto_generate_disabled(self):
        with patch.dict(os.environ, {"KIST_DIR": self.kist_dir}, clear=True):
            with self.assertRaises(KistError):
                get_profile_password("delta", auto_generate=True)

    def test_get_profile_and_password_resolution(self):
        create_profile_key("default")
        create_profile_key("staging")

        with patch.dict(os.environ, {"KIST_DIR": self.kist_dir}, clear=True):
            prof_def, pwd_def = get_profile_and_password("secrets.yaml")
            self.assertEqual(prof_def, "default")
            self.assertIsNotNone(pwd_def)

            prof_stg, pwd_stg = get_profile_and_password("secrets_staging.yaml")
            self.assertEqual(prof_stg, "staging")
            self.assertIsNotNone(pwd_stg)

            prof_raw, _ = get_profile_and_password("secrets_my_team")
            self.assertEqual(prof_raw, "my_team")

            prof_sub, _ = get_profile_and_password("secrets/secrets_team_b.yaml")
            self.assertEqual(prof_sub, "team_b")

    def test_resolve_secret_file_path_direct_and_extension(self):
        os.makedirs("secrets", exist_ok=True)
        try:
            with open("secrets/secrets_team_c.yaml", "w") as f:
                f.write("a: 1\n")
            with open("secrets_root.yaml", "w") as f:
                f.write("b: 2\n")

            self.assertEqual(resolve_secret_file_path("secrets_root"), "secrets_root.yaml")
            self.assertEqual(resolve_secret_file_path("secrets_root.yaml"), "secrets_root.yaml")

            self.assertEqual(resolve_secret_file_path("secrets_team_c"), "secrets/secrets_team_c.yaml")
            self.assertEqual(resolve_secret_file_path("secrets_team_c.yaml"), "secrets/secrets_team_c.yaml")
            self.assertEqual(resolve_secret_file_path("secrets/secrets_team_c.yaml"), "secrets/secrets_team_c.yaml")
        finally:
            if os.path.exists("secrets/secrets_team_c.yaml"):
                os.remove("secrets/secrets_team_c.yaml")
            if os.path.exists("secrets_root.yaml"):
                os.remove("secrets_root.yaml")
            if os.path.exists("secrets") and not os.listdir("secrets"):
                os.rmdir("secrets")


class TestHardenedEnvelopeAndGitFilters(unittest.TestCase):
    def test_envelope_encryption_and_decryption(self):
        plaintext = b"sensitive_secret_payload"
        password = "strong_master_password_test"
        ctx = {"profile": "prod", "env": "cloud"}

        envelope = encrypt_envelope(plaintext, password, ctx)
        self.assertTrue(is_kist_envelope(envelope))
        self.assertTrue(len(envelope) > 78)

        # Decrypt success
        decrypted = decrypt_envelope(envelope, password, ctx)
        self.assertEqual(decrypted, plaintext)

        # Decrypt failure with wrong password
        with self.assertRaises(DecryptionError):
            decrypt_envelope(envelope, "wrong_password", ctx)

        # Decrypt failure with wrong context (AAD mismatch)
        wrong_ctx = {"profile": "prod", "env": "local"}
        with self.assertRaises(DecryptionError):
            decrypt_envelope(envelope, password, wrong_ctx)

    def test_git_clean_and_smudge_stream_roundtrip(self):
        plaintext = "database:\n  host: 127.0.0.1\n  port: 5432\n  ssl: true\n"
        password = "my_git_password_123"

        # 1. Clean (Encrypt)
        in_clean = io.StringIO(plaintext)
        out_clean = io.BytesIO()
        git_clean_stream("production", master_password=password, in_stream=in_clean, out_stream=out_clean, filepath="secrets_production.yaml")

        encrypted_bytes = out_clean.getvalue()
        self.assertTrue(is_kist_envelope(encrypted_bytes))

        # Re-encrypting produces fresh salt and different ciphertext
        in_clean2 = io.StringIO(plaintext)
        out_clean2 = io.BytesIO()
        git_clean_stream("production", master_password=password, in_stream=in_clean2, out_stream=out_clean2, filepath="secrets_production.yaml")
        encrypted_bytes2 = out_clean2.getvalue()
        self.assertNotEqual(encrypted_bytes, encrypted_bytes2)

        # 2. Smudge (Decrypt)
        in_smudge = io.BytesIO(encrypted_bytes)
        out_smudge = io.StringIO()
        git_smudge_stream("production", master_password=password, in_stream=in_smudge, out_stream=out_smudge, filepath="secrets_production.yaml")

        self.assertEqual(out_smudge.getvalue(), plaintext)

    def test_leak_guard_detects_plaintext_and_permits_encrypted(self):
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
            self.assertEqual(code, 1)

            # Staged file with valid envelope
            ctx = git_context("default", "secrets.yaml")
            valid_envelope = encrypt_envelope(b"api_key: encrypted\n", "password", ctx)
            mock_show_encrypted = MagicMock()
            mock_show_encrypted.stdout = valid_envelope
            mock_show_encrypted.returncode = 0

            mock_run.side_effect = [mock_diff, mock_show_encrypted]
            code2 = run_leak_guard()
            self.assertEqual(code2, 0)


class TestKistTypePreservationAndDatabaseOperations(unittest.TestCase):
    def test_flatten_and_unflatten_nested_and_types(self):
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
        self.assertEqual(flat["server.port"], 8080)
        self.assertEqual(flat["server.debug"], True)
        self.assertEqual(flat["server.timeout"], 2.5)
        self.assertEqual(flat["server.tags"], ["prod", "us-east"])
        self.assertIsNone(flat["server.admin"])
        self.assertEqual(flat["name"], "myapp")

        unflat = kist_inst.unflatten(flat)
        self.assertEqual(unflat, data)

    @patch("psycopg.connect")
    def test_lock_yaml_type_preservation_and_prune(self, mock_connect):
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
        self.assertEqual(locked_cnt, 3)
        self.assertEqual(pruned_cnt, 1)

    @patch("psycopg.connect")
    def test_unlock_yaml_type_reconstruction(self, mock_connect):
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
            ("app.env", env_val, 1),
            ("app.port", port_val, 1),
            ("app.ssl", ssl_val, 1),
        ]

        unlocked_yaml = kist_inst.unlock_yaml()
        loaded = yaml.safe_load(unlocked_yaml)
        self.assertEqual(loaded["app"]["env"], "production")
        self.assertEqual(loaded["app"]["port"], 5432)
        self.assertEqual(loaded["app"]["ssl"], True)


class TestKistGitSetupAndStatus(unittest.TestCase):
    def test_run_git_setup_creates_shell_pre_commit_hook(self):
        with patch("subprocess.run") as mock_run, patch("os.chmod"):
            mock_run.return_value.returncode = 0
            if os.path.exists(".gitattributes"):
                os.remove(".gitattributes")
            run_git_setup(force_hook=True)

            with open(".gitattributes", "r") as f:
                gitattrs = f.read()
            self.assertIn("secrets*.yaml filter=kist", gitattrs)

            hook_path = os.path.join(".git", "hooks", "pre-commit")
            self.assertTrue(os.path.exists(hook_path))
            with open(hook_path, "r") as f:
                hook_content = f.read()
            self.assertIn("#!/usr/bin/env sh", hook_content)
            self.assertIn("kist pre-commit-guard", hook_content)

    def test_run_status_output_structure(self):
        with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
            exit_code = run_status()
            self.assertEqual(exit_code, 0)
            output = fake_out.getvalue()
            self.assertIn("Kist status", output)
            self.assertIn("Git clean filter", output)
            self.assertIn("Profiles:", output)
            self.assertIn("Database:", output)

    def test_run_fix_workflow(self):
        with patch("sys.stdout", new_callable=io.StringIO) as fake_out, patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            exit_code = run_fix()
            self.assertEqual(exit_code, 0)
            output = fake_out.getvalue()
            self.assertIn("Kist repair plan", output)


class TestKistSecurityAndHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.kist_dir = os.path.join(self.temp_dir, ".kist")
        self.env_patcher = patch.dict(os.environ, {"HOME": self.temp_dir, "KIST_DIR": self.kist_dir}, clear=False)
        self.env_patcher.start()

    def tearDown(self):
        self.env_patcher.stop()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_key_file_posix_permissions(self):
        pwd = create_profile_key("secure_profile")
        self.assertTrue(os.path.exists(self.kist_dir))
        pwd_file = os.path.join(self.kist_dir, "pwd_secure_profile")
        self.assertTrue(os.path.exists(pwd_file))

        if os.name != "nt":
            dir_stat = os.stat(self.kist_dir)
            file_stat = os.stat(pwd_file)
            self.assertEqual(dir_stat.st_mode & 0o777, 0o700)
            self.assertEqual(file_stat.st_mode & 0o777, 0o600)

    def test_mask_db_url(self):
        url = "postgresql://myuser:secretpassword123@db.prod.internal:5432/secrets_db"
        masked = mask_db_url(url)
        self.assertNotIn("secretpassword123", masked)
        self.assertIn("myuser:***@db.prod.internal:5432/secrets_db", masked)

        no_pwd = "postgresql://localhost/mydb"
        self.assertEqual(mask_db_url(no_pwd), no_pwd)

    def test_enforce_ssl_url(self):
        # Default missing sslmode to require
        url1 = "postgresql://user:pass@db.example.com:5432/secrets_db"
        enforced1 = enforce_ssl_url(url1)
        self.assertIn("sslmode=require", enforced1)

        # In development, disable is allowed
        url2 = "postgresql://user:pass@db.example.com:5432/secrets_db?sslmode=disable"
        self.assertIn("sslmode=disable", enforce_ssl_url(url2, production=False))

        # In production, disable is rejected
        with self.assertRaises(KistError):
            enforce_ssl_url(url2, production=True)

        url3 = "postgresql://user:pass@db.example.com:5432/secrets_db?sslmode=require&connect_timeout=5"
        enforced3 = enforce_ssl_url(url3)
        self.assertIn("sslmode=require", enforced3)
        self.assertIn("connect_timeout=5", enforced3)

        url4 = "postgresql://user:pass@db.example.com:5432/secrets_db?sslmode=verify-full&sslrootcert=/etc/ssl/ca.crt"
        enforced4 = enforce_ssl_url(url4)
        self.assertIn("sslmode=verify-full", enforced4)
        self.assertIn("sslrootcert=%2Fetc%2Fssl%2Fca.crt", enforced4)

        self.assertIsNone(enforce_ssl_url(None))
        self.assertEqual(enforce_ssl_url(""), "")

    @patch("psycopg.connect")
    def test_safe_db_connect_enforces_ssl_and_masks_errors(self, mock_connect):
        url = "postgresql://admin:supersecret@db.internal:5432/production"
        safe_db_connect(url)
        mock_connect.assert_called_once()
        called_url = mock_connect.call_args[0][0]
        self.assertIn("sslmode=require", called_url)

        # Connection error masking
        mock_connect.side_effect = psycopg.OperationalError("connection refused")
        with self.assertRaises(psycopg.OperationalError) as ctx:
            safe_db_connect(url)
        self.assertNotIn("supersecret", str(ctx.exception))
        self.assertIn("admin:***@db.internal:5432/production", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
