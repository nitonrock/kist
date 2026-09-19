import os
import shutil
import unittest
from unittest.mock import patch, MagicMock
import io
import sys
import tempfile
import yaml

from kist import (
    generate_password,
    get_kist_dir,
    get_profile_password,
    get_profile_and_password,
    resolve_secret_file_path,
    mask_db_url,
    enforce_ssl_url,
    safe_db_connect,
    safe_async_db_connect,
    run_status,
    run_fix,
    run_git_setup,
    run_leak_guard,
    git_clean_stream,
    git_smudge_stream,
    derive_fernet_key,
    Kist,
)


class TestKistPasswordGenerator(unittest.TestCase):
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

    def test_get_profile_password_from_kist_folder(self):
        os.makedirs(self.kist_dir, exist_ok=True)
        with open(os.path.join(self.kist_dir, "pwd_gamma"), "w") as f:
            f.write("saved_file_secret\n")

        with patch.dict(os.environ, {"KIST_DIR": self.kist_dir}, clear=True):
            pwd = get_profile_password("gamma")
            self.assertEqual(pwd, "saved_file_secret")

    def test_get_profile_password_auto_generates_and_saves(self):
        with patch.dict(os.environ, {"KIST_DIR": self.kist_dir}, clear=True):
            with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
                pwd = get_profile_password("delta")

            self.assertTrue(os.path.exists(os.path.join(self.kist_dir, "pwd_delta")))
            with open(os.path.join(self.kist_dir, "pwd_delta"), "r") as f:
                saved = f.read().strip()

            self.assertEqual(pwd, saved)
            self.assertIn("delta", fake_out.getvalue())
            self.assertIn(pwd, fake_out.getvalue())

            # Second call should retrieve the same password without re-generating
            with patch("sys.stdout", new_callable=io.StringIO) as fake_out2:
                pwd2 = get_profile_password("delta")
            self.assertEqual(pwd2, pwd)
            self.assertEqual(fake_out2.getvalue(), "")

    def test_get_profile_and_password_default(self):
        with patch.dict(os.environ, {"KIST_DIR": self.kist_dir}, clear=True):
            profile, pwd = get_profile_and_password("secrets.yaml")
            self.assertEqual(profile, "default")
            self.assertTrue(os.path.exists(os.path.join(self.kist_dir, "pwd_default")))
            with open(os.path.join(self.kist_dir, "pwd_default"), "r") as f:
                self.assertEqual(f.read().strip(), pwd)

    def test_get_profile_and_password_custom_profile(self):
        with patch.dict(os.environ, {"KIST_DIR": self.kist_dir}, clear=True):
            profile, pwd = get_profile_and_password("secrets_staging.yaml")
            self.assertEqual(profile, "staging")
            self.assertTrue(os.path.exists(os.path.join(self.kist_dir, "pwd_staging")))
            with open(os.path.join(self.kist_dir, "pwd_staging"), "r") as f:
                self.assertEqual(f.read().strip(), pwd)

    def test_get_profile_and_password_without_extension_or_prefix(self):
        with patch.dict(os.environ, {}, clear=True):
            profile, pwd = get_profile_and_password("secrets_my_team")
            self.assertEqual(profile, "my_team")
            profile_def, _ = get_profile_and_password("secrets")
            self.assertEqual(profile_def, "default")
            profile_sub, _ = get_profile_and_password("secrets/secrets_team_b.yaml")
            self.assertEqual(profile_sub, "team_b")

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


class TestGitFiltersAndSaltPrepending(unittest.TestCase):
    def test_git_clean_and_smudge_stream_roundtrip(self):
        plaintext = "database:\n  host: 127.0.0.1\n  port: 5432\n  ssl: true\n"
        password = "my_git_password_123"

        # 1. Clean (Encrypt)
        in_clean = io.StringIO(plaintext)
        out_clean = io.BytesIO()
        git_clean_stream("production", master_password=password, in_stream=in_clean, out_stream=out_clean)

        encrypted_bytes = out_clean.getvalue()
        self.assertTrue(len(encrypted_bytes) > 16)
        salt = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        self.assertTrue(ciphertext.startswith(b"gAAAAA"))

        # Encrypting again generates a different unique salt and ciphertext
        in_clean2 = io.StringIO(plaintext)
        out_clean2 = io.BytesIO()
        git_clean_stream("production", master_password=password, in_stream=in_clean2, out_stream=out_clean2)
        encrypted_bytes2 = out_clean2.getvalue()
        salt2 = encrypted_bytes2[:16]
        self.assertNotEqual(salt, salt2)
        self.assertNotEqual(encrypted_bytes, encrypted_bytes2)

        # 2. Smudge (Decrypt)
        in_smudge = io.BytesIO(encrypted_bytes)
        out_smudge = io.StringIO()
        git_smudge_stream("production", master_password=password, in_stream=in_smudge, out_stream=out_smudge)

        self.assertEqual(out_smudge.getvalue(), plaintext)

    def test_leak_guard_detects_plaintext_and_permits_encrypted(self):
        with patch("subprocess.run") as mock_run:
            # Staged file is secrets.yaml
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

            # Staged file with prepended salt
            mock_show_encrypted = MagicMock()
            mock_show_encrypted.stdout = os.urandom(16) + b"gAAAAABXYZ..."
            mock_show_encrypted.returncode = 0

            mock_run.side_effect = [mock_diff, mock_show_encrypted]
            code2 = run_leak_guard()
            self.assertEqual(code2, 0)


class TestKistTypePreservationAndPruning(unittest.TestCase):
    def test_flatten_and_unflatten_nested_and_types(self):
        kist_inst = Kist(profile_name="types_test", master_password="pwd")
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

        flat = kist_inst._flatten(data)
        self.assertEqual(flat["server.port"], 8080)
        self.assertEqual(flat["server.debug"], True)
        self.assertEqual(flat["server.timeout"], 2.5)
        self.assertEqual(flat["server.tags"], ["prod", "us-east"])
        self.assertIsNone(flat["server.admin"])
        self.assertEqual(flat["name"], "myapp")

        unflat = kist_inst._unflatten(flat)
        self.assertEqual(unflat, data)

    @patch("psycopg.connect")
    def test_lock_yaml_type_preservation_and_prune(self, mock_connect):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_cursor.fetchone.return_value = (7, os.urandom(16))

        kist_inst = Kist(profile_name="test_prof", master_password="password", db_url="postgresql://mock")

        # Mock existing keys for pruning: old_key is obsolete
        mock_cursor.fetchall.side_effect = [
            [("db.host",), ("old_key",)],  # SELECT secret_key
            [("old_key",)],                 # DELETE RETURNING secret_key
        ]

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
        mock_cursor.fetchone.return_value = (7, os.urandom(16))

        kist_inst = Kist(profile_name="test_prof", master_password="password", db_url="postgresql://mock")

        # Mock encrypted blobs in database
        port_enc = kist_inst.fernet.encrypt(b"5432")
        bool_enc = kist_inst.fernet.encrypt(b"true")
        str_enc = kist_inst.fernet.encrypt(b'"production"')

        mock_cursor.fetchall.return_value = [
            ("app.env", str_enc),
            ("app.port", port_enc),
            ("app.ssl", bool_enc),
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
            run_git_setup()
            
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
            self.assertIn("Kist Status Overview", output)
            self.assertIn("Git Pipeline & Hooks", output)
            self.assertIn("Secret Profiles Detected", output)
            self.assertIn("Database", output)

    def test_run_fix_workflow(self):
        with patch("sys.stdout", new_callable=io.StringIO) as fake_out, patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            exit_code = run_fix()
            self.assertEqual(exit_code, 0)
            output = fake_out.getvalue()
            self.assertIn("Kist Auto-Repair & Environment Sync", output)
            self.assertIn("Repairing Git Configuration & Plumbing", output)
            self.assertIn("Verifying Secret Profile Passwords", output)
            self.assertIn("Inspecting & Repairing Git Staging Index", output)
            self.assertIn("Repair Complete", output)


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

    def test_argon2id_derivation_and_roundtrip(self):
        salt = os.urandom(16)
        password = "strong_master_password_test"
        fernet1 = derive_fernet_key(password, salt)
        fernet2 = derive_fernet_key(password, salt)

        plaintext = b"super_secret_configuration"
        token = fernet1.encrypt(plaintext)
        decrypted = fernet2.decrypt(token)
        self.assertEqual(decrypted, plaintext)

    def test_key_file_posix_permissions(self):
        with patch.dict(os.environ, {"KIST_DIR": self.kist_dir}, clear=True):
            with patch("sys.stdout", new_callable=io.StringIO):
                pwd = get_profile_password("secure_profile")

            self.assertTrue(os.path.exists(self.kist_dir))
            pwd_file = os.path.join(self.kist_dir, "pwd_secure_profile")
            self.assertTrue(os.path.exists(pwd_file))

            # Check permissions
            dir_stat = os.stat(self.kist_dir)
            file_stat = os.stat(pwd_file)

            # 0o700 for dir, 0o600 for file
            self.assertEqual(dir_stat.st_mode & 0o777, 0o700)
            self.assertEqual(file_stat.st_mode & 0o777, 0o600)

    def test_mask_db_url(self):
        url = "postgresql://myuser:secretpassword123@db.prod.internal:5432/secrets_db"
        masked = mask_db_url(url)
        self.assertNotIn("secretpassword123", masked)
        self.assertIn("myuser:***@db.prod.internal:5432/secrets_db", masked)

        # URL without password
        no_pwd = "postgresql://localhost/mydb"
        self.assertEqual(mask_db_url(no_pwd), no_pwd)

    def test_enforce_ssl_url(self):
        # Default missing sslmode to require
        url1 = "postgresql://user:pass@db.example.com:5432/secrets_db"
        enforced1 = enforce_ssl_url(url1)
        self.assertIn("sslmode=require", enforced1)

        # Upgrade insecure sslmodes (disable, allow, prefer) to require
        url2 = "postgresql://user:pass@db.example.com:5432/secrets_db?sslmode=disable"
        self.assertEqual(enforce_ssl_url(url2), "postgresql://user:pass@db.example.com:5432/secrets_db?sslmode=require")

        url3 = "postgresql://user:pass@db.example.com:5432/secrets_db?sslmode=prefer&connect_timeout=5"
        enforced3 = enforce_ssl_url(url3)
        self.assertIn("sslmode=require", enforced3)
        self.assertIn("connect_timeout=5", enforced3)

        # Preserve strict sslmodes (verify-full, verify-ca)
        url4 = "postgresql://user:pass@db.example.com:5432/secrets_db?sslmode=verify-full&sslrootcert=/etc/ssl/ca.crt"
        enforced4 = enforce_ssl_url(url4)
        self.assertIn("sslmode=verify-full", enforced4)
        self.assertIn("sslrootcert=%2Fetc%2Fssl%2Fca.crt", enforced4)

        # Handle None and empty
        self.assertIsNone(enforce_ssl_url(None))
        self.assertEqual(enforce_ssl_url(""), "")

    @patch("psycopg.connect")
    def test_safe_db_connect_enforces_ssl_and_masks_errors(self, mock_connect):
        url = "postgresql://admin:supersecret@db.internal:5432/production"
        safe_db_connect(url)
        mock_connect.assert_called_once()
        called_url = mock_connect.call_args[0][0]
        self.assertIn("sslmode=require", called_url)

        # Test error masking
        import psycopg
        mock_connect.side_effect = psycopg.OperationalError("connection failed")
        with self.assertRaises(psycopg.OperationalError) as cm:
            safe_db_connect(url)
        err_msg = str(cm.exception)
        self.assertNotIn("supersecret", err_msg)
        self.assertIn("admin:***@db.internal:5432/production", err_msg)

    def test_git_clean_fails_closed_without_password(self):
        with patch.dict(os.environ, {}, clear=True):
            in_stream = io.StringIO("db_password: secret\n")
            out_stream = io.BytesIO()
            with self.assertRaises(SystemExit) as cm:
                with patch("sys.stderr", new_callable=io.StringIO):
                    git_clean_stream("missing_pwd_profile", in_stream=in_stream, out_stream=out_stream)
            self.assertEqual(cm.exception.code, 1)

    def test_leak_guard_detects_unencrypted_credentials_in_config_files(self):
        with patch("subprocess.run") as mock_run:
            # Staged file is config.yaml (not named secrets*.yaml)
            mock_diff = MagicMock()
            mock_diff.stdout = "config.yaml\n"
            mock_diff.returncode = 0

            # Content has plaintext API key
            mock_show = MagicMock()
            mock_show.stdout = b"api_key: sk_live_1234567890abcdef\n"
            mock_show.returncode = 0

            mock_run.side_effect = [mock_diff, mock_show]
            with patch("sys.stderr", new_callable=io.StringIO):
                code = run_leak_guard()
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
