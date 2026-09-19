import os
import sys
import json
import base64
import secrets
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import yaml
import psycopg
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# Database connection URL from environment
KIST_DATABASE_URL = os.getenv("KIST_DATABASE_URL")

# Default Argon2id parameters (OWASP recommended memory-hard configuration)
ARGON2_MEMORY_COST = 65536  # 64 MB memory cost in KiB
ARGON2_ITERATIONS = 2       # 2 time iterations
ARGON2_LANES = 4            # 4 parallel lanes
ARGON2_KEY_LENGTH = 32      # 256-bit derived key for Fernet

# =====================================================================
# 1. SQL SCHEMA DEFINITION
# =====================================================================
SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS kist_profiles (
    id SERIAL PRIMARY KEY,
    profile_name VARCHAR(100) UNIQUE NOT NULL,
    crypto_salt BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kist (
    id SERIAL PRIMARY KEY,
    profile_id INT REFERENCES kist_profiles(id) ON DELETE CASCADE,
    secret_key VARCHAR(255) NOT NULL,
    encrypted_blob BYTEA NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT unique_profile_secret UNIQUE (profile_id, secret_key)
);

CREATE INDEX IF NOT EXISTS idx_kist_profile_lookup ON kist(profile_id, secret_key);
"""


# =====================================================================
# 2. KEY DERIVATION & PASSWORD UTILITIES
# =====================================================================
def derive_fernet_key(
    password: str,
    salt: bytes,
    length: int = ARGON2_KEY_LENGTH,
    iterations: int = ARGON2_ITERATIONS,
    lanes: int = ARGON2_LANES,
    memory_cost: int = ARGON2_MEMORY_COST,
) -> Fernet:
    """Derives a Fernet instance from password and salt using Argon2id."""
    kdf = Argon2id(
        salt=salt,
        length=length,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
        ad=None,
        secret=None,
    )
    return Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8"))))


def generate_password(length: int = 32) -> str:
    """Generates a cryptographically secure random password."""
    return secrets.token_urlsafe(length)


def mask_db_url(db_url: Optional[str]) -> str:
    """Masks database credentials for safe error reporting and logs."""
    if not db_url:
        return ""
    try:
        parsed = urlsplit(db_url)
        if parsed.password:
            user = parsed.username or ""
            host = parsed.hostname or ""
            port = f":{parsed.port}" if parsed.port else ""
            netloc = f"{user}:***@{host}{port}"
            return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    except Exception:
        pass
    return db_url


def enforce_ssl_url(db_url: Optional[str], default_sslmode: str = "require") -> Optional[str]:
    """
    Ensures PostgreSQL connection URL enforces TLS/SSL transport encryption.
    - If sslmode is not specified, appends 'sslmode=require'.
    - If an insecure sslmode (disable, allow, prefer) is specified, upgrades it to 'require'.
    - Preserves secure sslmode settings ('require', 'verify-ca', 'verify-full') and other query parameters.
    """
    if not db_url:
        return db_url
    try:
        parsed = urlsplit(db_url)
        if not parsed.scheme or not parsed.netloc:
            return db_url
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        updated_query = []
        sslmode_found = False
        for k, v in query_pairs:
            if k.lower() == "sslmode":
                sslmode_found = True
                if v.lower() in ("disable", "allow", "prefer"):
                    updated_query.append((k, default_sslmode))
                else:
                    updated_query.append((k, v))
            else:
                updated_query.append((k, v))
        if not sslmode_found:
            updated_query.append(("sslmode", default_sslmode))
        new_query = urlencode(updated_query)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
    except Exception:
        return db_url


def safe_db_connect(db_url: str, **kwargs) -> psycopg.Connection:
    """
    Safely establishes psycopg connection with enforced TLS/SSL transport security,
    masking connection string credentials upon error.
    """
    enforced_url = enforce_ssl_url(db_url)
    try:
        return psycopg.connect(enforced_url, **kwargs)
    except psycopg.OperationalError as e:
        masked = mask_db_url(enforced_url)
        raise psycopg.OperationalError(f"Database connection failure ({masked}): {e}") from None


async def safe_async_db_connect(db_url: str, **kwargs) -> psycopg.AsyncConnection:
    """
    Safely establishes asynchronous psycopg connection with enforced TLS/SSL transport security,
    masking connection string credentials upon error.
    """
    enforced_url = enforce_ssl_url(db_url)
    try:
        return await psycopg.AsyncConnection.connect(enforced_url, **kwargs)
    except psycopg.OperationalError as e:
        masked = mask_db_url(enforced_url)
        raise psycopg.OperationalError(f"Database connection failure ({masked}): {e}") from None


def get_kist_dir() -> str:
    """Returns the path to the user's ~/.kist directory or $KIST_DIR if set."""
    return os.getenv("KIST_DIR") or os.path.expanduser("~/.kist")


def get_profile_password(profile_name: str, auto_generate: bool = True) -> Optional[str]:
    """
    Fetches the password for a given profile name.
    1. Checks environment variables:
       - 'default': KIST_PASSWORD_DEFAULT or KIST_PASSWORD
       - '<profile>': KIST_PASSWORD_<PROFILE> or KIST_PASSWORD
    2. Checks ~/.kist/pwd_<profile> (enforcing 0600 POSIX permissions)
    3. If not found and auto_generate is True, generates a password, writes it to ~/.kist/pwd_<profile>
       with strict 0600 permissions, and displays it.
    """
    if profile_name == "default":
        password = os.getenv("KIST_PASSWORD_DEFAULT") or os.getenv("KIST_PASSWORD")
    else:
        env_key = f"KIST_PASSWORD_{profile_name.upper()}"
        password = os.getenv(env_key) or os.getenv("KIST_PASSWORD")

    if password:
        return password

    kist_dir = get_kist_dir()
    pwd_file = os.path.join(kist_dir, f"pwd_{profile_name}")

    if os.path.exists(pwd_file):
        try:
            try:
                os.chmod(pwd_file, 0o600)
            except OSError:
                pass
            with open(pwd_file, "r") as f:
                saved_pwd = f.read().strip()
            if saved_pwd:
                return saved_pwd
        except Exception:
            pass

    if auto_generate:
        password = generate_password()
        os.makedirs(kist_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(kist_dir, 0o700)
        except OSError:
            pass
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(pwd_file, flags, 0o600)
        with open(fd, "w") as f:
            f.write(password)
        try:
            os.chmod(pwd_file, 0o600)
        except OSError:
            pass
        out_stream = sys.stderr if ("--clean" in sys.argv or "--smudge" in sys.argv) else sys.stdout
        print(f"🔑 Generated password for profile '{profile_name}': {password}", file=out_stream)
        return password

    return None


def resolve_secret_file_path(path_or_name: str) -> str:
    """
    Resolves the actual secret file path for a given name, relative path, or profile identifier.
    Automatically checks:
    1. Direct path (if file exists)
    2. Path with .yaml / .yml extension appended
    3. Inside 'secrets/' directory with direct path or extensions appended
    Fallback: returns expected file path in 'secrets/' if directory exists, or path with default extension.
    """
    candidates = [
        path_or_name,
        f"{path_or_name}.yaml",
        f"{path_or_name}.yml",
        os.path.join("secrets", path_or_name),
        os.path.join("secrets", f"{path_or_name}.yaml"),
        os.path.join("secrets", f"{path_or_name}.yml"),
    ]
    for cand in candidates:
        if os.path.isfile(cand):
            return cand

    # If no file exists yet (e.g. for unlock or reporting clear error on lock)
    if os.path.isdir("secrets"):
        if path_or_name.endswith(".yaml") or path_or_name.endswith(".yml"):
            return os.path.join("secrets", path_or_name)
        return os.path.join("secrets", f"{path_or_name}.yaml")

    if not (path_or_name.endswith(".yaml") or path_or_name.endswith(".yml")):
        return f"{path_or_name}.yaml"

    return path_or_name


def get_profile_and_password(file_path: str, auto_generate: bool = True) -> tuple[str, str]:
    """
    Extracts profile name from filename and fetches or generates its matching password.
    - 'secrets_team_a.yaml' -> Profile: 'team_a' -> KIST_PASSWORD_TEAM_A or ~/.kist/pwd_team_a
    - 'secrets_john.yaml'   -> Profile: 'john'   -> KIST_PASSWORD_JOHN or ~/.kist/pwd_john
    - 'secrets.yaml'        -> Profile: 'default' -> KIST_PASSWORD_DEFAULT or KIST_PASSWORD or ~/.kist/pwd_default
    - 'secrets_team_a'      -> Profile: 'team_a'
    - 'secrets'             -> Profile: 'default'
    - 'secrets/secrets_team_a.yaml' -> Profile: 'team_a'
    """
    filename = os.path.basename(file_path)
    base_name = filename.replace(".yaml", "").replace(".yml", "")

    if base_name == "secrets":
        profile_name = "default"
    elif base_name.startswith("secrets_"):
        profile_name = base_name[len("secrets_"):]
    else:
        profile_name = base_name

    password = get_profile_password(profile_name, auto_generate=auto_generate)
    return profile_name, password


# =====================================================================
# 3. CORE ENCRYPTED STORAGE LAYER
# =====================================================================
class Kist:
    def __init__(self, profile_name: str, master_password: Optional[str] = None, db_url: Optional[str] = None):
        if not master_password:
            master_password = get_profile_password(profile_name)

        if not master_password:
            raise ValueError(f"❌ Missing encryption password key for profile: '{profile_name}'")

        self.db_url = enforce_ssl_url(db_url or KIST_DATABASE_URL)
        self.profile_name = profile_name
        self.master_password = master_password

        # Production Context: PostgreSQL salt stored in kist_profiles table
        if self.db_url:
            self.profile_id, salt = self._get_or_create_profile(profile_name)
            self.fernet = derive_fernet_key(master_password, salt)
        else:
            # Standalone / offline mode
            self.profile_id = None
            self.fernet = None

    def _get_or_create_profile(self, profile_name: str) -> tuple[int, bytes]:
        """Ensures the profile exists in PostgreSQL and fetches its unique salt."""
        with safe_db_connect(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(SQL_SCHEMA)
                cur.execute("SELECT id, crypto_salt FROM kist_profiles WHERE profile_name = %s;", (profile_name,))
                row = cur.fetchone()
                if row:
                    return row[0], bytes(row[1])

                # Unique 16-byte random salt per profile
                new_salt = os.urandom(16)
                cur.execute(
                    "INSERT INTO kist_profiles (profile_name, crypto_salt) VALUES (%s, %s) RETURNING id;",
                    (profile_name, new_salt)
                )
                new_id = cur.fetchone()
                conn.commit()
                return new_id[0], new_salt

    def _flatten(self, d: dict, parent_key: str = '', sep: str = '.') -> dict:
        """Converts a nested directory tree layout into flat dot-notation entries."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
            if isinstance(v, dict):
                items.extend(self._flatten(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def _unflatten(self, d: dict, sep: str = '.') -> dict:
        """Reconstructs a nested dict structure back from flat records."""
        result = {}
        for k, v in d.items():
            parts = str(k).split(sep)
            current = result
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = v
        return result

    def get(self, key: str) -> Any:
        """Public application runtime endpoint to read from database."""
        if not self.profile_id:
            raise ValueError("❌ KIST_DATABASE_URL is not configured.")

        with safe_db_connect(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT encrypted_blob FROM kist WHERE profile_id = %s AND secret_key = %s;",
                    (self.profile_id, key)
                )
                row = cur.fetchone()

        if not row:
            raise KeyError(f"❌ Secret key '{key}' not found for profile '{self.profile_name}'.")

        try:
            decrypted_raw = self.fernet.decrypt(bytes(row[0])).decode("utf-8")
            try:
                return json.loads(decrypted_raw)
            except (json.JSONDecodeError, TypeError):
                return decrypted_raw
        except Exception:
            raise ValueError("❌ Cryptographic failure. Password configuration incorrect.")

    def lock_yaml(self, yaml_string: str, prune: bool = False) -> tuple[int, int]:
        """
        Flattens and encrypts YAML secrets into PostgreSQL rows with preserved data types.
        If prune is True, deletes secrets in the database that are not present in the provided YAML.
        Returns (locked_count, pruned_count).
        """
        if not self.profile_id:
            raise ValueError("❌ KIST_DATABASE_URL is not configured.")

        raw_data = yaml.safe_load(yaml_string)
        if not isinstance(raw_data, dict):
            raise ValueError("❌ YAML file root element must be an object structure.")

        flattened_secrets = self._flatten(raw_data)
        insert_query = """
            INSERT INTO kist (profile_id, secret_key, encrypted_blob, updated_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (profile_id, secret_key) 
            DO UPDATE SET encrypted_blob = EXCLUDED.encrypted_blob, updated_at = NOW();
        """
        pruned_count = 0
        pruned_keys = []

        with safe_db_connect(self.db_url) as conn:
            with conn.cursor() as cur:
                # Handle pruning of removed keys if requested
                if prune:
                    existing_keys = set()
                    cur.execute("SELECT secret_key FROM kist WHERE profile_id = %s;", (self.profile_id,))
                    for r in cur.fetchall():
                        existing_keys.add(r[0])
                    
                    target_keys = set(flattened_secrets.keys())
                    keys_to_delete = list(existing_keys - target_keys)
                    if keys_to_delete:
                        cur.execute(
                            "DELETE FROM kist WHERE profile_id = %s AND secret_key = ANY(%s) RETURNING secret_key;",
                            (self.profile_id, keys_to_delete)
                        )
                        deleted_rows = cur.fetchall()
                        pruned_count = len(deleted_rows)
                        pruned_keys = [r[0] for r in deleted_rows]

                # Upsert current secrets
                for key, val in flattened_secrets.items():
                    # Preserve types via JSON serialization
                    val_json = json.dumps(val)
                    encrypted_data = self.fernet.encrypt(val_json.encode("utf-8"))
                    cur.execute(insert_query, (self.profile_id, key, encrypted_data))
                    cur.execute(
                        "SELECT pg_notify(%s, %s);",
                        (
                            "kist_secret_updated",
                            json.dumps({
                                "profile_name": self.profile_name,
                                "profile_id": self.profile_id,
                                "secret_key": key,
                            }),
                        ),
                    )

                # Emit notifications for pruned keys
                for pkey in pruned_keys:
                    cur.execute(
                        "SELECT pg_notify(%s, %s);",
                        (
                            "kist_secret_updated",
                            json.dumps({
                                "profile_name": self.profile_name,
                                "profile_id": self.profile_id,
                                "secret_key": pkey,
                                "deleted": True,
                            }),
                        ),
                    )

                conn.commit()

        msg = f"🔒 Locked {len(flattened_secrets)} secrets into DB for profile '{self.profile_name}'."
        if prune and pruned_count > 0:
            msg += f" (Pruned {pruned_count} obsolete secrets)"
        print(msg)
        return len(flattened_secrets), pruned_count

    def unlock_yaml(self) -> str:
        """Extracts secrets for this profile from PostgreSQL and reconstructs nested YAML."""
        if not self.profile_id:
            raise ValueError("❌ KIST_DATABASE_URL is not configured.")

        query = "SELECT secret_key, encrypted_blob FROM kist WHERE profile_id = %s ORDER BY secret_key ASC;"
        flat_dict = {}

        with safe_db_connect(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(query, (self.profile_id,))
                rows = cur.fetchall()

        if not rows:
            return f"# No secrets found in the database for profile '{self.profile_name}'."

        for secret_key, encrypted_blob in rows:
            try:
                decrypted_raw = self.fernet.decrypt(bytes(encrypted_blob)).decode("utf-8")
                try:
                    decrypted_val = json.loads(decrypted_raw)
                except (json.JSONDecodeError, TypeError):
                    decrypted_val = decrypted_raw
                flat_dict[secret_key] = decrypted_val
            except Exception:
                raise ValueError("❌ Decryption failed. Invalid password.")

        nested_dict = self._unflatten(flat_dict)
        return yaml.dump(nested_dict, default_flow_style=False, sort_keys=False)

    def git_clean(self):
        """Convenience method for Git clean filter using random prepended salt."""
        from kist.git import git_clean_stream
        git_clean_stream(self.profile_name, master_password=self.master_password)

    def git_smudge(self):
        """Convenience method for Git smudge filter with prepended salt extraction."""
        from kist.git import git_smudge_stream
        git_smudge_stream(self.profile_name, master_password=self.master_password)
