"""Kist core: encrypted secret storage with scope-aware key-provider seams.

Default mode remains password-v1 for simple self-hosted deployments. The
kms-dek-v1 mode is an internal foundation for future cloud KMS providers; only
the local development/test provider is included here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import psycopg
import yaml
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

KIST_DATABASE_URL = os.getenv("KIST_DATABASE_URL")
ARGON2_MEMORY_COST = 65536
ARGON2_ITERATIONS = 2
ARGON2_LANES = 4
ARGON2_KEY_LENGTH = 32

MAGIC = b"KIST"
ENVELOPE_VERSION = 1
ALGORITHM_AES_256_GCM = 1
KDF_ARGON2ID = 1
KEY_MODE_PASSWORD = "password-v1"
KEY_MODE_KMS_DEK = "kms-dek-v1"
SALT_LENGTH = 16
NONCE_LENGTH = 12
HEADER_SIZE = 78


class KistError(Exception):
    """Base class for expected Kist errors."""


class MissingKeyError(KistError):
    """No profile key is available."""


class InvalidEnvelopeError(KistError):
    """Ciphertext is not a supported Kist envelope."""


class DecryptionError(KistError):
    """Ciphertext could not be authenticated or decrypted."""


class InsecureKeyStoreError(KistError):
    """Local profile-key storage does not meet minimum POSIX protections."""


@dataclass(frozen=True)
class Argon2Policy:
    memory_cost: int = ARGON2_MEMORY_COST
    iterations: int = ARGON2_ITERATIONS
    lanes: int = ARGON2_LANES


@dataclass(frozen=True)
class KistScope:
    organization: str = "local"
    project: str = "default"

    @classmethod
    def from_environment(cls) -> "KistScope":
        return cls(os.getenv("KIST_ORG_ID", "local"), os.getenv("KIST_PROJECT_ID", "default")).validated()

    def validated(self) -> "KistScope":
        return KistScope(_validate_scope_name(self.organization, "organization"), _validate_scope_name(self.project, "project"))


SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS kist_organizations (
    id UUID PRIMARY KEY,
    slug VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kist_projects (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES kist_organizations(id) ON DELETE CASCADE,
    slug VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_kist_project UNIQUE (organization_id, slug)
);

CREATE TABLE IF NOT EXISTS kist_profiles (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES kist_organizations(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES kist_projects(id) ON DELETE CASCADE,
    profile_name VARCHAR(100) NOT NULL,
    crypto_salt BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_kist_profile UNIQUE (project_id, profile_name)
);

CREATE TABLE IF NOT EXISTS kist_key_envelopes (
    id UUID PRIMARY KEY,
    profile_id UUID NOT NULL REFERENCES kist_profiles(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    key_reference TEXT NOT NULL,
    key_version TEXT,
    wrapped_dek BYTEA NOT NULL,
    encryption_context JSONB NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT one_active_kist_key_envelope UNIQUE (profile_id, active)
);

CREATE TABLE IF NOT EXISTS kist (
    id UUID PRIMARY KEY,
    profile_id UUID NOT NULL REFERENCES kist_profiles(id) ON DELETE CASCADE,
    secret_key VARCHAR(255) NOT NULL,
    encrypted_blob BYTEA NOT NULL,
    crypto_mode VARCHAR(32) NOT NULL DEFAULT 'password-v1',
    crypto_version SMALLINT NOT NULL DEFAULT 1,
    secret_version BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_profile_secret UNIQUE (profile_id, secret_key)
);

CREATE INDEX IF NOT EXISTS idx_kist_profile_lookup ON kist(profile_id, secret_key);
"""


def generate_password(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def get_kist_dir() -> str:
    return os.getenv("KIST_DIR") or os.path.expanduser("~/.kist")


def _validate_scope_name(value: str, label: str) -> str:
    value = value.strip()
    if not value or len(value) > 100:
        raise KistError(f"{label.capitalize()} names must contain between 1 and 100 characters.")
    if any(char in value for char in ("/", "\\", "\x00")):
        raise KistError(f"{label.capitalize()} names cannot contain path separators or NUL bytes.")
    return value


def _validate_profile_name(profile_name: str) -> str:
    return _validate_scope_name(profile_name, "profile")


def profile_password_path(profile_name: str) -> Path:
    return Path(get_kist_dir()) / f"pwd_{_validate_profile_name(profile_name)}"


def _check_secure_directory(path: Path) -> None:
    if os.name == "nt":
        return
    st = path.stat()
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise InsecureKeyStoreError(f"Insecure Kist directory permissions or ownership: {path}")


def read_secure_local_password(path: Path) -> str:
    if os.name == "nt":
        return path.read_text(encoding="utf-8").strip()
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise InsecureKeyStoreError(f"Credential path is not a regular non-symlink file: {path}")
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise InsecureKeyStoreError(f"Insecure credential file permissions or ownership: {path}")
    return path.read_text(encoding="utf-8").strip()


def write_secure_local_password(path: Path, password: str, *, overwrite: bool = False) -> None:
    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(directory, 0o700)
        _check_secure_directory(directory)
    if os.name == "nt":
        if path.exists() and not overwrite:
            raise KistError(f"Credential file already exists: {path}")
        path.write_text(password, encoding="utf-8")
        return
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError as exc:
        raise KistError(f"Credential file already exists: {path}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(password)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if not overwrite:
            path.unlink(missing_ok=True)
        raise


def get_profile_password(profile_name: str, auto_generate: bool = False, *, allow_env: bool = True, allow_local_file: bool = True) -> Optional[str]:
    _validate_profile_name(profile_name)
    if allow_env:
        env_key = "KIST_PASSWORD_DEFAULT" if profile_name == "default" else f"KIST_PASSWORD_{profile_name.upper()}"
        value = os.getenv(env_key) or os.getenv("KIST_PASSWORD")
        if value:
            return value
    path = profile_password_path(profile_name)
    if allow_local_file and path.exists():
        value = read_secure_local_password(path)
        if value:
            return value
    if auto_generate:
        raise KistError("Implicit profile-key generation is disabled. Use `kist profile create <name>`.")
    return None


def create_profile_key(profile_name: str, *, rotate: bool = False) -> str:
    password = generate_password()
    write_secure_local_password(profile_password_path(profile_name), password, overwrite=rotate)
    return password


def resolve_secret_file_path(path_or_name: str) -> str:
    candidates = [path_or_name, f"{path_or_name}.yaml", f"{path_or_name}.yml", os.path.join("secrets", path_or_name), os.path.join("secrets", f"{path_or_name}.yaml"), os.path.join("secrets", f"{path_or_name}.yml")]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    if os.path.isdir("secrets"):
        return os.path.join("secrets", path_or_name if path_or_name.endswith((".yaml", ".yml")) else f"{path_or_name}.yaml")
    return path_or_name if path_or_name.endswith((".yaml", ".yml")) else f"{path_or_name}.yaml"


def get_profile_and_password(filepath: str, auto_generate: bool = False) -> tuple[str, Optional[str]]:
    base_name = os.path.basename(filepath).removesuffix(".yaml").removesuffix(".yml")
    profile_name = "default" if base_name == "secrets" else base_name[len("secrets_"):] if base_name.startswith("secrets_") else base_name
    return profile_name, get_profile_password(profile_name, auto_generate=auto_generate)


def mask_db_url(db_url: Optional[str]) -> str:
    if not db_url:
        return ""
    try:
        parsed = urlsplit(db_url)
        host, user = parsed.hostname or "", parsed.username or ""
        port = f":{parsed.port}" if parsed.port else ""
        netloc = f"{user}:***@{host}{port}" if parsed.password else parsed.netloc
        query = urlencode((key, "***" if any(word in key.lower() for word in ("password", "token", "secret")) else value) for key, value in parse_qsl(parsed.query, keep_blank_values=True))
        return urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))
    except Exception:
        return "<invalid database URL>"


def _runtime_is_production(production: Optional[bool]) -> bool:
    return production if production is not None else os.getenv("KIST_ENV", "production").strip().lower() != "development"


def enforce_ssl_url(db_url: Optional[str], default_sslmode: str = "require", *, production: Optional[bool] = None) -> Optional[str]:
    if not db_url:
        return None
    parsed = urlsplit(db_url)
    if not parsed.scheme or not parsed.netloc:
        raise KistError("KIST_DATABASE_URL must be a valid PostgreSQL URL.")
    requested_mode = os.getenv("KIST_TLS_MODE", "auto").strip().lower()
    if requested_mode not in {"auto", "disable", "require", "verify-ca", "verify-full"}:
        raise KistError("KIST_TLS_MODE must be auto, disable, require, verify-ca, or verify-full.")
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    sslmode = (query.get("sslmode", "").strip().lower() or default_sslmode) if requested_mode == "auto" else requested_mode
    if sslmode not in {"disable", "require", "verify-ca", "verify-full"}:
        raise KistError(f"Unsupported PostgreSQL sslmode: {sslmode!r}.")
    if sslmode == "disable" and _runtime_is_production(production):
        raise KistError("sslmode=disable is only allowed when KIST_ENV=development.")
    if sslmode in {"verify-ca", "verify-full"} and not (query.get("sslrootcert") or os.getenv("PGSSLROOTCERT")):
        raise KistError(f"{sslmode} requires sslrootcert in the URL or PGSSLROOTCERT in the environment.")
    query["sslmode"] = sslmode
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))


def database_tls_mode(db_url: Optional[str]) -> Optional[str]:
    normalized = enforce_ssl_url(db_url)
    return dict(parse_qsl(urlsplit(normalized).query, keep_blank_values=True)).get("sslmode") if normalized else None


def safe_db_connect(db_url: str, **kwargs: Any) -> psycopg.Connection:
    try:
        return psycopg.connect(enforce_ssl_url(db_url), **kwargs)
    except psycopg.OperationalError as exc:
        raise psycopg.OperationalError(f"Database connection failure ({mask_db_url(db_url)}): {exc}") from None


async def safe_async_db_connect(db_url: str, **kwargs: Any) -> psycopg.AsyncConnection:
    try:
        return await psycopg.AsyncConnection.connect(enforce_ssl_url(db_url), **kwargs)
    except psycopg.OperationalError as exc:
        raise psycopg.OperationalError(f"Database connection failure ({mask_db_url(db_url)}): {exc}") from None


def _canonical_aad(context: dict[str, Any]) -> bytes:
    return json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _derive_aes_key(password: str, salt: bytes, policy: Argon2Policy) -> bytes:
    return Argon2id(salt=salt, length=ARGON2_KEY_LENGTH, iterations=policy.iterations, lanes=policy.lanes, memory_cost=policy.memory_cost, ad=None, secret=None).derive(password.encode("utf-8"))


def derive_fernet_key(password: str, salt: bytes, **kwargs: Any):
    """Legacy compatibility helper. New Kist writes use AES-GCM envelopes."""
    from cryptography.fernet import Fernet
    policy = Argon2Policy(memory_cost=kwargs.get("memory_cost", ARGON2_MEMORY_COST), iterations=kwargs.get("iterations", ARGON2_ITERATIONS), lanes=kwargs.get("lanes", ARGON2_LANES))
    return Fernet(base64.urlsafe_b64encode(_derive_aes_key(password, salt, policy)))


def _build_envelope(*, salt: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, policy: Argon2Policy) -> bytes:
    return b"".join([MAGIC, bytes([ENVELOPE_VERSION, ALGORITHM_AES_256_GCM, KDF_ARGON2ID, 0]), struct.pack(">I", policy.memory_cost), struct.pack(">I", policy.iterations), struct.pack(">H", policy.lanes), salt, nonce, hashlib.sha256(aad).digest(), ciphertext])


def encrypt_with_dek(plaintext: bytes, dek: bytes, context: dict[str, Any]) -> bytes:
    """Encrypt with a 32-byte DEK. Used by KMS mode and intentionally no-opinionated about its source."""
    if len(dek) != ARGON2_KEY_LENGTH:
        raise KistError("Kist requires a 32-byte AES-256 data-encryption key.")
    nonce, aad = os.urandom(NONCE_LENGTH), _canonical_aad(context)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return _build_envelope(salt=b"\x00" * SALT_LENGTH, nonce=nonce, aad=aad, ciphertext=ciphertext, policy=Argon2Policy())


def decrypt_with_dek(envelope: bytes, dek: bytes, context: dict[str, Any]) -> bytes:
    if len(dek) != ARGON2_KEY_LENGTH:
        raise KistError("Kist requires a 32-byte AES-256 data-encryption key.")
    _validate_envelope(envelope, context)
    try:
        return AESGCM(dek).decrypt(envelope[34:46], envelope[HEADER_SIZE:], _canonical_aad(context))
    except InvalidTag as exc:
        raise DecryptionError("Ciphertext authentication failed; key may be wrong or data was modified.") from exc


def encrypt_envelope(plaintext: bytes, password: str, context: dict[str, Any], policy: Argon2Policy = Argon2Policy()) -> bytes:
    salt, nonce, aad = os.urandom(SALT_LENGTH), os.urandom(NONCE_LENGTH), _canonical_aad(context)
    ciphertext = AESGCM(_derive_aes_key(password, salt, policy)).encrypt(nonce, plaintext, aad)
    return _build_envelope(salt=salt, nonce=nonce, aad=aad, ciphertext=ciphertext, policy=policy)


def is_kist_envelope(data: bytes) -> bool:
    return len(data) >= HEADER_SIZE + 16 and data.startswith(MAGIC)


def _validate_envelope(envelope: bytes, context: dict[str, Any]) -> None:
    if not is_kist_envelope(envelope):
        raise InvalidEnvelopeError("Content is not a supported Kist envelope.")
    if envelope[4] != ENVELOPE_VERSION or envelope[5] != ALGORITHM_AES_256_GCM or envelope[6] != KDF_ARGON2ID:
        raise InvalidEnvelopeError("Unsupported Kist envelope version or algorithm.")
    memory_cost, iterations, lanes = struct.unpack(">I", envelope[8:12])[0], struct.unpack(">I", envelope[12:16])[0], struct.unpack(">H", envelope[16:18])[0]
    if not (19 * 1024 <= memory_cost <= 1024 * 1024 and 1 <= iterations <= 20 and 1 <= lanes <= 32):
        raise InvalidEnvelopeError("Envelope contains unsafe Argon2 parameters.")
    aad = _canonical_aad(context)
    if not secrets.compare_digest(envelope[46:78], hashlib.sha256(aad).digest()):
        raise DecryptionError("Ciphertext context does not match the requested Kist scope, profile, or path.")


def decrypt_envelope(envelope: bytes, password: str, context: dict[str, Any]) -> bytes:
    _validate_envelope(envelope, context)
    salt = envelope[18:34]
    policy = Argon2Policy(struct.unpack(">I", envelope[8:12])[0], struct.unpack(">I", envelope[12:16])[0], struct.unpack(">H", envelope[16:18])[0])
    return decrypt_with_dek(envelope, _derive_aes_key(password, salt, policy), context)


def git_context(profile_name: str, filepath: str, scope: Optional[KistScope] = None) -> dict[str, str]:
    scope = (scope or KistScope.from_environment()).validated()
    return {"format": "kist-git-v1", "organization": scope.organization, "project": scope.project, "profile": _validate_profile_name(profile_name), "repository": os.getenv("KIST_REPOSITORY_ID", "local-repository"), "path": os.path.normpath(filepath).replace("\\", "/")}


class Kist:
    """Database-backed store scoped by organization, project, and profile."""

    def __init__(self, profile_name: str, master_password: Optional[str] = None, db_url: Optional[str] = None, scope: Optional[KistScope] = None, key_provider: Any = None, key_reference: Any = None):
        self.profile_name = _validate_profile_name(profile_name)
        self.scope = (scope or KistScope.from_environment()).validated()
        self.key_provider = key_provider
        self.key_reference = key_reference
        self.crypto_mode = KEY_MODE_KMS_DEK if key_provider else KEY_MODE_PASSWORD
        self.master_password = master_password or (None if key_provider else get_profile_password(self.profile_name))
        if self.crypto_mode == KEY_MODE_PASSWORD and not self.master_password:
            raise MissingKeyError(f"No encryption key configured for profile {self.profile_name!r}.")
        if self.crypto_mode == KEY_MODE_KMS_DEK and not key_reference:
            raise KistError("KMS mode requires a key reference.")
        self.db_url = enforce_ssl_url(db_url or KIST_DATABASE_URL) if (db_url or KIST_DATABASE_URL) else None
        self.organization_id: Optional[uuid.UUID] = None
        self.project_id: Optional[uuid.UUID] = None
        self.profile_id: Optional[uuid.UUID] = None
        if self.db_url:
            self.organization_id, self.project_id, self.profile_id = self.get_or_create_scope()

    def get_or_create_scope(self) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
        if not self.db_url:
            raise KistError("KIST_DATABASE_URL is not configured.")
        with safe_db_connect(self.db_url) as conn, conn.cursor() as cur:
            cur.execute(SQL_SCHEMA)
            cur.execute("SELECT id FROM kist_organizations WHERE slug = %s", (self.scope.organization,))
            row = cur.fetchone(); organization_id = uuid.UUID(str(row[0])) if row else uuid.uuid4()
            if not row: cur.execute("INSERT INTO kist_organizations (id, slug) VALUES (%s, %s)", (organization_id, self.scope.organization))
            cur.execute("SELECT id FROM kist_projects WHERE organization_id = %s AND slug = %s", (organization_id, self.scope.project))
            row = cur.fetchone(); project_id = uuid.UUID(str(row[0])) if row else uuid.uuid4()
            if not row: cur.execute("INSERT INTO kist_projects (id, organization_id, slug) VALUES (%s, %s, %s)", (project_id, organization_id, self.scope.project))
            cur.execute("SELECT id FROM kist_profiles WHERE project_id = %s AND profile_name = %s", (project_id, self.profile_name))
            row = cur.fetchone(); profile_id = uuid.UUID(str(row[0])) if row else uuid.uuid4()
            if not row: cur.execute("INSERT INTO kist_profiles (id, organization_id, project_id, profile_name, crypto_salt) VALUES (%s, %s, %s, %s, %s)", (profile_id, organization_id, project_id, self.profile_name, os.urandom(SALT_LENGTH)))
            conn.commit()
            return organization_id, project_id, profile_id

    @staticmethod
    def flatten(data: dict[str, Any], parent_key: str = "", sep: str = ".") -> dict[str, Any]:
        items: dict[str, Any] = {}
        for key, value in data.items():
            name = f"{parent_key}{sep}{key}" if parent_key else str(key)
            if isinstance(value, dict): items.update(Kist.flatten(value, name, sep))
            else: items[name] = value
        return items

    @staticmethod
    def unflatten(data: dict[str, Any], sep: str = ".") -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in data.items():
            current, parts = result, str(key).split(sep)
            for part in parts[:-1]:
                existing = current.get(part)
                if existing is None: current[part] = {}
                elif not isinstance(existing, dict): raise KistError(f"Cannot reconstruct nested secret path: {key!r}")
                current = current[part]
            current[parts[-1]] = value
        return result

    def _kms_context(self) -> dict[str, str]:
        if not self.organization_id or not self.project_id or not self.profile_id: raise KistError("KIST_DATABASE_URL is not configured.")
        return {"kist": "v1", "organization_id": str(self.organization_id), "project_id": str(self.project_id), "profile_id": str(self.profile_id)}

    def _db_context(self, secret_key: str, secret_version: int = 1) -> dict[str, str]:
        context = self._kms_context()
        return {"format": "kist-db-v2", **context, "profile": self.profile_name, "secret_key": secret_key, "secret_version": str(secret_version)}

    def _load_or_create_dek(self) -> bytes:
        if not self.profile_id or not self.db_url or not self.key_provider or not self.key_reference: raise KistError("KMS profile is not initialized.")
        context = self._kms_context()
        with safe_db_connect(self.db_url) as conn, conn.cursor() as cur:
            cur.execute("SELECT provider, key_reference, key_version, wrapped_dek, encryption_context FROM kist_key_envelopes WHERE profile_id = %s AND active = TRUE", (self.profile_id,))
            row = cur.fetchone()
            if row:
                from kist.kms.base import KMSKeyReference, WrappedDataKey
                stored_context = row[4] if isinstance(row[4], dict) else json.loads(row[4])
                wrapped = WrappedDataKey(provider=row[0], key_reference=KMSKeyReference(provider=row[0], key_id=row[1], key_version=row[2]), ciphertext=bytes(row[3]), encryption_context=stored_context)
                return self.key_provider.unwrap_key(wrapped)
            self.key_provider.validate_key_reference(self.key_reference)
            dek, wrapped = self.key_provider.generate_data_key(key_reference=self.key_reference, encryption_context=context)
            if len(dek) != ARGON2_KEY_LENGTH: raise KistError("KMS provider returned an invalid DEK length.")
            cur.execute("INSERT INTO kist_key_envelopes (id, profile_id, provider, key_reference, key_version, wrapped_dek, encryption_context, active) VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE)", (uuid.uuid4(), self.profile_id, wrapped.provider, wrapped.key_reference.key_id, wrapped.key_reference.key_version, wrapped.ciphertext, json.dumps(wrapped.encryption_context)))
            conn.commit()
            return dek

    def _decrypt_value(self, blob: bytes, mode: str, key: str, version: int) -> Any:
        context = self._db_context(key, version)
        if mode == KEY_MODE_PASSWORD:
            return json.loads(decrypt_envelope(blob, self.master_password, context).decode("utf-8"))
        if mode == KEY_MODE_KMS_DEK:
            dek = self._load_or_create_dek()
            try: return json.loads(decrypt_with_dek(blob, dek, context).decode("utf-8"))
            finally: dek = b""
        raise KistError(f"Unsupported secret crypto mode: {mode}")

    def get(self, key: str) -> Any:
        if not self.profile_id or not self.db_url: raise KistError("KIST_DATABASE_URL is not configured.")
        with safe_db_connect(self.db_url) as conn, conn.cursor() as cur:
            cur.execute("SELECT encrypted_blob, secret_version, crypto_mode FROM kist WHERE profile_id = %s AND secret_key = %s", (self.profile_id, key)); row = cur.fetchone()
        if not row: raise KeyError(f"Secret key {key!r} not found for profile {self.profile_name!r}.")
        return self._decrypt_value(bytes(row[0]), row[2], key, int(row[1]))

    def lock_yaml(self, yaml_string: str, prune: bool = False) -> tuple[int, int]:
        if not self.profile_id or not self.db_url: raise KistError("KIST_DATABASE_URL is not configured.")
        data = yaml.safe_load(yaml_string)
        if not isinstance(data, dict): raise KistError("YAML file root must be a mapping.")
        flattened, pruned_count = self.flatten(data), 0
        dek = self._load_or_create_dek() if self.crypto_mode == KEY_MODE_KMS_DEK else None
        try:
            with safe_db_connect(self.db_url) as conn, conn.cursor() as cur:
                if prune:
                    cur.execute("SELECT secret_key FROM kist WHERE profile_id = %s", (self.profile_id,)); to_delete = sorted({row[0] for row in cur.fetchall()} - set(flattened))
                    if to_delete: cur.execute("DELETE FROM kist WHERE profile_id = %s AND secret_key = ANY(%s)", (self.profile_id, to_delete)); pruned_count = len(to_delete)
                for key, value in flattened.items():
                    cur.execute("SELECT secret_version FROM kist WHERE profile_id = %s AND secret_key = %s", (self.profile_id, key)); previous = cur.fetchone(); secret_version = int(previous[0]) + 1 if previous else 1
                    payload, context = json.dumps(value, separators=(",", ":")).encode("utf-8"), self._db_context(key, secret_version)
                    encrypted = encrypt_with_dek(payload, dek, context) if dek else encrypt_envelope(payload, self.master_password, context)
                    cur.execute("""INSERT INTO kist (id, profile_id, secret_key, encrypted_blob, crypto_mode, crypto_version, secret_version, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW()) ON CONFLICT (profile_id, secret_key) DO UPDATE SET encrypted_blob = EXCLUDED.encrypted_blob, crypto_mode = EXCLUDED.crypto_mode, crypto_version = EXCLUDED.crypto_version, secret_version = EXCLUDED.secret_version, updated_at = NOW()""", (uuid.uuid4(), self.profile_id, key, encrypted, self.crypto_mode, ENVELOPE_VERSION, secret_version))
                    cur.execute("SELECT pg_notify(%s, %s)", ("kist_secret_updated", json.dumps({"organization_id": str(self.organization_id), "project_id": str(self.project_id), "profile_name": self.profile_name, "profile_id": str(self.profile_id), "secret_key": key})))
                conn.commit()
        finally:
            if dek is not None: dek = b""
        return len(flattened), pruned_count

    def unlock_yaml(self) -> str:
        if not self.profile_id or not self.db_url: raise KistError("KIST_DATABASE_URL is not configured.")
        with safe_db_connect(self.db_url) as conn, conn.cursor() as cur:
            cur.execute("SELECT secret_key, encrypted_blob, secret_version, crypto_mode FROM kist WHERE profile_id = %s ORDER BY secret_key", (self.profile_id,)); rows = cur.fetchall()
        flat = {key: self._decrypt_value(bytes(blob), mode, key, int(version)) for key, blob, version, mode in rows}
        return yaml.safe_dump(self.unflatten(flat), default_flow_style=False, sort_keys=False)

    def git_clean(self) -> None:
        from kist.git import git_clean_stream
        git_clean_stream(self.profile_name, self.master_password)

    def git_smudge(self) -> None:
        from kist.git import git_smudge_stream
        git_smudge_stream(self.profile_name, self.master_password)
