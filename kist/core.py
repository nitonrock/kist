"""Kist core: password-unlocked envelope encryption and opaque PostgreSQL storage.

Initial v1 format for unshipped Kist. Only this format is supported; there are
no older-format readers or migrations. Disposable test data should be recreated
when the format changes. Git writes encrypt the whole file.
One existing profile password unlocks a randomly generated content/index key
bundle. Names and values are encrypted together; exact name lookup uses HMAC.
All mutations through this module share a transaction-scoped profile lock.

No KMS, recipients, Guard, key caching, automatic content-key rotation,
collection-completeness proof, or rollback protection is implemented here.
Future access constructions must have explicit versions and fail closed.
Profile labels, row counts, sizes, revisions, and access patterns remain visible.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import struct
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import psycopg
import yaml
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

KIST_DATABASE_URL = os.getenv("KIST_DATABASE_URL")
KEY_MODE_PASSWORD = "password-wrap-v1"
SCHEMA_VERSION = 1
MAGIC = b"KIST"
ENVELOPE_VERSION = 1
ALGORITHM_AES_256_GCM = 1
KDF_ARGON2ID = 1
ENVELOPE_FLAGS = 0
ARGON2_MEMORY_COST = 65_536
ARGON2_ITERATIONS = 2
ARGON2_LANES = 4
ARGON2_KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
AAD_HASH_LENGTH = 32
AES_GCM_TAG_LENGTH = 16
# Prefix: magic, version, cipher, KDF, flags, memory, iterations, lanes.
_PREFIX = struct.Struct(">4sBBBBIIH")
HEADER_SIZE = _PREFIX.size + SALT_LENGTH + NONCE_LENGTH + AAD_HASH_LENGTH
# v1 has a wrapped random content key after the password header.
WRAPPED_KEY_LENGTH = ARGON2_KEY_LENGTH + AES_GCM_TAG_LENGTH
_ROW_MAGIC = b"KSTR\x01"
_MAX_PASSWORD_BYTES = 1_048_576

class KistError(Exception):
    """Expected Kist failure."""

class MissingKeyError(KistError):
    """No usable profile password."""

class InvalidEnvelopeError(KistError):
    """Unsupported or malformed envelope."""

class DecryptionError(KistError):
    """Authentication or decrypted-record validation failed."""

class InsecureKeyStoreError(KistError):
    """Unsafe local credential storage."""

class ConcurrentWriteError(KistError):
    """A mutation exhausted its transaction retries."""

class SchemaVersionError(KistError):
    """Explicit initialization is required or the schema version is unsupported."""

@dataclass(frozen=True)
class Argon2Policy:
    memory_cost: int = ARGON2_MEMORY_COST
    iterations: int = ARGON2_ITERATIONS
    lanes: int = ARGON2_LANES

    def validated(self) -> Argon2Policy:
        if any(type(v) is not int for v in (self.memory_cost, self.iterations, self.lanes)):
            raise KistError("Argon2 parameters must be integers.")
        # Deliberately bounded reader workload: reject hostile high-cost headers.
        if not 19_456 <= self.memory_cost <= 262_144:
            raise KistError("Argon2 memory must be 19456..262144 KiB.")
        if not 1 <= self.iterations <= 10 or not 1 <= self.lanes <= 16:
            raise KistError("Argon2 iterations must be 1..10 and lanes 1..16.")
        if self.memory_cost < 8 * self.lanes:
            raise KistError("Argon2 memory must be at least eight times lanes.")
        return self

@dataclass(frozen=True)
class KistScope:
    organization: str = "local"
    project: str = "default"

    @classmethod
    def from_environment(cls) -> KistScope:
        return cls(os.getenv("KIST_ORG_ID", "local"),
                   os.getenv("KIST_PROJECT_ID", "default")).validated()

    def validated(self) -> KistScope:
        return KistScope(_validate_scope_name(self.organization, "organization"),
                         _validate_scope_name(self.project, "project"))

SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS kist_schema (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version INTEGER NOT NULL CHECK (version = 1)
);
INSERT INTO kist_schema (singleton, version) VALUES (TRUE, 1)
ON CONFLICT (singleton) DO NOTHING;
CREATE TABLE IF NOT EXISTS kist_organizations (
    id UUID PRIMARY KEY,
    slug VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS kist_projects (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES kist_organizations(id) ON DELETE CASCADE,
    slug VARCHAR(100) NOT NULL,
    UNIQUE (organization_id, slug)
);
CREATE TABLE IF NOT EXISTS kist_profiles (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES kist_projects(id) ON DELETE CASCADE,
    profile_name VARCHAR(100) NOT NULL,
    UNIQUE (project_id, profile_name)
);
CREATE TABLE IF NOT EXISTS kist_key_bundles (
    id UUID PRIMARY KEY,
    profile_id UUID UNIQUE NOT NULL REFERENCES kist_profiles(id) ON DELETE CASCADE,
    access_mode VARCHAR(32) NOT NULL,
    bundle_version SMALLINT NOT NULL CHECK (bundle_version = 1),
    wrapped_bundle BYTEA NOT NULL,
    wrapper_revision BIGINT NOT NULL DEFAULT 1 CHECK (wrapper_revision >= 1),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (profile_id, id)
);
CREATE TABLE IF NOT EXISTS kist_secrets (
    id UUID PRIMARY KEY,
    profile_id UUID NOT NULL REFERENCES kist_profiles(id) ON DELETE CASCADE,
    lookup_token BYTEA NOT NULL CHECK (octet_length(lookup_token) = 32),
    key_bundle_id UUID NOT NULL,
    crypto_version SMALLINT NOT NULL CHECK (crypto_version = 1),
    secret_version BIGINT NOT NULL CHECK (secret_version >= 1),
    encrypted_blob BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (profile_id, key_bundle_id)
        REFERENCES kist_key_bundles(profile_id, id),
    UNIQUE (profile_id, lookup_token)
);
"""

def generate_password(length: int = 32) -> str:
    """Length is entropy bytes, not the final string character count."""
    if type(length) is not int or length < 16:
        raise KistError("Generated passwords need at least 16 entropy bytes.")
    return secrets.token_urlsafe(length)

def get_kist_dir() -> str:
    return os.getenv("KIST_DIR") or os.path.expanduser("~/.kist")

def _validate_scope_name(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise KistError(f"{label} must be a string.")
    value = value.strip()
    if not 1 <= len(value) <= 100 or value in {".", ".."}:
        raise KistError(f"Invalid {label} name.")
    if any(c in value for c in ("/", "\\", "\x00")):
        raise KistError(f"{label} cannot contain separators or NUL.")
    return value

def _validate_profile_name(value: str) -> str:
    return _validate_scope_name(value, "profile")

def _validate_secret_key(value: str) -> str:
    if not isinstance(value, str):
        raise KistError("Secret keys must be strings.")
    value = value.strip()
    if not 1 <= len(value) <= 255 or "\x00" in value:
        raise KistError("Invalid secret key length or NUL.")
    if any(not part or part != part.strip() for part in value.split(".")):
        raise KistError("Secret keys require non-empty, unpadded dot segments.")
    return value

def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str) or not password:
        raise MissingKeyError("A non-empty profile password is required.")
    raw = password.encode("utf-8")
    if len(raw) > _MAX_PASSWORD_BYTES:
        raise KistError("Profile password is too large.")
    return raw

def profile_password_path(profile_name: str) -> Path:
    return Path(get_kist_dir()) / f"pwd_{_validate_profile_name(profile_name)}"

def _secure_status(status: os.stat_result, directory: bool = False) -> None:
    valid_kind = stat.S_ISDIR(status.st_mode) if directory else stat.S_ISREG(status.st_mode)
    if not valid_kind or status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) & 0o077:
        raise InsecureKeyStoreError("Credential storage must be owner-only and owned by this user.")

def _open_secure_directory(path: Path) -> int:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise InsecureKeyStoreError("Local credential files require POSIX no-follow support; use environment credentials.")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _secure_status(os.fstat(fd), directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise

def _check_secure_directory(path: Path) -> None:
    fd = _open_secure_directory(path)
    os.close(fd)

def read_secure_local_password(path: Path) -> str:
    """Validate the opened descriptor, not a preceding path-stat result."""
    path = Path(path)
    directory = _open_secure_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as handle:
            _secure_status(os.fstat(handle.fileno()))
            raw = handle.read(_MAX_PASSWORD_BYTES + 1)
            if len(raw) > _MAX_PASSWORD_BYTES:
                raise InsecureKeyStoreError("Credential file is too large.")
            return raw.decode("utf-8").strip()
    finally:
        os.close(directory)

def write_secure_local_password(path: Path, password: str, *, overwrite: bool = False) -> None:
    """Atomic owner-only writes; do not silently repair unsafe existing directories."""
    raw = _password_bytes(password)
    if password != password.strip():
        raise KistError("Local-file passwords cannot have surrounding whitespace.")
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = _open_secure_directory(path.parent)
    temporary = f".kist-{secrets.token_hex(16)}"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        else:
            try:
                os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory,
                        follow_symlinks=False)
            except FileExistsError as exc:
                raise KistError("Credential file already exists.") from exc
            os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)

def get_profile_password(profile_name: str, auto_generate: bool = False, *,
                         allow_env: bool = True, allow_local_file: bool = True) -> Optional[str]:
    profile = _validate_profile_name(profile_name)
    if allow_env:
        value = os.getenv(f"KIST_PASSWORD_{profile.upper()}") or os.getenv("KIST_PASSWORD")
        if value:
            return value
    if allow_local_file:
        try:
            value = read_secure_local_password(profile_password_path(profile))
        except FileNotFoundError:
            value = None
        if value:
            return value
    if auto_generate:
        raise KistError("Implicit generation is disabled; use create_profile_key().")
    return None

def create_profile_key(profile_name: str, *, rotate: bool = False) -> str:
    """Create a local password only. Replacing it is NOT ciphertext rotation."""
    if rotate:
        raise KistError("Use rewrap_profile_password(); replacing a password file is not rotation.")
    password = generate_password()
    write_secure_local_password(profile_password_path(profile_name), password)
    return password

def remove_profile_key(profile_name: str) -> bool:
    """Remove a local profile password file if it exists."""
    profile = _validate_profile_name(profile_name)
    path = profile_password_path(profile)
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return False

delete_profile_key = remove_profile_key

def resolve_secret_file_path(path_or_name: Optional[str] = None, profile: Optional[str] = None) -> str:
    if path_or_name:
        candidates = [
            path_or_name,
            f"{path_or_name}.yaml",
            f"{path_or_name}.yml",
            os.path.join("secrets", path_or_name),
            os.path.join("secrets", f"{path_or_name}.yaml"),
            os.path.join("secrets", f"{path_or_name}.yml"),
            f"secrets_{path_or_name}.yaml",
            f"secrets_{path_or_name}.yml",
            os.path.join("secrets", f"secrets_{path_or_name}.yaml"),
            os.path.join("secrets", f"secrets_{path_or_name}.yml"),
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        name = path_or_name if path_or_name.endswith((".yaml", ".yml")) else f"{path_or_name}.yaml"
        return os.path.join("secrets", name) if os.path.isdir("secrets") else name

    target_profile = _validate_profile_name(profile or os.getenv("KIST_PROFILE", "default"))
    if target_profile == "default":
        candidates = [
            os.path.join("secrets", "default.yaml"),
            os.path.join("secrets", "default.yml"),
            os.path.join("secrets", "secrets.yaml"),
            os.path.join("secrets", "secrets.yml"),
            "secrets/default.yaml",
            "secrets/default.yml",
            "secrets.yaml",
            "secrets.yml",
            "secrets_default.yaml",
            "secrets_default.yml",
            "default.yaml",
            "default.yml",
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        return os.path.join("secrets", "default.yaml") if os.path.isdir("secrets") else "secrets/default.yaml" if os.path.exists("secrets") else "secrets.yaml"

    candidates = [
        os.path.join("secrets", f"{target_profile}.yaml"),
        os.path.join("secrets", f"{target_profile}.yml"),
        os.path.join("secrets", f"secrets_{target_profile}.yaml"),
        os.path.join("secrets", f"secrets_{target_profile}.yml"),
        f"secrets_{target_profile}.yaml",
        f"secrets_{target_profile}.yml",
        f"{target_profile}.yaml",
        f"{target_profile}.yml",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return os.path.join("secrets", f"{target_profile}.yaml") if os.path.isdir("secrets") else f"secrets_{target_profile}.yaml"

def get_profile_and_password(filepath: str, auto_generate: bool = False) -> tuple[str, Optional[str]]:
    name = os.path.basename(filepath)
    base = name[:-5] if name.endswith(".yaml") else name[:-4] if name.endswith(".yml") else name
    profile = "default" if base == "secrets" else base.removeprefix("secrets_")
    profile = _validate_profile_name(profile)
    return profile, get_profile_password(profile, auto_generate)

def mask_db_url(db_url: Optional[str]) -> str:
    """Conservative diagnostic: discard userinfo, query, and fragment entirely."""
    if not db_url:
        return ""
    try:
        p = urlsplit(db_url)
        host = p.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port = f":{p.port}" if p.port else ""
        return urlunsplit((p.scheme, host + port, p.path, "", ""))
    except (ValueError, TypeError):
        return "<invalid database URL>"

def _runtime_is_production(production: Optional[bool]) -> bool:
    return production if production is not None else os.getenv("KIST_ENV", "development").strip().lower() == "production"

def enforce_ssl_url(db_url: Optional[str], default_sslmode: str = "require", *,
                    production: Optional[bool] = None) -> Optional[str]:
    if not db_url:
        return db_url
    p = urlsplit(db_url)
    if p.scheme not in {"postgres", "postgresql"} or not p.netloc or p.fragment:
        raise KistError("Database configuration must be a PostgreSQL URL without a fragment.")
    items = parse_qsl(p.query, keep_blank_values=True)
    if len({k for k, _ in items}) != len(items):
        raise KistError("Duplicate database URL options are not supported.")
    query = dict(items)
    requested = os.getenv("KIST_TLS_MODE", "auto").strip().lower()
    modes = {"disable", "require", "verify-ca", "verify-full"}
    if requested not in modes | {"auto"}:
        raise KistError("Invalid KIST_TLS_MODE.")
    effective = (query.get("sslmode") or default_sslmode).strip().lower() if requested == "auto" else requested
    if effective not in modes:
        raise KistError("Unsupported sslmode.")
    if effective == "disable" and _runtime_is_production(production):
        raise KistError("TLS cannot be disabled in production.")
    if effective in {"verify-ca", "verify-full"} and not (query.get("sslrootcert") or os.getenv("PGSSLROOTCERT")):
        raise KistError("Certificate verification requires sslrootcert or PGSSLROOTCERT.")
    query["sslmode"] = effective
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(query), ""))

def database_tls_mode(db_url: Optional[str]) -> Optional[str]:
    normalized = enforce_ssl_url(db_url)
    return dict(parse_qsl(urlsplit(normalized).query)).get("sslmode") if normalized else None

def _connection_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    # Keep URL policy from being silently overridden by libpq kwargs.
    if any(k in kwargs for k in ("sslmode", "sslrootcert", "sslcert", "sslkey", "service", "host", "hostaddr")):
        raise KistError("Specify transport settings in the database URL, not connection kwargs.")
    return kwargs

def safe_db_connect(db_url: str, **kwargs: Any) -> psycopg.Connection[Any]:
    try:
        return psycopg.connect(enforce_ssl_url(db_url), **_connection_kwargs(kwargs))
    except psycopg.OperationalError:
        raise psycopg.OperationalError(f"Database connection failed ({mask_db_url(db_url)}).") from None

async def safe_async_db_connect(db_url: str, **kwargs: Any) -> psycopg.AsyncConnection[Any]:
    try:
        return await psycopg.AsyncConnection.connect(enforce_ssl_url(db_url), **_connection_kwargs(kwargs))
    except psycopg.OperationalError:
        raise psycopg.OperationalError(f"Database connection failed ({mask_db_url(db_url)}).") from None

def _canonical_aad(context: dict[str, Any]) -> bytes:
    try:
        return json.dumps(context, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise KistError("Context must be valid JSON.") from exc

def _json_bytes(value: Any) -> bytes:
    # Reject non-string mapping keys, unsupported Python types, and non-finite numbers.
    def validate(item: Any) -> None:
        if item is None or type(item) in (str, bool, int, float):
            return
        if isinstance(item, list):
            for v in item:
                validate(v)
            return
        if isinstance(item, dict):
            if any(not isinstance(k, str) for k in item):
                raise KistError("JSON mapping keys must be strings.")
            for v in item.values():
                validate(v)
            return
        raise KistError("Secret values must use JSON types.")
    try:
        validate(value)
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise KistError("Secret value is not valid JSON.") from exc

def _strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def invalid_constant(value: str) -> None:
        raise ValueError("Invalid JSON numeric constant")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise DecryptionError("Authenticated plaintext is not valid JSON.") from exc

def _derive_aes_key(password: str, salt: bytes, policy: Argon2Policy) -> bytes:
    policy.validated()
    if len(salt) != SALT_LENGTH:
        raise InvalidEnvelopeError("Invalid salt length.")
    return Argon2id(salt=salt, length=32, iterations=policy.iterations,
                    lanes=policy.lanes, memory_cost=policy.memory_cost).derive(_password_bytes(password))

def is_kist_envelope(data: bytes) -> bool:
    """Framing check only; not proof of validity or authentication."""
    return isinstance(data, bytes) and len(data) >= HEADER_SIZE + WRAPPED_KEY_LENGTH + NONCE_LENGTH + AES_GCM_TAG_LENGTH and data.startswith(MAGIC)

def encrypt_envelope(plaintext: bytes, password: str, context: dict[str, Any],
                     policy: Argon2Policy = Argon2Policy()) -> bytes:
    """Whole-object v1: password wraps random key, random key encrypts content."""
    if not isinstance(plaintext, bytes):
        raise KistError("Plaintext must be bytes.")
    policy.validated()
    salt, wrap_nonce, data_key = os.urandom(16), os.urandom(12), os.urandom(32)
    aad = _canonical_aad(context)
    header = (_PREFIX.pack(MAGIC, ENVELOPE_VERSION, 1, 1, 0, policy.memory_cost, policy.iterations, policy.lanes)
              + salt + wrap_nonce + hashlib.sha256(aad).digest())
    wrapping_key = _derive_aes_key(password, salt, policy)
    wrapped = AESGCM(wrapping_key).encrypt(wrap_nonce, data_key, b"kist-wrap-v1\x00" + header + aad)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext,
                                         b"kist-content-v1\x00" + header + wrapped + aad)
    return header + wrapped + nonce + ciphertext

def decrypt_envelope(envelope: bytes, password: str, context: dict[str, Any]) -> bytes:
    """Authenticate and decrypt the sole supported random-key v1 envelope."""
    if not is_kist_envelope(envelope):
        raise InvalidEnvelopeError("Not a Kist envelope.")
    magic, version, algorithm, kdf, flags, memory, iterations, lanes = _PREFIX.unpack(envelope[:_PREFIX.size])
    if version != ENVELOPE_VERSION or (algorithm, kdf, flags) != (1, 1, 0):
        raise InvalidEnvelopeError("Unsupported envelope version or algorithms.")
    try:
        policy = Argon2Policy(memory, iterations, lanes).validated()
    except KistError as exc:
        raise InvalidEnvelopeError("KDF parameters exceed supported reader limits.") from exc
    salt = envelope[18:34]
    wrap_nonce = envelope[34:46]
    aad = _canonical_aad(context)
    if not hmac.compare_digest(envelope[46:78], hashlib.sha256(aad).digest()):
        raise DecryptionError("Envelope context mismatch.")
    if len(envelope) < HEADER_SIZE + WRAPPED_KEY_LENGTH + 12 + 16:
        raise InvalidEnvelopeError("Truncated v1 envelope.")
    wrapping_key = _derive_aes_key(password, salt, policy)
    try:
        header = envelope[:HEADER_SIZE]
        wrapped = envelope[HEADER_SIZE:HEADER_SIZE + WRAPPED_KEY_LENGTH]
        data_key = AESGCM(wrapping_key).decrypt(wrap_nonce, wrapped, b"kist-wrap-v1\x00" + header + aad)
        start = HEADER_SIZE + WRAPPED_KEY_LENGTH
        return AESGCM(data_key).decrypt(envelope[start:start + 12], envelope[start + 12:],
                                         b"kist-content-v1\x00" + header + wrapped + aad)
    except InvalidTag as exc:
        raise DecryptionError("Wrong password or modified ciphertext.") from exc

def git_context(profile_name: str, filepath: str, scope: Optional[KistScope] = None) -> dict[str, str]:
    """Build authenticated context for whole-file Git encryption.

    Callers must pass a canonical repository-relative path on every platform.
    Renaming paths/scope/repository IDs requires decrypting and re-encrypting.
    """
    scope = (scope or KistScope.from_environment()).validated()
    return {"format": "kist-git-v1", "organization": scope.organization,
            "project": scope.project, "profile": _validate_profile_name(profile_name),
            "repository": os.getenv("KIST_REPOSITORY_ID", "local-repository"),
            "path": os.path.normpath(filepath).replace("\\", "/")}

@dataclass(frozen=True)
class _KeyBundle:
    id: uuid.UUID
    content_key: bytes
    index_key: bytes

# Reject duplicate YAML keys instead of silently keeping the last value, while supporting YAML merge keys (<<).
class _UniqueSafeLoader(yaml.SafeLoader):
    pass

def _unique_mapping(loader: _UniqueSafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict[str, Any]:
    seen_explicit_keys: set[str] = set()
    for key_node, _ in node.value:
        if key_node.tag != "tag:yaml.org,2002:merge":
            key = loader.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise KistError("YAML keys must be strings.")
            if key in seen_explicit_keys:
                raise KistError(f"Duplicate YAML key: {key!r}")
            seen_explicit_keys.add(key)

    loader.flatten_mapping(node)
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise KistError("YAML keys must be strings.")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result

_UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)

class Kist:
    """One scoped password-only store. No decrypted keys are cached between calls.

    Initialization is explicit. Scope rows may be created on first use; key
    bundles are created only by writes. Methods open their own READ COMMITTED
    transactions. Restrict the database role and search_path to trusted schemas.
    """
    def __init__(self, profile_name: Optional[str] = None, master_password: Optional[str] = None,
                 db_url: Optional[str] = None, scope: Optional[KistScope] = None) -> None:
        resolved_profile = profile_name if profile_name is not None else os.getenv("KIST_PROFILE", "default")
        self.profile_name = _validate_profile_name(resolved_profile)
        self.scope = (scope or KistScope.from_environment()).validated()
        self.master_password = master_password if master_password is not None else get_profile_password(self.profile_name)
        if self.master_password is not None:
            _password_bytes(self.master_password)
        configured = os.getenv("KIST_DATABASE_URL") if db_url is None else db_url
        self.db_url = enforce_ssl_url(configured) if configured else None
        self.organization_id: Optional[uuid.UUID] = None
        self.project_id: Optional[uuid.UUID] = None
        self.profile_id: Optional[uuid.UUID] = None

    @classmethod
    def from_file(cls, path: Any, **kwargs: Any) -> Any:
        """Open a read-only, offline store from an encrypted Kist envelope file.

        No database is used. See :class:`kist.file_store.FileKist`.
        """
        from kist.file_store import FileKist
        return FileKist(path, **kwargs)

    def _require_password(self) -> str:
        if not self.master_password:
            raise MissingKeyError(f"No encryption key configured for profile {self.profile_name!r}.")
        return self.master_password

    def _require_database(self) -> str:
        if not self.db_url:
            raise KistError("KIST_DATABASE_URL is not configured.")
        return self.db_url

    @classmethod
    def _check_schema(cls, cursor: psycopg.Cursor[Any]) -> None:
        cursor.execute("SELECT to_regclass('kist_schema')")
        if cursor.fetchone()[0] is None:
            raise SchemaVersionError("Initialize the v1 schema explicitly with init_db().")
        cursor.execute("SELECT version FROM kist_schema WHERE singleton = TRUE")
        row = cursor.fetchone()
        if row is None or row[0] != SCHEMA_VERSION:
            raise SchemaVersionError("Unsupported Kist schema version.")

    def init_db(self) -> None:
        with safe_db_connect(self._require_database()) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(%s)", (_lock_id("kist-v1-schema"),))
                cursor.execute(SQL_SCHEMA)
                self._check_schema(cursor)

    def get_or_create_scope(self) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
        with safe_db_connect(self._require_database()) as connection:
            with connection.cursor() as cursor:
                self._check_schema(cursor)
                cursor.execute("""INSERT INTO kist_organizations (id, slug) VALUES (%s, %s)
                    ON CONFLICT (slug) DO UPDATE SET slug = EXCLUDED.slug RETURNING id""",
                    (uuid.uuid4(), self.scope.organization))
                org = uuid.UUID(str(cursor.fetchone()[0]))
                cursor.execute("""INSERT INTO kist_projects (id, organization_id, slug) VALUES (%s, %s, %s)
                    ON CONFLICT (organization_id, slug) DO UPDATE SET slug = EXCLUDED.slug RETURNING id""",
                    (uuid.uuid4(), org, self.scope.project))
                project = uuid.UUID(str(cursor.fetchone()[0]))
                cursor.execute("""INSERT INTO kist_profiles (id, project_id, profile_name) VALUES (%s, %s, %s)
                    ON CONFLICT (project_id, profile_name) DO UPDATE
                    SET profile_name = EXCLUDED.profile_name RETURNING id""",
                    (uuid.uuid4(), project, self.profile_name))
                profile = uuid.UUID(str(cursor.fetchone()[0]))
        self.organization_id, self.project_id, self.profile_id = org, project, profile
        return org, project, profile

    def _ensure_scope(self) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
        if self.organization_id is None or self.project_id is None or self.profile_id is None:
            return self.get_or_create_scope()
        return self.organization_id, self.project_id, self.profile_id

    def _scope_context(self) -> dict[str, str]:
        org, project, profile = self._ensure_scope()
        return {"organization_id": str(org), "project_id": str(project), "profile_id": str(profile)}

    def _bundle_context(self, bundle_id: uuid.UUID) -> dict[str, str]:
        return {"format": "kist-db-key-bundle-v1", **self._scope_context(),
                "bundle_id": str(bundle_id), "bundle_version": "1", "access_mode": KEY_MODE_PASSWORD}

    def _load_bundle(self, cursor: psycopg.Cursor[Any], *, create: bool = False) -> Optional[_KeyBundle]:
        _, _, profile = self._ensure_scope()
        cursor.execute("""SELECT id, access_mode, bundle_version, wrapped_bundle
                          FROM kist_key_bundles WHERE profile_id = %s""", (profile,))
        row = cursor.fetchone()
        if row is None:
            if not create:
                return None
            bundle = _KeyBundle(uuid.uuid4(), os.urandom(32), os.urandom(32))
            # Binary payload contains two separately generated keys.
            wrapped = encrypt_envelope(b"KKB1" + bundle.content_key + bundle.index_key,
                                       self._require_password(), self._bundle_context(bundle.id))
            cursor.execute("""INSERT INTO kist_key_bundles
                (id, profile_id, access_mode, bundle_version, wrapped_bundle)
                VALUES (%s, %s, %s, 1, %s)""", (bundle.id, profile, KEY_MODE_PASSWORD, wrapped))
            return bundle
        bundle_id, mode, version, blob = row
        if mode != KEY_MODE_PASSWORD or version != 1:
            raise InvalidEnvelopeError("Unsupported key access mode or bundle version; no fallback permitted.")
        raw_blob = bytes(blob)
        if len(raw_blob) < 5 or raw_blob[4] != ENVELOPE_VERSION:
            raise InvalidEnvelopeError("Database key bundles require envelope v1.")
        raw = decrypt_envelope(raw_blob, self._require_password(), self._bundle_context(uuid.UUID(str(bundle_id))))
        if len(raw) != 68 or not raw.startswith(b"KKB1"):
            raise DecryptionError("Invalid key bundle payload.")
        return _KeyBundle(uuid.UUID(str(bundle_id)), raw[4:36], raw[36:68])

    def _lookup_token(self, bundle: _KeyBundle, key: str) -> bytes:
        context = {"format": "kist-name-index-v1", **self._scope_context(),
                   "secret_key": _validate_secret_key(key)}
        return hmac.new(bundle.index_key, _canonical_aad(context), hashlib.sha256).digest()

    def _row_context(self, bundle: _KeyBundle, row_id: uuid.UUID, token: bytes, version: int) -> bytes:
        if type(version) is not int or version < 1:
            raise InvalidEnvelopeError("Invalid secret version.")
        return _canonical_aad({"format": "kist-db-record-v1", **self._scope_context(),
                               "row_id": str(row_id), "bundle_id": str(bundle.id),
                               "lookup_token": token.hex(), "secret_version": str(version),
                               "crypto_version": "1"})

    def _decode_row(self, bundle: _KeyBundle, row: Any, expected_key: Optional[str] = None) -> tuple[str, Any]:
        row_id, token, bundle_id, crypto_version, version, blob = row
        token, blob = bytes(token), bytes(blob)
        if uuid.UUID(str(bundle_id)) != bundle.id or crypto_version != 1:
            raise InvalidEnvelopeError("Unsupported record key reference or format.")
        if len(token) != 32 or len(blob) < len(_ROW_MAGIC) + 12 + 16 or not blob.startswith(_ROW_MAGIC):
            raise InvalidEnvelopeError("Malformed encrypted database record.")
        start = len(_ROW_MAGIC)
        aad = self._row_context(bundle, uuid.UUID(str(row_id)), token, int(version))
        try:
            raw = AESGCM(bundle.content_key).decrypt(blob[start:start + 12], blob[start + 12:], _ROW_MAGIC + aad)
        except InvalidTag as exc:
            raise DecryptionError("Database record authentication failed.") from exc
        record = _strict_json(raw)
        if not isinstance(record, dict) or set(record) != {"key", "value"}:
            raise DecryptionError("Invalid encrypted record payload.")
        try:
            key = _validate_secret_key(record["key"])
        except KistError as exc:
            raise DecryptionError("Invalid encrypted secret name.") from exc
        if key != record["key"] or not hmac.compare_digest(token, self._lookup_token(bundle, key)):
            raise DecryptionError("Encrypted name does not match lookup token.")
        if expected_key is not None and key != expected_key:
            raise DecryptionError("Encrypted name does not match requested name.")
        return key, record["value"]

    def _lock_profile(self, cursor: psycopg.Cursor[Any]) -> None:
        _, _, profile = self._ensure_scope()
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", (_lock_id(f"kist-v1-profile:{profile}"),))

    def _notify(self, cursor: psycopg.Cursor[Any], row_id: uuid.UUID, event: str) -> None:
        cursor.execute("SELECT pg_notify(%s, %s)", ("kist_secret_updated", json.dumps(
            {"format": "kist-invalidation-v1", "profile_id": str(self.profile_id),
             "secret_id": str(row_id), "event": event}, separators=(",", ":"))))

    def _write(self, operation: Callable[[psycopg.Cursor[Any]], Any], max_retries: int = 3) -> Any:
        if type(max_retries) is not int or not 1 <= max_retries <= 20:
            raise KistError("max_retries must be 1..20.")
        self._ensure_scope()
        for attempt in range(max_retries):
            try:
                with safe_db_connect(self._require_database()) as connection:
                    with connection.cursor() as cursor:
                        cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                        self._check_schema(cursor)
                        self._lock_profile(cursor)
                        result = operation(cursor)
                return result
            except (psycopg.errors.SerializationFailure, psycopg.errors.DeadlockDetected) as exc:
                if attempt + 1 == max_retries:
                    raise ConcurrentWriteError("Mutation exhausted transaction retries.") from exc
                time.sleep(min(0.02 * 2 ** attempt, 0.5) + secrets.randbelow(20) / 1000)
        raise AssertionError("Unreachable retry exit")

    def _store(self, cursor: psycopg.Cursor[Any], bundle: _KeyBundle, key: str, value: Any) -> int:
        token = self._lookup_token(bundle, key)
        cursor.execute("""SELECT id, lookup_token, key_bundle_id, crypto_version, secret_version, encrypted_blob
            FROM kist_secrets WHERE profile_id = %s AND lookup_token = %s""", (self.profile_id, token))
        old = cursor.fetchone()
        if old:
            self._decode_row(bundle, old, key)
        row_id = uuid.UUID(str(old[0])) if old else uuid.uuid4()
        version = int(old[4]) + 1 if old else 1
        if version > 2 ** 63 - 1:
            raise KistError("Secret version exhausted.")
        nonce = os.urandom(12)
        aad = self._row_context(bundle, row_id, token, version)
        blob = _ROW_MAGIC + nonce + AESGCM(bundle.content_key).encrypt(
            nonce, _json_bytes({"key": key, "value": value}), _ROW_MAGIC + aad)
        if old:
            cursor.execute("""UPDATE kist_secrets SET encrypted_blob = %s,
                secret_version = %s, updated_at = NOW() WHERE id = %s AND profile_id = %s""",
                (blob, version, row_id, self.profile_id))
        else:
            cursor.execute("""INSERT INTO kist_secrets
                (id, profile_id, lookup_token, key_bundle_id, crypto_version, secret_version, encrypted_blob)
                VALUES (%s, %s, %s, %s, 1, %s, %s)""",
                (row_id, self.profile_id, token, bundle.id, version, blob))
        self._notify(cursor, row_id, "updated")
        return version

    def set(self, key: str, value: Any, max_retries: int = 3) -> int:
        key = _validate_secret_key(key)
        _json_bytes(value)
        def operation(cursor: psycopg.Cursor[Any]) -> int:
            bundle = self._load_bundle(cursor, create=True)
            assert bundle is not None
            return self._store(cursor, bundle, key, value)
        return self._write(operation, max_retries)

    def get(self, key: str) -> Any:
        key = _validate_secret_key(key)
        self._ensure_scope()
        with safe_db_connect(self._require_database()) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                self._check_schema(cursor)
                bundle = self._load_bundle(cursor)
                if bundle is None:
                    raise KeyError(key)
                cursor.execute("""SELECT id, lookup_token, key_bundle_id, crypto_version, secret_version, encrypted_blob
                    FROM kist_secrets WHERE profile_id = %s AND lookup_token = %s""",
                    (self.profile_id, self._lookup_token(bundle, key)))
                row = cursor.fetchone()
                if row is None:
                    raise KeyError(key)
                return self._decode_row(bundle, row, key)[1]

    def delete(self, key: str) -> bool:
        key = _validate_secret_key(key)
        def operation(cursor: psycopg.Cursor[Any]) -> bool:
            bundle = self._load_bundle(cursor)
            if bundle is None:
                return False
            cursor.execute("""SELECT id, lookup_token, key_bundle_id, crypto_version, secret_version, encrypted_blob
                FROM kist_secrets WHERE profile_id = %s AND lookup_token = %s""",
                (self.profile_id, self._lookup_token(bundle, key)))
            row = cursor.fetchone()
            if row is None:
                return False
            self._decode_row(bundle, row, key)
            row_id = uuid.UUID(str(row[0]))
            cursor.execute("DELETE FROM kist_secrets WHERE id = %s AND profile_id = %s", (row_id, self.profile_id))
            self._notify(cursor, row_id, "deleted")
            return True
        return self._write(operation)

    def delete_profile(self, profile_name: Optional[str] = None) -> bool:
        target_profile = _validate_profile_name(profile_name or self.profile_name)
        with safe_db_connect(self._require_database()) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                self._check_schema(cursor)
                cursor.execute("SELECT id FROM kist_organizations WHERE slug = %s", (self.scope.organization,))
                org_row = cursor.fetchone()
                if org_row is None:
                    return False
                org_id = uuid.UUID(str(org_row[0]))
                cursor.execute("SELECT id FROM kist_projects WHERE organization_id = %s AND slug = %s", (org_id, self.scope.project))
                proj_row = cursor.fetchone()
                if proj_row is None:
                    return False
                project_id = uuid.UUID(str(proj_row[0]))
                cursor.execute("SELECT id FROM kist_profiles WHERE project_id = %s AND profile_name = %s", (project_id, target_profile))
                profile_row = cursor.fetchone()
                if profile_row is None:
                    return False
                profile_id = uuid.UUID(str(profile_row[0]))
                cursor.execute("DELETE FROM kist_profiles WHERE id = %s", (profile_id,))
                if self.profile_id == profile_id:
                    self.profile_id = None
                return True

    @staticmethod
    def flatten(data: dict[str, Any], parent_key: str = "", sep: str = ".") -> dict[str, Any]:
        if sep != ".":
            raise KistError("Only the dot path separator is supported.")
        if not isinstance(data, dict):
            raise KistError("Secret data must be a mapping.")
        result: dict[str, Any] = {}
        active: set[int] = set()
        def walk(mapping: dict[str, Any], parent: str) -> None:
            if id(mapping) in active:
                raise KistError("Recursive YAML mappings are unsupported.")
            active.add(id(mapping))
            normalized: set[str] = set()
            try:
                for raw_key, value in mapping.items():
                    if not isinstance(raw_key, str):
                        raise KistError("YAML mapping keys must be strings.")
                    segment = raw_key.strip()
                    if not segment or "." in segment or "\x00" in segment or segment in normalized:
                        raise KistError("Invalid or normalization-colliding YAML key.")
                    normalized.add(segment)
                    name = _validate_secret_key(f"{parent}.{segment}" if parent else segment)
                    if isinstance(value, dict) and value:
                        walk(value, name)
                    else:
                        _json_bytes(value)
                        result[name] = value
            finally:
                active.remove(id(mapping))
        walk(data, parent_key)
        return result

    @staticmethod
    def unflatten(data: dict[str, Any], sep: str = ".") -> dict[str, Any]:
        if sep != ".":
            raise KistError("Only the dot separator is supported.")
        root: dict[str, Any] = {}
        leaves: set[tuple[str, ...]] = set()
        normalized: set[str] = set()
        for raw_key, value in data.items():
            key = _validate_secret_key(raw_key)
            if key in normalized:
                raise KistError("Normalization-colliding secret paths.")
            normalized.add(key)
            parts = key.split(".")
            current = root
            for index, part in enumerate(parts[:-1], 1):
                if tuple(parts[:index]) in leaves:
                    raise KistError("Conflicting leaf and nested secret paths.")
                current = current.setdefault(part, {})
            if parts[-1] in current:
                raise KistError("Conflicting leaf and nested secret paths.")
            current[parts[-1]] = value
            leaves.add(tuple(parts))
        return root

    def lock_yaml(self, yaml_string: str, prune: bool = False) -> tuple[int, int]:
        try:
            loaded = yaml.load(yaml_string, Loader=_UniqueSafeLoader)
        except (yaml.YAMLError, RecursionError) as exc:
            raise KistError("Invalid secret YAML.") from exc
        flattened = self.flatten({} if loaded is None else loaded)
        def operation(cursor: psycopg.Cursor[Any]) -> tuple[int, int]:
            bundle = self._load_bundle(cursor, create=True)
            assert bundle is not None
            removed = 0
            if prune:
                wanted = {self._lookup_token(bundle, k) for k in flattened}
                cursor.execute("""SELECT id, lookup_token, key_bundle_id, crypto_version, secret_version, encrypted_blob
                    FROM kist_secrets WHERE profile_id = %s""", (self.profile_id,))
                for row in cursor.fetchall():
                    self._decode_row(bundle, row)
                    if bytes(row[1]) not in wanted:
                        row_id = uuid.UUID(str(row[0]))
                        cursor.execute("DELETE FROM kist_secrets WHERE id = %s AND profile_id = %s", (row_id, self.profile_id))
                        self._notify(cursor, row_id, "deleted")
                        removed += 1
            for key in sorted(flattened):
                self._store(cursor, bundle, key, flattened[key])
            return len(flattened), removed
        return self._write(operation)

    def unlock_yaml(self) -> str:
        self._ensure_scope()
        with safe_db_connect(self._require_database()) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                self._check_schema(cursor)
                bundle = self._load_bundle(cursor)
                if bundle is None:
                    return "{}\n"
                cursor.execute("""SELECT id, lookup_token, key_bundle_id, crypto_version, secret_version, encrypted_blob
                    FROM kist_secrets WHERE profile_id = %s""", (self.profile_id,))
                values: dict[str, Any] = {}
                for row in cursor.fetchall():
                    key, value = self._decode_row(bundle, row)
                    if key in values:
                        raise DecryptionError("Duplicate decrypted secret names.")
                    values[key] = value
        nested = self.unflatten(dict(sorted(values.items())))
        return yaml.safe_dump(nested, default_flow_style=False, sort_keys=False, allow_unicode=True)

    def rewrap_profile_password(self, new_password: str, *, policy: Argon2Policy = Argon2Policy()) -> None:
        """Rewrap DB keys only; does NOT rotate data/index keys or change Git/files/env.

        Old snapshots and previously obtained keys remain usable. Update password
        provisioning separately; this is not an atomic cross-platform operation.
        Do not concurrently share this instance while changing its password.
        """
        _password_bytes(new_password)
        policy.validated()
        def operation(cursor: psycopg.Cursor[Any]) -> None:
            bundle = self._load_bundle(cursor)
            if bundle is None:
                raise KistError("No profile key bundle exists to rewrap.")
            wrapped = encrypt_envelope(b"KKB1" + bundle.content_key + bundle.index_key,
                                       new_password, self._bundle_context(bundle.id), policy)
            cursor.execute("""UPDATE kist_key_bundles SET wrapped_bundle = %s,
                wrapper_revision = wrapper_revision + 1, updated_at = NOW()
                WHERE id = %s AND profile_id = %s""", (wrapped, bundle.id, self.profile_id))
            self._notify(cursor, bundle.id, "key_bundle_rewrapped")
        self._write(operation)
        self.master_password = new_password

    def git_clean(self) -> None:
        from kist.git import git_clean_stream
        git_clean_stream(self.profile_name, self.master_password)

    def git_smudge(self) -> None:
        from kist.git import git_smudge_stream
        git_smudge_stream(self.profile_name, self.master_password)


def _lock_id(name: str) -> int:
    """Stable signed 64-bit advisory ID; collisions serialize, not bypass locks."""
    return int.from_bytes(hashlib.sha256(name.encode("utf-8")).digest()[:8], "big", signed=True)