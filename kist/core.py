"""Kist core: password-backed encrypted secret storage.

Kist 0.1.0 stores JSON-serializable secret values encrypted in PostgreSQL and
supports encrypted Git clean/smudge workflows through helpers used by
``kist.git``.

Security model:
- Secret values are encrypted with AES-256-GCM.
- Password-derived encryption keys use Argon2id.
- Every encryption receives a fresh random salt and nonce.
- Authenticated context binds ciphertext to a Kist scope, profile, secret key,
  secret version, or Git repository path.
- Password-v1 is the only supported database envelope mode in this release.

Non-goals for 0.1.0:
- KMS data-encryption keys.
- Kist Guard integration.
- Automatic key rotation.

This module does not contact a hosted Kist service. It uses only the configured
PostgreSQL database and local runtime key material.
"""

from __future__ import annotations

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


# ---------------------------------------------------------------------------
# Public constants and envelope format
# ---------------------------------------------------------------------------

KIST_DATABASE_URL = os.getenv("KIST_DATABASE_URL")

KEY_MODE_PASSWORD = "password-v1"

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

MAGIC_OFFSET = 0
VERSION_OFFSET = 4
ALGORITHM_OFFSET = 5
KDF_OFFSET = 6
FLAGS_OFFSET = 7

MEMORY_COST_OFFSET = 8
ITERATIONS_OFFSET = 12
LANES_OFFSET = 16
SALT_OFFSET = 18
NONCE_OFFSET = SALT_OFFSET + SALT_LENGTH
AAD_HASH_OFFSET = NONCE_OFFSET + NONCE_LENGTH
CIPHERTEXT_OFFSET = AAD_HASH_OFFSET + AAD_HASH_LENGTH

HEADER_SIZE = CIPHERTEXT_OFFSET


# ---------------------------------------------------------------------------
# Errors and configuration types
# ---------------------------------------------------------------------------

class KistError(Exception):
    """Base class for expected Kist errors."""


class MissingKeyError(KistError):
    """Raised when no password is available for a requested Kist profile."""


class InvalidEnvelopeError(KistError):
    """Raised when content is not a supported Kist encrypted envelope."""


class DecryptionError(KistError):
    """Raised when ciphertext cannot be authenticated or decrypted."""


class InsecureKeyStoreError(KistError):
    """Raised when a local password file lacks minimum POSIX protections."""


class ConcurrentWriteError(KistError):
    """Raised when Kist cannot safely serialize a secret update."""


@dataclass(frozen=True)
class Argon2Policy:
    """Parameters recorded in a password-v1 envelope."""

    memory_cost: int = ARGON2_MEMORY_COST
    iterations: int = ARGON2_ITERATIONS
    lanes: int = ARGON2_LANES

    def validated(self) -> "Argon2Policy":
        """Return validated KDF policy parameters."""
        if not 19 * 1024 <= self.memory_cost <= 1024 * 1024:
            raise KistError(
                "Argon2 memory cost must be between 19456 and 1048576 KiB."
            )

        if not 1 <= self.iterations <= 20:
            raise KistError(
                "Argon2 iterations must be between 1 and 20."
            )

        if not 1 <= self.lanes <= 32:
            raise KistError(
                "Argon2 lanes must be between 1 and 32."
            )

        if self.memory_cost < 8 * self.lanes:
            raise KistError(
                "Argon2 memory cost must be at least eight times the lane count."
            )

        return self


@dataclass(frozen=True)
class KistScope:
    """Logical Kist organization and project boundary."""

    organization: str = "local"
    project: str = "default"

    @classmethod
    def from_environment(cls) -> "KistScope":
        """Load scope settings from the process environment."""
        return cls(
            organization=os.getenv("KIST_ORG_ID", "local"),
            project=os.getenv("KIST_PROJECT_ID", "default"),
        ).validated()

    def validated(self) -> "KistScope":
        """Validate and normalize the organization/project values."""
        return KistScope(
            organization=_validate_scope_name(
                self.organization,
                "organization",
            ),
            project=_validate_scope_name(
                self.project,
                "project",
            ),
        )


# ---------------------------------------------------------------------------
# PostgreSQL schema
# ---------------------------------------------------------------------------

SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS kist_organizations (
    id UUID PRIMARY KEY,
    slug VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kist_projects (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL
        REFERENCES kist_organizations(id)
        ON DELETE CASCADE,
    slug VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_kist_project UNIQUE (organization_id, slug)
);

CREATE TABLE IF NOT EXISTS kist_profiles (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL
        REFERENCES kist_organizations(id)
        ON DELETE CASCADE,
    project_id UUID NOT NULL
        REFERENCES kist_projects(id)
        ON DELETE CASCADE,
    profile_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_kist_profile UNIQUE (project_id, profile_name)
);

CREATE TABLE IF NOT EXISTS kist (
    id UUID PRIMARY KEY,
    profile_id UUID NOT NULL
        REFERENCES kist_profiles(id)
        ON DELETE CASCADE,
    secret_key VARCHAR(255) NOT NULL,
    encrypted_blob BYTEA NOT NULL,
    crypto_mode VARCHAR(32) NOT NULL DEFAULT 'password-v1',
    crypto_version SMALLINT NOT NULL DEFAULT 1,
    secret_version BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_profile_secret UNIQUE (profile_id, secret_key)
);

CREATE INDEX IF NOT EXISTS idx_kist_profile_lookup
    ON kist (profile_id, secret_key);
"""


# ---------------------------------------------------------------------------
# Naming and local-password helpers
# ---------------------------------------------------------------------------

def generate_password(length: int = 32) -> str:
    """Generate a high-entropy URL-safe profile password."""
    if length < 16:
        raise KistError(
            "Generated profile passwords must contain at least 16 bytes."
        )

    return secrets.token_urlsafe(length)


def get_kist_dir() -> str:
    """Return the directory that holds optional local profile password files."""
    return os.getenv("KIST_DIR") or os.path.expanduser("~/.kist")


def _validate_scope_name(value: str, label: str) -> str:
    """Validate a profile, organization, or project name."""
    if not isinstance(value, str):
        raise KistError(
            f"{label.capitalize()} names must be strings."
        )

    normalized = value.strip()

    if not normalized or len(normalized) > 100:
        raise KistError(
            f"{label.capitalize()} names must contain between 1 and "
            "100 characters."
        )

    if any(character in normalized for character in ("/", "\\", "\x00")):
        raise KistError(
            f"{label.capitalize()} names cannot contain path separators "
            "or NUL bytes."
        )

    return normalized


def _validate_profile_name(profile_name: str) -> str:
    """Validate a profile name."""
    return _validate_scope_name(profile_name, "profile")


def _validate_secret_key(secret_key: str) -> str:
    """Validate a dot-separated logical secret key."""
    if not isinstance(secret_key, str):
        raise KistError("Secret keys must be strings.")

    normalized = secret_key.strip()

    if not normalized:
        raise KistError("Secret keys must not be empty.")

    if len(normalized) > 255:
        raise KistError(
            "Secret keys must contain at most 255 characters."
        )

    if "\x00" in normalized:
        raise KistError("Secret keys cannot contain NUL bytes.")

    if (
        normalized.startswith(".")
        or normalized.endswith(".")
        or ".." in normalized
    ):
        raise KistError(
            "Secret keys must use non-empty dot-separated path segments."
        )

    return normalized


def profile_password_path(profile_name: str) -> Path:
    """Return the expected local password-file path for a profile."""
    profile = _validate_profile_name(profile_name)
    return Path(get_kist_dir()) / f"pwd_{profile}"


def _check_secure_directory(path: Path) -> None:
    """Ensure a local password directory is owner-only on POSIX."""
    if os.name == "nt":
        return

    status = path.stat()

    if status.st_uid != os.getuid():
        raise InsecureKeyStoreError(
            "Kist directory is not owned by the current user: "
            f"{path}"
        )

    if stat.S_IMODE(status.st_mode) & 0o077:
        raise InsecureKeyStoreError(
            "Kist directory must not be readable, writable, or searchable "
            f"by group or other users: {path}"
        )


def read_secure_local_password(path: Path) -> str:
    """Read an owner-only local password file without following symlinks."""
    if os.name == "nt":
        return path.read_text(encoding="utf-8").strip()

    status = path.lstat()

    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise InsecureKeyStoreError(
            "Credential path is not a regular non-symlink file: "
            f"{path}"
        )

    if status.st_uid != os.getuid():
        raise InsecureKeyStoreError(
            "Credential file is not owned by the current user: "
            f"{path}"
        )

    if stat.S_IMODE(status.st_mode) & 0o077:
        raise InsecureKeyStoreError(
            "Credential file must not be readable or writable by group "
            f"or other users: {path}"
        )

    return path.read_text(encoding="utf-8").strip()


def write_secure_local_password(
    path: Path,
    password: str,
    *,
    overwrite: bool = False,
) -> None:
    """Write a local profile password with POSIX owner-only protections."""
    if not password:
        raise KistError("Profile passwords must not be empty.")

    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    if os.name == "nt":
        if path.exists() and not overwrite:
            raise KistError(
                f"Credential file already exists: {path}"
            )

        path.write_text(password, encoding="utf-8")
        return

    os.chmod(directory, 0o700)
    _check_secure_directory(directory)

    flags = os.O_WRONLY | os.O_CREAT

    if overwrite:
        flags |= os.O_TRUNC
    else:
        flags |= os.O_EXCL

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        descriptor = os.open(str(path), flags, 0o600)
    except FileExistsError as exc:
        raise KistError(
            f"Credential file already exists: {path}"
        ) from exc

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(password)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if not overwrite:
            path.unlink(missing_ok=True)
        raise


def get_profile_password(
    profile_name: str,
    auto_generate: bool = False,
    *,
    allow_env: bool = True,
    allow_local_file: bool = True,
) -> Optional[str]:
    """Find a profile password from explicit environment or local file sources.

    ``auto_generate`` is retained for compatibility but intentionally does not
    generate a secret implicitly. Use :func:`create_profile_key` instead.
    """
    profile = _validate_profile_name(profile_name)

    if allow_env:
        profile_environment_key = (
            "KIST_PASSWORD_DEFAULT"
            if profile == "default"
            else f"KIST_PASSWORD_{profile.upper()}"
        )

        password = (
            os.getenv(profile_environment_key)
            or os.getenv("KIST_PASSWORD")
        )

        if password:
            return password

    password_path = profile_password_path(profile)

    if allow_local_file and password_path.exists():
        password = read_secure_local_password(password_path)

        if password:
            return password

    if auto_generate:
        raise KistError(
            "Implicit profile-password generation is disabled. "
            "Use create_profile_key() or `kist profile create <name>`."
        )

    return None


def create_profile_key(
    profile_name: str,
    *,
    rotate: bool = False,
) -> str:
    """Create or intentionally replace one local profile password."""
    profile = _validate_profile_name(profile_name)
    password = generate_password()

    write_secure_local_password(
        profile_password_path(profile),
        password,
        overwrite=rotate,
    )

    return password


# ---------------------------------------------------------------------------
# File, profile, and database URL helpers
# ---------------------------------------------------------------------------

def resolve_secret_file_path(path_or_name: str) -> str:
    """Resolve common Kist secret-file naming conventions."""
    candidates = [
        path_or_name,
        f"{path_or_name}.yaml",
        f"{path_or_name}.yml",
        os.path.join("secrets", path_or_name),
        os.path.join("secrets", f"{path_or_name}.yaml"),
        os.path.join("secrets", f"{path_or_name}.yml"),
    ]

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    if os.path.isdir("secrets"):
        if path_or_name.endswith((".yaml", ".yml")):
            return os.path.join("secrets", path_or_name)

        return os.path.join("secrets", f"{path_or_name}.yaml")

    if path_or_name.endswith((".yaml", ".yml")):
        return path_or_name

    return f"{path_or_name}.yaml"


def get_profile_and_password(
    filepath: str,
    auto_generate: bool = False,
) -> tuple[str, Optional[str]]:
    """Infer a Kist profile from a conventional secret-file name."""
    file_name = os.path.basename(filepath)

    if file_name.endswith(".yaml"):
        base_name = file_name[:-5]
    elif file_name.endswith(".yml"):
        base_name = file_name[:-4]
    else:
        base_name = file_name

    if base_name == "secrets":
        profile_name = "default"
    elif base_name.startswith("secrets_"):
        profile_name = base_name.removeprefix("secrets_")
    else:
        profile_name = base_name

    profile_name = _validate_profile_name(profile_name)

    return (
        profile_name,
        get_profile_password(
            profile_name,
            auto_generate=auto_generate,
        ),
    )


def mask_db_url(db_url: Optional[str]) -> str:
    """Return a PostgreSQL URL suitable for error messages and diagnostics."""
    if not db_url:
        return ""

    try:
        parsed = urlsplit(db_url)

        host = parsed.hostname or ""
        user = parsed.username or ""
        port = f":{parsed.port}" if parsed.port else ""

        if parsed.password:
            netloc = f"{user}:***@{host}{port}"
        else:
            netloc = parsed.netloc

        query = urlencode(
            [
                (
                    key,
                    "***"
                    if any(
                        word in key.lower()
                        for word in ("password", "token", "secret")
                    )
                    else value,
                )
                for key, value in parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                )
            ]
        )

        return urlunsplit(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                query,
                parsed.fragment,
            )
        )
    except Exception:
        return "<invalid database URL>"


def _runtime_is_production(production: Optional[bool]) -> bool:
    """Return whether Kist should apply production transport restrictions."""
    if production is not None:
        return production

    return (
        os.getenv("KIST_ENV", "development").strip().lower()
        == "production"
    )


def enforce_ssl_url(
    db_url: Optional[str],
    default_sslmode: str = "require",
    *,
    production: Optional[bool] = None,
) -> Optional[str]:
    """Apply explicit Kist TLS policy to a PostgreSQL URL.

    Environment:
    - ``KIST_TLS_MODE=auto`` preserves URL ``sslmode`` or applies
      ``default_sslmode`` when none exists.
    - ``KIST_TLS_MODE=disable`` is allowed only outside production.
    - ``KIST_TLS_MODE=require`` enables TLS without certificate verification.
    - ``KIST_TLS_MODE=verify-ca`` and ``verify-full`` require ``sslrootcert``
      in the URL or ``PGSSLROOTCERT`` in the environment.

    Local development users may set ``KIST_TLS_MODE=disable`` explicitly.
    """
    if db_url is None:
        return None

    if db_url == "":
        return ""

    parsed = urlsplit(db_url)

    if not parsed.scheme or not parsed.netloc:
        raise KistError(
            "KIST_DATABASE_URL must be a valid PostgreSQL URL."
        )

    requested_mode = os.getenv(
        "KIST_TLS_MODE",
        "auto",
    ).strip().lower()

    valid_modes = {
        "auto",
        "disable",
        "require",
        "verify-ca",
        "verify-full",
    }

    if requested_mode not in valid_modes:
        raise KistError(
            "KIST_TLS_MODE must be auto, disable, require, verify-ca, "
            "or verify-full."
        )

    query = dict(
        parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
    )

    url_sslmode = query.get("sslmode", "").strip().lower()

    sslmode = (
        url_sslmode or default_sslmode
        if requested_mode == "auto"
        else requested_mode
    )

    if sslmode not in valid_modes - {"auto"}:
        raise KistError(
            f"Unsupported PostgreSQL sslmode: {sslmode!r}."
        )

    if sslmode == "disable" and _runtime_is_production(production):
        raise KistError(
            "sslmode=disable is allowed only outside KIST_ENV=production."
        )

    if sslmode in {"verify-ca", "verify-full"}:
        if not query.get("sslrootcert") and not os.getenv("PGSSLROOTCERT"):
            raise KistError(
                f"{sslmode} requires sslrootcert in the database URL "
                "or PGSSLROOTCERT in the environment."
            )

    query["sslmode"] = sslmode

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query),
            parsed.fragment,
        )
    )


def database_tls_mode(db_url: Optional[str]) -> Optional[str]:
    """Return the effective PostgreSQL sslmode after Kist policy is applied."""
    normalized = enforce_ssl_url(db_url)

    if not normalized:
        return None

    return dict(
        parse_qsl(
            urlsplit(normalized).query,
            keep_blank_values=True,
        )
    ).get("sslmode")


def safe_db_connect(
    db_url: str,
    **kwargs: Any,
) -> psycopg.Connection[Any]:
    """Open a PostgreSQL connection without leaking credentials in errors."""
    try:
        return psycopg.connect(
            enforce_ssl_url(db_url),
            **kwargs,
        )
    except psycopg.OperationalError as exc:
        raise psycopg.OperationalError(
            "Database connection failure "
            f"({mask_db_url(db_url)}): {exc}"
        ) from None


async def safe_async_db_connect(
    db_url: str,
    **kwargs: Any,
) -> psycopg.AsyncConnection[Any]:
    """Open an async PostgreSQL connection without leaking credentials."""
    try:
        return await psycopg.AsyncConnection.connect(
            enforce_ssl_url(db_url),
            **kwargs,
        )
    except psycopg.OperationalError as exc:
        raise psycopg.OperationalError(
            "Database connection failure "
            f"({mask_db_url(db_url)}): {exc}"
        ) from None


# ---------------------------------------------------------------------------
# Envelope cryptography
# ---------------------------------------------------------------------------

def _canonical_aad(context: dict[str, Any]) -> bytes:
    """Serialize authenticated context deterministically."""
    try:
        return json.dumps(
            context,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise KistError(
            "Kist encryption context must be JSON-serializable."
        ) from exc


def _derive_aes_key(
    password: str,
    salt: bytes,
    policy: Argon2Policy,
) -> bytes:
    """Derive one AES-256 key from a profile password and envelope salt."""
    if not isinstance(password, str) or not password:
        raise MissingKeyError(
            "A non-empty profile password is required."
        )

    if len(salt) != SALT_LENGTH:
        raise KistError(
            f"Kist salt must be exactly {SALT_LENGTH} bytes."
        )

    policy = policy.validated()

    return Argon2id(
        salt=salt,
        length=ARGON2_KEY_LENGTH,
        iterations=policy.iterations,
        lanes=policy.lanes,
        memory_cost=policy.memory_cost,
        ad=None,
        secret=None,
    ).derive(password.encode("utf-8"))


def _build_envelope(
    *,
    salt: bytes,
    nonce: bytes,
    aad: bytes,
    ciphertext: bytes,
    policy: Argon2Policy,
) -> bytes:
    """Build the stable Kist password-v1 binary envelope."""
    policy = policy.validated()

    if len(salt) != SALT_LENGTH:
        raise KistError(
            f"Kist salt must be exactly {SALT_LENGTH} bytes."
        )

    if len(nonce) != NONCE_LENGTH:
        raise KistError(
            f"Kist nonce must be exactly {NONCE_LENGTH} bytes."
        )

    if len(ciphertext) < AES_GCM_TAG_LENGTH:
        raise KistError(
            "AES-GCM ciphertext must include an authentication tag."
        )

    return b"".join(
        [
            MAGIC,
            bytes(
                [
                    ENVELOPE_VERSION,
                    ALGORITHM_AES_256_GCM,
                    KDF_ARGON2ID,
                    ENVELOPE_FLAGS,
                ]
            ),
            struct.pack(">I", policy.memory_cost),
            struct.pack(">I", policy.iterations),
            struct.pack(">H", policy.lanes),
            salt,
            nonce,
            hashlib.sha256(aad).digest(),
            ciphertext,
        ]
    )


def is_kist_envelope(data: bytes) -> bool:
    """Return whether bytes have the minimum Kist envelope structure."""
    return (
        isinstance(data, bytes)
        and len(data) >= HEADER_SIZE + AES_GCM_TAG_LENGTH
        and data.startswith(MAGIC)
    )


def _envelope_policy(envelope: bytes) -> Argon2Policy:
    """Read validated Argon2id parameters from an envelope."""
    policy = Argon2Policy(
        memory_cost=struct.unpack(
            ">I",
            envelope[MEMORY_COST_OFFSET:ITERATIONS_OFFSET],
        )[0],
        iterations=struct.unpack(
            ">I",
            envelope[ITERATIONS_OFFSET:LANES_OFFSET],
        )[0],
        lanes=struct.unpack(
            ">H",
            envelope[LANES_OFFSET:SALT_OFFSET],
        )[0],
    )

    try:
        return policy.validated()
    except KistError as exc:
        raise InvalidEnvelopeError(
            "Envelope contains unsafe Argon2 parameters."
        ) from exc


def _validate_envelope(
    envelope: bytes,
    context: dict[str, Any],
) -> Argon2Policy:
    """Validate envelope framing, algorithms, parameters, and context."""
    if not is_kist_envelope(envelope):
        raise InvalidEnvelopeError(
            "Content is not a supported Kist envelope."
        )

    if envelope[VERSION_OFFSET] != ENVELOPE_VERSION:
        raise InvalidEnvelopeError(
            "Unsupported Kist envelope version."
        )

    if envelope[ALGORITHM_OFFSET] != ALGORITHM_AES_256_GCM:
        raise InvalidEnvelopeError(
            "Unsupported Kist envelope encryption algorithm."
        )

    if envelope[KDF_OFFSET] != KDF_ARGON2ID:
        raise InvalidEnvelopeError(
            "Unsupported Kist envelope key-derivation algorithm."
        )

    if envelope[FLAGS_OFFSET] != ENVELOPE_FLAGS:
        raise InvalidEnvelopeError(
            "Unsupported Kist envelope flags."
        )

    policy = _envelope_policy(envelope)
    expected_aad_hash = hashlib.sha256(
        _canonical_aad(context)
    ).digest()

    actual_aad_hash = envelope[
        AAD_HASH_OFFSET:CIPHERTEXT_OFFSET
    ]

    if not secrets.compare_digest(
        actual_aad_hash,
        expected_aad_hash,
    ):
        raise DecryptionError(
            "Ciphertext context does not match the requested Kist scope, "
            "profile, secret key, version, or path."
        )

    return policy


def encrypt_envelope(
    plaintext: bytes,
    password: str,
    context: dict[str, Any],
    policy: Argon2Policy = Argon2Policy(),
) -> bytes:
    """Encrypt plaintext into a password-v1 Kist AES-256-GCM envelope."""
    if not isinstance(plaintext, bytes):
        raise KistError("Kist plaintext must be bytes.")

    policy = policy.validated()
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    aad = _canonical_aad(context)

    encryption_key = _derive_aes_key(
        password,
        salt,
        policy,
    )

    ciphertext = AESGCM(encryption_key).encrypt(
        nonce,
        plaintext,
        aad,
    )

    return _build_envelope(
        salt=salt,
        nonce=nonce,
        aad=aad,
        ciphertext=ciphertext,
        policy=policy,
    )


def decrypt_envelope(
    envelope: bytes,
    password: str,
    context: dict[str, Any],
) -> bytes:
    """Authenticate and decrypt a password-v1 Kist envelope."""
    policy = _validate_envelope(envelope, context)

    salt = envelope[SALT_OFFSET:NONCE_OFFSET]
    nonce = envelope[NONCE_OFFSET:AAD_HASH_OFFSET]
    ciphertext = envelope[CIPHERTEXT_OFFSET:]

    decryption_key = _derive_aes_key(
        password,
        salt,
        policy,
    )

    try:
        return AESGCM(decryption_key).decrypt(
            nonce,
            ciphertext,
            _canonical_aad(context),
        )
    except InvalidTag as exc:
        raise DecryptionError(
            "Ciphertext authentication failed; the password may be wrong "
            "or data was modified."
        ) from exc


# ---------------------------------------------------------------------------
# Git envelope context
# ---------------------------------------------------------------------------

def git_context(
    profile_name: str,
    filepath: str,
    scope: Optional[KistScope] = None,
) -> dict[str, str]:
    """Build authenticated context for a Git clean/smudge secret file."""
    resolved_scope = (
        scope or KistScope.from_environment()
    ).validated()

    return {
        "format": "kist-git-v1",
        "organization": resolved_scope.organization,
        "project": resolved_scope.project,
        "profile": _validate_profile_name(profile_name),
        "repository": os.getenv(
            "KIST_REPOSITORY_ID",
            "local-repository",
        ),
        "path": os.path.normpath(filepath).replace("\\", "/"),
    }


# ---------------------------------------------------------------------------
# Database-backed Kist store
# ---------------------------------------------------------------------------

class Kist:
    """PostgreSQL-backed, password-v1 Kist store.

    A Kist instance is scoped to exactly one organization, project, and
    profile. The caller must initialize the schema explicitly using
    :meth:`init_db` before normal read/write operations.

    Kist 0.1.0 assumes a serialized writer per profile. Concurrent writes to
    the same logical secret key are not supported by the public API.
    """

    def __init__(
        self,
        profile_name: str = "default",
        master_password: Optional[str] = None,
        db_url: Optional[str] = None,
        scope: Optional[KistScope] = None,
    ) -> None:
        """Create a scoped Kist store without mutating the database schema."""
        self.profile_name = _validate_profile_name(profile_name)
        self.scope = (
            scope or KistScope.from_environment()
        ).validated()

        self.master_password = (
            master_password
            or get_profile_password(self.profile_name)
        )

        if not self.master_password:
            raise MissingKeyError(
                "No encryption key configured for profile "
                f"{self.profile_name!r}."
            )

        configured_db_url = (
            KIST_DATABASE_URL
            if db_url is None
            else db_url
        )

        self.db_url = (
            enforce_ssl_url(configured_db_url)
            if configured_db_url
            else None
        )

        self.organization_id: Optional[uuid.UUID] = None
        self.project_id: Optional[uuid.UUID] = None
        self.profile_id: Optional[uuid.UUID] = None

    def init_db(self) -> None:
        """Explicitly create the Kist 0.1.0 schema.

        This method is intended for a setup/migration command or controlled
        deployment job. Runtime applications should normally receive only DML
        privileges and should not call it during startup.
        """
        if not self.db_url:
            raise KistError("KIST_DATABASE_URL is not configured.")

        with safe_db_connect(self.db_url) as connection:
            connection.execute(SQL_SCHEMA)

    def get_or_create_scope(
        self,
    ) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
        """Find or create this instance's organization/project/profile rows."""
        if not self.db_url:
            raise KistError("KIST_DATABASE_URL is not configured.")

        with safe_db_connect(self.db_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO kist_organizations (id, slug)
                    VALUES (%s, %s)
                    ON CONFLICT (slug)
                    DO UPDATE SET slug = EXCLUDED.slug
                    RETURNING id
                    """,
                    (
                        uuid.uuid4(),
                        self.scope.organization,
                    ),
                )
                organization_id = uuid.UUID(
                    str(cursor.fetchone()[0])
                )

                cursor.execute(
                    """
                    INSERT INTO kist_projects (
                        id,
                        organization_id,
                        slug
                    )
                    VALUES (%s, %s, %s)
                    ON CONFLICT (organization_id, slug)
                    DO UPDATE SET slug = EXCLUDED.slug
                    RETURNING id
                    """,
                    (
                        uuid.uuid4(),
                        organization_id,
                        self.scope.project,
                    ),
                )
                project_id = uuid.UUID(
                    str(cursor.fetchone()[0])
                )

                cursor.execute(
                    """
                    INSERT INTO kist_profiles (
                        id,
                        organization_id,
                        project_id,
                        profile_name
                    )
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (project_id, profile_name)
                    DO UPDATE
                    SET profile_name = EXCLUDED.profile_name
                    RETURNING id
                    """,
                    (
                        uuid.uuid4(),
                        organization_id,
                        project_id,
                        self.profile_name,
                    ),
                )
                profile_id = uuid.UUID(
                    str(cursor.fetchone()[0])
                )

        self.organization_id = organization_id
        self.project_id = project_id
        self.profile_id = profile_id

        return (
            organization_id,
            project_id,
            profile_id,
        )

    def _ensure_scope(
        self,
    ) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
        """Return initialized scope IDs, creating scope rows when needed."""
        if (
            self.organization_id is not None
            and self.project_id is not None
            and self.profile_id is not None
        ):
            return (
                self.organization_id,
                self.project_id,
                self.profile_id,
            )

        return self.get_or_create_scope()

    @staticmethod
    def flatten(
        data: dict[str, Any],
        parent_key: str = "",
        sep: str = ".",
    ) -> dict[str, Any]:
        """Flatten nested string-keyed mappings into dot-separated keys."""
        if not isinstance(data, dict):
            raise KistError("Secret data must be a mapping.")

        flattened: dict[str, Any] = {}

        for raw_key, value in data.items():
            if not isinstance(raw_key, str):
                raise KistError(
                    "Secret YAML mapping keys must be strings."
                )

            key = raw_key.strip()

            if not key or sep in key or "\x00" in key:
                raise KistError(
                    "Secret YAML mapping keys must be non-empty strings "
                    f"without {sep!r} or NUL bytes."
                )

            name = (
                f"{parent_key}{sep}{key}"
                if parent_key
                else key
            )

            if isinstance(value, dict):
                flattened.update(
                    Kist.flatten(
                        value,
                        parent_key=name,
                        sep=sep,
                    )
                )
            else:
                flattened[_validate_secret_key(name)] = value

        return flattened

    @staticmethod
    def unflatten(
        data: dict[str, Any],
        sep: str = ".",
    ) -> dict[str, Any]:
        """Reconstruct nested mappings from dot-separated secret keys."""
        result: dict[str, Any] = {}

        for raw_key, value in data.items():
            key = _validate_secret_key(str(raw_key))
            current = result
            parts = key.split(sep)

            for part in parts[:-1]:
                existing = current.get(part)

                if existing is None:
                    current[part] = {}

                elif not isinstance(existing, dict):
                    raise KistError(
                        "Cannot reconstruct nested secret path: "
                        f"{key!r}."
                    )

                current = current[part]

            leaf = parts[-1]

            if leaf in current and isinstance(current[leaf], dict):
                raise KistError(
                    "Cannot reconstruct nested secret path: "
                    f"{key!r}."
                )

            current[leaf] = value

        return result

    def _db_context(
        self,
        secret_key: str,
        secret_version: int,
    ) -> dict[str, str]:
        """Build immutable authenticated context for one database value."""
        organization_id, project_id, profile_id = self._ensure_scope()
        key = _validate_secret_key(secret_key)

        if secret_version < 1:
            raise KistError(
                "Secret versions must be positive integers."
            )

        return {
            "format": "kist-db-v1",
            "organization_id": str(organization_id),
            "project_id": str(project_id),
            "profile_id": str(profile_id),
            "profile": self.profile_name,
            "secret_key": key,
            "secret_version": str(secret_version),
        }

    def _encrypt_value(
        self,
        value: Any,
        *,
        secret_key: str,
        secret_version: int,
    ) -> bytes:
        """Serialize and encrypt one JSON-compatible secret value."""
        try:
            plaintext = json.dumps(
                value,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise KistError(
                f"Secret value for {secret_key!r} is not JSON-serializable."
            ) from exc

        return encrypt_envelope(
            plaintext,
            self.master_password,
            self._db_context(
                secret_key,
                secret_version,
            ),
        )

    def _decrypt_value(
        self,
        blob: bytes,
        *,
        secret_key: str,
        secret_version: int,
        crypto_mode: str,
    ) -> Any:
        """Decrypt and deserialize one stored password-v1 secret value."""
        if crypto_mode != KEY_MODE_PASSWORD:
            raise KistError(
                "Unsupported secret crypto mode: "
                f"{crypto_mode!r}."
            )

        plaintext = decrypt_envelope(
            blob,
            self.master_password,
            self._db_context(
                secret_key,
                secret_version,
            ),
        )

        try:
            return json.loads(plaintext.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise DecryptionError(
                "Stored Kist plaintext is not valid UTF-8 JSON."
            ) from exc
        except json.JSONDecodeError as exc:
            raise DecryptionError(
                "Stored Kist plaintext is not valid JSON."
            ) from exc

    def _notification_payload(
        self,
        secret_key: str,
    ) -> str:
        """Build a non-secret PostgreSQL cache-invalidation notification."""
        organization_id, project_id, profile_id = self._ensure_scope()

        return json.dumps(
            {
                "organization_id": str(organization_id),
                "project_id": str(project_id),
                "profile_name": self.profile_name,
                "profile_id": str(profile_id),
                "secret_key": _validate_secret_key(secret_key),
            },
            separators=(",", ":"),
        )

    def _next_secret_version(
        self,
        cursor: psycopg.Cursor[Any],
        secret_key: str,
    ) -> int:
        """Read and lock an existing secret row before replacing it.

        Kist 0.1.0 expects a serialized writer per profile. ``FOR UPDATE``
        protects updates to an existing record inside a transaction. A
        concurrent first insert is surfaced as a database integrity error rather
        than silently overwriting an unknown value.
        """
        _, _, profile_id = self._ensure_scope()

        cursor.execute(
            """
            SELECT secret_version
            FROM kist
            WHERE profile_id = %s
              AND secret_key = %s
            FOR UPDATE
            """,
            (
                profile_id,
                secret_key,
            ),
        )

        row = cursor.fetchone()

        return int(row[0]) + 1 if row else 1

    def _store_encrypted_value(
        self,
        cursor: psycopg.Cursor[Any],
        *,
        secret_key: str,
        encrypted_blob: bytes,
        secret_version: int,
    ) -> None:
        """Insert or replace one encrypted secret row in the active transaction."""
        _, _, profile_id = self._ensure_scope()

        cursor.execute(
            """
            INSERT INTO kist (
                id,
                profile_id,
                secret_key,
                encrypted_blob,
                crypto_mode,
                crypto_version,
                secret_version,
                updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (profile_id, secret_key)
            DO UPDATE
            SET encrypted_blob = EXCLUDED.encrypted_blob,
                crypto_mode = EXCLUDED.crypto_mode,
                crypto_version = EXCLUDED.crypto_version,
                secret_version = EXCLUDED.secret_version,
                updated_at = NOW()
            """,
            (
                uuid.uuid4(),
                profile_id,
                secret_key,
                encrypted_blob,
                KEY_MODE_PASSWORD,
                ENVELOPE_VERSION,
                secret_version,
            ),
        )

        cursor.execute(
            "SELECT pg_notify(%s, %s)",
            (
                "kist_secret_updated",
                self._notification_payload(secret_key),
            ),
        )

    def set(
        self,
        key: str,
        value: Any,
        max_retries: int = 3,
    ) -> int:
        """Store one JSON-serializable secret and return its new version.

        Uses row-level locking (``FOR UPDATE``) and an automatic retry loop to
        safely serialize concurrent updates and prevent stale version writes.
        """
        if not self.db_url:
            raise KistError("KIST_DATABASE_URL is not configured.")

        secret_key = _validate_secret_key(key)
        self._ensure_scope()

        for attempt in range(max_retries):
            try:
                with safe_db_connect(self.db_url) as connection:
                    with connection.cursor() as cursor:
                        secret_version = self._next_secret_version(
                            cursor,
                            secret_key,
                        )

                        encrypted_blob = self._encrypt_value(
                            value,
                            secret_key=secret_key,
                            secret_version=secret_version,
                        )

                        self._store_encrypted_value(
                            cursor,
                            secret_key=secret_key,
                            encrypted_blob=encrypted_blob,
                            secret_version=secret_version,
                        )

                return secret_version

            except (
                psycopg.errors.UniqueViolation,
                psycopg.errors.SerializationFailure,
                psycopg.errors.DeadlockDetected,
            ) as exc:
                if attempt == max_retries - 1:
                    raise ConcurrentWriteError(
                        "Concurrent write conflict for secret "
                        f"{secret_key!r}. Retry through the serialized writer."
                    ) from exc
                continue

    def get(self, key: str) -> Any:
        """Return one decrypted secret value."""
        if not self.db_url:
            raise KistError("KIST_DATABASE_URL is not configured.")

        secret_key = _validate_secret_key(key)
        _, _, profile_id = self._ensure_scope()

        with safe_db_connect(self.db_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        encrypted_blob,
                        secret_version,
                        crypto_mode
                    FROM kist
                    WHERE profile_id = %s
                      AND secret_key = %s
                    """,
                    (
                        profile_id,
                        secret_key,
                    ),
                )
                row = cursor.fetchone()

        if row is None:
            raise KeyError(
                f"Secret key {secret_key!r} was not found for profile "
                f"{self.profile_name!r}."
            )

        return self._decrypt_value(
            bytes(row[0]),
            secret_key=secret_key,
            secret_version=int(row[1]),
            crypto_mode=str(row[2]),
        )

    def delete(self, key: str) -> bool:
        """Delete one secret and notify listeners when a row existed."""
        if not self.db_url:
            raise KistError("KIST_DATABASE_URL is not configured.")

        secret_key = _validate_secret_key(key)
        _, _, profile_id = self._ensure_scope()

        with safe_db_connect(self.db_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    DELETE FROM kist
                    WHERE profile_id = %s
                      AND secret_key = %s
                    RETURNING id
                    """,
                    (
                        profile_id,
                        secret_key,
                    ),
                )
                deleted = cursor.fetchone() is not None

                if deleted:
                    cursor.execute(
                        "SELECT pg_notify(%s, %s)",
                        (
                            "kist_secret_updated",
                            self._notification_payload(secret_key),
                        ),
                    )

        return deleted

    def lock_yaml(
        self,
        yaml_string: str,
        prune: bool = False,
    ) -> tuple[int, int]:
        """Encrypt a YAML mapping into the scoped PostgreSQL secret store.

        Args:
            yaml_string:
                YAML document with a mapping at its root.

            prune:
                When true, delete secrets currently stored in this profile but
                absent from the supplied YAML mapping.

        Returns:
            A pair of ``(stored_or_updated_count, pruned_count)``.

        The write path is protected by a PostgreSQL transaction-scoped advisory
        lock (``pg_advisory_xact_lock``) on the active profile, serializing
        concurrent CI/deployment runs safely.
        """
        if not self.db_url:
            raise KistError("KIST_DATABASE_URL is not configured.")

        try:
            loaded = yaml.safe_load(yaml_string)
        except yaml.YAMLError as exc:
            raise KistError("Secret YAML could not be parsed safely.") from exc

        if loaded is None:
            loaded = {}

        if not isinstance(loaded, dict):
            raise KistError("Secret YAML root must be a mapping.")

        flattened = self.flatten(loaded)
        self._ensure_scope()

        pruned_count = 0

        try:
            with safe_db_connect(self.db_url) as connection:
                with connection.cursor() as cursor:
                    _, _, profile_id = self._ensure_scope()

                    # Acquire transaction-scoped advisory lock on the profile to serialize concurrent lock runs
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(hashtext(%s))",
                        (f"kist_profile:{profile_id}",),
                    )

                    if prune:
                        cursor.execute(
                            """
                            SELECT secret_key
                            FROM kist
                            WHERE profile_id = %s
                            FOR UPDATE
                            """,
                            (profile_id,),
                        )

                        existing_keys = {
                            str(row[0])
                            for row in cursor.fetchall()
                        }
                        keys_to_delete = sorted(
                            existing_keys - set(flattened)
                        )

                        if keys_to_delete:
                            cursor.execute(
                                """
                                DELETE FROM kist
                                WHERE profile_id = %s
                                  AND secret_key = ANY(%s)
                                """,
                                (
                                    profile_id,
                                    keys_to_delete,
                                ),
                            )
                            pruned_count = len(keys_to_delete)

                            for secret_key in keys_to_delete:
                                cursor.execute(
                                    "SELECT pg_notify(%s, %s)",
                                    (
                                        "kist_secret_updated",
                                        self._notification_payload(
                                            secret_key
                                        ),
                                    ),
                                )

                    for secret_key, value in flattened.items():
                        secret_version = self._next_secret_version(
                            cursor,
                            secret_key,
                        )

                        encrypted_blob = self._encrypt_value(
                            value,
                            secret_key=secret_key,
                            secret_version=secret_version,
                        )

                        self._store_encrypted_value(
                            cursor,
                            secret_key=secret_key,
                            encrypted_blob=encrypted_blob,
                            secret_version=secret_version,
                        )

            return len(flattened), pruned_count

        except psycopg.errors.UniqueViolation as exc:
            raise ConcurrentWriteError(
                "Concurrent first-write conflict while locking YAML. "
                "Retry through the serialized profile writer."
            ) from exc

    def unlock_yaml(self) -> str:
        """Return the scoped PostgreSQL secret store as safe YAML."""
        if not self.db_url:
            raise KistError("KIST_DATABASE_URL is not configured.")

        _, _, profile_id = self._ensure_scope()

        with safe_db_connect(self.db_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        secret_key,
                        encrypted_blob,
                        secret_version,
                        crypto_mode
                    FROM kist
                    WHERE profile_id = %s
                    ORDER BY secret_key
                    """,
                    (profile_id,),
                )
                rows = cursor.fetchall()

        flat_values: dict[str, Any] = {}

        for secret_key, encrypted_blob, secret_version, crypto_mode in rows:
            key = _validate_secret_key(str(secret_key))

            flat_values[key] = self._decrypt_value(
                bytes(encrypted_blob),
                secret_key=key,
                secret_version=int(secret_version),
                crypto_mode=str(crypto_mode),
            )

        nested_values = self.unflatten(flat_values)

        return yaml.safe_dump(
            nested_values,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

    def git_clean(self) -> None:
        """Run the Kist Git clean filter for this profile."""
        from kist.git import git_clean_stream

        git_clean_stream(
            self.profile_name,
            self.master_password,
        )

    def git_smudge(self) -> None:
        """Run the Kist Git smudge filter for this profile."""
        from kist.git import git_smudge_stream

        git_smudge_stream(
            self.profile_name,
            self.master_password,
        )