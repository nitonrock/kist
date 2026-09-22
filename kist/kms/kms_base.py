"""Provider-neutral KMS contract for Kist scope data-encryption keys."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class KMSKeyReference:
    """A provider key identifier, such as an AWS ARN or an alias."""

    provider: str
    key_id: str
    key_version: str | None = None


@dataclass(frozen=True)
class WrappedDataKey:
    """Persistable wrapped DEK. Plaintext DEKs must never be persisted or logged."""

    provider: str
    key_reference: KMSKeyReference
    ciphertext: bytes
    encryption_context: dict[str, str]
    format_version: int = 1


class KMSProviderError(Exception):
    """A KMS operation failed without exposing key material."""


class KMSProvider(ABC):
    """Vendor-neutral wrap/unwrap contract.

    Kist owns AES-GCM payload encryption, authenticated context, database
    storage, secret versions, and cache policy. A provider controls only the
    root key used to wrap and unwrap a profile-scoped 32-byte DEK.
    """

    name: str

    @abstractmethod
    def wrap_key(
        self,
        *,
        plaintext_key: bytes,
        key_reference: KMSKeyReference,
        encryption_context: Mapping[str, str],
    ) -> WrappedDataKey:
        """Wrap a 32-byte DEK. Never persist or log ``plaintext_key``."""

    @abstractmethod
    def unwrap_key(self, wrapped_key: WrappedDataKey) -> bytes:
        """Authorize and return a 32-byte plaintext DEK."""

    @abstractmethod
    def validate_key_reference(self, key_reference: KMSKeyReference) -> None:
        """Check that the configured provider key is usable."""

    def generate_data_key(
        self,
        *,
        key_reference: KMSKeyReference,
        encryption_context: Mapping[str, str],
    ) -> tuple[bytes, WrappedDataKey]:
        """Portable default: generate locally, then ask the provider to wrap it.

        Providers with a native data-key API may override this method. The
        returned plaintext key is transient and must not be persisted.
        """
        plaintext_key = os.urandom(32)
        wrapped = self.wrap_key(
            plaintext_key=plaintext_key,
            key_reference=key_reference,
            encryption_context=encryption_context,
        )
        return plaintext_key, wrapped

    def provider_metadata(self) -> dict[str, str]:
        """Safe metadata only; no credentials, ciphertext, or plaintext keys."""
        return {"provider": self.name}
