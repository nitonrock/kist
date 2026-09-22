"""Development/test-only KMS provider.

This provider exists to test the generic KMS integration without cloud SDKs. It
is not a substitute for cloud KMS, workload identity, HSM-backed custody, IAM,
or provider audit logging. Do not use it as a production KMS.
"""

from __future__ import annotations

import json
import os
from typing import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from kist.kms.base import KMSKeyReference, KMSProvider, KMSProviderError, WrappedDataKey


class LocalKMSProvider(KMSProvider):
    """Wrap DEKs with a caller-supplied 32-byte test key using AES-256-GCM."""

    name = "local"

    def __init__(self, kek: bytes):
        if len(kek) != 32:
            raise KMSProviderError("LocalKMSProvider requires a 32-byte test KEK.")
        self._kek = kek

    def wrap_key(
        self,
        *,
        plaintext_key: bytes,
        key_reference: KMSKeyReference,
        encryption_context: Mapping[str, str],
    ) -> WrappedDataKey:
        self.validate_key_reference(key_reference)
        if len(plaintext_key) != 32:
            raise KMSProviderError("Kist DEKs must be exactly 32 bytes.")
        nonce = os.urandom(12)
        context = dict(encryption_context)
        ciphertext = nonce + AESGCM(self._kek).encrypt(nonce, plaintext_key, self._aad(context))
        return WrappedDataKey(
            provider=self.name,
            key_reference=key_reference,
            ciphertext=ciphertext,
            encryption_context=context,
        )

    def unwrap_key(self, wrapped_key: WrappedDataKey) -> bytes:
        if wrapped_key.provider != self.name:
            raise KMSProviderError("LocalKMSProvider received a wrapped key from another provider.")
        self.validate_key_reference(wrapped_key.key_reference)
        if len(wrapped_key.ciphertext) < 12 + 16:
            raise KMSProviderError("Wrapped local DEK is malformed.")
        nonce, ciphertext = wrapped_key.ciphertext[:12], wrapped_key.ciphertext[12:]
        try:
            plaintext = AESGCM(self._kek).decrypt(nonce, ciphertext, self._aad(wrapped_key.encryption_context))
        except InvalidTag as exc:
            raise KMSProviderError("LocalKMSProvider could not authenticate the wrapped DEK.") from exc
        if len(plaintext) != 32:
            raise KMSProviderError("LocalKMSProvider recovered an invalid DEK length.")
        return plaintext

    def validate_key_reference(self, key_reference: KMSKeyReference) -> None:
        if key_reference.provider != self.name:
            raise KMSProviderError("LocalKMSProvider received a non-local key reference.")
        if not key_reference.key_id:
            raise KMSProviderError("LocalKMSProvider requires a non-empty key identifier.")

    @staticmethod
    def _aad(encryption_context: Mapping[str, str]) -> bytes:
        return json.dumps(dict(encryption_context), sort_keys=True, separators=(",", ":")).encode("utf-8")
