"""Explicit registry for supported Kist KMS providers."""

from __future__ import annotations

from typing import Any

from kist.kms.base import KMSProvider, KMSProviderError


def get_kms_provider(name: str, **config: Any) -> KMSProvider:
    """Return an explicitly supported provider; never import arbitrary classes."""
    normalized = name.strip().lower()
    if normalized == "local":
        from kist.kms.local import LocalKMSProvider
        return LocalKMSProvider(**config)
    if normalized == "aws-kms":
        raise KMSProviderError(
            "AWS KMS is not bundled in this Kist version. The provider seam is present, "
            "but cloud KMS support will be added only with tested SDK, IAM, migration, and operational guidance."
        )
    raise KMSProviderError(f"Unsupported KMS provider: {name!r}.")
