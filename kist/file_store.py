"""Offline, read-only secret store backed by a Kist Git envelope file.

Use this on embedded, air-gapped or CI systems that cannot reach PostgreSQL.
The input is the *encrypted* blob that the Kist Git clean filter stores, for
example produced in CI with::

    git show HEAD:secrets/device.yaml > dist/device.kist

The envelope is authenticated against the same context the Git filter used
(profile, organization, project, repository ID and repository-relative path),
so an envelope copied to another profile, scope or path fails closed.

Decrypted values are held in memory only, never written to disk. Argon2id runs
once per load (not per ``get``), which matters on small devices. Call
:meth:`FileKist.close` (or use a ``with`` block) to drop plaintext references.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Iterator, Optional, Union

import yaml

from kist.core import (
    DecryptionError,
    InvalidEnvelopeError,
    Kist,
    KistError,
    KistScope,
    MissingKeyError,
    _UniqueSafeLoader,
    _validate_profile_name,
    _validate_secret_key,
    decrypt_with_password_history,
    profile_from_path,
    retired_profile_passwords,
    get_profile_password,
    git_context,
    is_kist_envelope,
)

__all__ = ["FileKist"]

_MISSING: Any = object()
PathLike = Union[str, os.PathLike]


def _profile_from_git_path(git_path: str) -> str:
    """Profile the Git filter used for this path (secrets/device.yaml -> device)."""
    return profile_from_path(git_path)


class FileKist:
    """Read-only Kist store loaded from an encrypted envelope file.

    Args:
        path: Location of the envelope file on this system.
        git_path: Repository-relative path the file had when it was committed
            (for example ``"secrets/device.yaml"``). It is part of the
            authenticated context. Defaults to ``path``.
        profile_name: Profile password to use. Defaults to the profile the Git
            filter derives from ``git_path`` (``secrets/device.yaml`` -> ``device``).
        password: Profile password. Defaults to the normal Kist lookup
            (``KIST_PASSWORD_<PROFILE>``, ``KIST_PASSWORD``, ``~/.kist`` password file).
        scope: Organization/project scope. Defaults to ``KIST_ORG_ID`` /
            ``KIST_PROJECT_ID`` (environment, then ~/.kist/env_<profile>, then ~/.kist/env),
            like the Git filter.
        repository_id: Overrides ``KIST_REPOSITORY_ID`` used at commit time.
        lazy: When true (default), decrypt on first access instead of in ``__init__``.
    """

    def __init__(
        self,
        path: PathLike,
        *,
        git_path: Optional[str] = None,
        profile_name: Optional[str] = None,
        password: Optional[str] = None,
        scope: Optional[KistScope] = None,
        repository_id: Optional[str] = None,
        lazy: bool = True,
    ) -> None:
        self.path = Path(path)
        self.git_path = git_path if git_path is not None else os.fspath(path)
        self.profile_name = (_validate_profile_name(profile_name) if profile_name is not None
                             else _profile_from_git_path(self.git_path))
        self.scope = (scope or KistScope.from_environment(self.profile_name)).validated()
        self.repository_id = repository_id
        self._password = password
        self._values: Optional[dict[str, Any]] = None
        self.retired_password_used: Optional[str] = None
        self._lock = threading.Lock()
        if not lazy:
            self.reload()

    # -- loading -------------------------------------------------------------

    def _context(self) -> dict[str, str]:
        context = git_context(self.profile_name, self.git_path, self.scope)
        if self.repository_id is not None:
            context["repository"] = self.repository_id
        return context

    def _current_password(self) -> Optional[str]:
        password = self._password if self._password is not None else get_profile_password(self.profile_name)
        if not password and not retired_profile_passwords(self.profile_name):
            raise MissingKeyError(f"No password configured for profile {self.profile_name!r}.")
        return password

    def reload(self) -> None:
        """Re-read and decrypt the envelope file, replacing in-memory values."""
        try:
            envelope = self.path.read_bytes()
        except FileNotFoundError as exc:
            raise KistError(f"Kist envelope file not found: {self.path}") from exc
        if not is_kist_envelope(envelope):
            raise InvalidEnvelopeError(
                f"{self.path} is not a Kist v1 envelope. Export the committed blob "
                "(git show HEAD:<path>), not the plaintext working copy."
            )
        plaintext, self.retired_password_used = decrypt_with_password_history(
            envelope, self.profile_name, self._context(), self._current_password())
        try:
            text = plaintext.decode("utf-8")
            loaded = yaml.load(text, Loader=_UniqueSafeLoader)
        except UnicodeDecodeError as exc:
            raise DecryptionError("Kist envelope does not contain UTF-8 text.") from exc
        except (yaml.YAMLError, RecursionError) as exc:
            raise KistError("Invalid secret YAML inside envelope.") from exc
        finally:
            del plaintext
        values = Kist.flatten({} if loaded is None else loaded)
        with self._lock:
            self._values = values

    def _data(self) -> dict[str, Any]:
        with self._lock:
            values = self._values
        if values is None:
            self.reload()
            with self._lock:
                values = self._values
        assert values is not None
        return values

    # -- read API (mirrors Kist / TTLSecretStore) ----------------------------

    def get(self, key: str, default: Any = _MISSING) -> Any:
        key = _validate_secret_key(key)
        try:
            return self._data()[key]
        except KeyError:
            if default is not _MISSING:
                return default
            raise KeyError(key) from None

    get_secret = get

    def __getitem__(self, key: str) -> Any:
        return self.get(key)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self._data()

    def keys(self) -> list[str]:
        return sorted(self._data())

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self._data())

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        """Drop references to decrypted values (best effort in CPython)."""
        with self._lock:
            if self._values is not None:
                self._values.clear()
            self._values = None

    clear = close

    def __enter__(self) -> "FileKist":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "loaded" if self._values is not None else "not loaded"
        return f"FileKist(path={os.fspath(self.path)!r}, profile={self.profile_name!r}, {state})"

