"""Internal read-budget primitives; not yet wired into public read methods."""
from __future__ import annotations

import math
import time
from collections.abc import Callable
from numbers import Real

from kist.core import KistError

_PHASES = frozenset({
    "read", "scope_wait", "scope_init", "connection_acquire", "connect",
    "schema_check", "derivation_wait", "key_unlock", "query", "decrypt",
    "cache_wait", "cleanup",
})


def _phase(value: str) -> str:
    if not isinstance(value, str) or value not in _PHASES:
        raise ValueError("Unknown read phase.")
    return value


class _ReadTimeoutError(KistError, TimeoutError):
    """Internal timeout type. No driver exception or credentials are retained.

    retryable=False is conservative: this layer cannot decide whether repeating
    the operation is appropriate. This is not yet a public exception contract.
    """

    def __init__(self, *, phase: str, elapsed_seconds: float) -> None:
        self.phase = _phase(phase)
        self.elapsed_seconds = elapsed_seconds
        self.reason_code = "read_deadline_exceeded"
        self.retryable = False
        super().__init__(f"Read deadline exceeded during {self.phase}.")


class _ReadDeadline:
    """A single cooperative monotonic budget, not a cancellation mechanism.

    None disables expiry. A finite positive timeout starts at construction.
    The caller passes this same object through all phases. Checking remaining
    time does not renew the budget, stop SQL, or interrupt an Argon2 worker.
    """

    def __init__(
        self, timeout: float | None, *, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, Real):
                raise ValueError("Read timeout must be a finite positive number or None.")
            try:
                timeout = float(timeout)
            except (OverflowError, ValueError):
                raise ValueError("Read timeout must be finite and positive.") from None
            if not math.isfinite(timeout) or timeout <= 0:
                raise ValueError("Read timeout must be finite and positive.")
        self._clock = clock
        self._started = clock()
        self._timeout = timeout

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, self._clock() - self._started)

    def remaining(self, phase: str = "read") -> float | None:
        phase = _phase(phase)
        if self._timeout is None:
            return None
        elapsed = self.elapsed_seconds
        if elapsed >= self._timeout:
            raise _ReadTimeoutError(phase=phase, elapsed_seconds=elapsed)
        return self._timeout - elapsed

    def check(self, phase: str = "read") -> None:
        self.remaining(phase)
