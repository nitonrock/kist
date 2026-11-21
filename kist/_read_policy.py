"""Internal monotonic budget primitives for database-backed read APIs."""
from __future__ import annotations

import math
import time
from collections.abc import Callable
from numbers import Real

from kist.read_errors import ReadTimeoutError as _ReadTimeoutError
from kist.read_errors import _phase


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
