"""Deterministic tests for internal read-budget primitives; no database."""
import unittest

from kist._read_policy import _ReadDeadline, _ReadTimeoutError
from kist.core import KistError


class ReadDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0

    def clock(self):
        return self.now

    def test_budget_is_not_renewed_between_phases(self):
        deadline = _ReadDeadline(3, clock=self.clock)
        self.assertEqual(deadline.remaining("scope_init"), 3)
        self.now += 1
        self.assertEqual(deadline.remaining("connect"), 2)
        self.now += 1.5
        self.assertEqual(deadline.remaining("query"), 0.5)

    def test_repeated_checks_do_not_extend_budget(self):
        deadline = _ReadDeadline(1, clock=self.clock)
        for _ in range(5):
            self.assertEqual(deadline.remaining(), 1)
        self.now += 1
        with self.assertRaises(_ReadTimeoutError):
            deadline.check()

    def test_exact_boundary_expires(self):
        deadline = _ReadDeadline(2, clock=self.clock)
        self.now += 2
        with self.assertRaises(_ReadTimeoutError) as caught:
            deadline.check("query")
        self.assertEqual(caught.exception.phase, "query")
        self.assertEqual(caught.exception.elapsed_seconds, 2)

    def test_overdue_budget_expires(self):
        deadline = _ReadDeadline(1, clock=self.clock)
        self.now += 20
        with self.assertRaises(_ReadTimeoutError):
            deadline.remaining("cleanup")

    def test_disabled_deadline_does_not_expire(self):
        deadline = _ReadDeadline(None, clock=self.clock)
        self.now += 1000000
        self.assertIsNone(deadline.remaining("query"))
        self.assertIsNone(deadline.check())

    def test_invalid_timeouts_are_rejected(self):
        for timeout in [True, False, 0, -1, float("nan"), float("inf"),
                        -float("inf"), "3", object(), 10 ** 1000]:
            with self.subTest(timeout_type=type(timeout).__name__):
                with self.assertRaises(ValueError):
                    _ReadDeadline(timeout, clock=self.clock)

    def test_fractional_timeout(self):
        deadline = _ReadDeadline(0.25, clock=self.clock)
        self.now += 0.125
        self.assertEqual(deadline.remaining(), 0.125)

    def test_timeout_is_kist_and_builtin_timeout(self):
        error = _ReadTimeoutError(phase="query", elapsed_seconds=1)
        self.assertIsInstance(error, KistError)
        self.assertIsInstance(error, TimeoutError)
        self.assertEqual(error.reason_code, "read_deadline_exceeded")
        self.assertFalse(error.retryable)

    def test_unknown_phase_does_not_leak_input(self):
        deadline = _ReadDeadline(1, clock=self.clock)
        value = "example-private-name-and-password"
        for operation in [lambda: deadline.remaining(value),
                          lambda: _ReadTimeoutError(phase=value, elapsed_seconds=1)]:
            with self.assertRaises(ValueError) as caught:
                operation()
            self.assertNotIn(value, str(caught.exception))

    def test_timeout_has_no_raw_cause(self):
        deadline = _ReadDeadline(1, clock=self.clock)
        self.now += 1
        with self.assertRaises(_ReadTimeoutError) as caught:
            deadline.check("connect")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn("password", str(caught.exception))

    def test_independent_calls_have_independent_budgets(self):
        first = _ReadDeadline(2, clock=self.clock)
        self.now += 1
        second = _ReadDeadline(2, clock=self.clock)
        self.assertEqual(first.remaining(), 1)
        self.assertEqual(second.remaining(), 2)

    def test_elapsed_uses_injected_clock(self):
        deadline = _ReadDeadline(None, clock=self.clock)
        self.now += 4
        self.assertEqual(deadline.elapsed_seconds, 4)
