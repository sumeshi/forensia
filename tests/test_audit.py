from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from forensia.ai.audit import LLMCallLogger


class LLMCallLoggerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case = MagicMock()
        self.case.ai_logs_dir = MagicMock()
        self.logger = LLMCallLogger(self.case, "test-session")

    def _write(self, iteration: int = 1, phase: str = "plan",
               suffix: str = "main", **kwargs: object) -> None:
        defaults = dict(
            input_messages=[{"role": "user", "content": "hi"}],
            output="ok",
            model="gpt-4",
            base_url="http://localhost:1234",
        )
        defaults.update(kwargs)
        self.logger.write(iteration=iteration, phase=phase, suffix=suffix, **defaults)

    def test_total_calls_starts_at_zero(self) -> None:
        self.assertEqual(self.logger.total_calls, 0)

    def test_count_by_phase_empty(self) -> None:
        self.assertEqual(self.logger.count_by_phase(), {})

    def test_write_increments_total_calls(self) -> None:
        self._write()
        self.assertEqual(self.logger.total_calls, 1)

    def test_total_calls_counts_multiple_writes(self) -> None:
        for i in range(5):
            self._write(iteration=i)
        self.assertEqual(self.logger.total_calls, 5)

    def test_count_by_phase_aggregates_multiple_phases(self) -> None:
        self._write(iteration=1, phase="broad_plan")
        self._write(iteration=2, phase="broad_plan")
        self._write(iteration=1, phase="check")
        self.assertEqual(self.logger.count_by_phase(), {"broad_plan-main": 2, "check-main": 1})

    def test_count_by_phase_same_phase_different_suffixes(self) -> None:
        self._write(iteration=1, phase="section", suffix="plan")
        self._write(iteration=1, phase="section", suffix="check")
        self.assertEqual(self.logger.count_by_phase(), {"section-plan": 1, "section-check": 1})

    def test_total_calls_after_many_calls(self) -> None:
        for i in range(100):
            self._write(iteration=i, phase="plan")
        self.assertEqual(self.logger.total_calls, 100)

    def test_count_by_phase_after_many_calls(self) -> None:
        for i in range(50):
            self._write(iteration=i, phase="plan")
            self._write(iteration=i, phase="check")
        self.assertEqual(self.logger.count_by_phase(), {"plan-main": 50, "check-main": 50})

    def test_write_with_suffix_uses_suffix_in_stem(self) -> None:
        logger = LLMCallLogger(self.case, "stem-test")
        logger.base_dir = MagicMock()
        logger.write(
            iteration=7,
            phase="broad_plan",
            input_messages=[{"role": "user", "content": "test"}],
            output="response",
            model="gpt-4",
            base_url="http://localhost:1234",
            suffix="retry",
        )
        expected_path = logger.base_dir / "07-broad_plan-retry-01.json"
        expected_path.write_text.assert_called_once()

    def test_write_without_suffix_uses_call_as_default_suffix(self) -> None:
        logger = LLMCallLogger(self.case, "no-suffix")
        logger.base_dir = MagicMock()
        logger.write(
            iteration=3,
            phase="plan",
            input_messages=[{"role": "user", "content": "hi"}],
            output="ok",
            model="gpt-4",
            base_url="http://localhost:1234",
        )
        expected_path = logger.base_dir / "03-plan-call-01.json"
        expected_path.write_text.assert_called_once()

    def test_multiple_writes_same_iteration_and_phase_increment_counts(self) -> None:
        logger = LLMCallLogger(self.case, "multi-call")
        logger.base_dir = MagicMock()
        for _ in range(3):
            logger.write(
                iteration=1,
                phase="plan",
                suffix="analyse",
                input_messages=[],
                output="ok",
                model="gpt-4",
                base_url="http://localhost",
            )
        self.assertEqual(logger.total_calls, 3)
        self.assertEqual(logger.count_by_phase(), {"plan-analyse": 3})
        self.assertEqual(logger.base_dir.__truediv__.return_value.write_text.call_count, 3)
