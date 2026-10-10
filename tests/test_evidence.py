"""Prefetch evidence identifiers bind a record key to its complete source hash."""

from __future__ import annotations

import unittest

from forensia.core.evidence import make_prefetch_evidence_id

SOURCE_A = "a" * 64
SOURCE_B = "b" * 64


class EvidenceIdTests(unittest.TestCase):
    def test_prefetch_identity_uses_full_source_and_normalized_record_key(self) -> None:
        first = make_prefetch_evidence_id(SOURCE_A, "CMD.EXE", "A1B2C3D4")
        self.assertEqual(f"prefetch-{SOURCE_A}-cmd-exe-a1b2c3d4", first)
        self.assertEqual(
            first, make_prefetch_evidence_id(SOURCE_A, "cmd.exe", "a1b2c3d4")
        )
        self.assertNotEqual(
            first, make_prefetch_evidence_id(SOURCE_B, "CMD.EXE", "A1B2C3D4")
        )

    def test_source_identity_must_be_a_full_sha256(self) -> None:
        for invalid in ("a" * 12, "z" * 64, ""):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    make_prefetch_evidence_id(invalid, "app.exe", "abc123")


if __name__ == "__main__":
    unittest.main()
