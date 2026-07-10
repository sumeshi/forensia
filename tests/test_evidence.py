"""Contract tests for stable evidence identifier formats."""

from __future__ import annotations

import unittest

from forensia.core.evidence import (
    make_evtx_evidence_id,
    make_mft_evidence_id,
    make_prefetch_evidence_id,
)


class EvidenceIdTests(unittest.TestCase):
    def test_evtx_ids_normalize_channels_and_pad_records(self) -> None:
        cases = (
            (("Security", 12345), "evtx-security-000000012345"),
            (("Windows PowerShell", 1), "evtx-windows-powershell-000000000001"),
            (("AppLocker/EXE", 999), "evtx-applocker-exe-000000000999"),
            (("café", 7), "evtx-café-000000000007"),
            (("System", 0), "evtx-system-000000000000"),
            (("Security", 999999999999), "evtx-security-999999999999"),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(expected, make_evtx_evidence_id(*args))

    def test_mft_ids_pad_record_and_sequence_components(self) -> None:
        cases = (
            ((12345, 3), "mft-000000012345-03"),
            ((0, 0), "mft-000000000000-00"),
            ((999999999999, 99), "mft-999999999999-99"),
            ((1, 5), "mft-000000000001-05"),
            ((1, 100), "mft-000000000001-100"),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(expected, make_mft_evidence_id(*args))

    def test_prefetch_ids_normalize_names_and_hash_case(self) -> None:
        cases = (
            (("CMD.EXE", "A1B2C3D4"), "prefetch-cmd-exe-a1b2c3d4"),
            (("my app.exe", "DEADBEEF"), "prefetch-my-app-exe-deadbeef"),
            (("setup(v1).exe", "1234"), "prefetch-setup-v1--exe-1234"),
            (("foo.exe", "abcd1234"), "prefetch-foo-exe-abcd1234"),
            (("", "hash"), "prefetch--hash"),
        )
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(expected, make_prefetch_evidence_id(*args))
