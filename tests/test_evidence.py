from __future__ import annotations

import unittest

from forensia.core.evidence import (
    _slugify,
    make_evtx_evidence_id,
    make_mft_evidence_id,
    make_prefetch_evidence_id,
)


class SlugifyTests(unittest.TestCase):
    def test_slugify_plain_lowercase(self) -> None:
        self.assertEqual(_slugify("hello"), "hello")

    def test_slugify_uppercase_lowered(self) -> None:
        self.assertEqual(_slugify("HELLO"), "hello")

    def test_slugify_spaces_replaced(self) -> None:
        self.assertEqual(_slugify("hello world"), "hello-world")

    def test_slugify_special_chars(self) -> None:
        self.assertEqual(_slugify("a!b@c#d"), "a-b-c-d")

    def test_slugify_multiple_dashes_preserved(self) -> None:
        self.assertEqual(_slugify("a---b"), "a---b")

    def test_slugify_leading_trailing_dashes_stripped(self) -> None:
        self.assertEqual(_slugify("--hello--"), "hello")

    def test_slugify_unicode_alnum_preserved(self) -> None:
        self.assertEqual(_slugify("café"), "café")

    def test_slugify_unicode_non_alnum_trailing_stripped(self) -> None:
        self.assertEqual(_slugify("straße!"), "straße")

    def test_slugify_empty_returns_empty(self) -> None:
        self.assertEqual(_slugify(""), "")

    def test_slugify_only_special_chars_returns_empty(self) -> None:
        self.assertEqual(_slugify("!@#$"), "")


class MakeEvtxEvidenceIdTests(unittest.TestCase):
    def test_normal_channel_and_record(self) -> None:
        self.assertEqual(
            make_evtx_evidence_id("Security", 12345),
            "evtx-security-000000012345",
        )

    def test_channel_with_spaces(self) -> None:
        self.assertEqual(
            make_evtx_evidence_id("Windows PowerShell", 1),
            "evtx-windows-powershell-000000000001",
        )

    def test_channel_with_special_chars(self) -> None:
        self.assertEqual(
            make_evtx_evidence_id("AppLocker/EXE", 999),
            "evtx-applocker-exe-000000000999",
        )

    def test_channel_unicode(self) -> None:
        self.assertEqual(
            make_evtx_evidence_id("café", 7),
            "evtx-café-000000000007",
        )

    def test_record_number_zero(self) -> None:
        self.assertEqual(
            make_evtx_evidence_id("System", 0),
            "evtx-system-000000000000",
        )

    def test_record_number_large(self) -> None:
        self.assertEqual(
            make_evtx_evidence_id("Security", 999999999999),
            "evtx-security-999999999999",
        )

    def test_idempotent(self) -> None:
        self.assertEqual(
            make_evtx_evidence_id("Security", 12345),
            make_evtx_evidence_id("Security", 12345),
        )


class MakeMftEvidenceIdTests(unittest.TestCase):
    def test_normal_record_and_sequence(self) -> None:
        self.assertEqual(
            make_mft_evidence_id(12345, 3),
            "mft-000000012345-03",
        )

    def test_record_number_zero(self) -> None:
        self.assertEqual(
            make_mft_evidence_id(0, 0),
            "mft-000000000000-00",
        )

    def test_record_number_large(self) -> None:
        self.assertEqual(
            make_mft_evidence_id(999999999999, 99),
            "mft-999999999999-99",
        )

    def test_sequence_number_zero_padded(self) -> None:
        self.assertEqual(
            make_mft_evidence_id(1, 5),
            "mft-000000000001-05",
        )

    def test_sequence_number_two_digits_only(self) -> None:
        self.assertEqual(
            make_mft_evidence_id(1, 100),
            "mft-000000000001-100",
        )

    def test_idempotent(self) -> None:
        self.assertEqual(
            make_mft_evidence_id(12345, 3),
            make_mft_evidence_id(12345, 3),
        )


class MakePrefetchEvidenceIdTests(unittest.TestCase):
    def test_normal_name_and_hash(self) -> None:
        self.assertEqual(
            make_prefetch_evidence_id("CMD.EXE", "A1B2C3D4"),
            "prefetch-cmd-exe-a1b2c3d4",
        )

    def test_name_with_spaces(self) -> None:
        self.assertEqual(
            make_prefetch_evidence_id("my app.exe", "DEADBEEF"),
            "prefetch-my-app-exe-deadbeef",
        )

    def test_name_with_special_chars(self) -> None:
        self.assertEqual(
            make_prefetch_evidence_id("setup(v1).exe", "1234"),
            "prefetch-setup-v1--exe-1234",
        )

    def test_hash_already_lowercase(self) -> None:
        self.assertEqual(
            make_prefetch_evidence_id("foo.exe", "abcd1234"),
            "prefetch-foo-exe-abcd1234",
        )

    def test_hash_uppercase_lowered(self) -> None:
        self.assertEqual(
            make_prefetch_evidence_id("foo.exe", "ABCD1234"),
            "prefetch-foo-exe-abcd1234",
        )

    def test_empty_name(self) -> None:
        self.assertEqual(
            make_prefetch_evidence_id("", "hash"),
            "prefetch--hash",
        )

    def test_idempotent(self) -> None:
        self.assertEqual(
            make_prefetch_evidence_id("CMD.EXE", "A1B2C3D4"),
            make_prefetch_evidence_id("CMD.EXE", "A1B2C3D4"),
        )
