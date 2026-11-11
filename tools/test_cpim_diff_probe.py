#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.cpim_diff_probe import CPIM_LEN, SEGMENTS, build_report, compare_pair


class CpimDiffProbeTests(unittest.TestCase):
    def test_segment_boundaries_cover_exact_cpim(self):
        self.assertEqual(SEGMENTS[0][1], 0)
        self.assertEqual(SEGMENTS[-1][2], CPIM_LEN)
        for left, right in zip(SEGMENTS, SEGMENTS[1:]):
            self.assertEqual(left[2], right[1])

    def test_changes_are_localized_without_byte_values(self):
        left = bytearray(CPIM_LEN)
        right = bytearray(CPIM_LEN)
        right[0x08] = 0xA5
        right[0x32] = 0xB6
        right[0xE1] = 0xC7
        result = compare_pair(bytes(left), bytes(right))
        self.assertEqual(result["status"], "compared")
        self.assertFalse(result["equal"])
        self.assertEqual(result["changed_bytes"], 3)
        changed = {item["name"]: item["changed_bytes"] for item in result["segments"]}
        self.assertEqual(changed["session16"], 1)
        self.assertEqual(changed["body_a"], 1)
        self.assertEqual(changed["body_b"], 1)
        self.assertEqual(result["segments"][1]["first_changed_offsets"], [0x08])
        self.assertNotIn('"165"', json.dumps(result))

    def test_equal_missing_and_invalid_captures_are_distinct(self):
        data = bytes(CPIM_LEN)
        self.assertTrue(compare_pair(data, data)["equal"])
        self.assertEqual(compare_pair(None, data)["status"], "missing-capture")
        self.assertEqual(compare_pair(b"short", data)["status"], "invalid-length")
        self.assertIsNone(compare_pair(b"short", data)["equal"])

    def test_build_report_emits_hashes_but_not_raw_bytes_or_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = bytes(CPIM_LEN)
            b = bytearray(a)
            b[0x05] = 0x7E
            (root / "a").write_bytes(a)
            (root / "b").write_bytes(bytes(b))
            report = build_report({
                "baseline_a": root / "a",
                "baseline_b": root / "b",
                "frozen_a": root / "missing_a",
                "frozen_b": root / "missing_b",
            })
            self.assertEqual(report["pairs"]["baseline_repeat"]["changed_bytes"], 1)
            self.assertEqual(report["pairs"]["baseline_repeat"]["segments"][1]["name"], "session16")
            self.assertEqual(report["pairs"]["frozen_repeat"]["status"], "missing-capture")
            self.assertFalse(report["privacy"]["raw_cpim_bytes_included"])
            serialized = json.dumps(report)
            self.assertNotIn(str(root), serialized)
            self.assertNotIn('"126"', serialized)


if __name__ == "__main__":
    unittest.main()
