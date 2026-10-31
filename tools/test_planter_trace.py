#!/usr/bin/env python3
"""Regression tests for the planter trace analyzer (standard library only)."""
from __future__ import annotations
import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

SOURCE = Path(__file__).with_name("analyze_planter_trace.py")
SPEC = importlib.util.spec_from_file_location("analyze_planter_trace", SOURCE)
assert SPEC and SPEC.loader
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)


class PlanterTraceTests(unittest.TestCase):
    def test_partition_exact(self):
        regions = [("head", 0, 0x0D60)]
        regions.extend((n, o, o + 256) for n, o in ANALYZER.DEFAULT_TABLES.items())
        regions.extend((n, o, o + size) for n, o, size in ANALYZER.DEFAULT_UNKNOWN_RANGES)
        regions.sort(key=lambda row: row[1])
        cursor = 0
        for name, start, end in regions:
            self.assertEqual(start, cursor, name)
            self.assertGreater(end, start)
            cursor = end
        self.assertEqual(cursor, ANALYZER.PLANTER_SIZE)

    def test_identity_permutation(self):
        self.assertEqual(ANALYZER.cycle_lengths(bytes(range(256))), {1: 256})

    def test_single_256_cycle(self):
        self.assertEqual(ANALYZER.cycle_lengths(bytes((i + 1) & 255 for i in range(256))), {256: 1})

    def test_duplicate_byte_is_not_permutation(self):
        self.assertIsNone(ANALYZER.cycle_lengths(bytes(256)))

    def test_unknown_scan(self):
        data = b"prefix" + bytes(range(256)) + b"suffix"
        hits = ANALYZER.scan_bijections(data)
        self.assertTrue(any(offset == 6 for offset, _ in hits))

    def test_slot_anchored_snapshot_fallback_and_final_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(ANALYZER.load_planter_snapshot(root), (None, None))
            (root / "planter.slot_anchored.bin").write_bytes(b"anchored")
            self.assertEqual(
                ANALYZER.load_planter_snapshot(root),
                (b"anchored", "slot-anchored"),
            )
            (root / "planter.final.bin").write_bytes(b"validated")
            self.assertEqual(
                ANALYZER.load_planter_snapshot(root),
                (b"validated", "final"),
            )

    def test_manifest_round_trip(self):
        manifest = {"tables": list(ANALYZER.DEFAULT_TABLES.items()),
                    "unknown_ranges": ANALYZER.DEFAULT_UNKNOWN_RANGES}
        self.assertEqual(ANALYZER.resolve_tables(manifest), ANALYZER.DEFAULT_TABLES)
        self.assertEqual(ANALYZER.resolve_unknown_ranges(manifest), ANALYZER.DEFAULT_UNKNOWN_RANGES)

    def test_partition_validator(self):
        out = io.StringIO()
        with redirect_stdout(out):
            ANALYZER.validate_partition()
        self.assertIn("contiguous, non-overlapping", out.getvalue())
        self.assertNotIn("WARNING", out.getvalue())


if __name__ == "__main__":
    unittest.main()
