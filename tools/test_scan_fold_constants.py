from __future__ import annotations

import unittest

from tools.scan_fold_constants import extract_constants, scan_image


SOURCE = """
pub const K_7C954560: Lanes = [0x2a000000u32; 4];
pub const K_7C954570: Lanes = [0x15936d71u32; 4];
pub const K_7C954580: Lanes = [0x5a278f86u32; 4];
"""


class FoldConstantScanTests(unittest.TestCase):
    def test_extracts_lane_broadcasts_from_fold_source(self):
        self.assertEqual(
            extract_constants(SOURCE),
            [
                ("K_7C954560", 0x2A000000),
                ("K_7C954570", 0x15936D71),
                ("K_7C954580", 0x5A278F86),
            ],
        )

    def test_distinguishes_full_broadcast_from_scalar_only_hits(self):
        constants = extract_constants(SOURCE)
        image = (
            b"prefix"
            + (0x2A000000).to_bytes(4, "little") * 4
            + b"middle"
            + (0x15936D71).to_bytes(4, "little")
            + b"suffix"
        )
        result = scan_image(image, constants)
        self.assertEqual(result["constant_count"], 3)
        self.assertEqual(result["broadcast_key_count"], 1)
        self.assertEqual(result["scalar_key_count"], 2)
        self.assertFalse(result["complete_broadcast_set"])
        self.assertEqual(result["constants"][0]["broadcast_offsets"], ["0x6"])
        self.assertEqual(result["constants"][1]["scalar_offsets"], ["0x1c"])
        self.assertIn("do not prove", result["interpretation"])


if __name__ == "__main__":
    unittest.main()
