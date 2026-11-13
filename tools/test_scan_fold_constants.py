from __future__ import annotations

import struct
import unittest

from tools.scan_fold_constants import elf_locations, extract_constants, scan_image


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
        self.assertRegex(result["image_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(result["image_bytes"], len(image))
        self.assertEqual(result["broadcast_key_count"], 1)
        self.assertEqual(result["scalar_key_count"], 2)
        self.assertFalse(result["complete_broadcast_set"])
        self.assertEqual(result["constants"][0]["broadcast_offsets"], ["0x6"])
        self.assertEqual(result["constants"][1]["scalar_offsets"], ["0x1c"])
        self.assertIn("do not prove", result["interpretation"])

    def test_elf_offset_mapping_identifies_section_and_load_address(self):
        image = bytearray(384)
        image[:4] = b"\x7fELF"
        image[4:6] = b"\x02\x01"
        struct.pack_into("<Q", image, 32, 64)    # e_phoff
        struct.pack_into("<Q", image, 40, 120)   # e_shoff
        struct.pack_into("<HH", image, 54, 56, 1)
        struct.pack_into("<HHH", image, 58, 64, 3, 2)

        # One PT_LOAD maps file offset 0 -> ELF virtual address 0x1000.
        struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 0, 0x1000, 0, 384, 384, 0x1000)

        # Section 1 is .rodata at file offset 256 / ELF VA 0x1100.
        struct.pack_into("<IIQQQQIIQQ", image, 120 + 64,
                         1, 1, 2, 0x1100, 256, 16, 0, 0, 8, 0)
        # Section 2 is the section-name string table at 320.
        struct.pack_into("<IIQQQQIIQQ", image, 120 + 128,
                         9, 3, 0, 0, 320, 19, 0, 0, 1, 0)
        image[320:339] = b"\x00.rodata\x00.shstrtab\x00"

        mapped = elf_locations(bytes(image), 260)
        self.assertEqual(mapped["section"]["name"], ".rodata")
        self.assertEqual(mapped["section"]["section_offset"], "0x4")
        self.assertEqual(mapped["section"]["elf_vaddr"], "0x1104")
        self.assertEqual(mapped["segments"][0]["type"], "PT_LOAD")
        self.assertEqual(mapped["segments"][0]["elf_vaddr"], "0x1104")


if __name__ == "__main__":
    unittest.main()
