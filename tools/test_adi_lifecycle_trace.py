#!/usr/bin/env python3
"""Regression tests for ADI lifecycle GDB trace helpers (standard library only)."""
from __future__ import annotations

import unittest

from tools.adi_lifecycle_trace_helpers import (
    parse_out_slot_address,
    resolve_output_buffer,
)


class OutSlotAddressTests(unittest.TestCase):
    def test_integer_address(self):
        self.assertEqual(parse_out_slot_address(0x7FFF12345678), 0x7FFF12345678)

    def test_hexadecimal_string_address(self):
        self.assertEqual(parse_out_slot_address("0x7fff12345678"), 0x7FFF12345678)

    def test_decimal_string_address(self):
        self.assertEqual(parse_out_slot_address("000123"), 123)

    def test_zero_is_allowed_for_later_null_slot_handling(self):
        self.assertEqual(parse_out_slot_address(0), 0)

    def test_rejects_boolean(self):
        with self.assertRaises(TypeError):
            parse_out_slot_address(True)

    def test_rejects_non_integer_text(self):
        with self.assertRaises(ValueError):
            parse_out_slot_address("0xnot-an-address")

    def test_rejects_unsupported_types(self):
        with self.assertRaises(TypeError):
            parse_out_slot_address(None)

    def test_rejects_negative_and_overflow(self):
        for value in (-1, 1 << 64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_out_slot_address(value)


class OutputBufferResolutionTests(unittest.TestCase):
    def test_resolves_hex_start_slots_and_captures_output(self):
        reads = []
        captured = []

        def read_u64(address):
            reads.append(("u64", address))
            return 0x70001000

        def read_u32(address):
            reads.append(("u32", address))
            return 276

        def capture(address, length, limit):
            captured.append((address, length, limit))
            return {"status": "ok", "length": length}

        result = resolve_output_buffer(
            "0x1000",
            "0x1008",
            read_u64_at=read_u64,
            read_u32_at=read_u32,
            capture_bytes=capture,
            limit=4096,
        )

        self.assertEqual(result["pointer"], 0x70001000)
        self.assertEqual(result["length"], 276)
        self.assertEqual(result["data"], {"status": "ok", "length": 276})
        self.assertEqual(reads, [("u64", 0x1000), ("u32", 0x1008)])
        self.assertEqual(captured, [(0x70001000, 276, 4096)])

    def test_resolves_integer_otp_slots(self):
        result = resolve_output_buffer(
            0x2000,
            0x2008,
            read_u64_at=lambda _: 0x71000000,
            read_u32_at=lambda _: 28,
            capture_bytes=lambda address, length, limit: {
                "status": "ok", "address": address, "length": length, "limit": limit
            },
            limit=4096,
        )
        self.assertEqual(result["pointer"], 0x71000000)
        self.assertEqual(result["length"], 28)

    def test_invalid_slot_does_not_read_inferior_memory(self):
        def unexpected(_):
            self.fail("memory reader must not be called for an invalid slot")

        result = resolve_output_buffer(
            "not-an-address",
            "0x1008",
            read_u64_at=unexpected,
            read_u32_at=unexpected,
            capture_bytes=lambda *_: self.fail("capture must not run"),
            limit=4096,
        )
        self.assertEqual(result["pointer"], 0)
        self.assertEqual(result["length"], 0)
        self.assertEqual(result["data"]["status"], "out-slot-parse-error:ValueError")

    def test_read_failure_is_reported_without_raising(self):
        def broken(_):
            raise RuntimeError("synthetic inferior read failure")

        result = resolve_output_buffer(
            0x1000,
            0x1008,
            read_u64_at=broken,
            read_u32_at=lambda _: 28,
            capture_bytes=lambda *_: self.fail("capture must not run"),
            limit=4096,
        )
        self.assertEqual(result["data"]["status"], "out-slot-read-error:RuntimeError")


if __name__ == "__main__":
    unittest.main()
