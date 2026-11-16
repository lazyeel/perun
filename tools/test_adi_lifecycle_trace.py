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





class OutputAllocationRegistryTests(unittest.TestCase):
    def test_primary_and_repeated_outputs_remain_correlated_until_dispose(self):
        from tools.adi_lifecycle_trace_helpers import (
            remember_output_allocation,
            take_output_allocation,
        )

        allocations = {}
        self.assertTrue(remember_output_allocation(
            allocations, 0x1000, kind="mid", call_id=1, length=60
        ))
        self.assertTrue(remember_output_allocation(
            allocations, 0x2000, kind="otp", call_id=1, length=28
        ))
        self.assertTrue(remember_output_allocation(
            allocations, 0x3000, kind="mid", call_id=2, length=60
        ))
        self.assertTrue(remember_output_allocation(
            allocations, 0x4000, kind="otp", call_id=2, length=28
        ))

        self.assertEqual(
            take_output_allocation(allocations, 0x1000),
            {"kind": "mid", "call_id": 1, "length": 60},
        )
        self.assertEqual(
            take_output_allocation(allocations, 0x2000),
            {"kind": "otp", "call_id": 1, "length": 28},
        )
        self.assertEqual(
            take_output_allocation(allocations, 0x3000),
            {"kind": "mid", "call_id": 2, "length": 60},
        )
        self.assertEqual(
            take_output_allocation(allocations, 0x4000),
            {"kind": "otp", "call_id": 2, "length": 28},
        )
        self.assertEqual(allocations, {})

    def test_reused_heap_address_does_not_inherit_previous_owner(self):
        from tools.adi_lifecycle_trace_helpers import (
            remember_output_allocation,
            take_output_allocation,
        )

        allocations = {}
        remember_output_allocation(
            allocations, 0x7000, kind="mid", call_id=10, length=60
        )
        from tools.adi_lifecycle_trace_helpers import peek_output_allocation
        self.assertEqual(
            peek_output_allocation(allocations, 0x7000),
            {"kind": "mid", "call_id": 10, "length": 60},
        )
        self.assertEqual(allocations[0x7000][0]["call_id"], 10)
        first = take_output_allocation(allocations, 0x7000)
        self.assertEqual(first["call_id"], 10)
        remember_output_allocation(
            allocations, 0x7000, kind="otp", call_id=11, length=28
        )
        second = take_output_allocation(allocations, 0x7000)
        self.assertEqual(second, {"kind": "otp", "call_id": 11, "length": 28})

    def test_multiple_live_allocations_at_same_address_are_fifo(self):
        from tools.adi_lifecycle_trace_helpers import (
            remember_output_allocation,
            take_output_allocation,
        )

        allocations = {}
        remember_output_allocation(
            allocations, 0x8000, kind="mid", call_id=20, length=60
        )
        remember_output_allocation(
            allocations, 0x8000, kind="otp", call_id=21, length=28
        )
        self.assertEqual(
            take_output_allocation(allocations, 0x8000)["call_id"], 20
        )
        self.assertEqual(
            take_output_allocation(allocations, 0x8000)["call_id"], 21
        )
        self.assertIsNone(take_output_allocation(allocations, 0x8000))

    def test_unknown_and_invalid_pointers_are_not_attributed(self):
        from tools.adi_lifecycle_trace_helpers import (
            remember_output_allocation,
            take_output_allocation,
        )

        allocations = {}
        self.assertFalse(remember_output_allocation(
            allocations, 0, kind="mid", call_id=1, length=60
        ))
        self.assertFalse(remember_output_allocation(
            allocations, True, kind="otp", call_id=1, length=28
        ))
        for pointer in (0, True, -1, "0x1000", None):
            self.assertIsNone(take_output_allocation(allocations, pointer))
        self.assertEqual(allocations, {})


class ApiEventStreamValidationTests(unittest.TestCase):
    @staticmethod
    def entry(call_id, parent=None, api="export"):
        return {
            "event": "api_entry",
            "call_id": call_id,
            "parent_call_id": parent,
            "api": api,
        }

    @staticmethod
    def terminal(kind, call_id, parent=None, api="export"):
        return {
            "event": kind,
            "call_id": call_id,
            "parent_call_id": parent,
            "api": api,
        }

    def test_balanced_entry_and_return(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([
            self.entry(1),
            {"event": "opcode_arguments", "api_call_id": 1},
            self.terminal("api_return", 1),
        ])
        self.assertTrue(result["valid"])
        self.assertEqual(result["api_entry_count"], 1)
        self.assertEqual(result["api_return_count"], 1)
        self.assertEqual(result["open_call_ids"], [])
        self.assertEqual(result["errors"], [])

    def test_nested_calls_must_return_in_lifo_order(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([
            self.entry(1, api="outer"),
            self.entry(2, parent=1, api="inner"),
            self.terminal("api_return", 2, parent=1, api="inner"),
            self.terminal("api_return", 1, api="outer"),
        ])
        self.assertTrue(result["valid"])
        self.assertEqual(result["api_return_count"], 2)

    def test_unwind_is_a_valid_terminal_event(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([
            self.entry(1),
            self.terminal("api_unwind", 1),
        ])
        self.assertTrue(result["valid"])
        self.assertEqual(result["api_unwind_count"], 1)

    def test_unclosed_entry_is_reported(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([self.entry(7)])
        self.assertFalse(result["valid"])
        self.assertEqual(result["open_call_ids"], [7])

    def test_terminal_without_entry_is_reported(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([self.terminal("api_return", 7)])
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "terminal-without-entry")

    def test_duplicate_call_id_is_reported(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([self.entry(1), self.entry(1)])
        self.assertFalse(result["valid"])
        self.assertIn("duplicate-entry-call-id", [e["code"] for e in result["errors"]])

    def test_wrong_parent_link_is_reported(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([
            self.entry(1),
            self.entry(2, parent=99),
            self.terminal("api_return", 2, parent=99),
            self.terminal("api_return", 1),
        ])
        self.assertFalse(result["valid"])
        self.assertIn(
            "entry-parent-does-not-match-active-frame",
            [e["code"] for e in result["errors"]],
        )

    def test_parent_cannot_return_while_child_is_open(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([
            self.entry(1, api="parent"),
            self.entry(2, parent=1, api="child"),
            self.terminal("api_return", 1, api="parent"),
        ])
        self.assertFalse(result["valid"])
        self.assertIn(
            "terminal-is-not-current-stack-top",
            [e["code"] for e in result["errors"]],
        )

    def test_opcode_capture_must_reference_current_frame(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([
            self.entry(1),
            self.entry(2, parent=1),
            {"event": "opcode_arguments", "api_call_id": 1},
        ])
        self.assertFalse(result["valid"])
        self.assertIn(
            "opcode-capture-call-id-not-current-frame",
            [e["code"] for e in result["errors"]],
        )

    def test_return_probe_failure_is_explicit(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([
            self.entry(1),
            {"event": "api_return_probe_error", "call_id": 1},
        ])
        self.assertFalse(result["valid"])
        self.assertIn(
            "return-probe-creation-failed",
            [e["code"] for e in result["errors"]],
        )

    def test_invalid_call_id_types_are_rejected(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        for call_id in (True, 0, -1, "1", None):
            with self.subTest(call_id=call_id):
                result = validate_api_event_stream([self.entry(call_id)])
                self.assertFalse(result["valid"])


    @staticmethod
    def otp_return(call_id, outputs, api="qi864985u0"):
        return {
            "event": "api_return",
            "call_id": call_id,
            "parent_call_id": None,
            "api": api,
            "outputs": outputs,
        }

    @staticmethod
    def dispose_entry(call_id, pointer, owner):
        return {
            "event": "api_entry",
            "call_id": call_id,
            "parent_call_id": None,
            "api": "jk24uiwqrg",
            "arguments": {
                "pointer": hex(pointer),
                "otp_output_owner": owner,
            },
        }

    @staticmethod
    def dispose_return(call_id, owner):
        return {
            "event": "api_return",
            "call_id": call_id,
            "parent_call_id": None,
            "api": "jk24uiwqrg",
            "disposed_output_owner": owner,
        }

    def test_otp_outputs_must_match_dispose_entry_and_return_owners(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        mid_owner = {"kind": "mid", "call_id": 1, "length": 60}
        otp_owner = {"kind": "otp", "call_id": 1, "length": 28}
        result = validate_api_event_stream([
            self.entry(1, api="qi864985u0"),
            self.otp_return(1, {
                "mid": {"pointer": 0x1000, "length": 60},
                "otp": {"pointer": 0x2000, "length": 28},
            }),
            self.dispose_entry(2, 0x1000, mid_owner),
            self.dispose_return(2, mid_owner),
            self.dispose_entry(3, 0x2000, otp_owner),
            self.dispose_return(3, otp_owner),
        ])
        self.assertTrue(result["valid"])
        self.assertEqual(result["tracked_output_allocations"], 2)
        self.assertEqual(result["disposed_output_allocations"], 2)
        self.assertEqual(result["outstanding_output_allocations"], 0)

    def test_unmatched_otp_output_fails_validation(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([
            self.entry(1, api="qi864985u0"),
            self.otp_return(1, {
                "mid": {"pointer": 0x1100, "length": 60},
                "otp": {"pointer": 0, "length": 0},
            }),
        ])
        self.assertFalse(result["valid"])
        self.assertEqual(result["outstanding_output_allocations"], 1)
        self.assertIn(
            "output-allocation-not-disposed",
            [e["code"] for e in result["errors"]],
        )

    def test_dispose_owner_mismatch_is_detected(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        expected = {"kind": "mid", "call_id": 1, "length": 60}
        wrong = {"kind": "otp", "call_id": 1, "length": 28}
        result = validate_api_event_stream([
            self.entry(1, api="qi864985u0"),
            self.otp_return(1, {"mid": {"pointer": 0x1200, "length": 60}}),
            self.dispose_entry(2, 0x1200, wrong),
            self.dispose_return(2, wrong),
        ])
        self.assertFalse(result["valid"])
        error_codes = [e["code"] for e in result["errors"]]
        self.assertIn("dispose-entry-owner-mismatch", error_codes)
        self.assertIn("dispose-return-owner-mismatch", error_codes)
        self.assertIn("output-allocation-not-disposed", error_codes)

    def test_same_heap_pointer_can_be_reused_after_dispose(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        first_owner = {"kind": "mid", "call_id": 1, "length": 60}
        second_owner = {"kind": "otp", "call_id": 3, "length": 28}
        result = validate_api_event_stream([
            self.entry(1, api="qi864985u0"),
            self.otp_return(1, {"mid": {"pointer": 0x1300, "length": 60}}),
            self.dispose_entry(2, 0x1300, first_owner),
            self.dispose_return(2, first_owner),
            self.entry(3, api="qi864985u0"),
            self.otp_return(3, {"otp": {"pointer": 0x1300, "length": 28}}),
            self.dispose_entry(4, 0x1300, second_owner),
            self.dispose_return(4, second_owner),
        ])
        self.assertTrue(result["valid"])
        self.assertEqual(result["tracked_output_allocations"], 2)
        self.assertEqual(result["disposed_output_allocations"], 2)


    def test_complete_lifecycle_contract_accepts_cold_start_end_and_five_otp_calls(self):
        from tools.adi_lifecycle_trace_helpers import validate_complete_lifecycle_contract
        events = [self.entry(1, api="rsegvyrt87")]
        events[0]["phase_id"] = 1
        events[0]["arguments"] = {"spim": {"status": "ok", "length": 347}}
        start_return = self.terminal("api_return", 1, api="rsegvyrt87")
        start_return.update({
            "phase_id": 1, "return_value": 0,
            "outputs": {
                "cpim": {"pointer": 0x1000, "length": 276, "data": {"status": "ok"}},
                "session": 7,
            },
        })
        events.append(start_return)
        end_entry = self.entry(2, api="uv5t6nhkui")
        end_entry["phase_id"] = 2
        end_entry["arguments"] = {
            "session": 7,
            "ptm": {"status": "ok", "length": 64},
            "tk": {"status": "ok", "length": 32},
        }
        events.append(end_entry)
        end_return = self.terminal("api_return", 2, api="uv5t6nhkui")
        end_return.update({"phase_id": 2, "return_value": 0})
        events.append(end_return)
        code_entry = self.entry(3, api="aslgmuibau")
        code_entry["phase_id"] = 3
        events.append(code_entry)
        code_return = self.terminal("api_return", 3, api="aslgmuibau")
        code_return.update({"phase_id": 3, "return_value": 0})
        events.append(code_return)
        next_id = 4
        for sample in range(5):
            otp_entry = self.entry(next_id, api="qi864985u0")
            otp_entry["phase_id"] = 4
            events.append(otp_entry)
            otp_return = self.terminal("api_return", next_id, api="qi864985u0")
            otp_return.update({
                "phase_id": 4, "return_value": 0,
                "outputs": {
                    "mid": {"pointer": 0x10000 + sample * 0x100, "length": 60, "data": {"status": "ok"}},
                    "otp": {"pointer": 0x20000 + sample * 0x100, "length": 28, "data": {"status": "ok"}},
                },
            })
            events.append(otp_return)
            next_id += 1
            for pointer, kind, length in (
                (0x10000 + sample * 0x100, "mid", 60),
                (0x20000 + sample * 0x100, "otp", 28),
            ):
                owner = {"kind": kind, "call_id": otp_entry["call_id"], "length": length}
                events.append(self.dispose_entry(next_id, pointer, owner))
                events.append(self.dispose_return(next_id, owner))
                next_id += 1

        result = validate_complete_lifecycle_contract(events)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["provisioning_start_calls"], 1)
        self.assertEqual(result["provisioning_end_calls"], 1)
        self.assertEqual(result["otp_request_calls"], 5)
        self.assertEqual(result["dispose_calls"], 10)
        self.assertEqual(result["spim_bytes"], 347)
        self.assertEqual(result["cpim_bytes"], 276)
        self.assertTrue(result["session_matches"])

    def test_complete_lifecycle_contract_rejects_missing_end_and_out_of_order_otp(self):
        from tools.adi_lifecycle_trace_helpers import validate_complete_lifecycle_contract
        events = [
            self.entry(1, api="rsegvyrt87"),
            self.terminal("api_return", 1, api="rsegvyrt87"),
            self.entry(2, api="qi864985u0"),
            self.terminal("api_return", 2, api="qi864985u0"),
        ]
        events[0]["phase_id"] = 1
        events[0]["arguments"] = {"spim": {"status": "ok", "length": 347}}
        events[1].update({
            "phase_id": 1, "return_value": 0,
            "outputs": {
                "cpim": {"pointer": 1, "length": 276, "data": {"status": "ok"}},
                "session": 1,
            },
        })
        events[2].update({"phase_id": 4, "arguments": {}})
        events[3].update({
            "phase_id": 4, "return_value": 0,
            "outputs": {
                "mid": {"pointer": 2, "length": 60, "data": {"status": "ok"}},
                "otp": {"pointer": 3, "length": 28, "data": {"status": "ok"}},
            },
        })
        result = validate_complete_lifecycle_contract(events)
        self.assertFalse(result["valid"])
        codes = [error["code"] for error in result["errors"]]
        self.assertIn("expected-exactly-one-provisioning-end", codes)
        self.assertIn("expected-exactly-one-post-end-login-code-check", codes)
        self.assertIn("expected-primary-and-four-repeat-otp-requests", codes)


    def test_empty_stream_is_not_accepted_as_valid_capture(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([])
        self.assertFalse(result["valid"])
        self.assertEqual(result["event_count"], 0)

    def test_jsonl_reader_reports_parse_errors_without_echoing_payload(self):
        import json
        import tempfile
        from pathlib import Path
        from tools.adi_lifecycle_trace_helpers import validate_api_event_log
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.jsonl"
            path.write_text(
                json.dumps(self.entry(1)) + "\n"
                + "{secret=not-json}\n"
                + json.dumps(self.terminal("api_return", 1)) + "\n",
                encoding="utf-8",
            )
            result = validate_api_event_log(path)
        self.assertFalse(result["valid"])
        self.assertEqual(result["jsonl_parse_errors"], [{"line": 2, "code": "invalid-json"}])
        self.assertNotIn("secret", str(result))

    def test_non_string_event_kind_is_ignored_without_type_error(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([
            {"event": ["not", "hashable"]},
            {"event": {"unexpected": "object"}},
            self.entry(1),
            self.terminal("api_return", 1),
        ])
        self.assertTrue(result["valid"])
        self.assertEqual(result["event_count"], 4)

    def test_boolean_parent_id_is_not_accepted_as_integer_one(self):
        from tools.adi_lifecycle_trace_helpers import validate_api_event_stream
        result = validate_api_event_stream([
            self.entry(1),
            self.entry(2, parent=True),
            self.terminal("api_return", 2, parent=True),
            self.terminal("api_return", 1),
        ])
        self.assertFalse(result["valid"])
        self.assertIn(
            "entry-parent-does-not-match-active-frame",
            [e["code"] for e in result["errors"]],
        )

