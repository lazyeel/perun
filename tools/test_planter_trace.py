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

ACCESS_SOURCE = Path(__file__).with_name("planter_access.py")
ACCESS_SPEC = importlib.util.spec_from_file_location("planter_access", ACCESS_SOURCE)
assert ACCESS_SPEC and ACCESS_SPEC.loader
ACCESS = importlib.util.module_from_spec(ACCESS_SPEC)
ACCESS_SPEC.loader.exec_module(ACCESS)

COMPARE_SOURCE = Path(__file__).with_name("compare_zone_regions.py")
COMPARE_SPEC = importlib.util.spec_from_file_location("compare_zone_regions", COMPARE_SOURCE)
assert COMPARE_SPEC and COMPARE_SPEC.loader
COMPARE = importlib.util.module_from_spec(COMPARE_SPEC)
COMPARE_SPEC.loader.exec_module(COMPARE)


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

    def test_whole_object_scan_finds_shifted_window(self):
        data = bytearray(ANALYZER.PLANTER_SIZE)
        offset = 0x1ACC
        data[offset:offset + 256] = bytes(range(256))
        hits = ANALYZER.scan_bijections(bytes(data))
        self.assertIn(offset, [candidate for candidate, _ in hits])

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

    def test_sparse_write_probe_offsets_target_window_tails(self):
        expected = {
            "fam2_tail": ANALYZER.DEFAULT_TABLES["fam2"] + 0xFF,
            "fam4_tail": ANALYZER.DEFAULT_TABLES["fam4"] + 0xFF,
            "fam3_control_tail": ANALYZER.DEFAULT_TABLES["fam3"] + 0xFF,
        }
        self.assertEqual(dict(ACCESS.SPARSE_WRITE_PROBE_OFFSETS), expected)
        self.assertTrue(all(0 <= offset < ANALYZER.PLANTER_SIZE
                            for offset in expected.values()))



class IntelAddressTests(unittest.TestCase):
    def test_scaled_index_and_table_base(self):
        result = ACCESS.analyze_intel_address(
            "rdi+rax*4+0x1f30",
            {"rdi": 0x100000, "rax": 5},
            object_base=0x100000,
        )
        self.assertEqual(result["effective_address"], 0x101f44)
        self.assertEqual(result["object_offset"], 0x1f44)
        self.assertEqual(result["table_base_offset"], 0x1f30)
        self.assertEqual(result["index_offset"], 20)
        self.assertEqual(result["anchor_register"], "rdi")

    def test_negative_displacement(self):
        result = ACCESS.analyze_intel_address(
            "rbp-0x30", {"rbp": 0x700000}, object_base=0x700000
        )
        self.assertEqual(result["effective_address"], 0x6fffd0)
        self.assertIsNone(result["object_offset"])

    def test_adjusted_object_pointer(self):
        result = ACCESS.analyze_intel_address(
            "r12+rcx+0x20",
            {"r12": 0x200100, "rcx": 7},
            object_base=0x200000,
        )
        self.assertEqual(result["object_offset"], 0x127)
        self.assertEqual(result["table_base_offset"], 0x120)
        self.assertEqual(result["index_offset"], 7)

    def test_rip_relative_is_not_guessed(self):
        self.assertIsNone(
            ACCESS.analyze_intel_address(
                "rip+0x1234", {"rip": 0x100000}, object_base=0x100000
            )
        )

    def test_intel_operand_width(self):
        operands = ACCESS.parse_intel_memory_operands(
            "movzx eax, BYTE PTR [rdi+rax+0x2460]"
        )
        self.assertEqual(operands, [("rdi+rax+0x2460", 1)])





class ProcessMapTests(unittest.TestCase):
    def test_classify_file_backed_and_anonymous_mappings(self):
        mappings = ACCESS.parse_proc_maps(
            "1000-2000 r--p 00001000 08:01 10 /system/lib64/libfoo.so\n"
            "3000-5000 rw-p 00000000 00:00 0 [heap]\n"
        )
        file_info = ACCESS.classify_mapped_address(0x1123, mappings)
        self.assertEqual(file_info["label"], "libfoo.so")
        self.assertEqual(file_info["offset"], 0x1123)
        self.assertEqual(file_info["kind"], "file-offset")
        heap_info = ACCESS.classify_mapped_address(0x3456, mappings)
        self.assertEqual(heap_info["label"], "[heap]")
        self.assertEqual(heap_info["offset"], 0x456)
        self.assertEqual(heap_info["kind"], "mapping-offset")

    def test_module_rva_precedes_maps(self):
        info = ACCESS.classify_mapped_address(
            0x500123, [], module_base=0x500000
        )
        self.assertEqual(info["label"], "libCoreADI.so")
        self.assertEqual(info["offset"], 0x123)
        self.assertEqual(info["kind"], "module-rva")

    def test_mapping_relative_table_base_and_index(self):
        mapping = {
            "start": 0x3000, "end": 0x5000, "file_offset": 0,
            "file_backed": False, "label": "[heap]",
        }
        result = ACCESS.analyze_intel_address(
            "rdi+rax+0x120", {"rdi": 0x3400, "rax": 7},
            object_base=0x100000, mapping=mapping,
        )
        self.assertEqual(result["mapped_offset"], 0x527)
        self.assertEqual(result["mapped_base_offset"], 0x520)
        self.assertEqual(result["mapped_index_offset"], 7)
        self.assertEqual(result["mapped_anchor_register"], "rdi")




class MaskedModulePointerTests(unittest.TestCase):
    def test_module_relative_base_with_encoded_register(self):
        module_base = 0x70000000
        mask = 0x6DA8B117
        registers = {
            "r14": module_base + 0x24070 + mask,
            "rax": 0x2a,
        }
        result = ACCESS.analyze_intel_address(
            "r14+rax*1-0x6da8b117",
            registers,
            module_base=module_base,
            module_size=0x200000,
        )
        self.assertEqual(result["effective_address"], module_base + 0x2409a)
        self.assertEqual(result["module_base_offset"], 0x24070)
        self.assertEqual(result["module_anchor_register"], "r14")
        self.assertEqual(result["module_index_offset"], 0x2a)
        self.assertEqual(result["module_index_registers"], ("rax",))





class ZoneRegionComparisonTests(unittest.TestCase):
    def test_exact_table_match_inside_family_zone(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            table = bytes((i * 17) & 0xff for i in range(256))
            (root / "fam4_zone.bin").write_bytes(b"prefix" + table + b"suffix")
            (root / "fam1_zone.bin").write_bytes(bytes(768))
            result = COMPARE.compare_zone_regions(table + bytes(512), root)
            fam4 = next(x for x in result["zones"] if x["file"] == "fam4_zone.bin")
            self.assertEqual(fam4["table_exact_offsets"], [6])
            self.assertEqual(fam4["best_equal_bytes"], 256)
            self.assertEqual(fam4["best_offset"], 6)
            self.assertEqual(result["table_size"], 256)
            self.assertEqual(len(result["table_sha256"]), 64)

    def test_near_match_reports_score_without_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            table = bytes(range(256))
            mutated = bytearray(table)
            mutated[100] ^= 0xff
            (root / "fam2_zone.bin").write_bytes(bytes(mutated) + bytes(512))
            result = COMPARE.compare_zone_regions(table, root)
            row = result["zones"][0]
            self.assertEqual(row["best_equal_bytes"], 255)
            self.assertEqual(row["best_offset"], 0)
            self.assertNotIn("data", row)



if __name__ == "__main__":
    unittest.main()



class TraceLifecycleTests(unittest.TestCase):
    """Keep a valid capture from accidentally terminating the live oracle."""

    def test_valid_planter_snapshot_does_not_stop_the_inferior(self):
        trace_source = Path(__file__).with_name("planter_trace_gdb.py")
        source = trace_source.read_text(encoding="utf-8")
        body = source.split("class FirstMixerReadBP", 1)[1].split(
            "class PlanterBaseLoadBP", 1
        )[0]
        self.assertNotIn('if STATE["final_dumped"] or', body)
        self.assertNotIn("return True", body)
        self.assertIn('if STATE["active_op"] != TRANSFORM_OPCODE:', body)
        self.assertIn('if not STATE["final_dumped"]:', body)
        self.assertIn("return False", body)

 
    def test_manifest_uses_v31_after_lifecycle_fix(self):
        trace_source = Path(__file__).with_name("planter_trace_gdb.py")
        source = trace_source.read_text(encoding="utf-8")
        self.assertIn('"script_version": "v33"', source)


    def test_slot_pointer_watchpoint_is_hardware_only_and_armed_first(self):
        trace_source = Path(__file__).with_name("planter_trace_gdb.py")
        source = trace_source.read_text(encoding="utf-8")

        source_slot = source.split("class SourceSlotStoreBP", 1)[1].split(
            "class PostMallocBP", 1
        )[0]
        self.assertLess(
            source_slot.index("arm_slot_pointer_hardware_watchpoint()"),
            source_slot.index("arm_sparse_window_write_probes()"),
        )

        watchpoint = source.split("class SlotPointerWriteBP", 1)[1].split(
            "def arm_slot_pointer_hardware_watchpoint", 1
        )[0]
        self.assertIn("gdb.BP_WATCHPOINT", watchpoint)
        self.assertIn("gdb.WP_WRITE", watchpoint)
        self.assertIn("return False", watchpoint)

        installer = source.split("def arm_slot_pointer_hardware_watchpoint", 1)[1].split(
            "def arm_sparse_window_write_probes", 1
        )[0]
        self.assertIn("hardware", installer.lower())
        self.assertIn("bp.delete()", installer)
        self.assertIn("software-rejected", installer)
        self.assertIn("slot_pointer_events.csv", installer)


    def test_slot_pointer_watchpoint_stops_after_source_anchor_match(self):
        trace_source = Path(__file__).with_name("planter_trace_gdb.py")
        source = trace_source.read_text(encoding="utf-8")
        body = source.split("class SlotPointerWriteBP", 1)[1].split(
            "def arm_slot_pointer_hardware_watchpoint", 1
        )[0]
        self.assertIn("bounded_source_delta(previous, source)", body)
        self.assertIn("bounded_source_delta(current, source)", body)
        self.assertIn("if matches:", body)
        self.assertIn("self.enabled = False", body)
        self.assertIn("SLOT POINTER WATCH DISABLED: source+0x20 anchor captured", body)

    def test_bounded_source_delta_suppresses_unrelated_values(self):
        trace_source = Path(__file__).with_name("planter_trace_gdb.py")
        source = trace_source.read_text(encoding="utf-8")
        helper = source.split("def bounded_source_delta", 1)[1].split(
            "class SlotPointerWriteBP", 1
        )[0]
        self.assertIn("abs(delta) <= 0x100000", helper)
        self.assertIn('return "na"', helper)

    def test_slot_pointer_watchpoint_uses_expression_spec(self):
        trace_source = Path(__file__).with_name("planter_trace_gdb.py")
        source = trace_source.read_text(encoding="utf-8")
        body = source.split("class SlotPointerWriteBP", 1)[1].split(
            "def arm_slot_pointer_hardware_watchpoint", 1
        )[0]
        self.assertIn('f"*(unsigned long long *)0x{address:x}"', body)
        self.assertNotIn('f"-location *(unsigned long long *)', body)

    def test_slot_pointer_watchpoint_reports_failure_stage_without_raw_message(self):
        trace_source = Path(__file__).with_name("planter_trace_gdb.py")
        source = trace_source.read_text(encoding="utf-8")
        installer = source.split("def arm_slot_pointer_hardware_watchpoint", 1)[1].split(
            "def arm_sparse_window_write_probes", 1
        )[0]
        self.assertIn('stage = "create-watchpoint"', installer)
        self.assertIn('status = f"setup-error:{stage}:{type(exc).__name__}"', installer)


    def test_workflow_redacts_and_reports_each_slot_pointer_transition(self):
        workflow_path = Path(__file__).parents[1] / ".github" / "workflows" / "planter-genesis-trace.yml"
        source = workflow_path.read_text(encoding="utf-8")
        self.assertIn("safe_slot_events = []", source)
        self.assertIn('row.get("old_source_delta", "")', source)
        self.assertIn('row.get("new_source_delta", "")', source)
        self.assertIn("def safe_relative_offset(value):", source)
        self.assertIn("magnitude <= 0x100000", source)
        self.assertIn('safe_relative_offset(row.get("old_source_delta", ""))', source)
        self.assertIn('safe_relative_offset(row.get("new_source_delta", ""))', source)
        self.assertIn('re.fullmatch(r"0x[0-9a-f]+", rva)', source)
        self.assertIn("| Old source-relative offset | New source-relative offset |", source)
        self.assertIn("for index, event in enumerate(safe_slot_events, 1)", source)
        self.assertNotIn("row.get(\"old_pointer\")", source)


class DeterministicInputProbeTests(unittest.TestCase):
    def test_gettimeofday_probe_returns_without_running_libc_body(self):
        for filename in ("time_freeze_gdb.py", "rdtsc_freeze_gdb.py"):
            source = (Path(__file__).with_name(filename)).read_text(encoding="utf-8")
            helper = source.split("def return_from_gettimeofday", 1)[1].split(
                "class GtBP", 1
            )[0]
            self.assertIn('gdb.execute("set $rax = 0")', helper)
            self.assertIn('gdb.execute("set $rsp = %#x" % (rsp + 8))', helper)
            self.assertIn('gdb.execute("set $pc = %#x" % ret)', helper)
            self.assertIn("return_from_gettimeofday(tv)", source)
            self.assertIn('log("POKE gettimeofday #', source)

    def test_rdtsc_probe_uses_architectural_eax_edx_and_skips_instruction(self):
        source = (Path(__file__).with_name("rdtsc_freeze_gdb.py")).read_text(encoding="utf-8")
        body = source.split("class RdtscBP", 1)[1].split("class ArmBP", 1)[0]
        self.assertIn('gdb.execute("set $eax = %#x" % FROZEN_RAX)', body)
        self.assertIn('gdb.execute("set $edx = %#x" % FROZEN_RDX)', body)
        self.assertIn('gdb.execute("set $pc = %#x" % (self.addr + 2))', body)

    def test_probe_captures_are_opt_in_and_private(self):
        source = (Path(__file__).parents[1] / "crates/perun-cli/examples/adi-android/adi_test.c").read_text(encoding="utf-8")
        helper = source.split("static void save_env_blob", 1)[1].split("#ifdef DUMP_ADI", 1)[0]
        self.assertIn('getenv(env_name)', helper)
        self.assertIn("O_CREAT | O_TRUNC, 0600", helper)
        self.assertIn('save_env_blob("ADI_SPIM_OUT"', source)
        self.assertIn('save_env_blob("ADI_CPIM_OUT"', source)


class WorkflowProbeRestorationTests(unittest.TestCase):
    def test_standard_trace_restores_full_planter_gdb_script(self):
        workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "planter-genesis-trace.yml").read_text(encoding="utf-8")
        marker = "# Return to the original state before the standard trace invocation."
        self.assertIn(marker, workflow)
        tail = workflow.split(marker, 1)[1].split("      - name: Build a redacted trace report", 1)[0]
        self.assertIn('export GDB_SCRIPT="$GITHUB_WORKSPACE/tools/planter_trace_gdb.py"', tail)
        self.assertLess(
            tail.index('export GDB_SCRIPT="$GITHUB_WORKSPACE/tools/planter_trace_gdb.py"'),
            tail.index('timeout --signal=TERM --kill-after=5s 4m bash'),
        )
