#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.capture_manifest import build_manifest, file_fingerprint, tree_fingerprint


class CaptureManifestTests(unittest.TestCase):
    def test_file_fingerprint_hashes_content_without_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "secret-identity"
            payload = b"\x00private-identity\xff"
            path.write_bytes(payload)
            result = file_fingerprint("identity", path)
            self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(result["bytes"], len(payload))
            self.assertNotIn(str(path), json.dumps(result))
            self.assertNotIn(payload.decode("latin1"), json.dumps(result))

    def test_tree_fingerprint_is_stable_and_content_sensitive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            root.mkdir()
            (root / "one").write_bytes(b"alpha")
            (root / "nested").mkdir()
            (root / "nested" / "two").write_bytes(b"beta")
            first = tree_fingerprint("state", root)
            second = tree_fingerprint("state", root)
            self.assertEqual(first, second)
            self.assertEqual(first["file_count"], 2)
            self.assertNotIn("nested", json.dumps(first))
            (root / "one").write_bytes(b"changed")
            self.assertNotEqual(first["tree_sha256"], tree_fingerprint("state", root)["tree_sha256"])

    def test_manifest_keeps_native_replay_and_gdb_sessions_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            work.mkdir()
            (work / "fixed-input.spim").write_bytes(b"S" * 347)
            (work / "native-live.cpim").write_bytes(b"C" * 276)
            (work / "adi_identifier").write_bytes(b"I" * 16)
            (work / "adi-data").mkdir()
            (work / "adi-data" / "state.bin").write_bytes(b"state secret")
            (work / "native-exit-code.txt").write_text("0")
            (work / "full-cycle-exit-code.txt").write_text("0")
            lifecycle = work / "full-adi-capture"
            lifecycle.mkdir()
            for name, payload in (
                ("device_identity.bin", b"private identity"),
                ("spim.bin", b"private SPIM"),
                ("cpim.bin", b"private CPIM"),
                ("ptm.bin", b"private PTM"),
                ("tk.bin", b"private TK"),
                ("mid.bin", b"private MID"),
                ("otp.bin", b"private OTP"),
                ("adi-state-after-end.bin", b"private adi.pb"),
                ("adi-state-after-end.bin.status", b"present"),
            ):
                (lifecycle / name).write_bytes(payload)
            (work / "adi-data" / "adi.pb").write_bytes(b"private adi.pb")
            (lifecycle / "adi-lifecycle.trace").write_text(
                "adi lifecycle trace v1\n"
                "phase=1 phase_name=provisioning_start api=rsegvyrt87\n"
                "phase=1 phase_name=provisioning_start opcode=0x716bd86c\n"
                "phase=2 phase_name=provisioning_end api=uv5t6nhkui\n"
                "phase=4 phase_name=otp_request api=qi864985u0\n"
                "phase=4 phase_name=otp_request opcode=0x12345678\n"
                "phase=-1 phase_name=unknown api=unclassified_export\n",
                encoding="ascii",
            )

            seed = work / "fixed-input-probe" / "seed"
            (seed / "adi-data").mkdir(parents=True)
            (seed / "adi-data" / "state.bin").write_bytes(b"state secret")
            (seed / "adi_identifier").write_bytes(b"I" * 16)
            probe = work / "fixed-input-probe"
            for name in ("baseline_a", "baseline_b", "frozen_a", "frozen_b"):
                (probe / f"{name}.cpim").write_bytes(bytes(276))
                (probe / f"{name}.rc").write_text("0")
            (probe / "cpim-diff.json").write_text(json.dumps({"schema_version": 1, "pairs": {"baseline_repeat": {"equal": True}}}))

            trace = work / "traces" / "run-1-2"
            trace.mkdir(parents=True)
            (trace / "run.json").write_text(json.dumps({
                "run_id": "run-1-2", "script_version": "v33",
                "entry_rva": 123, "transform_opcode": 456,
            }))
            (trace / "planter.final.bin").write_bytes(b"planter")
            (trace / "source.at_dd511.bin").write_bytes(b"source")
            (work / "run-exit-code.txt").write_text("0")

            second = work / "traces-index1" / "run-2-3"
            second.mkdir(parents=True)
            (second / "run.json").write_text(json.dumps({
                "run_id": "run-2-3", "script_version": "v34",
            }))
            (second / "fam1_candidate_events.csv").write_text(
                "active_opcode,resolution,fam1_index\n"
                "0x716bd86c,source-anchored-fam1-window,0x0\n"
                "0x716bd86c,source-anchored-fam1-window,0x1\n"
                "0x716bd86c,source-anchored-fam1-window,0x2\n"
            )
            (second / "trace.log").write_text(
                "[12:00:00] FAM1 PRODUCER REVERSE RESULT: lineage_status=sil-producer-found "
                "reverse_steps=466 producer_status=found producer_rva=0xe2432 "
                "producer_mnemonic=add producer_forward_check=yes "
                "upstream_status=found upstream_rva=0xe23c4 "
                "upstream_mnemonic=xor upstream_forward_check=yes "
                "sil_producer_status=found sil_producer_rva=0xe1bd7 "
                "sil_producer_mnemonic=and sil_producer_forward_check=yes\n"
            )
            (work / "index1-target-hit.txt").write_text("2")
            (work / "index1-exit-code.txt").write_text("0")

            manifest = build_manifest(work, "abc123", "42")
            groups = manifest["capture_groups"]
            self.assertTrue(groups["native_control"]["artifacts"][0]["present"])
            self.assertEqual(groups["fixed_input_replays"]["spim_source"], "native_control.spim")
            self.assertTrue(groups["fixed_input_replays"]["cpim_segment_diff"]["pairs"]["baseline_repeat"]["equal"])
            lifecycle_group = groups["full_lifecycle"]
            self.assertEqual(lifecycle_group["exit_code"], "0")
            lifecycle_artifacts = {item["label"]: item for item in lifecycle_group["artifacts"]}
            self.assertTrue(lifecycle_artifacts["otp.bin"]["present"])
            self.assertTrue(lifecycle_artifacts["adi-state-after-end.bin"]["present"])
            trace = lifecycle_group["trace"]
            self.assertTrue(trace["artifact"]["present"])
            self.assertEqual(
                trace["opcode_sequence"],
                [
                    {"phase_id": 1, "phase": "provisioning_start", "opcode": "0x716bd86c"},
                    {"phase_id": 4, "phase": "otp_request", "opcode": "0x12345678"},
                ],
            )
            self.assertEqual(
                [row["name"] for row in trace["api_calls"]],
                ["rsegvyrt87", "uv5t6nhkui", "qi864985u0", "unclassified_export"],
            )
            self.assertEqual(trace["api_calls"][-1]["phase_id"], -1)
            self.assertIn("ephemeral runner", lifecycle_group["pairing_rule"])
            self.assertTrue(lifecycle_group["state_directory_after_cycle"]["present"])
            self.assertEqual(groups["gdb_trace"]["metadata"]["tracer_version"], "v33")
            self.assertIn("separate GDB live provisioning process", groups["gdb_trace"]["process_role"])
            self.assertIn("must not be paired", groups["gdb_trace"]["pairing_rule"])
            index_probe = groups["fam1_index1_probe"]
            self.assertTrue(index_probe["trace_directory_present"])
            self.assertEqual(index_probe["target_hit"], "2")
            self.assertEqual(index_probe["candidate_writer"]["observed_indices"], [0, 1, 2])
            self.assertEqual(index_probe["reverse_lineage"]["producers"][0]["rva"], "0xe2432")
            serialized = json.dumps(manifest)
            self.assertNotIn("state secret", serialized)
            self.assertNotIn("private identity", serialized)
            self.assertNotIn("private OTP", serialized)
            self.assertNotIn("private adi.pb", serialized)
            self.assertNotIn(str(work), serialized)
            self.assertFalse(manifest["privacy"]["raw_artifacts_included"])

    def test_missing_inputs_are_explicit_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = build_manifest(Path(tmp), "sha", "run")
            self.assertFalse(manifest["capture_groups"]["native_control"]["artifacts"][0]["present"])
            self.assertIsNone(manifest["capture_groups"]["full_lifecycle"]["exit_code"])
            self.assertFalse(manifest["capture_groups"]["full_lifecycle"]["artifacts"][0]["present"])
            self.assertFalse(manifest["capture_groups"]["gdb_trace"]["trace_directory_present"])


if __name__ == "__main__":
    unittest.main()
