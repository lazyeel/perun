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

            seed = work / "fixed-input-probe" / "seed"
            (seed / "adi-data").mkdir(parents=True)
            (seed / "adi-data" / "state.bin").write_bytes(b"state secret")
            (seed / "adi_identifier").write_bytes(b"I" * 16)
            probe = work / "fixed-input-probe"
            for name in ("baseline_a", "baseline_b", "frozen_a", "frozen_b"):
                (probe / f"{name}.cpim").write_bytes(name.encode())
                (probe / f"{name}.rc").write_text("0")

            trace = work / "traces" / "run-1-2"
            trace.mkdir(parents=True)
            (trace / "run.json").write_text(json.dumps({
                "run_id": "run-1-2", "script_version": "v33",
                "entry_rva": 123, "transform_opcode": 456,
            }))
            (trace / "planter.final.bin").write_bytes(b"planter")
            (trace / "source.at_dd511.bin").write_bytes(b"source")
            (work / "run-exit-code.txt").write_text("0")

            manifest = build_manifest(work, "abc123", "42")
            groups = manifest["capture_groups"]
            self.assertTrue(groups["native_control"]["artifacts"][0]["present"])
            self.assertEqual(groups["fixed_input_replays"]["spim_source"], "native_control.spim")
            self.assertEqual(groups["gdb_trace"]["metadata"]["tracer_version"], "v33")
            self.assertIn("separate GDB live provisioning process", groups["gdb_trace"]["process_role"])
            self.assertIn("must not be paired", groups["gdb_trace"]["pairing_rule"])
            serialized = json.dumps(manifest)
            self.assertNotIn("state secret", serialized)
            self.assertNotIn(str(work), serialized)
            self.assertFalse(manifest["privacy"]["raw_artifacts_included"])

    def test_missing_inputs_are_explicit_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = build_manifest(Path(tmp), "sha", "run")
            self.assertFalse(manifest["capture_groups"]["native_control"]["artifacts"][0]["present"])
            self.assertFalse(manifest["capture_groups"]["gdb_trace"]["trace_directory_present"])


if __name__ == "__main__":
    unittest.main()
