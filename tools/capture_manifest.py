#!/usr/bin/env python3
"""Create a privacy-preserving provenance manifest for an Anisette trace run.

Only sizes and SHA-256 fingerprints leave the ephemeral runner. No artifact
bytes, absolute paths, UUIDs, environment values, or state filenames are emitted.
The manifest deliberately keeps distinct processes in separate capture groups.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any


TRACE_ARTIFACTS = (
    "source.at_dd511.bin",
    "source.at_postmalloc.bin",
    "source.final.bin",
    "planter.at_writer_candidate.bin",
    "planter.at_base_load.bin",
    "planter.slot_anchored.bin",
    "planter.final.bin",
)


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def file_fingerprint(label: str, path: Path) -> dict[str, Any]:
    """Return an allow-listed logical label, size and content hash only."""
    if not path.is_file() or path.is_symlink():
        return {"label": label, "present": False}
    digest, size = sha256_file(path)
    return {"label": label, "present": True, "bytes": size, "sha256": digest}


def tree_fingerprint(label: str, root: Path) -> dict[str, Any]:
    """Hash a directory tree without disclosing names or file-level metadata."""
    if not root.is_dir() or root.is_symlink():
        return {"label": label, "present": False}

    digest = hashlib.sha256()
    count = 0
    total_bytes = 0
    symlinks_skipped = 0
    files = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())

    for path in files:
        if path.is_symlink():
            symlinks_skipped += 1
            continue
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        file_hash, size = sha256_file(path)
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(file_hash))
        count += 1
        total_bytes += size

    return {
        "label": label,
        "present": True,
        "file_count": count,
        "bytes": total_bytes,
        "symlinks_skipped": symlinks_skipped,
        "tree_sha256": digest.hexdigest(),
    }


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None


def latest_trace_run(trace_root: Path) -> Path | None:
    if not trace_root.is_dir():
        return None
    candidates = [item for item in trace_root.glob("run-*") if item.is_dir() and not item.is_symlink()]
    return max(candidates, key=lambda item: item.stat().st_mtime_ns) if candidates else None


def build_manifest(
    work: Path,
    source_sha: str,
    workflow_run_id: str,
    system_image: Path | None = None,
) -> dict[str, Any]:
    probe = work / "fixed-input-probe"
    seed = probe / "seed"
    trace_run = latest_trace_run(work / "traces")

    native = {
        "process_role": "initial non-GDB live provisioning control",
        "artifacts": [
            file_fingerprint("spim", work / "fixed-input.spim"),
            file_fingerprint("cpim", work / "native-live.cpim"),
            file_fingerprint("persistent_device_identity", work / "adi_identifier"),
            tree_fingerprint("adi_state_after_native_control", work / "adi-data"),
        ],
        "pairing_rule": (
            "SPIM and CPIM are saved by the same native-control process. "
            "The identity and state fingerprints describe persistent local "
            "context, not a cryptographic binding to every later tape."
        ),
        "exit_code": read_text(work / "native-exit-code.txt"),
    }

    replay_names = ("baseline_a", "baseline_b", "frozen_a", "frozen_b")
    replay_artifacts = [
        file_fingerprint(f"{name}_cpim", probe / f"{name}.cpim")
        for name in replay_names
    ]
    replay_artifacts.extend(
        file_fingerprint(f"{name}_exit_code", probe / f"{name}.rc")
        for name in replay_names
    )
    replay = {
        "process_role": "four separate offline replay processes",
        "spim_source": "native_control.spim",
        "state_seed": [
            file_fingerprint("persistent_device_identity_seed", seed / "adi_identifier"),
            tree_fingerprint("adi_state_seed", seed / "adi-data"),
        ],
        "outputs": replay_artifacts,
        "summary_present": (probe / "summary.env").is_file(),
        "cpim_segment_diff": read_json(probe / "cpim-diff.json"),
        "pairing_rule": (
            "Each replay is a separate process using the saved native-control "
            "SPIM. The workflow restores the captured identity/state seed "
            "before each replay. Replay CPIM outputs are not the GDB trace's CPIM."
        ),
    }

    trace_metadata: dict[str, Any] = {}
    trace_files: list[dict[str, Any]] = []
    if trace_run is not None:
        try:
            raw = json.loads((trace_run / "run.json").read_text(encoding="utf-8"))
            trace_metadata = {
                "trace_run_id": raw.get("run_id"),
                "tracer_version": raw.get("script_version"),
                "entry_rva": raw.get("entry_rva"),
                "transform_opcode": raw.get("transform_opcode"),
            }
        except (OSError, ValueError, TypeError):
            trace_metadata = {"run_manifest_present": False}
        for name in TRACE_ARTIFACTS:
            trace_files.append(file_fingerprint(name, trace_run / name))

    # Separate terminal replay: same saved SPIM/state seed, distinct inferior.
    index1_run = latest_trace_run(work / "traces-index1")
    index1_probe: dict[str, Any] = {
        "process_role": "separate offline-SPIM GDB replay; terminal reverse probe",
        "trace_directory_present": index1_run is not None,
        "target_hit": read_text(work / "index1-target-hit.txt") or "2",
        "exit_code": read_text(work / "index1-exit-code.txt"),
        "artifacts": [],
    }
    if index1_run is not None:
        try:
            raw = json.loads((index1_run / "run.json").read_text(encoding="utf-8"))
            index1_probe["metadata"] = {
                "trace_run_id": raw.get("run_id"),
                "tracer_version": raw.get("script_version"),
            }
        except (OSError, ValueError, TypeError):
            index1_probe["metadata"] = {"run_manifest_present": False}
        candidate_path = index1_run / "fam1_candidate_events.csv"
        index1_probe["artifacts"].append(
            file_fingerprint("fam1_candidate_events", candidate_path)
        )
        candidate_events: list[dict[str, str]] = []
        try:
            import csv
            with candidate_path.open(newline="", encoding="utf-8") as stream:
                candidate_events = list(csv.DictReader(stream))
        except (OSError, UnicodeError, ValueError):
            candidate_events = []
        target_rows = [
            row for row in candidate_events
            if row.get("active_opcode", "").lower() == "0x716bd86c"
            and row.get("resolution") == "source-anchored-fam1-window"
            and row.get("fam1_index", "na") != "na"
        ]
        observed_indices: list[int] = []
        for row in target_rows:
            try:
                observed_indices.append(int(row["fam1_index"], 16))
            except (KeyError, ValueError):
                continue
        index1_probe["candidate_writer"] = {
            "matching_store_events": len(target_rows),
            "observed_indices": observed_indices[:8],
            "distinct_indices": len(set(observed_indices)),
        }

        # Only static instruction metadata and aggregate execution counts escape.
        reverse_fields: dict[str, str] = {}
        try:
            for line in (index1_run / "trace.log").read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                if "FAM1 PRODUCER REVERSE RESULT:" in line:
                    reverse_fields = dict(
                        token.split("=", 1) for token in line.split() if "=" in token
                    )
        except OSError:
            pass
        producer_rows = []
        for prefix in ("producer", "upstream", "upstream2", "upstream3", "upstream4"):
            if reverse_fields.get(f"{prefix}_status") == "found":
                producer_rows.append({
                    "label": prefix,
                    "rva": reverse_fields.get(f"{prefix}_rva", "n/a"),
                    "mnemonic": reverse_fields.get(f"{prefix}_mnemonic", "unknown"),
                    "forward_check": reverse_fields.get(f"{prefix}_forward_check", "no"),
                })
        sil_producer = None
        if reverse_fields.get("sil_producer_status") == "found":
            sil_producer = {
                "rva": reverse_fields.get("sil_producer_rva", "n/a"),
                "mnemonic": reverse_fields.get("sil_producer_mnemonic", "unknown"),
                "forward_check": reverse_fields.get("sil_producer_forward_check", "no"),
            }
        index1_probe["reverse_lineage"] = {
            "status": reverse_fields.get("lineage_status", "not-observed"),
            "reverse_steps": reverse_fields.get("reverse_steps", "n/a"),
            "producers": producer_rows,
            "sil_producer": sil_producer,
        }

    gdb_trace = {
        "process_role": "separate GDB live provisioning process",
        "metadata": trace_metadata,
        "artifacts": trace_files,
        "pairing_rule": (
            "The workflow unsets ADI_OFFLINE_SPIM, ADI_SPIM_OUT and ADI_CPIM_OUT "
            "before this run. It performs a fresh network provisioning request. "
            "Its source/planter snapshots must not be paired with the initial "
            "native-control SPIM/CPIM or with offline replay outputs."
        ),
        "trace_directory_present": trace_run is not None,
    }

    runtime = [
        tree_fingerprint("apple_library_directory", work / "libs"),
        tree_fingerprint("bionic_sysroot", work / "sysroot"),
    ]
    if system_image is not None:
        runtime.append(file_fingerprint("android_system_image", system_image))

    return {
        "manifest_version": 1,
        "workflow": {
            "run_id": workflow_run_id,
            "source_revision": source_sha,
            "native_control_exit_code": native["exit_code"],
            "gdb_trace_exit_code": read_text(work / "run-exit-code.txt"),
            "fam1_index1_trace_exit_code": read_text(work / "index1-exit-code.txt"),
        },
        "runtime_fingerprints": runtime,
        "capture_groups": {
            "native_control": native,
            "fixed_input_replays": replay,
            "gdb_trace": gdb_trace,
            "fam1_index1_probe": index1_probe,
        },
        "session_separation": [
            "A matching byte hash identifies identical bytes, not a common provisioning session.",
            "Only native_control.spim and native_control.cpim are asserted to be outputs of one process.",
            "fixed_input_replays are separate offline processes seeded from native_control.spim.",
            "gdb_trace is a separate live provisioning process; its planter/source observations are not paired to native_control.spim/cpim.",
            "The manifest does not prove every tape or auxiliary snapshot belongs to one session.",
        ],
        "privacy": {
            "raw_artifacts_included": False,
            "absolute_paths_included": False,
            "device_identity_included": False,
            "state_filenames_included": False,
            "hashes_are_integrity_fingerprints_not_authenticators": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", default=os.environ.get("GITHUB_SHA", "unknown"))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "unknown"))
    parser.add_argument("--system-image", type=Path, default=(
        Path(os.environ["SYS_IMG"]) if os.environ.get("SYS_IMG") else None
    ))
    args = parser.parse_args()

    manifest = build_manifest(args.work, args.source_sha, args.run_id, args.system_image)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(args.output)
    print(f"capture manifest written: {args.output.name}")
    print("raw bytes and absolute paths were not included")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
