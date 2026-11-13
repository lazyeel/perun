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
import re
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


def summarize_syscall_trace(root: Path) -> dict[str, Any]:
    """Publish only syscall names/counts, never arguments, paths or buffers."""
    if not root.is_dir() or root.is_symlink():
        return {"present": False, "files": 0, "calls": {}}
    allowed = {
        "getrandom", "open", "openat", "read", "clock_gettime",
        "gettimeofday", "time", "getpid", "gettid", "close", "mmap",
    }
    counts: dict[str, int] = {}
    files = 0
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\(")
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        files += 1
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                match = pattern.search(line)
                if match and match.group(1) in allowed:
                    name = match.group(1)
                    counts[name] = counts.get(name, 0) + 1
        except OSError:
            continue
    return {"present": files > 0, "files": files, "calls": dict(sorted(counts.items()))}


def byte_diff_summary(left: Path, right: Path) -> dict[str, Any]:
    """Compare binary outputs without exposing byte values."""
    if (not left.is_file() or left.is_symlink()
            or not right.is_file() or right.is_symlink()):
        return {"status": "missing", "equal": None}
    try:
        a, b = left.read_bytes(), right.read_bytes()
    except OSError:
        return {"status": "unreadable", "equal": None}
    overlap = min(len(a), len(b))
    changed = sum(x != y for x, y in zip(a[:overlap], b[:overlap]))
    length_delta = abs(len(a) - len(b))
    return {
        "status": "compared",
        "equal": a == b,
        "left_bytes": len(a),
        "right_bytes": len(b),
        "changed_bytes": changed + length_delta,
        "length_delta": length_delta,
    }


def latest_trace_run(trace_root: Path) -> Path | None:
    if not trace_root.is_dir():
        return None
    candidates = [item for item in trace_root.glob("run-*") if item.is_dir() and not item.is_symlink()]
    return max(candidates, key=lambda item: item.stat().st_mtime_ns) if candidates else None


def summarize_lifecycle_trace(path: Path) -> dict[str, Any]:
    """Expose only phase labels, API names and vdfut opcodes from the private trace."""
    result: dict[str, Any] = {
        "present": path.is_file() and not path.is_symlink(),
        "opcode_sequence": [],
        "api_calls": [],
        "coreadi_init_calls": [],
        "unclassified_lines": 0,
    }
    if not result["present"]:
        return result

    phase_pattern = re.compile(r"phase=(-?\d+)\s+phase_name=([a-z0-9_]+)\s+")
    opcode_pattern = re.compile(r"opcode=(0x[0-9a-fA-F]{1,8})")
    api_pattern = re.compile(r"api=([A-Za-z0-9_]+)")
    cvu_pattern = re.compile(r"coreadi_init=([A-Za-z0-9_]+)")
    for line in path.read_text(encoding="ascii", errors="replace").splitlines():
        # Header and armed marker are metadata, not missing API/opcode events.
        if not line or line == "adi lifecycle trace v1" or "trace=armed" in line:
            continue
        phase_match = phase_pattern.search(line)
        if not phase_match:
            if line and not line.startswith("trace="):
                result["unclassified_lines"] += 1
            continue
        phase_id = int(phase_match.group(1))
        phase_name = phase_match.group(2)
        opcode_match = opcode_pattern.search(line)
        api_match = api_pattern.search(line)
        cvu_match = cvu_pattern.search(line)
        if opcode_match:
            result["opcode_sequence"].append({
                "phase_id": phase_id,
                "phase": phase_name,
                "opcode": opcode_match.group(1).lower(),
            })
        elif api_match:
            result["api_calls"].append({
                "phase_id": phase_id,
                "phase": phase_name,
                "name": api_match.group(1),
            })
        elif cvu_match:
            result["coreadi_init_calls"].append({
                "phase_id": phase_id,
                "phase": phase_name,
                "name": cvu_match.group(1),
            })
        else:
            result["unclassified_lines"] += 1
    return result


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

    # Full lifecycle control is intentionally a different process from the
    # start-only planter trace. Raw token/state bytes remain on the ephemeral
    # runner; this manifest publishes fingerprints and lengths only.
    lifecycle_root = work / "full-adi-capture"
    lifecycle_names = (
        "device_identity.bin",
        "spim.bin",
        "cpim.bin",
        "provisioning-start-rc.bin",
        "session.bin",
        "ptm.bin",
        "tk.bin",
        "provisioning-end-rc.bin",
        "adi-state-before-end.bin",
        "adi-state-before-end.bin.status",
        "adi-state-after-end.bin",
        "adi-state-after-end.bin.status",
        "login-code-after-end.bin",
        "adi-state-before-otp.bin",
        "adi-state-before-otp.bin.status",
        "otp-time-before.bin",
        "otp-request-rc.bin",
        "mid.bin",
        "otp.bin",
        "otp-time-after.bin",
        "adi-state-after-otp.bin",
        "adi-lifecycle.trace",
        "adi-lifecycle-args.jsonl",
        "adi-state-after-otp.bin.status",
    )
    lifecycle_names += tuple(
        f"otp-repeat-{sample:02d}-{suffix}.bin"
        for sample in range(1, 5)
        for suffix in (
            "rc", "time-before", "mid", "otp", "time-after",
            "state-before", "state-after",
        )
    )
    lifecycle_names += ("adi-state-after-otp-probes.bin",)
    full_lifecycle = {
        "process_role": "separate native Bionic full provisioning and OTP control",
        "exit_code": read_text(work / "full-cycle-exit-code.txt"),
        "artifacts": [
            file_fingerprint(name, lifecycle_root / name)
            for name in lifecycle_names
        ],
        "state_directory_after_cycle": tree_fingerprint(
            "adi_state_after_full_lifecycle", work / "adi-data"
        ),
        "trace": {
            "artifact": file_fingerprint(
                "adi_lifecycle_trace", lifecycle_root / "adi-lifecycle.trace"
            ),
            "argument_capture": file_fingerprint(
                "adi_lifecycle_arguments", lifecycle_root / "adi-lifecycle-args.jsonl"
            ),
            **summarize_lifecycle_trace(lifecycle_root / "adi-lifecycle.trace"),
        },
        "syscall_trace": summarize_syscall_trace(lifecycle_root / "syscalls"),
        "pairing_rule": (
            "All listed lifecycle inputs and outputs are captured by one native "
            "Bionic process. The state snapshots bracket ProvisioningEnd and "
            "OTPRequest. Raw captures are sealed as age ciphertext before upload; "
            "this public manifest contains only lengths, hashes and derived "
            "counts. A missing state file is reported by its adjacent .status capture."
        ),
    }

    warm_root = lifecycle_root / "warm-offline"
    warm_replays = {
        "process_role": (
            "two offline ProvisioningStart replays using the exact SPIM and "
            "completed state/identity seed from the full-lifecycle process"
        ),
        "spim_source": "full_lifecycle.spim",
        "state_seed": tree_fingerprint("completed_lifecycle_state_seed", warm_root / "seed"),
        "outputs": [
            file_fingerprint("warm_a_cpim", warm_root / "a.cpim"),
            file_fingerprint("warm_b_cpim", warm_root / "b.cpim"),
            file_fingerprint("warm_a_exit_code", warm_root / "a.rc"),
            file_fingerprint("warm_b_exit_code", warm_root / "b.rc"),
        ],
        "cpim_diff": byte_diff_summary(warm_root / "a.cpim", warm_root / "b.cpim"),
        "syscalls": summarize_syscall_trace(lifecycle_root / "syscalls"),
        "coverage_note": (
            "strace observes syscalls, not direct vDSO fast-path calls; no "
            "clock_gettime syscall does not prove no clock read occurred"
        ),
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
        "manifest_version": 2,
        "workflow": {
            "run_id": workflow_run_id,
            "source_revision": source_sha,
            "native_control_exit_code": native["exit_code"],
            "gdb_trace_exit_code": read_text(work / "run-exit-code.txt"),
            "fam1_index1_trace_exit_code": read_text(work / "index1-exit-code.txt"),
            "full_lifecycle_exit_code": read_text(work / "full-cycle-exit-code.txt"),
        },
        "runtime_fingerprints": runtime,
        "capture_groups": {
            "native_control": native,
            "full_lifecycle": full_lifecycle,
            "warm_state_replays": warm_replays,
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
