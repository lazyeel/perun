#!/usr/bin/env python3
"""Privacy-preserving byte-range comparison for repeated 276-byte CPIM captures.

Only hashes, byte counts, and differing offsets are emitted. No CPIM byte values
or raw artifacts are printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

CPIM_LEN = 0x114
SEGMENTS = (
    ("version", 0x00, 0x04),
    ("session16", 0x04, 0x14),
    ("body_a_length", 0x14, 0x18),
    ("body_a", 0x18, 0xB8),
    ("digest", 0xB8, 0xD8),
    ("body_b_length", 0xD8, 0xDC),
    ("body_b_version", 0xDC, 0xE0),
    ("body_b", 0xE0, 0x114),
)
CAPTURE_NAMES = ("baseline_a", "baseline_b", "frozen_a", "frozen_b")
PAIR_NAMES = (
    ("baseline_repeat", "baseline_a", "baseline_b"),
    ("frozen_repeat", "frozen_a", "frozen_b"),
    ("baseline_a_vs_frozen_a", "baseline_a", "frozen_a"),
    ("baseline_b_vs_frozen_b", "baseline_b", "frozen_b"),
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _runs(offsets: list[int]) -> list[list[int]]:
    if not offsets:
        return []
    result: list[list[int]] = []
    start = previous = offsets[0]
    for value in offsets[1:]:
        if value != previous + 1:
            result.append([start, previous + 1])
            start = value
        previous = value
    result.append([start, previous + 1])
    return result


def load_capture(path: str | Path) -> tuple[bytes | None, dict[str, Any]]:
    source = Path(path)
    if not source.is_file():
        return None, {"present": False, "path_included": False}
    data = source.read_bytes()
    metadata: dict[str, Any] = {
        "present": True,
        "length": len(data),
        "sha256": _sha256(data),
        "valid_cpim_length": len(data) == CPIM_LEN,
    }
    return data, metadata


def compare_pair(left: bytes | None, right: bytes | None) -> dict[str, Any]:
    if left is None or right is None:
        return {"status": "missing-capture", "equal": None, "segments": []}
    if len(left) != CPIM_LEN or len(right) != CPIM_LEN:
        return {
            "status": "invalid-length",
            "equal": None,
            "left_length": len(left),
            "right_length": len(right),
            "segments": [],
        }
    segments = []
    changed_total = 0
    for name, start, end in SEGMENTS:
        offsets = [i for i in range(start, end) if left[i] != right[i]]
        changed_total += len(offsets)
        segments.append({
            "name": name,
            "range": [start, end],
            "length": end - start,
            "changed_bytes": len(offsets),
            "changed_runs": _runs(offsets)[:8],
            "first_changed_offsets": offsets[:16],
        })
    return {
        "status": "compared",
        "equal": changed_total == 0,
        "changed_bytes": changed_total,
        "segments": segments,
    }


def build_report(paths: dict[str, str | Path]) -> dict[str, Any]:
    captures: dict[str, bytes | None] = {}
    metadata: dict[str, Any] = {}
    for name in CAPTURE_NAMES:
        captures[name], metadata[name] = load_capture(paths[name])
    pairs = {}
    for pair_name, left_name, right_name in PAIR_NAMES:
        result = compare_pair(captures[left_name], captures[right_name])
        result["left"] = left_name
        result["right"] = right_name
        pairs[pair_name] = result
    return {
        "schema_version": 1,
        "expected_cpim_length": CPIM_LEN,
        "captures": metadata,
        "pairs": pairs,
        "privacy": {
            "raw_cpim_bytes_included": False,
            "absolute_paths_included": False,
            "byte_values_included": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in CAPTURE_NAMES:
        parser.add_argument(f"--{name.replace('_', '-')}", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = build_report({name: getattr(args, name) for name in CAPTURE_NAMES})
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
