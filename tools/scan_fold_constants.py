#!/usr/bin/env python3
"""Scan an Android CoreADI image for Windows Configuration fold SIMD constants.

A full set of 16-byte broadcast-vector matches is strong static signature
evidence, not proof that the corresponding routine is reachable from OTPRequest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any

CONSTANT_RE = re.compile(
    r"pub const (K_[A-Fa-f0-9]+): Lanes = \[(0x[0-9A-Fa-f]+)u32; 4\];"
)


def extract_constants(source: str) -> list[tuple[str, int]]:
    constants = [(name, int(value, 16)) for name, value in CONSTANT_RE.findall(source)]
    if not constants:
        raise ValueError("no Lanes broadcast constants found in fold_zone.rs")
    names = [name for name, _ in constants]
    if len(names) != len(set(names)):
        raise ValueError("duplicate fold constant names")
    return constants


def find_all(data: bytes, needle: bytes, limit: int = 16) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < limit:
        index = data.find(needle, start)
        if index < 0:
            break
        offsets.append(index)
        start = index + 1
    return offsets


def scan_image(image: bytes, constants: list[tuple[str, int]]) -> dict[str, Any]:
    rows = []
    broadcast_found = 0
    scalar_found = 0
    for name, value in constants:
        scalar = struct.pack("<I", value)
        broadcast = scalar * 4
        broadcast_offsets = find_all(image, broadcast)
        scalar_offsets = find_all(image, scalar)
        broadcast_found += bool(broadcast_offsets)
        scalar_found += bool(scalar_offsets)
        rows.append({
            "name": name,
            "value": f"0x{value:08x}",
            "broadcast_offsets": [f"0x{x:x}" for x in broadcast_offsets],
            "broadcast_match_count_capped": len(broadcast_offsets),
            "scalar_offsets": [f"0x{x:x}" for x in scalar_offsets],
            "scalar_match_count_capped": len(scalar_offsets),
        })
    total = len(constants)
    return {
        "schema_version": 1,
        "image_bytes": len(image),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "constant_count": total,
        "broadcast_key_count": broadcast_found,
        "scalar_key_count": scalar_found,
        "complete_broadcast_set": broadcast_found == total,
        "constants": rows,
        "interpretation": (
            "broadcast hits are static signature evidence only; they do not prove "
            "that the fold routine is reachable from OTPRequest"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("crates/perun-adi-core/src/fold_zone.rs"),
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    constants = extract_constants(args.source.read_text(encoding="utf-8"))
    result = scan_image(args.image.read_bytes(), constants)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    print(
        f"fold constants: broadcast {result['broadcast_key_count']}/"
        f"{result['constant_count']}; scalar {result['scalar_key_count']}/"
        f"{result['constant_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
