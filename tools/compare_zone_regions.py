#!/usr/bin/env python3
"""Compare a live module lookup table against the repository's baked zones.

Only hashes, exact-match offsets and byte-equality counts are returned.
Raw runtime bytes are never printed.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def _find_all(haystack: bytes, needle: bytes) -> list[int]:
    offsets = []
    start = 0
    while True:
        offset = haystack.find(needle, start)
        if offset < 0:
            return offsets
        offsets.append(offset)
        start = offset + 1


def compare_zone_regions(runtime_region: bytes, zone_dir: str | Path) -> dict:
    if len(runtime_region) < 256:
        raise ValueError("runtime region must contain at least 256 bytes")
    table = runtime_region[:256]
    results = []
    for path in sorted(Path(zone_dir).glob("*_zone.bin")):
        zone = path.read_bytes()
        exact_offsets = _find_all(zone, table)
        best = (-1, -1)
        if len(zone) >= 256:
            for offset in range(len(zone) - 255):
                score = sum(a == b for a, b in zip(table, zone[offset:offset + 256]))
                if score > best[0]:
                    best = (score, offset)
        results.append({
            "file": path.name,
            "size": len(zone),
            "whole_region_exact": len(runtime_region) == len(zone) and runtime_region == zone,
            "table_exact_offsets": exact_offsets,
            "best_equal_bytes": best[0],
            "best_offset": best[1],
            "sha256": hashlib.sha256(zone).hexdigest(),
        })
    return {
        "runtime_size": len(runtime_region),
        "runtime_sha256": hashlib.sha256(runtime_region).hexdigest(),
        "table_sha256": hashlib.sha256(table).hexdigest(),
        "table_size": len(table),
        "zones": results,
    }
