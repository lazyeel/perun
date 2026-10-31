#!/usr/bin/env python3
"""Analyze a single run directory emitted by tools/planter_trace_gdb.py."""
from __future__ import annotations

import argparse
import ast
import csv
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

DEFAULT_TABLES = {
    "fam1": 0x0D60, "fam2": 0x1A00, "fam3": 0x2460, "fam4": 0x1390,
}
DEFAULT_UNKNOWN_RANGES = [
    ("unknown_e60_1390", 0x0E60, 0x1390 - 0x0E60),
    ("unknown_1490_1a00", 0x1490, 0x1A00 - 0x1490),
    ("unknown_1b00_1f30", 0x1B00, 0x1F30 - 0x1B00),
    ("unknown_1f30_2460", 0x1F30, 0x2460 - 0x1F30),
    ("unknown_2560_2700", 0x2560, 0x2700 - 0x2560),
]
PLANTER_SIZE = 0x2700


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def cycle_lengths(table: bytes) -> Counter[int] | None:
    if len(table) != 256 or len(set(table)) != 256:
        return None
    seen = bytearray(256)
    cycles: Counter[int] = Counter()
    for start in range(256):
        if seen[start]:
            continue
        cur, length = start, 0
        while not seen[cur]:
            seen[cur] = 1
            length += 1
            cur = table[cur]
        cycles[length] += 1
    return cycles


def describe_bytes(name: str, data: bytes) -> None:
    unique = len(set(data))
    print(f"{name}: size={len(data):#x} unique={unique}/{min(256, len(data))} "
          f"zeros={data.count(0)} entropy={entropy(data):.4f} bits/byte")
    print(f"  first32={data[:32].hex()}")
    if len(data) == 256 and unique == 256:
        cycles = cycle_lengths(data) or Counter()
        print(f"  permutation: cycles={sum(cycles.values())}, fixed_points={cycles.get(1, 0)}, "
              f"lengths={dict(sorted(cycles.items()))}")


def scan_bijections(data: bytes, step: int = 1) -> list[tuple[int, Counter[int]]]:
    found = []
    for offset in range(0, max(0, len(data) - 255), step):
        window = data[offset:offset + 256]
        if len(window) == 256 and len(set(window)) == 256:
            found.append((offset, cycle_lengths(window) or Counter()))
    return found


def read_manifest(root: Path) -> dict:
    path = root / "run.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"WARNING: invalid run.json: {exc}")
        return {}


def resolve_tables(manifest: dict) -> dict[str, int]:
    raw = manifest.get("tables")
    if not raw:
        return dict(DEFAULT_TABLES)
    try:
        return {str(name): int(offset) for name, offset in raw}
    except (TypeError, ValueError):
        return dict(DEFAULT_TABLES)


def resolve_unknown_ranges(manifest: dict) -> list[tuple[str, int, int]]:
    raw = manifest.get("unknown_ranges")
    if not raw:
        return list(DEFAULT_UNKNOWN_RANGES)
    try:
        return [(str(name), int(offset), int(size)) for name, offset, size in raw]
    except (TypeError, ValueError):
        return list(DEFAULT_UNKNOWN_RANGES)


def validate_partition(tables: dict[str, int] | None = None,
                       unknown: list[tuple[str, int, int]] | None = None) -> None:
    tables = tables if tables is not None else DEFAULT_TABLES
    unknown = unknown if unknown is not None else DEFAULT_UNKNOWN_RANGES
    regions = [("head", 0, 0x0D60)]
    regions.extend((name, off, off + 256) for name, off in tables.items())
    regions.extend((name, off, off + size) for name, off, size in unknown)
    regions.sort(key=lambda x: x[1])
    cursor = 0
    for name, start, end in regions:
        if start != cursor:
            kind = "overlap" if start < cursor else "gap"
            print(f"WARNING: partition {kind} before {name}: cursor={cursor:#x} start={start:#x}")
        if end <= start:
            print(f"WARNING: invalid range for {name}: {start:#x}..{end:#x}")
        cursor = max(cursor, end)
    if cursor == PLANTER_SIZE:
        print("planter byte partition: contiguous, non-overlapping, full 0x2700 coverage")
    else:
        print(f"WARNING: partition ends at {cursor:#x}, expected {PLANTER_SIZE:#x}")


def load_planter_snapshot(root: Path) -> tuple[bytes | None, str | None]:
    """Prefer a four-window-validated dump; otherwise use the active-slot capture."""
    final_path = root / "planter.final.bin"
    if final_path.is_file():
        return final_path.read_bytes(), "final"
    anchored_path = root / "planter.slot_anchored.bin"
    if anchored_path.is_file():
        return anchored_path.read_bytes(), "slot-anchored"
    return None, None


def extract_planter_base(root: Path) -> int | None:
    log = root / "trace.log"
    if not log.is_file():
        return None
    pattern = re.compile(
        r"PLANTER WRITER CANDIDATE:.*?base_operand=(0x[0-9a-fA-F]+).*?source_plus_32_match=True"
    )
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.search(line)
        if match:
            return int(match.group(1), 16)
    return None


def parse_writer_events(root: Path, planter_base: int | None) -> None:
    path = root / "writer_events.csv"
    if not path.is_file():
        print("writer_events.csv: absent")
        return
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    with path.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            groups[row.get("name", "unknown")].append(row)
    if not groups:
        print("writer_events.csv: no direct stores")
        return
    print("direct writer instruction events:")
    for name, rows in sorted(groups.items()):
        try:
            indices = [int(row["index"], 16) for row in rows]
            addresses = [int(row["ea"], 16) for row in rows]
            values = [int(row["value"], 16) for row in rows]
        except (KeyError, ValueError):
            print(f"  {name}: malformed rows={len(rows)}")
            continue
        unique_indices = len(set(indices))
        holes = max(0, max(indices) - min(indices) + 1 - unique_indices)
        msg = (f"  {name}: hits={len(rows)} unique_indices={unique_indices} "
               f"index_range={min(indices):#x}..{max(indices):#x} holes={holes} "
               f"unique_values={len(set(values))}/256")
        if planter_base is not None and name not in ("staging_write_a", "staging_write_b"):
            relative = [addr - planter_base for addr in addresses]
            msg += (f" effective_range={min(relative):#x}..{max(relative):#x} "
                    f"within_planter={all(0 <= off < PLANTER_SIZE for off in relative)}")
        print(msg)


def parse_change_coverage(root: Path) -> None:
    log = root / "trace.log"
    if not log.is_file():
        return
    pattern = re.compile(r"CHANGE (\w+) hit=\d+ pc_after=.*?changed=(\d+) \[(.*?)\]")
    item = re.compile(r"(0x[0-9a-fA-F]+):[0-9a-fA-F]{2}>[0-9a-fA-F]{2}")
    counts: Counter[str] = Counter()
    changed: Counter[str] = Counter()
    offsets: dict[str, set[int]] = defaultdict(set)
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.search(line)
        if not match:
            continue
        name, n, preview = match.groups()
        counts[name] += 1
        changed[name] += int(n)
        offsets[name].update(int(m.group(1), 16) for m in item.finditer(preview))
    if counts:
        print("software-watchpoint change coverage (first 48 offsets per hit):")
        for name in sorted(counts):
            print(f"  {name}: events={counts[name]} changed_bytes={changed[name]} "
                  f"distinct_preview_offsets={len(offsets[name])}")


def parse_writer_stats(root: Path) -> None:
    path = root / "writer_stats.txt"
    if not path.is_file():
        print("writer_stats.txt: absent (no final mixer snapshot)")
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ": " not in line:
            continue
        name, raw = line.split(": ", 1)
        try:
            stats = ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            stats = raw
        print(f"writer_stats {name}: {stats}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace_dir", type=Path)
    args = parser.parse_args()
    root: Path = args.trace_dir
    if not root.is_dir():
        parser.error(f"trace directory does not exist: {root}")
    manifest = read_manifest(root)
    tables = resolve_tables(manifest)
    unknown = resolve_unknown_ranges(manifest)
    validate_partition(tables, unknown)

    planter, planter_kind = load_planter_snapshot(root)
    source = (root / "source.final.bin").read_bytes() if (root / "source.final.bin").is_file() else None
    if manifest:
        print(f"run={manifest.get('run_id')} version={manifest.get('script_version')} pid={manifest.get('pid')}")
    else:
        print("run.json absent: using default layout")

    if planter is None:
        print("planter.final.bin and planter.slot_anchored.bin absent: no object snapshot captured")
    else:
        filename = "planter.final.bin" if planter_kind == "final" else "planter.slot_anchored.bin"
        print(f"{filename} size={len(planter):#x} kind={planter_kind}")
        if planter_kind == "slot-anchored":
            print("  provenance: captured at active [RBP-0x30] slot when it matched source+0x20 and writer base")
            print("  note: this does not assert the legacy four-window permutation signature")
        if len(planter) >= PLANTER_SIZE:
            full_object_bijections = scan_bijections(planter)
            print(f"full-object byte-aligned 256-byte bijections: {len(full_object_bijections)}")
            for offset, cycles in full_object_bijections:
                print(f"  object_offset={offset:#06x} cycles={dict(sorted(cycles.items()))}")
            for name, off in tables.items():
                describe_bytes(name, planter[off:off + 256])
            fifth = planter[0x1F30:0x1F30 + 256]
            describe_bytes("fifth_1f30_candidate", fifth)
            for name, off, size in unknown:
                region = planter[off:off + size]
                describe_bytes(name, region)
                candidates = scan_bijections(region)
                print(f"  256-byte bijection candidates in {name}: {len(candidates)}")
                for local, cycles in candidates[:12]:
                    print(f"    absolute_offset={off + local:#x} cycles={dict(cycles)}")
        else:
            print("incomplete planter dump; skip fixed offsets")

    if source is not None:
        describe_bytes("source.final", source)
    if planter is not None and len(planter) >= PLANTER_SIZE and source is not None and len(source) >= 256:
        mismatches = sum(x != y for x, y in zip(source[32:256], planter[:224]))
        print(f"source[32:256] == planter[0:224]: {mismatches == 0} mismatches={mismatches}/224")

    if (root / "staging.copy_entry.256.bin").is_file():
        copy = (root / "staging.copy_entry.256.bin").read_bytes()
        if planter is not None and len(planter) >= 0x0E60:
            compare = sum(x == y for x, y in zip(copy[:256], planter[0x0D60:0x0E60]))
            print(f"staging.copy_entry -> fam1: exact={compare}/256")
    if (root / "staging.final.span_256.bin").is_file() and planter is not None and len(planter) >= 0x0E60:
        final = (root / "staging.final.span_256.bin").read_bytes()
        exact = sum(x == y for x, y in zip(final[:256], planter[0x0D60:0x0E60]))
        xor = sum((x ^ 0x3B) == y for x, y in zip(final[:256], planter[0x0D60:0x0E60]))
        print(f"staging.final -> fam1: exact={exact}/256 XOR-3B={xor}/256")

    parse_writer_events(root, extract_planter_base(root))
    parse_change_coverage(root)
    parse_writer_stats(root)
    if planter_kind == "final":
        print("STATUS: same-session four-window-validated planter snapshot captured")
    elif planter_kind == "slot-anchored":
        print("STATUS: same-session active-slot-anchored object captured; legacy four-window signature not satisfied")
    else:
        print("STATUS: partial capture; no planter object snapshot captured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
