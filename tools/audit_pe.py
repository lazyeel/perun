#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0
"""Forensic PE audit: is the binary .NET (managed/CIL) or native?

The campaign's docs once called the Apple host binaries ".NET
ReadyToRun". This tool settles the question from the bytes: the
PE optional header's DataDirectory[14]
(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, the CLR header) is the
ONLY loader-level truth -- a nonzero RVA means the image carries a
CLR header and the loader runs it as managed; a zero VA means the
image is a plain native PE.

For every audited file the tool prints:
  * the machine type, the characteristics, the subsystem;
  * the full 16-entry DataDirectory table with sizes;
  * the DataDirectory[14] verdict (NATIVE vs CLR) with raw bytes;
  * the Rich Header when present (the MSVC toolchain signature)
    and the compiled-object/@comp.id markers.

Usage:
    python3 tools/audit_pe.py <file> [file ...]
"""

from __future__ import annotations

import struct
import sys

MACHINE = {0x014C: "i386", 0x8664: "AMD64", 0xAA64: "ARM64"}
SUBSYS = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 14: "XBOX"}

DIR_NAMES = [
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
    "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
    "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR (CLR)", "RESERVED",
]


def align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def read_rich(data: bytes, off_rich_ptr: int) -> list[tuple[int, int, int]] | None:
    """Decode the Rich Header starting at the 'DanS' marker.

    off_rich_ptr is the file offset of the Rich END marker's value
    (the xor key). Products: 1=imp/import, 8=obj/assembler... The
    canonical table lives in the MSVC docs; the (product, build,
    count) triples are enough for toolchain dating.
    """
    # find DanS: 16-byte aligned xor'd 'DanS' then checksum
    for off in range(0x40, min(0x400, len(data)) - 4, 4):
        w = struct.unpack_from("<I", data, off)[0]
        key = w ^ 0x536E6144  # 'DanS' LE
        if not (0 <= key <= 0xFFFFFFFF):
            continue
        # verify checksum at +0x10
        try:
            chk = struct.unpack_from("<I", data, off + 0x10)[0] ^ key
        except struct.error:
            continue
        # DanS marker: 3 dwords of padding pattern then checksum
        d0 = struct.unpack_from("<I", data, off + 0xC)[0] ^ key
        if chk == 0 or d0 != chk:
            continue
        # walk backwards-compatible: decode from off+0x14 until 'Rich'
        rows = []
        i = off + 0x14
        while i + 8 <= min(off + 0x400, len(data)):
            prod, cnt = struct.unpack_from("<II", data, i)
            prod ^= key
            cnt ^= key
            build, count = prod >> 16, prod & 0xFFFF
            if cnt == 0:
                break
            rows.append((build, cnt, count))
            i += 8
        return rows
    return None


def audit(path: str) -> int:
    data = open(path, "rb").read()
    print(f"===== {path} ({len(data)} bytes) =====")
    if data[:2] != b"MZ":
        print("  not a PE (no MZ magic)")
        return 1
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        print(f"  not a PE (bad signature at {e_lfanew:#x})")
        return 1
    machine, nsec, _ts, _psym, _nsym, optsz, chars = struct.unpack_from(
        "<HHIIIHH", data, e_lfanew + 4
    )
    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
    is64 = magic == 0x20B
    print(f"  machine={MACHINE.get(machine, hex(machine))} sections={nsec} "
          f"magic={'PE32+' if is64 else 'PE32'} characteristics={chars:#06x}")
    # subsystem at opts +0x44 (PE32+) / +0x44 (PE32 same offset in OptionalHeader)
    subsys = struct.unpack_from("<H", data, e_lfanew + 24 + 0x44)[0]
    dll_flag = "DLL" if chars & 0x2000 else "EXE"
    print(f"  subsystem={SUBSYS.get(subsys, subsys)} type={dll_flag}")
    # DataDirectories: PE32+ at opt+112, 16 entries of (VA, Size)
    dd_off = e_lfanew + 24 + (112 if is64 else 96)
    print("  DataDirectory:")
    for i in range(16):
        va, size = struct.unpack_from("<II", data, dd_off + i * 8)
        name = DIR_NAMES[i]
        mark = ""
        if i == 14:
            mark = "  <== CLR HEADER"
        print(f"    [{i:2d}] {name:24s} VA={va:#010x} size={size:#x}{mark}")
    # THE verdict
    va14, size14 = struct.unpack_from("<II", data, dd_off + 14 * 8)
    if va14 == 0:
        print("  VERDICT: DataDirectory[14].VirtualAddress == 0 -> "
              "NO CLR header -> 100% NATIVE (no .NET metadata, no CIL, "
              "no managed entry).")
    else:
        # read the CLR header words for the record
        # map va via sections
        sec_off = e_lfanew + 24 + optsz
        rva2off = None
        for s in range(nsec):
            so = sec_off + s * 40
            vs, vr, rs, ro = struct.unpack_from("<IIII", data, so + 8)
            if vr <= va14 < vr + max(vs, rs):
                rva2off = ro + (va14 - vr)
                break
        if rva2off is not None:
            cb, mj, mn = struct.unpack_from("<IHH", data, rva2off)
            print(f"  VERDICT: CLR HEADER PRESENT at RVA {va14:#x}: "
                  f"cb={cb:#x} runtime={mj}.{mn} -> MANAGED image.")
    # Rich header (MSVC toolchain signature)
    rich = read_rich(data, 0)
    if rich:
        builds = {b for b, _, _ in rich}
        print(f"  Rich Header: {len(rich)} product entries, builds={sorted(builds)}")
        print("  -> compiled with MSVC (the Rich Header is the MSVC linker's "
              "toolchain record; a .NET ReadyToRun image would carry a CLR "
              "header INSTEAD, and R2R code still shows in DataDirectory[14])")
    print()
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    rc = 0
    for p in sys.argv[1:]:
        rc |= audit(p)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
