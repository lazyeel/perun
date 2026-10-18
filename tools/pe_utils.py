#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0
"""PE utilities for the white-box reconstruction: RVA -> file offset,
section table, and the planter table extraction.

The Configuration last mile reads its mix material out of the DLL's
own image: a pointer row from the table at .rva 0x97eca0 (r11) is
combined with a session-dependent byte index, and the byte at
base + index + constant lands in the MBA mixers. To reproduce those
reads OFFLINE the table rows and the image bytes must be addressable
by RVA -- this module provides exactly that.
"""

from __future__ import annotations

import struct
import sys

IMAGE_BASE = 0x7C800000
PLANTER_RVA = 0x97ECA0
PLANTER_ROWS = 563


def rva_to_offset(data: bytes, rva: int) -> int:
    """Map an RVA into the file via the PE section table."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    sec_off = pe + 24 + optsz
    for i in range(nsec):
        s = sec_off + i * 40
        virt_size, virt_rva, raw_size, raw_off = struct.unpack_from("<IIII", data, s + 8)
        if virt_rva <= rva < virt_rva + max(virt_size, raw_size):
            delta = rva - virt_rva
            if delta < raw_size:
                return raw_off + delta
            raise ValueError(f"rva {rva:#x} falls in virtual-only tail of section")
    raise ValueError(f"rva {rva:#x} outside every section")


def read_u32(data: bytes, rva: int) -> int:
    return struct.unpack_from("<I", data, rva_to_offset(data, rva))[0]


def read_u64(data: bytes, rva: int) -> int:
    return struct.unpack_from("<Q", data, rva_to_offset(data, rva))[0]


def read_bytes(data: bytes, rva: int, n: int) -> bytes:
    return data[rva_to_offset(data, rva) : rva_to_offset(data, rva) + n]


def load_image(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: pe_utils.py <CoreADI64.dll> [rva ...]", file=sys.stderr)
        return 2
    data = load_image(sys.argv[1])
    for a in sys.argv[2:]:
        rva = int(a, 0)
        off = rva_to_offset(data, rva)
        print(f"rva {rva:#x} -> file offset {off:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
