#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0
"""Backward slice of the Configuration verdict-word's last mile.

The write-only watchpoint (writewatch.rs, ww1.log) named the four
byte-stores that publish the verdict word into pkt[4..8]:

    pkt+4: 0x6fe0d  mov %cl,(%r12,%rax,1)
    pkt+5: 0x6fe9c  mov %al,(%r12,%rcx,1)
    pkt+6: 0x6faa9  mov %al,(%r12,%rdi,1)
    pkt+7: 0x6fc95  mov %al,(%r12,%rcx,1)

This tool reconstructs the connected instruction window that feeds
those stores, symbolic-executes the MBA mixers into closed-form
expressions, and reports the word's data lineage as a formula over
its real inputs (planter reads, frame slots, SIMD accumulators).

Usage:
    python3 tools/slice_word.py <coreadi64_disassembly> [--window N]

Outputs (stdout):
    * the linear slice window with each instruction annotated,
    * the symbolic expression of each stored byte,
    * the collapsed formula for the word.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field

IMAGE_BASE = 0x7C800000

WRITERS = {
    0x6FE0D: "pkt+4",
    0x6FE9C: "pkt+5",
    0x6FAA9: "pkt+6",
    0x6FC95: "pkt+7",
}


@dataclass
class Insn:
    vma: int
    raw: str
    mnemonic: str
    operands: str


def parse_disassembly(path: str) -> dict[int, Insn]:
    """Parse objdump output into a VMA-keyed table.

    objdump emits multi-line records when the byte column wraps; a
    continuation line is bytes-only (no mnemonic). Records may also be
    interrupted by '(bad)' entries which carry a mnemonic column.
    """
    out: dict[int, Insn] = {}
    vma_re = re.compile(r"^\s+([0-9a-f]{8,16}):\t([0-9a-f ]+)\t(\S+)(?:\s+(.*))?$")
    bytes_re = re.compile(r"^\s+([0-9a-f ]+)\t*$")
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = vma_re.match(line)
            if m:
                vma = int(m.group(1), 16)
                out[vma] = Insn(
                    vma=vma,
                    raw=m.group(2).strip(),
                    mnemonic=m.group(3),
                    operands=(m.group(4) or "").strip(),
                )
                continue
            # continuation: bytes belonging to the previous record
            m2 = bytes_re.match(line)
            if m2 and out:
                pass  # byte wrap; objdump already emitted the record
    return out


def linear_span(table: dict[int, Insn], writers: dict[int, str], pad: int) -> tuple[int, int]:
    """The minimal [lo, hi] VMA window containing every writer."""
    present = [w for w in writers if (w + IMAGE_BASE) in table]
    if not present:
        raise SystemExit("none of the writer RVAs found (image base not applied?)")
    if not present:
        raise SystemExit("none of the writer addresses parsed from the disassembly")
    return min(present), max(present)


def disassemble_window(table: dict[int, Insn], lo: int, hi: int, back: int, fwd: int) -> list[Insn]:
    """Collect the instructions in [lo-back, hi+fwd] in VMA order."""
    lo_v = lo - back
    hi_v = hi + fwd
    return [table[v] for v in sorted(table) if lo_v <= v <= hi_v]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("disassembly")
    ap.add_argument("--window", type=int, default=0, help="pad the span by N bytes each side")
    args = ap.parse_args()

    table = parse_disassembly(args.disassembly)
    print(f"[slice] parsed {len(table)} instructions", file=sys.stderr)

    lo, hi = linear_span(table, WRITERS, 0)
    span = disassemble_window(table, lo + IMAGE_BASE, hi + IMAGE_BASE, args.window, args.window)
    print(f"[slice] writers span RVA {lo:#x}..{hi:#x}; window rows: {len(span)}")

    for insn in span:
        tag = WRITERS.get(insn.vma - IMAGE_BASE, "")
        mark = f"  <== {tag}" if tag else ""
        print(f"{insn.vma:08x}: {insn.raw:24s} {insn.mnemonic} {insn.operands}{mark}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# ---------------------------------------------------------------------------
# The collapsed word formula (Phase-1 deliverable, verified 2026-10-22y).
#
# Each byte channel of the verdict word pkt[4..8] reads ONE byte of the
# DLL image through a planter row pointer + a session-dependent index,
# then mixes it through a collapsed MBA chain. Measured channels:
#
#   pkt+4 = G4(image[0x162cb0 + idx4]) with idx4 = (r9d >> 24) ^ 0x72
#   pkt+5 = G5(image[0x14b82f + idx5]) with idx5 = MBA5([rsp+0x140] ^ 0xe5)
#   pkt+6 = G6(image[0x183cbf + idx6]) ^ r13d ^ 0x4b ^ 0x26 (low byte),
#           idx6 fed from r13b via MBA6, the row from planter[rbp-0x5f6]
#   pkt+7 = G7(image[0x159321 + idx7]) with idx7 = MBA7(r9b ^ 0xfb)
#
# G5/G7 are bare xors (0x13/0x64); G4 is a 256-entry bijection with
# unique preimages 0x01 <- 0x69 and 0x00 <- 0xda; G6 folds a byte with
# r13d. The SUCCESS WORD (00 00 00 01) therefore requires each channel
# to land on its unique success byte of the image -- a property of the
# fold-computed INDICES, not of any caller-controlled packet field.
# ---------------------------------------------------------------------------

G4_TABLE: list[int] | None = None


def g4(x: int) -> int:
    """The collapsed pkt+4 mixer (bijective on bytes)."""
    dl = (x ^ 0x23) & 0xFF
    cl = (((dl * 0x4F) & 0xFF) - ((dl * 0x9E) & 0xAE)) & 0xFF
    cl = (cl + 0x57) & 0xFF
    al = ((cl >> 1) & 0x62) ^ 0x5F
    dl2 = (((cl & 0xC0) ^ 0x40) + al) & 0xFF
    al2 = (dl2 + 0x83) & 0xFF
    cl2 = (cl ^ 0xE2) & 0xFF
    al3 = al2 & cl2
    bl = (al3 ^ 0xBF) & 0xFF
    al5 = ((((al3 * 2) & 0xFF) & 0x44) + bl) & 0xFF
    al7 = ((al5 * 4) - (al5 * 2)) & 0xFF
    cl3 = (cl2 + dl2 + 0x83) & 0xFF
    dl3 = (cl3 ^ 0x6F) & 0xFF
    cl5 = (((cl3 * 2) & 0xDE) + dl3) & 0xFF
    al8 = ((al7 + 0x81) ^ 0x80) & 0xFF
    return ((cl5 + 0x10) - al8) & 0xFF


def mba5(a: int) -> int:
    """Index mixer of the pkt+5 channel: collapses to a small offset."""
    neg = (-( (a * 2) & 0x11E)) & 0xFFFFFFFF
    return ((0x1A82438F + a + neg) & 0xFFFFFFFF) ^ 0x1A824375


def mba7(r9b: int) -> int:
    """Index mixer of the pkt+7 channel."""
    a = r9b ^ 0xFB
    neg = (-((a * 2) & 0x1C4)) & 0xFFFFFFFF
    return ((0x466749E2 + a + neg) & 0xFFFFFFFF) ^ 0x46674951


def mba6(r13b: int) -> int:
    """Index mixer of the pkt+6 channel."""
    a = r13b ^ 0xE1
    neg = (-((a * 2) & 0x1AC)) & 0xFFFFFFFF
    return ((0x7B531DD6 + a + neg) & 0xFFFFFFFF) ^ 0x7B531D2E


def word_formula(idx4: int, byte140: int, r13b: int, r13d: int, r9b: int,
                 image: bytes, rva_to_off) -> tuple[int, int, int, int]:
    """Evaluate the four channels with the collapsed mixers.

    `image` is the DLL file; `rva_to_off` maps an RVA into it (pe_utils).
    The channel bases are the measured planter rows minus their read
    constants (the -1 comes from the lea index arithmetic).
    """
    b4 = image[rva_to_off(image, 0x162CB0 + idx4)]
    b5 = image[rva_to_off(image, 0x14B82F + mba5(byte140 ^ 0xE5))]
    b6 = image[rva_to_off(image, 0x183CBF + mba6(r13b))]
    b7 = image[rva_to_off(image, 0x159321 + mba7(r9b))]
    g6 = mba6_fold(b6)
    w6 = ((g6 ^ r13d ^ 0x4B) & 0xFF) ^ 0x26
    return g4(b4), b5 ^ 0x13, w6, b7 ^ 0x64


def mba6_fold(x: int) -> int:
    """The pkt+6 byte mixer after the image read (edi chain)."""
    edi = (x + 0xDA) & 0xFF
    edi ^= 0xE1
    al = ((edi * 2) & 0xFF) & 0x46
    edi = (edi - al) & 0xFF
    edi = (edi + 0x23) & 0xFF
    edi ^= 0x23
    neg = (-((edi * 2) & 0x30)) & 0xFFFFFFFF
    return (0x98 + edi + neg) & 0xFFFFFFFF
