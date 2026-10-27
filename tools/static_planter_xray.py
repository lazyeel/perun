#!/usr/bin/env python3
"""Static x-ray of the planter writers in libCoreADI.so (Android transform).

Locates every instruction that addresses the four family windows
(disp32 0xd60 / 0x1a00 / 0x2460 / 0x1390) and every read/write of the
[rbp-0x30] planter-pointer slot, by raw byte-pattern scan plus targeted
Capstone disassembly. No debugger, no execution.

Findings recorded 2026-10-25h (FINDINGS.md):
  fam1  0xfb05b/0xfb075  mov byte [r12+rsi+0xd60], dl   -- sequential 256-byte copy
  fam2  0xe250c          mov byte [rdi+rcx+0x1a00], r14b
  fam3  0xe25c2          mov byte [rdi+rax+0x2460], r8b
  fam4  0xe26ae          mov byte [r8+rax+0x1390], r13b
  fifth window: 0xe24c9  mov byte [rdi+r15+0x1f30], cl  (previously uncataloged)
  planter base loads: r12=[rbp-0x30] @0xfac8a, rdi=[rbp-0x30] @0xe243d
"""

import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

SO = sys.argv[1] if len(sys.argv) > 1 else "libs/libCoreADI.so"
CODE_LO, CODE_HI = 0x80000, 0x110000

FAMILIES = [(0xD60, "fam1"), (0x1A00, "fam2"), (0x2460, "fam3"), (0x1390, "fam4")]


def scan_disp32(data: bytes, disp: int):
    needle = struct.pack("<I", disp)
    hits, pos = [], CODE_LO
    while True:
        pos = data.find(needle, pos, CODE_HI)
        if pos < 0:
            return hits
        hits.append(pos)
        pos += 1


def disasm_around(data: bytes, md: Cs, rva: int, back: int = 32, fwd: int = 48):
    start = max(0, rva - back)
    out = []
    for insn in md.disasm(data[start : rva + fwd], start):
        out.append(insn)
        if insn.address + insn.size > rva + fwd:
            break
    return out


def main():
    data = open(SO, "rb").read()
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    print(f"target: {SO} ({len(data)} bytes)\n")

    for disp, name in FAMILIES:
        hits = scan_disp32(data, disp)
        non_mixer = [h for h in hits if not (0xE6B41 <= h <= 0xE7100) and not (0xFBF00 <= h <= 0xFC100)]
        print(f"{name} (disp32 {disp:#x}): {len(hits)} total, {len(non_mixer)} outside the mixers/digest")
        for h in non_mixer:
            for insn in disasm_around(data, md, h, back=8, fwd=8):
                if insn.address <= h < insn.address + insn.size:
                    print(f"  {h:#x}: {insn.mnemonic} {insn.op_str}   [{insn.bytes.hex()}]")
                    break
        print()

    print("[rbp-0x30] writers (mov [rbp-0x30], reg) in the code zone:")
    for prefix, names in [(0x48, ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]), (0x4C, ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"])]:
        for reg_i, reg in enumerate(names):
            needle = bytes([prefix, 0x89, 0x45 | (reg_i << 3), 0xD0])
            pos = CODE_LO
            while True:
                pos = data.find(needle, pos, CODE_HI)
                if pos < 0:
                    break
                print(f"  {pos:#x}: mov [rbp-0x30], {reg}")
                pos += 1

    print("\n[rbp-0x30] readers (mov reg, [rbp-0x30]) in the code zone:")
    for prefix, names in [(0x48, ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]), (0x4C, ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"])]:
        for reg_i, reg in enumerate(names):
            needle = bytes([prefix, 0x8B, 0x45 | (reg_i << 3), 0xD0])
            pos = CODE_LO
            while True:
                pos = data.find(needle, pos, CODE_HI)
                if pos < 0:
                    break
                print(f"  {pos:#x}: mov {reg}, [rbp-0x30]")
                pos += 1


if __name__ == "__main__":
    main()
