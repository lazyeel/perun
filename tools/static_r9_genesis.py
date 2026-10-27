#!/usr/bin/env python3
"""Static trace of the fam1 source buffer genesis in libCoreADI.so (Android).

Follows the r9 source of the fam1 copy loop (0xfb048) backward through pure
disassembly. Findings (2026-10-25i, FINDINGS.md):

  [rbp-0x3f8]  the source buffer pointer; written by exactly ONE instruction:
               0xdd83b  mov [rbp-0x3f8], rax     where rax = return of
               0xdd826  call [rbp-0x168]        (CFF internal call, 64 sites)
  0xfaada..0xfac6d:  23 constant byte-patches through the pointer
               (values 0x5b 0x82 0xe5 0x91 0x91 0xb6 0xae 0x39 .. at masked
                indices r10-0x47227dXX, reverse order)
  0xfb022  mov r9, [rbp-0x3f8]   the copy loop's source load
  0xfb048..0xfb0a6  the fam1 copy: planter_fam1[i] = source[i]

  The 23 patches cannot produce a session-dynamic permutation (23 << 256):
  the called function's side effects are the true KDF generator. One
  breakpoint at 0xdd826 captures the function pointer and the buffer content.

Also maps the planter head init (0xfaca3..0xfacd9, dword 0x4a5ea897 at
+0x7a8..0x7b4) and the weave-feed slot constants loaded at 0xfad5b..0xfad9f.
"""

import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

SO = sys.argv[1] if len(sys.argv) > 1 else "libs/libCoreADI.so"
CODE_LO, CODE_HI = 0x80000, 0x110000


def find_all(data: bytes, needle: bytes, lo: int, hi: int):
    pos, hits = lo, []
    while True:
        pos = data.find(needle, pos, hi)
        if pos < 0:
            return hits
        hits.append(pos)
        pos += 1


def main():
    data = open(SO, "rb").read()
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # the one writer of the source pointer
    needle = bytes([0x48, 0x89, 0x85, 0x08, 0xFC, 0xFF, 0xFF])  # mov [rbp-0x3f8], rax
    writers = find_all(data, needle, CODE_LO, CODE_HI)
    print(f"[rbp-0x3f8] writers (mov [rbp-0x3f8], rax): {[hex(w) for w in writers]}")
    for w in writers:
        chunk = data[w - 48 : w + 16]
        for insn in md.disasm(chunk, w - 48):
            mark = ">>>" if insn.address <= w < insn.address + insn.size else "   "
            print(f"  {mark} {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

    # the calls through the dispatcher slot
    needle = bytes([0xFF, 0x95, 0x98, 0xFE, 0xFF, 0xFF])  # call [rbp-0x168]
    calls = find_all(data, needle, CODE_LO, CODE_HI)
    print(f"\ncall [rbp-0x168] sites: {len(calls)}")
    for c in calls:
        print(f"  {c:#x}")

    # the byte-patches through the source pointer
    patch_count = 0
    for rm in (0x95, 0x8D, 0x85):  # rdx, rcx, rax as the pointer register
        needle_load = bytes([0x48, 0x8B, rm, 0x08, 0xFC, 0xFF, 0xFF])  # mov reg, [rbp-0x3f8]
        for load in find_all(data, needle_load, CODE_LO, CODE_HI):
            after = data[load + 7 : load + 17]
            if bytes([0xC6, 0x04]) in after[:5]:  # mov byte [reg+idx], imm8
                patch_count += 1
                print(f"  patch via {hex(load)}")
    print(f"\nbyte-patches through [rbp-0x3f8]: {patch_count}")


if __name__ == "__main__":
    main()
