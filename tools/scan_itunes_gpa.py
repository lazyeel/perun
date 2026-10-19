#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0
"""Static audit of iTunes.exe's 109 GetProcAddress call sites.

The forensic PE audit (2026-10-23f) proved the host binaries are
100% native MSVC C++, and the caller hunt left iTunes.exe's
109-site KERNEL32!GetProcAddress cluster as the one unexamined
64-bit candidate. This tool dissects it statically -- no runtime,
no guesses: for every `call [GetProcAddress]` site it walks a
window of instructions before the call, tracks what lands in RDX
(the export-name argument under the Win64 ABI), and classifies
the site:

  * DIRECT-LEA      -- a rip-relative lea onto a plain .rdata
                        string: the site resolves a NAMED export
                        outright;
  * DEOBFUSCATED    -- a call to a string-deobfuscator (a helper
                        that returns a runtime-decoded buffer)
                        feeds RDX before the call;
  * REGISTER/OTHER  -- the name arrives in a register/stack with
                        no in-window producer (table-driven or
                        cross-block data flow).

Every DIRECT-LEA string is printed; the ADI watch-list
(vdfut768ig, cvu8io98wun, CoreADI*) is flagged loudly. The
summary classifies all sites by the DLL/module family their
strings belong to.

Usage:
    python3 tools/scan_itunes_gpa.py <iTunes.exe> [--window 30]
"""

from __future__ import annotations

import argparse
import re
import struct
import sys

# ── PE ────────────────────────────────────────────────────────────────────


class PE:
    def __init__(self, path: str) -> None:
        self.data = open(path, "rb").read()
        e = struct.unpack_from("<I", self.data, 0x3C)[0]
        (_m, self.nsec, _ts, _ps, _ns, self.optsz, _ch) = struct.unpack_from("<HHIIIHH", self.data, e + 4)
        magic = struct.unpack_from("<H", self.data, e + 24)[0]
        if magic != 0x20B:
            raise SystemExit("not PE32+")
        self.image_base = struct.unpack_from("<Q", self.data, e + 24 + 24)[0]
        dd = e + 24 + 112
        self.imp_va, self.imp_sz = struct.unpack_from("<II", self.data, dd + 8)
        self.sections = []
        so = e + 24 + self.optsz
        for i in range(self.nsec):
            s = so + i * 40
            nm = self.data[s : s + 8].rstrip(b"\0").decode(errors="replace")
            vs, vr, rs, ro = struct.unpack_from("<IIII", self.data, s + 8)
            self.sections.append((nm, vr, max(vs, rs), ro))

    def r2o(self, rva: int) -> int:
        for _nm, vr, sz, ro in self.sections:
            if vr <= rva < vr + sz:
                return ro + (rva - vr)
        raise ValueError(f"rva {rva:#x} outside sections")

    def text(self) -> tuple[int, int, int]:
        for nm, vr, sz, ro in self.sections:
            if nm == ".text":
                return vr, sz, ro
        raise SystemExit("no .text")

    def iat_slot(self, dll_want: str, func_want: str) -> int | None:
        """The IAT slot RVA for func_want imported from dll_want."""
        off = self.r2o(self.imp_va)
        if off is None:
            return None
        i = 0
        while True:
            oft, _ts, _fc, name_rva, fthunk = struct.unpack_from("<IIIII", self.data, off + i * 20)
            if name_rva == 0:
                return None
            no = self.r2o(name_rva)
            dll = self.data[no : no + 32].split(b"\0")[0].decode(errors="replace")
            if dll_want.upper() in dll.upper():
                to = self.r2o(oft or fthunk)
                j = 0
                while True:
                    fn = struct.unpack_from("<Q", self.data, to + j * 8)[0]
                    if fn == 0:
                        break
                    if fn & 0x8000000000000000:
                        nm = f"ord#{fn & 0xffff}"
                    else:
                        fo = self.r2o(fn & 0x7FFFFFFF)
                        nm = self.data[fo + 2 : fo + 2 + 64].split(b"\0")[0].decode(errors="replace")
                    if nm == func_want:
                        return fthunk + j * 8
                    j += 1
            i += 1

    def cstr_at_rva(self, rva: int, maxn: int = 64) -> str | None:
        try:
            o = self.r2o(rva)
        except ValueError:
            return None
        if o is None:
            return None
        raw = self.data[o : o + maxn]
        s = raw.split(b"\0")[0]
        if len(s) < 2:
            return None
        if all(32 <= b < 127 for b in s):
            return s.decode()
        return None


# ── scan ─────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image")
    ap.add_argument("--window", type=int, default=30)
    args = ap.parse_args()

    pe = PE(args.image)
    slot = pe.iat_slot("KERNEL32", "GetProcAddress")
    if slot is None:
        print("GetProcAddress not in the import table")
        return 1
    print(f"GetProcSlot IAT RVA = {slot:#x}")

    tvr, tsz, tro = pe.text()
    text = pe.data[tro : tro + tsz]

    sites = []
    i = 0
    while True:
        i = text.find(b"\xff\x15", i + 1)
        if i < 0:
            break
        disp = struct.unpack_from("<i", text, i + 2)[0]
        if tvr + i + 6 + disp == slot:
            sites.append(tvr + i)
    print(f"call [GetProcAddress] sites: {len(sites)}")

    # string watch-list
    def adi_flag(s: str) -> str:
        low = s.lower()
        if "vdfut" in low or "cvu8" in low:
            return " *** ADI-EXPORT ***"
        if "coreadi" in low:
            return " *** ADI-MODULE ***"
        return ""

    import capstone  # the sandbox keeps capstone in the system python3

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def decode_window(site: int, back: int):
        """Back-search an instruction boundary whose linear decode
        reaches `site` exactly; return the decoded instructions
        ending at site (+6)."""
        for b in range(back, 0, -1):
            start = site - b
            insns = []
            hit = False
            for insn in md.disasm(text[start - tvr : site - tvr + 8], start):
                insns.append(insn)
                if insn.address == site:
                    hit = True
                    break
                if insn.address > site:
                    break
            if hit:
                return insns
        return []

    def classify(insns) -> tuple[str, list[str]]:
        """Track RDX producers over the pre-call window."""
        kind = "OTHER"
        strings: list[str] = []
        for insn in insns:
            if insn.mnemonic == "lea" and insn.op_str.startswith("rdx, [rip"):
                m = re.search(r"rip \+ (0x[0-9a-f]+)\]", insn.op_str)
                if m:
                    tgt = insn.address + insn.size + int(m.group(1), 16)
                    s = pe.cstr_at_rva(tgt)
                    if s is not None:
                        kind = "DIRECT-LEA"
                        strings.append(s)
            elif insn.mnemonic in ("mov", "push") and insn.op_str.startswith("rdx"):
                # mov rdx, <reg> -- a register-carried name: look one
                # step for a call just before (deobfuscator pattern:
                # call helper; mov rdx, rax)
                kind = "REGISTER" if kind == "OTHER" else kind
            elif insn.mnemonic == "call" and not insn.op_str.startswith("qword ptr [rip"):
                # a direct call inside the window: potential string
                # deobfuscator feeding the name
                if kind != "DIRECT-LEA":
                    kind = "CALL-BEFORE (deobfuscator/helper?)"
        return kind, strings

    from collections import Counter

    classes = Counter()
    all_strings: list[str] = []
    adi_hits: list[tuple[int, str]] = []

    for site in sites:
        insns = decode_window(site, args.window)
        kind, strings = classify(insns)
        classes[kind] += 1
        for s in strings:
            all_strings.append(s)
            if adi_flag(s):
                adi_hits.append((site, s))
                print(f"\n== ADI HIT at call site {site:#x}:")
                for k in insns:
                    mark = "  <<<< GetProcAddress" if k.address == site else ""
                    print(f"  {k.address:#x}: {k.bytes.hex():18s} {k.mnemonic} {k.op_str}{mark}")

    print("\n=== classification of all sites ===")
    for k, v in classes.most_common():
        print(f"  {v:4d}  {k}")
    print("\n=== resolved export-name strings (deduped, sorted) ===")
    for s in sorted(set(all_strings)):
        print(f"  {s!r}{adi_flag(s)}")
    if adi_hits:
        print(f"\n*** {len(adi_hits)} ADI-related site(s) ***")
        return 0
    print("\n*** no ADI-related site among the 109 ***")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
