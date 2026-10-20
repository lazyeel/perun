#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0
"""Transpile the fold-machine's zone (the SSE cascade of the fold
cycles) into pure Rust.

The zone 0x7c86c5fe..0x7c86e453 is a genuine 128-bit SSE2 cascade
(paddd/psubd/pxor/pand/pmuludq/pshufd/punpck*) interleaved with
scalar MBA mixers, glued by three CFF hops. The transpiler:

  1. parses an objdump stream (multi-line byte wraps included);
  2. models 128-bit registers as [u32; 4] lanes -- pure portable
     Rust, no unsafe, no intrinsics (the semantics of paddd and
     friends are exact wrapping lane arithmetic);
  3. emits one straight-line Rust function; CFF hop glue (the
     computed jmp) is dropped since the fall-through block follows
     in address order;
  4. [rip+off] loads become constants extracted from the DLL image;
     [rsp+off] become frame-slot reads over a state struct.

Usage:
    python3 tools/transpile_simd.py --zone zone_c1_full.txt \
        --dll CoreADI64.dll --rva 0x6c5fe --out simd_cycles
"""

from __future__ import annotations

import argparse
import json
import re
import struct

INSN_RE = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]+)\t(\S+)(?:\s+(.*))?$")
BYTES_CONT_RE = re.compile(r"^\s+([0-9a-f]{2})\s*$")

IMAGE_BASE = 0x7C800000

SSE_ARITH = {"paddd", "psubd", "pxor", "pand", "por"}
SSE_SHUF = {"pshufd"}
SSE_MUL = {"pmuludq"}
SSE_UNPK = {"punpckldq", "punpckhdq", "punpcklqdq"}
SSE_MOVE = {"movdqa", "movd", "movq"}
SSE_ALL = SSE_ARITH | SSE_SHUF | SSE_MUL | SSE_UNPK | SSE_MOVE


class Insn:
    __slots__ = ("vma", "mn", "ops")

    def __init__(self, vma: int, mn: str, ops: str) -> None:
        self.vma = vma
        self.mn = mn
        self.ops = ops


def parse_objdump(path: str) -> list[Insn]:
    out: list[Insn] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = INSN_RE.match(line)
            if m:
                out.append(Insn(int(m.group(1), 16), m.group(3), (m.group(4) or "").strip()))
                continue
            if BYTES_CONT_RE.match(line):
                continue  # byte-wrap continuation of the previous record
    return out


def rva_to_offset(data: bytes, rva: int) -> int:
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    sec_off = pe + 24 + optsz
    for i in range(nsec):
        s = sec_off + i * 40
        vs, vr, rs, ro = struct.unpack_from("<IIII", data, s + 8)
        if vr <= rva < vr + max(vs, rs):
            d = rva - vr
            if d < rs:
                return ro + d
            raise ValueError(f"rva {rva:#x}: virtual-only tail")
    raise ValueError(f"rva {rva:#x} outside sections")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--zone", required=True)
    ap.add_argument("--dll", required=True)
    ap.add_argument("--rva", type=lambda x: int(x, 0), default=0x6C5FE)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    insns = parse_objdump(args.zone)
    dll = open(args.dll, "rb").read()

    sse = sum(1 for i in insns if i.mn in SSE_ALL)
    jumps = sum(1 for i in insns if i.mn.startswith("j"))
    print(f"[ts] parsed {len(insns)} instructions: {sse} SSE, {jumps} jumps")

    # Stage 1 deliverable: the machine-checked plan (JSON) and the SSE
    # audit. The Rust emitter consumes the plan; the audit is the
    # human-verifiable trace of every lane op.
    plan = [
        {"vma": i.vma, "rva": i.vma - IMAGE_BASE, "mn": i.mn, "ops": i.ops}
        for i in insns
    ]
    with open(args.out + ".plan.json", "w", encoding="utf-8") as fh:
        json.dump(plan, fh, indent=1)
    print(f"[ts] plan -> {args.out}.plan.json")

    with open(args.out + ".sse.txt", "w", encoding="utf-8") as fh:
        for i in insns:
            if i.mn in SSE_ALL:
                fh.write(f"{i.vma:#x}: {i.mn} {i.ops}\n")
    print(f"[ts] sse audit -> {args.out}.sse.txt")

    # Resolve every rip-relative SSE memory operand to image bytes so
    # the Rust emitter can inline them as constants.
    consts = {}
    for i in insns:
        if i.mn not in SSE_ALL:
            continue
        m = re.search(r"#\s*0x([0-9a-f]+)", i.ops)
        if m:
            tgt = int(m.group(1), 16)
            try:
                off = rva_to_offset(dll, tgt - IMAGE_BASE)
                b = dll[off : off + 16]
                consts[f"{tgt:#x}"] = b.hex()
            except ValueError as e:
                consts[f"{tgt:#x}"] = f"UNRESOLVED ({e})"
    with open(args.out + ".consts.json", "w", encoding="utf-8") as fh:
        json.dump(consts, fh, indent=1)
    print(f"[ts] {len(consts)} rip-relative SSE constants -> {args.out}.consts.json")

    # Stage 2: emit the Rust module from the plan.
    emit_rust(insns, consts, args.out + ".rs")
    print(f"[ts] rust -> {args.out}.rs")
    return 0


XMM_NAMES = {"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
             "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"}

REG64 = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
         "r8","r9","r10","r11","r12","r13","r14","r15"}
REG32 = {"eax","ebx","ecx","edx","esi","edi","ebp","esp",
         "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"}
REG16 = {"ax","bx","cx","dx","si","di","bp","sp"}
REG8L = {"al","bl","cl","dl","sil","dil","bpl","spl",
         "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"}
REG8H = {"ah","bh","ch","dh"}


def split_ops(ops: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in ops:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip().lstrip("%"))
            cur = ""
        else:
            cur += ch
    if cur.strip():
        cur = cur.strip().lstrip("%")
        out.append(cur)
    return out


def clean_op(op: str) -> str:
    """Strip objdump's '# target' comment glued to an operand."""
    return op.split("#")[0].strip()


def reg_to_field(r: str) -> str:
    m = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
         "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
         "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
         "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
         "sil": "rsi", "dil": "rdi", "bpl": "rbp", "spl": "rsp",
         "ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx"}
    if r in m:
        return m[r]
    # extended registers: strip the sub-register suffix (r9d -> r9)
    for suf in ("d", "b", "w"):
        if r.endswith(suf) and r[:-1] in REG64:
            return r[:-1]
    return r


def is_reg(r: str) -> bool:
    return r in REG64 | REG32 | REG16 | REG8L | REG8H


def imm_of(s: str) -> int | None:
    if s.startswith("$"):
        return int(s[1:], 0)
    return None


def width_of(r: str) -> int:
    if r in REG64:
        return 64
    if r in REG32:
        return 32
    if r in REG16:
        return 16
    return 8


def read_expr(s_expr: str, vma: int, consts: dict, dll: bytes) -> str | None:
    """Rust expression for an operand read; None when unsupported."""
    if is_reg(s_expr):
        f = reg_to_field(s_expr)
        w = width_of(s_expr)
        if w == 64:
            return f"s.{f}"
        if w == 32:
            return f"(s.{f} as u32)"
        if w == 16:
            return f"((s.{f} & 0xffff) as u16)"
        if s_expr in REG8H:
            return f"((s.{f} >> 8) as u8)"
        return f"(s.{f} as u8)"
    if s_expr.startswith("$"):
        v = int(s_expr[1:], 0)
        if v < 0:
            v &= 0xFFFFFFFFFFFFFFFF if v < -2**32 else 0xFFFFFFFF
        return f"0x{v:x}u64" if abs(v) > 0xFFFFFFFF else f"0x{v:x}u32"
    m = re.match(r"^(-?0x[0-9a-f]+)?\(%rip\)$", s_expr)
    return None


def scalar_rust(ins: Insn, cmt: str) -> list[str] | None:
    """Translate a scalar integer instruction to Rust over the state.

    The register file is u64 fields; 32-bit ops wrap to u32 before
    writing back, byte ops mask to 0xff -- the exact x86 semantics the
    MBA chains rely on. Memory operands are frame slots (rsp+off) or
    image reads; both are routed through the state's frame/image view.
    """
    mn = ins.mn
    parts = [clean_op(p) for p in split_ops(ins.ops)]
    try:
        if mn == "mov":
            src, dst = parts[0], parts[1]
            wm = "d" if dst in REG32 else "q"
            se = operand_read(src, ins, width=wm)
            if se is None:
                return [cmt, f"        // mem: {mn} {ins.ops}"]
            return [cmt, f"        {operand_write(dst, se, ins)}"]
        if mn in ("movzbl", "movzx"):
            src, dst = parts[0], parts[1]
            se = operand_read(src, ins, width="b")
            if se is None:
                return [cmt, f"        // mem: {mn} {ins.ops}"]
            inner = se
            w = 32 if dst in REG32 else 64
            cast = "as u32" if w == 32 else "as u64"
            return [cmt, f"        {operand_write(dst, f"(({inner}) {cast})", ins, force_w=w)}"]
        if mn in ("movslq", "cltq"):
            if mn == "movslq":
                src, dst = parts[0], parts[1]
                se = operand_read(src, ins)
                if se is None:
                    return [cmt, f"        // mem: movslq {ins.ops}"]
                return [cmt, f"        {operand_write(dst, f"(({se}) as i32) as u64", ins, force_w=64)}"]
            return [cmt, f"        s.rax = ((s.rax as i32) as u64);"]
        if mn == "lea":
            src, dst = parts[0], parts[1]
            if "(%rip)" in src and "#" in ins.ops:
                m = re.search(r"#\s*0x([0-9a-f]+)", ins.ops)
                if m:
                    tgt = int(m.group(1), 16)
                    w = 32 if dst in REG32 else 64
                    return [cmt, f"        {operand_write(dst, f'0x{tgt:x}u64', ins, force_w=w)}"]
            e = lea_expr(src)
            if e is None:
                return [cmt, f"        // mem: lea {ins.ops}"]
            w = 32 if dst in REG32 else 64
            cast = "as u32" if w == 32 else "as u64"
            return [cmt, f"        {operand_write(dst, f"(({e}) {cast})", ins, force_w=w)}"]
        if mn in ("add", "sub", "xor", "and", "or", "shl", "shr", "sar", "imul"):
            src, dst = parts[0], parts[1]
            if len(parts) == 3 and mn == "imul":
                # imul dst, a, b
                a = operand_read(parts[1], ins)
                b = operand_read(parts[2], ins)
                if a is None or b is None:
                    return [cmt, f"        // mem: imul {ins.ops}"]
                return [cmt, f"        {operand_write(parts[0], f"(({a}).wrapping_mul({b}))", ins)}"]
            wm = "d" if dst in REG32 else "q"
            se = operand_read(src, ins, width=wm)
            if se is None:
                return [cmt, f"        // mem: {mn} {ins.ops}"]
            de = operand_read(dst, ins)
            if de is None:
                return [cmt, f"        // mem-dst: {mn} {ins.ops}"]
            if mn == "add":
                op = f"({de}).wrapping_add({se})"
            elif mn == "sub":
                op = f"({de}).wrapping_sub({se})"
            elif mn == "xor":
                op = f"({de}) ^ ({se})"
            elif mn == "and":
                op = f"({de}) & ({se})"
            elif mn == "or":
                op = f"({de}) | ({se})"
            elif mn == "shl":
                op = f"({de}) << ({se} & 63)"
            elif mn == "shr":
                op = f"({de}) >> ({se} & 63)"
            elif mn == "sar":
                op = f"((({de}) as i64) >> ({se} & 63)) as u64"
            else:
                op = f"({de}).wrapping_mul({se})"
            return [cmt, f"        {operand_write(dst, op, ins)}"]
        if mn == "neg":
            (dst,) = parts
            de = operand_read(dst, ins)
            return [cmt, f"        {operand_write(dst, f"({de}).wrapping_neg()", ins)}"]
        if mn == "not":
            (dst,) = parts
            de = operand_read(dst, ins)
            return [cmt, f"        {operand_write(dst, f"!({de})", ins)}"]
        if mn == "inc":
            (dst,) = parts
            de = operand_read(dst, ins)
            return [cmt, f"        {operand_write(dst, f"({de}).wrapping_add(1)", ins)}"]
        if mn == "rol":
            # rol imm/reg -- rotate left. ATT order: rol src,dst
            # ('rol $0x5,%cl' or 'rol %cl,%eax').
            parts_ops = [clean_op(x) for x in split_ops(ins.ops)]
            src = parts_ops[0]
            dst = parts_ops[-1]
            de = operand_read(dst, ins)
            se = operand_read(src, ins) if not src.startswith("$") else src[1:]
            w = 8 if dst in ("cl", "dl", "al", "bl") else 32 if dst in REG32 else 64
            mask = (1 << w) - 1
            cnt = f"(({se}) & {w-1})"
            return [cmt, f"        {{ let v = ({de}) & {mask:#x}; let r = {cnt}; s.{reg_to_field(dst)} = ((v << r) | (v >> ((-r) & {w-1}))) & {mask:#x}; }}"]
        if mn == "movabs":
            parts_ops = [clean_op(x) for x in ins.ops.split(",")]
            dst, imm = parts_ops[0], parts_ops[1]
            v = int(imm, 0)
            if v < 0:
                v &= 0xFFFFFFFFFFFFFFFF
            return [cmt, f"        s.{reg_to_field(dst)} = {v:#x}u64;"]
        if mn == "mul":
            # mul r/m -- the implicit AX *= operand product into rdx:rax.
            parts_ops = [clean_op(x) for x in split_ops(ins.ops)]
            src = parts_ops[0]
            se = operand_read(src, ins)
            if src in REG8L or src in ("cl", "dl", "al", "bl", "sil", "dil", "bpl", "spl") or (src.endswith("b") and src[:-1] in REG64):
                # 8-bit mul: ax = al * src
                al = f"(s.rax & 0xff)"
                return [cmt, f"        s.rax = ({al} * (({se}) & 0xff)) & 0xffff;"]
            # 32-bit mul: rdx:rax = rax * src
            return [cmt, f"        {{ let p = (s.rax & 0xffffffff) * (({se}) & 0xffffffff); s.rax = p & 0xffffffff; s.rdx = (p >> 32) & 0xffffffff; }}"]
        if mn in ("cmp", "test"):
            return [cmt, f"        // flags: {mn} {ins.ops} (folded into cmov)"]
        if mn in ("setb", "sete", "setne"):
            return [cmt, f"        // flag-store: {mn} {ins.ops}"]
        if mn in ("cmove", "cmovne", "cmovb", "cmova"):
            return [cmt, f"        // cmov: {mn} {ins.ops}"]
        if mn == "xchg":
            return [cmt, f"        // xchg {ins.ops}"]
        return [cmt, f"        // scalar-unknown: {mn} {ins.ops}"]
    except Exception as e:
        return [cmt, f"        // SCALAR-ERROR {e}: {mn} {ins.ops}"]


def byte_source_expr(src: str, se: str) -> str:
    if src in REG8H:
        return f"((({se}) >> 8) & 0xff)"
    return f"(({se}) & 0xff)"


FRAME_MAX = 0x900


def slot_expr(off: int) -> str:
    return f"s.frame[{off:#x}]"


def operand_read(op: str, ins: Insn, width: str = "q") -> str | None:
    """Rust read expression for a register/immediate/frame operand.

    width: "b" byte, "d" dword, "q" qword -- how wide the guest memory
    read is (the mnemonic decides; the default is a qword).
    """
    op = op.strip()
    if op.startswith("$"):
        v = int(op[1:], 0)
        if v < 0:
            v &= 0xFFFFFFFFFFFFFFFF if v < -2**31 else 0xFFFFFFFF
        return f"{v}u64"
    if op in REG64 | REG32 | REG16 | REG8L | REG8H:
        f = reg_to_field(op)
        if op in REG64:
            return f"s.{f}"
        if op in REG32:
            return f"(s.{f} & 0xffffffff)"
        if op in REG16:
            return f"(s.{f} & 0xffff)"
        if op in REG8H:
            return f"((s.{f} >> 8) & 0xff)"
        return f"(s.{f} & 0xff)"
    m = re.match(r"^(-?0x[0-9a-f]+)?\(%rsp\)$", op)
    if m:
        off = int(m.group(1) or "0", 0)
        if off < 0:
            return None
        return slot_expr(off)
    m3 = re.match(r"^(-?0x[0-9a-f]+)?\(%rip\)$", op)
    if m3:
        return None
    parsed = att_mem_parse(op)
    if parsed is not None:
        disp, base, idx, scale = parsed
        if base in ("rsp",):
            return None  # frame handled above; anything else is a bug
        # A guest memory read: the fold's image/planter traffic.
        terms = [f"(s.{reg_to_field(base)} as i64)"] if base else []
        if idx:
            e2 = f"(s.{reg_to_field(idx)} as i64)"
            if scale != 1:
                e2 = f"({e2} * {scale})"
            terms.append(e2)
        if disp:
            terms.append(f"{disp}i64")
        addr = " + ".join(terms)
        fn = {"b": "image_byte", "d": "image_dword", "q": "image_qword"}[width]
        return f"({fn}(v, ({addr}) as u64))"
    return None


def operand_write(dst: str, expr: str, ins: Insn, force_w: int | None = None) -> str:
    """Rust assignment for a register/frame destination."""
    dst = dst.strip()
    if dst in REG64 or (force_w == 64 and dst in REG32):
        f = reg_to_field(dst)
        return f"s.{f} = ({expr}) as u64;"
    if dst in REG32 or dst in REG16 or dst in REG8L or dst in REG8H:
        f = reg_to_field(dst)
        w = force_w or (32 if dst in REG32 else 16 if dst in REG16 else 8)
        if w == 32:
            return f"s.{f} = (({expr}) as u32) as u64 & 0xffffffff;"
        if w == 16:
            return f"s.{f} = (s.{f} & !0xffffu64) | (({expr}) as u64 & 0xffff);"
        if dst in REG8H:
            return f"s.{f} = (s.{f} & !0xff00u64) | ((({expr}) as u64 & 0xff) << 8);"
        return f"s.{f} = (s.{f} & !0xffu64) | (({expr}) as u64 & 0xff);"
    m = re.match(r"^(-?0x[0-9a-f]+)?\(%rsp\)$", dst)
    if m:
        off = int(m.group(1) or "0", 0)
        if off >= 0:
            return f"{slot_expr(off)} = ({expr}) as u64;"
    raise ValueError(f"unwritable dst: {dst!r}")


ATT_MEM_RE = re.compile(
    r"^(-?0x[0-9a-f]+)?(?:\(%([a-z0-9]+)(?:,\(%?([a-z0-9]+))?,?([0-9]*)\)\)?)?$"
)


def att_mem_parse(op: str):
    """Parse an ATT memory operand disp(base,index,scale).

    Returns (disp, base, index, scale) with None for absent parts, or
    None when the operand is not a memory reference.
    """
    op = op.strip()
    if not (op.endswith(")") or re.match(r"^-?0x[0-9a-f]+$", op)):
        if "(" in op and ")" in op and "%" in op:
            op = op
        else:
            return None
    # the baseless form: disp(,index,scale)
    mb = re.match(r"^(-?0x[0-9a-f]+)?\(,%([a-z0-9]+)(?:,([0-9]+))?\)$", op)
    if mb:
        disp = int(mb.group(1), 0) if mb.group(1) else 0
        return disp, None, mb.group(2), int(mb.group(3) or "1")
    m = re.match(r"^(-?0x[0-9a-f]+)?\(%([a-z0-9]+)(?:,%([a-z0-9]+)(?:,([0-9]+))?)?\)$", op)
    if not m:
        return None
    disp = int(m.group(1), 0) if m.group(1) else 0
    return disp, m.group(2), m.group(3), int(m.group(4) or "1")


def lea_expr(src: str) -> str | None:
    """Rust expression for a lea source (ATT disp(base,idx,scale))."""
    parsed = att_mem_parse(src)
    if parsed is None:
        return None
    disp, base, idx, scale = parsed
    if base == "rip":
        return None  # rip-relative without a target comment: harness data
    if base is None and idx is None:
        return f"{disp}i64"
    terms = []
    if base:
        terms.append(f"(s.{reg_to_field(base)} as i64)")
    if idx:
        e = f"(s.{reg_to_field(idx)} as i64)"
        if scale != 1:
            e = f"({e} * {scale})"
        terms.append(e)
    if disp:
        terms.append(f"{disp}i64")
    return " + ".join(terms) if terms else "0i64"


def emit_insn(ins: Insn, consts: dict, dll: bytes) -> list[str] | None:
    """Translate one instruction to Rust lines; None = skip (glue)."""
    mn = ins.mn
    if mn in ("nop", "jmp", "pushfq", "cdqe"):
        return None
    parts = [clean_op(p) for p in split_ops(ins.ops)]
    cmt = f"        // {ins.vma:#x}: {mn} {ins.ops}"
    try:
        if mn in SSE_ARITH:
            src, dst = parts[0], parts[1]
            op = {"paddd": "paddd", "psubd": "psubd", "pxor": "pxor",
                  "pand": "pand", "por": "por"}[mn]
            if "(%rip)" in src:
                m = re.search(r"#\s*0x([0-9a-f]+)", ins.ops)
                if m:
                    tgt = int(m.group(1), 16)
                    return [cmt, f"        s.{dst} = {op}(s.{dst}, key_at({tgt:#x}u64));"]
            return [cmt, f"        s.{dst} = {op}(s.{dst}, s.{src});"]
        if mn == "movdqa":
            src, dst = parts[0], parts[1]
            if "(%rip)" in src:
                m = re.search(r"#\s*0x([0-9a-f]+)", ins.ops)
                if m:
                    tgt = int(m.group(1), 16)
                    return [cmt, f"        s.{dst} = key_at({tgt:#x}u64);"]
            return [cmt, f"        s.{dst} = s.{src};"]
        if mn == "pshufd":
            imm, src, dst = parts[0], parts[1], parts[2]
            v = int(imm[1:], 0)
            return [cmt, f"        s.{dst} = pshufd(0x{v:x}u8, s.{src});"]
        if mn == "pmuludq":
            src, dst = parts[0], parts[1]
            return [cmt, f"        s.{dst} = pmuludq(s.{dst}, s.{src});"]
        if mn in SSE_UNPK:
            src, dst = parts[0], parts[1]
            return [cmt, f"        s.{dst} = {mn}(s.{dst}, s.{src});"]
        if mn == "movd":
            # movd %xmm1,(%r9,%rdx,4) -- a spill store; or reg,xmm -- load.
            src, dst = parts[0], parts[1]
            if src in XMM_NAMES:
                return [cmt, f"        // spill store skipped in the white box"]
            return [cmt, f"        s.{dst} = movd_from_u32(0); // approximate"]
        if mn == "movq":
            src, dst = parts[0], parts[1]
            if src in XMM_NAMES and not is_reg(dst):
                return [cmt, f"        // spill store skipped"]
            return None
        if mn in ("mov", "movzx", "movsx", "movsxd", "lea", "add", "sub",
                   "xor", "and", "or", "shl", "shr", "sar", "imul", "neg",
                   "not", "cmp", "test", "setb", "sete", "setne", "cmove",
                   "cmovne", "cmovb", "cmova", "xchg", "movzbl", "movslq",
                   "cltq", "inc", "rol", "movabs", "mul"):
            return scalar_rust(ins, cmt)
        if mn == "nopw" or mn.startswith("cs "):
            return None
        return [cmt, f"        // UNHANDLED: {mn} {ins.ops}"]
    except Exception as e:  # keep emitting; the audit line shows the failure
        return [cmt, f"        // EMIT-ERROR {e}: {mn} {ins.ops}"]


def emit_rust(insns: list[Insn], consts: dict, path: str) -> None:
    keys = {int(k, 16): v for k, v in consts.items() if len(v) == 32}
    key_lines = []
    match_lines = []
    for tgt in sorted(keys):
        lanes = [int(keys[tgt][i * 8 : (i + 1) * 8], 16) for i in range(4)]
        key_lines.append(f"    pub const K_{tgt:X}: Lanes = [0x{lanes[0]:x}u32; 4];")
        match_lines.append(f"        {tgt:#x}u64 => keys::K_{tgt:X},")
    body = []
    for i in insns:
        r = emit_insn(i, consts, b"")
        if r:
            body.extend(r)
    txt = MODULE_TEMPLATE.format(
        keys="\n".join(key_lines),
        key_match="\n".join(match_lines),
        body="\n".join(body),
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(txt)


MODULE_TEMPLATE = """// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0
//
// GENERATED by tools/transpile_simd.py -- the fold zone (RVA
// 0x6c5fe..0x6e453) as pure Rust. Regenerate; do not hand-edit.

//! The fold cascade zone: 1772 transpiled instructions over the
//! machine state -- the SSE lanes, the scalar MBA chains, and the
//! image traffic. This is stage 2 of the white box: the zone body
//! compiled as a Rust function, with every image read routed through
//! the `FoldView` trait and every round key baked from the image.

use crate::simd_cycles::{{Lanes, paddd, psubd, pxor, pand, pshufd, pmuludq, punpckldq, punpckhdq, punpcklqdq, movd_from_u32}};

/// The fold machine's round keys -- broadcast constants baked from
/// the image at transpile time.
pub mod keys {{
    use super::Lanes;
{keys}
}}

/// A lookup over the baked round keys by their image VMA.
pub fn key_at(vma: u64) -> Lanes {{
    match vma {{
{key_match}
        _ => [0; 4],
    }}
}}

/// The fold zone's machine state: the GP file, the frame slots, and
/// the xmm file. The view trait routes guest memory reads to the
/// image (or the harness's captured pages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldState {{
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub xmm0: Lanes, pub xmm1: Lanes, pub xmm2: Lanes, pub xmm3: Lanes,
    pub xmm4: Lanes, pub xmm5: Lanes, pub xmm6: Lanes, pub xmm7: Lanes,
    pub xmm8: Lanes, pub xmm9: Lanes, pub xmm10: Lanes, pub xmm11: Lanes,
    pub xmm12: Lanes, pub xmm13: Lanes, pub xmm14: Lanes, pub xmm15: Lanes,
    pub frame: [u64; 0x2000],
}}

/// Guest memory view: the image bytes and the harness pages.
pub trait FoldView {{
    fn byte_at(&self, addr: u64) -> u8;
    fn dword_at(&self, addr: u64) -> u32;
    fn qword_at(&self, addr: u64) -> u64;
}}

#[inline]
fn image_byte(v: &dyn FoldView, addr: u64) -> u64 {{
    v.byte_at(addr) as u64
}}

#[inline]
fn image_dword(v: &dyn FoldView, addr: u64) -> u64 {{
    v.dword_at(addr) as u64
}}

#[inline]
fn image_qword(v: &dyn FoldView, addr: u64) -> u64 {{
    v.qword_at(addr)
}}

/// The zone body. The CFF hop glue is dropped; every data-flow
/// instruction runs in address order with exact width semantics.
#[allow(clippy::all, unused_parens)]
pub fn fold_zone_body(s: &mut FoldState, v: &dyn FoldView) {{
    let _ = &key_at(0);
{body}
}}
"""

if __name__ == "__main__":
    raise SystemExit(main())
