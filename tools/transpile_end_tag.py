#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0
"""Transpile the measured 64-round End tag SSE circuit to pure Rust.

Development oracle only. Two independent ptrace streams must execute the same
321-instruction circuit 64 times. The emitter produces arithmetic and static
read-only lookup data, never an Apple image, executable bytes, capture reads or
expected output. Initial/final semantic states stay in a caller-selected
private directory for the differential gate.
"""

import argparse
import os
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from transpile_end_tail import LIB_BASE, reg_value
from transpile_planter import address, audit_flags, emit, read_op, write_op

HEAP_ADDRESS = 0x7FFFF78C8000
HEAP_LEN = 0x4000
HEAP_SEED_BASE = 0x7FFFF77FF000
STACK_SEED_BASE = 0x7FFFFFFEF000
DATA_ADDRESS = 0x7FFFF77FB000
DATA_LEN = 0x5000
FRAME_LEN = 0x500
OUTPUT_A_ADDRESS = 0x7FFFF78CB300
OUTPUT_B_ADDRESS = 0x7FFFF78C9500
OUTPUT_LEN = 0x400
START_RVA = 0x156780
BLOCK_RECORDS = 321
ROUNDS = 64
PERIOD_RECORDS = BLOCK_RECORDS * ROUNDS
REQUIRED_RECORDS = PERIOD_RECORDS + 4
REC = 984
TREC = 152
XMM_OFF = 160
RODATA_START = 0x2E0
RODATA_END = 0x49F40

SSE_BINARY = {
    "paddd", "psubd", "pand", "pxor", "por", "paddq", "psubq",
    "pcmpgtd", "pcmpeqd", "pminud", "pmulld", "pshufb", "orpd",
}
SSE_CONVERT = {"pmovzxdq", "pmovsxdq", "pmovzxwd"}
SSE_SHIFT = {"psrld", "pslld", "psrlq", "psllq"}
SSE_MNEMONICS = (
    SSE_BINARY | SSE_CONVERT | SSE_SHIFT |
    {"movdqa", "movq", "movd", "pextrq", "pextrd", "pinsrd", "pinsrw",
     "pshufd", "shufps", "punpckhdq", "blendvpd"}
)


def read_trace(path):
    data = Path(path).read_bytes()
    if len(data) != REQUIRED_RECORDS * REC:
        raise ValueError(f"{path}: expected {REQUIRED_RECORDS} records, got {len(data) // REC}")
    rows = []
    for at in range(0, len(data), REC):
        header = data[at:at + TREC]
        xstate = data[at + TREC:at + REC]
        xmm = [xstate[XMM_OFF + index * 16:XMM_OFF + (index + 1) * 16]
               for index in range(16)]
        rows.append((struct.unpack_from("<Q", header)[0],
                     struct.unpack_from("<16Q", header, 8), xmm))
    return rows


def load_case(spec):
    name, path = spec.split("=", 1)
    root = Path(path)
    trace = read_trace(root / "taground.trace.bin")
    if trace[0][0] != LIB_BASE + START_RVA:
        raise ValueError(f"{name}: wrong circuit entry {trace[0][0] - LIB_BASE:#x}")
    for at in range(BLOCK_RECORDS, PERIOD_RECORDS):
        if trace[at][0] != trace[at - BLOCK_RECORDS][0]:
            raise ValueError(f"{name}: circuit PC period differs at record {at}")
    registers, rbp, xmm = trace[0][1], trace[0][1][6], trace[0][2]
    stack = (root / "stack.bin").read_bytes()
    heap = (root / "heap.bin").read_bytes()
    data = (root / "ca_rw.bin").read_bytes()
    frame_start = rbp - FRAME_LEN
    frame = stack[frame_start - STACK_SEED_BASE:frame_start - STACK_SEED_BASE + FRAME_LEN]
    dynamic = heap[HEAP_ADDRESS - HEAP_SEED_BASE:HEAP_ADDRESS - HEAP_SEED_BASE + HEAP_LEN]
    expected_a = (root / "expected_a.bin").read_bytes()
    expected_b = (root / "expected_b.bin").read_bytes()
    if (len(frame) != FRAME_LEN or len(dynamic) != HEAP_LEN or len(data) != DATA_LEN or
            len(expected_a) != OUTPUT_LEN or len(expected_b) != OUTPUT_LEN):
        raise ValueError(f"{name}: truncated semantic state")
    return dict(name=name, trace=trace, registers=registers, rbp=rbp, xmm=xmm,
                frame=frame, heap=dynamic, data=data,
                expected_a=expected_a, expected_b=expected_b)


def effective_address(ins, registers, op):
    value = op.mem.disp
    if op.mem.base:
        value += reg_value(ins, registers, op.mem.base)
    if op.mem.index:
        value += reg_value(ins, registers, op.mem.index) * op.mem.scale
    return value & 0xFFFFFFFFFFFFFFFF


def is_write_only_destination(ins, index, op):
    if index != 0 or op.type != X86_OP_MEM:
        return False
    return ins.mnemonic in {"mov", "movd", "movq", "movdqa", "movdqu", "pextrd", "pextrq"}


def decode_and_census(case, image):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = []
    static = set()
    for index, (ip, registers, _) in enumerate(case["trace"][:PERIOD_RECORDS]):
        rva = ip - LIB_BASE
        ins = next(md.disasm(image[rva:rva + 15], ip, count=1), None)
        if ins is None:
            raise ValueError(f"cannot decode {rva:#x}")
        if ins.mnemonic in ("call", "ret") or (ins.mnemonic.startswith("j") and ins.mnemonic != "jmp"):
            raise ValueError(f"unsupported tag-round control flow at {rva:#x}")
        if index < BLOCK_RECORDS:
            insns.append(ins)
        if ins.mnemonic == "lea":
            continue
        for op_index, op in enumerate(ins.operands):
            if op.type != X86_OP_MEM or not (op.access & 1):
                continue
            if is_write_only_destination(ins, op_index, op):
                continue
            address_value = effective_address(ins, registers, op)
            for byte_index in range(op.size):
                current = (address_value + byte_index) & 0xFFFFFFFFFFFFFFFF
                if case["rbp"] - FRAME_LEN <= current < case["rbp"]:
                    continue
                if HEAP_ADDRESS <= current < HEAP_ADDRESS + HEAP_LEN:
                    continue
                if DATA_ADDRESS <= current < DATA_ADDRESS + DATA_LEN:
                    continue
                rva_read = current - LIB_BASE
                if RODATA_START <= rva_read < RODATA_END:
                    static.add(rva_read)
                    continue
                raise ValueError(
                    f"{case['name']}: unclassified read at {current:#x}, site {rva:#x}")
    return insns, static


def contiguous_ranges(values):
    values = sorted(values)
    if not values:
        return []
    groups = [[values[0]]]
    for value in values[1:]:
        if value == groups[-1][-1] + 1:
            groups[-1].append(value)
        else:
            groups.append([value])
    return [(group[0], len(group)) for group in groups]


def tables_rust(image, static):
    zero_page = {value for value in static if value < 0x1000}
    pages = sorted({value & ~0xFFF for value in static if value >= 0x1000})
    ranges = contiguous_ranges(zero_page)
    out = ["""// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0
//
// GENERATED by tools/transpile_end_tag.py. Static, non-executable lookup data.

//! Read-only data used by the End tag-round arithmetic core, not an Apple image.

pub(crate) static ZERO_PAGE_RANGES: &[(u32, &[u8])] = &[
"""]
    for start, length in ranges:
        data = image[start:start + length]
        out.append(f"    (0x{start:x}, &[\n        ")
        out.append(", ".join(f"0x{byte:02x}" for byte in data))
        out.append("\n    ]),\n")
    out.append("""];

""")
    for rva in pages:
        data = image[rva:rva + 0x1000]
        if len(data) != 0x1000:
            raise ValueError(f"truncated static page {rva:#x}")
        out.append(f"pub(crate) static PAGE_{rva:05X}: [u8; 4096] = [\n")
        for pos in range(0, len(data), 16):
            out.append("    " + ", ".join(f"0x{byte:02x}" for byte in data[pos:pos + 16]) + ",\n")
        out.append("];\n\n")
    out.append("""pub(crate) fn read8(address: u64) -> Option<u8> {
    let rva = address.checked_sub(super::end_tag_round_core::LIB_BASE)? as u32;
    if rva < 0x1000 {
        for &(start, bytes) in ZERO_PAGE_RANGES {
            if rva >= start && rva - start < bytes.len() as u32 {
                return Some(bytes[(rva - start) as usize]);
            }
        }
        return None;
    }
    let page = rva & !0xfff;
    let offset = (rva & 0xfff) as usize;
    let table: &[u8; 4096] = match page {
""")
    for rva in pages:
        out.append(f"        0x{rva:05x} => &PAGE_{rva:05X},\n")
    out.append("""        _ => return None,
    };
    Some(table[offset])
}
""")
    return "".join(out), len(ranges), len(pages)


def xmm_name(ins, index):
    op = ins.operands[index]
    if op.type != X86_OP_REG:
        raise ValueError(f"expected XMM register: {ins.op_str}")
    name = ins.reg_name(op.reg)
    if not name.startswith("xmm"):
        raise ValueError(f"expected XMM register: {ins.op_str}")
    return int(name[3:])


def xmm_read(ins, index):
    op = ins.operands[index]
    if op.type == X86_OP_REG:
        return f"s.xmm[{xmm_name(ins, index)}]"
    if op.type == X86_OP_MEM:
        return f"s.load128({address(ins, op)})"
    raise ValueError(f"unsupported XMM read: {ins.op_str}")


def xmm_write(ins, index, value="_v"):
    op = ins.operands[index]
    if op.type == X86_OP_REG:
        return [f"s.xmm[{xmm_name(ins, index)}] = {value};"]
    if op.type == X86_OP_MEM:
        raise ValueError(f"unmeasured 128-bit memory write: {ins.op_str}")
    raise ValueError(f"unsupported XMM write: {ins.op_str}")


def operand_is_xmm(ins, index):
    op = ins.operands[index]
    return op.type == X86_OP_REG and ins.reg_name(op.reg).startswith("xmm")


def emit_tag(ins):
    mn = ins.mnemonic
    if mn == "jmp":
        return ["// measured CFF dispatch; structured Rust supplies the successor"]
    if mn not in SSE_MNEMONICS:
        return emit(ins)
    if mn in SSE_BINARY:
        helper = "por" if mn == "orpd" else mn
        return [
            f"let _a = {xmm_read(ins, 0)};",
            f"let _b = {xmm_read(ins, 1)};",
            f"let _v = {helper}(_a, _b);",
        ] + xmm_write(ins, 0)
    if mn == "movdqa":
        return [f"let _v = {xmm_read(ins, 1)};"] + xmm_write(ins, 0)
    if mn in SSE_CONVERT:
        return [f"let _v = {mn}({xmm_read(ins, 1)});"] + xmm_write(ins, 0)
    if mn in SSE_SHIFT:
        if ins.operands[1].type == X86_OP_IMM:
            count = f"0x{ins.operands[1].imm:x}u64"
        else:
            count = f"qword(&{xmm_read(ins, 1)}, 0)"
        return [f"let _v = {mn}({xmm_read(ins, 0)}, {count});"] + xmm_write(ins, 0)
    if mn in ("pshufd", "shufps"):
        control = ins.operands[2].imm
        if mn == "pshufd":
            value = f"pshufd({xmm_read(ins, 1)}, 0x{control:x}u8)"
        else:
            value = f"shufps({xmm_read(ins, 0)}, {xmm_read(ins, 1)}, 0x{control:x}u8)"
        return [f"let _v = {value};"] + xmm_write(ins, 0)
    if mn == "punpckhdq":
        return [f"let _v = punpckhdq({xmm_read(ins, 0)}, {xmm_read(ins, 1)});"] + xmm_write(ins, 0)
    if mn == "blendvpd":
        # Capstone exposes the two explicit operands; the mask is implicit XMM0.
        return [f"let _v = blendvpd({xmm_read(ins, 0)}, {xmm_read(ins, 1)}, s.xmm[0]);"] + xmm_write(ins, 0)
    if mn in ("movq", "movd"):
        width = 64 if mn == "movq" else 32
        if operand_is_xmm(ins, 1):
            reader = "qword" if width == 64 else "dword"
            cast = "" if width == 64 else " as u64"
            return [f"let _v = {reader}(&{xmm_read(ins, 1)}, 0){cast};"] + write_op(ins, 0)
        constructor = "from_qword" if width == 64 else "from_dword"
        if operand_is_xmm(ins, 0):
            return [f"let _v = {constructor}({read_op(ins, 1)});"] + xmm_write(ins, 0)
        raise ValueError(f"mov has no XMM operand: {ins.op_str}")
    if mn in ("pextrq", "pextrd"):
        reader = "qword" if mn == "pextrq" else "dword"
        lane = ins.operands[2].imm
        cast = "" if mn == "pextrq" else " as u64"
        return [f"let _v = {reader}(&{xmm_read(ins, 1)}, {lane}){cast};"] + write_op(ins, 0)
    if mn in ("pinsrd", "pinsrw"):
        helper = "insert_dword" if mn == "pinsrd" else "insert_word"
        lane = ins.operands[2].imm
        return [f"let _v = {helper}({xmm_read(ins, 0)}, {lane}, {read_op(ins, 1)});"] + xmm_write(ins, 0)
    raise ValueError(f"unsupported tag instruction at {ins.address:#x}: {mn} {ins.op_str}")


def render_body(insns):
    body = []
    for ins in insns:
        body.append(f"        // {ins.address - LIB_BASE:#x}: {ins.mnemonic} {ins.op_str}")
        body.append(f"        s.site = 0x{ins.address - LIB_BASE:x};")
        body.append("        {")
        body.extend("            " + line for line in emit_tag(ins))
        body.append("        }")
    return "\n".join(body)


TEMPLATE = r'''// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0
//
// GENERATED by tools/transpile_end_tag.py. Regenerate; do not hand-edit.

//! Exact straight-line End tag round. No Apple machine code or runtime image.

use crate::end_tag_round::*;
use crate::end_tag_round_tables;

pub(crate) const LIB_BASE: u64 = 0x7ffff7679000;
const HEAP_ADDRESS: u64 = 0x7ffff78c8000;
const HEAP_LEN: usize = 0x4000;
const DATA_ADDRESS: u64 = 0x7ffff77fb000;
const DATA_LEN: usize = 0x5000;
const FRAME_LEN: usize = 0x500;
const OUTPUT_A_ADDRESS: u64 = 0x7ffff78cb300;
const OUTPUT_B_ADDRESS: u64 = 0x7ffff78c9500;
const OUTPUT_LEN: usize = 0x400;

/// Explicit semantic state at the start of the 64-round tag subcircuit.
#[derive(Clone)]
pub struct TagRoundState {
    pub registers: [u64; 16],
    pub xmm: [Xmm; 16],
    pub frame: Vec<u8>,
    pub heap: [u8; HEAP_LEN],
    pub data: [u8; DATA_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTagRoundFrame;

impl core::fmt::Display for InvalidTagRoundFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "End tag-round frame must be exactly {FRAME_LEN} bytes")
    }
}

impl std::error::Error for InvalidTagRoundFrame {}

impl TagRoundState {
    pub fn new(registers: [u64; 16], xmm: [Xmm; 16], frame: Vec<u8>, heap: [u8; HEAP_LEN], data: [u8; DATA_LEN]) -> Result<Self, InvalidTagRoundFrame> {
        if frame.len() != FRAME_LEN {
            return Err(InvalidTagRoundFrame);
        }
        Ok(Self { registers, xmm, frame, heap, data })
    }
}

#[derive(Clone, Default)]
struct Registers {
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rbp: u64, rsp: u64,
    r8: u64, r9: u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
}

struct TagRoundCore {
    regs: Registers,
    xmm: [Xmm; 16],
    site: u64,
    zf: bool,
    cf: bool,
    frame: Vec<u8>,
    heap: [u8; HEAP_LEN],
    data: [u8; DATA_LEN],
}

impl TagRoundCore {
    fn new(state: &TagRoundState) -> Self {
        let r = &state.registers;
        Self {
            regs: Registers {
                rax: r[0], rbx: r[1], rcx: r[2], rdx: r[3],
                rsi: r[4], rdi: r[5], rbp: r[6], rsp: r[7],
                r8: r[8], r9: r[9], r10: r[10], r11: r[11],
                r12: r[12], r13: r[13], r14: r[14], r15: r[15],
            },
            xmm: state.xmm,
            site: 0,
            zf: false,
            cf: false,
            frame: state.frame.clone(),
            heap: state.heap,
            data: state.data,
        }
    }

    fn finish(self, state: &mut TagRoundState) {
        let r = self.regs;
        state.registers = [
            r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.rsp,
            r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15,
        ];
        state.xmm = self.xmm;
        state.frame = self.frame;
        state.heap = self.heap;
    }

    fn read8(&self, address: u64) -> u8 {
        let bottom = self.regs.rbp.wrapping_sub(FRAME_LEN as u64);
        if address >= bottom && address < bottom + FRAME_LEN as u64 {
            return self.frame[(address - bottom) as usize];
        }
        if (HEAP_ADDRESS..HEAP_ADDRESS + HEAP_LEN as u64).contains(&address) {
            return self.heap[(address - HEAP_ADDRESS) as usize];
        }
        if (DATA_ADDRESS..DATA_ADDRESS + DATA_LEN as u64).contains(&address) {
            return self.data[(address - DATA_ADDRESS) as usize];
        }
        if let Some(byte) = end_tag_round_tables::read8(address) {
            return byte;
        }
        panic!("unclassified End tag-round read at {address:#x}, site {:#x}", self.site);
    }

    fn load(&self, address: u64, size: usize) -> u64 {
        assert!(matches!(size, 1 | 2 | 4 | 8));
        let mut bytes = [0u8; 8];
        for (index, slot) in bytes.iter_mut().enumerate().take(size) {
            *slot = self.read8(address.wrapping_add(index as u64));
        }
        u64::from_le_bytes(bytes)
    }

    fn load128(&self, address: u64) -> Xmm {
        let mut bytes = [0u8; 16];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = self.read8(address.wrapping_add(index as u64));
        }
        bytes
    }

    fn store(&mut self, address: u64, size: usize, value: u64) {
        assert!(matches!(size, 1 | 2 | 4 | 8));
        let bottom = self.regs.rbp.wrapping_sub(FRAME_LEN as u64);
        if address >= bottom && address + size as u64 <= bottom + FRAME_LEN as u64 {
            let offset = (address - bottom) as usize;
            self.frame[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
            return;
        }
        if address >= HEAP_ADDRESS && address + size as u64 <= HEAP_ADDRESS + HEAP_LEN as u64 {
            let offset = (address - HEAP_ADDRESS) as usize;
            self.heap[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
            return;
        }
        panic!("unclassified End tag-round write at {address:#x}, site {:#x}", self.site);
    }
}

#[inline]
fn mask(bits: u32) -> u64 {
    if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 }
}
#[inline] fn alu_add(bits: u32, a: u64, b: u64) -> u64 { a.wrapping_add(b) & mask(bits) }
#[inline] fn alu_xor(bits: u32, a: u64, b: u64) -> u64 { (a ^ b) & mask(bits) }
#[inline] fn alu_and(bits: u32, a: u64, b: u64) -> u64 { (a & b) & mask(bits) }

/// Execute the measured 321-instruction circuit exactly 64 times.
pub fn transform_tag_round(state: &mut TagRoundState) -> ([u8; OUTPUT_LEN], [u8; OUTPUT_LEN]) {
    let mut core = TagRoundCore::new(state);
    for _ in 0..64 {
        round_core(&mut core);
    }
    core.finish(state);
    let a_at = (OUTPUT_A_ADDRESS - HEAP_ADDRESS) as usize;
    let b_at = (OUTPUT_B_ADDRESS - HEAP_ADDRESS) as usize;
    (
        state.heap[a_at..a_at + OUTPUT_LEN].try_into().expect("first tag-round output"),
        state.heap[b_at..b_at + OUTPUT_LEN].try_into().expect("second tag-round output"),
    )
}

#[allow(clippy::all, unused_parens)]
fn round_core(s: &mut TagRoundCore) {
{{BODY}}
}
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--case1", required=True, help="name=case-dir")
    ap.add_argument("--case2", required=True, help="name=case-dir")
    ap.add_argument("--image", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--state-dir", required=True)
    args = ap.parse_args()
    cases = [load_case(args.case1), load_case(args.case2)]
    if [pc for pc, _, _ in cases[0]["trace"][:PERIOD_RECORDS]] != [pc for pc, _, _ in cases[1]["trace"][:PERIOD_RECORDS]]:
        raise ValueError("independent inputs execute different tag-round circuits")
    image = Path(args.image).read_bytes()
    decoded = [decode_and_census(case, image) for case in cases]
    insns = decoded[0][0]
    static = decoded[0][1] | decoded[1][1]
    if len(insns) != BLOCK_RECORDS:
        raise ValueError(f"decoded {len(insns)} instructions instead of {BLOCK_RECORDS}")
    audit_flags(insns)
    for ins in insns:
        emit_tag(ins)

    out_dir = Path(args.out_dir)
    tables, zero_ranges, pages = tables_rust(image, static)
    (out_dir / "end_tag_round_tables.rs").write_text(tables)
    (out_dir / "end_tag_round_core.rs").write_text(TEMPLATE.replace("{{BODY}}", render_body(insns)))

    state_dir = Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    for case in cases:
        xmm = b"".join(case["xmm"])
        blob = (struct.pack("<16Q", *case["registers"]) + xmm + case["frame"] +
                case["heap"] + case["data"] + case["expected_a"] + case["expected_b"])
        path = state_dir / (case["name"] + ".bin")
        path.write_bytes(blob)
        os.chmod(path, 0o600)
    print(f"transpiled {len(insns)} instructions, {zero_ranges} page-zero ranges and {pages} data pages")


if __name__ == "__main__":
    main()
