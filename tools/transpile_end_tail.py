#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0
"""Transpile measured End pre-tail/tail circuits to pure Rust.

Development oracle only. Two independent ptrace streams must execute the same
circuit: 137 instructions for pre-tail or 3,370 for tail. The generator emits no
Apple machine code, image, capture reads or expected output. Initial/final
semantic states are written only to a caller-selected private directory for
differential tests.
"""
import argparse
import os
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP

from transpile_planter import audit_flags, emit

LIB_BASE = 0x7FFFF7679000
TAIL_ADDRESS = 0x7FFFF78335B5
TAIL_LEN = 0x220
TAIL_STATE_LEN = 0x230
SOURCE_ADDRESS = 0x7FFFF7833800
SOURCE_LEN = 0x220
HEAP_ADDRESS = 0x7FFFF78C8000
HEAP_LEN = 0x4000
HEAP_SEED_BASE = 0x7FFFF77FF000
STACK_SEED_BASE = 0x7FFFFFFEF000
DATA_ADDRESS = 0x7FFFF77FB000
DATA_LEN = 0x5000
FRAME_LEN = 0x500
BLOCK_RECORDS = 3370
REQUIRED_RECORDS = 7002
PERIOD_RECORDS = 7002
ITERATIONS = 34
TRACE_BASENAME = "block.trace.bin"
MODE = "tail"
REGISTER_ORDER = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]
FULL_REGS = set(REGISTER_ORDER)
ALIAS32 = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
}
ALIAS16 = {
    "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
    "si": "rsi", "di": "rdi", "bp": "rbp", "sp": "rsp",
}
ALIAS8 = {
    "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
    "sil": "rsi", "dil": "rdi", "bpl": "rbp", "spl": "rsp",
}
HIGH8 = {"ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx"}


def reg_value(ins, values, reg):
    if reg == 0:
        return 0
    if reg == X86_REG_RIP:
        return ins.address + ins.size
    name = ins.reg_name(reg)
    if name in FULL_REGS:
        return values[REGISTER_ORDER.index(name)]
    if name in ALIAS32:
        return values[REGISTER_ORDER.index(ALIAS32[name])] & 0xFFFFFFFF
    if name in ALIAS16:
        return values[REGISTER_ORDER.index(ALIAS16[name])] & 0xFFFF
    if name in ALIAS8:
        return values[REGISTER_ORDER.index(ALIAS8[name])] & 0xFF
    if name in HIGH8:
        return (values[REGISTER_ORDER.index(HIGH8[name])] >> 8) & 0xFF
    if name.startswith("r") and name[-1:] in "bwd":
        parent = name[:-1]
        if parent in FULL_REGS:
            value = values[REGISTER_ORDER.index(parent)]
            return value & {"b": 0xFF, "w": 0xFFFF, "d": 0xFFFFFFFF}[name[-1]]
    raise ValueError(f"unknown register {name} at {ins.address:#x}")


def read_trace(path):
    data = Path(path).read_bytes()
    if len(data) != REQUIRED_RECORDS * 984:
        raise ValueError(f"{path}: expected {REQUIRED_RECORDS} records, got {len(data) // 984}")
    rows = []
    for at in range(0, len(data), 984):
        header = data[at:at + 152]
        rows.append((struct.unpack_from("<Q", header)[0],
                     struct.unpack_from("<16Q", header, 8)))
    return rows


def load_case(spec):
    name, paths = spec.split("=", 1)
    trace_dir, seed_dir, final_dir = paths.split(":")
    trace = read_trace(Path(trace_dir) / TRACE_BASENAME)
    if [pc for pc, _ in trace[:BLOCK_RECORDS]] != [pc for pc, _ in trace[BLOCK_RECORDS:2 * BLOCK_RECORDS]]:
        raise ValueError(f"{name}: first two circuit iterations have different PC streams")
    for at in range(BLOCK_RECORDS, PERIOD_RECORDS):
        if trace[at][0] != trace[at - BLOCK_RECORDS][0]:
            raise ValueError(f"{name}: circuit PC period differs at record {at}")
    registers, rbp = trace[0][1], trace[0][1][6]
    stack = (Path(seed_dir) / "stack.bin").read_bytes()
    heap = (Path(seed_dir) / "heap.bin").read_bytes()
    data = (Path(seed_dir) / "ca_rw.bin").read_bytes()
    if len(data) != DATA_LEN:
        raise ValueError(f"{name}: expected {DATA_LEN} CoreADI RW bytes")
    frame_start = rbp - FRAME_LEN
    frame = stack[frame_start - STACK_SEED_BASE:frame_start - STACK_SEED_BASE + FRAME_LEN]
    dynamic = heap[HEAP_ADDRESS - HEAP_SEED_BASE:HEAP_ADDRESS - HEAP_SEED_BASE + HEAP_LEN]
    tail_at = TAIL_ADDRESS - HEAP_SEED_BASE
    tail = heap[tail_at:tail_at + TAIL_STATE_LEN]
    source = heap[SOURCE_ADDRESS - HEAP_SEED_BASE:SOURCE_ADDRESS - HEAP_SEED_BASE + SOURCE_LEN] if MODE == "pretail" else b""
    final_path = (Path(seed_dir) / "mid.bin") if MODE == "pretail" else (Path(final_dir) / "adi-data/adi.pb")
    final = final_path.read_bytes()
    expected = final[0x35:0x35 + TAIL_LEN]
    if (len(frame) != FRAME_LEN or len(dynamic) != HEAP_LEN or len(tail) != TAIL_STATE_LEN or
            len(expected) != TAIL_LEN or (MODE == "pretail" and len(source) != SOURCE_LEN)):
        raise ValueError(f"{name}: truncated semantic state")
    return dict(name=name, trace=trace, registers=registers, rbp=rbp,
                frame=frame, heap=dynamic, data=data, source=source, tail=tail, expected=expected)


def decode_and_census(case, image):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = []
    pages = set()
    for ip, registers in case["trace"][:BLOCK_RECORDS]:
        rva = ip - LIB_BASE
        ins = next(md.disasm(image[rva:rva + 15], ip, count=1), None)
        if ins is None:
            raise ValueError(f"cannot decode {rva:#x}")
        if ins.mnemonic in ("call", "ret") or (ins.mnemonic.startswith("j") and ins.mnemonic != "jmp"):
            raise ValueError(f"unsupported tail control flow at {rva:#x}")
        for op in ins.operands:
            if op.type != X86_OP_MEM or not (op.access & 1):
                continue
            address = op.mem.disp
            if op.mem.base:
                address += reg_value(ins, registers, op.mem.base)
            if op.mem.index:
                address += reg_value(ins, registers, op.mem.index) * op.mem.scale
            address &= 0xFFFFFFFFFFFFFFFF
            if (LIB_BASE <= address < LIB_BASE + len(image) and
                    not DATA_ADDRESS <= address < DATA_ADDRESS + DATA_LEN):
                pages.add((address - LIB_BASE) & ~0xFFF)
        insns.append(ins)
    return insns, sorted(pages)


def tables_rust(image, pages):
    out = ["""// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0
//
// GENERATED by tools/transpile_end_tail.py. Static, non-executable lookup data.

//! Read-only tables used by the End tail arithmetic core, not an Apple image.

"""]
    for rva in pages:
        data = image[rva:rva + 0x1000]
        if rva >= 0x186168:
            raise ValueError(f"static page {rva:#x} is outside the measured image")
        # The last page includes the zero-initialized BSS tail.
        data = data + bytes(0x1000 - len(data))
        out.append("pub(crate) static PAGE_%05X: [u8; 4096] = [\n" % rva)
        for pos in range(0, len(data), 16):
            out.append("    " + ", ".join("0x%02x" % b for b in data[pos:pos + 16]) + ",\n")
        out.append("];\n\n")
    out.append("pub(crate) fn read8(address: u64) -> Option<u8> {\n")
    prefix = "end_pretail" if MODE == "pretail" else "end_tail"
    out.append(f"    let rva = address.checked_sub(super::{prefix}_core::LIB_BASE)?;\n")
    out.append("    let page = rva & !0xfff;\n")
    out.append("    let offset = (rva & 0xfff) as usize;\n")
    out.append("    let table: &[u8; 4096] = match page {\n")
    for rva in pages:
        out.append("        0x%05x => &PAGE_%05X,\n" % (rva, rva))
    out.append("        _ => return None,\n    };\n    Some(table[offset])\n}\n")
    return "".join(out)


def emit_tail(ins):
    if ins.mnemonic == "jmp":
        return ["// measured CFF dispatch; structured Rust supplies the successor"]
    return emit(ins)


def render_body(insns):
    body = []
    for ins in insns:
        body.append("        // %#x: %s %s" % (ins.address - LIB_BASE, ins.mnemonic, ins.op_str))
        body.append("        s.site = 0x%x;" % (ins.address - LIB_BASE))
        body.append("        {")
        body.extend("            " + line for line in emit_tail(ins))
        body.append("        }")
    return "\n".join(body)


TEMPLATE = r'''// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0
//
// GENERATED by tools/transpile_end_tail.py. Regenerate; do not hand-edit.

//! Exact straight-line End tail block. No Apple machine code or runtime image.

use crate::end_tail_tables;

pub(crate) const LIB_BASE: u64 = 0x7ffff7679000;
const TAIL_ADDRESS: u64 = 0x7ffff78335b5;
const TAIL_LEN: usize = 0x230;
const OUTPUT_LEN: usize = 0x220;
const HEAP_ADDRESS: u64 = 0x7ffff78c8000;
const HEAP_LEN: usize = 0x4000;
const DATA_ADDRESS: u64 = 0x7ffff77fb000;
const DATA_LEN: usize = 0x5000;
const FRAME_LEN: usize = 0x500;

/// Explicit semantic state at the start of one 34-block tail transformation.
/// Genesis of this state from provisioning inputs is a separate boundary.
#[derive(Clone)]
pub struct TailState {
    pub registers: [u64; 16],
    pub frame: Vec<u8>,
    pub heap: [u8; HEAP_LEN],
    pub data: [u8; DATA_LEN],
    pub tail: [u8; TAIL_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTailFrame;

impl core::fmt::Display for InvalidTailFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "End tail frame must be exactly {FRAME_LEN} bytes")
    }
}

impl std::error::Error for InvalidTailFrame {}

impl TailState {
    pub fn new(registers: [u64; 16], frame: Vec<u8>, heap: [u8; HEAP_LEN], data: [u8; DATA_LEN], tail: [u8; TAIL_LEN]) -> Result<Self, InvalidTailFrame> {
        if frame.len() != FRAME_LEN {
            return Err(InvalidTailFrame);
        }
        Ok(Self { registers, frame, heap, data, tail })
    }
}

#[derive(Clone, Default)]
struct Registers {
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rbp: u64, rsp: u64,
    r8: u64, r9: u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
}

struct TailCore {
    regs: Registers,
    site: u64,
    zf: bool,
    cf: bool,
    frame: Vec<u8>,
    heap: [u8; HEAP_LEN],
    data: [u8; DATA_LEN],
    tail: [u8; TAIL_LEN],
}

impl TailCore {
    fn new(state: &TailState) -> Self {
        let r = &state.registers;
        Self {
            regs: Registers {
                rax: r[0], rbx: r[1], rcx: r[2], rdx: r[3],
                rsi: r[4], rdi: r[5], rbp: r[6], rsp: r[7],
                r8: r[8], r9: r[9], r10: r[10], r11: r[11],
                r12: r[12], r13: r[13], r14: r[14], r15: r[15],
            },
            site: 0,
            zf: false,
            cf: false,
            frame: state.frame.clone(),
            heap: state.heap,
            data: state.data,
            tail: state.tail,
        }
    }

    fn finish(self, state: &mut TailState) {
        let r = self.regs;
        state.registers = [
            r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.rsp,
            r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15,
        ];
        state.frame = self.frame;
        state.tail = self.tail;
    }

    fn read8(&self, address: u64) -> u8 {
        let bottom = self.regs.rbp.wrapping_sub(FRAME_LEN as u64);
        if address >= bottom && address < bottom + FRAME_LEN as u64 {
            return self.frame[(address - bottom) as usize];
        }
        if (HEAP_ADDRESS..HEAP_ADDRESS + HEAP_LEN as u64).contains(&address) {
            return self.heap[(address - HEAP_ADDRESS) as usize];
        }
        if (TAIL_ADDRESS..TAIL_ADDRESS + TAIL_LEN as u64).contains(&address) {
            return self.tail[(address - TAIL_ADDRESS) as usize];
        }
        if (DATA_ADDRESS..DATA_ADDRESS + DATA_LEN as u64).contains(&address) {
            return self.data[(address - DATA_ADDRESS) as usize];
        }
        if let Some(byte) = end_tail_tables::read8(address) {
            return byte;
        }
        panic!("unclassified End tail read at {address:#x}, site {:#x}", self.site);
    }

    fn load(&self, address: u64, size: usize) -> u64 {
        assert!(matches!(size, 1 | 2 | 4 | 8));
        let mut bytes = [0u8; 8];
        for (i, slot) in bytes.iter_mut().enumerate().take(size) {
            *slot = self.read8(address.wrapping_add(i as u64));
        }
        u64::from_le_bytes(bytes)
    }

    fn store(&mut self, address: u64, size: usize, value: u64) {
        assert!(matches!(size, 1 | 2 | 4 | 8));
        let bottom = self.regs.rbp.wrapping_sub(FRAME_LEN as u64);
        if address >= bottom && address + size as u64 <= bottom + FRAME_LEN as u64 {
            let offset = (address - bottom) as usize;
            self.frame[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
            return;
        }
        if address >= TAIL_ADDRESS && address + size as u64 <= TAIL_ADDRESS + TAIL_LEN as u64 {
            let offset = (address - TAIL_ADDRESS) as usize;
            self.tail[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
            return;
        }
        panic!("unclassified End tail write at {address:#x}, site {:#x}", self.site);
    }
}

#[inline]
fn mask(bits: u32) -> u64 {
    if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 }
}
#[inline] fn alu_add(bits: u32, a: u64, b: u64) -> u64 { a.wrapping_add(b) & mask(bits) }
#[inline] fn alu_sub(bits: u32, a: u64, b: u64) -> u64 { a.wrapping_sub(b) & mask(bits) }
#[inline] fn alu_mul(bits: u32, a: u64, b: u64) -> u64 { a.wrapping_mul(b) & mask(bits) }
#[inline] fn alu_xor(bits: u32, a: u64, b: u64) -> u64 { (a ^ b) & mask(bits) }
#[inline] fn alu_and(bits: u32, a: u64, b: u64) -> u64 { (a & b) & mask(bits) }
#[inline] fn alu_or(bits: u32, a: u64, b: u64) -> u64 { (a | b) & mask(bits) }
#[inline]
fn shift_count(bits: u32, count: u64) -> u32 {
    (count & if bits == 64 { 63 } else { 31 }) as u32
}
#[inline]
fn alu_shl(bits: u32, a: u64, b: u64) -> u64 {
    ((a & mask(bits)) << shift_count(bits, b)) & mask(bits)
}
#[inline]
fn alu_shr(bits: u32, a: u64, b: u64) -> u64 {
    (a & mask(bits)) >> shift_count(bits, b)
}
/// Execute the same measured circuit over all 34 sixteen-byte blocks.
pub fn transform_tail(state: &mut TailState) -> [u8; OUTPUT_LEN] {
    let mut core = TailCore::new(state);
    for _ in 0..34 {
        block_core(&mut core);
    }
    core.finish(state);
    state.tail[..OUTPUT_LEN].try_into().expect("544-byte End tail output")
}

#[allow(clippy::all, unused_parens)]
fn block_core(s: &mut TailCore) {
{{BODY}}
}
'''


def render_core(insns):
    text = TEMPLATE.replace("{{BODY}}", render_body(insns))
    if MODE == "pretail":
        text = text.replace("end_tail", "end_pretail")
        text = text.replace("End tail", "End pre-tail")
        text = text.replace("TailState", "PretailState")
        text = text.replace("TailCore", "PretailCore")
        text = text.replace("InvalidTailFrame", "InvalidPretailFrame")
        text = text.replace("transform_tail", "transform_pretail")
        text = text.replace("GENERATED by tools/transpile_end_pretail.py", "GENERATED by tools/transpile_end_tail.py")
        text = text.replace("one 34-block tail transformation", "one 544-iteration pre-tail transformation")
        text = text.replace("for _ in 0..34", "for _ in 0..543")
        text = text.replace("    core.finish(state);", "    last_core(&mut core);\n    core.finish(state);")
        text = text.replace("all 34 sixteen-byte blocks", "all 544 one-byte iterations")
        text = text.replace("34-block transformation", "544-iteration transformation")
        text = text.replace(
            "Execute the same measured circuit over all 544 one-byte iterations.",
            "Execute 543 full one-byte circuits and the final measured store.",
        )
        text = text.replace(
            "const OUTPUT_LEN: usize = 0x220;",
            "const OUTPUT_LEN: usize = 0x220;\nconst SOURCE_ADDRESS: u64 = 0x7ffff7833800;\nconst SOURCE_LEN: usize = 0x220;",
        )
        text = text.replace(
            "    pub tail: [u8; TAIL_LEN],",
            "    pub source: [u8; SOURCE_LEN],\n    pub tail: [u8; TAIL_LEN],",
        )
        text = text.replace(
            "    tail: [u8; TAIL_LEN],",
            "    source: [u8; SOURCE_LEN],\n    tail: [u8; TAIL_LEN],",
        )
        text = text.replace(
            "heap: [u8; HEAP_LEN], data: [u8; DATA_LEN], tail: [u8; TAIL_LEN]",
            "heap: [u8; HEAP_LEN], data: [u8; DATA_LEN], source: [u8; SOURCE_LEN], tail: [u8; TAIL_LEN]",
        )
        text = text.replace(
            "Ok(Self { registers, frame, heap, data, tail })",
            "Ok(Self { registers, frame, heap, data, source, tail })",
        )
        text = text.replace(
            "            data: state.data,\n            tail: state.tail,",
            "            data: state.data,\n            source: state.source,\n            tail: state.tail,",
        )
        text = text.replace(
            "        if (TAIL_ADDRESS..TAIL_ADDRESS + TAIL_LEN as u64).contains(&address) {",
            "        if (SOURCE_ADDRESS..SOURCE_ADDRESS + SOURCE_LEN as u64).contains(&address) {\n            return self.source[(address - SOURCE_ADDRESS) as usize];\n        }\n        if (TAIL_ADDRESS..TAIL_ADDRESS + TAIL_LEN as u64).contains(&address) {",
        )
        text = text.replace(
            "#[inline] fn alu_or(bits: u32, a: u64, b: u64) -> u64 { (a | b) & mask(bits) }\n",
            "",
        )
        text += ("\n#[allow(clippy::all, unused_parens)]\n"
                 "fn last_core(s: &mut PretailCore) {\n" +
                 render_body(insns[:1]) + "\n}\n")
    return text


def main():
    global MODE, BLOCK_RECORDS, REQUIRED_RECORDS, PERIOD_RECORDS, ITERATIONS, TRACE_BASENAME
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["tail", "pretail"], default="tail")
    ap.add_argument("--case1", required=True, help="name=trace-dir:seed-dir:final-dir")
    ap.add_argument("--case2", required=True, help="name=trace-dir:seed-dir:final-dir")
    ap.add_argument("--image", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--state-dir", required=True)
    args = ap.parse_args()
    MODE = args.mode
    if MODE == "pretail":
        BLOCK_RECORDS = 137
        REQUIRED_RECORDS = 75002
        PERIOD_RECORDS = 74506
        ITERATIONS = 544
        TRACE_BASENAME = "pretail.trace.bin"
    cases = [load_case(args.case1), load_case(args.case2)]
    if [pc for pc, _ in cases[0]["trace"][:BLOCK_RECORDS]] != [pc for pc, _ in cases[1]["trace"][:BLOCK_RECORDS]]:
        raise ValueError("independent inputs execute different tail circuits")
    image = Path(args.image).read_bytes()
    decoded = [decode_and_census(case, image) for case in cases]
    if decoded[0][1] != decoded[1][1]:
        raise ValueError("independent inputs use different static pages")
    insns, pages = decoded[0]
    audit_flags(insns)
    for ins in insns:
        emit_tail(ins)

    out_dir = Path(args.out_dir)
    prefix = "end_pretail" if MODE == "pretail" else "end_tail"
    tables = tables_rust(image, pages)
    if MODE == "pretail":
        tables = tables.replace("End tail", "End pre-tail")
    (out_dir / f"{prefix}_tables.rs").write_text(tables)
    (out_dir / f"{prefix}_core.rs").write_text(render_core(insns))
    state_dir = Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    for case in cases:
        blob = (struct.pack("<16Q", *case["registers"]) + case["frame"] + case["heap"] +
                case["data"] + case["source"] + case["tail"] + case["expected"])
        path = state_dir / (case["name"] + ".bin")
        path.write_bytes(blob)
        os.chmod(path, 0o600)
    print("transpiled", len(insns), "instructions and", len(pages), "data pages")


if __name__ == "__main__":
    main()
