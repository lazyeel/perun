#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0
"""Transpile one measured End middle-tag stage to pure Rust.

Development oracle only. Record boundaries select a small semantic circuit from
0x149170. Initial and final semantic states are emitted only into a private
caller-selected directory for differential tests; production receives no
capture, expected output, Apple image or native subprocess.
"""

import argparse
import os
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM

from transpile_end_tail import LIB_BASE
from transpile_end_tag import (
    DATA_ADDRESS, DATA_LEN, HEAP_ADDRESS, HEAP_LEN,
    HEAP_SEED_BASE, STACK_SEED_BASE, RODATA_START, RODATA_END, REC, TREC, XMM_OFF,
    effective_address, is_write_only_destination, tables_rust, emit_tag, render_body,
)
from transpile_planter import audit_flags

TRACE_RECORDS = 52066
FRAME_LEN = 0x700
TAG_ADDRESS = 0x7FFFF78337D5
TAG_LEN = 16


def trace_record(path, index):
    with Path(path).open("rb") as handle:
        handle.seek(index * REC)
        data = handle.read(REC)
    if len(data) != REC:
        raise ValueError(f"{path}: missing record {index}")
    return (struct.unpack_from("<Q", data)[0], struct.unpack_from("<16Q", data, 8),
            [data[TREC + XMM_OFF + i * 16:TREC + XMM_OFF + (i + 1) * 16] for i in range(16)])


def trace_pcs(path, start, end):
    pcs = []
    with Path(path).open("rb") as handle:
        handle.seek(start * REC)
        for _ in range(end - start):
            header = handle.read(TREC)
            if len(header) != TREC:
                raise ValueError(f"{path}: truncated PC stream")
            pcs.append(struct.unpack_from("<Q", header)[0])
            handle.seek(REC - TREC, 1)
    return pcs


def load_case(spec, start, end):
    name, path = spec.split("=", 1)
    root = Path(path)
    trace = root / "end-serializer.trace.bin"
    if trace.stat().st_size != TRACE_RECORDS * REC:
        raise ValueError(f"{name}: expected {TRACE_RECORDS} records")
    first = trace_record(trace, start)
    last = trace_record(trace, end)
    stack = (root / "stack.bin").read_bytes()
    expected_stack = (root / "expected_stack.bin").read_bytes()
    heap_file = (root / "heap.bin").read_bytes()
    expected_heap_file = (root / "expected_heap.bin").read_bytes()
    data = (root / "ca_rw.bin").read_bytes()
    expected_data = (root / "expected_ca_rw.bin").read_bytes()
    rbp = first[1][6]
    frame_start = rbp - FRAME_LEN
    frame = stack[frame_start - STACK_SEED_BASE:frame_start - STACK_SEED_BASE + FRAME_LEN]
    expected_frame = expected_stack[frame_start - STACK_SEED_BASE:frame_start - STACK_SEED_BASE + FRAME_LEN]
    heap_at = HEAP_ADDRESS - HEAP_SEED_BASE
    heap = heap_file[heap_at:heap_at + HEAP_LEN]
    expected_heap = expected_heap_file[heap_at:heap_at + HEAP_LEN]
    tag_at = TAG_ADDRESS - HEAP_SEED_BASE
    tag = heap_file[tag_at:tag_at + TAG_LEN]
    expected_tag = expected_heap_file[tag_at:tag_at + TAG_LEN]
    if (len(frame) != FRAME_LEN or len(expected_frame) != FRAME_LEN or
            len(heap) != HEAP_LEN or len(expected_heap) != HEAP_LEN or
            len(data) != DATA_LEN or len(expected_data) != DATA_LEN or
            len(tag) != TAG_LEN or len(expected_tag) != TAG_LEN):
        raise ValueError(f"{name}: truncated semantic state")
    return dict(name=name, root=root, trace=trace, first=first, last=last,
                frame=frame, expected_frame=expected_frame,
                heap=heap, expected_heap=expected_heap,
                data=data, expected_data=expected_data,
                tag=tag, expected_tag=expected_tag,
                pcs=trace_pcs(trace, start, end))


def decode_and_census(case, start, end, image):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = []
    static = set()
    rbp = case["first"][1][6]
    with case["trace"].open("rb") as handle:
        handle.seek(start * REC)
        for _ in range(end - start):
            header = handle.read(TREC)
            handle.seek(REC - TREC, 1)
            ip = struct.unpack_from("<Q", header)[0]
            registers = struct.unpack_from("<16Q", header, 8)
            rva = ip - LIB_BASE
            ins = next(md.disasm(image[rva:rva + 15], ip, count=1), None)
            if ins is None:
                raise ValueError(f"cannot decode {rva:#x}")
            if ins.mnemonic in ("call", "ret") or (ins.mnemonic.startswith("j") and ins.mnemonic != "jmp"):
                raise ValueError(f"unsupported middle-stage control flow at {rva:#x}")
            insns.append(ins)
            if ins.mnemonic == "lea":
                continue
            for op_index, op in enumerate(ins.operands):
                if op.type != X86_OP_MEM or not (op.access & 1):
                    continue
                if is_write_only_destination(ins, op_index, op):
                    continue
                address = effective_address(ins, registers, op)
                for byte_index in range(op.size):
                    current = (address + byte_index) & 0xFFFFFFFFFFFFFFFF
                    if rbp - FRAME_LEN <= current < rbp:
                        continue
                    if HEAP_ADDRESS <= current < HEAP_ADDRESS + HEAP_LEN:
                        continue
                    if DATA_ADDRESS <= current < DATA_ADDRESS + DATA_LEN:
                        continue
                    if TAG_ADDRESS <= current < TAG_ADDRESS + TAG_LEN:
                        continue
                    rva_read = current - LIB_BASE
                    if RODATA_START <= rva_read < RODATA_END:
                        static.add(rva_read)
                        continue
                    raise ValueError(f"{case['name']}: unclassified read {current:#x} at {rva:#x}")
    return insns, static


TEMPLATE = r'''// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0
//
// GENERATED by tools/transpile_end_middle.py. Regenerate; do not hand-edit.

//! Exact straight-line End middle-tag stage. No Apple image or capture input.

use crate::end_tag_round::*;
use crate::{{PREFIX}}_tables;

pub(crate) const LIB_BASE: u64 = 0x7ffff7679000;
const HEAP_ADDRESS: u64 = 0x7ffff78c8000;
const HEAP_LEN: usize = 0x4000;
const DATA_ADDRESS: u64 = 0x7ffff77fb000;
const DATA_LEN: usize = 0x5000;
const FRAME_LEN: usize = 0x700;
const TAG_ADDRESS: u64 = 0x7ffff78337d5;
const TAG_LEN: usize = 16;

#[derive(Clone)]
pub struct {{STATE}} {
    pub registers: [u64; 16],
    pub xmm: [Xmm; 16],
    pub frame: Vec<u8>,
    pub heap: [u8; HEAP_LEN],
    pub data: [u8; DATA_LEN],
    pub tag: [u8; TAG_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid{{STATE}}Frame;

impl core::fmt::Display for Invalid{{STATE}}Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "End middle-stage frame must be exactly {FRAME_LEN} bytes")
    }
}

impl std::error::Error for Invalid{{STATE}}Frame {}

impl {{STATE}} {
    pub fn new(registers: [u64; 16], xmm: [Xmm; 16], frame: Vec<u8>, heap: [u8; HEAP_LEN], data: [u8; DATA_LEN], tag: [u8; TAG_LEN]) -> Result<Self, Invalid{{STATE}}Frame> {
        if frame.len() != FRAME_LEN {
            return Err(Invalid{{STATE}}Frame);
        }
        Ok(Self { registers, xmm, frame, heap, data, tag })
    }
}

#[derive(Clone, Default)]
struct Registers {
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rbp: u64, rsp: u64,
    r8: u64, r9: u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
}

struct {{CORE}} {
    regs: Registers,
    xmm: [Xmm; 16],
    site: u64,
    #[allow(dead_code)]
    zf: bool,
    #[allow(dead_code)]
    cf: bool,
    frame: Vec<u8>,
    heap: [u8; HEAP_LEN],
    data: [u8; DATA_LEN],
    tag: [u8; TAG_LEN],
}

impl {{CORE}} {
    fn new(state: &{{STATE}}) -> Self {
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
            tag: state.tag,
        }
    }

    fn finish(self, state: &mut {{STATE}}) {
        let r = self.regs;
        state.registers = [
            r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.rsp,
            r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15,
        ];
        state.xmm = self.xmm;
        state.frame = self.frame;
        state.heap = self.heap;
        state.data = self.data;
        state.tag = self.tag;
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
        if (TAG_ADDRESS..TAG_ADDRESS + TAG_LEN as u64).contains(&address) {
            return self.tag[(address - TAG_ADDRESS) as usize];
        }
        if let Some(byte) = {{PREFIX}}_tables::read8(address) {
            return byte;
        }
        panic!("unclassified End middle-stage read at {address:#x}, site {:#x}", self.site);
    }

    fn load(&self, address: u64, size: usize) -> u64 {
        assert!(matches!(size, 1 | 2 | 4 | 8));
        let mut bytes = [0u8; 8];
        for (index, slot) in bytes.iter_mut().enumerate().take(size) {
            *slot = self.read8(address.wrapping_add(index as u64));
        }
        u64::from_le_bytes(bytes)
    }

    #[allow(dead_code)]
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
        if address >= TAG_ADDRESS && address + size as u64 <= TAG_ADDRESS + TAG_LEN as u64 {
            let offset = (address - TAG_ADDRESS) as usize;
            self.tag[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
            return;
        }
        panic!("unclassified End middle-stage write at {address:#x}, site {:#x}", self.site);
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
#[inline] fn shift_count(bits: u32, count: u64) -> u32 { (count & if bits == 64 { 63 } else { 31 }) as u32 }
#[inline] fn alu_shl(bits: u32, a: u64, b: u64) -> u64 { ((a & mask(bits)) << shift_count(bits, b)) & mask(bits) }
#[inline] fn alu_shr(bits: u32, a: u64, b: u64) -> u64 { (a & mask(bits)) >> shift_count(bits, b) }
#[inline] fn alu_rol(bits: u32, a: u64, b: u64) -> u64 {
    let count = shift_count(bits, b);
    let value = a & mask(bits);
    ((value << count) | (value >> ((bits - count) % bits))) & mask(bits)
}

pub fn {{FUNCTION}}(state: &mut {{STATE}}) {
    let mut core = {{CORE}}::new(state);
    block_core(&mut core);
    core.finish(state);
}

#[allow(clippy::all, unused_parens)]
fn block_core(s: &mut {{CORE}}) {
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
    ap.add_argument("--start-record", type=int, required=True)
    ap.add_argument("--end-record", type=int, required=True)
    ap.add_argument("--prefix", required=True, help="for example end_tag_middle0")
    args = ap.parse_args()
    start, end = args.start_record, args.end_record
    if not 0 <= start < end <= TRACE_RECORDS:
        raise ValueError("invalid record boundaries")
    cases = [load_case(spec, start, end) for spec in (args.case1, args.case2)]
    if cases[0]["pcs"] != cases[1]["pcs"]:
        raise ValueError("independent inputs execute different middle-stage PCs")
    image = Path(args.image).read_bytes()
    decoded = [decode_and_census(case, start, end, image) for case in cases]
    insns = decoded[0][0]
    static = decoded[0][1] | decoded[1][1]
    audit_flags(insns)
    for ins in insns:
        emit_tag(ins)
    tables, zero_ranges, pages = tables_rust(image, static)
    tables = tables.replace("super::end_tag_round_core::LIB_BASE", f"super::{args.prefix}_core::LIB_BASE")
    out_dir = Path(args.out_dir)
    (out_dir / f"{args.prefix}_tables.rs").write_text(tables)
    text = TEMPLATE.replace("{{PREFIX}}", args.prefix)
    text = text.replace("{{STATE}}", "TagMiddle0State" if args.prefix == "end_tag_middle0" else "TagMiddleState")
    text = text.replace("{{CORE}}", "TagMiddle0Core" if args.prefix == "end_tag_middle0" else "TagMiddleCore")
    text = text.replace("{{FUNCTION}}", f"transform_{args.prefix.removeprefix('end_')}")
    text = text.replace("{{BODY}}", render_body(insns))
    used = {ins.mnemonic for ins in insns}
    for helper, mnemonic in [("alu_or", "or"), ("alu_mul", "imul"),
                             ("alu_add", "add"), ("alu_sub", "sub"),
                             ("alu_xor", "xor"), ("alu_and", "and")]:
        if mnemonic not in used:
            marker = f"#[inline] fn {helper}("
            text = "\n".join(line for line in text.split("\n") if not line.startswith(marker))
    for helper, mnemonic in [("alu_shl", "shl"), ("alu_shr", "shr")]:
        if mnemonic not in used:
            marker = f"#[inline] fn {helper}("
            text = "\n".join(line for line in text.split("\n") if not line.startswith(marker))
    if not used.intersection({"rol", "shl", "shr"}):
        text = text.replace("#[inline] fn shift_count(bits: u32, count: u64) -> u32 { (count & if bits == 64 { 63 } else { 31 }) as u32 }\n", "")
    if "rol" not in used:
        text = text.replace(
            "#[inline] fn alu_rol(bits: u32, a: u64, b: u64) -> u64 {\n"
            "    let count = shift_count(bits, b);\n"
            "    let value = a & mask(bits);\n"
            "    ((value << count) | (value >> ((bits - count) % bits))) & mask(bits)\n}\n",
            "",
        )
    (out_dir / f"{args.prefix}_core.rs").write_text(text)

    state_dir = Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    for case in cases:
        first, last = case["first"], case["last"]
        initial = (struct.pack("<16Q", *first[1]) + b"".join(first[2]) + case["frame"] +
                   case["heap"] + case["data"] + case["tag"])
        expected = (struct.pack("<16Q", *last[1]) + b"".join(last[2]) + case["expected_frame"] +
                    case["expected_heap"] + case["expected_data"] + case["expected_tag"])
        path = state_dir / (case["name"] + ".bin")
        path.write_bytes(initial + expected)
        os.chmod(path, 0o600)
    print(f"transpiled {len(insns)} instructions, {zero_ranges} page-zero ranges and {pages} data pages")


if __name__ == "__main__":
    main()
