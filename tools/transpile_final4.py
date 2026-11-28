#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0
"""Transpile the measured 20-iteration final-four producer to pure Rust.

Development oracle only. Each case supplies its own record boundaries and
same-process initial/final stacks. The generated core has no capture reads,
expected output, Apple image or native subprocess.
"""

import argparse
import os
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM

from transpile_end_tail import LIB_BASE
from transpile_end_tag import (
    REC, TREC, STACK_SEED_BASE, RODATA_START, RODATA_END,
    effective_address, is_write_only_destination, tables_rust, emit_tag, render_body,
)
from transpile_end_middle import trace_record, trace_pcs
from transpile_planter import audit_flags

FRAME_LEN = 0x700
TAIL_LEN = 20
SOURCE_LEN = 20
TAIL_RBP_OFFSET = 0x43D0
STORE_RVA = 0xB7E6B
ITERATIONS = 20
BLOCK_RECORDS = 28


def load_case(spec):
    name, payload = spec.split("=", 1)
    path, start, end = payload.rsplit(":", 2)
    start, end = int(start), int(end)
    root = Path(path)
    trace = root / "gap.trace.bin"
    first = trace_record(trace, start)
    last = trace_record(trace, end)
    stack = (root / "stack.bin").read_bytes()
    expected_stack = (root / "expected_stack.bin").read_bytes()
    rbp = first[1][6]
    frame_start = rbp - FRAME_LEN
    frame = stack[frame_start - STACK_SEED_BASE:frame_start - STACK_SEED_BASE + FRAME_LEN]
    expected_frame = expected_stack[frame_start - STACK_SEED_BASE:frame_start - STACK_SEED_BASE + FRAME_LEN]
    tail_address = rbp - TAIL_RBP_OFFSET
    tail_at = tail_address - STACK_SEED_BASE
    tail = stack[tail_at:tail_at + TAIL_LEN]
    expected_tail = expected_stack[tail_at:tail_at + TAIL_LEN]
    source_at = tail_at + 0x20
    source = stack[source_at:source_at + SOURCE_LEN]
    expected_source = expected_stack[source_at:source_at + SOURCE_LEN]
    final4 = (root / "cap/adi-state-after-end.bin").read_bytes()[0x265:0x269]
    if (len(frame) != FRAME_LEN or len(expected_frame) != FRAME_LEN or
            len(tail) != TAIL_LEN or len(expected_tail) != TAIL_LEN or
            len(source) != SOURCE_LEN or len(expected_source) != SOURCE_LEN or
            len(final4) != 4):
        raise ValueError(f"{name}: truncated semantic state")
    if expected_tail[16:20] != final4:
        raise ValueError(f"{name}: output does not contain the native final-four word")
    return dict(name=name, root=root, trace=trace, first=first, last=last,
                frame=frame, expected_frame=expected_frame,
                tail=tail, expected_tail=expected_tail,
                source=source, expected_source=expected_source, final4=final4,
                start=start, end=end, tail_address=tail_address,
                pcs=trace_pcs(trace, start, end))


def decode_and_census(case, image):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = []
    static = set()
    rbp = case["first"][1][6]
    with case["trace"].open("rb") as handle:
        handle.seek(case["start"] * REC)
        for _ in range(case["end"] - case["start"]):
            header = handle.read(TREC)
            handle.seek(REC - TREC, 1)
            ip = struct.unpack_from("<Q", header)[0]
            registers = struct.unpack_from("<16Q", header, 8)
            rva = ip - LIB_BASE
            ins = next(md.disasm(image[rva:rva + 15], ip, count=1), None)
            if ins is None:
                raise ValueError(f"cannot decode {rva:#x}")
            if ins.mnemonic in ("call", "ret") or (ins.mnemonic.startswith("j") and ins.mnemonic != "jmp"):
                raise ValueError(f"unsupported final-four control flow at {rva:#x}")
            if len(insns) < BLOCK_RECORDS:
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
                    if case["tail_address"] <= current < case["tail_address"] + TAIL_LEN:
                        continue
                    source_address = case["tail_address"] + 0x20
                    if source_address <= current < source_address + SOURCE_LEN:
                        continue
                    rva_read = current - LIB_BASE
                    if RODATA_START <= rva_read < RODATA_END:
                        static.add(rva_read)
                        continue
                    raise ValueError(f"{case['name']}: unclassified read {current:#x} at {rva:#x}")
    return insns, static


def validate_case(case, image):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    ins = next(md.disasm(image[STORE_RVA:STORE_RVA + 15], LIB_BASE + STORE_RVA, count=1), None)
    op = ins.operands[0]
    addresses = []
    with case["trace"].open("rb") as handle:
        handle.seek(case["start"] * REC)
        for _ in range(ITERATIONS * BLOCK_RECORDS):
            header = handle.read(TREC)
            handle.seek(REC - TREC, 1)
            ip = struct.unpack_from("<Q", header)[0]
            if ip != LIB_BASE + STORE_RVA:
                continue
            registers = struct.unpack_from("<16Q", header, 8)
            addresses.append(effective_address(ins, registers, op))
    if len(addresses) != ITERATIONS:
        raise ValueError(f"{case['name']}: expected {ITERATIONS} stores, got {len(addresses)}")
    if addresses[0] != case["tail_address"] or any(b - a != 1 for a, b in zip(addresses, addresses[1:])):
        raise ValueError(f"{case['name']}: destination is not the expected contiguous 20-byte buffer")
    for at in range(BLOCK_RECORDS, ITERATIONS * BLOCK_RECORDS):
        if case["pcs"][at] != case["pcs"][at - BLOCK_RECORDS]:
            raise ValueError(f"{case['name']}: PC period differs at {at}")


TEMPLATE = r'''// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0
//
// GENERATED by tools/transpile_final4.py. Regenerate; do not hand-edit.

//! Exact 20-iteration final-four producer. No Apple image or capture input.

use crate::end_tag_round::*;
use crate::end_final4_tables;

pub(crate) const LIB_BASE: u64 = 0x7ffff7679000;
const FRAME_LEN: usize = 0x700;
const TAIL_RBP_OFFSET: u64 = 0x43d0;
const TAIL_LEN: usize = 20;
const SOURCE_LEN: usize = 20;

#[derive(Clone)]
pub struct Final4State {
    pub registers: [u64; 16],
    pub xmm: [Xmm; 16],
    pub frame: Vec<u8>,
    pub source: [u8; SOURCE_LEN],
    pub tail: [u8; TAIL_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidFinal4Frame;

impl core::fmt::Display for InvalidFinal4Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "End final-four frame must be exactly {FRAME_LEN} bytes")
    }
}

impl std::error::Error for InvalidFinal4Frame {}

impl Final4State {
    pub fn new(registers: [u64; 16], xmm: [Xmm; 16], frame: Vec<u8>, source: [u8; SOURCE_LEN], tail: [u8; TAIL_LEN]) -> Result<Self, InvalidFinal4Frame> {
        if frame.len() != FRAME_LEN {
            return Err(InvalidFinal4Frame);
        }
        Ok(Self { registers, xmm, frame, source, tail })
    }
}

#[derive(Clone, Default)]
struct Registers {
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rbp: u64, rsp: u64,
    r8: u64, r9: u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
}

struct Final4Core {
    regs: Registers,
    xmm: [Xmm; 16],
    site: u64,
    zf: bool,
    cf: bool,
    frame: Vec<u8>,
    source: [u8; SOURCE_LEN],
    tail: [u8; TAIL_LEN],
}

impl Final4Core {
    fn new(state: &Final4State) -> Self {
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
            source: state.source,
            tail: state.tail,
        }
    }

    fn finish(self, state: &mut Final4State) {
        let r = self.regs;
        state.registers = [
            r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.rsp,
            r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15,
        ];
        state.xmm = self.xmm;
        state.frame = self.frame;
        state.tail = self.tail;
    }

    fn tail_address(&self) -> u64 {
        self.regs.rbp.wrapping_sub(TAIL_RBP_OFFSET)
    }

    fn read8(&self, address: u64) -> u8 {
        let bottom = self.regs.rbp.wrapping_sub(FRAME_LEN as u64);
        if address >= bottom && address < bottom + FRAME_LEN as u64 {
            return self.frame[(address - bottom) as usize];
        }
        let tail = self.tail_address();
        if (tail..tail + TAIL_LEN as u64).contains(&address) {
            return self.tail[(address - tail) as usize];
        }
        let source = tail + 0x20;
        if (source..source + SOURCE_LEN as u64).contains(&address) {
            return self.source[(address - source) as usize];
        }
        if let Some(byte) = end_final4_tables::read8(address) {
            return byte;
        }
        panic!("unclassified End final-four read at {address:#x}, site {:#x}", self.site);
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
        let tail = self.tail_address();
        if address >= tail && address + size as u64 <= tail + TAIL_LEN as u64 {
            let offset = (address - tail) as usize;
            self.tail[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
            return;
        }
        panic!("unclassified End final-four write at {address:#x}, site {:#x}", self.site);
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

pub fn transform_final4(state: &mut Final4State) -> [u8; TAIL_LEN] {
    let mut core = Final4Core::new(state);
    for _ in 0..20 {
        block_core(&mut core);
    }
    core.finish(state);
    state.tail
}

#[allow(clippy::all, unused_parens)]
fn block_core(s: &mut Final4Core) {
{{BODY}}
}
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--case1", required=True, help="name=case-dir:start:end")
    ap.add_argument("--case2", required=True, help="name=case-dir:start:end")
    ap.add_argument("--image", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--state-dir", required=True)
    args = ap.parse_args()
    cases = [load_case(spec) for spec in (args.case1, args.case2)]
    if cases[0]["pcs"] != cases[1]["pcs"]:
        raise ValueError("independent inputs execute different final-four PCs")
    if cases[0]["first"][1][6] - cases[0]["tail_address"] != cases[1]["first"][1][6] - cases[1]["tail_address"]:
        raise ValueError("independent inputs use different RBP-relative destinations")
    image = Path(args.image).read_bytes()
    for case in cases:
        validate_case(case, image)
    decoded = [decode_and_census(case, image) for case in cases]
    insns = decoded[0][0]
    static = decoded[0][1] | decoded[1][1]
    if len(insns) != BLOCK_RECORDS:
        raise ValueError(f"decoded {len(insns)} instructions instead of {BLOCK_RECORDS}")
    audit_flags(insns)
    for ins in insns:
        emit_tag(ins)
    tables, zero_ranges, pages = tables_rust(image, static)
    tables = tables.replace("super::end_tag_round_core::LIB_BASE", "super::end_final4_core::LIB_BASE")
    out_dir = Path(args.out_dir)
    (out_dir / "end_final4_tables.rs").write_text(tables)
    (out_dir / "end_final4_core.rs").write_text(TEMPLATE.replace("{{BODY}}", render_body(insns)))

    state_dir = Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    for case in cases:
        first, last = case["first"], case["last"]
        initial = (struct.pack("<16Q", *first[1]) + b"".join(first[2]) + case["frame"] +
                   case["source"] + case["tail"])
        expected = (struct.pack("<16Q", *last[1]) + b"".join(last[2]) + case["expected_frame"] +
                    case["expected_source"] + case["expected_tail"])
        path = state_dir / (case["name"] + ".bin")
        path.write_bytes(initial + expected + case["final4"])
        os.chmod(path, 0o600)
    print(f"transpiled {len(insns)} instructions, {zero_ranges} page-zero ranges and {pages} data pages")


if __name__ == "__main__":
    main()
