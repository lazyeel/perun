#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0
"""Transpile the measured planter circuit to exact, dependency-free Rust.

Usage (development oracle only)::

    python3 tools/transpile_planter.py --core /private/core-dd511.bin \
        --out-dir crates/perun-adi-core/src

The core and every raw value it contains stay outside the repository.  The
script prints only instruction/data counts.  It consumes the executed stream,
not linear disassembly, and emits Rust plus non-executable lookup data, never
x86 machine code.  Unsupported instructions, operands, control flow and flag
dependencies are hard errors rather than silent approximations.
"""
import argparse
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from unicorn import UC_HOOK_CODE

from planter_replay import ARENA, N_ARENA, Lab, LIB_BASE

PAGE_RVAS = [
    0x0F000, 0x18000, 0x19000, 0x1A000, 0x1C000, 0x26000, 0x2A000,
    0x05000, 0x09000, 0x1F000, 0x46000, 0x185000,
    0x31000, 0x34000, 0x3A000, 0x3B000, 0x3D000, 0x3E000, 0x184000,
]
SCHEDULE_STORES = {0xE090F, 0xE09B7, 0xE09D5, 0xE09F5}
MASK64 = (1 << 64) - 1

REG_ALIASES = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
    "si": "rsi", "di": "rdi", "bp": "rbp", "sp": "rsp",
    "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
    "ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx",
    "sil": "rsi", "dil": "rdi", "bpl": "rbp", "spl": "rsp",
}
for _n in range(8, 16):
    for _suffix in ("d", "w", "b"):
        REG_ALIASES["r%d%s" % (_n, _suffix)] = "r%d" % _n
HIGH8 = {"ah", "bh", "ch", "dh"}
FLAG_NEUTRAL = {
    "mov", "movzx", "movsxd", "lea", "cdqe", "not",
    "sete", "setne", "seta", "cmove", "cmovne", "jmp",
}
FLAG_CONSUMERS = {"sete", "setne", "seta", "cmove", "cmovne", "adc"}
ALLOWED_DISPATCH = {0xE0A2B, 0xE1F6B, 0xE26DE}


def parent(name):
    return REG_ALIASES.get(name, name)


def reg_read(name):
    field = parent(name)
    if name in HIGH8:
        return "((s.regs.%s >> 8) & 0xff)" % field
    if name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp") or (
            name.startswith("r") and name[1:].isdigit()):
        return "s.regs.%s" % field
    if name.startswith("e") or (name.startswith("r") and name.endswith("d")):
        return "(s.regs.%s & 0xffffffff)" % field
    if name.endswith("w") or name in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
        return "(s.regs.%s & 0xffff)" % field
    return "(s.regs.%s & 0xff)" % field


def reg_write(name, value="_v"):
    field = parent(name)
    if name in HIGH8:
        return "s.regs.%s = (s.regs.%s & !0xff00u64) | ((%s & 0xff) << 8);" % (field, field, value)
    if name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp") or (
            name.startswith("r") and name[1:].isdigit()):
        return "s.regs.%s = %s;" % (field, value)
    if name.startswith("e") or (name.startswith("r") and name.endswith("d")):
        return "s.regs.%s = (%s as u32) as u64;" % (field, value)
    if name.endswith("w") or name in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
        return "s.regs.%s = (s.regs.%s & !0xffffu64) | (%s & 0xffff);" % (field, field, value)
    return "s.regs.%s = (s.regs.%s & !0xffu64) | (%s & 0xff);" % (field, field, value)


def imm(value):
    return "0x%xu64" % (value & MASK64)


def address(ins, op):
    terms = []
    if op.mem.base:
        name = ins.reg_name(op.mem.base)
        terms.append(imm(ins.address + ins.size) if name == "rip" else reg_read(name))
    if op.mem.index:
        index = reg_read(ins.reg_name(op.mem.index))
        if op.mem.scale != 1:
            index = "(%s).wrapping_mul(%d)" % (index, op.mem.scale)
        terms.append(index)
    if op.mem.disp:
        terms.append(imm(op.mem.disp))
    if not terms:
        return "0u64"
    result = terms[0]
    for term in terms[1:]:
        result = "(%s).wrapping_add(%s)" % (result, term)
    return result


def read_op(ins, index):
    op = ins.operands[index]
    if op.type == X86_OP_REG:
        return reg_read(ins.reg_name(op.reg))
    if op.type == X86_OP_IMM:
        return imm(op.imm)
    if op.type == X86_OP_MEM:
        return "s.load(%s, %d)" % (address(ins, op), op.size)
    raise ValueError("unsupported read operand %s" % ins.op_str)


def write_op(ins, index, value="_v"):
    op = ins.operands[index]
    if op.type == X86_OP_REG:
        return [reg_write(ins.reg_name(op.reg), value)]
    if op.type == X86_OP_MEM:
        return [
            "let _addr = %s;" % address(ins, op),
            "s.store(_addr, %d, %s);" % (op.size, value),
        ]
    raise ValueError("unsupported write operand %s" % ins.op_str)


def bits(ins, index=0):
    return ins.operands[index].size * 8


def emit_assignment(ins, value):
    return ["let _v = (%s) & mask(%d);" % (value, bits(ins))] + write_op(ins, 0)


def emit_binary(ins):
    helper = {"add": "alu_add", "sub": "alu_sub", "imul": "alu_mul"}.get(ins.mnemonic)
    if helper is None:
        helper = "alu_" + ins.mnemonic
    width = bits(ins)
    return [
        "let _a = %s;" % read_op(ins, 0),
        "let _b = %s;" % read_op(ins, 1),
        "let _v = %s(%d, _a, _b);" % (helper, width),
    ] + write_op(ins, 0)


def emit(ins):
    mn = ins.mnemonic
    n = len(ins.operands)
    if mn in ("mov", "movzx") and n == 2:
        return emit_assignment(ins, read_op(ins, 1))
    if mn == "movsxd" and n == 2 and bits(ins, 1) == 32 and bits(ins, 0) == 64:
        return emit_assignment(ins, "((%s as u32) as i32) as i64 as u64" % read_op(ins, 1))
    if mn == "cdqe" and n == 0:
        return ["s.regs.rax = ((s.regs.rax as u32) as i32) as i64 as u64;"]
    if mn == "lea" and n == 2 and ins.operands[1].type == X86_OP_MEM:
        return emit_assignment(ins, address(ins, ins.operands[1]))
    if mn in ("add", "sub", "xor", "and", "or", "imul") and n == 2:
        return emit_binary(ins)
    if mn == "imul" and n == 3:
        width = bits(ins)
        return [
            "let _a = %s;" % read_op(ins, 1),
            "let _b = %s;" % read_op(ins, 2),
            "let _v = alu_mul(%d, _a, _b);" % width,
        ] + write_op(ins, 0)
    if mn in ("shl", "shr") and n == 2:
        width = bits(ins)
        return [
            "let _a = %s;" % read_op(ins, 0),
            "let _b = %s;" % read_op(ins, 1),
            "let _v = alu_%s(%d, _a, _b);" % (mn, width),
        ] + write_op(ins, 0)
    if mn in ("shld", "shrd") and n == 3 and bits(ins) in (32, 64):
        width = bits(ins)
        return [
            "let _a = %s;" % read_op(ins, 0),
            "let _b = %s;" % read_op(ins, 1),
            "let _c = %s;" % read_op(ins, 2),
            "let _v = alu_%s(%d, _a, _b, _c);" % (mn, width),
        ] + write_op(ins, 0)
    if mn == "rol" and n == 2:
        width = bits(ins)
        return [
            "let _a = %s;" % read_op(ins, 0),
            "let _b = %s;" % read_op(ins, 1),
            "let _v = alu_rol(%d, _a, _b);" % width,
        ] + write_op(ins, 0)
    if mn == "neg" and n == 1:
        return emit_assignment(ins, "alu_sub(%d, 0, %s)" % (bits(ins), read_op(ins, 0)))
    if mn == "not" and n == 1:
        return emit_assignment(ins, "!(%s)" % read_op(ins, 0))
    if mn == "mul" and n == 1 and bits(ins) == 8:
        return [
            "let _v = ((s.regs.rax & 0xff) as u16).wrapping_mul((%s & 0xff) as u16) as u64;" % read_op(ins, 0),
            "s.regs.rax = (s.regs.rax & !0xffffu64) | (_v & 0xffff);",
        ]
    if mn == "cmp" and n == 2:
        return [
            "let _a = %s;" % read_op(ins, 0),
            "let _b = %s;" % read_op(ins, 1),
            "s.zf = alu_sub(%d, _a, _b) == 0;" % bits(ins),
            "s.cf = (_a & mask(%d)) < (_b & mask(%d));" % (bits(ins), bits(ins)),
        ]
    if mn == "test" and n == 2:
        return [
            "let _a = %s;" % read_op(ins, 0),
            "let _b = %s;" % read_op(ins, 1),
            "s.zf = alu_and(%d, _a, _b) == 0;" % bits(ins),
            "s.cf = false;",
        ]
    if mn == "adc" and n == 2:
        return [
            "let _a = %s;" % read_op(ins, 0),
            "let _b = %s;" % read_op(ins, 1),
            "let _v = alu_add(%d, alu_add(%d, _a, _b), s.cf as u64);" % (bits(ins), bits(ins)),
        ] + write_op(ins, 0)
    if mn in ("sete", "setne", "seta") and n == 1 and bits(ins) == 8:
        predicate = {"sete": "s.zf", "setne": "!s.zf", "seta": "!s.cf && !s.zf"}[mn]
        return ["let _v = if %s { 1 } else { 0 };" % predicate] + write_op(ins, 0)
    if mn in ("cmove", "cmovne") and n == 2:
        predicate = "s.zf" if mn == "cmove" else "!s.zf"
        body = ["let _v = %s;" % read_op(ins, 1)] + write_op(ins, 0)
        return ["if %s {" % predicate] + ["    " + line for line in body] + ["}"]
    raise ValueError("unsupported instruction at %#x: %s %s" % (ins.address, mn, ins.op_str))


def audit_flags(insns):
    source = None
    for ins in insns:
        mn = ins.mnemonic
        if mn in FLAG_CONSUMERS:
            if source not in ("cmp", "test"):
                raise ValueError("unproven flag source at %#x: %s" % (ins.address, ins.op_str))
            if mn == "adc":
                source = None
        elif mn in ("cmp", "test"):
            source = mn
        elif mn not in FLAG_NEUTRAL:
            source = None


def emit_post(ins):
    if ins.mnemonic == "jmp":
        rva = ins.address - LIB_BASE
        if rva not in ALLOWED_DISPATCH:
            raise ValueError("unmeasured post-schedule jump at %#x" % rva)
        return ["// measured computed dispatch; structured Rust supplies the successor"]
    return emit(ins)


def capture_rounds(core):
    lab = Lab(core)
    lab.run()
    arena = bytes(lab.uc.mem_read(ARENA, N_ARENA))
    streams = [[], []]
    stores = [0]

    def hook(uc, address, size, data):
        block = stores[0] // 4
        if block >= 2:
            uc.emu_stop()
            return True
        streams[block].append((address, size))
        if address - LIB_BASE in SCHEDULE_STORES:
            stores[0] += 1
            if stores[0] == 8:
                uc.emu_stop()
        return True

    lab.uc.hook_add(UC_HOOK_CODE, hook)
    lab.uc.ctl_flush_tb()
    lab.run_arena(arena)
    return lab, streams


def capture_post(core):
    lab = Lab(core)
    pcs, sizes = [], []

    def hook(uc, address, size, data):
        pcs.append(address)
        sizes.append(size)
        return True

    lab.uc.hook_add(UC_HOOK_CODE, hook)
    lab.uc.ctl_flush_tb()
    lab.run()
    final_sched = max(i for i, pc in enumerate(pcs) if pc == LIB_BASE + 0xE09F5)
    first_head = pcs.index(LIB_BASE + 0xE1F74, final_sched)
    first_tail = pcs.index(LIB_BASE + 0xE26DE, first_head)
    bridge = list(zip(pcs[final_sched + 1:first_head], sizes[final_sched + 1:first_head]))
    body = list(zip(pcs[first_head:first_tail + 1], sizes[first_head:first_tail + 1]))
    assert len(bridge) == 1138, len(bridge)
    assert len(body) == 479, len(body)
    return lab, bridge, body


def tables_rust(lab):
    out = ["""// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0
//
// GENERATED by tools/transpile_planter.py. Static, non-executable lookup data.

//! Read-only tables used by the planter arithmetic core. These are data pages,
//! not an Apple image: no machine code, loader, relocation or capture is used.

"""]
    for rva in PAGE_RVAS:
        data = bytes(lab.uc.mem_read(LIB_BASE + rva, 0x1000))
        out.append("pub(crate) static PAGE_%05X: [u8; 4096] = [\n" % rva)
        for pos in range(0, len(data), 16):
            out.append("    " + ", ".join("0x%02x" % b for b in data[pos:pos + 16]) + ",\n")
        out.append("];\n\n")
    out.append("pub(crate) fn read8(address: u64) -> Option<u8> {\n")
    out.append("    let rva = address.checked_sub(super::planter_core::LIB_BASE)?;\n")
    out.append("    let page = rva & !0xfff;\n")
    out.append("    let offset = (rva & 0xfff) as usize;\n")
    out.append("    let table: &[u8; 4096] = match page {\n")
    for rva in PAGE_RVAS:
        out.append("        0x%05x => &PAGE_%05X,\n" % (rva, rva))
    out.append("        _ => return None,\n    };\n    Some(table[offset])\n}\n")
    return "".join(out)


def render_body(insns, post=False):
    body = []
    for ins in insns:
        body.append("        // %#x: %s %s" % (ins.address - LIB_BASE, ins.mnemonic, ins.op_str))
        body.append("        {")
        emitted = emit_post(ins) if post else emit(ins)
        body.extend("            " + line for line in emitted)
        body.append("        }")
    return "\n".join(body)


def core_rust(insns, setup, window):
    return (TEMPLATE
            .replace("{{BODY}}", render_body(insns))
            .replace("{{POST_SETUP}}", render_body(setup, post=True))
            .replace("{{WINDOW_BODY}}", render_body(window, post=True)))


TEMPLATE = r'''// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0
//
// GENERATED by tools/transpile_planter.py. Regenerate; do not hand-edit.

//! Exact pure-Rust transcription of the complete planter genesis.
//! No Apple machine code or runtime memory image is present in this module.

use crate::planter_tables;

pub(crate) const LIB_BASE: u64 = 0x7ffff7679000;
const RBP: u64 = 0x7fffffffa1b0;
const ARENA_BASE: u64 = 0x7ffff7814600;
const PLANTER_BASE: u64 = RBP - 0x44a0;
const SCHEDULE_OFFSET: u64 = 0x18d0;
const STATIC_POINTERS: u64 = LIB_BASE + 0x184060;
const FRAME_BOTTOM: u64 = RBP - 0x5000;
const FRAME_LEN: usize = 0x6000;
const SCHEDULE_LEN: usize = 0xf0;

#[derive(Clone, Default)]
struct Registers {
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rbp: u64,
    r8: u64, r9: u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
}

struct PlanterCore {
    regs: Registers,
    zf: bool,
    cf: bool,
    frame: Vec<u8>,
    arena: [u8; 240],
}

impl PlanterCore {
    fn new(arena: &[u8; 240]) -> Self {
        let mut s = Self {
            regs: Registers::default(),
            zf: false,
            cf: false,
            frame: vec![0; FRAME_LEN],
            arena: *arena,
        };
        s.regs.rbp = RBP;
        s.regs.rsi = 0x4d5;
        s.regs.r13 = STATIC_POINTERS;
        s.store(RBP - 0x1c0, 8, ARENA_BASE);
        s.store(RBP - 0x30, 8, PLANTER_BASE);
        s.store(RBP - 0x208, 8, PLANTER_BASE - 0x10);
        s.store(RBP - 0x180, 8, PLANTER_BASE + 0x2980);
        s.store(RBP - 0xb8, 8, 0x3530c296);
        s.store(RBP - 0x1f0, 8, 0x8d3a63fb);
        s.store(RBP - 0x108, 4, 0x81a7e77f);
        s.store(RBP - 0xd8, 4, 0x1a2a37eb);
        s.store(RBP - 0x110, 4, 0xd98e6ab6);
        s.store(RBP - 0x1a8, 4, 0xcb61306c);
        s
    }

    fn link(&mut self) {
        // The only data carried between rounds: four output-dependent masks.
        let a = self.load(RBP - 0x78, 4) ^ 0x75f919ee;
        let b = self.load(RBP - 0xd0, 4) ^ 0x72808175;
        let c = self.load(RBP - 0x70, 4) ^ 0x5e280a83;
        let d = self.load(RBP - 0x80, 4) ^ 0x1841dc71;
        self.store(RBP - 0x1a8, 4, a);
        self.store(RBP - 0x110, 4, b);
        self.store(RBP - 0xd8, 4, c);
        self.store(RBP - 0x108, 4, d);
        let cursor = self.load(RBP - 0xb8, 8).wrapping_add(0x10);
        self.store(RBP - 0xb8, 8, cursor);
        self.regs.rsi = 0x4d5;
        self.regs.r13 = STATIC_POINTERS;
    }

    fn read8(&self, address: u64) -> u8 {
        if address >= FRAME_BOTTOM && address < FRAME_BOTTOM + FRAME_LEN as u64 {
            return self.frame[(address - FRAME_BOTTOM) as usize];
        }
        if address >= ARENA_BASE && address < ARENA_BASE + self.arena.len() as u64 {
            return self.arena[(address - ARENA_BASE) as usize];
        }
        if let Some(byte) = planter_tables::read8(address) {
            return byte;
        }
        panic!("unclassified planter read at {address:#x}");
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
        assert!(address >= FRAME_BOTTOM && address + size as u64 <= FRAME_BOTTOM + FRAME_LEN as u64,
                "unclassified planter write at {address:#x}");
        let offset = (address - FRAME_BOTTOM) as usize;
        self.frame[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
    }

    fn schedule(&self) -> [u8; SCHEDULE_LEN] {
        let address = PLANTER_BASE + SCHEDULE_OFFSET;
        let offset = (address - FRAME_BOTTOM) as usize;
        let mut out = [0u8; SCHEDULE_LEN];
        out.copy_from_slice(&self.frame[offset..offset + SCHEDULE_LEN]);
        out
    }

    fn window_tables(&self) -> [[u8; 256]; 7] {
        // Family::ALL order: D60, 1390, 1A00, 1F30, 2460, C50, 1280.
        let offsets = [0xd60usize, 0x1390, 0x1a00, 0x1f30, 0x2460, 0xc50, 0x1280];
        let mut tables = [[0u8; 256]; 7];
        for (table, window_offset) in tables.iter_mut().zip(offsets) {
            let address = PLANTER_BASE + window_offset as u64;
            let offset = (address - FRAME_BOTTOM) as usize;
            table.copy_from_slice(&self.frame[offset..offset + 256]);
        }
        tables
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
#[inline]
fn alu_shld(bits: u32, a: u64, b: u64, count: u64) -> u64 {
    let n = shift_count(bits, count);
    if n == 0 { return a & mask(bits); }
    assert!(n < bits);
    (((a & mask(bits)) << n) | ((b & mask(bits)) >> (bits - n))) & mask(bits)
}
#[inline]
fn alu_shrd(bits: u32, a: u64, b: u64, count: u64) -> u64 {
    let n = shift_count(bits, count);
    if n == 0 { return a & mask(bits); }
    assert!(n < bits);
    (((a & mask(bits)) >> n) | ((b & mask(bits)) << (bits - n))) & mask(bits)
}
#[inline]
fn alu_rol(bits: u32, a: u64, b: u64) -> u64 {
    let n = shift_count(bits, b) % bits;
    let a = a & mask(bits);
    if n == 0 { a } else { ((a << n) | (a >> (bits - n))) & mask(bits) }
}

fn scheduled(arena: &[u8; 240]) -> PlanterCore {
    let mut s = PlanterCore::new(arena);
    for block in 0..15 {
        if block != 0 {
            s.link();
        }
        round_core(&mut s);
    }
    s
}

/// Expand the 240-byte arena to the native 240-byte schedule.
pub(crate) fn schedule(arena: &[u8; 240]) -> [u8; SCHEDULE_LEN] {
    scheduled(arena).schedule()
}

/// Expand the arena to the schedule and all seven generated window tables.
pub(crate) fn expand(arena: &[u8; 240]) -> ([u8; SCHEDULE_LEN], [[u8; 256]; 7]) {
    let mut s = scheduled(arena);
    post_schedule_setup(&mut s);
    for _ in 0..256 {
        window_iteration(&mut s);
    }
    (s.schedule(), s.window_tables())
}

#[allow(clippy::all, unused_parens)]
fn round_core(s: &mut PlanterCore) {
{{BODY}}
}

#[allow(clippy::all, unused_parens)]
fn post_schedule_setup(s: &mut PlanterCore) {
{{POST_SETUP}}
}

#[allow(clippy::all, unused_parens)]
fn window_iteration(s: &mut PlanterCore) {
{{WINDOW_BODY}}
}
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--core", required=True, help="private development-only gcore checkpoint")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    lab, streams = capture_rounds(args.core)
    first, second = streams[0][371:], streams[1][36:]
    assert len(first) == len(second) == 3092
    assert [x[0] for x in first] == [x[0] for x in second]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = []
    for address, size in second:
        ins = next(md.disasm(bytes(lab.uc.mem_read(address, size)), address))
        if ins.mnemonic.startswith("j") or ins.mnemonic in ("call", "ret"):
            raise ValueError("control flow in shared core at %#x" % address)
        insns.append(ins)
    post_lab, bridge, window = capture_post(args.core)

    def decode_post(stream):
        decoded = []
        for address, size in stream:
            ins = next(md.disasm(bytes(post_lab.uc.mem_read(address, size)), address))
            if ins.mnemonic in ("call", "ret") or (ins.mnemonic.startswith("j") and ins.mnemonic != "jmp"):
                raise ValueError("unmeasured post-schedule control flow at %#x" % address)
            decoded.append(ins)
        return decoded

    setup_insns, window_insns = decode_post(bridge), decode_post(window)
    for group in (insns, setup_insns, window_insns):
        audit_flags(group)
    for ins in insns:
        emit(ins)
    for ins in setup_insns + window_insns:
        emit_post(ins)
    out_dir = Path(args.out_dir)
    (out_dir / "planter_tables.rs").write_text(tables_rust(post_lab))
    (out_dir / "planter_core.rs").write_text(core_rust(insns, setup_insns, window_insns))
    print("transpiled", len(insns) + len(setup_insns) + len(window_insns),
          "instructions and", len(PAGE_RVAS), "data pages")


if __name__ == "__main__":
    main()
