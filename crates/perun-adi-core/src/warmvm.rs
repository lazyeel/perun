// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! warmvm: an interpreter for the lifted ADI warm-OTP program.
//!
//! `tools/trace_lift.py` turns the executed instruction stream of the
//! Apple-ADI warm path into a small dst-first IR (`program.bin`) plus a
//! per-case bundle (entry state, memory seeds, libc replay stubs).  This
//! module executes that IR with full x86-64 semantics for the subset the
//! path uses and verifies every step against the captured corpus: at
//! record `i` the VM must show exactly the recorded `rip`, 16 GP
//! registers and 16 XMM registers before executing the instruction.
//!
//! The VM is deliberately strict:
//!
//! * unmapped reads/writes are errors (the seeds must cover every access),
//! * libc is never executed: a stub at its call site replays the callee's
//!   complete return state (GP + XMM + rip), as measured,
//! * `rdtsc` is the frozen fake clock of the capture (`tsc_base`,
//!   +4096 per read), not the host counter.
//!
//! Nothing here is Apple-specific: the engine is a data-driven program.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom};

/// Bytes of the per-record trace header (rip + GP regs + metadata).
pub const TREC: usize = 152;
/// Bytes of the full XSAVE payload stored after the header.
pub const XSTATE: usize = 832;
/// One trace record.
pub const REC: usize = TREC + XSTATE;
/// Offset of XMM0..15 inside the XSAVE payload (16 bytes each).
pub const XMM_OFF: usize = 160;

pub const PAGE_BITS: u32 = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_BITS;

// -- IR opcodes (must match tools/trace_lift.py) ---------------------------
pub const MOV: u16 = 1;
pub const MOVZX: u16 = 2;
pub const MOVSX: u16 = 3;
pub const LEA: u16 = 4;
pub const ADD: u16 = 5;
pub const SUB: u16 = 6;
pub const AND: u16 = 7;
pub const OR: u16 = 8;
pub const XOR: u16 = 9;
pub const ADC: u16 = 10;
pub const SBB: u16 = 11;
pub const CMP: u16 = 12;
pub const TEST: u16 = 13;
pub const NEG: u16 = 14;
pub const NOT: u16 = 15;
pub const MUL: u16 = 16;
pub const IMUL1: u16 = 17;
pub const IMUL2: u16 = 18;
pub const IMUL3: u16 = 19;
pub const DIV: u16 = 20;
pub const IDIV: u16 = 21;
pub const SHL: u16 = 22;
pub const SHR: u16 = 23;
pub const SAR: u16 = 24;
pub const ROL: u16 = 25;
pub const ROR: u16 = 26;
pub const SHLD: u16 = 27;
pub const SHRD: u16 = 28;
pub const SETCC: u16 = 29;
pub const CMOVCC: u16 = 30;
pub const JCC: u16 = 31;
pub const JMP: u16 = 32;
pub const CALL: u16 = 33;
pub const RET: u16 = 34;
pub const PUSH: u16 = 35;
pub const POP: u16 = 36;
pub const RDTSC: u16 = 37;
pub const SYSCALL: u16 = 38;
pub const NOP: u16 = 39;
pub const BSWAP: u16 = 40;
pub const SSE_MOVDQA: u16 = 41;
pub const SSE_MOVDQU: u16 = 42;
pub const SSE_MOVUPS: u16 = 43;
pub const SSE_MOVQ: u16 = 44;
pub const SSE_MOVD: u16 = 45;
pub const SSE_PADDD: u16 = 46;
pub const SSE_PSUBD: u16 = 47;
pub const SSE_PAND: u16 = 48;
pub const SSE_POR: u16 = 49;
pub const SSE_PXOR: u16 = 50;
pub const SSE_PMULLD: u16 = 51;
pub const SSE_PMULLW: u16 = 52;
pub const SSE_PSHUFD: u16 = 53;
pub const SSE_PSHUFB: u16 = 54;
pub const SSE_PMOVZX: u16 = 55;
pub const SSE_PINSRD: u16 = 56;
pub const SSE_PEXTRD: u16 = 57;
pub const SSE_PEXTRQ: u16 = 58;
pub const SSE_PACKUSDW: u16 = 59;
pub const SSE_PACKUSWB: u16 = 60;
pub const SSE_PUNPCKLQDQ: u16 = 61;
pub const SSE_PCMPEQD: u16 = 62;
pub const SSE_PSLLD: u16 = 63;
pub const SSE_PSRLD: u16 = 64;
pub const SSE_BLENDVPS: u16 = 65;

pub fn op_name(op: u16) -> &'static str {
    const NAMES: [&str; 66] = [
        "?",
        "mov",
        "movzx",
        "movsx",
        "lea",
        "add",
        "sub",
        "and",
        "or",
        "xor",
        "adc",
        "sbb",
        "cmp",
        "test",
        "neg",
        "not",
        "mul",
        "imul1",
        "imul2",
        "imul3",
        "div",
        "idiv",
        "shl",
        "shr",
        "sar",
        "rol",
        "ror",
        "shld",
        "shrd",
        "setcc",
        "cmovcc",
        "jcc",
        "jmp",
        "call",
        "ret",
        "push",
        "pop",
        "rdtsc",
        "syscall",
        "nop",
        "bswap",
        "movdqa",
        "movdqu",
        "movups",
        "movq",
        "movd",
        "paddd",
        "psubd",
        "pand",
        "por",
        "pxor",
        "pmulld",
        "pmullw",
        "pshufd",
        "pshufb",
        "pmovzx",
        "pinsrd",
        "pextrd",
        "pextrq",
        "packusdw",
        "packuswb",
        "punpcklqdq",
        "pcmpeqd",
        "pslld",
        "psrld",
        "blendvps",
    ];
    NAMES.get(op as usize).copied().unwrap_or("?")
}

// -- operands --------------------------------------------------------------
const OP_NONE: u8 = 0;
const OP_REG: u8 = 1;
const OP_MEM: u8 = 2;
const OP_IMM: u8 = 3;
const OP_XMM: u8 = 4;
const OP_TARGET: u8 = 5;

/// Registers use size codes 1/2/4/8; 17 means the high byte of the
/// classic first four registers (ah/ch/dh/bh), bits 8..15.
pub const HB: u8 = 17;

// Indices into `Vm::gpr` are ptrace's, not the x86 encoding's: rax, rbx, rcx,
// rdx, rsi, rdi, rbp, rsp, r8..r15.  The mul/div/shld forms write rdx
// implicitly, so name it once instead of hard-coding the wrong 2.
const RDX: usize = 3;
const RAX: usize = 0;
const RSP: usize = 7;

#[derive(Clone, Copy, Debug)]
pub enum Operand {
    None,
    Reg {
        idx: u8,
        size: u8,
    },
    Mem {
        base: u8,
        index: u8,
        scale: u8,
        size: u8,
        disp: i64,
    },
    Imm {
        val: u64,
        size: u8,
    },
    Xmm {
        idx: u8,
    },
    Target(u64),
}

impl Operand {
    pub fn size(&self) -> u8 {
        match self {
            Operand::Reg { size, .. } | Operand::Mem { size, .. } | Operand::Imm { size, .. } => {
                *size
            }
            _ => 8,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Insn {
    pub op: u16,
    pub extra: u8,
    pub ilen: u8,
    pub ops: [Operand; 3],
    pub nops: u8,
}

// -- errors ----------------------------------------------------------------
#[derive(Debug)]
pub enum VmError {
    NoInsn(u64),
    BadProgram(String),
    BadBundle(String),
    Read { addr: u64, len: usize },
    Write { addr: u64, len: usize },
    DivZero,
    Unsupported(u16),
    BadOperand(&'static str),
    Io(io::Error),
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmError::NoInsn(a) => write!(f, "no instruction at {a:#x}"),
            VmError::BadProgram(s) => write!(f, "bad program: {s}"),
            VmError::BadBundle(s) => write!(f, "bad bundle: {s}"),
            VmError::Read { addr, len } => {
                write!(f, "unmapped read of {len} bytes at {addr:#x}")
            }
            VmError::Write { addr, len } => {
                write!(f, "unmapped write of {len} bytes at {addr:#x}")
            }
            VmError::DivZero => write!(f, "division by zero"),
            VmError::Unsupported(op) => write!(f, "unsupported op {op}"),
            VmError::BadOperand(s) => write!(f, "bad operand: {s}"),
            VmError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl From<io::Error> for VmError {
    fn from(e: io::Error) -> Self {
        VmError::Io(e)
    }
}

// -- paged memory ----------------------------------------------------------
pub struct Memory {
    pages: HashMap<u64, Box<[u8; PAGE_SIZE]>>,
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl Memory {
    pub fn new() -> Self {
        Memory {
            pages: HashMap::new(),
        }
    }

    pub fn seed(&mut self, addr: u64, data: &[u8]) {
        // seeding is infallible by construction: it allocates pages
        let _ = self.write_bytes(addr, data);
    }

    pub fn read_bytes(&self, mut addr: u64, out: &mut [u8]) -> Result<(), u64> {
        let mut off = 0usize;
        while off < out.len() {
            let page = addr >> PAGE_BITS;
            let within = (addr as usize) & (PAGE_SIZE - 1);
            let n = (PAGE_SIZE - within).min(out.len() - off);
            let p = self.pages.get(&page).ok_or(addr)?;
            out[off..off + n].copy_from_slice(&p[within..within + n]);
            addr += n as u64;
            off += n;
        }
        Ok(())
    }

    pub fn write_bytes(&mut self, mut addr: u64, data: &[u8]) -> Result<(), u64> {
        let mut off = 0usize;
        while off < data.len() {
            let page = addr >> PAGE_BITS;
            let within = (addr as usize) & (PAGE_SIZE - 1);
            let n = (PAGE_SIZE - within).min(data.len() - off);
            let p = self
                .pages
                .entry(page)
                .or_insert_with(|| Box::new([0u8; PAGE_SIZE]));
            p[within..within + n].copy_from_slice(&data[off..off + n]);
            addr += n as u64;
            off += n;
        }
        Ok(())
    }

    pub fn read_uint(&self, addr: u64, len: usize) -> Result<u64, VmError> {
        let mut b = [0u8; 8];
        self.read_bytes(addr, &mut b[..len])
            .map_err(|addr| VmError::Read { addr, len })?;
        Ok(u64::from_le_bytes(b))
    }

    pub fn write_uint(&mut self, addr: u64, len: usize, v: u64) -> Result<(), VmError> {
        let b = v.to_le_bytes();
        self.write_bytes(addr, &b[..len])
            .map_err(|addr| VmError::Write { addr, len })
    }
}

// -- CPU state -------------------------------------------------------------
#[derive(Clone, Copy, Default)]
pub struct Flags {
    pub cf: bool,
    pub pf: bool,
    pub af: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
}

pub const REG_NAMES: [&str; 16] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

fn size_mask(size: u8) -> u64 {
    match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

fn size_sign(size: u8) -> u64 {
    match size {
        1 => 0x80,
        2 => 0x8000,
        4 => 0x8000_0000,
        _ => 0x8000_0000_0000_0000,
    }
}

fn size_bits(size: u8) -> u32 {
    (size as u32) * 8
}

/// Sign-extend `v` (already masked to `size`) to 128 bits.
fn sext128(v: u64, size: u8) -> i128 {
    let bits = size_bits(size);
    let v = v & size_mask(size);
    if bits == 64 {
        v as i64 as i128
    } else {
        let shift = 64 - bits;
        (((v << shift) as i64) >> shift) as i128
    }
}

fn parity(v: u64) -> bool {
    (v & 0xff).count_ones().is_multiple_of(2)
}

pub struct Vm {
    pub program: Program,
    pub mem: Memory,
    pub gpr: [u64; 16],
    pub xmm: [[u8; 16]; 16],
    pub rip: u64,
    pub flags: Flags,
    pub tsc: u64,
    pub tsc_step: u64,
}

impl Vm {
    pub fn new(program: Program) -> Self {
        Vm {
            program,
            mem: Memory::new(),
            gpr: [0; 16],
            xmm: [[0; 16]; 16],
            rip: 0,
            flags: Flags::default(),
            tsc: 0,
            tsc_step: 4096,
        }
    }

    // -- operand helpers ---------------------------------------------------
    fn ea(&self, o: &Operand) -> u64 {
        match o {
            Operand::Mem {
                base,
                index,
                scale,
                disp,
                ..
            } => {
                let mut a = *disp as u64;
                if *base != 0xff {
                    a = a.wrapping_add(self.gpr[*base as usize]);
                }
                if *index != 0xff {
                    a = a.wrapping_add(self.gpr[*index as usize].wrapping_mul(*scale as u64));
                }
                a
            }
            _ => 0,
        }
    }

    pub fn read_op(&self, o: &Operand) -> Result<u64, VmError> {
        match o {
            Operand::Reg { idx, size } => Ok(reg_read(&self.gpr, *idx as usize, *size)),
            Operand::Mem { size, .. } => self.mem.read_uint(self.ea(o), *size as usize),
            Operand::Imm { val, .. } => Ok(*val),
            Operand::Target(v) => Ok(*v),
            _ => Err(VmError::BadOperand("read")),
        }
    }

    pub fn write_op(&mut self, o: &Operand, v: u64) -> Result<(), VmError> {
        match o {
            Operand::Reg { idx, size } => {
                reg_write(&mut self.gpr, *idx as usize, *size, v);
                Ok(())
            }
            Operand::Mem { size, .. } => self.mem.write_uint(self.ea(o), *size as usize, v),
            _ => Err(VmError::BadOperand("write")),
        }
    }

    fn read_xmm(&self, o: &Operand) -> Result<[u8; 16], VmError> {
        match o {
            Operand::Xmm { idx } => Ok(self.xmm[*idx as usize]),
            Operand::Mem { .. } => {
                let mut b = [0u8; 16];
                self.mem
                    .read_bytes(self.ea(o), &mut b)
                    .map_err(|addr| VmError::Read { addr, len: 16 })?;
                Ok(b)
            }
            _ => Err(VmError::BadOperand("xmm read")),
        }
    }

    fn write_xmm(&mut self, o: &Operand, v: &[u8; 16]) -> Result<(), VmError> {
        match o {
            Operand::Xmm { idx } => {
                self.xmm[*idx as usize] = *v;
                Ok(())
            }
            Operand::Mem { .. } => self
                .mem
                .write_bytes(self.ea(o), v)
                .map_err(|addr| VmError::Write { addr, len: 16 }),
            _ => Err(VmError::BadOperand("xmm write")),
        }
    }

    /// Read 4/8 bytes from an XMM register's low lanes or a GP location.
    fn read_wide(&self, o: &Operand, len: usize) -> Result<u64, VmError> {
        match o {
            Operand::Xmm { idx } => {
                let mut b = [0u8; 8];
                b[..len].copy_from_slice(&self.xmm[*idx as usize][..len]);
                Ok(u64::from_le_bytes(b))
            }
            _ => self.read_op(o),
        }
    }

    /// Write 4/8 bytes: XMM destination keeps its other bytes (low lanes
    /// replaced, upper zeroed for movd/movq).
    fn write_wide(&mut self, o: &Operand, len: usize, v: u64) -> Result<(), VmError> {
        match o {
            Operand::Xmm { idx } => {
                let b = v.to_le_bytes();
                let mut x = [0u8; 16];
                x[..len].copy_from_slice(&b[..len]);
                self.xmm[*idx as usize] = x;
                Ok(())
            }
            _ => {
                let b = v.to_le_bytes();
                match o {
                    Operand::Reg { idx, .. } => {
                        // movd/movq to a GP register: 4-byte form zero-extends
                        reg_write(&mut self.gpr, *idx as usize, len as u8, v);
                        Ok(())
                    }
                    Operand::Mem { .. } => self
                        .mem
                        .write_bytes(self.ea(o), &b[..len])
                        .map_err(|addr| VmError::Write { addr, len }),
                    _ => Err(VmError::BadOperand("wide write")),
                }
            }
        }
    }

    // -- flags -------------------------------------------------------------
    fn set_szp(&mut self, res: u64, size: u8) {
        let masked = res & size_mask(size);
        self.flags.zf = masked == 0;
        self.flags.sf = (masked & size_sign(size)) != 0;
        self.flags.pf = parity(masked);
    }

    fn cond(&self, cc: u8) -> bool {
        let f = &self.flags;
        match cc & 0xf {
            0x0 => f.of,
            0x1 => !f.of,
            0x2 => f.cf,
            0x3 => !f.cf,
            0x4 => f.zf,
            0x5 => !f.zf,
            0x6 => f.cf || f.zf,
            0x7 => !f.cf && !f.zf,
            0x8 => f.sf,
            0x9 => !f.sf,
            0xa => f.pf,
            0xb => !f.pf,
            0xc => f.sf != f.of,
            0xd => f.sf == f.of,
            0xe => f.zf || (f.sf != f.of),
            0xf => !f.zf && (f.sf == f.of),
            _ => unreachable!(),
        }
    }

    // -- execution ---------------------------------------------------------
    pub fn step(&mut self) -> Result<(), VmError> {
        let insn = *self
            .program
            .insns
            .get(&self.rip)
            .ok_or(VmError::NoInsn(self.rip))?;
        self.exec(&insn)
    }

    fn push(&mut self, v: u64) -> Result<(), VmError> {
        let rsp = self.gpr[RSP].wrapping_sub(8);
        self.gpr[RSP] = rsp;
        self.mem.write_uint(rsp, 8, v)
    }

    fn pop(&mut self) -> Result<u64, VmError> {
        let rsp = self.gpr[RSP];
        let v = self.mem.read_uint(rsp, 8)?;
        self.gpr[RSP] = rsp.wrapping_add(8);
        Ok(v)
    }

    fn exec(&mut self, insn: &Insn) -> Result<(), VmError> {
        let o = insn.ops;
        let next = self.rip.wrapping_add(insn.ilen as u64);
        match insn.op {
            MOV => {
                let v = self.read_op(&o[1])?;
                self.write_op(&o[0], v)?;
                self.rip = next;
            }
            MOVZX => {
                let sz = o[1].size();
                let v = self.read_op(&o[1])? & size_mask(sz);
                self.write_op(&o[0], v)?;
                self.rip = next;
            }
            MOVSX => {
                let sz = o[1].size();
                let v = self.read_op(&o[1])? & size_mask(sz);
                let ext = sext128(v, sz) as u64;
                self.write_op(&o[0], ext)?;
                self.rip = next;
            }
            LEA => {
                let a = self.ea(&o[1]);
                self.write_op(&o[0], a)?;
                self.rip = next;
            }
            ADD | SUB | AND | OR | XOR | ADC | SBB | CMP | TEST => {
                self.exec_alu(insn.op, &o[0], &o[1])?;
                self.rip = next;
            }
            NEG => {
                let size = o[0].size();
                let mask = size_mask(size);
                let dst = self.read_op(&o[0])? & mask;
                let res = (0u64.wrapping_sub(dst)) & mask;
                self.flags.cf = dst != 0;
                self.flags.of = dst == size_sign(size);
                self.flags.af = (dst & 0xf) != 0;
                self.set_szp(res, size);
                self.write_op(&o[0], res)?;
                self.rip = next;
            }
            NOT => {
                let size = o[0].size();
                let dst = self.read_op(&o[0])?;
                self.write_op(&o[0], !dst & size_mask(size))?;
                self.rip = next;
            }
            MUL => {
                self.exec_mul(&o[0], false)?;
                self.rip = next;
            }
            IMUL1 => {
                self.exec_mul(&o[0], true)?;
                self.rip = next;
            }
            IMUL2 => {
                let size = o[0].size();
                let a = self.read_op(&o[0])?;
                let b = self.read_op(&o[1])?;
                let p = sext128(a, size).wrapping_mul(sext128(b, size));
                let res = (p as u64) & size_mask(size);
                self.flags.cf = p != sext128(res, size);
                self.flags.of = self.flags.cf;
                self.write_op(&o[0], res)?;
                self.rip = next;
            }
            IMUL3 => {
                let size = o[0].size();
                let a = self.read_op(&o[1])?;
                let b = self.read_op(&o[2])?;
                let p = sext128(a, size).wrapping_mul(sext128(b, size));
                let res = (p as u64) & size_mask(size);
                self.flags.cf = p != sext128(res, size);
                self.flags.of = self.flags.cf;
                self.write_op(&o[0], res)?;
                self.rip = next;
            }
            DIV => {
                self.exec_div(&o[0], false)?;
                self.rip = next;
            }
            IDIV => {
                self.exec_div(&o[0], true)?;
                self.rip = next;
            }
            SHL | SHR | SAR | ROL | ROR => {
                self.exec_shift(insn.op, &o[0], &o[1])?;
                self.rip = next;
            }
            SHLD | SHRD => {
                self.exec_dshift(insn.op, &o[0], &o[1], &o[2])?;
                self.rip = next;
            }
            SETCC => {
                let v = self.cond(insn.extra) as u64;
                self.write_op(&o[0], v)?;
                self.rip = next;
            }
            CMOVCC => {
                if self.cond(insn.extra) {
                    let v = self.read_op(&o[1])?;
                    self.write_op(&o[0], v)?;
                }
                self.rip = next;
            }
            JCC => {
                let t = self.read_op(&o[0])?;
                self.rip = if self.cond(insn.extra) { t } else { next };
            }
            JMP => {
                self.rip = self.read_op(&o[0])?;
            }
            CALL => {
                let t = self.read_op(&o[0])?;
                self.push(next)?;
                self.rip = t;
            }
            RET => {
                self.rip = self.pop()?;
            }
            PUSH => {
                let v = self.read_op(&o[0])?;
                self.push(v)?;
                self.rip = next;
            }
            POP => {
                let v = self.pop()?;
                self.write_op(&o[0], v)?;
                self.rip = next;
            }
            RDTSC => {
                self.gpr[RAX] = self.tsc;
                self.gpr[RDX] = self.tsc >> 32;
                self.tsc = self.tsc.wrapping_add(self.tsc_step);
                self.rip = next;
            }
            NOP => self.rip = next,
            BSWAP => {
                let size = o[0].size();
                let v = self.read_op(&o[0])?;
                let r = match size {
                    4 => (v as u32).swap_bytes() as u64,
                    8 => v.swap_bytes(),
                    _ => return Err(VmError::BadOperand("bswap size")),
                };
                self.write_op(&o[0], r)?;
                self.rip = next;
            }
            SSE_MOVDQA | SSE_MOVDQU | SSE_MOVUPS => {
                let v = self.read_xmm(&o[1])?;
                self.write_xmm(&o[0], &v)?;
                self.rip = next;
            }
            SSE_MOVQ | SSE_MOVD => {
                let len = if insn.op == SSE_MOVQ { 8 } else { 4 };
                let v = self.read_wide(&o[1], len)?;
                self.write_wide(&o[0], len, v)?;
                self.rip = next;
            }
            SSE_PADDD | SSE_PSUBD | SSE_PAND | SSE_POR | SSE_PXOR | SSE_PMULLD | SSE_PMULLW
            | SSE_PCMPEQD => {
                let a = self.read_xmm(&o[0])?;
                let b = self.read_xmm(&o[1])?;
                let mut r = [0u8; 16];
                match insn.op {
                    SSE_PADDD => {
                        for i in 0..4 {
                            let x = rd32(&a, i).wrapping_add(rd32(&b, i));
                            wr32(&mut r, i, x);
                        }
                    }
                    SSE_PSUBD => {
                        for i in 0..4 {
                            let x = rd32(&a, i).wrapping_sub(rd32(&b, i));
                            wr32(&mut r, i, x);
                        }
                    }
                    SSE_PAND => {
                        for i in 0..16 {
                            r[i] = a[i] & b[i];
                        }
                    }
                    SSE_POR => {
                        for i in 0..16 {
                            r[i] = a[i] | b[i];
                        }
                    }
                    SSE_PXOR => {
                        for i in 0..16 {
                            r[i] = a[i] ^ b[i];
                        }
                    }
                    SSE_PMULLD => {
                        for i in 0..4 {
                            let x = rd32(&a, i).wrapping_mul(rd32(&b, i));
                            wr32(&mut r, i, x);
                        }
                    }
                    SSE_PMULLW => {
                        for i in 0..8 {
                            let x = rd16(&a, i).wrapping_mul(rd16(&b, i));
                            wr16(&mut r, i, x);
                        }
                    }
                    SSE_PCMPEQD => {
                        for i in 0..4 {
                            let x = if rd32(&a, i) == rd32(&b, i) {
                                0xffff_ffff
                            } else {
                                0
                            };
                            wr32(&mut r, i, x);
                        }
                    }
                    _ => unreachable!(),
                }
                self.write_xmm(&o[0], &r)?;
                self.rip = next;
            }
            SSE_PSHUFD => {
                let a = self.read_xmm(&o[1])?;
                let imm = insn.extra as u32;
                let mut r = [0u8; 16];
                for i in 0..4 {
                    let lane = ((imm >> (2 * i)) & 3) as usize;
                    wr32(&mut r, i, rd32(&a, lane));
                }
                self.write_xmm(&o[0], &r)?;
                self.rip = next;
            }
            SSE_PSHUFB => {
                let a = self.read_xmm(&o[0])?;
                let b = self.read_xmm(&o[1])?;
                let mut r = [0u8; 16];
                for i in 0..16 {
                    r[i] = if b[i] & 0x80 != 0 {
                        0
                    } else {
                        a[(b[i] & 0x0f) as usize]
                    };
                }
                self.write_xmm(&o[0], &r)?;
                self.rip = next;
            }
            SSE_PMOVZX => {
                let a = self.read_xmm(&o[1])?;
                let mut r = [0u8; 16];
                match insn.extra {
                    0 => {
                        // pmovzxbd: 4 bytes -> 4 dwords
                        for (i, &byte) in a.iter().take(4).enumerate() {
                            wr32(&mut r, i, byte as u32);
                        }
                    }
                    1 => {
                        // pmovzxbw: 8 bytes -> 8 words
                        for (i, &byte) in a.iter().take(8).enumerate() {
                            wr16(&mut r, i, byte as u16);
                        }
                    }
                    _ => {
                        // pmovzxdq: 2 dwords -> 2 qwords
                        for i in 0..2 {
                            wr64(&mut r, i, rd32(&a, i) as u64);
                        }
                    }
                }
                self.write_xmm(&o[0], &r)?;
                self.rip = next;
            }
            SSE_PINSRD => {
                let mut dst = self.read_xmm(&o[0])?;
                let v = self.read_op(&o[1])? as u32;
                wr32(&mut dst, (insn.extra & 3) as usize, v);
                self.write_xmm(&o[0], &dst)?;
                self.rip = next;
            }
            SSE_PEXTRD | SSE_PEXTRQ => {
                let src = self.read_xmm(&o[1])?;
                let idx = insn.extra as usize;
                let v = if insn.op == SSE_PEXTRD {
                    rd32(&src, idx & 3) as u64
                } else {
                    rd64(&src, idx & 1)
                };
                self.write_op(&o[0], v)?;
                self.rip = next;
            }
            SSE_PACKUSDW => {
                let a = self.read_xmm(&o[0])?;
                let b = self.read_xmm(&o[1])?;
                let mut r = [0u8; 16];
                for i in 0..4 {
                    wr16(&mut r, i, sat_u16(rd32(&a, i) as i32));
                }
                for i in 0..4 {
                    wr16(&mut r, 4 + i, sat_u16(rd32(&b, i) as i32));
                }
                self.write_xmm(&o[0], &r)?;
                self.rip = next;
            }
            SSE_PACKUSWB => {
                let a = self.read_xmm(&o[0])?;
                let b = self.read_xmm(&o[1])?;
                let mut r = [0u8; 16];
                // PACKUSWB saturates eight words from each source, not four:
                // it is the byte-wide pack, so both halves fill all 16 bytes.
                for (i, slot) in r.iter_mut().take(8).enumerate() {
                    *slot = sat_u8(rd16(&a, i) as i16);
                }
                for i in 0..8 {
                    r[8 + i] = sat_u8(rd16(&b, i) as i16);
                }
                self.write_xmm(&o[0], &r)?;
                self.rip = next;
            }
            SSE_PUNPCKLQDQ => {
                let a = self.read_xmm(&o[0])?;
                let b = self.read_xmm(&o[1])?;
                let mut r = [0u8; 16];
                r[..8].copy_from_slice(&a[..8]);
                r[8..].copy_from_slice(&b[..8]);
                self.write_xmm(&o[0], &r)?;
                self.rip = next;
            }
            SSE_PSLLD | SSE_PSRLD => {
                let a = self.read_xmm(&o[0])?;
                let cnt = self.read_op(&o[1])?;
                let mut r = [0u8; 16];
                if cnt <= 31 {
                    for i in 0..4 {
                        let x = if insn.op == SSE_PSLLD {
                            rd32(&a, i) << cnt
                        } else {
                            rd32(&a, i) >> cnt
                        };
                        wr32(&mut r, i, x);
                    }
                }
                self.write_xmm(&o[0], &r)?;
                self.rip = next;
            }
            SSE_BLENDVPS => {
                let a = self.read_xmm(&o[0])?;
                let b = self.read_xmm(&o[1])?;
                let mask = self.xmm[0];
                let mut r = [0u8; 16];
                for i in 0..4 {
                    let pick_src = rd32(&mask, i) & 0x8000_0000 != 0;
                    wr32(&mut r, i, if pick_src { rd32(&b, i) } else { rd32(&a, i) });
                }
                self.write_xmm(&o[0], &r)?;
                self.rip = next;
            }
            SYSCALL => return Err(VmError::Unsupported(SYSCALL)),
            other => return Err(VmError::Unsupported(other)),
        }
        Ok(())
    }

    fn exec_alu(&mut self, op: u16, dst_o: &Operand, src_o: &Operand) -> Result<(), VmError> {
        let size = dst_o.size();
        let mask = size_mask(size);
        let sign = size_sign(size);
        let dst = self.read_op(dst_o)? & mask;
        let src = self.read_op(src_o)? & mask;
        let mut res;
        match op {
            ADD | ADC => {
                let c = if op == ADC && self.flags.cf { 1u128 } else { 0 };
                let full = dst as u128 + src as u128 + c;
                res = (full as u64) & mask;
                self.flags.cf = (full >> size_bits(size)) & 1 != 0;
                self.flags.of = ((dst ^ res) & (src ^ res) & sign) != 0;
                self.flags.af = ((dst ^ src ^ res) & 0x10) != 0;
            }
            SUB | CMP | SBB => {
                let c = if op == SBB && self.flags.cf { 1 } else { 0 };
                res = dst.wrapping_sub(src).wrapping_sub(c) & mask;
                self.flags.cf = (dst as u128) < (src as u128 + c as u128);
                self.flags.of = ((dst ^ src) & (dst ^ res) & sign) != 0;
                self.flags.af = ((dst ^ src ^ res) & 0x10) != 0;
            }
            AND | OR | XOR | TEST => {
                res = match op {
                    AND | TEST => dst & src,
                    OR => dst | src,
                    _ => dst ^ src,
                };
                self.flags.cf = false;
                self.flags.of = false;
                self.flags.af = false;
            }
            _ => unreachable!(),
        }
        res &= mask;
        self.set_szp(res, size);
        if op != CMP && op != TEST {
            self.write_op(dst_o, res)?;
        }
        Ok(())
    }

    fn exec_mul(&mut self, src_o: &Operand, signed: bool) -> Result<(), VmError> {
        let size = src_o.size();
        let src = self.read_op(src_o)? & size_mask(size);
        match size {
            1 => {
                let a = self.gpr[RAX] & 0xff;
                if signed {
                    let p = (a as u8 as i8 as i16).wrapping_mul(src as u8 as i8 as i16);
                    let u = p as u16 as u64;
                    self.gpr[RAX] = (self.gpr[RAX] & !0xffff) | u;
                    let cf = p != (u & 0xff) as u8 as i8 as i16;
                    self.flags.cf = cf;
                    self.flags.of = cf;
                } else {
                    let p = a.wrapping_mul(src) & 0xffff;
                    self.gpr[RAX] = (self.gpr[RAX] & !0xffff) | p;
                    let cf = (p >> 8) != 0;
                    self.flags.cf = cf;
                    self.flags.of = cf;
                }
            }
            2 => {
                let a = self.gpr[RAX] & 0xffff;
                let p = if signed {
                    ((a as u16 as i16 as i32) * (src as u16 as i16 as i32)) as u32 as u64
                } else {
                    a.wrapping_mul(src)
                } & 0xffff_ffff;
                self.gpr[RAX] = (self.gpr[RAX] & !0xffff) | (p & 0xffff);
                self.gpr[RDX] = (self.gpr[RDX] & !0xffff) | (p >> 16);
                let cf = if signed {
                    p as u32 as i32 != (p & 0xffff) as u16 as i16 as i32
                } else {
                    (p >> 16) != 0
                };
                self.flags.cf = cf;
                self.flags.of = cf;
            }
            4 => {
                let a = self.gpr[RAX] & 0xffff_ffff;
                let p = if signed {
                    ((a as u32 as i32 as i64) * (src as u32 as i32 as i64)) as u64
                } else {
                    a.wrapping_mul(src)
                };
                self.gpr[RAX] = p & 0xffff_ffff;
                self.gpr[RDX] = (p >> 32) & 0xffff_ffff;
                let cf = if signed {
                    p as i64 != (p & 0xffff_ffff) as u32 as i32 as i64
                } else {
                    (p >> 32) != 0
                };
                self.flags.cf = cf;
                self.flags.of = cf;
            }
            _ => {
                let p = if signed {
                    ((self.gpr[RAX] as i64 as i128) * (src as i64 as i128)) as u128
                } else {
                    (self.gpr[RAX] as u128) * (src as u128)
                };
                self.gpr[RAX] = p as u64;
                self.gpr[RDX] = (p >> 64) as u64;
                let cf = if signed {
                    p as i128 != (p as u64 as i64 as i128)
                } else {
                    (p >> 64) != 0
                };
                self.flags.cf = cf;
                self.flags.of = cf;
            }
        }
        Ok(())
    }

    fn exec_div(&mut self, src_o: &Operand, signed: bool) -> Result<(), VmError> {
        let size = src_o.size();
        let src = self.read_op(src_o)? & size_mask(size);
        if src == 0 {
            return Err(VmError::DivZero);
        }
        match size {
            1 => {
                let a = (self.gpr[RAX] & 0xffff) as u16;
                let (q, r) = if signed {
                    let n = a as i16 as i32;
                    let d = src as u8 as i8 as i32;
                    (n / d, n % d)
                } else {
                    let d = src as u16;
                    ((a / d) as i32, (a % d) as i32)
                };
                let packed = ((q as u16 & 0xff) as u64) | (((r as u16 & 0xff) as u64) << 8);
                self.gpr[RAX] = (self.gpr[RAX] & !0xffff) | packed;
            }
            2 => {
                let a = ((self.gpr[RDX] & 0xffff) << 16 | (self.gpr[RAX] & 0xffff)) as u32;
                if signed {
                    let n = a as i32;
                    let d = src as u16 as i16 as i32;
                    let q = n / d;
                    let r = n % d;
                    self.gpr[RAX] = (self.gpr[RAX] & !0xffff) | (q as u16 as u64);
                    self.gpr[RDX] = (self.gpr[RDX] & !0xffff) | (r as u16 as u64);
                } else {
                    let d = src as u32;
                    let q = a / d;
                    let r = a % d;
                    self.gpr[RAX] = (self.gpr[RAX] & !0xffff) | (q as u64 & 0xffff);
                    self.gpr[RDX] = (self.gpr[RDX] & !0xffff) | (r as u64 & 0xffff);
                }
            }
            4 => {
                let a = ((self.gpr[RDX] & 0xffff_ffff) << 32) | (self.gpr[RAX] & 0xffff_ffff);
                if signed {
                    let n = a as i64;
                    let d = src as u32 as i32 as i64;
                    let q = n / d;
                    let r = n % d;
                    self.gpr[RAX] = q as u64 & 0xffff_ffff;
                    self.gpr[RDX] = r as u64 & 0xffff_ffff;
                } else {
                    let d = src;
                    let q = a / d;
                    let r = a % d;
                    self.gpr[RAX] = q & 0xffff_ffff;
                    self.gpr[RDX] = r & 0xffff_ffff;
                }
            }
            _ => {
                let a = ((self.gpr[RDX] as u128) << 64) | (self.gpr[RAX] as u128);
                if signed {
                    let n = a as i128;
                    let d = src as i64 as i128;
                    let q = n.checked_div(d).ok_or(VmError::DivZero)?;
                    let r = n % d;
                    self.gpr[RAX] = q as u64;
                    self.gpr[RDX] = r as u64;
                } else {
                    let d = src as u128;
                    let q = a / d;
                    let r = a % d;
                    self.gpr[RAX] = q as u64;
                    self.gpr[RDX] = r as u64;
                }
            }
        }
        Ok(())
    }

    fn shift_count(&self, o: &Operand, size: u8) -> Result<u32, VmError> {
        let raw = self.read_op(o)?;
        let mask = if size == 8 { 63 } else { 31 };
        Ok((raw & mask) as u32)
    }

    fn exec_shift(&mut self, op: u16, dst_o: &Operand, cnt_o: &Operand) -> Result<(), VmError> {
        let size = dst_o.size();
        let bits = size_bits(size);
        let mask = size_mask(size);
        let dst = self.read_op(dst_o)? & mask;
        let cnt = self.shift_count(cnt_o, size)?;
        if cnt == 0 {
            return Ok(());
        }
        let res;
        match op {
            SHL => {
                res = (dst << cnt) & mask;
                self.flags.cf = ((dst >> (bits - cnt)) & 1) != 0;
                self.flags.of = (((res >> (bits - 1)) & 1) ^ self.flags.cf as u64) != 0;
            }
            SHR => {
                res = dst >> cnt;
                self.flags.cf = ((dst >> (cnt - 1)) & 1) != 0;
                self.flags.of = ((dst >> (bits - 1)) & 1) != 0;
            }
            SAR => {
                let s = sext128(dst, size);
                res = ((s >> cnt) as u64) & mask;
                self.flags.cf = ((dst >> (cnt - 1)) & 1) != 0;
                self.flags.of = false;
            }
            ROL => {
                let c = cnt % bits;
                res = if c == 0 {
                    dst
                } else {
                    ((dst << c) | (dst >> (bits - c))) & mask
                };
                self.flags.cf = (res & 1) != 0;
                self.flags.of = ((res >> (bits - 1)) & 1) != self.flags.cf as u64;
            }
            ROR => {
                let c = cnt % bits;
                res = if c == 0 {
                    dst
                } else {
                    ((dst >> c) | (dst << (bits - c))) & mask
                };
                self.flags.cf = ((res >> (bits - 1)) & 1) != 0;
                self.flags.of = ((res >> (bits - 1)) & 1) != ((res >> (bits - 2)) & 1);
            }
            _ => unreachable!(),
        }
        self.set_szp(res, size);
        self.write_op(dst_o, res)?;
        Ok(())
    }

    fn exec_dshift(
        &mut self,
        op: u16,
        dst_o: &Operand,
        src_o: &Operand,
        cnt_o: &Operand,
    ) -> Result<(), VmError> {
        let size = dst_o.size();
        let bits = size_bits(size);
        let mask = size_mask(size);
        let dst = self.read_op(dst_o)? & mask;
        let src = self.read_op(src_o)? & mask;
        let cnt = self.shift_count(cnt_o, size)?;
        if cnt == 0 {
            return Ok(());
        }
        let res;
        if op == SHLD {
            res = ((dst << cnt) | (src >> (bits - cnt))) & mask;
            self.flags.cf = ((dst >> (bits - cnt)) & 1) != 0;
            self.flags.of = ((dst >> (bits - 1)) & 1) != ((res >> (bits - 1)) & 1);
        } else {
            res = ((dst >> cnt) | (src << (bits - cnt))) & mask;
            self.flags.cf = ((dst >> (cnt - 1)) & 1) != 0;
            self.flags.of = ((dst >> (bits - 1)) & 1) != ((res >> (bits - 1)) & 1);
        }
        self.set_szp(res, size);
        self.write_op(dst_o, res)?;
        Ok(())
    }
}

fn reg_read(gpr: &[u64; 16], idx: usize, size: u8) -> u64 {
    let v = gpr[idx];
    match size {
        1 => v & 0xff,
        2 => v & 0xffff,
        4 => v & 0xffff_ffff,
        8 => v,
        HB => (v >> 8) & 0xff,
        _ => v,
    }
}

fn reg_write(gpr: &mut [u64; 16], idx: usize, size: u8, v: u64) {
    match size {
        1 => gpr[idx] = (gpr[idx] & !0xff) | (v & 0xff),
        2 => gpr[idx] = (gpr[idx] & !0xffff) | (v & 0xffff),
        4 => gpr[idx] = v & 0xffff_ffff, // x86-64 zero-extends 32-bit writes
        8 => gpr[idx] = v,
        HB => gpr[idx] = (gpr[idx] & !0xff00) | ((v & 0xff) << 8),
        _ => gpr[idx] = v,
    }
}

fn rd16(b: &[u8; 16], i: usize) -> u16 {
    u16::from_le_bytes([b[2 * i], b[2 * i + 1]])
}

fn wr16(b: &mut [u8; 16], i: usize, v: u16) {
    b[2 * i..2 * i + 2].copy_from_slice(&v.to_le_bytes());
}

fn rd32(b: &[u8; 16], i: usize) -> u32 {
    u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
}

fn wr32(b: &mut [u8; 16], i: usize, v: u32) {
    b[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
}

fn rd64(b: &[u8; 16], i: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[8 * i..8 * i + 8]);
    u64::from_le_bytes(x)
}

fn wr64(b: &mut [u8; 16], i: usize, v: u64) {
    b[8 * i..8 * i + 8].copy_from_slice(&v.to_le_bytes());
}

fn sat_u16(v: i32) -> u16 {
    v.clamp(0, 0xffff) as u16
}

fn sat_u8(v: i16) -> u8 {
    v.clamp(0, 0xff) as u8
}

// -- program file ----------------------------------------------------------
pub struct Program {
    pub insns: HashMap<u64, Insn>,
    /// (module idx, load bias, size)
    pub modules: Vec<(u8, u64, u64)>,
}

impl Program {
    pub fn load(path: &str) -> Result<Self, VmError> {
        let data = fs::read(path).map_err(VmError::Io)?;
        Self::parse(&data)
    }

    pub fn parse(data: &[u8]) -> Result<Self, VmError> {
        let mut c = Cursor::new(data);
        let magic = c.u32()?;
        if magic != 0x5056_4d50 {
            return Err(VmError::BadProgram(format!("magic {magic:#x}")));
        }
        let ver = c.u32()?;
        if ver != 3 {
            return Err(VmError::BadProgram(format!("version {ver}")));
        }
        let ninsn = c.u32()? as usize;
        let nmods = c.u32()? as usize;
        let mut modules = Vec::with_capacity(nmods);
        let mut mod_of = HashMap::new();
        for _ in 0..nmods {
            let idx = c.u8()?;
            let bias = c.u64()?;
            let size = c.u64()?;
            mod_of.insert(idx, bias);
            modules.push((idx, bias, size));
        }
        let mut insns = HashMap::with_capacity(ninsn);
        for _ in 0..ninsn {
            let module = c.u8()?;
            let op = c.u16()?;
            let nops = c.u8()?;
            let extra = c.u8()?;
            let ilen = c.u8()?;
            let rva = c.u64()?;
            if nops > 3 {
                return Err(VmError::BadProgram(format!("nops {nops}")));
            }
            let mut ops = [Operand::None; 3];
            for slot in ops.iter_mut().take(nops as usize) {
                *slot = c.operand()?;
            }
            let bias = *mod_of
                .get(&module)
                .ok_or_else(|| VmError::BadProgram(format!("module {module}")))?;
            insns.insert(
                bias.wrapping_add(rva),
                Insn {
                    op,
                    extra,
                    ilen,
                    ops,
                    nops,
                },
            );
        }
        Ok(Program { insns, modules })
    }

    pub fn locate(&self, addr: u64) -> Option<(u8, u64)> {
        for &(idx, bias, size) in &self.modules {
            if addr >= bias && addr < bias.wrapping_add(size) {
                return Some((idx, addr - bias));
            }
        }
        None
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], VmError> {
        if self.at + n > self.data.len() {
            return Err(VmError::BadProgram("truncated".into()));
        }
        let s = &self.data[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, VmError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, VmError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, VmError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, VmError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, VmError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn operand(&mut self) -> Result<Operand, VmError> {
        let tag = self.u8()?;
        Ok(match tag {
            OP_NONE => Operand::None,
            OP_REG => Operand::Reg {
                idx: self.u8()?,
                size: self.u8()?,
            },
            OP_MEM => Operand::Mem {
                base: self.u8()?,
                index: self.u8()?,
                scale: self.u8()?,
                size: self.u8()?,
                disp: self.i64()?,
            },
            OP_IMM => Operand::Imm {
                val: self.u64()?,
                size: self.u8()?,
            },
            OP_XMM => Operand::Xmm { idx: self.u8()? },
            OP_TARGET => Operand::Target(self.u64()?),
            other => return Err(VmError::BadProgram(format!("operand tag {other}"))),
        })
    }
}

// -- case bundle -----------------------------------------------------------
#[derive(Clone)]
pub struct Stub {
    pub rec_call: u64,
    pub rec_ret: u64,
    pub ret: u64,
    pub push: bool,
    pub gpr: [u64; 16],
    pub xmm: [[u8; 16]; 16],
}

/// One 8-byte word a libc call wrote, as observed by the tracer.
///
/// `rec_call`/`rec_ret` label the excursion, so the VM can apply the whole
/// batch when it takes that stub without knowing which libc function ran.
#[derive(Clone, Copy, Debug)]
pub struct MemDelta {
    pub rec_call: u64,
    pub rec_ret: u64,
    pub addr: u64,
    pub value: u64,
}

pub struct CaseBundle {
    pub entry_ip: u64,
    pub stop_rec: u64,
    pub tsc_base: u64,
    pub otp_addr: u64,
    pub otp: Vec<u8>,
    pub gpr: [u64; 16],
    pub xmm: [[u8; 16]; 16],
    pub seeds: Vec<(u64, Vec<u8>)>,
    pub stubs: Vec<Stub>,
    pub mem: Vec<MemDelta>,
}

impl CaseBundle {
    pub fn load(path: &str) -> Result<Self, VmError> {
        let data = fs::read(path).map_err(VmError::Io)?;
        Self::parse(&data)
    }

    pub fn parse(data: &[u8]) -> Result<Self, VmError> {
        let mut c = Cursor::new(data);
        let magic = c.u32()?;
        if magic != 0x4356_4d50 {
            return Err(VmError::BadBundle(format!("magic {magic:#x}")));
        }
        let ver = c.u32()?;
        if !(2..=3).contains(&ver) {
            return Err(VmError::BadBundle(format!("version {ver}")));
        }
        let entry_ip = c.u64()?;
        let stop_rec = c.u64()?;
        let tsc_base = c.u64()?;
        let otp_addr = c.u64()?;
        let otp_len = c.u32()? as usize;
        let otp = c.take(otp_len)?.to_vec();
        let mut gpr = [0u64; 16];
        for v in gpr.iter_mut() {
            *v = c.u64()?;
        }
        let xmm = read_xmm_block(&mut c)?;
        let nseeds = c.u32()? as usize;
        let mut seeds = Vec::with_capacity(nseeds);
        for _ in 0..nseeds {
            let addr = c.u64()?;
            let len = c.u64()? as usize;
            let bytes = c.take(len)?.to_vec();
            seeds.push((addr, bytes));
        }
        let nstubs = c.u32()? as usize;
        let mut stubs = Vec::with_capacity(nstubs);
        for _ in 0..nstubs {
            let rec_call = c.u64()?;
            let rec_ret = c.u64()?;
            let ret = c.u64()?;
            let push = c.u8()? != 0;
            let mut gpr = [0u64; 16];
            for v in gpr.iter_mut() {
                *v = c.u64()?;
            }
            let xmm = read_xmm_block(&mut c)?;
            stubs.push(Stub {
                rec_call,
                rec_ret,
                ret,
                push,
                gpr,
                xmm,
            });
        }
        let mut mem = Vec::new();
        if ver >= 3 {
            let nmem = c.u32()? as usize;
            mem.reserve(nmem);
            for _ in 0..nmem {
                mem.push(MemDelta {
                    rec_call: c.u64()?,
                    rec_ret: c.u64()?,
                    addr: c.u64()?,
                    value: c.u64()?,
                });
            }
        }
        Ok(CaseBundle {
            entry_ip,
            stop_rec,
            tsc_base,
            otp_addr,
            otp,
            gpr,
            xmm,
            seeds,
            stubs,
            mem,
        })
    }
}

fn read_xmm_block(c: &mut Cursor<'_>) -> Result<[[u8; 16]; 16], VmError> {
    let raw = c.take(256)?;
    let mut xmm = [[0u8; 16]; 16];
    for (i, x) in xmm.iter_mut().enumerate() {
        x.copy_from_slice(&raw[16 * i..16 * i + 16]);
    }
    Ok(xmm)
}

// -- trace reader ----------------------------------------------------------
pub struct TraceRec {
    pub ip: u64,
    pub gpr: [u64; 16],
    pub xmm: [[u8; 16]; 16],
    pub kind: u8,
}

pub struct TraceReader {
    f: BufReader<File>,
    /// index of the next record to be read
    pub pos: u64,
    pub n: u64,
}

impl TraceReader {
    pub fn open(path: &str) -> Result<Self, VmError> {
        let f = File::open(path).map_err(VmError::Io)?;
        let len = f.metadata().map_err(VmError::Io)?.len() as usize;
        Ok(TraceReader {
            f: BufReader::with_capacity(1 << 20, f),
            pos: 0,
            n: (len / REC) as u64,
        })
    }

    pub fn seek_rec(&mut self, rec: u64) -> Result<(), VmError> {
        self.f
            .seek(SeekFrom::Start(rec * REC as u64))
            .map_err(VmError::Io)?;
        self.pos = rec;
        Ok(())
    }

    pub fn next_record(&mut self) -> Result<Option<TraceRec>, VmError> {
        let mut buf = [0u8; REC];
        match self.f.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(VmError::Io(e)),
        }
        self.pos += 1;
        let ip = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let mut gpr = [0u64; 16];
        for (i, v) in gpr.iter_mut().enumerate() {
            *v = u64::from_le_bytes(buf[8 + 8 * i..16 + 8 * i].try_into().unwrap());
        }
        let mut xmm = [[0u8; 16]; 16];
        let base = TREC + XMM_OFF;
        for (i, x) in xmm.iter_mut().enumerate() {
            x.copy_from_slice(&buf[base + 16 * i..base + 16 * i + 16]);
        }
        Ok(Some(TraceRec {
            ip,
            gpr,
            xmm,
            kind: buf[148],
        }))
    }
}

// -- run and verify --------------------------------------------------------
pub struct RunOptions {
    pub verify_xmm: bool,
    pub stop_rec: Option<u64>,
    pub progress_every: u64,
    pub quiet: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            verify_xmm: true,
            stop_rec: None,
            progress_every: 100_000,
            quiet: false,
        }
    }
}

#[derive(Default)]
pub struct RunStats {
    pub steps: u64,
    pub stubs: u64,
    pub records: u64,
    pub tsc_reads: u64,
}

pub struct Mismatch {
    pub rec: u64,
    pub expected_ip: u64,
    pub actual_ip: u64,
    pub reg_diffs: Vec<String>,
    pub xmm_diffs: Vec<String>,
    pub last: Vec<String>,
    pub cause: Option<String>,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "divergence at rec {}: expected ip {:#x}, VM rip {:#x}",
            self.rec, self.expected_ip, self.actual_ip
        )?;
        if let Some(c) = &self.cause {
            writeln!(f, "cause: {c}")?;
        }
        for d in &self.reg_diffs {
            writeln!(f, "  reg {d}")?;
        }
        for d in &self.xmm_diffs {
            writeln!(f, "  xmm {d}")?;
        }
        for l in &self.last {
            writeln!(f, "  back: {l}")?;
        }
        Ok(())
    }
}

fn fmt_loc(program: &Program, addr: u64) -> String {
    match program.locate(addr) {
        Some((idx, rva)) => format!("m{idx}:{rva:#x}"),
        None => format!("{addr:#x}"),
    }
}

pub fn run_verified(
    vm: &mut Vm,
    bundle: &CaseBundle,
    trace: &mut TraceReader,
    opt: &RunOptions,
) -> Result<RunStats, Box<Mismatch>> {
    let stop = opt.stop_rec.unwrap_or(bundle.stop_rec);
    let mut stats = RunStats::default();
    let mut i = 0u64;
    let mut stub_at = 0usize;
    let mut history: VecDeque<String> = VecDeque::with_capacity(12);
    trace
        .seek_rec(0)
        .map_err(|e| Box::new(fail(0, vm, 0, Some(e.to_string()))))?;

    while i <= stop {
        let rec = match trace.next_record() {
            Ok(Some(r)) => r,
            Ok(None) => return Err(Box::new(fail(i, vm, 0, Some("trace ended".into())))),
            Err(e) => return Err(Box::new(fail(i, vm, 0, Some(e.to_string())))),
        };
        stats.records += 1;
        if let Err((_ip_ok, reg_diffs, xmm_diffs)) = compare(vm, &rec, opt.verify_xmm) {
            let mut mm = fail(i, vm, rec.ip, None);
            mm.reg_diffs = reg_diffs;
            mm.xmm_diffs = xmm_diffs;
            mm.last = history.iter().cloned().collect();
            return Err(Box::new(mm));
        }
        if !opt.quiet && opt.progress_every > 0 && i.is_multiple_of(opt.progress_every) {
            eprintln!(
                "  rec {}/{} ip {} grip {:#x}",
                i,
                stop,
                fmt_loc(&vm.program, rec.ip),
                vm.gpr[RSP]
            );
        }
        if i == stop {
            break;
        }
        if stub_at < bundle.stubs.len() && bundle.stubs[stub_at].rec_call == i {
            let st = &bundle.stubs[stub_at];
            let call_rec = i;
            vm.gpr = st.gpr;
            vm.xmm = st.xmm;
            // libc is not lifted, but its caller-visible stores are: replay
            // them before resuming so the engine reads what it wrote.
            for d in &bundle.mem {
                if d.rec_call == call_rec && d.rec_ret == st.rec_ret {
                    // a VM-side write error here is a diagnostic, not an
                    // escape: map it into the same Mismatch box the caller
                    // already handles for every other stop.
                    if let Err(e) = vm.mem.write_uint(d.addr, 8, d.value) {
                        let mut mm = fail(i, vm, d.addr, Some(e.to_string()));
                        mm.last = history.iter().cloned().collect();
                        return Err(Box::new(mm));
                    }
                }
            }
            vm.rip = st.ret;
            stub_at += 1;
            stats.stubs += 1;
            i = st.rec_ret;
            history.push_back(format!(
                "rec {call_rec}: libc stub -> rec {i} {}",
                fmt_loc(&vm.program, vm.rip)
            ));
            if history.len() > 12 {
                history.pop_front();
            }
            if let Err(e) = trace.seek_rec(i) {
                return Err(Box::new(fail(i, vm, 0, Some(e.to_string()))));
            }
            continue;
        }
        let op = match vm.program.insns.get(&vm.rip) {
            Some(insn) => insn.op,
            None => {
                let mut mm = fail(i, vm, rec.ip, Some("no instruction".into()));
                mm.last = history.iter().cloned().collect();
                return Err(Box::new(mm));
            }
        };
        if vm.rip == rec.ip {
            history.push_back(format!(
                "rec {i} {} {}",
                fmt_loc(&vm.program, vm.rip),
                op_name(op)
            ));
            if history.len() > 12 {
                history.pop_front();
            }
        }
        match vm.step() {
            Ok(()) => {}
            Err(e) => {
                let mut mm = fail(i, vm, rec.ip, Some(e.to_string()));
                mm.actual_ip = vm.rip;
                mm.last = history.iter().cloned().collect();
                return Err(Box::new(mm));
            }
        }
        stats.steps += 1;
        i += 1;
    }
    Ok(stats)
}

fn fail(rec: u64, vm: &Vm, expected_ip: u64, cause: Option<String>) -> Mismatch {
    Mismatch {
        rec,
        expected_ip,
        actual_ip: vm.rip,
        reg_diffs: Vec::new(),
        xmm_diffs: Vec::new(),
        last: Vec::new(),
        cause,
    }
}

type Diffs = (bool, Vec<String>, Vec<String>);

fn compare(vm: &Vm, rec: &TraceRec, verify_xmm: bool) -> Result<(), Diffs> {
    let mut ip_ok = true;
    let mut regs = Vec::new();
    let mut xs = Vec::new();
    if vm.rip != rec.ip {
        ip_ok = false;
    }
    for (i, name) in REG_NAMES.iter().enumerate() {
        if vm.gpr[i] != rec.gpr[i] {
            regs.push(format!(
                "{}: vm {:#018x} != trace {:#018x}",
                name, vm.gpr[i], rec.gpr[i]
            ));
        }
    }
    if verify_xmm {
        for i in 0..16 {
            if vm.xmm[i] != rec.xmm[i] {
                xs.push(format!(
                    "xmm{}: vm {} != trace {}",
                    i,
                    hex(&vm.xmm[i]),
                    hex(&rec.xmm[i])
                ));
            }
        }
    }
    if ip_ok && regs.is_empty() && xs.is_empty() {
        Ok(())
    } else {
        Err((ip_ok, regs, xs))
    }
}

fn hex(b: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for x in b.iter() {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Load a bundle into a fresh VM.
pub fn prepare(bundle: &CaseBundle, program: Program) -> Vm {
    let mut vm = Vm::new(program);
    for (addr, bytes) in &bundle.seeds {
        vm.mem.seed(*addr, bytes);
    }
    vm.gpr = bundle.gpr;
    vm.xmm = bundle.xmm;
    vm.rip = bundle.entry_ip;
    vm.tsc = bundle.tsc_base;
    vm
}

pub fn otp(vm: &Vm, bundle: &CaseBundle) -> Result<Vec<u8>, VmError> {
    let mut out = vec![0u8; bundle.otp.len()];
    vm.mem
        .read_bytes(bundle.otp_addr, &mut out)
        .map_err(|addr| VmError::Read {
            addr,
            len: out.len(),
        })?;
    Ok(out)
}
