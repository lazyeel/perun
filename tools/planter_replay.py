#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0
"""Development-only Unicorn replay of the Android planter checkpoint.

The input is a private ``gcore`` checkpoint at libCoreADI RVA ``0xDD511``.
Raw checkpoints, arenas, registers and generated planters must remain outside
the repository with mode 0600/0700.  This module is an oracle for generation
and differential development, never a production dependency.
"""
import struct

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RSI,
    UC_X86_REG_RDI,
    UC_X86_REG_RBP,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
    UC_X86_REG_R14,
    UC_X86_REG_R15,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_FS_BASE,
    UC_X86_REG_GS_BASE,
)

LIB_BASE = 0x7FFFF7679000
ARENA = 0x7FFFF7814600
N_ARENA = 0xF0
START_RVA = 0xDD511
STOP_RVA = 0xE26DE
PLANTER_OFF = 0x44A0
SCHED_OFF = 0x18D0

REG_ORDER = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10",
    "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax",
    "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base",
    "ds", "es", "fs", "gs",
]
UC_GPR = {
    "rax": UC_X86_REG_RAX,
    "rbx": UC_X86_REG_RBX,
    "rcx": UC_X86_REG_RCX,
    "rdx": UC_X86_REG_RDX,
    "rsi": UC_X86_REG_RSI,
    "rdi": UC_X86_REG_RDI,
    "rbp": UC_X86_REG_RBP,
    "rsp": UC_X86_REG_RSP,
    "r8": UC_X86_REG_R8,
    "r9": UC_X86_REG_R9,
    "r10": UC_X86_REG_R10,
    "r11": UC_X86_REG_R11,
    "r12": UC_X86_REG_R12,
    "r13": UC_X86_REG_R13,
    "r14": UC_X86_REG_R14,
    "r15": UC_X86_REG_R15,
    "eflags": UC_X86_REG_EFLAGS,
    "fs_base": UC_X86_REG_FS_BASE,
    "gs_base": UC_X86_REG_GS_BASE,
}


def parse_core(path):
    """Return PT_LOAD and PT_NOTE records from an ELF core checkpoint."""
    with open(path, "rb") as f:
        header = f.read(0x40)
        phoff = struct.unpack_from("<Q", header, 0x20)[0]
        phentsize = struct.unpack_from("<H", header, 0x36)[0]
        phnum = struct.unpack_from("<H", header, 0x38)[0]
        loads, notes = [], []
        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            record = struct.unpack_from("<IIQQQQQQ", f.read(phentsize), 0)
            if record[0] == 1:
                loads.append(record)
            elif record[0] == 4:
                notes.append(record)
    return loads, notes


def parse_regs(path, notes):
    """Read NT_PRSTATUS solely to reconstruct the private oracle checkpoint."""
    with open(path, "rb") as f:
        for ptype, flags, off, vaddr, paddr, filesz, memsz, align in notes:
            f.seek(off)
            blob = f.read(filesz)
            pos = 0
            while pos + 12 <= len(blob):
                namesz, descsz, ntype = struct.unpack_from("<III", blob, pos)
                pos += 12
                pos += (namesz + 3) & ~3
                desc = blob[pos:pos + descsz]
                pos += (descsz + 3) & ~3
                if ntype == 1 and len(desc) >= 112 + 27 * 8:
                    values = struct.unpack_from("<27Q", desc, 112)
                    return dict(zip(REG_ORDER, values))
    return {}


def _stop_at_window_end(uc, address, size, lab):
    if address == LIB_BASE + STOP_RVA:
        lab.hits[0] += 1
        if lab.hits[0] >= 256:
            uc.emu_stop()
    return True


class Lab:
    """Reconstruct one checkpoint; install hooks before every measured run."""

    def __init__(self, core, map_limit=512 * 1024 * 1024):
        loads, notes = parse_core(core)
        self.regs = parse_regs(core, notes)
        if not self.regs:
            raise ValueError("no NT_PRSTATUS in the checkpoint")
        self.rbp = self.regs["rbp"]
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.contents = []
        with open(core, "rb") as f:
            for ptype, flags, off, vaddr, paddr, filesz, memsz, align in loads:
                if memsz == 0 or memsz > map_limit:
                    continue
                hi = (vaddr + memsz + 0xFFF) & ~0xFFF
                try:
                    self.uc.mem_map(vaddr, hi - vaddr, 7)
                except Exception:
                    continue
                f.seek(off)
                data = f.read(filesz)
                self.contents.append((vaddr, data, memsz))
                if data:
                    self.uc.mem_write(vaddr, data)
                if memsz > filesz:
                    self.uc.mem_write(vaddr + filesz, b"\0" * (memsz - filesz))
        self.hits = [0]
        self._reset()
        self.uc.hook_add(UC_HOOK_CODE, _stop_at_window_end, self)

    def _reset(self):
        for vaddr, data, memsz in self.contents:
            if data:
                self.uc.mem_write(vaddr, data)
            if memsz > len(data):
                self.uc.mem_write(vaddr + len(data), b"\0" * (memsz - len(data)))
        for name, reg in UC_GPR.items():
            self.uc.reg_write(reg, self.regs[name])
        self.uc.reg_write(UC_X86_REG_RIP, LIB_BASE + START_RVA)
        self.hits[0] = 0

    def _finish(self):
        rbp = self.uc.reg_read(UC_X86_REG_RBP)
        self.blob = bytes(self.uc.mem_read(rbp - PLANTER_OFF, 0x2700))
        self.sched = self.blob[SCHED_OFF:SCHED_OFF + 0xF0]

    def run(self):
        self._reset()
        self.uc.emu_start(LIB_BASE + START_RVA, 0xFFFFFFFFFFFFFFFF,
                          count=500_000_000)
        self._finish()

    def run_arena(self, arena):
        if len(arena) != N_ARENA:
            raise ValueError("the planter arena is exactly 240 bytes")
        self._reset()
        self.uc.mem_write(ARENA, bytes(arena))
        self.uc.emu_start(LIB_BASE + START_RVA, 0xFFFFFFFFFFFFFFFF,
                          count=500_000_000)
        self._finish()
        return self.sched
