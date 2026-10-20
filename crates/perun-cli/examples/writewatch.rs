// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! writewatch: a WRITE-ONLY watchpoint over the provisioning packet.
//!
//! The Configuration body (0xcfe0b46a) accepts the honest SPIM packet,
//! runs its cascade, and rewrites pkt[4..] with its verdict word --
//! the digest 0x9058b9ad on a failing session, 00000001 on a live one.
//! This tool catches the exact instruction that performs that write:
//!
//!   * the packet page is mapped PROT_READ -- reads pass, writes fault;
//!   * the SEGV handler logs rip/addr/registers, unprotects the page,
//!     and sets TF so the write retires;
//!   * the TRAP handler re-seals the page -- every subsequent write
//!     to the packet faults again and is logged the same way.
//!
//! The result is the full write schedule of the body against its own
//! packet, ending in the publisher of the verdict word at +4.

use perun_core::loader::{DLL_PROCESS_ATTACH, Image};
use perun_shims::table::ShimTable;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

type ExportFn = unsafe extern "win64" fn(u64, u64, u64, u64) -> u64;

static WATCH_BASE: AtomicU64 = AtomicU64::new(0);
static WATCH_LEN: AtomicU64 = AtomicU64::new(0);
static ZONE_PROBE_AT: AtomicU64 = AtomicU64::new(0);
static ZONE_PROBE_ORIG: AtomicU64 = AtomicU64::new(0);
static ZONE_PROBE_HIT: AtomicU64 = AtomicU64::new(0);
static SPIM_BASE: AtomicU64 = AtomicU64::new(0);
static SPIM_HIT: AtomicU64 = AtomicU64::new(0);
static RESEAL_SPIM: AtomicBool = AtomicBool::new(false);
static T8_BASE: AtomicU64 = AtomicU64::new(0);
static T8_HIT: AtomicU64 = AtomicU64::new(0);
static RESEAL_T8: AtomicBool = AtomicBool::new(false);
static INIT_PKT_Q0: AtomicU64 = AtomicU64::new(0);
static INIT_PKT_Q1: AtomicU64 = AtomicU64::new(0);
static ZONE_REARM: AtomicBool = AtomicBool::new(false);
static RESEAL: AtomicBool = AtomicBool::new(false);
static HIT_N: AtomicU64 = AtomicU64::new(0);

extern "C" fn on_segv(_sig: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    unsafe {
        let addr = (*info).si_addr() as u64;
        let uc = &mut *(ctx as *mut libc::ucontext_t);
        // PERUN_T8_ADDR: a write-only watch over the T8 table's page --
        // catching the writer instruction that fills the r9 conveyor's
        // first table (the 0x...a051 family).
        // PERUN_SPIM_TRACE: read-watch over the SPIM page -- every
        // guest read faults with the reader's rip and the offset.
        let sp = SPIM_BASE.load(Ordering::SeqCst);
        if sp != 0 && addr >= sp && addr < sp + 0x1000 {
            let rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
            let n = SPIM_HIT.fetch_add(1, Ordering::SeqCst);
            let off = addr - sp;
            let rax = uc.uc_mcontext.gregs[libc::REG_RAX as usize] as u64;
            let rbx = uc.uc_mcontext.gregs[libc::REG_RBX as usize] as u64;
            let rcx = uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u64;
            let rdx = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u64;
            let rsi = uc.uc_mcontext.gregs[libc::REG_RSI as usize] as u64;
            let rdi = uc.uc_mcontext.gregs[libc::REG_RDI as usize] as u64;
            let r8v = uc.uc_mcontext.gregs[libc::REG_R8 as usize] as u64;
            let r9v = uc.uc_mcontext.gregs[libc::REG_R9 as usize] as u64;
            let r10 = uc.uc_mcontext.gregs[libc::REG_R10 as usize] as u64;
            let r11 = uc.uc_mcontext.gregs[libc::REG_R11 as usize] as u64;
            let r14 = uc.uc_mcontext.gregs[libc::REG_R14 as usize] as u64;
            let mut line = [0u8; 320];
            let msg = format!(
                "[spim] READ#{n} rip={rip:#x} (rva={:#x}) spim+{off:#x} | rax={rax:#x} rbx={rbx:#x} rcx={rcx:#x} rdx={rdx:#x} rsi={rsi:#x} rdi={rdi:#x} r8={r8v:#x} r9={r9v:#x} r10={r10:#x} r11={r11:#x} r14={r14:#x}\n",
                rip.wrapping_sub(0x7c80_0000)
            );
            let bytes = msg.as_bytes();
            let nc = line.len().min(bytes.len());
            line[..nc].copy_from_slice(&bytes[..nc]);
            libc::write(2, line.as_ptr().cast(), nc);
            libc::mprotect(sp as *mut libc::c_void, 0x1000, libc::PROT_READ);
            uc.uc_mcontext.gregs[libc::REG_EFL as usize] |= 0x100;
            RESEAL_SPIM.store(true, Ordering::SeqCst);
            return;
        }
        let t8 = T8_BASE.load(Ordering::SeqCst);
        if t8 != 0 && addr >= t8 && addr < t8 + 0x1000 {
            let rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
            let n = T8_HIT.fetch_add(1, Ordering::SeqCst);
            let off = addr - t8;
            let rax = uc.uc_mcontext.gregs[libc::REG_RAX as usize] as u64;
            let rbx = uc.uc_mcontext.gregs[libc::REG_RBX as usize] as u64;
            let rcx = uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u64;
            let rdx = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u64;
            let rsi = uc.uc_mcontext.gregs[libc::REG_RSI as usize] as u64;
            let rdi = uc.uc_mcontext.gregs[libc::REG_RDI as usize] as u64;
            let r8v = uc.uc_mcontext.gregs[libc::REG_R8 as usize] as u64;
            let r9v = uc.uc_mcontext.gregs[libc::REG_R9 as usize] as u64;
            let r11 = uc.uc_mcontext.gregs[libc::REG_R11 as usize] as u64;
            let mut line = [0u8; 320];
            let msg = format!(
                "[t8] WRITE#{n} rip={rip:#x} (rva={:#x}) t8+{off:#x} | rax={rax:#x} rbx={rbx:#x} rcx={rcx:#x} rdx={rdx:#x} rsi={rsi:#x} rdi={rdi:#x} r8={r8v:#x} r9={r9v:#x} r11={r11:#x}\n",
                rip.wrapping_sub(0x7c80_0000)
            );
            let bytes = msg.as_bytes();
            let n_copy = line.len().min(bytes.len());
            line[..n_copy].copy_from_slice(&bytes[..n_copy]);
            libc::write(2, line.as_ptr().cast(), n_copy);
            libc::mprotect(
                t8 as *mut libc::c_void,
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE,
            );
            uc.uc_mcontext.gregs[libc::REG_EFL as usize] |= 0x100;
            RESEAL_T8.store(true, Ordering::SeqCst);
            return;
        }
        let base = WATCH_BASE.load(Ordering::SeqCst);
        let len = WATCH_LEN.load(Ordering::SeqCst);
        if len == 0 || addr < base || addr >= base.wrapping_add(len) {
            // Not our page: reinstall the default handler and re-raise so
            // the process dies with the real crash context.
            libc::signal(libc::SIGSEGV, libc::SIG_DFL);
            return;
        }
        let rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
        let off = addr - base;
        let n = HIT_N.fetch_add(1, Ordering::SeqCst);
        // PERUN_ITER0_SNAP: on the FIRST write capture the guest's
        // full frame [rsp-0x100 .. rsp+0x2000) -- the honestest
        // iteration-state snapshot, saved raw (regs + frame) to
        // PERUN_ITER0_OUT for the white-box driver's entry meal.
        if n == 0 && std::env::var_os("PERUN_ITER0_SNAP").is_some() {
            let rsp_g = uc.uc_mcontext.gregs[libc::REG_RSP as usize] as u64;
            let lo = rsp_g.wrapping_sub(0x100);
            let span = 0x2100usize;
            let g = &uc.uc_mcontext.gregs;
            let regs: [u64; 17] = [
                g[libc::REG_RAX as usize] as u64,
                g[libc::REG_RBX as usize] as u64,
                g[libc::REG_RCX as usize] as u64,
                g[libc::REG_RDX as usize] as u64,
                g[libc::REG_RSI as usize] as u64,
                g[libc::REG_RDI as usize] as u64,
                g[libc::REG_RBP as usize] as u64,
                g[libc::REG_RSP as usize] as u64,
                g[libc::REG_R8 as usize] as u64,
                g[libc::REG_R9 as usize] as u64,
                g[libc::REG_R10 as usize] as u64,
                g[libc::REG_R11 as usize] as u64,
                g[libc::REG_R12 as usize] as u64,
                g[libc::REG_R13 as usize] as u64,
                g[libc::REG_R14 as usize] as u64,
                g[libc::REG_R15 as usize] as u64,
                rip,
            ];
            let out = std::env::var("PERUN_ITER0_OUT")
                .unwrap_or_else(|_| "/opt/data/il/iter0_stack.bin".into());
            if let Ok(mut f) = std::fs::File::create(&out) {
                use std::io::Write as _;
                let _ = f.write_all(
                    &regs
                        .iter()
                        .flat_map(|v| v.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );
                let _ = f.write_all(&(rsp_g.wrapping_sub(0x100)).to_le_bytes());
                // The frame: read the guest's own stack span.
                let sl = std::slice::from_raw_parts(lo as *const u8, span);
                let _ = f.write_all(sl);
            }
        }
        let rax = uc.uc_mcontext.gregs[libc::REG_RAX as usize] as u64;
        let rbx = uc.uc_mcontext.gregs[libc::REG_RBX as usize] as u64;
        let rcx = uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u64;
        let rdx = uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u64;
        let rsi = uc.uc_mcontext.gregs[libc::REG_RSI as usize] as u64;
        let rdi = uc.uc_mcontext.gregs[libc::REG_RDI as usize] as u64;
        let rbp = uc.uc_mcontext.gregs[libc::REG_RBP as usize] as u64;
        let r8 = uc.uc_mcontext.gregs[libc::REG_R8 as usize] as u64;
        let r9 = uc.uc_mcontext.gregs[libc::REG_R9 as usize] as u64;
        let r10 = uc.uc_mcontext.gregs[libc::REG_R10 as usize] as u64;
        let r11 = uc.uc_mcontext.gregs[libc::REG_R11 as usize] as u64;
        let r12 = uc.uc_mcontext.gregs[libc::REG_R12 as usize] as u64;
        let r13 = uc.uc_mcontext.gregs[libc::REG_R13 as usize] as u64;
        let r14 = uc.uc_mcontext.gregs[libc::REG_R14 as usize] as u64;
        let r15 = uc.uc_mcontext.gregs[libc::REG_R15 as usize] as u64;
        // Raw write(2): async-signal-safe.
        let mut line = [0u8; 512];
        let msg = format!(
            "[ww] WRITE#{n} rip={rip:#x} (rva={:#x}) pkt+{off:#x} | rax={rax:#x} rbx={rbx:#x} rcx={rcx:#x} rdx={rdx:#x} rsi={rsi:#x} rdi={rdi:#x} rbp={rbp:#x} r8={r8:#x} r9={r9:#x} r10={r10:#x} r11={r11:#x} r12={r12:#x} r13={r13:#x} r14={r14:#x} r15={r15:#x}\n",
            rip.wrapping_sub(0x7c80_0000)
        );
        let bytes = msg.as_bytes();
        let n_copy = line.len().min(bytes.len());
        line[..n_copy].copy_from_slice(&bytes[..n_copy]);
        libc::write(2, line.as_ptr().cast(), n_copy);
        // Unseal so the faulting store retires, and arm TF so the very
        // next trap lets us re-seal (the write-only watch loop).
        libc::mprotect(
            base as *mut libc::c_void,
            len as usize,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        let flags = uc.uc_mcontext.gregs[libc::REG_EFL as usize] as u64;
        uc.uc_mcontext.gregs[libc::REG_EFL as usize] = (flags | 0x100) as i64;
        RESEAL.store(true, Ordering::SeqCst);
    }
}

extern "C" fn on_trap(_sig: libc::c_int, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    unsafe {
        // The zone probe: int3 at the fold zone's entry -- dump the
        // register file, restore the byte, single-step past it, and
        // re-arm for a second hit.
        let uc = &mut *(ctx as *mut libc::ucontext_t);
        let rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
        let zat = ZONE_PROBE_AT.load(Ordering::SeqCst);
        if zat != 0 && rip == zat + 1 {
            let n = ZONE_PROBE_HIT.fetch_add(1, Ordering::SeqCst);
            let g = &uc.uc_mcontext.gregs;
            let regs: [(&str, u64); 16] = [
                ("rax", g[libc::REG_RAX as usize] as u64),
                ("rbx", g[libc::REG_RBX as usize] as u64),
                ("rcx", g[libc::REG_RCX as usize] as u64),
                ("rdx", g[libc::REG_RDX as usize] as u64),
                ("rsi", g[libc::REG_RSI as usize] as u64),
                ("rdi", g[libc::REG_RDI as usize] as u64),
                ("rbp", g[libc::REG_RBP as usize] as u64),
                ("rsp", g[libc::REG_RSP as usize] as u64),
                ("r8", g[libc::REG_R8 as usize] as u64),
                ("r9", g[libc::REG_R9 as usize] as u64),
                ("r10", g[libc::REG_R10 as usize] as u64),
                ("r11", g[libc::REG_R11 as usize] as u64),
                ("r12", g[libc::REG_R12 as usize] as u64),
                ("r13", g[libc::REG_R13 as usize] as u64),
                ("r14", g[libc::REG_R14 as usize] as u64),
                ("r15", g[libc::REG_R15 as usize] as u64),
            ];
            let mut line = [0u8; 4096];
            let rsp_v = uc.uc_mcontext.gregs[libc::REG_RSP as usize] as u64;
            let mut msg = format!("[zone] HIT#{n} entry rip={rip:#x}\n");
            for (name, val) in regs {
                msg.push_str(&format!("  {name}={val:#x}\n"));
            }
            // The round's frame slots (the store offsets and the index
            // seeds the 16 channels read): one dump line each.
            for off in [
                0x88, 0xe8, 0x140, 0x310, 0x3c8, 0x4a0, 0x500, 0x508, 0x5c0, 0x68, 0x70,
            ] {
                let v = std::ptr::read_volatile((rsp_v + off) as *const u64);
                msg.push_str(&format!("  [rsp+{off:#x}]={v:#x}\n"));
            }
            // The T-table quartet's heads and the round's own indexes:
            let (r8v, r12v, r14v, rdxv) = (
                uc.uc_mcontext.gregs[libc::REG_R8 as usize] as u64,
                uc.uc_mcontext.gregs[libc::REG_R12 as usize] as u64,
                uc.uc_mcontext.gregs[libc::REG_R14 as usize] as u64,
                uc.uc_mcontext.gregs[libc::REG_RDX as usize] as u64,
            );
            // The init packet's own head -- the digest source check
            // (the a051 family lives in the init packet the body
            // published; T8 may be its direct rearrangement).
            msg.push_str(&format!(
                "  INITPKT: {:016x} {:016x}\n",
                INIT_PKT_Q0.load(Ordering::SeqCst),
                INIT_PKT_Q1.load(Ordering::SeqCst)
            ));
            // The ROUND-0 INDEXED words of the four tables -- the
            // conveyor's exact operands. The indexes are computed
            // here the way the guest computes them right after
            // this probe point (0x6f86d..0x6f892): ebx>>16 byte
            // ^0xe4 for T14, cl^0x70 for T12, (bpl+0x70)^0x70 for
            // Tdx, and [rsp+0x88]'s byte for T8.
            {
                let ebx = uc.uc_mcontext.gregs[libc::REG_RBX as usize] as u32;
                let rcxv = uc.uc_mcontext.gregs[libc::REG_RCX as usize] as u64;
                let rbpv = uc.uc_mcontext.gregs[libc::REG_RBP as usize] as u64;
                let f88 = std::ptr::read_volatile((rsp_v + 0x88) as *const u64) as u32;
                let i8 = (f88 & 0xff) as u64;
                let i14 = (((ebx >> 16) & 0xff) ^ 0xe4) as u64;
                let i12 = ((rcxv as u8) ^ 0x70) as u64;
                let idxdx = ((rbpv as u8).wrapping_add(0x70) ^ 0x70) as u64;
                if r8v > 0x10000 && r14v > 0x10000 && r12v > 0x10000 && rdxv > 0x10000 {
                    let w8 = std::ptr::read_volatile((r8v + i8 * 4) as *const u32);
                    let w14 = std::ptr::read_volatile((r14v + i14 * 4) as *const u32);
                    let w12 = std::ptr::read_volatile((r12v + i12 * 4) as *const u32);
                    let wdx = std::ptr::read_volatile((rdxv + idxdx * 4) as *const u32);
                    msg.push_str(&format!(
                        "  TIDX i8={i8:#x} T8={w8:#x} i14={i14:#x} T14={w14:#x} i12={i12:#x} T12={w12:#x} idxDx={idxdx:#x} Tdx={wdx:#x}\n"
                    ));
                }
            }
            // The first SIXTEEN words of each quartet table -- the
            // fill patterns (base words and index sweeps) side by side.
            for (name, base) in [("T8", r8v), ("T12", r12v), ("T14", r14v), ("Tdx", rdxv)] {
                if base > 0x10000 {
                    let mut row = String::new();
                    for k in 0..16u64 {
                        let w = std::ptr::read_volatile((base + k * 4) as *const u32);
                        row.push_str(&format!("{w:08x} "));
                    }
                    msg.push_str(&format!("  {name}ROW {base:#x}: {row}\n"));
                }
            }
            for (name, base) in [("T8", r8v), ("T12", r12v), ("T14", r14v), ("Tdx", rdxv)] {
                if base > 0x10000 {
                    let w0 = std::ptr::read_volatile(base as *const u32);
                    let w1 = std::ptr::read_volatile((base + 4) as *const u32);
                    let wmid = std::ptr::read_volatile((base + 0x200) as *const u32);
                    msg.push_str(&format!(
                        "  {name}[{base:#x}]: [0]={w0:#x} [1]={w1:#x} [mid]={wmid:#x}\n"
                    ));
                }
            }
            // The two packet-adjacent state pages the rounds also fold:
            let pkt_q = WATCH_BASE.load(Ordering::SeqCst);
            if pkt_q != 0 {
                for off in [0x0, 0x10, 0x20, 0x30] {
                    let v = std::ptr::read_volatile((pkt_q + off) as *const u64);
                    msg.push_str(&format!("  [pkt+{off:#x}]={v:#x}\n"));
                }
            }
            let bytes = msg.as_bytes();
            let nc = line.len().min(bytes.len());
            line[..nc].copy_from_slice(&bytes[..nc]);
            libc::write(2, line.as_ptr().cast(), nc);
            // Reusable probe: restore, rewind, single-step -- and the
            // TF trap handler re-arms the 0xcc (PERUN_ZONE_PROBE_MAX
            // caps the fire count; default 8).
            std::ptr::write_volatile(zat as *mut u8, ZONE_PROBE_ORIG.load(Ordering::SeqCst) as u8);
            uc.uc_mcontext.gregs[libc::REG_RIP as usize] = zat as i64;
            let flags = uc.uc_mcontext.gregs[libc::REG_EFL as usize] as u64;
            uc.uc_mcontext.gregs[libc::REG_EFL as usize] = (flags | 0x100) as i64;
            RESEAL.store(true, Ordering::SeqCst);
            ZONE_REARM.store(true, Ordering::SeqCst);
            return;
        }
        // The single-step after a SPIM read: re-seal the page.
        if RESEAL_SPIM.swap(false, Ordering::SeqCst) {
            let sb = SPIM_BASE.load(Ordering::SeqCst);
            if sb != 0 {
                libc::mprotect(sb as *mut libc::c_void, 0x1000, libc::PROT_NONE);
            }
            let flags = uc.uc_mcontext.gregs[libc::REG_EFL as usize] as u64;
            uc.uc_mcontext.gregs[libc::REG_EFL as usize] = (flags & !0x100) as i64;
            return;
        }
        // The single-step after a probe hit: put the 0xcc back (up to
        // PERUN_ZONE_PROBE_MAX fires), then re-seal the watch page.
        if ZONE_REARM.swap(false, Ordering::SeqCst) {
            let zat2 = ZONE_PROBE_AT.load(Ordering::SeqCst);
            let max: u64 = std::env::var("PERUN_ZONE_PROBE_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8);
            if ZONE_PROBE_HIT.load(Ordering::SeqCst) < max && zat2 != 0 {
                std::ptr::write_volatile(zat2 as *mut u8, 0xcc);
            } else {
                ZONE_PROBE_AT.store(0, Ordering::SeqCst);
            }
            let flags = uc.uc_mcontext.gregs[libc::REG_EFL as usize] as u64;
            uc.uc_mcontext.gregs[libc::REG_EFL as usize] = (flags & !0x100) as i64;
            RESEAL.store(true, Ordering::SeqCst);
            return;
        }
        if RESEAL_T8.swap(false, Ordering::SeqCst) {
            let t8b = T8_BASE.load(Ordering::SeqCst);
            if t8b != 0 {
                libc::mprotect(t8b as *mut libc::c_void, 0x1000, libc::PROT_READ);
            }
            let flags = uc.uc_mcontext.gregs[libc::REG_EFL as usize] as u64;
            uc.uc_mcontext.gregs[libc::REG_EFL as usize] = (flags & !0x100) as i64;
            return;
        }
        if RESEAL.swap(false, Ordering::SeqCst) {
            let base = WATCH_BASE.load(Ordering::SeqCst);
            let len = WATCH_LEN.load(Ordering::SeqCst);
            libc::mprotect(base as *mut libc::c_void, len as usize, libc::PROT_READ);
            let uc = &mut *(ctx as *mut libc::ucontext_t);
            let flags = uc.uc_mcontext.gregs[libc::REG_EFL as usize] as u64;
            uc.uc_mcontext.gregs[libc::REG_EFL as usize] = (flags & !0x100) as i64;
        }
    }
}

fn install_handlers() {
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = on_segv as *const () as usize;
        act.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
        libc::sigemptyset(&raw mut act.sa_mask);
        libc::sigaction(libc::SIGSEGV, &raw const act, std::ptr::null_mut());
        let mut act2: libc::sigaction = std::mem::zeroed();
        act2.sa_sigaction = on_trap as *const () as usize;
        act2.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
        libc::sigemptyset(&raw mut act2.sa_mask);
        libc::sigaction(libc::SIGTRAP, &raw const act2, std::ptr::null_mut());
    }
}

fn region(n: usize) -> *mut u8 {
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            n,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            eprintln!("mmap failed");
            std::process::exit(1);
        }
        std::ptr::write_bytes(p.cast::<u8>(), 0, n);
        p.cast::<u8>()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: writewatch <dll> <spim.bin>");
        std::process::exit(2);
    }
    let bytes = std::fs::read(&args[0]).unwrap_or_else(|e| {
        eprintln!("read dll: {e}");
        std::process::exit(1);
    });
    let spim = std::fs::read(&args[1]).unwrap_or_else(|e| {
        eprintln!("read spim: {e}");
        std::process::exit(1);
    });
    let mut table = ShimTable::collect();
    let image = match Image::load(&bytes, &mut table) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("load: {e:?}");
            std::process::exit(1);
        }
    };
    let _ = unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
    let dll_main = if let Some(f) = unsafe { image.entry_dll_main() } {
        f
    } else {
        eprintln!("no entry");
        std::process::exit(1);
    };
    if unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) } == 0 {
        eprintln!("DllMain FALSE");
        std::process::exit(3);
    }
    let op_ptr = if let Some(p) = image.get_export_by_name("vdfut768ig") {
        p
    } else {
        eprintln!("no export");
        std::process::exit(1);
    };
    let op: ExportFn = unsafe { std::mem::transmute(op_ptr) };

    // The honest cvu path call first: the Windows way to set the path.
    let cvu_ptr = if let Some(p) = image.get_export_by_name("cvu8io98wun") {
        p
    } else {
        eprintln!("no cvu export");
        std::process::exit(1);
    };
    let cvu: ExportFn = unsafe { std::mem::transmute(cvu_ptr) };
    let path_page = region(0x1000);
    let wide: Vec<u16> = "/opt/data/home/.perun/appdata/Common/Apple Computer/iTunes/adi\0"
        .encode_utf16()
        .collect();
    unsafe {
        for (i, w) in wide.iter().enumerate() {
            std::ptr::write_volatile((path_page as *mut u16).add(i), *w);
        }
    }
    // PERUN_T8_ADDR: write-watch the T8 page from the very start
    // (the table fills somewhere between cvu and the cfg conveyor).
    // The handlers go in FIRST -- host writes on the shared heap page
    // need the fall-through path from the very first cvu step.
    install_handlers();
    if let Some(v) = std::env::var("PERUN_T8_ADDR")
        .ok()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
    {
        T8_BASE.store(v, Ordering::SeqCst);
        WATCH_LEN.store(0x1000, Ordering::SeqCst);
        WATCH_BASE.store(0, Ordering::SeqCst);
        // Seal the page read-only NOW: any write (the table's fill
        // included) faults into the handler with the writer's rip.
        let pg = v & !0xfff;
        let mr = unsafe { libc::mprotect(pg as *mut libc::c_void, 0x1000, libc::PROT_READ) };
        eprintln!("[ww] T8 watch armed at {v:#x} (mprotect={mr})");
    }
    let _ = unsafe { cvu(path_page as u64, 0, 0, 0) };
    eprintln!("[ww] cvu rc noted");

    // The HONEST V1 init -- the a4485c6 contract, ported from
    // pipeline.rs verbatim: the live Call-1 envelope (the identity
    // string, the container form, the root path, the nanosec page)
    // with the V1-keyed packet (bytes 3 and 7 set), which answers
    // rc=0 and publishes the -45061 'not provisioned' verdict word
    // {ffff4ffb, 00000001} -- the SUCCESS family the T-quartet
    // sweep must bake instead of the failed branch's 0x4145a051.
    let init_ctx = region(0x1_0000);
    let init_pkt = region(0x1000);
    unsafe {
        std::ptr::write_bytes(init_pkt.cast::<u8>(), 0, 4096);
        std::ptr::write_volatile(init_pkt.cast::<u8>().add(3), 1);
        std::ptr::write_volatile(init_pkt.cast::<u8>().add(7), 1);
        let c = init_ctx.cast::<u64>();
        std::ptr::write_bytes(init_ctx.cast::<u8>(), 0, 0x1_0000);
        std::ptr::write_volatile(c.add(0), init_pkt as u64);
        std::ptr::write_volatile(c.add(1), 0x0000_0004_0000_0010); // len | flags
        std::ptr::write_volatile(c.add(2), 0x0000_7fff_0000_0000); // stack tag
        let cont18 = region(64);
        let ident_buf = region(4096);
        let id_hex: String = std::env::var("PERUN_IDENT").unwrap_or_else(|_| {
            perun_adi_win32::net::identity()
                .device_id
                .chars()
                .filter(|ch| *ch != '.')
                .take(16)
                .collect()
        });
        std::ptr::copy_nonoverlapping(id_hex.as_ptr(), ident_buf.cast::<u8>(), id_hex.len());
        std::ptr::write_volatile(ident_buf.cast::<u8>().add(id_hex.len()), 0);
        std::ptr::write_volatile(cont18.cast::<u64>(), ident_buf as u64);
        std::ptr::write_volatile(cont18.add(8) as *mut u64, 0x40u64 << 32);
        std::ptr::write_volatile(c.add(3), cont18 as u64); // +0x18 container
        std::ptr::write_volatile(c.add(4), 0x15); // +0x20 21, measured
        std::ptr::write_volatile(c.add(5), region(4096) as u64); // +0x28 zero page
        std::ptr::write_volatile(c.add(6), region(4096) as u64); // +0x30 zero page
        std::ptr::write_volatile(c.add(7), 0x0000_7fff_0000_0000);
        std::ptr::write_volatile(c.add(8), region(4096) as u64); // +0x40 zero page
        std::ptr::write_volatile(c.add(9), ident_buf as u64); // +0x48 identity
        let p68 = region(64);
        std::ptr::copy_nonoverlapping(b"/opt/data/perun/".as_ptr(), p68.cast::<u8>(), 16);
        std::ptr::write_volatile(p68.cast::<u8>().add(16), 0);
        std::ptr::write_volatile(c.add(13), p68 as u64); // +0x68 root path
        let nsp = region(64);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        std::ptr::write_volatile(nsp.cast::<u64>(), now);
        std::ptr::write_volatile(c.add(14), nsp as u64); // +0x70 nanosec
        eprintln!("[ww] ident={id_hex:?}");
        let r = op(0xb0eda7af, init_ctx as u64, 0, 0);
        // Keep the init packet for the probe: the T8 tail family
        // check (a051) and the X-sweep comparison -- the early
        // 0x67891 series fills this packet right before the
        // T-quartet allocations.
        let ipk = std::slice::from_raw_parts(init_pkt.cast::<u8>(), 0x180);
        let mut row = String::new();
        for b in ipk.iter().take(64) {
            row.push_str(&format!("{b:02x}"));
        }
        eprintln!("[ww] initpkt[0..64] = {row}");
        let mut row2 = String::new();
        for b in ipk.iter().skip(64).take(64) {
            row2.push_str(&format!("{b:02x}"));
        }
        eprintln!("[ww] initpkt[64..128] = {row2}");
        INIT_PKT_Q0.store(
            std::ptr::read_volatile(init_pkt.cast::<u64>()),
            Ordering::SeqCst,
        );
        INIT_PKT_Q1.store(
            std::ptr::read_volatile((init_pkt as *mut u64).add(1)),
            Ordering::SeqCst,
        );
        eprintln!("[ww] init rc={r:#x} ({r})");
    }

    // The provisioning packet on its OWN page (so the watch covers the
    // packet and nothing else): hdr V2, the BE SPIM length, the dsid
    // -1, then the 347-byte SPIM body.
    let pkt = region(0x1000);
    unsafe {
        let pb = pkt.cast::<u8>();
        *pb.add(0) = 0x00;
        *pb.add(1) = 0x00;
        *pb.add(2) = 0x00;
        *pb.add(3) = 0x02;
        let l = spim.len() as u32;
        *pb.add(4) = (l >> 24) as u8;
        *pb.add(5) = ((l >> 16) & 0xff) as u8;
        *pb.add(6) = ((l >> 8) & 0xff) as u8;
        *pb.add(7) = (l & 0xff) as u8;
        for i in 8..16usize {
            *pb.add(i) = 0xff; // the dsid wildcard
        }
        std::ptr::copy_nonoverlapping(spim.as_ptr(), pb.add(16), spim.len());
    }
    // The SPIM body page (the body reads it; it is NOT watched) and the
    // dedicated OUT buffer.
    let spim_page = region(0x1000);
    unsafe {
        std::ptr::copy_nonoverlapping(spim.as_ptr(), spim_page.cast::<u8>(), spim.len());
    }
    let out = region(0x1000);

    // The envelope frame: {pkt, input size, output size 512, flags 0x08,
    // the SPIM pointer/len pair, the measured 0x1d0, the OUT buffer}.
    let ctx = region(0x1_0000);
    unsafe {
        let c = ctx.cast::<u64>();
        std::ptr::write_volatile(c.add(0), pkt as u64);
        std::ptr::write_volatile(c.add(1), u64::from(spim.len() as u32) + 16);
        std::ptr::write_volatile(c.add(2), 512);
        std::ptr::write_volatile(c.add(3), 0x08);
        std::ptr::write_volatile(c.add(4), 0);
        std::ptr::write_volatile(c.add(6), spim_page as u64);
        std::ptr::write_volatile(c.add(7), u64::from(spim.len() as u32));
        std::ptr::write_volatile(c.add(14), 0x1d0);
        std::ptr::write_volatile(c.add(16), out as u64);
    }

    // PERUN_ZONE_PROBE=1: an int3 at the fold zone's entry
    // (image_base + 0x6c5fe) dumps the register file once, then
    // resumes -- measuring whether the cfg path crosses the zone.
    let zone_probe = std::env::var_os("PERUN_ZONE_PROBE").is_some();
    #[allow(unused_assignments)]
    let mut zone_orig = 0u8;
    let image_base = 0x7c80_0000u64;
    if zone_probe {
        unsafe {
            let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let a = image_base
                + u64::from(
                    std::env::var("PERUN_ZONE_PROBE_RVA")
                        .ok()
                        .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                        .unwrap_or(0x6c5fe),
                );
            let pg = a & !((page - 1) as u64);
            libc::mprotect(
                pg as *mut libc::c_void,
                page,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
            zone_orig = std::ptr::read_volatile(a as *const u8);
            std::ptr::write_volatile(a as *mut u8, 0xcc);
            ZONE_PROBE_AT.store(a, Ordering::SeqCst);
            ZONE_PROBE_ORIG.store(u64::from(zone_orig), Ordering::SeqCst);
        }
    }

    eprintln!(
        "[ww] pages: pkt={:#x} spim_page={:#x} out={:#x} init_pkt={:#x} init_ctx={:#x} ctx={:#x}",
        pkt as usize,
        spim_page as usize,
        out as usize,
        init_pkt as usize,
        init_ctx as usize,
        ctx as usize
    );
    // PERUN_SPIM_TRACE=1: read-watch the SPIM page from the cfg
    // call -- every guest read faults with its rip and offset.
    if std::env::var_os("PERUN_SPIM_TRACE").is_some() {
        SPIM_BASE.store(spim_page as u64, Ordering::SeqCst);
        unsafe {
            libc::mprotect(spim_page as *mut libc::c_void, 0x1000, libc::PROT_NONE);
        }
        eprintln!("[ww] SPIM read-watch armed at {:#x}", spim_page as usize);
    }
    // Arm the write-only watch over the packet page and call
    // (PERUN_NO_WATCH=1 leaves the packet writable -- the
    // probe-only runs).
    let no_watch = std::env::var_os("PERUN_NO_WATCH").is_some();
    WATCH_BASE.store(pkt as u64, Ordering::SeqCst);
    WATCH_LEN.store(if no_watch { 0 } else { 0x1000 }, Ordering::SeqCst);
    install_handlers();
    if !no_watch {
        unsafe {
            libc::mprotect(pkt as *mut libc::c_void, 0x1000, libc::PROT_READ);
        }
    }
    let r = unsafe { op(0xcfe0b46a, ctx as u64, 0, 0) };
    eprintln!("[ww] cfg rc={r:#x} ({r})");
    // The full post-call packet: the early series' own tape
    // (368 generated bytes at [4..0x174)) for the parity test.
    if std::env::var_os("PERUN_ITER0_SNAP").is_some() {
        let outp = std::env::var("PERUN_PKT_AFTER_OUT")
            .unwrap_or_else(|_| "/opt/data/il/pkt_after_iter0.bin".into());
        let full = unsafe { std::slice::from_raw_parts(pkt.cast::<u8>(), 0x400) };
        let _ = std::fs::write(&outp, full);
        eprintln!(
            "[ww] post-call packet saved to {outp} ({} bytes)",
            full.len()
        );
    }
    eprintln!("[ww] writes logged: {}", HIT_N.load(Ordering::SeqCst));
    unsafe {
        let pb = std::slice::from_raw_parts(pkt.cast::<u8>(), 0x40);
        eprintln!(
            "[ww] pkt[0..0x40] = {}",
            pb.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        libc::mprotect(
            pkt as *mut libc::c_void,
            0x1000,
            libc::PROT_READ | libc::PROT_WRITE,
        );
    }
}
