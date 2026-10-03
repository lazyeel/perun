// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! `perun` — runner and inspector for native PE images under the runtime.

use perun_core::loader::{DLL_PROCESS_ATTACH, Image, LoadError};
use perun_shims::table::ShimTable;
use std::path::Path;

mod adi;
mod fetcher;
mod sap;
mod scaffold;
mod store;

fn main() {
    unsafe { install_crash_probe() };
    let code = run();
    // Exit via C ABI to avoid unwinding across guest frames.
    unsafe { libc::_exit(code) }
}

// ── single-stepping the flattened dispatcher ─────────────────────────────────
//
// ptrace is refused by the sandbox and Ghidra will not recover the flattened jump
// table, so the body of `vdfut768ig` is reachable only from inside. The x86 trap
// flag needs no ptrace: with TF set in EFLAGS the CPU raises SIGTRAP after the
// next instruction, and the handler is handed the ucontext either way.
//
// The cost control is the whole design. A guest call into an imported function
// leaves the image for host code -- a Rust shim, the allocator, glibc -- and if
// TF were still set the CPU would single-step every instruction of all of it, which
// turns one HeapAlloc into tens of thousands of traps and looks exactly like a hang
// in the shim. So TF is cleared the moment RIP leaves the image, the shim runs at
// native speed, and the walk resumes because an int3 is planted on the shim's
// return address in the guest: the shim returns into the breakpoint, that trap
// re-arms TF, and the walk continues. One planted breakpoint per shim call instead
// of one trap per instruction.
//
// Inside the handler there is no I/O of any kind. The history is a fixed ring of
// plain stores, and nothing is printed until the walk is finished, at which point
// the process exits.
//
// PERUN_STEPS=N arms the walk. PERUN_STEP_UNTIL=<rva> stops it at an address;
// the stop is also taken when the return code the library is about to publish is
// seen in a register, which catches the decision wherever the flattened body
// computes it rather than only where this particular build stores it.
static mut STEP_ARMED: bool = false;
static mut STEP_SEALS: u64 = 0;
/// The .data page to put back under PROT_NONE, set by a seal fault and
/// consumed by the next single-step trap. Zero means nothing to re-seal.
static mut STEP_RESEAL: usize = 0;
static mut SEAL_PAGES: u64 = 0;

/// PERUN_FORCE_AT=<rva>:<reg>=<value>,... forces named registers when the walk
/// reaches that guest address. This exists because the registers that mask the
/// barrier's flag are produced by arithmetic inside the flattened body, so no
/// argument sweep can reach them; a debugger is not an option either, since the
/// walk and gdb both consume SIGTRAP and cannot run at once. Zero means unset.
static mut FORCE_AT: u64 = 0;
static mut FORCE_REGS: [(i32, u64); 6] = [(0, 0); 6];
static mut FORCE_N: usize = 0;
static mut STEP_PRIMED: bool = false;
static mut STEP_ENTERED: bool = false;
static mut STEP_COUNT: u64 = 0;
static mut STEP_MAX: u64 = 0;
static mut STEP_STOP_RVA: u64 = 0;
static mut STEP_STOP_ON_CODE: bool = true;
/// PERUN_STOP_EDI_ZERO: halt the walk the first time edi is zero inside the
/// window PERUN_STOP_EDI_ZERO_LO..HI. Both bounds are absolute.
static mut STEP_STOP_EDI_ZERO: bool = false;
static mut STEP_STOP_EDI_LO: u64 = 0;
static mut STEP_STOP_EDI_HI: u64 = u64::MAX;
/// The ADI code the walk stops on. Overridable with PERUN_STOP_CODE, because
/// the code that publishes one error is not the code that publishes the next,
/// and the publisher of -45002 is not where -45018's is: hard-coding one of
/// them made the search for the other impossible.
static mut STEP_STOP_CODE: u32 = ERRNO_45018;
/// Power of two, and it must be one: the slot index is a bitmask
/// (`STEP_IDX & (STEP_RING - 1)`) while the reader used to fold with
/// `% STEP_RING`, and at 160 000 the two disagree. 160000-1 is 0x270FF, whose
/// bits 8..11 are clear, so every index with any of those bits set folded onto
/// a small slot while the slots the reader looked at stayed empty -- which is
/// why a walk of 80 457 instructions reported 128 zero entries, and why
/// shortening the walk did not help either.
///
/// 2^18, raised from 2^17 on 2026-09-30: a complete walk of the clean path is
/// 222 935 instructions, and at 2^17 the ring kept only the **last** 131 072
/// of them. The dump then silently omitted the whole early region -- which is
/// where the transform loop lives, at step ~17 600 -- while still writing a
/// full-looking file of 131 072 rows. Reading that file, the loop looked
/// absent. It was the same failure as the truncated 128-entry window, one
/// magnitude up: a ring that is too small does not look empty, it looks
/// complete.
const STEP_RING: usize = 1 << 18;
static mut STEP_RIP: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_EDX: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_RDX: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_RCX: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_R10: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_EDI: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_RAX: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_R12: [u64; STEP_RING] = [0; STEP_RING];
/// RSP alongside every RIP. A write-watchpoint cannot be built from RIPs
/// alone: `[rsp+0x50]` names a different address on every instruction, because
/// the frame is built by `sub rsp,0x16a8` and then walked. Carrying the stack
/// pointer with each step is what turns "who wrote this slot" into a question
/// the recorded trace can answer offline, by decoding each instruction and
/// asking whether its destination operand is `[rsp+0x50]`.
static mut STEP_RSP: [u64; STEP_RING] = [0; STEP_RING];
/// The rest of the register file, for the same reason. The transform loop at
/// RVA `0x6783f` reads `rax` as its base, `r10` as its limit and `edi` as the
/// byte, and derives `eax` from `r14d` -- and none of the four is initialised
/// anywhere in the 60 bytes before it, because that window is an indirect jump
/// (`jmp *%rdx`) into a control-flow-flattened body. Static disassembly cannot
/// answer where a register came from when the writes live in other basic
/// blocks; the recorded value can, and that is the difference between reading
/// the seed and guessing it.
static mut STEP_R9: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_R11: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_R14: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_R8: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_RSI: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_RDI: [u64; STEP_RING] = [0; STEP_RING];
/// RBX, for one reason: a writer of the second buffer layer is
/// `mov byte ptr [r12 + rcx], al`, and its byte comes from `rax`. The trace had
/// the 64-bit RAX but the analyzer could not read a byte out of it, so the
/// column read `??` and the second layer's contents were unrecoverable. AL is
/// derived from RAX in the dump itself, so no new array is needed for the
/// common case; RBX is here because `mov ..., bl` appears in the same family.
static mut STEP_RBX: [u64; STEP_RING] = [0; STEP_RING];
/// R13, R15 and RBP, for one measured reason. The dispatcher at RVA 0xb15c8
/// reads the byte that steers the choice between the 113 publisher blocks, and
/// in that region the guest addresses memory through `[r12 + r15]` -- an index
/// the trace did not carry. A writer of that byte between the two buffer layers
/// and the decision was therefore invisible, and the dispatcher read a value
/// that no recorded instruction explained. These three close that gap: RBP is
/// also what `0xb15e0` folds into the index, so a frame change was equally
/// unobservable.
static mut STEP_R13: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_R15: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_RBP: [u64; STEP_RING] = [0; STEP_RING];
static mut STEP_IDX: usize = 0;
const EFLAGS_TF: u64 = 0x100;
/// -45018, the code the library is about to publish when the header check fails.
const ERRNO_45018: u32 = 0xffff_5026;
/// This image's span. CoreADI64.dll prefers base 0x7c800000 and is 0x1a5000.
static mut STEP_DLL_LO: u64 = 0;
static mut STEP_DLL_HI: u64 = 0;

/// Arm the walk, and report it once. Everything else is done by the handler.
unsafe fn arm_steps(n: u64) {
    unsafe {
        STEP_MAX = n.clamp(1, 1 << 30);
        STEP_COUNT = 0;
        STEP_IDX = 0;
        STEP_PRIMED = false;
        STEP_ENTERED = false;
        STEP_ARMED = true;
    }
}

/// Print the ring and the register file. Called only after the walk is over, so
/// it is not on the trap path and can afford to be readable.
fn report_stop(why: &str, rip: u64, edi: u64, rax: u64, rbx: u64, rcx: u64, rsp: u64) {
    println!("[perun] walk stopped: {why}");
    println!("[perun] instructions: {}", unsafe { STEP_COUNT });
    println!(
        "[stop] rip={rip:#018x} edi={edi:#x} rax={rax:#018x} rbx={rbx:#018x} rcx={rcx:#x} rsp={rsp:#018x}"
    );
    println!("[perun] last guest instructions, oldest first:");
    // PERUN_SLOTS=off[,off,...] reads those `[rsp+off]` guest stack slots at
    // the stop point. The ring carries registers and rip but no memory read, so
    // a slot that decides a branch -- `rsp+0x80` at RVA 0x90625 -- could only be
    // inspected by attaching gdb, which cannot take a hardware watchpoint here
    // and cannot write the 0xcc into perun's RX mapping either. Off unless asked:
    // reading guest memory here is safe (this runs after the walk has stopped),
    // but an offset typo would otherwise print whatever is there.
    if let Some(spec) = std::env::var_os("PERUN_SLOTS") {
        for off_s in spec.to_string_lossy().split(',').filter(|s| !s.is_empty()) {
            let Ok(off) = u64::from_str_radix(off_s.trim().trim_start_matches("0x"), 16) else {
                println!("[slot] {off_s:?} is not hex");
                continue;
            };
            let addr = rsp.wrapping_add(off);
            // SAFETY: the walk has stopped and this is the same process, so
            // nothing can unmap the guest stack under this read.
            let v = unsafe { std::ptr::read_volatile(addr as *const u64) };
            println!("[slot] rsp+{off:#x} = {addr:#018x} -> {v:#018x}");
        }
    }
    let n = unsafe { STEP_IDX }.min(STEP_RING);
    // STEP_IDX is the index AFTER the last store, so the oldest entry of a
    // window ending there is at STEP_IDX - n. Adding k to STEP_IDX instead
    // walks forward off the end and prints whatever the ring has not written.
    // STEP_IDX is the index AFTER the last store, so the newest entry is at
    // STEP_IDX - 1. Walk BACKWARDS from there to get the tail, and start at the
    // oldest when the walk is shorter than the window.
    let idx = unsafe { STEP_IDX };
    let count = n.min(128);
    // The reader folds the same way the writer does. A power-of-two ring makes
    // the mask and a modulo agree; at 160 000 they did not, and that mismatch
    // is what emptied this window.
    let first = idx.wrapping_sub(count);
    for k in 0..count {
        let slot = (first + k) & (STEP_RING - 1);
        let rp = unsafe { STEP_RIP[slot] };
        let ed = unsafe { STEP_EDX[slot] };
        let dx = unsafe { STEP_RDX[slot] };
        let cx = unsafe { STEP_RCX[slot] };
        let edi = unsafe { STEP_EDI[slot] };
        let rax = unsafe { STEP_RAX[slot] };
        let r10 = unsafe { STEP_R10[slot] };
        let r12 = unsafe { STEP_R12[slot] };
        let sp = unsafe { STEP_RSP[slot] };
        println!(
            "  [{k:4}] rip={rp:#018x} edx={ed:#010x} rdx={dx:#018x} edi={edi:#010x} rax={rax:#010x} r10={r10:#018x} rcx={cx:#x} r12={r12:#018x} rsp={sp:#018x}"
        );
    }
}

/// Dump the whole ring as `index rip rsp`, oldest first, for offline analysis.
///
/// The 128-entry window above is a reading convenience and cannot answer a
/// question about a slot, because the writer of `[rsp+0x50]` may be thousands
/// of instructions earlier. PERUN_TRACE_FILE names the output.
///
/// One line per instruction, hex only, no formatting that could fail: this
/// runs after the walk, but it still runs on a thread whose guest frames are
/// still on the stack, and an allocation here would be an allocation on top of
/// a frame the library is holding.
fn dump_ring(path: &str) {
    use std::io::Write as _;
    let Ok(mut f) = std::fs::File::create(path) else {
        eprintln!("[perun] trace file {path}: cannot create");
        return;
    };
    let idx = unsafe { STEP_IDX };
    let n = idx.min(STEP_RING);
    // PERUN_TRACE_TAIL=N dumps only the last N steps. The walk itself takes
    // seconds; formatting 22 hex columns per row takes hours, and a full dump
    // of a 218,000-step walk at ~30 rows/s is two hours for data most of
    // which is not needed. The decision that selects the error code sits in the
    // last few thousand steps, so the tail is the default way to ask.
    let n = match std::env::var("PERUN_TRACE_TAIL")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        Some(k) if k > 0 => n.min(k),
        _ => n,
    };
    let first = idx.wrapping_sub(n);
    let mut line = String::with_capacity(48);
    for k in 0..n {
        let slot = (first + k) & (STEP_RING - 1);
        let rp = unsafe { STEP_RIP[slot] };
        let sp = unsafe { STEP_RSP[slot] };
        line.clear();
        use std::fmt::Write as _;
        // edi is carried because the slot's writer is `mov [rsp+0x50], edi`:
        // without the register the trace says who wrote and not what.
        let ed = unsafe { STEP_EDI[slot] };
        let r9 = unsafe { STEP_R9[slot] };
        let r11 = unsafe { STEP_R11[slot] };
        let r14 = unsafe { STEP_R14[slot] };
        let r8 = unsafe { STEP_R8[slot] };
        let rsi = unsafe { STEP_RSI[slot] };
        let rdi = unsafe { STEP_RDI[slot] };
        let r12 = unsafe { STEP_R12[slot] };
        let r10 = unsafe { STEP_R10[slot] };
        let rcx = unsafe { STEP_RCX[slot] };
        let rdx = unsafe { STEP_RDX[slot] };
        let rax = unsafe { STEP_RAX[slot] };
        // RAX and RBX are the 32- and 16/8-bit views of what is already
        // dumped as a 64-bit register, so EAX/AL/AX come from RAX for free and
        // BL/CL/DL from RBX/RCX/RDX. A writer of `mov byte ptr [r12+rcx], al`
        // is invisible in the value column without this: the byte it stores is
        // AL, and only the 64-bit form was being printed.
        let rbx = unsafe { STEP_RBX[slot] };
        let al = rax & 0xff;
        let bl = rbx & 0xff;
        let cl = rcx & 0xff;
        let dl = rdx & 0xff;
        let r13 = unsafe { STEP_R13[slot] };
        let r15 = unsafe { STEP_R15[slot] };
        let rbp = unsafe { STEP_RBP[slot] };
        let _ = writeln!(
            line,
            "{k} {rp:x} {sp:x} {ed:x} {rax:x} {rdx:x} {rcx:x} {r10:x} {r9:x} {r11:x} {r14:x} {r8:x} {rsi:x} {rdi:x} {r12:x} {al:x} {bl:x} {cl:x} {dl:x} {r13:x} {r15:x} {rbp:x}"
        );
        let _ = f.write_all(line.as_bytes());
    }
    let _ = f.flush();
    eprintln!("[perun] wrote {n} steps to {path}");
}

/// POSIX signal handler: print guest-crash context (RIP, RSP, fault address)
/// straight to stderr, without unwinding.
///
/// Async-signal-safe by construction: no allocation, no TLS access, no
/// `format!` — everything runs on raw `write(2)`. (An earlier version read
/// a thread-local call counter here, which faulted *again inside the
/// handler* when the guest had clobbered the TLS block, destroying the
/// primary fault context.) SIGTRAP is not expected in production: there are
/// no int3 plants; it is reported and the process exits.
unsafe fn crash_handler(sig: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // Edition 2024: an unsafe fn body is no longer an unsafe context; the
    // whole handler is one unsafe block by intent.
    unsafe {
        let si_addr = (*info).si_addr() as u64;
        // ucontext_t.gregs layout (x86_64 glibc): REG_RIP=16, REG_RSP=19, etc.
        let uc = ctx.cast::<libc::ucontext_t>();
        let regs = (*uc).uc_mcontext.gregs.as_mut_ptr();
        let rip = *regs.add(libc::REG_RIP as usize) as u64;
        let rsp = *regs.add(libc::REG_RSP as usize) as u64;
        let rdi = *regs.add(libc::REG_RDI as usize) as u64;
        let rsi = *regs.add(libc::REG_RSI as usize) as u64;

        // The reference thunk page executes `hlt` when the guest returns — a
        // privileged instruction faults as SIGSEGV with rip at the hlt. Bounce
        // to the trampoline landing pad instead of dying: the guest function
        // has returned, and the landing restores the host frame.
        const RETURN_HLT: u64 = 0x1_0000_0000;
        if sig == libc::SIGSEGV && (rip == RETURN_HLT + 2 || rip == RETURN_HLT) {
            // rax holds the guest's return value; the landing expects to be
            // entered as if reached by `ret` from the thunk — rsp already sits
            // at the guest stack top edge.
            *regs.add(libc::REG_RIP as usize) = sap::guest_landing_for_signal() as i64;
            return;
        }

        // Single-stepping. Everything here is two stores and a flag, because
        // this runs once per instruction. No I/O, no allocation, no formatting.
        //
        // Three cases: a guest instruction, which is recorded and stepped over; a
        // step that has left the image, which is a call into a host shim and must
        // run at full speed, so TF is cleared and an int3 is planted on the shim's
        // return address; and the stop condition, which publishes the ring and
        // exits.
        if sig == libc::SIGTRAP && STEP_ARMED {
            let rip = *regs.add(libc::REG_RIP as usize) as u64;
            let flags = *regs.add(libc::REG_EFL as usize) as u64;
            let rax = *regs.add(libc::REG_RAX as usize) as u64;
            let rdi = *regs.add(libc::REG_RDI as usize) as u64;
            let rdx = *regs.add(libc::REG_RDX as usize) as u64;
            let rbx = *regs.add(libc::REG_RBX as usize) as u64;
            let rcx = *regs.add(libc::REG_RCX as usize) as u64;
            let rsp = *regs.add(libc::REG_RSP as usize) as u64;

            // Re-seal a .data page a moment after a seal fault opened it. The
            // trap that brings us here is the one raised after the retried
            // instruction retired, so closing the page here catches the *next*
            // access instead of losing every access after the first.
            if STEP_RESEAL != 0 {
                let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                let target = STEP_RESEAL;
                STEP_RESEAL = 0;
                libc::mprotect(target as *mut libc::c_void, page, libc::PROT_NONE);
            }

            if !STEP_PRIMED {
                // The trap raised by hand, before the guest was entered. Its only
                // job is to install TF in the context the thread resumes from;
                // the CPU then traps after the first guest instruction.
                STEP_PRIMED = true;
                *regs.add(libc::REG_EFL as usize) = (flags | EFLAGS_TF) as i64;
                return;
            }

            // Host code is traced as well as guest code. Dropping TF for a shim
            // was tried and is wrong: with the flag clear the shim never traps
            // again, so the walk cannot resume, and the ways of resuming it --
            // planting an int3 on the return address -- corrupt the guest, since
            // that byte can be the second byte of an instruction. Counting the
            // trap in the handler costs two stores, which is cheap enough to leave
            // TF on and simply not record the instructions that are not ours.
            if rip < STEP_DLL_LO || rip >= STEP_DLL_HI {
                *regs.add(libc::REG_EFL as usize) = (flags | EFLAGS_TF) as i64;
                return;
            }

            // Forced registers, applied to the live context so the instruction at
            // this address sees them. TF stays set and the step is still recorded,
            // so the walk is otherwise unchanged and the trace stays honest.
            unsafe {
                let (at, n) = (FORCE_AT, FORCE_N);
                if at != 0 && rip == at {
                    for k in 0..n {
                        let (idx, val) = FORCE_REGS[k];
                        *regs.add(idx as usize) = val as i64;
                    }
                    eprintln!("[perun] forced {n} register(s) at rip={rip:#x}");
                }
            }

            STEP_ENTERED = true;
            let slot = STEP_IDX & (STEP_RING - 1);
            STEP_RIP[slot] = rip;
            STEP_EDX[slot] = rdx as u32 as u64;
            STEP_RDX[slot] = rdx;
            STEP_RCX[slot] = *regs.add(libc::REG_RCX as usize) as u64;
            STEP_R10[slot] = *regs.add(libc::REG_R10 as usize) as u64;
            STEP_EDI[slot] = rdi;
            STEP_RAX[slot] = *regs.add(libc::REG_RAX as usize) as u64;
            STEP_R12[slot] = *regs.add(libc::REG_R12 as usize) as u64;
            // One more store, for the same reason as the rest: the trap runs
            // per instruction and nothing here may allocate. RSP is what makes
            // a stack slot addressable from the recorded trace.
            STEP_RSP[slot] = rsp;
            STEP_R9[slot] = *regs.add(libc::REG_R9 as usize) as u64;
            STEP_R11[slot] = *regs.add(libc::REG_R11 as usize) as u64;
            STEP_R14[slot] = *regs.add(libc::REG_R14 as usize) as u64;
            STEP_R8[slot] = *regs.add(libc::REG_R8 as usize) as u64;
            STEP_RSI[slot] = *regs.add(libc::REG_RSI as usize) as u64;
            STEP_RDI[slot] = rdi;
            STEP_RBX[slot] = *regs.add(libc::REG_RBX as usize) as u64;
            STEP_R13[slot] = *regs.add(libc::REG_R13 as usize) as u64;
            STEP_R15[slot] = *regs.add(libc::REG_R15 as usize) as u64;
            STEP_RBP[slot] = *regs.add(libc::REG_RBP as usize) as u64;
            STEP_IDX = STEP_IDX.wrapping_add(1);
            STEP_COUNT += 1;

            // The stop is the library about to publish -45018, wherever the
            // flattened body arrives at that value. Catching it here rather than
            // at a fixed address is what makes this independent of the build.
            let g = |r: libc::c_int| *regs.add(r as usize) as u32;
            // The value is published in different registers on different routes
            // -- edi before the epilogue moves it, eax after -- so sample the
            // argument and result registers rather than assuming one.
            let wants_stop = STEP_STOP_RVA != 0 && rip == STEP_STOP_RVA
                || STEP_STOP_ON_CODE
                    && (g(libc::REG_RDI) == STEP_STOP_CODE
                        || g(libc::REG_RAX) == STEP_STOP_CODE
                        || g(libc::REG_RCX) == STEP_STOP_CODE
                        || g(libc::REG_RDX) == STEP_STOP_CODE
                        || g(libc::REG_R8) == STEP_STOP_CODE
                        || g(libc::REG_R9) == STEP_STOP_CODE
                        || g(libc::REG_R10) == STEP_STOP_CODE
                        || g(libc::REG_R11) == STEP_STOP_CODE
                        || g(libc::REG_RSI) == STEP_STOP_CODE)
                // PERUN_STOP_EDI_ZERO: stop the first time edi is zero, within
                // the address window named by PERUN_STOP_EDI_ZERO_LO/HI. The
                // flattened body holds 137 `xor edi,edi` sites, so a static
                // scan cannot say which of them is "status = 0" as opposed to
                // dispatch arithmetic; only the run can. The window matters --
                // without it the condition fires in unrelated code below the
                // export and answers nothing.
                || (STEP_STOP_EDI_ZERO
                    && g(libc::REG_RDI) == 0
                    && rip >= STEP_STOP_EDI_LO
                    && rip < STEP_STOP_EDI_HI);
            if wants_stop || STEP_COUNT >= STEP_MAX {
                *regs.add(libc::REG_EFL as usize) = (flags & !EFLAGS_TF) as i64;
                STEP_ARMED = false;
                let why = if wants_stop {
                    "the decision"
                } else {
                    "the budget"
                };
                let (w, ri, ed, ax, bx, cx, sp) = (why, rip, rdi, rax, rbx, rcx, rsp);
                report_stop(w, ri, ed, ax, bx, cx, sp);
                if let Some(p) = std::env::var_os("PERUN_TRACE_FILE") {
                    let p = p.to_string_lossy().into_owned();
                    dump_ring(&p);
                }
                libc::_exit(0);
            }

            // Keep TF set: this is what makes the walk self-sustaining.
            *regs.add(libc::REG_EFL as usize) = (flags | EFLAGS_TF) as i64;
            return;
        }

        // PERUN_SEAL_DATA: a touch of a sealed .data page faults. Record the
        // address and the faulting instruction, unprotect the page so the
        // retried instruction completes, and re-seal it on the trap that
        // follows.
        //
        // The re-seal is the whole point. Leaving the page open reported one
        // access per 4 KiB and nothing more, and because 0x19dba0, 0x19dda0
        // and 0x19db98 all sit on the page at 0x19d000, a log of "the body
        // reads two globals" was really a log of "the body opens two pages".
        // With the walk armed the retried instruction raises SIGTRAP, and
        // that trap is where the page goes back to PROT_NONE, so every
        // access is seen rather than the first one.
        //
        // The message says "touch" and not "read": mprotect cannot tell a load
        // from a store or a read-modify-write, and printing RIP lets the
        // instruction decide that, instead of the log asserting something the
        // instrument does not know.
        if sig == libc::SIGSEGV && SEAL_PAGES > 0 {
            let a = si_addr as usize;
            let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let base = a & !(page - 1);
            let n = STEP_SEALS;
            let mut m = format!("[seal {n}] touch at {a:x} rip {rip:x}\n");
            // Longest plausible: "[seal 4294967295] touch at ffffffffffff rip ffffffffffffffff"
            if m.len() > 96 {
                m.truncate(96);
            }
            libc::write(2, m.as_ptr().cast(), m.len());
            STEP_SEALS = n + 1;
            if STEP_ARMED {
                // Re-seal on the next trap, i.e. once this instruction retires.
                STEP_RESEAL = base;
            }
            libc::mprotect(
                base as *mut libc::c_void,
                page,
                libc::PROT_READ | libc::PROT_WRITE,
            );
            return;
        }

        // SIGTRAP in production means an unexpected int3/ICEBP in the guest
        // image — the debug watchpoint plants are gone. Report and die: the
        // state at the trap is not recoverable.
        if sig == libc::SIGTRAP {
            let mut out: [u8; 128] = [0; 128];
            let mut n = 0usize;
            let push = |s: &[u8], out: &mut [u8], n: &mut usize| {
                for &b in s {
                    if *n < out.len() {
                        out[*n] = b;
                        *n += 1;
                    }
                }
            };
            push(
                b"[perun] unexpected SIGTRAP (int3) at rip=",
                &mut out,
                &mut n,
            );
            push(&hex16(rip), &mut out, &mut n);
            push(b"\n", &mut out, &mut n);
            libc::write(2, out.as_ptr().cast(), n);
            // The state at the trap is what a flattened dispatcher gives up
            // last, so report it: the flattened jump table is not recoverable
            // statically and ptrace is refused by the sandbox, which leaves the
            // probe as the only instrument that reaches these sites at all.
            if std::env::var_os("PERUN_TRAP_REGS").is_some() {
                let g = |r: libc::c_int| *regs.add(r as usize) as u64;
                let mut o2: [u8; 1024] = [0; 1024];
                let mut m = 0usize;
                let put = |s: &[u8], o: &mut [u8], n: &mut usize| {
                    for &b in s {
                        if *n < o.len() {
                            o[*n] = b;
                            *n += 1;
                        }
                    }
                };
                for (nm, r) in [
                    ("rax", libc::REG_RAX),
                    ("rbx", libc::REG_RBX),
                    ("rcx", libc::REG_RCX),
                    ("rdx", libc::REG_RDX),
                    ("rsi", libc::REG_RSI),
                    ("rdi", libc::REG_RDI),
                    ("rbp", libc::REG_RBP),
                    ("rsp", libc::REG_RSP),
                    ("r8", libc::REG_R8),
                    ("r9", libc::REG_R9),
                    ("r10", libc::REG_R10),
                    ("r11", libc::REG_R11),
                    ("r12", libc::REG_R12),
                    ("r13", libc::REG_R13),
                    ("r14", libc::REG_R14),
                    ("r15", libc::REG_R15),
                ] {
                    put(nm.as_bytes(), &mut o2, &mut m);
                    put(b"=", &mut o2, &mut m);
                    put(&hex16(g(r)), &mut o2, &mut m);
                    put(b" ", &mut o2, &mut m);
                }
                put(b"\n[trap] stack:", &mut o2, &mut m);
                let sp = g(libc::REG_RSP);
                for i in 0..8u64 {
                    let word = std::ptr::read_volatile((sp + i * 8) as *const u64);
                    put(b" ", &mut o2, &mut m);
                    put(&hex16(word), &mut o2, &mut m);
                }
                put(b"\n", &mut o2, &mut m);
                libc::write(2, o2.as_ptr().cast(), m);
            }
            libc::_exit(128 + sig);
        }

        let mut out: [u8; 256] = [0; 256];
        let mut n = 0usize;
        let push = |s: &[u8], out: &mut [u8], n: &mut usize| {
            for &b in s {
                if *n < out.len() {
                    out[*n] = b;
                    *n += 1;
                }
            }
        };
        push(b"[perun] guest crash: signal ", &mut out, &mut n);
        push(&hexdec(sig as u64, 2), &mut out, &mut n);
        push(b" addr=", &mut out, &mut n);
        push(&hex16(si_addr), &mut out, &mut n);
        push(b" rip=", &mut out, &mut n);
        push(&hex16(rip), &mut out, &mut n);
        push(b" rsp=", &mut out, &mut n);
        push(&hex16(rsp), &mut out, &mut n);
        push(b" rdi=", &mut out, &mut n);
        push(&hex16(rdi), &mut out, &mut n);
        push(b" rsi=", &mut out, &mut n);
        push(&hex16(rsi), &mut out, &mut n);
        push(b"\n", &mut out, &mut n);
        libc::write(2, out.as_ptr().cast(), n);
        libc::_exit(128 + sig);
    }
}

/// Fixed-width hex of a u64 into a static buffer — no allocator.
unsafe fn hex16(v: u64) -> [u8; 18] {
    let mut buf: [u8; 18] = [b'0'; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for i in 0..16 {
        buf[2 + i] = HEX[((v >> (60 - 4 * i)) & 0xF) as usize];
    }
    buf
}

unsafe fn hexdec(v: u64, _pad: usize) -> [u8; 21] {
    let mut buf: [u8; 21] = [0; 21];
    let s = v.to_string();
    for (i, b) in s.bytes().take(20).enumerate() {
        buf[i] = b;
    }
    buf
}

/// # Safety
/// Must be installed before any guest code runs; the alt-stack it
/// registers must stay mapped for the process lifetime.
pub unsafe fn install_crash_probe() {
    unsafe {
        // Alternate signal stack: the guest can leave the main stack pointer
        // anywhere when it faults, so the handler must not rely on it.
        static mut ALT: [u8; 64 * 1024] = [0; 64 * 1024];
        let mut ss: libc::stack_t = std::mem::zeroed();
        ss.ss_sp = std::ptr::addr_of_mut!(ALT).cast();
        ss.ss_size = 64 * 1024;
        libc::sigaltstack(&raw const ss, std::ptr::null_mut());

        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = crash_handler as *const () as usize;
        act.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigaction(libc::SIGSEGV, &raw const act, std::ptr::null_mut());
        libc::sigaction(libc::SIGFPE, &raw const act, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &raw const act, std::ptr::null_mut());
        libc::sigaction(libc::SIGTRAP, &raw const act, std::ptr::null_mut());
    }
}

/// Help text for the low-level lane, printed without running anything.
///
/// Intercepted in `run()` before the dispatch, never inside the commands: `sap`
/// spawns a 256 MiB guest thread and may fetch Apple's assets, `run` maps a PE,
/// `seq` executes a script, `call` would export-call a guest and `scaffold` would
/// try to parse the flag as a trap line, so a `--help` reaching them either starts
/// real work or fails confusingly. `-h` and `--help` count anywhere in the tail,
/// the way every other flag here does.
fn low_level_help(sub: &str) -> Option<&'static str> {
    Some(match sub {
        "run" => concat!(
            "usage: perun run <image.dll> [--verbose] [--trace] [--trace-file F] [--no-teb]\n\n",
            "  Loads a PE32+ image, resolves its imports against the Win32 shim table,\n",
            "  installs a per-thread TEB, and calls DllMain(DLL_PROCESS_ATTACH).\n\n",
            "  --verbose        print the image summary before loading\n",
            "  --trace          log the instrumented Win32 call sites (partial coverage)\n",
            "  --trace-file F   redirect stderr onto F, where the trace lines land\n",
            "  --no-teb         skip TEB initialization\n"
        ),
        "info" => concat!(
            "usage: perun info <image.dll>\n\n",
            "  Prints the PE32+ header and sections, then the import table (DLL, named and\n",
            "  ordinal) and the export names. Accepts PE32+ only; a Mach-O file goes to\n",
            "  `perun mach info`.\n"
        ),
        "mach" => concat!(
            "usage: perun mach info <macho>\n\n",
            "  Parses a 64-bit Mach-O image: header, segments, sections and the symbol\n",
            "  table, without mapping it or running any guest code.\n"
        ),
        "adi" => concat!(
            "usage: perun adi headers [<image.dll>] [--adi-dir DIR]\n\n",
            "  Runs CoreADI64.dll natively -- no Bionic, no QEMU, no Wine -- and reports\n",
            "  what the Anisette v3 opcodes produce on this host: each opcode's status\n",
            "  and how many bytes it wrote.\n\n",
            "  <image.dll>      the library; defaults to the extracted iTunes copy\n",
            "  --adi-dir DIR     where the SPIM cache lives (adi.pb, adi-<hash>.pb)\n\n",
            "  The three opcodes return 0 once the barrier is passed, but this image\n",
            "  imports no networking API, so no OTP is minted and no token header is\n",
            "  printed. The command reports that rather than inventing values.\n"
        ),
        "sap" => concat!(
            "usage: perun sap [<assets-dir>] [--mac AA:BB:CC:DD:EE:FF] [--sign HEX | --file F]\n\n",
            "  Runs the FairPlay SAP session (init, two exchange rounds, sign) against the\n",
            "  live endpoints. With no arguments the asset cache is used as-is, and a first\n",
            "  run fetches the missing images itself from Apple's public update package.\n\n",
            "  <assets-dir>     use this directory instead of the default cache\n",
            "  --mac            force the machine address for this run, overriding the pin\n",
            "  --sign HEX       sign this payload instead of the built-in smoke string\n",
            "  --file F         sign the contents of F instead\n\n",
            "  This command starts a real session and may perform network I/O.\n"
        ),
        "seq" => concat!(
            "usage: perun seq <image.dll> <export> --script=FILE\n\n",
            "  Loads one image and runs DllMain once, then drives a script of export calls\n",
            "  in the same process so guest state carries between them. One verb per line,\n",
            "  `#` starts a comment:\n\n",
            "    load NAME FILE   read FILE into a named guest buffer\n",
            "    poke T V         write a qword; T = scratch+OFF | ctx+OFF | RVA\n",
            "    call [EXPORT] A0 A1 A2 A3\n",
            "                     call the export (default vdfut768ig); args are tokens:\n",
            "                     buffer names, scratch/ctx with optional +OFF, or numbers\n",
            "    zero scratch|ctx clear that region\n",
            "    dump            print the non-zero qwords of scratch and ctx\n\n",
            "  Export names match the export table case-sensitively.\n"
        ),
        "call" => concat!(
            "usage: perun call <image.dll> <export> [arg0 arg1 arg2 arg3] [flags]\n\n",
            "  Loads the image, runs DllMain once, then calls one export with up to four\n",
            "  positional arguments in Win64 order (rcx, rdx, r8, r9). Values may be plain\n",
            "  numbers or the tokens `scratch`, `ctx`, and either with a +OFF suffix.\n\n",
            "  --load=NAME=FILE   read FILE into a named guest buffer, usable as a value\n",
            "  --patch=RVA=HEX    patch bytes into the mapped image (mprotect'd, RX after)\n",
            "  --poke=T=V         write a qword before the call; T = RVA | scratch+OFF | ctx+OFF\n",
            "  --poke-ptr=RVA=V   write V through the pointer stored at guest RVA\n",
            "  --peek=RVA[,RVA…]  read guest qwords after the call\n",
            "  --peek-ptr=RVA     dereference a guest RVA as a host pointer and dump it\n",
            "  --verbose          print the image summary before loading\n\n",
            "  Option values resolve after the whole command line is parsed, so a buffer\n",
            "  name works as a value wherever its --load sits.\n",
            "  PERUN_SEQ=N repeats one call in-process (call#0, call#1, …).\n"
        ),
        "scaffold" => concat!(
            "usage: perun scaffold \"TRAP-line\" [...]\n\n",
            "  Turns an unresolved-import trap report into a compiling `win32_api!` stub\n",
            "  with the observed arguments and the file whose family owns the API. Accepts\n",
            "  the bare `DLL!func(args)` shape, the full `[perun] TRAP: …` line, and the\n",
            "  hint payload pasted back verbatim. Several lines may be given at once.\n\n",
            "  example: perun scaffold \"[perun] TRAP: KERNEL32!FooBar(0x1, 0x0, 0x0, 0x0)\"\n",
            "           perun scaffold 'KERNEL32!FooBar(0x1, 0x0, 0x0, 0x0)'\n\n",
            "  Exit 0 when every line parsed, 1 when one did not.\n"
        ),
        _ => return None,
    })
}

/// True when the tail carries a help flag anywhere, the way the other parsers
/// accept their flags in any position.
fn help_flag_present(tail: &[String]) -> bool {
    tail.iter().any(|a| a == "-h" || a == "--help")
}

/// Returns `Some(0)` when a help request was satisfied without running anything.
fn low_level_help_requested(sub: &str, tail: &[String]) -> Option<i32> {
    if !help_flag_present(tail) {
        return None;
    }
    print!("{}", low_level_help(sub)?);
    Some(0)
}

fn run() -> i32 {
    run_with_args(&std::env::args().collect::<Vec<String>>())
}

/// The dispatcher, separated from `main` so the argv-driven help interception is
/// testable without launching a process.
fn run_with_args(args: &[String]) -> i32 {
    // argv[0] persona: a binary invoked as `ipatool` (basename) runs the
    // strict majd/ipatool grammar for EVERYTHING, including the bare
    // `--help`/`--version` root flags; `perun` keeps its native grammar.
    let argv0 = args
        .first()
        .map(|s| {
            std::path::Path::new(s)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let ipatool_persona = argv0 == "ipatool";
    if ipatool_persona {
        return store::cli::run(&args[1..]);
    }
    if args.len() < 2 {
        eprintln!(
            "usage: perun run <image.dll> [--verbose] [--trace] [--trace-file F] [--no-teb]\n       perun info <image.dll>\n       perun mach info <macho>\n       perun scaffold \"TRAP-line\" [...]\n       perun sap [--mac AA:BB:CC:DD:EE:FF] [--sign HEX|--file F]\n       perun store <auth|search|purchase|download|list-purchases|list-versions|get-version-metadata> ...\n       ipatool aliases: perun auth login|info|revoke · perun search -t ... · perun purchase -i ...\n                        perun download -i ... · perun list-purchases · perun list-versions ..."
        );
        return 2;
    }

    // `-h`/`--help` for the low-level lane never reaches the commands: `sap`
    // would spawn a guest thread and hit Apple's endpoints, `seq` would run its
    // script, `run` would map the image. Answered here instead.
    if let Some(code) = low_level_help_requested(&args[1], &args[2..]) {
        return code;
    }

    match args[1].as_str() {
        "info" => cmd_info(&args[2]),
        "run" => cmd_run(&args[2..]),
        "call" => cmd_call(&args[2..]),
        "mach" => cmd_mach(&args[2..]),
        "scaffold" => scaffold::run(&args[2..]),
        "sap" => cmd_sap(&args[2..]),
        "adi" => {
            if args[2] == "headers" {
                adi::run(&args[3..])
            } else {
                eprintln!("usage: perun adi headers [<image.dll>] [--adi-dir DIR]");
                2
            }
        }
        "store" => store::cli::run(&args[2..]),
        "seq" => cmd_seq(&args[2..]),
        // ipatool-compatible top-level aliases: same grammar, no "store".
        "auth" => store::cli::run(&args[1..]),
        "search" => store::cli::run(&args[1..]),
        "purchase" => store::cli::run(&args[1..]),
        "download" => store::cli::run(&args[1..]),
        "list-purchases" | "purchases" => store::cli::run(&args[1..]),
        "list-versions" => store::cli::run(&args[1..]),
        "get-version-metadata" => store::cli::run(&args[1..]),
        _ => {
            eprintln!("unknown command: {}", args[1]);
            2
        }
    }
}

struct RunOpts {
    verbose: bool,
    trace: bool,
    trace_file: Option<String>,
    no_teb: bool,
}

fn parse_opts(args: &[String]) -> RunOpts {
    let mut o = RunOpts {
        verbose: false,
        trace: false,
        trace_file: None,
        no_teb: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--verbose" => o.verbose = true,
            "--trace" => o.trace = true,
            "--trace-file" => {
                i += 1;
                o.trace_file = args.get(i).cloned();
            }
            "--no-teb" => o.no_teb = true,
            other => eprintln!("[perun] warning: unknown flag {other} ignored"),
        }
        i += 1;
    }
    o
}

fn cmd_run(args: &[String]) -> i32 {
    let path = &args[0];
    let opts = parse_opts(&args[1..]);

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {path}: {e}");
            return 1;
        }
    };

    if opts.verbose
        && let Ok(info) = perun_core::image::PeInfo::parse(&bytes)
    {
        println!(
            "[perun] image {path}: entry={:#x} base={:#x} sections={}",
            info.opt.address_of_entry_point,
            info.opt.image_base,
            info.sections.len()
        );
    }

    let mut table = ShimTable::collect();
    let image = match Image::load(&bytes, &mut table) {
        Ok(img) => img,
        Err(LoadError::UnsupportedMachine { machine }) => {
            eprintln!("error: unsupported machine {machine:#06x} (only x86_64 PE32+)");
            return 1;
        }
        Err(e) => {
            eprintln!("error: {e:?}");
            return 1;
        }
    };

    println!("[perun] loaded at {:#x}", image.base() as usize);
    println!("[perun] shim table: {} APIs registered", table.len());

    // Phase 0: thread context. GS must point at a FakeTEB before any guest
    // code runs; MSVC CRT startup reads TEB fields immediately. Installed
    // after mapping so the TEB can carry the real image base.
    if opts.no_teb {
        println!("[perun] phase0: TEB/GS setup SKIPPED (--no-teb)");
    } else {
        let _ = unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
        println!("[perun] phase0: FakeTEB installed at GS_BASE");
    }

    if opts.trace {
        let file = opts.trace_file.clone().unwrap_or_default();
        // Edition 2024: set_var touches global state, now unsafe.
        // We run this before any guest threads exist.
        unsafe {
            std::env::set_var("PERUN_TRACE", "1");
            if !file.is_empty() {
                std::env::set_var("PERUN_TRACE_FILE", &file);
            }
        }
        // PERUN_TRACE_FILE used to be accepted but never read: every shim
        // checks only PERUN_TRACE and logs to stderr. Make --trace-file
        // real by pointing stderr at the file, so all eprintln trace lines
        // (shims, traps, loader) land there instead of the console.
        if !file.is_empty() {
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file)
            {
                Ok(f) => {
                    use std::os::unix::io::AsRawFd;
                    let fd = f.as_raw_fd();
                    // dup2 is async-signal-safe wrt the later crash handler;
                    // after this eprintln goes to the file.
                    if unsafe { libc::dup2(fd, 2) } < 0 {
                        eprintln!("[perun] warning: dup2 --trace-file {file}: failed");
                    }
                    // `f` closes here; fd 2 keeps the description open.
                }
                Err(e) => {
                    eprintln!("[perun] warning: open --trace-file {file}: {e}");
                }
            }
        }
        println!("[perun] tracing enabled");
    }

    // Phase 2: DllMain(DLL_PROCESS_ATTACH).
    let dll_main = if let Some(f) = unsafe { image.entry_dll_main() } {
        f
    } else {
        eprintln!("error: image has no entry point");
        return 1;
    };
    println!("[perun] calling DllMain(DLL_PROCESS_ATTACH)...");
    let ret = unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) };
    if ret != 0 {
        println!("[perun] DllMain returned TRUE — init complete");
        0
    } else {
        println!("[perun] DllMain returned FALSE — init failed (see trap log above)");
        3
    }
}

/// `perun call <image.dll> <export> [arg0 arg1 arg2 arg3]`
///
/// Loads the image, runs `DllMain`, then invokes the named export through the
/// Win64 ABI with up to four integer/pointer arguments. Each argument is
/// parsed as hex (0x…) or decimal. Arguments that look like pointers are
/// backed by a zeroed scratch page so the guest can read/write them safely.
fn cmd_call(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!(
            "usage: perun call <image.dll> <export> [arg0 arg1 arg2 arg3] [--verbose] [--load=NAME=FILE] [--patch=RVA=HEX] [--poke=RVA=VAL] [--poke-ptr=RVA=VAL] [--peek=RVA] [--peek-ptr=RVA]   (PERUN_SEQ=N repeats the call in-process)"
        );
        return 2;
    }
    // `--verbose` is accepted anywhere on the command line: pulled out of the
    // stream entirely, it never lands in the positional-argument slots.
    let verbose = args.iter().any(|a| a == "--verbose");
    let pos: Vec<String> = args
        .iter()
        .filter(|a| **a != "--verbose")
        .cloned()
        .collect();
    let path = &pos[0];
    let export_name = &pos[1];

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {path}: {e}");
            return 1;
        }
    };

    if verbose && let Ok(info) = perun_core::image::PeInfo::parse(&bytes) {
        println!(
            "[perun] image {path}: entry={:#x} base={:#x} sections={}",
            info.opt.address_of_entry_point,
            info.opt.image_base,
            info.sections.len()
        );
    }

    let mut table = ShimTable::collect();
    let image = match Image::load(&bytes, &mut table) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("error: {e:?}");
            return 1;
        }
    };

    let _ = unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };

    let dll_main = if let Some(f) = unsafe { image.entry_dll_main() } {
        f
    } else {
        eprintln!("error: image has no entry point");
        return 1;
    };
    let ret = unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) };
    if ret == 0 {
        eprintln!("error: DllMain returned FALSE; refusing to call export");
        return 3;
    }
    println!("[perun] DllMain TRUE; shim table {} APIs", table.len());

    let export_ptr = if let Some(p) = image.get_export_by_name(export_name) {
        p
    } else {
        eprintln!("error: export {export_name:?} not found");
        return 1;
    };
    println!("[perun] export {export_name} @ {:#x}", export_ptr as usize);

    // Scratch page for pointer-backed arguments / output capture.
    let scratch = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            0x1000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if scratch == libc::MAP_FAILED {
        eprintln!("error: scratch mmap failed");
        return 1;
    }
    unsafe { std::ptr::write_bytes(scratch.cast::<u8>(), 0, 0x1000) };

    // A larger zeroed region to stand in for a guest context struct. The token
    // "ctx" resolves to it, so callers can point a global at a fake context.
    let ctx_size = 0x10000usize;
    let ctx = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            ctx_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ctx == libc::MAP_FAILED {
        eprintln!("error: ctx mmap failed");
        return 1;
    }
    unsafe { std::ptr::write_bytes(ctx.cast::<u8>(), 0, ctx_size) };

    // --load=NAME=FILE: read a file into a fresh guest-visible buffer and
    // register NAME as a token resolving to its address. This is how real
    // server material (e.g. a GrandSlam `spim` blob) gets handed to the
    // dispatcher's param struct, mirroring what the Android ADI engine feeds
    // ADIProvisioningStart.
    let mut loads: Vec<(String, u64, usize)> = Vec::new(); // (name, addr, len)

    // Parse up to 4 positional args. The token "scratch" resolves to the clean
    // scratch page address, so callers can hand the guest a zeroed parameter
    // block. Options of the form --poke RVA=VALUE write a qword into guest
    // memory (image.base + RVA) before the call, letting us pre-fill globals.
    let mut argv = [0u64; 4];
    // (kind, target, value): kind 0 = guest RVA, kind 1 = ctx offset,
    // kind 2 = scratch offset
    let mut pokes: Vec<(u8, u64, u64)> = Vec::new();
    // --patch=RVA=HEXBYTES: raw code patch into the mapped image (mprotect'd)
    let mut patches: Vec<(u64, Vec<u8>)> = Vec::new();
    // --peek=RVA[,RVA...]: read guest qwords after the call
    let mut peeks: Vec<String> = Vec::new();
    // --peek-ptr=RVA[,RVA...]: dereference guest RVA as host pointer, dump object
    let mut peek_ptrs: Vec<String> = Vec::new();
    let mut ai = 0usize;
    // Positional args are collected first, resolved after all options.
    let mut positional: Vec<String> = Vec::new();
    let resolve = |tok: &str| -> Option<u64> {
        match tok {
            "scratch" => Some(scratch as u64),
            "ctx" => Some(ctx as u64),
            _ => parse_num(tok),
        }
    };
    // --poke specs are stored raw and resolved after the loop so values can
    // reference loaded buffers by name regardless of CLI order.
    // (kind, target, value_string)
    let mut poke_specs: Vec<(u8, u64, String)> = Vec::new();
    let mut poke_ptr_specs: Vec<(u64, String)> = Vec::new();
    // The positional stream (with --verbose already filtered out) drives both
    // the argument slots and the --patch/--poke/--peek option parsing below.
    for a in &pos[2..] {
        if let Some(spec) = a.strip_prefix("--load=") {
            let (name, path) = spec.split_once('=').unwrap_or((spec, ""));
            let data = match std::fs::read(path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: --load {path:?}: {e}");
                    std::process::exit(2);
                }
            };
            let len = data.len();
            let buf = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len.max(1),
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if buf == libc::MAP_FAILED {
                eprintln!("error: --load mmap failed");
                std::process::exit(2);
            }
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf.cast::<u8>(), len) };
            println!("[perun] load {name:?} <- {path} ({len} bytes @ {buf:p})");
            loads.push((name.to_string(), buf as u64, len));
            continue;
        }
        if let Some(spec) = a.strip_prefix("--patch=") {
            let (rva_s, hex_s) = spec.split_once('=').unwrap_or((spec, ""));
            let rva = parse_num(rva_s).unwrap_or_else(|| {
                eprintln!("error: bad --patch rva {rva_s:?}");
                std::process::exit(2);
            });
            let clean: String = hex_s.chars().filter(char::is_ascii_hexdigit).collect();
            if !clean.len().is_multiple_of(2) || clean.is_empty() {
                eprintln!("error: bad --patch bytes {hex_s:?}");
                std::process::exit(2);
            }
            let bytes: Vec<u8> = (0..clean.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
                .collect();
            patches.push((rva, bytes));
            continue;
        }
        if let Some(spec) = a.strip_prefix("--peek=") {
            peeks.push(spec.to_string());
            continue;
        }
        if let Some(spec) = a.strip_prefix("--peek-ptr=") {
            peek_ptrs.push(spec.to_string());
            continue;
        }
        if let Some(spec) = a.strip_prefix("--poke=") {
            let (tgt_s, val_s) = spec.split_once('=').unwrap_or((spec, ""));
            if let Some(off_s) = tgt_s.strip_prefix("ctx+") {
                let off = parse_num(off_s).unwrap_or_else(|| {
                    eprintln!("error: bad ctx offset {off_s:?}");
                    std::process::exit(2);
                });
                poke_specs.push((1, off, val_s.to_string()));
            } else if let Some(off_s) = tgt_s.strip_prefix("scratch+") {
                let off = parse_num(off_s).unwrap_or_else(|| {
                    eprintln!("error: bad scratch offset {off_s:?}");
                    std::process::exit(2);
                });
                poke_specs.push((2, off, val_s.to_string()));
            } else {
                let rva = parse_num(tgt_s).unwrap_or_else(|| {
                    eprintln!("error: bad --poke rva {tgt_s:?}");
                    std::process::exit(2);
                });
                poke_specs.push((0, rva, val_s.to_string()));
            }
            continue;
        }
        if let Some(spec) = a.strip_prefix("--poke-ptr=") {
            // --poke-ptr=RVA=VALUE: read the qword at guest RVA as a host
            // pointer, then write VALUE to the pointed-to memory. Used to poke
            // through the provisioning gate's double dereference.
            let (rva_s, val_s) = spec.split_once('=').unwrap_or((spec, ""));
            let rva = parse_num(rva_s).unwrap_or_else(|| {
                eprintln!("error: bad --poke-ptr rva {rva_s:?}");
                std::process::exit(2);
            });
            poke_ptr_specs.push((rva, val_s.to_string()));
            continue;
        }
        if ai < 4 {
            positional.push(a.clone());
        }
    }

    // Resolve positional args after all options so --load/--poke/--patch are
    // registered first regardless of CLI order.
    for a in &positional {
        if ai >= 4 {
            break;
        }
        // Loaded buffers are addressable by name (e.g. "spim").
        let loaded = loads
            .iter()
            .find(|(n, _, _)| n == a)
            .map(|(_, addr, _)| *addr);
        argv[ai] = loaded.or_else(|| resolve(a)).unwrap_or_else(|| {
            eprintln!("error: bad argument {a:?}");
            std::process::exit(2);
        });
        ai += 1;
    }

    // Resolve deferred poke values now that all --load buffers are registered.
    // A value may be a loaded buffer name, scratch/ctx (optionally +OFF), or a
    // number.
    let resolve_val = |s: &str| -> Option<u64> {
        if let Some((_, addr, _)) = loads.iter().find(|(n, _, _)| n == s) {
            return Some(*addr);
        }
        if let Some(off_s) = s.strip_prefix("ctx+") {
            let off = parse_num(off_s)?;
            return Some((ctx as u64).wrapping_add(off));
        }
        if let Some(off_s) = s.strip_prefix("scratch+") {
            let off = parse_num(off_s)?;
            return Some((scratch as u64).wrapping_add(off));
        }
        resolve(s)
    };
    for (kind, tgt, val_s) in &poke_specs {
        let val = resolve_val(val_s).unwrap_or_else(|| {
            eprintln!("error: bad --poke value {val_s:?}");
            std::process::exit(2);
        });
        pokes.push((*kind, *tgt, val));
    }
    for (rva, val_s) in &poke_ptr_specs {
        let val = resolve_val(val_s).unwrap_or_else(|| {
            eprintln!("error: bad --poke-ptr value {val_s:?}");
            std::process::exit(2);
        });
        // Two indirections, and they are easy to misread: the guest global at
        // `base + rva` holds a pointer, and `val` is written THROUGH that
        // pointer. `--poke=RVA=V` writes the pointer itself; this writes to
        // what it points at.
        let slot = (image.base() as u64).wrapping_add(*rva) as *const u64;
        let target = unsafe { std::ptr::read(slot) };
        if (target as usize) < 0x1000 {
            eprintln!(
                "error: --poke-ptr [RVA {rva:#x}]: the slot holds {target:#x}, \
                 which is not a pointer; the global is probably uninitialised"
            );
            std::process::exit(2);
        }
        unsafe { std::ptr::write(target as *mut u64, val) };
        println!("[perun] poke-ptr [RVA {rva:#x}] -> {target:#x} := {val:#x}");
    }

    // Apply pokes. kind 0 -> guest memory (image.base + rva); kind 1 -> ctx
    // region; kind 2 -> scratch (parameter) region.
    for (kind, tgt, val) in &pokes {
        let addr = match kind {
            0 => (image.base() as u64).wrapping_add(*tgt) as *mut u64,
            1 => (ctx as u64).wrapping_add(*tgt) as *mut u64,
            _ => (scratch as u64).wrapping_add(*tgt) as *mut u64,
        };
        unsafe { std::ptr::write(addr, *val) };
        let label = match kind {
            0 => format!("[RVA {tgt:#x}]"),
            1 => format!("ctx[{tgt:#x}]"),
            _ => format!("scratch[{tgt:#x}]"),
        };
        println!("[perun] poke {label} = {val:#x} (abs {addr:p})");
    }

    // Apply raw code patches. The image sections are mapped RX, so flip the
    // target page(s) to RWX, write the bytes, then restore RX.
    for (rva, bytes) in &patches {
        let addr = (image.base() as u64).wrapping_add(*rva) as *mut u8;
        let page = (addr as usize) & !0xfff;
        let end = (addr as usize) + bytes.len();
        let npages = (end - page).div_ceil(0x1000);
        unsafe {
            libc::mprotect(
                page as *mut libc::c_void,
                npages * 0x1000,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr, bytes.len());
            libc::mprotect(
                page as *mut libc::c_void,
                npages * 0x1000,
                libc::PROT_READ | libc::PROT_EXEC,
            );
        }
        println!("[perun] patch RVA {rva:#x} <- {} bytes", bytes.len());
        // Read back to confirm the write landed (mprotect may have failed).
        let rb = unsafe { std::slice::from_raw_parts(addr, bytes.len().min(8)) };
        println!("[perun]   readback: {}", hexdump(rb));
    }

    type ExportFn = unsafe extern "win64" fn(u64, u64, u64, u64) -> u64;
    let f: ExportFn = unsafe { std::mem::transmute(export_ptr) };

    // PERUN_SEQ=N: repeat the call N times in the SAME process so gate state set
    // by an earlier call carries into later ones (Android provisioning is a
    // sequence of calls in one process; the Windows dispatcher folds them in).
    // PERUN_FORCE_AT=<rva>:<reg>=<value>[,<reg>=<value>]...
    // Registers are the usual x86 names. The address is an RVA in the guest image.
    if let Ok(spec) = std::env::var("PERUN_FORCE_AT") {
        let (addr_s, rest) = match spec.split_once(':') {
            Some(p) => p,
            None => {
                eprintln!("[perun] PERUN_FORCE_AT needs <rva>:<reg>=<v>,... : {spec:?}");
                return 2;
            }
        };
        let addr = match u64::from_str_radix(addr_s.trim_start_matches("0x"), 16) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("[perun] PERUN_FORCE_AT address is not hex: {addr_s:?}");
                return 2;
            }
        };
        let mut pairs: Vec<(i32, u64)> = Vec::new();
        for item in rest.split(',').filter(|s| !s.trim().is_empty()) {
            let (rname, vname) = match item.split_once('=') {
                Some(p) => p,
                None => continue,
            };
            let idx = match rname.trim() {
                "rax" => libc::REG_RAX,
                "rbx" => libc::REG_RBX,
                "rcx" => libc::REG_RCX,
                "rdx" => libc::REG_RDX,
                "rsi" => libc::REG_RSI,
                "rdi" => libc::REG_RDI,
                "rbp" => libc::REG_RBP,
                "r8" => libc::REG_R8,
                "r9" => libc::REG_R9,
                "r10" => libc::REG_R10,
                "r11" => libc::REG_R11,
                "r12" => libc::REG_R12,
                "r13" => libc::REG_R13,
                "r14" => libc::REG_R14,
                "r15" => libc::REG_R15,
                // 32-bit spellings address the same slot in the ucontext on x86_64,
                // so accept both; the barrier's masks are named that way.
                "eax" => libc::REG_RAX,
                "ebx" => libc::REG_RBX,
                "ecx" => libc::REG_RCX,
                "edx" => libc::REG_RDX,
                "esi" => libc::REG_RSI,
                "edi" => libc::REG_RDI,
                "ebp" => libc::REG_RBP,
                "r8d" => libc::REG_R8,
                "r9d" => libc::REG_R9,
                "r10d" => libc::REG_R10,
                "r11d" => libc::REG_R11,
                "r12d" => libc::REG_R12,
                "r13d" => libc::REG_R13,
                "r14d" => libc::REG_R14,
                "r15d" => libc::REG_R15,
                other => {
                    eprintln!("[perun] PERUN_FORCE_AT: unknown register {other:?}");
                    return 2;
                }
            };
            let v = match u64::from_str_radix(vname.trim_start_matches("0x"), 16) {
                Ok(v) => v,
                Err(_) => {
                    eprintln!("[perun] PERUN_FORCE_AT: value is not hex: {vname:?}");
                    return 2;
                }
            };
            pairs.push((idx, v));
        }
        if pairs.is_empty() || pairs.len() > 6 {
            eprintln!(
                "[perun] PERUN_FORCE_AT needs 1..=6 registers, got {}",
                pairs.len()
            );
            return 2;
        }
        // The handler sees an absolute rip, so carry the image base with the RVA.
        // Print both: an RVA that looks absolute is a common way to get this wrong.
        let abs_addr = image.base() as u64 + addr;
        unsafe {
            for (k, p) in pairs.iter().enumerate() {
                FORCE_REGS[k] = *p;
            }
            FORCE_N = pairs.len();
            FORCE_AT = abs_addr;
        }
        eprintln!(
            "[perun] forcing {} register(s) at guest rva {addr:#x} (abs {abs_addr:#x})",
            pairs.len()
        );
    }

    let seq_n: usize = std::env::var("PERUN_SEQ")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    // PERUN_STEPS=N single-steps the call, for a body whose control flow is
    // flattened and therefore invisible to a static decompiler.
    let steps: u64 = std::env::var("PERUN_STEPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let stop_rva: u64 = std::env::var("PERUN_STEP_UNTIL")
        .ok()
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    // PERUN_STOP_CODE: which ADI code the walk stops on. Defaults to -45018,
    // but the publisher of -45002 lives elsewhere and pinning the old default
    // is what made it unfindable. Accepts the decimal or the 0x form.
    unsafe {
        STEP_STOP_EDI_ZERO = std::env::var_os("PERUN_STOP_EDI_ZERO").is_some();
        let rd = |k: &str| {
            std::env::var(k)
                .ok()
                .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        };
        STEP_STOP_EDI_LO = rd("PERUN_STOP_EDI_ZERO_LO").unwrap_or(0);
        STEP_STOP_EDI_HI = rd("PERUN_STOP_EDI_ZERO_HI").unwrap_or(u64::MAX);
    };
    if let Ok(v) = std::env::var("PERUN_STOP_CODE") {
        let parsed = if let Some(hex) = v.trim().strip_prefix("0x") {
            u32::from_str_radix(hex, 16).ok()
        } else {
            v.trim().parse::<u32>().ok()
        };
        match parsed {
            Some(code) => unsafe { STEP_STOP_CODE = code },
            None => eprintln!("[perun] ignoring unparsable PERUN_STOP_CODE {v:?}"),
        }
    }
    // No need for a sign-extended variant: the comparison below truncates each
    // register to u32, so a code held in a 64-bit register matches too.
    // PERUN_SEAL_DATA=1: mark the image's .data pages PROT_NONE before the call.
    // Any read of a global then faults, and the crash handler prints the
    // address, which names the global the body is consulting without decoding
    // the flattened body.
    let sealed: Vec<usize> = if std::env::var_os("PERUN_SEAL_DATA").is_some() {
        let lo = image.base();
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mut v = Vec::new();
        // .data: RVA 0x19d000 .. 0x19f0a8 per the section table
        for rva in (0x19d000..0x19f0a8).step_by(page) {
            let p = unsafe { lo.add(rva) };
            let aligned = unsafe { p.cast::<u8>().offset(-((rva % page) as isize)) };
            if unsafe { libc::mprotect(aligned.cast(), page, libc::PROT_NONE) } == 0 {
                v.push(rva / page);
            }
        }
        eprintln!("[perun] sealed {} data pages", v.len());
        v
    } else {
        Vec::new()
    };
    let _ = &sealed;
    unsafe {
        SEAL_PAGES = sealed.len() as u64;
    }

    // Optional session initialiser, run once before the call under test.
    // CoreADI64.dll exports exactly two entry points and the ADI lane needs
    // both: the initialiser takes the provisioning path in rcx and returns 0,
    // and only then does the dispatcher read a well-formed path instead of
    // whatever was on the stack. PERUN_INIT names the export, PERUN_INIT_ARG0
    // supplies its first argument (a loaded-buffer token or a literal).
    if let Ok(init_name) = std::env::var("PERUN_INIT") {
        if let Some(init_ptr) = image.get_export_by_name(&init_name) {
            let a0 = std::env::var("PERUN_INIT_ARG0")
                .ok()
                .map(|s| resolve_val(&s).unwrap_or(0))
                .unwrap_or(0);
            let a1 = std::env::var("PERUN_INIT_ARG1")
                .ok()
                .map(|s| resolve_val(&s).unwrap_or(0))
                .unwrap_or(0);
            let init_fn: ExportFn = unsafe { std::mem::transmute(init_ptr) };
            let r = unsafe { init_fn(a0, a1, 0, 0) };
            println!("[perun] init {init_name}({a0:#x}, {a1:#x}) returned {r:#x} ({r})");
        } else {
            eprintln!("[perun] PERUN_INIT={init_name:?} is not an export of this image");
        }
    }

    for iter in 0..seq_n {
        println!(
            "[perun] call#{iter} {export_name}({:#x}, {:#x}, {:#x}, {:#x})...",
            argv[0], argv[1], argv[2], argv[3]
        );
        // Arm here, not before the loop: DllMain runs guest code too, and its
        // instructions would otherwise consume the whole budget before the
        // export is ever entered.
        if steps > 0 && iter == 0 {
            unsafe {
                STEP_DLL_LO = image.base() as u64;
                STEP_DLL_HI = STEP_DLL_LO + 0x1A_5000;
                STEP_STOP_RVA = if stop_rva != 0 {
                    STEP_DLL_LO + stop_rva
                } else {
                    0
                };
                arm_steps(steps);
                // Enter the handler once so it can install TF in the context the
                // thread resumes from; after that the CPU drives itself.
                libc::raise(libc::SIGTRAP);
            }
            eprintln!("[perun] walking the export, up to {steps} instructions");
        }
        // PERUN_MEM: snapshot the caller's scratch and the context before the
        // call. The -45020 subject is in no register and not in the frame, so
        // the next place it can be is memory the call itself writes.
        let mem_on = std::env::var_os("PERUN_MEM").is_some();
        let mut mem_pre: Vec<u64> = Vec::new();
        if mem_on {
            mem_pre =
                unsafe { std::slice::from_raw_parts(scratch as *const u64, 0x1000 / 8) }.to_vec();
        }
        // PERUN_DIFF: report what the call changed inside the image. The
        // -45020 decision is made from something the library produces itself,
        // so snapshot before and diff after instead of guessing at the input.
        let diff_on = std::env::var_os("PERUN_DIFF").is_some();
        let mut before: Vec<u64> = Vec::new();
        let mut img_base = 0u64;
        if diff_on {
            img_base = image.base() as u64;
            before = unsafe {
                std::slice::from_raw_parts(img_base as *const u64, 0x1A_5000 / 8).to_vec()
            };
        }
        // The PE lane runs the guest on *this* thread's stack, so the frame
        // the export builds with `sub rsp,0x16a8` lands on whatever the host
        // left there. The flattened body reads a byte out of that region to
        // form its dispatch index (RVA 0xb15c8, `movzx eax,byte [rcx+rax]`),
        // and at RVA 0x6783f it reads our parameter packet byte by byte. Both
        // are uninitialised-memory reads from the guest's point of view, and
        // the first was observed returning leftover x86 code from perun's own
        // execution -- a dispatch decision that depended on the host.
        //
        // Zeroing *below* the current stack pointer is what is needed: the
        // guest pushes eight registers and then subtracts, so its frame is
        // under this frame, not in it. An array allocated as a local would
        // land above, in the wrong place entirely.
        if std::env::var_os("PERUN_ZERO_GUEST_STACK").is_some() {
            unsafe {
                let here = &0u8 as *const u8 as usize; // any local: gives the frame address
                let lo = here.saturating_sub(1 << 20);
                std::ptr::write_bytes(lo as *mut u8, 0, here - lo);
            }
        }
        // The isolated stack, when asked for. A separate mapping is the real
        // fix; the memset above is the diagnostic that showed the problem, and
        // it leaves Win64's 16-byte call alignment broken, which is why it
        // faults rather than merely changing the answer.
        let pe_stack = if std::env::var_os("PERUN_PE_STACK").is_some() {
            match unsafe { perun_core::teb::alloc_pe_stack(perun_core::teb::PE_STACK_SIZE) } {
                Some((limit, base)) => {
                    unsafe { perun_core::teb::set_pe_stack_bounds(limit, base) };
                    eprintln!(
                        "[perun] guest stack 0x{limit:x}..0x{base:x} ({} MiB, zeroed)",
                        perun_core::teb::PE_STACK_SIZE >> 20
                    );
                    // PERUN_PE_STACK_SEED writes bytes into the guest stack
                    // before the call. The guest builds its frame with
                    // `sub rsp,0x16a8` and reads below that frame, so the
                    // region under it is exactly the "stack residue" this
                    // runtime cannot otherwise control -- and layer 2 keys off
                    // it. Zeroing it changes the result (PERUN_ZERO_GUEST_STACK),
                    // so setting it deliberately is the search knob.
                    if let Ok(seed) = std::env::var("PERUN_PE_STACK_SEED") {
                        let clean: String =
                            seed.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                        let mut bytes = Vec::with_capacity(clean.len() / 2);
                        let raw = clean.as_bytes();
                        let mut i = 0;
                        while i + 1 < raw.len() {
                            let hi = (raw[i] as char).to_digit(16).unwrap_or(0) as u8;
                            let lo = (raw[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
                            bytes.push((hi << 4) | lo);
                            i += 2;
                        }
                        if !bytes.is_empty() {
                            // PERUN_PE_STACK_SEED_AT is the distance below the top
                            // of the mapping where the bytes land; it defaults to
                            // one MiB, well under the frame the guest will build.
                            let at = std::env::var("PERUN_PE_STACK_SEED_AT")
                                .ok()
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(1 << 20);
                            let addr = base.wrapping_sub(at);
                            let n = bytes.len().min(at as usize);
                            unsafe {
                                std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, n);
                            }
                            eprintln!(
                                "[perun] seeded guest stack: {n} byte(s) at 0x{addr:x} (top-0x{at:x})"
                            );
                        }
                    }
                    Some(base)
                }
                None => {
                    eprintln!("[perun] could not map a guest stack; staying on this one");
                    None
                }
            }
        } else {
            None
        };
        let r = match pe_stack {
            Some(top) => unsafe {
                perun_core::teb::call_on_stack(f, top, [argv[0], argv[1], argv[2], argv[3]])
            },
            None => unsafe { f(argv[0], argv[1], argv[2], argv[3]) },
        };
        println!("[perun] call#{iter} {export_name} returned {r:#x} ({r})");
        if mem_on {
            let after_mem =
                unsafe { std::slice::from_raw_parts(scratch as *const u64, 0x1000 / 8) };
            let mut n = 0;
            for (i, (a, b)) in mem_pre.iter().zip(after_mem.iter()).enumerate() {
                if a != b {
                    n += 1;
                    if n <= 32 {
                        println!("[mem] scratch[0x{:x}]: {:#018x} -> {:#018x}", i * 8, a, b);
                    }
                }
            }
            println!("[mem] {n} qword(s) changed in the caller's scratch");
        }
        if diff_on {
            let after =
                unsafe { std::slice::from_raw_parts(img_base as *const u64, 0x1A_5000 / 8) };
            let mut n = 0;
            for (i, (a, b)) in before.iter().zip(after.iter()).enumerate() {
                if a != b {
                    n += 1;
                    if n <= 64 {
                        println!("[diff] RVA {:#x}: {:#018x} -> {:#018x}", i * 8, a, b);
                    }
                }
            }
            println!("[diff] {n} qword(s) changed in the image");
        }
        // When the guest returns before the budget the walk ends without ever
        // reaching a stop condition, and the handler prints nothing. The ring
        // is full at that point, so report it here: an absent report reads as
        // an empty ring, which is how a completed walk was mistaken for a
        // walk that never happened.
        if steps > 0 && unsafe { STEP_COUNT } > 0 && unsafe { STEP_ARMED } {
            report_stop("the call returned", 0, 0, 0, 0, 0, 0);
            // The ring dump belongs here too, not only beside the stop
            // condition. A walk that ends because the guest returned is the
            // common case -- and that is the case where the file was silently
            // not written, which is how a 222 687-instruction walk came to look
            // like a walk that never happened. The comment above already
            // names this failure mode for the report; the dump had it too.
            if let Some(p) = std::env::var_os("PERUN_TRACE_FILE") {
                let p = p.to_string_lossy().into_owned();
                dump_ring(&p);
            }
            unsafe { STEP_ARMED = false };
        }
    }

    // --peek=RVA[,RVA...]: read qwords from guest memory after the call so the
    // caller can watch globals (e.g. the provisioning gate) for writes.
    for spec in &peeks {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let rva = parse_num(part).unwrap_or_else(|| {
                eprintln!("error: bad --peek rva {part:?}");
                std::process::exit(2);
            });
            let addr = (image.base() as u64).wrapping_add(rva) as *const u64;
            let v = unsafe { std::ptr::read(addr) };
            println!("[perun] peek [RVA {rva:#x}] = {v:#x}");
        }
    }

    // --peek-ptr=RVA[,RVA...]: read the qword at each guest RVA as a host
    // pointer and dump the first 64 bytes of the pointed-to object. This is
    // how we inspect the provisioning-gate object behind the double deref.
    for spec in &peek_ptrs {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let rva = parse_num(part).unwrap_or_else(|| {
                eprintln!("error: bad --peek-ptr rva {part:?}");
                std::process::exit(2);
            });
            let slot = (image.base() as u64).wrapping_add(rva) as *const u64;
            let target = unsafe { std::ptr::read(slot) };
            println!("[perun] peek-ptr [RVA {rva:#x}] -> {target:#x}");
            if target != 0 {
                let obj = unsafe { std::slice::from_raw_parts(target as *const u8, 64) };
                println!("[perun]   object[0..64] = {}", hexdump(obj));
            }
        }
    }

    // Dump every non-zero qword in the scratch page with its offset, so the
    // caller can see exactly which output fields the dispatcher wrote.
    {
        let page = unsafe { std::slice::from_raw_parts(scratch as *const u64, 0x1000 / 8) };
        let mut any = false;
        for (i, &q) in page.iter().enumerate() {
            if q != 0 {
                println!("[perun] scratch[{:#x}] = {q:#x}", i * 8);
                any = true;
            }
        }
        if !any {
            println!("[perun] scratch: all zero (no output written)");
        }
    }

    // Dump memory behind any argument that looks like a readable pointer, so
    // we can see what the guest wrote into its parameter blocks.
    for (i, a) in argv.iter().enumerate() {
        let p = *a as *const u8;
        if p.is_null() {
            continue;
        }
        // An argument does not have to be a pointer. A command selector such as
        // 0x632b8d6e is a small integer, and reading through it faults: the
        // probe cannot make an arbitrary integer safe, because the kernel
        // returns EFAULT for the read but the value may still be inside a
        // mapping the guest owns, or not. So restrict the dump to the ranges
        // this command actually handed out, and report a literal as a literal.
        let in_scratch = (scratch as u64..scratch as u64 + 0x1000).contains(a);
        let in_ctx = (ctx as u64..ctx as u64 + ctx_size as u64).contains(a);
        let in_image = (image.base() as u64..image.base() as u64 + 0x400000).contains(a);
        if !(in_scratch || in_ctx || in_image) {
            println!("[perun] arg{i} [{a:#x}] — not a pointer (literal or out of range)");
            continue;
        }
        let bytes = unsafe { std::slice::from_raw_parts(p, 64) };
        if bytes.iter().any(|&b| b != 0) {
            println!("[perun] arg{i} [{a:#x}] -> {}", hexdump(bytes));
        }
    }
    0
}

/// Resolve a token to a guest-visible address: loaded buffer name, scratch/ctx
/// (optionally +OFF), or a plain number.
fn resolve_token(tok: &str, scratch: u64, ctx: u64, loads: &[(String, u64, usize)]) -> Option<u64> {
    if let Some((_, addr, _)) = loads.iter().find(|(n, _, _)| n == tok) {
        return Some(*addr);
    }
    if let Some(off_s) = tok.strip_prefix("ctx+") {
        let off = parse_num(off_s)?;
        return Some(ctx.wrapping_add(off));
    }
    if let Some(off_s) = tok.strip_prefix("scratch+") {
        let off = parse_num(off_s)?;
        return Some(scratch.wrapping_add(off));
    }
    match tok {
        "scratch" => Some(scratch),
        "ctx" => Some(ctx),
        _ => parse_num(tok),
    }
}

/// `perun seq <image.dll> <export> --script=FILE`
///
/// Load the image once, run `DllMain` once, then drive a SCRIPT of export calls
/// in the SAME process so guest state carries across calls. This mirrors how a
/// real host (iTunes on Windows, the ADI engine on Android) drives the ADI
/// provisioning sequence: `SetProvisioningPath` -> `SetAndroidID` -> `GetLoginCode`
/// -> `ProvisioningStart` -> `ProvisioningEnd`, all folded into dispatcher command
/// codes on the Windows DLL.
///
/// Script lines (whitespace-separated, `#` starts a comment):
///   load NAME FILE          read FILE into a named guest buffer
///   poke TARGET VALUE       write a qword; TARGET = scratch+OFF | ctx+OFF | RVA
///   poke-ptr RVA VALUE      write VALUE through the pointer stored at RVA
///   call EXPORT A0 A1 A2 A3 call the named export; EXPORT defaults to the
///                           binary's own, and naming it is what lets one
///                           session drive cvu8io98wun and vdfut768ig in the
///                           order the real host uses
///   zero scratch|ctx        clear the region
///   dump                    print non-zero qwords of scratch and ctx
///
/// Note the difference between `poke` and `poke-ptr`, because getting it
/// backwards faults in the host and looks like a guest crash: `poke 0x19db98 X`
/// writes X at that RVA, while `poke-ptr 0x19db98 X` dereferences the qword
/// stored there and writes through it. Before any call the qword is zero, so
/// `poke-ptr` on a not-yet-created object is a null dereference.
fn cmd_seq(args: &[String]) -> i32 {
    if args.len() < 3 {
        eprintln!("usage: perun seq <image.dll> <export> --script=FILE");
        return 2;
    }
    let path = &args[0];
    let export_name = &args[1];
    let mut script_path: Option<String> = None;
    for a in &args[2..] {
        if let Some(p) = a.strip_prefix("--script=") {
            script_path = Some(p.to_string());
        }
    }
    let script_path = if let Some(p) = script_path {
        p
    } else {
        eprintln!("error: --script=FILE required");
        return 2;
    };

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {path}: {e}");
            return 1;
        }
    };
    let mut table = ShimTable::collect();
    let image = match Image::load(&bytes, &mut table) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("error: {e:?}");
            return 1;
        }
    };
    let _ = unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
    let dll_main = if let Some(f) = unsafe { image.entry_dll_main() } {
        f
    } else {
        eprintln!("error: image has no entry point");
        return 1;
    };
    let ret = unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) };
    if ret == 0 {
        eprintln!("error: DllMain returned FALSE");
        return 3;
    }
    println!("[perun] DllMain TRUE; shim table {} APIs", table.len());
    let export_ptr = if let Some(p) = image.get_export_by_name(export_name) {
        p
    } else {
        eprintln!("error: export {export_name:?} not found");
        return 1;
    };
    println!("[perun] export {export_name} @ {:#x}", export_ptr as usize);

    // Same as `cmd_call`: when PERUN_PE_STACK is set the guest runs on a
    // dedicated mapping, and every call in the sequence must be switched onto
    // it. Without this the sequence runs on the host thread's stack, which is
    // where the flattened body dereferences a masked index and faults, so a
    // two-call sequence could not reproduce the single-call result at all and
    // the init-then-provision experiment was unmeasurable rather than negative.
    let pe_stack = if std::env::var_os("PERUN_PE_STACK").is_some() {
        match unsafe { perun_core::teb::alloc_pe_stack(perun_core::teb::PE_STACK_SIZE) } {
            Some((limit, base)) => {
                unsafe { perun_core::teb::set_pe_stack_bounds(limit, base) };
                eprintln!(
                    "[perun] guest stack 0x{limit:x}..0x{base:x} ({} MiB, zeroed)",
                    perun_core::teb::PE_STACK_SIZE >> 20
                );
                Some(base)
            }
            None => {
                eprintln!("[perun] could not map a guest stack; staying on this one");
                None
            }
        }
    } else {
        None
    };

    // PERUN_AUX_IMAGE loads a second image into the same process, sharing the
    // shim table. Without it a sequence can only ever call one library, and the
    // one experiment that matters -- a real caller export from CoreFP.dll, then
    // vdfut768ig from CoreADI64.dll -- cannot be run at all.
    let aux_image = std::env::var_os("PERUN_AUX_IMAGE").and_then(|p| {
        let path = p.to_string_lossy().into_owned();
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            eprintln!("[perun] aux image {path:?}: {e}");
            Vec::new()
        });
        if bytes.is_empty() {
            return None;
        }
        match Image::load(&bytes, &mut table) {
            Ok(img) => {
                println!("[perun] aux image {path} loaded");
                Some(img)
            }
            Err(e) => {
                eprintln!("[perun] aux image {path:?}: {e}");
                None
            }
        }
    });

    let scratch = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            0x1000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if scratch == libc::MAP_FAILED {
        eprintln!("error: scratch mmap failed");
        return 1;
    }
    unsafe { std::ptr::write_bytes(scratch.cast::<u8>(), 0, 0x1000) };
    let ctx_size = 0x10000usize;
    let ctx = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            ctx_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ctx == libc::MAP_FAILED {
        eprintln!("error: ctx mmap failed");
        return 1;
    }
    unsafe { std::ptr::write_bytes(ctx.cast::<u8>(), 0, ctx_size) };

    // Each `call` step re-resolves the export by name, so the default export
    // resolved above is only the fallback for scripts that never name one.
    let mut loads: Vec<(String, u64, usize)> = Vec::new();
    let script = match std::fs::read_to_string(&script_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: read script {script_path}: {e}");
            return 1;
        }
    };

    let dump_region = |name: &str, base: u64, nq: usize| {
        let page = unsafe { std::slice::from_raw_parts(base as *const u64, nq) };
        let mut any = false;
        for (i, &q) in page.iter().enumerate() {
            if q != 0 {
                println!("[perun] {name}[{:#x}] = {q:#x}", i * 8);
                any = true;
            }
        }
        if !any {
            println!("[perun] {name}: all zero");
        }
    };

    let mut step = 0usize;
    for raw in script.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        step += 1;
        let toks: Vec<&str> = line.split_whitespace().collect();
        match toks[0] {
            "load" => {
                if toks.len() < 3 {
                    eprintln!("[seq] step {step}: load NAME FILE");
                    return 2;
                }
                let data = match std::fs::read(toks[2]) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("[seq] step {step}: load {}: {e}", toks[2]);
                        return 1;
                    }
                };
                let len = data.len();
                let buf = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        len.max(1),
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                if buf == libc::MAP_FAILED {
                    eprintln!("[seq] step {step}: load mmap failed");
                    return 1;
                }
                unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf.cast::<u8>(), len) };
                println!(
                    "[seq] step {step}: load {:?} <- {} ({len} bytes @ {buf:p})",
                    toks[1], toks[2]
                );
                loads.push((toks[1].to_string(), buf as u64, len));
            }
            "poke" => {
                if toks.len() < 3 {
                    eprintln!("[seq] step {step}: poke TARGET VALUE");
                    return 2;
                }
                let tgt = toks[1];
                let val =
                    if let Some(v) = resolve_token(toks[2], scratch as u64, ctx as u64, &loads) {
                        v
                    } else {
                        eprintln!("[seq] step {step}: bad poke value {:?}", toks[2]);
                        return 2;
                    };
                let (dst, label) = if let Some(off_s) = tgt.strip_prefix("scratch+") {
                    let off = parse_num(off_s).unwrap();
                    (
                        (scratch as u64).wrapping_add(off),
                        format!("scratch[{off:#x}]"),
                    )
                } else if let Some(off_s) = tgt.strip_prefix("ctx+") {
                    let off = parse_num(off_s).unwrap();
                    ((ctx as u64).wrapping_add(off), format!("ctx[{off:#x}]"))
                } else {
                    let rva = parse_num(tgt).unwrap_or_else(|| {
                        eprintln!("[seq] step {step}: bad poke target {tgt:?}");
                        std::process::exit(2);
                    });
                    (
                        (image.base() as u64).wrapping_add(rva),
                        format!("RVA[{rva:#x}]"),
                    )
                };
                unsafe { std::ptr::write(dst as *mut u64, val) };
                println!("[seq] step {step}: poke {label} = {val:#x}");
            }
            // Write a qword THROUGH the pointer stored at a guest RVA. `poke`
            // writes to guest memory directly, which cannot reach the
            // provisioning-gate object: that object is a HOST allocation the
            // guest makes during the call, so its pointer only exists after
            // call#0 and the value has to be written between two calls. That is
            // the whole reason this verb exists and `call --poke-ptr` does not
            // cover it -- there, every poke runs before the call loop.
            "poke-ptr" => {
                if toks.len() < 3 {
                    eprintln!("[seq] step {step}: poke-ptr RVA VALUE");
                    return 2;
                }
                let rva = parse_num(toks[1]).unwrap_or_else(|| {
                    eprintln!("[seq] step {step}: bad poke-ptr rva {:?}", toks[1]);
                    std::process::exit(2);
                });
                let val =
                    if let Some(v) = resolve_token(toks[2], scratch as u64, ctx as u64, &loads) {
                        v
                    } else {
                        eprintln!("[seq] step {step}: bad poke-ptr value {:?}", toks[2]);
                        return 2;
                    };
                let slot = (image.base() as u64).wrapping_add(rva) as *const u64;
                let target = unsafe { std::ptr::read(slot) };
                unsafe { std::ptr::write(target as *mut u64, val) };
                println!("[seq] step {step}: poke-ptr [RVA {rva:#x}] -> {target:#x} = {val:#x}");
            }
            "zero" => {
                if toks.len() < 2 {
                    eprintln!("[seq] step {step}: zero scratch|ctx");
                    return 2;
                }
                match toks[1] {
                    "scratch" => unsafe { std::ptr::write_bytes(scratch.cast::<u8>(), 0, 0x1000) },
                    "ctx" => unsafe { std::ptr::write_bytes(ctx.cast::<u8>(), 0, ctx_size) },
                    other => {
                        eprintln!("[seq] step {step}: zero {other}?");
                        return 2;
                    }
                }
                println!("[seq] step {step}: zero {}", toks[1]);
            }
            "dump" => {
                println!("[seq] step {step}: dump");
                dump_region("scratch", scratch as u64, 0x1000 / 8);
                dump_region("ctx", ctx as u64, 0x10000 / 8);
            }
            "call" => {
                let export_name = toks.get(1).copied().unwrap_or("vdfut768ig");
                let export_ptr = if let Some(p) = image.get_export_by_name(export_name) {
                    Some(p)
                } else {
                    aux_image
                        .as_ref()
                        .and_then(|a| a.get_export_by_name(export_name))
                };
                let Some(export_ptr) = export_ptr else {
                    eprintln!("[seq] step {step}: export {export_name:?} not found");
                    return 1;
                };
                type ExportFn = unsafe extern "win64" fn(u64, u64, u64, u64) -> u64;
                let f: ExportFn = unsafe { std::mem::transmute(export_ptr) };
                let mut argv = [0u64; 4];
                for (i, slot) in argv.iter_mut().enumerate() {
                    let tok = toks.get(i + 2).copied().unwrap_or("0");
                    *slot = if let Some(v) = resolve_token(tok, scratch as u64, ctx as u64, &loads)
                    {
                        v
                    } else {
                        eprintln!("[seq] step {step}: bad call arg {tok:?}");
                        return 2;
                    };
                }
                println!(
                    "[seq] step {step}: call {export_name}({:#x}, {:#x}, {:#x}, {:#x})...",
                    argv[0], argv[1], argv[2], argv[3]
                );
                let r = unsafe {
                    match pe_stack {
                        Some(top) => perun_core::teb::call_on_stack(
                            f,
                            top,
                            [argv[0], argv[1], argv[2], argv[3]],
                        ),
                        None => f(argv[0], argv[1], argv[2], argv[3]),
                    }
                };
                println!("[seq] step {step}: returned {r:#x} ({r})");
                // Show what the guest wrote into the scratch param block.
                dump_region("scratch", scratch as u64, 0x1000 / 8);
            }
            other => {
                eprintln!("[seq] step {step}: unknown verb {other:?}");
                return 2;
            }
        }
    }
    println!("[seq] done ({step} steps)");
    0
}

fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn hexdump(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| c.join(""))
        .collect::<Vec<_>>()
        .join(" ")
}

fn cmd_info(path: &str) -> i32 {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {path}: {e}");
            return 1;
        }
    };
    match perun_core::image::PeInfo::parse(&bytes) {
        Ok(info) => {
            println!("Image:           {path}");
            println!("Size:            {} bytes", bytes.len());
            println!("Machine:         x86_64 (validated by parser)");
            println!("Entry point RVA: {:#x}", info.opt.address_of_entry_point);
            println!("Preferred base:  {:#x}", info.opt.image_base);
            println!("Size of image:   {:#x}", info.opt.size_of_image);
            for s in &info.sections {
                println!(
                    "  {:8} VA={:#08x} VSize={:#x} Raw={:#x}",
                    s.name_str(),
                    s.virtual_address,
                    s.virtual_size,
                    s.size_of_raw_data,
                );
            }
            let imports = info.imports(&bytes);
            if imports.is_empty() {
                println!("Imports:         (none)");
            } else {
                let total: usize = imports.iter().map(|(_, s)| s.len()).sum();
                println!(
                    "Imports:         {} dll(s), {total} symbol(s)",
                    imports.len()
                );
                for (dll, syms) in &imports {
                    for sym in syms {
                        match sym {
                            perun_core::image::ImportSymbol::Name(n) => {
                                println!("  {dll}!{n}");
                            }
                            perun_core::image::ImportSymbol::Ordinal(o) => {
                                println!("  {dll}!#{o}");
                            }
                        }
                    }
                }
            }
            let exports = info.exports(&bytes);
            if exports.is_empty() {
                println!("Exports:         (none)");
            } else {
                println!("Exports:         {} name(s)", exports.len());
                for name in &exports {
                    println!("  {name}");
                }
            }
            0
        }
        Err(e) => {
            eprintln!("parse failed: {e:?}");
            1
        }
    }
}

// ── Mach-O surface ──────────────────────────────────────────────────────────

fn cmd_mach(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: perun mach info <macho-file>");
        return 2;
    }
    if args[0].as_str() == "info" {
        let data = match std::fs::read(&args[1]) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("read {}: {e}", args[1]);
                return 1;
            }
        };
        match perun_core::macho::MachInfo::parse(&data) {
            Ok(info) => {
                println!("preferred base: {:#x}", info.base);
                println!("segments:");
                for s in &info.segments {
                    println!(
                        "  {:16} vm={:#018x}+{:#x} file={:#x}+{:#x}",
                        s.name_str(),
                        s.vmaddr,
                        s.vmsize,
                        s.fileoff,
                        s.filesize,
                    );
                }
                println!(
                    "fixups: {} rebases, {} binds, {} defined symbols",
                    info.rebases.len(),
                    info.binds.len(),
                    info.symbols.len(),
                );
                let obf: Vec<&str> = info
                    .symbols
                    .iter()
                    .map(|s| s.name.as_str())
                    .filter(|n| {
                        matches!(
                            *n,
                            "_cp2g1b9ro"
                                | "_Mib5yocT"
                                | "_Fc3vhtJDvr"
                                | "_IPaI1oem5iL"
                                | "_jEHf8Xzsv8K"
                                | "_jfkdDAjba3jd"
                                | "_gLg1CWr7p"
                                | "_WIn9UJ86JKdV4dM"
                                | "_X46O5IeS"
                                | "_YlCJ3lg"
                                | "_dku592fbFAj"
                                | "_fdjkDSAFjklaf2s"
                                | "_lxpgvVMLd0S7uRl"
                        )
                    })
                    .collect();
                if !obf.is_empty() {
                    println!("SAP symbols present: {}", obf.join(", "));
                }
                0
            }
            Err(e) => {
                eprintln!("parse failed: {e}");
                1
            }
        }
    } else {
        eprintln!("unknown mach subcommand: {}", args[0]);
        2
    }
}

fn cmd_sap(args: &[String]) -> i32 {
    // Bare `perun sap` is the zero-config smoke test: cached (or freshly
    // fetched) assets, auto-detected machine address, built-in payload.
    // Guest obfuscated code keeps deep recursion and wide frames; run the
    // whole sequence on a dedicated thread with a large stack, mirroring
    // the reference emulator's separate 8MB guest stack.
    let args = args.to_vec();
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || {
            // sigaltstack is per-thread: the crash/int3 handlers rely on
            // SA_ONSTACK to survive guest-clobbered RSPs, but this spawned
            // thread starts without one. Install it here, before any guest
            // code runs on this thread.
            unsafe { sap::install_thread_altstack() };
            cmd_sap_inner(&args)
        })
        .expect("failed to spawn SAP thread");
    if let Ok(code) = handle.join() {
        code
    } else {
        eprintln!("[sap] thread panicked");
        1
    }
}

fn cmd_sap_inner(args: &[String]) -> i32 {
    // Asset resolution: an explicit directory wins; otherwise a complete
    // pinned cache is used as-is; otherwise the zero-config fetcher
    // downloads the missing assets (first run only) and the command
    // continues from the cache. A directory is recognized positionally
    // (first non-flag argument), so flag-only invocations work.
    let dir = if !args.is_empty() && Path::new(&args[0]).is_dir() {
        args[0].clone()
    } else {
        match fetcher::ensure_cache(true) {
            Ok(cache) => cache.display().to_string(),
            Err(e) => {
                eprintln!("assets: {e}");
                return 1;
            }
        }
    };
    // Machine address: auto-detected (pinned on first use), or forced
    // per-run with --mac for differential-testing the FairPlay identity.
    let mut mac: Option<[u8; 6]> = None;
    let mut sign_hex: Option<String> = None;
    let mut sign_file: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--mac" if i + 1 < args.len() => {
                match store::parse_mac_text(&args[i + 1]) {
                    Ok(m) => mac = Some(m),
                    Err(e) => {
                        eprintln!("--mac: {e}: {}", args[i + 1]);
                        return 2;
                    }
                }
                i += 2;
            }
            "--sign" if i + 1 < args.len() => {
                sign_hex = Some(args[i + 1].clone());
                i += 2;
            }
            "--file" if i + 1 < args.len() => {
                sign_file = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }
    let mac = match mac {
        Some(m) => m,
        None => store::primary_mac(),
    };
    let guid = store::appstore::guid_from_mac(&mac);
    println!("[sap] machine guid: {guid}");

    let assets = match sap::SapAssets::load_dir(&dir) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("assets: {e}");
            return 1;
        }
    };

    // Speculative TLS: the certificate download (~100-150 ms of network) runs
    // concurrently with image mapping; the setup phase joins the result. The
    // thread only performs the HTTPS fetch — it touches no guest state, no
    // process-wide handlers, and its failure surfaces as a setup error below,
    // exactly as a synchronous fetch would. The fetcher caches the certificate
    // (TTL 24h), so on cache hits the thread is a file read and the hot path
    // performs zero CDN round-trips before the protocol POST.
    let cert_fetch = std::thread::spawn(|| -> Result<Vec<u8>, String> {
        let path = fetcher::ensure_cert()?;
        std::fs::read(&path).map_err(|e| format!("read cached certificate: {e}"))
    });

    let t0 = std::time::Instant::now();
    let mut rt = match sap::SapRuntime::new(&assets) {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime: {e}");
            return 1;
        }
    };
    println!("[sap] images loaded natively in {:?}", t0.elapsed());
    println!("[sap] {}", rt.entry_report());

    let t0 = std::time::Instant::now();
    match rt.init(mac) {
        Ok(ctx) => println!("[sap] SAPInit OK: context {:#x} ({:?})", ctx, t0.elapsed()),
        Err(e) => {
            eprintln!("[sap] SAPInit failed: {e}");
            return 1;
        }
    }

    // Join the speculative certificate fetch (started before image loading).
    let cert = match cert_fetch.join() {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            eprintln!("[sap] setup failed: {e}");
            return 1;
        }
        Err(_) => {
            eprintln!("[sap] certificate fetch thread panicked");
            return 1;
        }
    };

    let t0 = std::time::Instant::now();
    match rt.setup_with_cert(mac, cert) {
        Ok(()) => println!("[sap] SAP setup complete ({:?})", t0.elapsed()),
        Err(e) => {
            eprintln!("[sap] SAP setup failed: {e}");
            return 1;
        }
    }

    let payload = if let Some(hex) = &sign_hex {
        hex_decode(hex)
    } else if let Some(path) = &sign_file {
        match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("read {path}: {e}");
                return 1;
            }
        }
    } else {
        b"perun native SAP smoke test".to_vec()
    };

    let t0 = std::time::Instant::now();
    match rt.sign(&payload) {
        Ok(sig) => {
            println!(
                "[sap] SAPSign OK: {} bytes in {:?}",
                sig.len(),
                t0.elapsed()
            );
            let mut hex = String::with_capacity(sig.len() * 2);
            for b in &sig {
                hex.push_str(&format!("{b:02x}"));
            }
            println!("[sap] signature: {hex}");
            0
        }
        Err(e) => {
            eprintln!("[sap] SAPSign failed: {e}");
            1
        }
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(char::is_ascii_hexdigit).collect();
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap_or(0))
        .collect()
}

#[cfg(test)]
mod help_tests {
    use super::*;

    const LOW_LEVEL: [&str; 8] = [
        "run", "info", "mach", "sap", "seq", "call", "scaffold", "adi",
    ];

    #[test]
    fn bare_auth_prints_help_instead_of_panicking() {
        // Regression: `sub[1..]` used to be evaluated before the empty check, so a
        // bare `auth` panicked with a slice-range error in both personas.
        for persona_bin in ["ipatool", "perun"] {
            let args = vec![persona_bin.to_string(), "auth".to_string()];
            let code = run_with_args(&args);
            assert!(
                code == 0 || code == 2,
                "{persona_bin} auth returned {code}, expected help (0) or usage (2)"
            );
        }
    }

    #[test]
    fn every_low_level_command_has_help() {
        for sub in LOW_LEVEL {
            assert!(low_level_help(sub).is_some(), "{sub} should have help");
        }
    }

    #[test]
    fn help_is_absent_for_commands_that_route_to_the_store_lane() {
        // The store lane owns its own cobra help, byte-for-byte; the low-level
        // intercept must not shadow it.
        for sub in [
            "store",
            "auth",
            "search",
            "purchase",
            "download",
            "list-purchases",
            "list-versions",
        ] {
            assert!(
                low_level_help(sub).is_none(),
                "{sub} must not be intercepted"
            );
        }
    }

    #[test]
    fn help_text_carries_no_runtime_log_line() {
        // The regression this pins: `perun sap --help` used to fall through to the
        // command and run a live session, emitting [fetcher]/[sap] log lines and
        // performing network I/O. A help string must not contain a log prefix.
        for sub in LOW_LEVEL {
            let text = low_level_help(sub).expect("help exists");
            assert!(
                !text.lines().any(|l| l.starts_with('[')),
                "{sub} help must not contain a bracketed log line"
            );
            assert!(!text.is_empty(), "{sub} help must not be empty");
        }
    }

    #[test]
    fn help_flag_is_found_in_any_position() {
        let v = |s: &[&str]| {
            s.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<String>>()
        };
        assert!(help_flag_present(&v(&["--help"])));
        assert!(help_flag_present(&v(&["-h"])));
        assert!(help_flag_present(&v(&[
            "--mac", "AA:BB", "--help", "extra"
        ])));
        assert!(!help_flag_present(&v(&[])));
        assert!(!help_flag_present(&v(&["--verbose", "--trace"])));
    }

    #[test]
    fn dispatcher_answers_help_before_running_the_command() {
        // The bug lived in the wiring, not the helper: `--help` reached the
        // command and started real work. Drive the dispatcher directly and assert
        // it returns 0 without touching the filesystem, a guest thread or network.
        for sub in LOW_LEVEL {
            for flag in ["-h", "--help"] {
                let args: Vec<String> = ["perun", sub, flag]
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                assert_eq!(run_with_args(&args), 0, "perun {sub} {flag}");
            }
        }
    }

    #[test]
    fn unknown_subcommand_with_help_flag_is_not_answered() {
        let args = vec!["--help".to_string()];
        assert!(help_flag_present(&args));
        assert!(low_level_help("bogus").is_none());
    }
}
