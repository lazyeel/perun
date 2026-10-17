// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The end-to-end Windows-lane driver: one process, one live session,
//! no register forces. The five proven nodes assembled:
//!   1. GSA startMachineProvisioning -> a fresh SPIM under OUR device-id.
//!   2. Init (0xb0eda7af) with the live Call-1 envelope shape: the
//!      V1-word packet, flags 4, and the identity/path slots the live
//!      stand carried (+0x48 identity string, +0x68 a path buffer).
//!   3. Configuration (0xcfe0b46a) with the win_ctx container -- it
//!      mints the state objects and the event pair.
//!   4. Transform (0x716bd86c) with the pkt_pass2 V1-word envelope and
//!      the fresh SPIM -- the fold algebra passes legitimately
//!      (byte==0x01, zero terms) and the worker is invoked.
//!   5. The session director (PERUN_SESSION_DIRECTOR) stands in for
//!      the host worker thread the DLL's contract assumes.
//!
//! Everything after the fold gates is the guest's own state chain:
//! whether the worker reaches the CPIM write depends only on the
//! session this pipeline builds. No Android artifacts are read.

use perun_core::loader::{DLL_PROCESS_ATTACH, Image};
use perun_shims::table::ShimTable;

// ── The walk-less station circuit (2026-10-22d) ────────────────────────
// The seq instruments proved the transform's whole downstream chain is
// deterministic given five fixed stations: the term-birth dispatch
// (0x7019d, where the self-check reads the packet word), the r12 loop
// (0x8af68e, wants the CFF table base), and the three finalization
// writes (0xb472b/0xb473a/0xb4748, the result slots [rsp+0xbf0/0xba0/
// 0xc70]). In seq those ran under the TF walk; here the same five
// stations run as int3 breakpoints -- the pipeline has no stepper, but
// the .text page is RWX and the call is synchronous, so a trap handler
// can do the identical work: read the word, seed the success word,
// fix the registers, and resume.
//
// PERUN_TR_SEED=1 arms the circuit for the transform call only; the
// word it seeds is the measured live success word 00000001, and the
// before-word is printed so every run reports what the worker itself
// published (the seq show-only probe, built in).
static mut STATION_AT: [u64; 32] = [0; 32];
static mut STATION_KIND: [u8; 32] = [0; 32]; // 0=off 1=word-seed 2=r12 3=rax-finalize
static mut STATION_N: usize = 0;
static mut SEED_BASE: u64 = 0; // the image base, for the CFF table fix
static mut STATION_ORIG: [u8; 32] = [0; 32];
static mut REARM_AT: u64 = 0;
#[allow(dead_code)]
static mut REARM_ORIG: u8 = 0;

unsafe extern "C" fn segv_namer(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    uctx: *mut libc::c_void,
) {
    unsafe {
        let uc = uctx as *mut libc::ucontext_t;
        let rip = (*uc).uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
        eprintln!("[segv-namer] guest SEGV rip={rip:#x} -- naming and dying");
        libc::_exit(139);
    }
}

unsafe extern "C" fn station_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    uctx: *mut libc::c_void,
) {
    unsafe {
        let uc = uctx as *mut libc::ucontext_t;
        let gregs = &mut (*uc).uc_mcontext.gregs;
        // int3 semantics: RIP points PAST the 0xcc byte, so the station
        // address is rip - 1.
        let rip_raw = gregs[libc::REG_RIP as usize] as u64;
        // The re-arm step: the previous trap restored the original
        // byte and single-stepped the WHOLE instruction; this trap is
        // that TF step (the landing rip is instruction start + length,
        // which we cannot know in advance -- so the pending flag, not
        // an address match, identifies it). Put the 0xcc back at the
        // station and clear TF.
        if REARM_AT != 0 {
            std::ptr::write_volatile(REARM_AT as *mut u8, 0xcc);
            let flags = gregs[libc::REG_EFL as usize] as u64;
            gregs[libc::REG_EFL as usize] = (flags & !0x100) as i64;
            REARM_AT = 0;
            return;
        }
        let rip = rip_raw - 1;
        let n = STATION_N;
        for k in 0..n {
            if STATION_AT[k] != rip {
                continue;
            }
            let rsp = gregs[libc::REG_RSP as usize] as u64;
            let rcx = gregs[libc::REG_RCX as usize] as u64;
            match STATION_KIND[k] {
                1 => {
                    // The self-check slot: [rcx+4] as u32 in gate reading
                    // (BE bytes 4..7 of the packet). Show it, then seed the
                    // success word. Value 0 = show only.
                    let dst = (rcx + 4) as *mut u32;
                    let before = std::ptr::read_volatile(dst);
                    let gat = before.swap_bytes();
                    eprintln!("[station] word @0x7019d: was {before:#010x} (gatelike {gat:#010x})");
                    std::ptr::write_volatile(dst, 0x0100_0000); // BE 00000001
                }
                2 => {
                    gregs[libc::REG_R12 as usize] = (SEED_BASE + 0x95fc90) as i64;
                }
                3 => {
                    // The finalization writes want a writable page; the
                    // guest stack top (rsp rounded down a page) always is.
                    gregs[libc::REG_RAX as usize] = (rsp & !0xfff) as i64;
                }
                7 => {
                    // The SetPath tail-gate seed: the final cascade
                    // compares the fold term to the INIT opcode term
                    // (cmp $0x9005d7c2,%edi at 0x8feaa); seeding rdi
                    // with the init term passes it (measured in seq,
                    // SetPath rc=0 x2 with the word+term pair).
                    let rdi_v = gregs[libc::REG_RDI as usize] as u64;
                    eprintln!("[station] tail-seed rip={rip:#x} rdi was {rdi_v:#x} -> 0x9005d7c2");
                    gregs[libc::REG_RDI as usize] = 0x9005_d7c2;
                }
                6 => {
                    // The -45026 gate observer: the E-gate at 0x8b05c7
                    // (cmp r9d, 0x4069d332) -- print the incoming r9d,
                    // the E it folds to, and the frame slots the gate
                    // reads. NO writes.
                    let r9d = gregs[libc::REG_R9 as usize] as u32;
                    let edx = gregs[libc::REG_RDX as usize] as u32;
                    eprintln!(
                        "[station] gate rip={rip:#x} edx={edx:#x} (E={:#x}, pass {}) r9d={r9d:#x} rdi={:#x}",
                        edx.wrapping_sub(0x4069_d332),
                        edx == 0x4069_d333,
                        gregs[libc::REG_RDI as usize] as u64
                    );
                }
                4 => {
                    // Observer: name the station and dump the contract
                    // registers; at the fork also read [rsi+4] -- the
                    // field that picks the crypto route.
                    let rsi = gregs[libc::REG_RSI as usize] as u64;
                    let mut fork = String::new();
                    if rip == SEED_BASE + 0x131577 && rsi > 0x1000 && rsi < 0x8000_0000_0000 {
                        let f4 = std::ptr::read_volatile((rsi + 4) as *const u32);
                        fork = format!(" [rsi+4]={f4:#x}");
                    }
                    eprintln!(
                        "[station] observer rip={rip:#x} rax={:#x} rdi={:#x} rsi={:#x} r9={:#x} rbp={:#x}{fork}",
                        gregs[libc::REG_RAX as usize] as u64,
                        gregs[libc::REG_RDI as usize] as u64,
                        rsi,
                        gregs[libc::REG_R9 as usize] as u64,
                        gregs[libc::REG_RBP as usize] as u64
                    );
                }
                _ => {}
            }
            // Resume semantics for a station whose instruction is
            // longer than the int3 byte: restore the original byte,
            // rewind RIP to the instruction start, single-step it,
            // and let the next trap (the TF step, rip past the whole
            // instruction) re-arm the 0xcc and clear TF.
            std::ptr::write_volatile(rip as *mut u8, STATION_ORIG[k]);
            REARM_AT = rip;
            gregs[libc::REG_RIP as usize] = rip as i64;
            let flags = gregs[libc::REG_EFL as usize] as u64;
            gregs[libc::REG_EFL as usize] = (flags | 0x100) as i64; // TF
            return;
        }
        // Not ours: re-raise for the default handler to name it.
        libc::signal(libc::SIGTRAP, libc::SIG_DFL);
        libc::raise(libc::SIGTRAP);
    }
}

fn stations_arm(image_base: u64, seed_word: bool) {
    stations_arm_mode(image_base, seed_word, false)
}

fn stations_arm_init(image_base: u64) {
    unsafe {
        // The init watch: the word-seed station (kind 1, [rcx+4] =
        // the packet word) plus the single confirmed gate observer.
        // PERUN_INIT_WORD_SEED=0 drops the seed (honest control).
        let seed = std::env::var("PERUN_INIT_WORD_SEED")
            .map(|v| v != "0")
            .unwrap_or(true);
        STATION_N = if seed { 2 } else { 1 };
        STATION_AT[0] = image_base + 0x7019d;
        STATION_KIND[0] = 1;
        STATION_AT[1] = image_base + 0x66d14;
        STATION_KIND[1] = 6;
        SEED_BASE = image_base;
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let arr = std::ptr::addr_of!(STATION_AT);
        let mut pages: Vec<u64> = Vec::new();
        let mut k = 0usize;
        while k < STATION_N {
            let a = std::ptr::read_volatile((*arr).as_ptr().add(k));
            STATION_ORIG[k] = std::ptr::read_volatile(a as *const u8);
            let pg = a & !(page as u64 - 1);
            if !pages.contains(&pg) {
                pages.push(pg);
            }
            k += 1;
        }
        for pg in &pages {
            libc::mprotect(
                *pg as *mut libc::c_void,
                page,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
        }
        k = 0;
        while k < STATION_N {
            let a = std::ptr::read_volatile((*arr).as_ptr().add(k));
            std::ptr::write_volatile(a as *mut u8, 0xcc);
            k += 1;
        }
        let act = libc::sigaction {
            sa_sigaction: station_handler as *const () as usize,
            sa_mask: std::mem::zeroed(),
            sa_flags: libc::SA_SIGINFO | libc::SA_NODEFER,
            sa_restorer: None,
        };
        libc::sigaction(libc::SIGTRAP, &act, core::ptr::null_mut());
        println!("[stations] init watch armed (word-seed {seed})");
    }
}

fn disarm_stations() {
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let arr = std::ptr::addr_of!(STATION_AT);
        let mut pages: Vec<u64> = Vec::new();
        let mut k = 0usize;
        while k < STATION_N {
            let at = std::ptr::read_volatile((*arr).as_ptr().add(k));
            std::ptr::write_volatile(at as *mut u8, STATION_ORIG[k]);
            let pg = at & !(page as u64 - 1);
            if !pages.contains(&pg) {
                pages.push(pg);
            }
            k += 1;
        }
        for pg in &pages {
            libc::mprotect(
                *pg as *mut libc::c_void,
                page,
                libc::PROT_READ | libc::PROT_EXEC,
            );
        }
        STATION_N = 0;
        libc::signal(libc::SIGTRAP, libc::SIG_DFL);
    }
    println!("[stations] disarmed");
}

/// mode observers_only: arm ONLY the observer stations (kinds 4/6) --
/// the SetPath/SetID watch must not carry the transform's action
/// stations (the r12/rax seeds) into the session selectors.
#[allow(clippy::too_many_arguments)]
fn stations_arm_mode(image_base: u64, seed_word: bool, observers_only: bool) {
    unsafe {
        // Five action stations plus observers over the worker's own
        // route: entry (0x100050), return into the boundary block
        // (0x91512 -- rax = the worker's verdict), the post-check
        // contract (0x9154e), the epilogue (0x131620), the crypto
        // fork (0x131577).
        if observers_only {
            // The session watch. Under PERUN_SESS_WORDS=1 the TWO
            // LOCKS are seeded (the verdict word at [PKT+4..8] via
            // the 0x7019d station, and the init-term tail at 0x8feaa
            // -- the pair that carries SetPath to rc=0); without it
            // the same two sites are pure observers. The rest are the
            // worker-route observers and the confirmed gate heads.
            let seeds = std::env::var_os("PERUN_SESS_WORDS").is_some();
            STATION_AT[0] = image_base + 0x7019d;
            STATION_KIND[0] = if seeds { 1 } else { 4 };
            STATION_AT[1] = image_base + 0x8feaa;
            STATION_KIND[1] = if seeds { 7 } else { 4 };
            STATION_AT[2] = image_base + 0x100050;
            STATION_KIND[2] = 4;
            STATION_AT[3] = image_base + 0x91512;
            STATION_KIND[3] = 4;
            STATION_AT[4] = image_base + 0x9154e;
            STATION_KIND[4] = 4;
            STATION_AT[5] = image_base + 0x131577;
            STATION_KIND[5] = 4;
            STATION_AT[6] = image_base + 0x8fee2;
            STATION_KIND[6] = 4;
            STATION_AT[7] = image_base + 0x66d14;
            STATION_KIND[7] = 6;
            STATION_N = 8;
            SEED_BASE = image_base;
        } else {
            STATION_N = if seed_word { 10 } else { 9 };
            // The 45026-gate observer rides along on every arming (it
            // never writes; observing SetPath needs the whole table).
            // NOTE: armed only around transform by default; PERUN_SESS_ARM
            // arms the same table around SetPath/SetID instead.
            STATION_AT[0] = image_base + 0x7019d;
            STATION_KIND[0] = 1;
            STATION_AT[1] = image_base + 0xaf68e;
            STATION_KIND[1] = 2;
            STATION_AT[2] = image_base + 0xb472b;
            STATION_KIND[2] = 3;
            STATION_AT[3] = image_base + 0xb473a;
            STATION_KIND[3] = 3;
            STATION_AT[4] = image_base + 0xb4748;
            STATION_KIND[4] = 3;
            STATION_AT[5] = image_base + 0x100050;
            STATION_KIND[5] = 4;
            STATION_AT[6] = image_base + 0x91512;
            STATION_KIND[6] = 4;
            STATION_AT[7] = image_base + 0x9154e;
            STATION_KIND[7] = 4;
            STATION_AT[8] = image_base + 0x131620;
            STATION_KIND[8] = 4;
            STATION_AT[9] = image_base + 0x131577;
            STATION_KIND[9] = 4;
            STATION_AT[10] = image_base + 0xb05c7;
            STATION_KIND[10] = 6;
        }
        SEED_BASE = image_base;
        // Patch the int3 bytes. The .text page is RWX (the loader maps
        // it PROT_READ|WRITE|EXEC); each address is a verified
        // instruction boundary from the walk.
        let n_armed = STATION_N;
        println!("[arm] base={image_base:#x} n={n_armed}");
        // The loader seals sections to their PE permissions after the
        // RWX map (.text ends up R+X), so the int3 patch needs the
        // pages writable first. One mprotect per touched page.
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let mut pages: Vec<u64> = Vec::new();
        let arr = std::ptr::addr_of!(STATION_AT);
        let mut k = 0usize;
        while k < STATION_N {
            let a = std::ptr::read_volatile((*arr).as_ptr().add(k));
            STATION_ORIG[k] = std::ptr::read_volatile(a as *const u8);
            let pg = a & !(page as u64 - 1);
            if !pages.contains(&pg) {
                pages.push(pg);
            }
            k += 1;
        }
        for pg in &pages {
            libc::mprotect(
                *pg as *mut libc::c_void,
                page,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
        }
        let mut k = 0usize;
        while k < STATION_N {
            let a = std::ptr::read_volatile((*arr).as_ptr().add(k));
            std::ptr::write_volatile(a as *mut u8, 0xcc);
            k += 1;
        }
        // The action: SIGTRAP with SA_NODEFER|SA_SIGINFO so nested
        // traps from the same thread reach the handler too.
        let act = libc::sigaction {
            sa_sigaction: station_handler as *const () as usize,
            sa_mask: std::mem::zeroed(),
            sa_flags: libc::SA_SIGINFO | libc::SA_NODEFER,
            sa_restorer: None,
        };
        libc::sigaction(libc::SIGTRAP, &act, core::ptr::null_mut());
        // Name any guest SEGV that hits while the circuit is armed:
        // the worker's crypto branch dies somewhere past the fork,
        // and the crash rip is the next station candidate.
        let segv_act = libc::sigaction {
            sa_sigaction: segv_namer as *const () as usize,
            sa_mask: std::mem::zeroed(),
            sa_flags: libc::SA_SIGINFO,
            sa_restorer: None,
        };
        libc::sigaction(libc::SIGSEGV, &segv_act, core::ptr::null_mut());
        let n = STATION_N;
        println!(
            "[stations] armed {n} int3 station(s) @ base {image_base:#x} (word-seed {seed_word})"
        );
        // Self-test: raise a SIGTRAP we control. If the handler is
        // live it prints and returns; if not, the run dies here --
        // which is exactly the information needed either way.
    }
}

// The HONEST WRAPPER (asm): vdfut NEVER writes [rsp+0x30] in
// its own body -- the ONLY write in the whole function is a
// pxor/movdqu ZERO-FILL at RVA 0x8c30c, off the transform route.
// The SPIM pointer in the worker's frame is the CALLER'S OWN
// stack slot: parked pre-call at [rsp+0x38], which the callee's
// entry (rsp = ours - 8) reads as ITS [rsp+0x30]. This shim
// reproduces the live wrapper's construction with no external
// poke. SysV args: rdi=f, rsi=a0, rdx=a1, rcx=a2, r8=spim.
core::arch::global_asm! {
    ".text",
    ".globl perun_honest_wrapper",
    "perun_honest_wrapper:",
    "push rbx",
    "mov rbx, rdi",          // f
    "sub rsp, 0x1000",       // a frame; the callee's rsp+0x30 lives inside it
    "mov QWORD PTR [rsp+0x28], r8",  // SPIM: call pushes ret (-8), the callee reads its [rsp+0x30] = our [rsp+0x28]
    "mov rcx, rsi",           // win64 a0
    "mov rdx, rdx",           // win64 a1 (unchanged)
    "xor r8, r8",             // win64 a2
    "xor r9, r9",             // win64 a3
    "mov r12, QWORD PTR [rsp+0x28]",   // witness: the slot still holds SPIM after the call
    "call rbx",
    "mov QWORD PTR [rsp+0xF00], r12",  // park the witness for the caller
    "add rsp, 0x1000",
    "pop rbx",
    "ret",
}

unsafe extern "sysv64" {
    fn perun_honest_wrapper(
        f: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64,
        a0: u64,
        a1: u64,
        a2: u64,
        spim: u64,
    ) -> u64;
}

fn page(len: usize) -> *mut core::ffi::c_void {
    unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    }
}

fn put(buf: *mut core::ffi::c_void, off: usize, bytes: &[u8]) {
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>().add(off), bytes.len())
    };
}

// Host callbacks for the envelope's code slots. The live envelopes
// carried WRAPPER FUNCTIONS there (the guest calls them while minting
// its session objects); ours carried the DLL export (wrong semantics)
// or zero. Each callback logs its four register args and answers a
// distinct fresh page, so the first run tells WHICH slot fires with
// WHAT signature -- the empirical ABI of the wrapper contract.
fn cb_page() -> *mut core::ffi::c_void {
    page(4096)
}

/// The address of a win64 callback as a plain integer, the way the
/// envelope's code slots want it (clippy: function items cast
/// through their pointer type).
/// Call the guest through perun's PE-stack trampoline -- the seq
/// instruments invoke every export this way and the only canon that
/// answers rc=0 on the live nonce (s195) is a seq run: the direct
/// f() call leaves the guest's frame slots on a Rust stack, and the
/// init body's deep cascade reads them differently (measured:
/// direct -> -45020 digest profile, trampoline -> rc=0 verdict
/// profile on the SAME envelope and nonce). PERUN_NO_PE_STACK=1
/// keeps the direct call for the A/B control.
fn guest_call(
    f: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
) -> u64 {
    static PE_STACK: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    if std::env::var_os("PERUN_NO_PE_STACK").is_some() {
        return unsafe { f(a0, a1, a2, a3) };
    }
    let top = *PE_STACK.get_or_init(|| unsafe {
        let (limit, base) = perun_core::teb::alloc_pe_stack(perun_core::teb::PE_STACK_SIZE)
            .expect("pe stack alloc");
        perun_core::teb::set_pe_stack_bounds(limit, base);
        base
    });
    unsafe { perun_core::teb::call_on_stack(f, top, [a0, a1, a2, a3]) }
}

fn cb_addr(f: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64) -> u64 {
    f as usize as u64
}

macro_rules! cb {
    ($name:ident) => {
        unsafe extern "win64" fn $name(a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
            let r = cb_page() as u64;
            println!(
                "[cb:{}] a0={a0:#x} a1={a1:#x} a2={a2:#x} a3={a3:#x} -> {r:#x}",
                stringify!($name)
            );
            r
        }
    };
}

cb!(cb_slot28);
cb!(cb_slot30);
cb!(cb_slot40);
cb!(cb_slot48);
cb!(cb_slot50);
cb!(cb_slot70);
cb!(cb_slot90);
cb!(cb_slot98);
cb!(cb_slota0);
cb!(cb_slotb0);
cb!(cb_slotb8);

/// The guest's dispatcher-state register (RVA 0x161324): the low dword is
/// the dispatch offset the 0x90exx cursor family indexes with, the high
/// dword a counter. Watching it after every opcode shows which call
/// advances the session state and by how much.
fn peek_state(image: &Image, tag: &str) {
    let base = image.base() as u64;
    for rva in (0x16131cu64..=0x161334u64).step_by(6) {
        let v = unsafe { std::ptr::read_volatile((base + rva) as *const u64) };
        println!("[state:{tag}] RVA {rva:#x} = {v:#x}");
    }
}

/// The session-object slots ([0x19dda0..0x19ddb0]): the family the
/// worker dereferences (rsi = [[0x19ddb0]] and the fork's [+4] field).
/// Dumping after EVERY call shows WHICH opcode mints which object --
/// the map of the wrapper's session construction.
fn peek_slots(image: &Image, tag: &str) {
    let base = image.base() as u64;
    for rva in (0x19dda0u64..=0x19ddb0u64).step_by(8) {
        let v = unsafe { std::ptr::read_volatile((base + rva) as *const u64) };
        println!("[slot:{tag}] RVA {rva:#x} = {v:#x}");
        if v > 0x1000 && v < 0x8000_0000_0000 {
            let obj = v;
            let mut line = String::new();
            for off in (0u64..0x40).step_by(8) {
                let f = unsafe { std::ptr::read_volatile((obj + off) as *const u64) };
                line.push_str(&format!(" {f:016x}"));
            }
            println!("[obj:{tag}] +0x00..0x38 ={line}");
            // Identity hunt (PERUN_OBJHUNT=1 only): print the pointer
            // fields' content in hex+ASCII. The read is page-safe (the
            // buffers are heap blocks far from edges in practice).
            if std::env::var_os("PERUN_OBJHUNT").is_none() {
                continue;
            }
            for off in (0x18u64..=0x38).step_by(8) {
                #[allow(clippy::collapsible_if)]
                let f = unsafe { std::ptr::read_volatile((obj + off) as *const u64) };
                if f > 0x1000 && f < 0x8000_0000_0000 && (f & 7) == 0 {
                    let mut bytes = [0u8; 64];
                    for (k, slot) in bytes.iter_mut().enumerate() {
                        *slot = unsafe { std::ptr::read_volatile((f + k as u64) as *const u8) };
                    }
                    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                    let printable: String = bytes
                        .iter()
                        .map(|b| {
                            if b.is_ascii_graphic() || *b == 0 {
                                *b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    println!("[obj:{tag}] +{off:#x} -> {f:#x}");
                    println!("[obj:{tag}] hex64 = {hex}");
                    println!("[obj:{tag}] asc64 = {printable:?}");
                }
            }
        }
    }
}

fn main() {
    let image_path = std::env::args().nth(1).unwrap_or_else(|| {
        "/opt/data/adi-pe/extracted/itunes_extracted/iTunes/CoreADI64.dll".into()
    });

    // ── node 1: the network half, a live SPIM for this machine ──────────
    // The GSA request MOVED to node 2.6 (after init-2): the SPIM must be
    // minted under the identity that exists AFTER the guest has built its
    // session transport. PERUN_GUEST_ID=1 makes 2.6 read the GUEST'S OWN
    // generated material from the session object and mint the id from IT
    // (the live wrapper's architecture: one generated value into both the
    // guest and the GSA headers). The default falls back to collect_linux.
    let guest_mode = std::env::var("PERUN_GUEST_ID").unwrap_or_default();
    let guest_active = !guest_mode.is_empty();
    let mut id = perun_adi_win32::net::identity(); // re-minted in 2.6
    let mut ep: Option<perun_adi_win32::net::Endpoints> = None;
    let mut start: Option<perun_adi_win32::net::Start> = None;
    println!("[id] (pre-init) device-id {} lu {}", id.device_id, id.lu);
    // The honest Windows chain needs the network BEFORE
    // configuration: the cfg packet carries the machine's own fresh
    // SPIM slices (start_provisioning's answer). PERUN_NET=0 disables
    // (offline instrument runs); guest_mode=3 keeps the old probe path.
    let net_on = std::env::var("PERUN_NET").map(|v| v != "0").unwrap_or(true);
    // The honest Windows chain mints the SPIM BEFORE configuration
    // (the cfg packet carries it). guest_mode=3 keeps its own probe
    // path; the default (empty) runs the plain honest network half.
    if net_on && (guest_mode == "3" || guest_mode.is_empty()) {
        ep = Some(match perun_adi_win32::net::lookup(&id) {
            Ok(e) => e,
            Err(e) => {
                println!("[net] lookup failed: {e}");
                return;
            }
        });
        start = Some(
            match perun_adi_win32::net::start_provisioning(&id, ep.as_ref().unwrap()) {
                Ok(s) => s,
                Err(e) => {
                    println!("[net] start failed: {e}");
                    return;
                }
            },
        );
        let s = start.as_ref().unwrap();
        println!(
            "[net] (prime) spim {} bytes, ptxid {}",
            s.spim.len(),
            s.ptxid
        );
    }

    // Seed the registry the Windows host would have: the ADI guests
    // probe ProductId (the iTunes wrapper's key is SOFTWARE\Apple Inc.\
    // CoreADI); the Linux stand for the machine certificate is
    // /etc/machine-id. PERUN_NO_REGISTRY=1 skips it: the s195 canon
    // (rc=0 on the live nonce) runs on an EMPTY registry.
    if std::env::var_os("PERUN_NO_REGISTRY").is_none() {
        let reg = perun_shims::registry::Registry::global();
        if let Ok(pid) = std::fs::read_to_string("/etc/machine-id") {
            let pid = pid.trim().to_string();
            reg.set(
                "ProductId",
                perun_shims::registry::RegValue {
                    data: format!("{pid}\0").into_bytes(),
                    kind: perun_shims::registry::RegType::Sz,
                },
            );
        }
        // The wrapper's own registry footprint (the strings inside
        // iTunes.exe carry this key): the ADI provisioning state
        // lives under SOFTWARE\Apple Inc.\CoreADI. Seeding the
        // key with our canonical InstallDir gives the guest the
        // environment a real Windows host would show (the
        // RegQueryValueExA store was empty and the key simply did
        // not exist -- ERROR_FILE_NOT_FOUND -- on every probe).
        let inst = format!(
            "{}/Common/Apple Computer/iTunes/adi\0",
            std::env::var("PERUN_APPDATA")
                .unwrap_or_else(|_| "/opt/data/home/.perun/appdata".into())
        );
        for (name, data) in [("InstallDir", inst.clone()), ("InstallDirW", String::new())] {
            reg.set(
                name,
                perun_shims::registry::RegValue {
                    data: data.into_bytes(),
                    kind: perun_shims::registry::RegType::Sz,
                },
            );
        }
        println!("[reg] CoreADI InstallDir seeded");
    }

    // ── the guest half: load once, DllMain once ─────────────────────────
    let bytes = std::fs::read(&image_path).expect("read image");
    let mut table = ShimTable::collect();
    let image = Image::load(&bytes, &mut table).expect("load image");
    let _teb = unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
    let dll_main = unsafe { image.entry_dll_main() }.expect("entry");
    assert!(unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) } != 0);
    let cvu: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 =
        unsafe { std::mem::transmute(image.get_export_by_name("cvu8io98wun").expect("cvu")) };
    let f: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 =
        unsafe { std::mem::transmute(image.get_export_by_name("vdfut768ig").expect("vdfut")) };

    // cvu8io98wun, the SECOND export: the initializer the iTunes
    // wrapper calls with the provisioning PATH (the PE lane's own
    // constructor -- the Android library never had it, which is why
    // the live dump shows no cvu call). The old run passed it the
    // fold-triple state page; the real contract takes the path in
    // rcx. PERUN_CVU_MODE picks: "state" (the historical triple),
    // "path" (the initializer contract -- the wrapper's own session
    // construction, the missing SetID equivalent on Windows).
    // PERUN_NO_CVU=1 skips the cvu call entirely: the s195 canon (and
    // the Mach-O live reference) never calls the second export before
    // init, and the cvu-minted session objects change the init body's
    // route -- the diff experiment measures whether the object's
    // existence (not its contents) is the fork.
    let state = page(4096);
    if std::env::var_os("PERUN_NO_CVU").is_none() {
        unsafe {
            *state.cast::<u64>() = 0x2000000001;
            *state.cast::<u8>().add(6) = 0;
            *state.cast::<u8>().add(7) = 1;
            let mode = std::env::var("PERUN_CVU_MODE").unwrap_or_else(|_| "state".into());
            let (r, desc) = match mode.as_str() {
                "path" => {
                    let path = std::env::var("PERUN_APPDATA")
                        .unwrap_or_else(|_| "/opt/data/home/.perun/appdata/Common".into());
                    let pathb = page(4096);
                    std::ptr::copy_nonoverlapping(path.as_ptr(), pathb.cast::<u8>(), path.len());
                    (cvu(pathb as u64, 0, 0, 0), format!("path {path:?}"))
                }
                _ => (cvu(state as u64, 0x2000000001, 0, 0), "state triple".into()),
            };
            println!("[cvu] rc={r} ({desc})");
            peek_slots(&image, "after_cvu");
        }
    } else {
        println!("[cvu] skipped (PERUN_NO_CVU)");
    }

    // Shared envelope buffers.
    let pkt = page(4096);
    let ctx = page(0x1_0000);
    let spimp = page(0x1000);
    let urlp = page(0x1000);
    let olen = page(64);
    let out = page(0x1000);
    let aux = [page(4096); 6];
    let ident = page(4096);
    let pathb = page(4096);
    // The live Call-1 envelope carried REAL data at +0x48/+0x68: the
    // identity string and the provisioning path. Empty buffers read as
    // absent; fill them the way the iTunes wrapper would.
    {
        let id_hex: String = std::env::var("PERUN_IDENT").unwrap_or_else(|_| {
            id.device_id
                .chars()
                .filter(|c| *c != '.')
                .take(16)
                .collect()
        });
        put(ident, 0, id_hex.as_bytes());
        put(ident, id_hex.len(), b"\0");
        let path = format!(
            "{}/Apple Computer/iTunes/adi",
            std::env::var("PERUN_APPDATA")
                .unwrap_or_else(|_| "/opt/data/home/.perun/appdata/Common".into())
        );
        put(pathb, 0, path.as_bytes());
        put(pathb, path.len(), b"\0");
        println!("[env] ident={id_hex:?} path={path:?}");
    }

    // (The SPIM is minted in node 2.6, post-init-2; the persist lives there.)

    // ── node 2: init with the live Call-1 shape ────────────────────────
    // The live Call-1 packet was V2-HEADED with a 12-byte nonce tail
    // (00 00 00 02 | c9 34 19 2e ...). Our V1-keyed stand passes the
    // null-session fold but lands the -45001 verdict; the live shape
    // (V2 header, live terms) is what walked to the -45061 state verdict.
    // Probe the V2-header form with a zero nonce tail.
    // PERUN_NO_INITV2=1 skips this probe: the gate at 0x66d14 reads
    // a PHASE counter through [rsp+0x6c0] (E = counter + 0x4069d332),
    // and every init call advances it -- the probe leaves the main
    // init arriving as E=2 where the gate wants the first phase.
    if std::env::var_os("PERUN_NO_INITV2").is_none() {
        unsafe {
            std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
            *pkt.cast::<u32>() = 2; // hdr 00 00 00 02, the live Call-1 header
            let c0 = ctx.cast::<u64>();
            std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
            std::ptr::write(c0.add(0), pkt as u64);
            std::ptr::write(c0.add(1), 0x4000_0000_0010); // len 0x10 | flags 4
            std::ptr::write(c0.add(3), 0x0022_6564);
            std::ptr::write(c0.add(4), 0x1);
            std::ptr::write(c0.add(9), 0x2);
            let r = guest_call(f, 0xb0eda7af, ctx as u64, 0, 0);
            println!("[init:v2] rc={r:#x} ({r})");
            let pk = std::slice::from_raw_parts(pkt.cast::<u8>(), 16);
            println!(
                "[init:v2] pkt[0..16] = {}",
                pk[..16]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
        }
    }
    // PERUN_SESS_FLAGS_EARLY=1: seed the session flags BEFORE the
    // main init -- the live wrapper's init ran on a machine whose
    // adi.pb persisted (the flags set), and E at the init gate may
    // read them. Measured on this round: our body folds E=2 at
    // 0x66d14 while the live verdict profile implies E=1's branch.
    if std::env::var_os("PERUN_SESS_FLAGS_EARLY").is_some() {
        unsafe {
            let slot_ptr = image.base() as u64 + 0x19dda8;
            let obj = std::ptr::read_volatile(slot_ptr as *const u64);
            if obj > 0x1000 {
                std::ptr::write_volatile((obj + 8) as *mut u64, 1);
                std::ptr::write_volatile((obj + 0xc) as *mut u64, 1);
                println!("[sess-flags-early] [{obj:#x}+8]/[+0xc] = 1");
            } else {
                println!("[sess-flags-early] slot 0x19dda8 = {obj:#x}: no object yet");
            }
        }
    }
    // The live stand carried: V1-word packet (pkt bytes 3 and 7 = 1),
    // len 0x10 with flags 4, a stack tag at +0x10, buffers at
    // +0x18/+0x28/+0x30/+0x40, +0x20=21, +0x48 = the IDENTITY STRING,
    // +0x68 = a PATH buffer, and size fields 0x70/0x80/0x90/0x98/0xa0.
    unsafe {
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        *pkt.cast::<u8>().add(3) = 1;
        *pkt.cast::<u8>().add(7) = 1;
        // PERUN_INIT_LIVE_PKT=<path>: the live Call-1 packet (V2 +
        // the wrapper's 12-byte nonce). The zero tail answers the
        // -45061 family; the LIVE nonce bytes are fold coefficients
        // (the SetID/transform rounds proved the mechanism) -- with
        // them the init body's fold accumulates the table the way
        // the live chain's first body did.
        if let Some(live) = std::env::var("PERUN_INIT_LIVE_PKT")
            .ok()
            .and_then(|f| std::fs::read(f).ok())
        {
            std::ptr::copy_nonoverlapping(live.as_ptr(), pkt.cast::<u8>(), live.len().min(16));
        }
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        let c = ctx.cast::<u64>();
        std::ptr::write(c.add(0), pkt as u64);
        std::ptr::write(c.add(1), 0x0000_0004_0000_0010); // len 0x10 | flags 4
        // +0x10: the LIVE Call-1 carried 0x0000768000000000 (the
        // wrapper's own address-space tag, NOT the 7fff stack form).
        // PERUN_INIT_TAG3 overrides for the diff experiment.
        let tag3: u64 = std::env::var("PERUN_INIT_TAG3")
            .ok()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0x0000_7fff_0000_0000);
        std::ptr::write(c.add(2), tag3); // stack-ish tag (live: 7680 form)
        // +0x18: the live Call-1 carried a CONTAINER POINTER
        // ({0x7680aecd4151, 0xe8b<<32} = {buffer ptr, len<<32} --
        // the len form matches the DLL's own len-shifted slots).
        // Our honest stand-in: a container page holding {our ident
        // buffer, its length <<32}. PERUN_INIT_CONT=0 reverts to
        // the bare zero page (the old baseline).
        let cont18 = page(64);
        {
            let ident_len = 0x40u64; // the ident page's readable span
            std::ptr::write_volatile(cont18 as *mut u64, ident as u64);
            std::ptr::write_volatile(cont18.add(8) as *mut u64, ident_len << 32);
        }
        let use_cont = std::env::var("PERUN_INIT_CONT")
            .map(|v| v != "0")
            .unwrap_or(true);
        std::ptr::write(
            c.add(3),
            if use_cont {
                cont18 as u64
            } else {
                aux[0] as u64
            },
        );
        std::ptr::write(c.add(4), 0x15); // 21, measured
        std::ptr::write(c.add(5), aux[1] as u64);
        std::ptr::write(c.add(6), aux[2] as u64);
        std::ptr::write(c.add(7), tag3);
        std::ptr::write(c.add(8), aux[3] as u64);
        // PERUN_INIT_LIVE_CTX=1: fill the still-untested slots with the
        // LIVE Call-1 forms -- +0x60 (a heap pointer), +0x68 (the live
        // provisioning PATH '/opt/data/perun/'), +0x70 (a nanosec
        // address) -- the bounded diffs behind the init's fold.
        // +0x68 is the LIVE Call-1's PATH string pointer ('/opt/
        // data/perun/' -- the ROOT provisioning dir, read as ASCII
        // in the dump). The honest default now carries it ALWAYS:
        // the previous baseline left the slot ZERO while every live
        // envelope had a path there, and SetPath's own +0x80 path
        // contract shows the DLL reads these strings. PERUN_INIT_
        // LIVE_CTX adds the remaining still-untested live slots.
        {
            let p68 = page(64);
            put(p68, 0, b"/opt/data/perun/");
            put(p68, 16, b"\0");
            std::ptr::write(c.add(13), p68 as u64); // +0x68 the root path, ALWAYS
        }
        if std::env::var_os("PERUN_INIT_LIVE_CTX").is_some() {
            let p60 = page(64);
            std::ptr::write(c.add(12), p60 as u64); // +0x60 heap ptr
            // (+0x68 already set to the root path above.)
            // +0x70: the live was a NANOSEC-carrying address (a
            // wrapper time source), not a callback -- a fresh page
            // with a nanosec timestamp answers both readings.
            let nsp = page(64);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            std::ptr::write_volatile(nsp as *mut u64, now);
            std::ptr::write(c.add(14), nsp as u64); // +0x70 the nanosec page
        }
        // +0x48: the live Call-1 carried the FULL dashed UUID string
        // ('1A7DC030-8887-C2D8-F470-E2EA813C70C1', 36 chars). Ours by
        // default is the 16-char ident buffer; PERUN_INIT_UUID points
        // the slot at a full 36-char string built from the guest's
        // material (mode 4 reads it back after init-1 and re-inits).
        let uuid36: Option<String> = match std::env::var("PERUN_INIT_UUID") {
            Ok(u) => Some(u),
            Err(_)
                if std::env::var("PERUN_GUEST_ID")
                    .map(|v| v == "5")
                    .unwrap_or(false) =>
            {
                // Mode 5: ONE wrapper-owned identity string everywhere
                // (the live dump's architecture): the dashed UUID form
                // of our own device id feeds init's +0x48, the GSA
                // headers, SetID, and the envelope slots.
                let segs: Vec<String> = perun_adi_win32::net::identity()
                    .device_id
                    .split('.')
                    .map(|s| s.to_string())
                    .collect();
                // The live X-Mme shape: the first FOUR 8-hex segments
                // dash-mapped 8-4-4-4-12 ('1A7DC030'+'8887C2D8'+
                // 'F470E2EA'+'813C70C1' -> 1A7DC030-8887-C2D8-F470-
                // E2EA813C70C1). Ours: s1..s4 the same mapping.
                let hex32: String = segs.iter().take(4).cloned().collect::<String>();
                Some(format!(
                    "{}-{}-{}-{}-{}",
                    &hex32[0..8],
                    &hex32[8..12],
                    &hex32[12..16],
                    &hex32[16..20],
                    &hex32[20..32]
                ))
            }
            Err(_) => None,
        };
        match uuid36 {
            Some(u) => {
                put(aux[4], 0, u.as_bytes());
                put(aux[4], u.len(), b"\0");
                std::ptr::write(c.add(9), aux[4] as u64); // +0x48 the full form
            }
            None => {
                std::ptr::write(c.add(9), ident as u64); // +0x48 identity
            }
        }
        if std::env::var_os("PERUN_INIT_CB").is_some() {
            std::ptr::write(c.add(10), 0x40e8_976e_6bde_5309); // +0x50
            std::ptr::write(c.add(11), 0xbee2_365f_bf17_664b); // +0x58
        }
        // The live Call-1 carried CODE pointers at +0x28/+0x30/+0x40/
        // +0x70/+0xa8/+0xb8 (the Android wrapper's own CFF functions).
        // The live Call-1 carried the WRAPPER's own functions in every
        // code slot -- the guest calls them while minting its session
        // state. The DLL-export probe (wrong semantics) kept the
        // verdict; these LOGGING callbacks expose the real ABI on the
        // first call: which slot fires, with which register args.
        // The s195 canon (the only envelope that answers rc=0 on
        // the live nonce) carries ZEROED AUX PAGES at +0x28/+0x30/
        // +0x40 -- not code pointers. PERUN_INIT_CB=1 restores the
        // callback experiment.
        if std::env::var_os("PERUN_INIT_CB").is_some() {
            std::ptr::write(c.add(5), cb_addr(cb_slot28)); // +0x28
            std::ptr::write(c.add(6), cb_addr(cb_slot30)); // +0x30
            std::ptr::write(c.add(8), cb_addr(cb_slot40)); // +0x40
        } else {
            std::ptr::write(c.add(5), aux[1] as u64); // +0x28 a zero page
            std::ptr::write(c.add(6), aux[2] as u64); // +0x30 a zero page
            std::ptr::write(c.add(8), aux[3] as u64); // +0x40 a zero page
        }
        // The live Call-1 and the s195 canon carry SIZE CONSTANTS at
        // +0x80/+0x90/+0x98/+0xa0 (0x70/0xc2/0xf4/0x30 -- descriptor
        // magics), NOT code pointers: with the live nonce the init
        // body dives into the deep cascade and READS these as
        // descriptor sizes; the cb addresses corrupted it to -45020.
        std::ptr::write(c.add(16), 0x70); // +0x80 the live SIZE constant
        std::ptr::write(c.add(18), 0xc2); // +0x90 the live SIZE constant
        std::ptr::write(c.add(19), 0xf4); // +0x98 the live SIZE constant
        std::ptr::write(c.add(20), 0x30); // +0xa0 the live SIZE constant
        if std::env::var_os("PERUN_INIT_CB").is_some() {
            std::ptr::write(c.add(21), cb_addr(cb_slota0)); // +0xa8
            std::ptr::write(c.add(22), cb_addr(cb_slotb0)); // +0xb0
            std::ptr::write(c.add(23), cb_addr(cb_slotb8)); // +0xb8
        }
        // arg3: the live Call-1 carried a wrapper code pointer there;
        // the s195 canon (the canon that answers rc=0 on the live
        // nonce) passes ZERO -- PERUN_INIT_ARG3=0 reproduces it.
        let a3: u64 = match std::env::var("PERUN_INIT_ARG3") {
            Ok(v) => v.trim().parse().unwrap_or(0),
            Err(_) => cb_page() as u64,
        };
        // PERUN_SESS_ARM around the MAIN init: the unified self-check
        // (decoded this campaign) has the init body writing its verdict
        // word into [PKT+4..8] (ours: the digest 0x4145a051), and the
        // 0x7019d dispatch's af7 route folds it -- success needs
        // 00000001 there, exactly the transform's mechanism. The seed
        // station writes the live success word; PERUN_INIT_WORD_SEED=0
        // is the honest control.
        let init_arm = std::env::var_os("PERUN_SESS_ARM").is_some();
        if init_arm {
            stations_arm_init(image.base() as u64);
        }
        let r = guest_call(f, 0xb0eda7af, ctx as u64, 0, a3);
        if init_arm {
            disarm_stations();
        }
        peek_slots(&image, "after_init");
        println!("[init] rc={r:#x} ({r}) arg3={a3:#x}");
        let ipk = std::slice::from_raw_parts(pkt.cast::<u8>(), 32);
        println!(
            "[init] pkt[0..32] = {}",
            ipk[..16]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        peek_state(&image, "init");
    }

    // ── node 3 (the honest Windows chain, step 3): configuration
    // (0xcfe0b46a) -- a RECOGNISED Windows opcode (table 24).
    // ── node 3: configuration mints the session objects ────────────────
    // The container the cfg reads: the Android stand (identity-bound,
    // its blobs answer -45020) or OUR synthesis -- the same geometry
    // (V2|4|0xf0 blob-1, pad, 0x34|4 blob-2) carrying this machine's
    // fresh SPIM slices. PERUN_CFG_SYNTH switches to the synthesis.
    let wctx_path = if std::env::var_os("PERUN_CFG_SYNTH").is_some() {
        "/opt/data/il/variants/win_ctx_synth.bin"
    } else {
        "/opt/data/il/variants/win_ctx.bin"
    };
    let wctx = std::fs::read(wctx_path).expect("win_ctx container");
    println!("[cfg] container: {wctx_path}");
    let wctxp = page(0x2000);
    put(wctxp, 0, &wctx);
    unsafe {
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        let c = ctx.cast::<u64>();
        std::ptr::write(c.add(0), wctxp as u64);
        std::ptr::write(c.add(1), 0x30); // len
        std::ptr::write(c.add(2), 0x4); // flags
        std::ptr::write(c.add(3), 0x00226564); // measured
        std::ptr::write(c.add(4), 0x1); // measured
        std::ptr::write(c.add(9), 0x2); // +0x48 measured
        // The live cfg envelope carried the wrapper's code table in
        // its slots too (the handle-minting site 0x7c85b321 calls
        // through the envelope's callback slots *0x708/*0x610). Our
        // logging callbacks go in every code slot: if cfg ever gets
        // past the body check and starts minting, the first fire
        // names the contract's real ABI.
        std::ptr::write(c.add(4), cb_addr(cb_slot48)); // +0x20
        // The s195 canon (the only envelope that answers rc=0 on
        // the live nonce) carries ZEROED AUX PAGES at +0x28/+0x30/
        // +0x40 -- not code pointers. PERUN_INIT_CB=1 restores the
        // callback experiment.
        if std::env::var_os("PERUN_INIT_CB").is_some() {
            std::ptr::write(c.add(5), cb_addr(cb_slot28)); // +0x28
            std::ptr::write(c.add(6), cb_addr(cb_slot30)); // +0x30
            std::ptr::write(c.add(8), cb_addr(cb_slot40)); // +0x40
        } else {
            std::ptr::write(c.add(5), aux[1] as u64); // +0x28 a zero page
            std::ptr::write(c.add(6), aux[2] as u64); // +0x30 a zero page
            std::ptr::write(c.add(8), aux[3] as u64); // +0x40 a zero page
        }
        std::ptr::write(c.add(14), cb_addr(cb_slot70)); // +0x70
        std::ptr::write(c.add(18), cb_addr(cb_slot90)); // +0x90
        std::ptr::write(c.add(19), cb_addr(cb_slot98)); // +0x98
        if std::env::var_os("PERUN_INIT_CB").is_some() {
            std::ptr::write(c.add(21), cb_addr(cb_slota0)); // +0xa8
            std::ptr::write(c.add(22), cb_addr(cb_slotb0)); // +0xb0
            std::ptr::write(c.add(23), cb_addr(cb_slotb8)); // +0xb8
        }
        let r = guest_call(f, 0xcfe0b46a, ctx as u64, 0, 0);
        println!("[cfg] rc={r:#x} ({r})");
        peek_state(&image, "cfg");

        // The cfg packet must be a 48-byte BLOB (the live cfg_pkt was
        // hdr 00 00 00 02 | a4 4a 7d bb | 44B session data), not the
        // container itself -- the container rides the envelope slot.
        // Synthesize ours: V2 hdr + our fresh SPIM's tail as the data
        // (this machine's own session material, no Android stands).
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        *pkt.cast::<u32>() = 2; // hdr 00 00 00 02, the live cfg_pkt's
        // The cfg packet's data slice = OUR fresh SPIM's tail. The
        // honest chain resolved the network in node 1; if the network
        // is off (PERUN_NET=0) fall back to the zero tail (the cfg
        // gate still runs; the blob's content is the diff to study).
        let spim_ref: &[u8] = match start.as_ref() {
            Some(s) => &s.spim,
            None => &[],
        };
        let sptail = spim_ref;
        let n = sptail.len().min(44);
        std::ptr::copy_nonoverlapping(
            sptail[sptail.len() - n..].as_ptr(),
            pkt.cast::<u8>().add(4),
            n,
        );
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        std::ptr::write(c.add(0), pkt as u64);
        std::ptr::write(c.add(1), 0x4000_0000_0030); // len 0x30 | flags 4
        std::ptr::write(c.add(3), 0x00226564); // measured
        std::ptr::write(c.add(4), 0x1); // measured
        std::ptr::write(c.add(9), 0x2); // +0x48 measured
        let r3 = guest_call(f, 0xcfe0b46a, ctx as u64, 0, 0);
        println!("[cfg:blob] rc={r3:#x} ({r3})");
        let pk = std::slice::from_raw_parts(pkt.cast::<u8>(), 48);
        println!(
            "[cfg:blob] pkt[0..48] = {}",
            pk[..48]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        peek_state(&image, "cfg_blob");

        // Configuration with a SYNTHESIZED 48-byte packet (the Windows
        // lane's own data, no Android stands): bytes 3/7 carry the fold
        // keys, the tail carries our own I-Client-Time string the live
        // Call 8 had. The question: does a fold-passing packet let the
        // configuration mints run on OUR session objects?
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        *pkt.cast::<u8>().add(3) = 1; // fold key, word 0
        *pkt.cast::<u8>().add(7) = 1; // fold key, word 1
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        std::ptr::write(c.add(0), pkt as u64);
        std::ptr::write(c.add(1), 0x4000_0000_0010); // len 0x10: the words only
        std::ptr::write(c.add(3), 0x00226564); // measured
        std::ptr::write(c.add(4), 0x1); // measured
        std::ptr::write(c.add(9), 0x2); // +0x48 measured
        let r2 = guest_call(f, 0xcfe0b46a, ctx as u64, 0, 0);
        println!("[cfg:synth] rc={r2:#x} ({r2})");
        let pk = std::slice::from_raw_parts(pkt.cast::<u8>(), 48);
        println!(
            "[cfg:synth] pkt[0..48] = {}",
            pk[..48]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        peek_state(&image, "cfg_synth");
    }

    // ── node 3.5: the ANDROID canon's middle calls -- REMOVED from the
    // honest Windows chain (RESEARCH table 24: 0xb23c691e/0xc774d292 are
    // unknownAdiFunction on the Windows build; the Android opcode set
    // does not transfer). Kept under PERUN_LEGACY_ANDROID=1 for
    // instrument comparisons only.
    let legacy_android = std::env::var_os("PERUN_LEGACY_ANDROID").is_some();
    if legacy_android {
        // ── node 3.5: the canon's middle calls, even though they reject ────
        // The live cycle ran SetPath (0xb23c691e) and SetID (0xc774d292)
        // between the two inits and the transform. On the Windows dispatcher
        // both return -45019 (unknownAdiFunction) -- but the measured
        // inter-call dependency (the finish matrix re-keying the OTP's fold)
        // says a call's SIDE EFFECT on the dispatcher cursor can matter more
        // than its return code. Run both, in the live order, and read what
        // the transform behind them does.
        unsafe {
            // The LIVE SetPath (dumprun4): a V2-HEADED packet with a fresh
            // 12-byte nonce, NO time tag at +0x10, a fresh nonce at +0x18,
            // the SELF-pointer at +0x20, and the {len, flags} pair repeated
            // at +0x28 -- the double-nested envelope. Heap/code slots after.
            std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
            *pkt.cast::<u32>() = 2; // V2 header, the live form
            // PERUN_SETPATH_LIVE_PKT=<path>: the live packet's 12-byte tail
            // is the fold's coefficients; urandom tails die at -45018.
            let setpath_live = std::env::var("PERUN_SETPATH_LIVE_PKT")
                .ok()
                .and_then(|f| std::fs::read(f).ok());
            match setpath_live {
                Some(live) => {
                    std::ptr::copy_nonoverlapping(
                        live.as_ptr(),
                        pkt.cast::<u8>(),
                        live.len().min(16),
                    );
                }
                None => {
                    let mut b = [0u8; 12];
                    let mut fh = std::fs::File::open("/dev/urandom").unwrap();
                    use std::io::Read as _;
                    fh.read_exact(&mut b).unwrap();
                    std::ptr::copy_nonoverlapping(b.as_ptr(), pkt.cast::<u8>().add(4), 12);
                }
            }
            std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
            let c = ctx.cast::<u64>();
            std::ptr::write(c.add(0), pkt as u64);
            std::ptr::write(c.add(1), 0x4000_0000_0010);
            std::ptr::write(c.add(2), 0); // +0x10 no tag (the live form)
            // +0x18: the LIVE SetPath carried a NANOSEC TIME TAG here
            // (0xe2720690ff56d95e -- the same shifted-nanosecond class
            // as the init slots), not a random nonce. The previous runs
            // wrote urandom bytes into a TIME slot. Honest fix: a real
            // nanosecond timestamp, both +0x18 and +0x38 (the live had
            // a second time tag at +0x38).
            {
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                std::ptr::write(ctx.cast::<u64>().add(3), now_ns); // +0x18 time tag
            }
            std::ptr::write(c.add(4), ctx as u64); // +0x20 SELF
            std::ptr::write(c.add(5), 0x4000_0000_0010); // +0x28 len|flags again
            // +0x38: the live SetPath's SECOND time tag (0x618974abaf043478
            // in the dump). Ours was zero -- a real nanosecond timestamp.
            {
                let now_ns2 = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                std::ptr::write(c.add(7), now_ns2); // +0x38 the second time tag
            }
            // SetPath's own contract: ctx[+0x80] = A PATH STRING
            // (the live dump shows '/opt/data/adi-mnt/stage/adi-data'
            // as ASCII there -- the working provisioning dir the call
            // SETS; init's +0x68 carried the ROOT '/opt/data/perun/').
            // The honest Windows stand-in: our real adi dir, ALWAYS.
            // PERUN_SP_PATH_UTF16=1 writes it as UTF-16LE (the wchar
            // form Windows APIs take; cvu8io98wun's name says wchar).
            {
                let adi_dir = format!(
                    "{}/adi\0",
                    std::env::var("PERUN_APPDATA").unwrap_or_else(|_| {
                        "/opt/data/home/.perun/appdata/Common/Apple Computer/iTunes".into()
                    })
                );
                let p80 = page(0x1000);
                if std::env::var_os("PERUN_SP_PATH_UTF16").is_some() {
                    let mut wide: Vec<u16> =
                        adi_dir.trim_end_matches('\0').encode_utf16().collect();
                    wide.push(0);
                    for (i, w) in wide.iter().enumerate() {
                        std::ptr::write_volatile((p80 as *mut u16).add(i), *w);
                    }
                } else {
                    put(p80, 0, adi_dir.as_bytes());
                }
                std::ptr::write(c.add(16), p80 as u64); // +0x80 the path string, ALWAYS
            }
            // The dumprun4 SetPath ctx was captured on the ANDROID stand:
            // its VALUES are Android address-space artifacts (the 0x7680_
            // heap prefix is the stand's own region -- the same class of
            // residue as the arg3 stack garbage), NOT Windows semantics.
            // What transfers is the STRUCTURE: +0x38 a time tag,
            // +0x40/+0x48/+0x50/+0x60 code pointers the body may CALL
            // while folding (the term-collapse hypothesis: our zeros mean
            // no calls happen and the raw opcode term rides to the tail),
            // +0x68 a string, +0x80 the provisioning path. PERUN_SP_LIVE_
            // CTX=1 tests that structure with OUR OWN stand-ins.
            if std::env::var_os("PERUN_SP_LIVE_CTX").is_some() {
                std::ptr::write(c.add(6), 0x0000_7fff_0000_0000); // +0x30 our stack-space tag
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                std::ptr::write(c.add(7), now_ns); // +0x38 a real time tag
                std::ptr::write(c.add(8), cb_addr(cb_slot40)); // +0x40 callable code
                std::ptr::write(c.add(9), cb_addr(cb_slot48)); // +0x48
                std::ptr::write(c.add(10), cb_addr(cb_slot50)); // +0x50
                std::ptr::write(c.add(12), cb_addr(cb_slot70)); // +0x60
                std::ptr::write(c.add(13), aux[4] as u64); // +0x68 a string page
                put(aux[4], 0, b"cannot persist ");
                std::ptr::write(c.add(16), pathb as u64); // +0x80 the provisioning path
            }
            // PERUN_SESS_ARM=1: arm the observer table around the
            // SetPath/SetID pair (the gate-45026 station names what the
            // session selectors fold; the transform stations stay cold).
            let sess_arm = std::env::var_os("PERUN_SESS_ARM").is_some();
            if sess_arm {
                stations_arm_mode(image.base() as u64, false, true);
            }
            let r = guest_call(f, 0xb23c691e, ctx as u64, 0, 0);
            println!("[setpath] rc={r:#x} ({r})");
            // The LIVE SetID envelope (decoded from dumprun4): a V2-headed
            // 20-byte packet, the len/flags pair 0x400000014, the arg1
            // buffer {int32 20, int32 20} (the DLL rewrites the second
            // length), and the identity as a 24-char hex string at
            // +0xa0..+0xb8 (the live: '1A7DC030' '8887C2D8' '4700E2EA').
            // Ours: the guest's hex16 plus an 8-hex tail derived from the
            // re-minted tails -- the X-Mme full id's shape.
            std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
            *pkt.cast::<u8>().add(0) = 2; // V2 header, the live form
            // PERUN_SETID_LIVE_PKT=<path>[,<path2>]: the live packets key
            // the selector's fold past -45018 (the wrapper's nonce-tail
            // bytes are fold COEFFICIENTS, not entropy). TWO paths = the
            // live PAIR: call #1 gets the first (the '1a7d' fail packet,
            // whose body still RUNS and contributes to the fold table),
            // call #2 gets the success packet. The live numbering is the
            // measured canon; swapping them answers -45019.
            let setid_live_pair: Vec<Vec<u8>> = std::env::var("PERUN_SETID_LIVE_PKT")
                .map(|spec| {
                    spec.split(',')
                        .filter_map(|f| std::fs::read(f.trim()).ok())
                        .collect()
                })
                .unwrap_or_default();
            match setid_live_pair.first() {
                Some(live) => {
                    std::ptr::copy_nonoverlapping(
                        live.as_ptr(),
                        pkt.cast::<u8>(),
                        live.len().min(16),
                    );
                }
                None => {
                    let mut b = [0u8; 12];
                    let mut fh = std::fs::File::open("/dev/urandom").unwrap();
                    use std::io::Read as _;
                    fh.read_exact(&mut b).unwrap();
                    std::ptr::copy_nonoverlapping(b.as_ptr(), pkt.cast::<u8>().add(4), 12);
                }
            }
            std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
            // The LIVE SetID envelope, slot for slot: the time tag (the
            // same tag<<32 construction as init-2), the wrapper nonce, the
            // SELF-pointer at +0x20, the 'cannot persist' string, the
            // wrapper code pointers, and the size trio -- the validator
            // walks the envelope as a container and empty slots fault it
            // into the session-class rejects.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0x64e8);
            let nonce = {
                let mut b = [0u8; 8];
                let mut fh = std::fs::File::open("/dev/urandom").unwrap();
                use std::io::Read as _;
                fh.read_exact(&mut b).unwrap();
                u64::from_le_bytes(b)
            };
            std::ptr::write(c.add(0), pkt as u64);
            std::ptr::write(c.add(1), 0x4000_0000_0014);
            std::ptr::write(c.add(2), now << 32); // +0x10 tag<<32
            std::ptr::write(c.add(3), nonce); // +0x18
            // The live envelope carried +0x20 = a SECOND envelope
            // (arg1 in the dump points at its own struct; the deep dump
            // derefs it as the outer, and the inner holds the
            // {ptr,len} descriptor family). PERUN_SETID_INNER=1 builds
            // the inner struct as a real page and hands its address.
            let inner: *mut core::ffi::c_void = if std::env::var_os("PERUN_SETID_INNER").is_some() {
                let ip = page(0x100);
                let ci = ip.cast::<u64>();
                std::ptr::write(ci.add(0), pkt as u64);
                std::ptr::write(ci.add(1), 0x0000_0004_0000_0014);
                std::ptr::write(ci.add(2), now << 32);
                std::ptr::write(ci.add(3), nonce);
                std::ptr::write(ci.add(4), ip as u64); // self
                std::ptr::write(ci.add(5), 0xffff_5037);
                std::ptr::write(ci.add(6), aux[1] as u64);
                std::ptr::write(ci.add(7), cb_addr(cb_slot48));
                ip
            } else {
                std::ptr::null_mut()
            };
            let slot20: u64 = if std::env::var_os("PERUN_SETID_INNER").is_some() {
                inner as u64
            } else {
                ctx as u64 + 0x20
            };
            std::ptr::write(c.add(4), slot20); // +0x20 the live inner envelope
            std::ptr::write(c.add(5), 0xffff_5037); // +0x28 the live error marker
            put(aux[1], 0, b"cannot persist \0");
            std::ptr::write(c.add(6), aux[1] as u64); // +0x30
            let dll_code = image.base() as u64 + 0x5afc0;
            std::ptr::write(c.add(7), dll_code); // +0x38 code ptr
            std::ptr::write(c.add(8), 0); // +0x40
            std::ptr::write(c.add(9), 0x70); // +0x48
            std::ptr::write(c.add(10), 0); // +0x50
            std::ptr::write(c.add(11), 0xc2); // +0x58
            std::ptr::write(c.add(12), 0xf4); // +0x60
            std::ptr::write(c.add(13), 0x30); // +0x68
            std::ptr::write(c.add(14), 0); // +0x70
            std::ptr::write(c.add(15), dll_code); // +0x78
            std::ptr::write(c.add(16), dll_code); // +0x80
            std::ptr::write(c.add(17), dll_code); // +0x88
            std::ptr::write(c.add(18), dll_code); // +0x90
            std::ptr::write(c.add(19), dll_code); // +0x98
            put(aux[2], 0, &{
                let mut v = [0u8; 32];
                let idb = std::slice::from_raw_parts(ident.cast::<u8>(), 16);
                for (k, b) in idb.iter().take(16).enumerate() {
                    v[k] = *b;
                }
                // The 8-hex tail: from the re-minted identity's own
                // segments, the X-Mme full-id shape.
                let tail_hex = id
                    .device_id
                    .split('.')
                    .nth(1)
                    .unwrap_or("00000000")
                    .to_uppercase();
                for (k, b) in tail_hex.bytes().take(8).enumerate() {
                    v[16 + k] = b;
                }
                v
            });
            // The live arg1 descriptor read {20, 4} before the call -- the
            // DLL rewrote the second field to 20 on success. The live
            // envelope pointed +0x20 at the descriptor AND at itself
            // through the same slot family; ours keeps the descriptor.
            // The live +0x20 slot pointed at the envelope ITSELF (self);
            // the {20,4} descriptor lived INSIDE the packet's tail, not
            // in a separate slot.
            std::ptr::write(aux[3] as *mut u32, 20);
            std::ptr::write((aux[3] as *mut u32).add(1), 4);
            std::ptr::write(c.add(4), ctx as u64 + 0x20); // +0x20 SELF-PTR
            // The live envelope's identity span: a 24-char hex string at
            // +0xa0..+0xb8 with a NUL after char 24, then one more 8-hex
            // group at +0xb8. Ours: the guest's hex16 (16) + the re-minted
            // identity's first tail (8) = 24 chars, NUL, then the second
            // tail (8) -- the X-Mme full-id's exact 32-hex span.
            // Mode 5 parks the full 32-hex span in aux[2]; the default
            // (modes 3/4) composes hex16 + the device-id's tails.
            let idb: Vec<u8> = if std::env::var("PERUN_GUEST_ID")
                .map(|v| v == "5")
                .unwrap_or(false)
            {
                std::slice::from_raw_parts(aux[2].cast::<u8>(), 32).to_vec()
            } else {
                std::slice::from_raw_parts(ident.cast::<u8>(), 16).to_vec()
            };
            let tail1: [u8; 8] = id
                .device_id
                .split('.')
                .nth(1)
                .unwrap_or("00000000")
                .as_bytes()[..8]
                .try_into()
                .unwrap();
            let tail2: [u8; 8] = id
                .device_id
                .split('.')
                .nth(2)
                .unwrap_or("00000000")
                .as_bytes()[..8]
                .try_into()
                .unwrap();
            // PERUN_SETID_SPAN: 24 (live 24-char span) | 16 (hex16 only).
            // PERUN_SETID_LIVE_SPAN=<path>: the EXACT live 32-byte span
            // ('1A7DC0308887C2D8' + NUL + '470E2EA813C70C1') -- the
            // measured live form, byte for byte.
            let span = std::env::var("PERUN_SETID_SPAN").unwrap_or_else(|_| "24".into());
            let span: usize = span.parse().unwrap_or(24);
            let live_span = std::env::var("PERUN_SETID_LIVE_SPAN")
                .ok()
                .and_then(|f| std::fs::read(f).ok());
            let mut srcs: Vec<u8> = Vec::new();
            if let Some(ls) = live_span {
                // The live span wins: 32 bytes at +0xa0..+0xb8.
                for (k, b) in ls.iter().take(32).enumerate() {
                    std::ptr::write(ctx.cast::<u8>().add(0xa0 + k), *b);
                }
            } else {
                srcs.extend_from_slice(&idb);
                if span >= 24 {
                    srcs.extend_from_slice(&tail1);
                    srcs.push(0);
                    for (k, b) in tail2.iter().enumerate() {
                        std::ptr::write(ctx.cast::<u8>().add(0xb8 + k), *b);
                    }
                } else {
                    srcs.push(0);
                }
                for (k, b) in srcs.iter().enumerate() {
                    std::ptr::write(ctx.cast::<u8>().add(0xa0 + k), *b);
                }
            }
            // The LIVE call carried a CODE POINTER in R9 (arg3 =
            // 0x7680ae906d1c, the wrapper's own frame); ours was NULL.
            // The selector's r9d gate masks the argument -- pass a real
            // guest code address, the DLL's own export.
            let dll_code = image.base() as u64 + 0x5afc0;
            // The LIVE canon called SetID TWICE (dumprun4: the '1a7d'
            // short-string fail first, then the full form's success). The
            // selector's slot container at [rsp+0x340] INHERITS between
            // vdfut calls through the uncleaned frame -- the second call
            // reads what the first wrote. Run it twice, exactly like the
            // live sequence.
            // PERUN_SETID_CB=1: arg3 = a LIGHT host callback (the live
            // call passed the wrapper's own code pointer; our vdfut-as-
            // arg3 was a heavy recursive hazard -- the validator's
            // counter exploded through it).
            let r2 = if std::env::var_os("PERUN_SETID_CB").is_some() {
                guest_call(f, 0xc774d292, ctx as u64, 0, cb_addr(cb_slot48))
            } else {
                guest_call(f, 0xc774d292, ctx as u64, 0, dll_code)
            };
            println!("[setid#1] rc={r2:#x} ({r2})");
            // Rebuild the envelope: the first call rewrote the packet.
            // The live canon's call #2 carried ITS OWN packet (the
            // success one); the pair's second path supplies it.
            std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
            *pkt.cast::<u8>().add(0) = 2;
            match setid_live_pair.get(1) {
                Some(live2) => {
                    std::ptr::copy_nonoverlapping(
                        live2.as_ptr(),
                        pkt.cast::<u8>(),
                        live2.len().min(16),
                    );
                }
                None => {
                    let mut b = [0u8; 12];
                    let mut fh = std::fs::File::open("/dev/urandom").unwrap();
                    use std::io::Read as _;
                    fh.read_exact(&mut b).unwrap();
                    std::ptr::copy_nonoverlapping(b.as_ptr(), pkt.cast::<u8>().add(4), 12);
                }
            }
            std::ptr::write(c.add(0), pkt as u64);
            let r3 = if std::env::var_os("PERUN_SETID_CB").is_some() {
                guest_call(f, 0xc774d292, ctx as u64, 0, cb_addr(cb_slot48))
            } else {
                guest_call(f, 0xc774d292, ctx as u64, 0, dll_code)
            };
            println!("[setid#2] rc={r3:#x} ({r3})");
            if sess_arm {
                // Disarm the session observers: the page re-seal, the byte
                // restores, and the SIGTRAP disposition reset. The transform
                // arming later (if any) reopens what it needs.
                {
                    let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                    let arr = std::ptr::addr_of!(STATION_AT);
                    let mut pages: Vec<u64> = Vec::new();
                    let mut k = 0usize;
                    while k < STATION_N {
                        let at = std::ptr::read_volatile((*arr).as_ptr().add(k));
                        std::ptr::write_volatile(at as *mut u8, STATION_ORIG[k]);
                        let pg = at & !(page as u64 - 1);
                        if !pages.contains(&pg) {
                            pages.push(pg);
                        }
                        k += 1;
                    }
                    for pg in &pages {
                        libc::mprotect(
                            *pg as *mut libc::c_void,
                            page,
                            libc::PROT_READ | libc::PROT_EXEC,
                        );
                    }
                    STATION_N = 0;
                    libc::signal(libc::SIGTRAP, libc::SIG_DFL);
                }
                println!("[stations] session observers disarmed");
            }
        }
    } // legacy_android: the Android middle calls end here

    // ── node 2.6 (legacy): THE GSA re-mint for the ANDROID transform
    // opcode -- not part of the honest Windows chain.
    if legacy_android {
        // Mode 3 (PERUN_GUEST_ID=3): the pipe74 conditions -- the network
        // ran BEFORE init (the session object's buffer only fills with real
        // server data), so read the GUEST'S material at [obj+0x20] -> +0x20
        // and RE-MINT the GSA request under it: a second start under the
        // guest's own id, fresh SPIM onto the page, a second init-2
        // transplant, then transform. Modes 1/2 keep the deferred network.
        let guest_ident: Option<String> = if guest_mode == "live" {
            // Mode "live": the measurement probe -- the WHOLE chain rides
            // the live dump's identity string (the fold table's seed and
            // the live packet's coefficients come from the same session).
            // Purely diagnostic: proves or kills the coherence hypothesis.
            Some("1A7DC0308887C2D8".to_string())
        } else if guest_active {
            let slot_ptr = image.base() as u64 + 0x19ddb0;
            let obj = unsafe { std::ptr::read_volatile(slot_ptr as *const u64) };
            let mid = if obj > 0x1000 {
                unsafe { std::ptr::read_volatile((obj + 0x20) as *const u64) }
            } else {
                0
            };
            if mid > 0x1000 && (mid & 7) == 0 {
                let b = unsafe { std::slice::from_raw_parts((mid + 0x20) as *const u8, 8) };
                Some(b.iter().map(|x| format!("{x:02X}")).collect())
            } else {
                println!("[guest-id] object chain missing; fallback");
                None
            }
        } else {
            None
        };
        println!("[guest-id] material -> {guest_ident:?}");
        if guest_mode == "5" {
            // Mode 5: ONE wrapper-owned identity string everywhere. No
            // material reads, no re-mint: the collect_linux id IS the
            // session's id -- init carried its uuid36 at +0x48, the GSA
            // request rides it, SetID's span and the envelope slots follow.
            // PERUN_IDENT overrides the hex16 (a measurement probe: align
            // the fold table's seed with the live packet's coefficients).
            let segs: Vec<String> = id.device_id.split('.').map(|s| s.to_string()).collect();
            let hex32: String = segs.iter().take(4).cloned().collect::<String>();
            let hex16: String = std::env::var("PERUN_IDENT")
                .unwrap_or_else(|_| segs.iter().take(2).cloned().collect::<String>());
            // ident = hex16 (the envelope slots' live form, no dashes).
            put(ident, 0, hex16.as_bytes());
            put(ident, hex16.len(), b"\0");
            println!("[env] ident={hex16:?}");
            // Park the 32-hex span for the SetID call below.
            put(aux[2], 0, hex32.as_bytes());
            put(aux[2], hex32.len(), b"\0");
            println!("[env] setid-span={hex32:?}");
        }
        if guest_mode == "4" {
            // Mode 4: the material is random per run (measured), so the
            // ONLY way to hand init the identity the guest itself minted
            // is a SECOND init-1 pass inside the same process: read the
            // material, build the full dashed UUID from it (the live
            // Call-1 carried the 36-char form), and re-init with it.
            if let Some(h) = &guest_ident {
                let tail1: String = id
                    .device_id
                    .split('.')
                    .nth(1)
                    .unwrap_or("00000000")
                    .to_uppercase();
                let tail2: String = id
                    .device_id
                    .split('.')
                    .nth(2)
                    .unwrap_or("00000000")
                    .to_uppercase();
                let mut hex32: String = h.clone();
                hex32.push_str(&tail1);
                hex32.push_str(&tail2);
                let uuid36 = format!(
                    "{}-{}-{}-{}-{}",
                    &hex32[0..8],
                    &hex32[8..12],
                    &hex32[12..16],
                    &hex32[16..20],
                    &hex32[20..32]
                );
                println!("[guest-id] mode4 uuid36 = {uuid36:?}");
                // Re-run init-1 with the UUID in +0x48.
                // (set_var not needed: the UUID is written directly below.)
                unsafe {
                    std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
                    *pkt.cast::<u8>().add(3) = 1;
                    *pkt.cast::<u8>().add(7) = 1;
                    std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
                    let c = ctx.cast::<u64>();
                    std::ptr::write(c.add(0), pkt as u64);
                    std::ptr::write(c.add(1), 0x0000_0004_0000_0010);
                    std::ptr::write(c.add(2), 0x0000_7fff_0000_0000);
                    // +0x18: the live Call-1 carried a CONTAINER POINTER
                    // ({0x7680aecd4151, 0xe8b<<32} = {buffer ptr, len<<32} --
                    // the len form matches the DLL's own len-shifted slots).
                    // Our honest stand-in: a container page holding {our ident
                    // buffer, its length <<32}. PERUN_INIT_CONT=0 reverts to
                    // the bare zero page (the old baseline).
                    let cont18 = page(64);
                    {
                        let ident_len = 0x40u64; // the ident page's readable span
                        std::ptr::write_volatile(cont18 as *mut u64, ident as u64);
                        std::ptr::write_volatile(cont18.add(8) as *mut u64, ident_len << 32);
                    }
                    let use_cont = std::env::var("PERUN_INIT_CONT")
                        .map(|v| v != "0")
                        .unwrap_or(true);
                    std::ptr::write(
                        c.add(3),
                        if use_cont {
                            cont18 as u64
                        } else {
                            aux[0] as u64
                        },
                    );
                    std::ptr::write(c.add(4), 0x15);
                    std::ptr::write(c.add(5), cb_addr(cb_slot28));
                    std::ptr::write(c.add(6), cb_addr(cb_slot30));
                    std::ptr::write(c.add(7), 0x0000_7fff_0000_0000);
                    std::ptr::write(c.add(8), cb_addr(cb_slot40));
                    put(aux[4], 0, uuid36.as_bytes());
                    put(aux[4], uuid36.len(), b"\0");
                    std::ptr::write(c.add(9), aux[4] as u64); // +0x48 the full UUID
                    std::ptr::write(c.add(10), 0x40e8_976e_6bde_5309);
                    std::ptr::write(c.add(11), 0xbee2_365f_bf17_664b);
                    std::ptr::write(c.add(14), cb_addr(cb_slot70));
                    std::ptr::write(c.add(18), cb_addr(cb_slot90));
                    std::ptr::write(c.add(21), cb_addr(cb_slota0));
                    std::ptr::write(c.add(22), cb_addr(cb_slotb0));
                    std::ptr::write(c.add(23), cb_addr(cb_slotb8));
                    let a3 = cb_page();
                    let r = guest_call(f, 0xb0eda7af, ctx as u64, 0, a3 as u64);
                    println!("[init#2pass] rc={r:#x} ({r})");
                    peek_slots(&image, "after_reinit");
                    // The material object the second pass minted:
                    let slot_ptr = image.base() as u64 + 0x19ddb0;
                    let obj = std::ptr::read_volatile(slot_ptr as *const u64);
                    let mid = if obj > 0x1000 {
                        std::ptr::read_volatile((obj + 0x20) as *const u64)
                    } else {
                        0
                    };
                    if mid > 0x1000 && (mid & 7) == 0 {
                        let b = std::slice::from_raw_parts((mid + 0x20) as *const u8, 8);
                        let m2: String = b.iter().map(|x| format!("{x:02X}")).collect();
                        println!("[guest-id] material after re-init -> {m2:?}");
                    }
                    // ident buffer follows the guest's minted identity now.
                    let idb = uuid36
                        .chars()
                        .filter(|c| *c != '-')
                        .take(16)
                        .collect::<String>();
                    put(ident, 0, idb.as_bytes());
                    put(ident, idb.len(), b"\0");
                    println!("[env] ident={idb:?}");
                }
                // (remove_var not needed: nothing was set.)
            }
        }
        if guest_mode == "3"
            && let Some(h) = &guest_ident
        {
            id = perun_adi_win32::net::identity_overridden(h);
            println!(
                "[guest-id] re-minted device-id {} lu {}",
                id.device_id, id.lu
            );
            ep = Some(match perun_adi_win32::net::lookup(&id) {
                Ok(e) => e,
                Err(e) => {
                    println!("[net] re-mint lookup failed: {e}");
                    return;
                }
            });
            start = Some(
                match perun_adi_win32::net::start_provisioning(&id, ep.as_ref().unwrap()) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("[net] re-mint start failed: {e}");
                        return;
                    }
                },
            );
            let s = start.as_ref().unwrap();
            println!(
                "[net] (re-mint) spim {} bytes, ptxid {}",
                s.spim.len(),
                s.ptxid
            );
            unsafe {
                std::ptr::copy_nonoverlapping(s.spim.as_ptr(), spimp.cast::<u8>(), s.spim.len());
            }
            // The ident buffer follows the re-minted identity.
            // PERUN_IDENT_FULL=1 probes the FULL X-Mme-Device-Id form
            // (the 36-char dashed UUID shape) in the envelope slots;
            // the live dump carried the 16-char no-dash form.
            let id_hex: String = h.clone();
            let id_put: String = if std::env::var_os("PERUN_IDENT_FULL").is_some() {
                format!(
                    "{id_hex}-{}/{}/{}",
                    id.device_id.split('.').nth(1).unwrap_or("00000000"),
                    id.device_id.split('.').nth(2).unwrap_or("00000000"),
                    id.lu.trim_start_matches('X')
                )
            } else {
                id_hex.clone()
            };
            put(ident, 0, id_put.as_bytes());
            put(ident, id_put.len(), b"\0");
            println!("[env] ident={id_put:?}");
            std::fs::write("/opt/data/il/fresh_spim.bin", &s.spim).expect("save spim");
            println!("[env] fresh spim saved: {} bytes", s.spim.len());
        }
        if guest_active && guest_mode != "3" && guest_mode != "5" {
            id = match &guest_ident {
                Some(h) => perun_adi_win32::net::identity_overridden(h),
                None => perun_adi_win32::net::identity(),
            };
            println!("[guest-id] device-id {} lu {}", id.device_id, id.lu);
        }
        if ep.is_none() {
            ep = Some(match perun_adi_win32::net::lookup(&id) {
                Ok(e) => e,
                Err(e) => {
                    println!("[net] lookup failed: {e}");
                    return;
                }
            });
        }
        if start.is_none() {
            start = Some(
                match perun_adi_win32::net::start_provisioning(&id, ep.as_ref().unwrap()) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("[net] start failed: {e}");
                        return;
                    }
                },
            );
        }
        {
            let start = start.as_ref().unwrap();
            println!(
                "[net] spim {} bytes, ptxid {}",
                start.spim.len(),
                start.ptxid
            );
        }
        // Shadow the Options with the resolved values for the rest of the
        // pipeline: everything downstream reads the minted bindings.
        let ep = match ep {
            Some(e) => e,
            None => return,
        };
        let start = match start {
            Some(s) => s,
            None => return,
        };
        // ── node 3.5/4/4.5 (legacy, continuing node 2.6's block: the
        // transform consumes the minted `start`/`ep` -- the shadowed
        // bindings live only inside that block): the SECOND init (an
        // Android-canon shape), the ANDROID transform opcode
        // 0x716bd86c, and the network finish built for it -- ONE block.
        // ── node 3.5: the SECOND init -- the live Call-5 SHAPE ─────────────
        // The live Call 5 is NOT a copy of Call 1: the layout differs slot
        // by slot. Call 5's carries a TIME TAG at +0x10 (and doubled at
        // +0x18), the identity string WITHOUT dashes at +0x28, the string
        // "adi" at +0x30, "cannot persist " at +0x68, and the sizes at
        // +0x80/+0x90/+0x98/+0xa0. This call is what arms the transform:
        // it hands the guest the identity and the persistence strings the
        // worker's inputs are built from.
        unsafe {
            std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
            *pkt.cast::<u8>().add(3) = 1;
            *pkt.cast::<u8>().add(7) = 1;
            // Zero tail, the same healed form as init-1's packet: the
            // live nonce is session material and reads as FOREIGN data
            // (-45020); the zero tail answers the -45061 family.
            std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
            let c = ctx.cast::<u64>();
            // +0x10: the live time tag (0x618a2474 = the live stand's unix
            // stamp doubled into +0x18). Ours: THIS machine's clock, the
            // same construction.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0x618a_2474);
            std::ptr::write(c.add(2), now << 32); // +0x10 tag<<32
            std::ptr::write(c.add(3), (now << 32) | now); // +0x18 doubled
            std::ptr::write(c.add(4), cb_addr(cb_slot48)); // +0x20 the live had a WRAPPER code ptr here
            std::ptr::write(c.add(5), ident as u64); // +0x28 identity, no dashes
            std::ptr::write(c.add(6), aux[0] as u64); // +0x30 the "adi" string
            std::ptr::write(c.add(8), cb_addr(cb_slot40)); // +0x40 the live code ptr
            std::ptr::write(c.add(9), (0x64e8u64) << 32); // +0x48 the live tag
            std::ptr::write(c.add(13), 0); // +0x68 "cannot persist" ptr
            std::ptr::write(c.add(16), 0x70); // +0x80
            std::ptr::write(c.add(18), 0xc2); // +0x90
            std::ptr::write(c.add(19), 0xf4); // +0x98
            std::ptr::write(c.add(20), 0x30); // +0xa0
            // The envelope's buffer slots that need real strings:
            put(aux[0], 0, b"adi\0");
            put(aux[1], 0, b"cannot persist \0");
            std::ptr::write(c.add(6), aux[0] as u64); // +0x30 "adi"
            std::ptr::write(c.add(13), aux[1] as u64); // +0x68 the persist string
            let c2 = ctx.cast::<u64>();
            std::ptr::write(c2.add(0), pkt as u64);
            std::ptr::write(c2.add(1), 0x0000_0004_0000_0010);
            let r = guest_call(f, 0xb0eda7af, ctx as u64, 0, 0);
            peek_slots(&image, "after_init2");
            println!("[init2] rc={r:#x} ({r})");
            let pk = std::slice::from_raw_parts(pkt.cast::<u8>(), 32);
            println!(
                "[init2] pkt[0..32] = {}",
                pk[..32]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            // The worker's early-exit fork decoded from the ring: it
            // loads the session object through the [0x19ddb0] slot and
            // tests THE OBJECT'S +4 FIELD -- zero takes the early exit
            // (cache check -> ReleaseMutex -> epilogue), nonzero would
            // take the crypto route. PERUN_SESS4 seeds that field right
            // after init-2, the same field the live wrapper's init
            // chain leaves populated.
            if let Some(v) = std::env::var("PERUN_SESS4")
                .ok()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            {
                let slot_ptr = image.base() as u64 + 0x19ddb0;
                let obj = std::ptr::read_volatile(slot_ptr as *const u64);
                if obj > 0x1000 {
                    std::ptr::write_volatile((obj + 4) as *mut u64, v);
                    println!("[sess4] [{obj:#x}+4] = {v:#x} (the fork's field)");
                } else {
                    println!("[sess4] slot 0x19ddb0 = {obj:#x}: no object to seed");
                }
            }
        }

        // ── node 4: transform with the fresh SPIM ───────────────────────────
        let url = b"https://gsa.apple.com/grandslam/MidService/startMachineProvisioning\0";
        // PERUN_TR_FLAGS=1: seed the gate object's session flags before
        // the call -- the measured flag experiment ([0x19dda8]+0x8/+0xc)
        // opened the worker's SUCCESS branch, which then died reading an
        // event handle from a garbage slot. The live wrapper's init chain
        // leaves these set; with the live packet now carrying the real
        // fold coefficients, the flags may complete the route.
        if std::env::var_os("PERUN_TR_FLAGS").is_some() {
            unsafe {
                let slot_ptr = image.base() as u64 + 0x19dda8;
                let obj = std::ptr::read_volatile(slot_ptr as *const u64);
                if obj > 0x1000 {
                    std::ptr::write_volatile((obj + 8) as *mut u64, 1);
                    std::ptr::write_volatile((obj + 0xc) as *mut u64, 1);
                    println!("[tr-flags] [{obj:#x}+8]=1 [+0xc]=1 seeded");
                } else {
                    println!("[tr-flags] slot 0x19dda8 = {obj:#x}: no object");
                }
                let slot_b = image.base() as u64 + 0x19ddb0;
                let objb = std::ptr::read_volatile(slot_b as *const u64);
                if objb > 0x1000 {
                    std::ptr::write_volatile((objb + 4) as *mut u64, 1);
                    println!("[tr-flags] [{objb:#x}+4]=1 seeded (the fork's field)");
                }
            }
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                start.spim.as_ptr(),
                spimp.cast::<u8>(),
                start.spim.len(),
            );
            std::ptr::copy_nonoverlapping(url.as_ptr(), urlp.cast::<u8>(), url.len());
            std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
            // The LIVE Call-6 packet (52 bytes, decoded byte-for-byte from
            // dumprun4): V2 header + the wrapper's nonce-tail that keys the
            // selector's fold. Zero tails died at -45018 before the body
            // ever ran; the live bytes carry the fold coefficients.
            *pkt.cast::<u8>().add(3) = 1;
            *pkt.cast::<u8>().add(7) = 1;
            // PERUN_TR_LIVE_PKT=<path>: replace the synthetic packet with
            // the live 52-byte Call-6 body (decoded from dumprun4) -- the
            // wrapper's nonce-tail keys the selector's fold; a zero tail
            // died at -45018 before the body ever ran.
            if let Some(live) = std::env::var("PERUN_TR_LIVE_PKT")
                .ok()
                .and_then(|f| std::fs::read(f).ok())
            {
                std::ptr::copy_nonoverlapping(live.as_ptr(), pkt.cast::<u8>(), live.len().min(52));
            }
            std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
            let dll_code = image.base() as u64 + 0x5afc0;
            let c = ctx.cast::<u64>();
            std::ptr::write(c.add(0), pkt as u64);
            std::ptr::write(c.add(1), 0x4000_0000_0034);
            std::ptr::write(c.add(3), start.spim.len() as u64); // +0x18
            std::ptr::write(c.add(4), urlp as u64); // +0x20
            std::ptr::write(c.add(5), 2); // +0x28
            std::ptr::write(c.add(6), spimp as u64); // +0x30
            std::ptr::write(c.add(7), start.spim.len() as u64); // +0x38
            std::ptr::write(c.add(8), 4); // +0x40
            std::ptr::write(c.add(9), cb_addr(cb_slot48)); // +0x48 = the live wrapper code slot
            std::ptr::write(c.add(10), 0); // +0x50 = the live INLINE length slot (the worker writes 0x114 here)
            std::ptr::write(c.add(11), start.spim.len() as u64); // +0x58
            std::ptr::write(c.add(12), 0); // +0x60
            std::ptr::write(c.add(13), spimp as u64); // +0x68
            std::ptr::write(c.add(14), 0x1d0); // +0x70
            std::ptr::write(c.add(15), urlp as u64); // +0x78
            // The LIVE after-diff: +0x80 came back as the worker's OWN
            // heap pointer (0x7680aece17c0), not the caller's buffer.
            // The envelope slot is INLINE -- the worker allocates and
            // writes the CPIM address there. Same for +0x50 (the 0x114
            // length). Keep the out page only as a fallback probe.
            std::ptr::write(c.add(16), 0); // +0x80 = the worker's CPIM slot
            // The live Call-6 carried FIVE wrapper code pointers at
            // +0x88..+0xa8 and the identity bytes at +0xb0/+0xb8; ours
            // had neither. Probe: the DLL's own export as a valid guest
            // code address, and our identity string inline.
            std::ptr::write(c.add(17), cb_addr(cb_slot98)); // +0x88 (live wrapper code)
            std::ptr::write(c.add(18), cb_addr(cb_slota0)); // +0x90
            std::ptr::write(c.add(19), cb_addr(cb_slotb0)); // +0x98
            std::ptr::write(c.add(20), cb_addr(cb_slotb8)); // +0xa0
            std::ptr::write(c.add(21), cb_addr(cb_slot70)); // +0xa8
            let idsrc = std::slice::from_raw_parts(ident.cast::<u8>(), 16);
            for (i, b) in idsrc.iter().enumerate() {
                std::ptr::write(ctx.cast::<u8>().add(0xb0 + i), *b);
            }
            // PERUN_HONEST=1: call the transform through the honest
            // wrapper -- the SPIM pointer parked in the caller's own
            // frame slot, the construction the live wrapper used; no
            // external FIX30CTX poke. The library provably never
            // writes the slot itself.
            // PERUN_TR_SEED=1: arm the int3 station circuit around THIS
            // call (the seq-proven five stations; the word seed is the
            // show-and-seed probe -- the before-word print is built in).
            let tr_seed = std::env::var_os("PERUN_TR_SEED").is_some();
            if tr_seed {
                stations_arm(image.base() as u64, true);
            }
            let r = if std::env::var_os("PERUN_HONEST").is_some() {
                perun_honest_wrapper(f, 0x716bd86c, ctx as u64, 0xffff_ffff, spimp as u64)
            } else {
                // The live Call-6 carried arg3 = a CODE POINTER (the
                // wrapper's own callback frame); ours was NULL. Probe:
                // the DLL's own export as a valid guest code address.
                // The live arg3 was the wrapper's frame pointer with
                // low bytes 0xae906d1c; if the fold mixes r9d into E as
                // a TERM, the exact live low-dword matters. PERUN_TR_R9
                // overrides; the default keeps the DLL code address.
                let r9v = std::env::var("PERUN_TR_R9")
                    .ok()
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(dll_code);
                guest_call(f, 0x716bd86c, ctx as u64, 0xffff_ffff, r9v)
            };
            if tr_seed {
                // Disarm before anything else touches the image: restore
                // the original bytes, drop the trap table, reset the
                // SIGTRAP disposition to default.
                {
                    let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                    let mut pages: Vec<u64> = Vec::new();
                    let arr = std::ptr::addr_of!(STATION_AT);
                    let mut k = 0usize;
                    while k < STATION_N {
                        let at = std::ptr::read_volatile((*arr).as_ptr().add(k));
                        std::ptr::write_volatile(at as *mut u8, STATION_ORIG[k]);
                        let pg = at & !(page as u64 - 1);
                        if !pages.contains(&pg) {
                            pages.push(pg);
                        }
                        k += 1;
                    }
                    for pg in &pages {
                        libc::mprotect(
                            *pg as *mut libc::c_void,
                            page,
                            libc::PROT_READ | libc::PROT_EXEC,
                        );
                    }
                    STATION_N = 0;
                    libc::signal(libc::SIGTRAP, libc::SIG_DFL);
                }
                println!("[stations] disarmed");
            }
            println!("[transform] rc={r:#x} ({r})");
            peek_state(&image, "transform");
            // The live contract: the worker writes the CPIM pointer at
            // +0x80, the length 0x114 at +0x50, the session id at +0x60.
            // Read all three slots back -- plus whatever pages the
            // callbacks handed out.
            let cpim_ptr = std::ptr::read_volatile((ctx as u64 + 0x80) as *const u64);
            let cpim_len = std::ptr::read_volatile((ctx as u64 + 0x50) as *const u64);
            let session = std::ptr::read_volatile((ctx as u64 + 0x60) as *const u64);
            println!(
                "[tr-out] ctx[+0x80]={cpim_ptr:#x} ctx[+0x50]={cpim_len:#x} ctx[+0x60]={session:#x}"
            );
            if cpim_ptr > 0x1000 && cpim_len > 0 {
                let n = cpim_len.min(0x400) as usize;
                let bytes = std::slice::from_raw_parts(cpim_ptr as *const u8, n);
                println!(
                    "[tr-out] first {n} bytes: {}",
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                );
                std::fs::write("/opt/data/il/tr_cpim_live.bin", bytes).ok();
                println!("[tr-out] wrote /opt/data/il/tr_cpim_live.bin");
            }
            // The live transform had OLEN=0/OUT=0: the worker's CPIM (if
            // any) would land IN the SPIM buffer (the envelope's only
            // writable data slot, +0x30/+0x68 both point there). Diff the
            // spim page around the SPIM body after the call.
            let sp0 = std::slice::from_raw_parts(spimp.cast::<u8>(), 0x400);
            let nz = sp0.iter().filter(|b| **b != 0).count();
            println!("[spim] nonzero in spim page[0..1024] after transform: {nz}");
            println!(
                "[spim] spim[0..64] = {}",
                sp0[..64]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            // The live Call-6 envelope had OLEN=0/OUT=0 -- the CPIM, if
            // the worker mints one, lands in the SPIM buffer itself. The
            // page is writable; read what changed past the SPIM body.
            let n_after = start.spim.len();
            let tail = std::slice::from_raw_parts(spimp.cast::<u8>().add(n_after), 0x200);
            let tnz = tail.iter().filter(|b| **b != 0).count();
            println!("[spim] nonzero in spim[{n_after}..{n_after}+512]: {tnz}");
            if tnz > 0 {
                std::fs::write("/opt/data/il/spim_tail_after_transform.bin", tail).unwrap();
                println!("[spim] wrote /opt/data/il/spim_tail_after_transform.bin");
            }
        }

        // What did transform write into the packet? The live run rewrote the
        // packet in place with a status header; ours may differ and the diff
        // tells which branch the worker took without needing any sniffers.
        unsafe {
            let pk = std::slice::from_raw_parts(pkt.cast::<u8>(), 64);
            let nz = pk.iter().filter(|b| **b != 0).count();
            println!("[pkt] nonzero in pkt[0..64]: {nz}");
            println!(
                "[pkt] pkt[0..48] = {}",
                pk[..48]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
        }

        // ── node 4.5: the network finish -- close the loop ──────────────────
        // The canon: transform writes the CPIM; the CPIM goes to
        // finishMachineProvisioning; the server answers ptm/tk. Our
        // transform's worker still reads -45001 (no session state), so the
        // out buffer is empty -- send what we have and read the server's
        // own verdict: it validates the CPIM's binding to this machine and
        // answers ec=<code>. That ec is the FIRST outside oracle for the
        // offline chain, and the shape of the answer tells whether the
        // machine-binding lives in the CPIM at all.
        let out_len = unsafe { std::ptr::read(olen.cast::<u64>()) } as usize;
        let mut cpim =
            unsafe { std::slice::from_raw_parts(out.cast::<u8>(), out_len.min(0x1000)) }.to_vec();
        println!("[net] cpim candidate: {out_len} bytes (empty unless the worker minted)");
        // PERUN_FINISH_CPIM=<path>: override the CPIM sent to the server --
        // the probe lane for testing how the server binds the finish
        // request (an external artifact against a fresh ptxid, etc.).
        // The answer's ec is the outside oracle for the whole offline chain.
        if let Some(f) = std::env::var_os("PERUN_FINISH_CPIM") {
            match std::fs::read(f.to_string_lossy().as_ref()) {
                Ok(bytes) => {
                    println!(
                        "[net] PERUN_FINISH_CPIM override: {} bytes from {}",
                        bytes.len(),
                        f.to_string_lossy()
                    );
                    cpim = bytes;
                }
                Err(e) => println!("[net] PERUN_FINISH_CPIM unreadable: {e}"),
            }
        }
        match perun_adi_win32::net::finish_provisioning(&id, &ep, &cpim, &start.ptxid) {
            Ok(fin) => {
                println!(
                    "[net] FINISH ec=0: ptm {} bytes, tk {} bytes, rinfo {}",
                    fin.ptm.len(),
                    fin.tk.len(),
                    fin.rinfo
                );
                std::fs::write("/opt/data/il/ptm.bin", &fin.ptm).expect("ptm");
                std::fs::write("/opt/data/il/tk.bin", &fin.tk).expect("tk");
            }
            Err(e) => println!("[net] finish: {e}"),
        }

        // ── node 5 (legacy, same block: consumes `start`): the ANDROID
        // finish opcode 0x0b2b3196 probe.
        // ── node 5: the finish opcode probe (0x0b2b3196) ────────────────────
        // Its envelope shape is not yet decoded (the live Call-7 dump sits in
        // dumprun4 behind the same ctx-printing the others were). Probe with
        // the transform shape to see the opcode's rejection class: whether it
        // even exists in the Windows dispatcher (not -45019) is the question.
        unsafe {
            let dg = &start.spim;
            // The finish matrix, ungated: the four double-V1 probes (each
            // rc=0x0, each publishing the worker's -45001 verdict in place)
            // are what shifts the dispatcher so the FOLLOWING OTP's dword-1|1
            // packet passes its header fold (pipe17 measured: matrix then
            // init3+transform3 then OTP = 0x0; without the matrix the OTP
            // reads -45018, 5/5). The first measured inter-call dependency.
            {
                for (len, dname, dg_bytes) in [
                    (0x24u64, "z24", None),
                    (0x24, "s24", Some(dg)),
                    (0x34, "z34", None),
                    (0x34, "s34", Some(dg)),
                ] {
                    std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
                    *pkt.cast::<u8>().add(3) = 1;
                    *pkt.cast::<u8>().add(7) = 1;
                    if let Some(d) = dg_bytes {
                        for i in 0..32usize {
                            *pkt.cast::<u8>().add(8 + i) = d[d.len() - 32 + i];
                        }
                    }
                    std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
                    let c = ctx.cast::<u64>();
                    std::ptr::write(c.add(0), pkt as u64);
                    std::ptr::write(c.add(1), 0x4000_0000_0000 | len);
                    std::ptr::write(c.add(3), 0x114);
                    std::ptr::write(c.add(6), spimp as u64);
                    std::ptr::write(c.add(7), start.spim.len() as u64);
                    std::ptr::write(c.add(10), olen as u64);
                    std::ptr::write(c.add(13), spimp as u64);
                    std::ptr::write(c.add(16), out as u64);
                    let r = guest_call(f, 0x0b2b3196, ctx as u64, 0, 0);
                    println!("[finish:{dname}] rc={r:#x} ({r})");
                    let pk = std::slice::from_raw_parts(pkt.cast::<u8>(), 48);
                    println!(
                        "[finish:{dname}] pkt[0..48] = {}",
                        pk[..48]
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    );
                    peek_state(&image, &format!("finish_{dname}"));
                }
            }
        }
    } // legacy_android: the finish-opcode probe ends here

    // ── node 6 (the honest Windows chain's tail): OTP (0x3e58e7f9) --
    // a RECOGNISED Windows opcode (RESEARCH table 24).
    // OTP, minimal null-session envelope: the fold runs on dword-1 words
    // (pkt_pass2's shape) and returns 0 with the packet untouched -- the
    // canon's verdict channel reports nothing to publish. The live-shaped
    // 24-slot envelope (nested envelopes, writer buffers, the 60/487/28/24/16
    // sizes) is decoded and wired, but on a null session the dispatcher
    // rejects it at the header fold (-45018): richer slots demand the live
    // session state. It is kept in the file's history for the day the flags
    // exist; the minimal form is what a null session can run.
    unsafe {
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        *pkt.cast::<u8>().add(3) = 1; // byte 3 = 1: word 0's fold key
        *pkt.cast::<u8>().add(7) = 1; // byte 7 = 1: word 1's fold key
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        let c = ctx.cast::<u64>();
        std::ptr::write(c.add(0), pkt as u64);
        std::ptr::write(c.add(1), 0x4000_0000_0010); // len 0x10 | flags 4
        std::ptr::write(c.add(9), aux[5] as u64); // +0x48 (the live had a buffer)
        let r = guest_call(f, 0x3e58e7f9, ctx as u64, 0, 0);
        println!("[otp] rc={r:#x} ({r})");
        let pk = std::slice::from_raw_parts(pkt.cast::<u8>(), 32);
        println!(
            "[otp] pkt[0..32] = {}",
            pk[..32]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        peek_state(&image, "otp");
    }

    // ── the gate-object readout: what did each opcode leave behind? ──────
    {
        let base = image.base() as u64;
        for rva in (0x19dda0u64..=0x19ddb0u64).step_by(8) {
            let slot = unsafe { std::ptr::read_volatile((base + rva) as *const u64) };
            println!("[slot] RVA {rva:#x} = {slot:#x}");
            if slot > 0x1000 && slot < 0x8000_0000_0000 {
                let mut line = String::new();
                for off in (0u64..0x40).step_by(8) {
                    let v = unsafe { std::ptr::read_volatile((slot + off) as *const u64) };
                    line.push_str(&format!(" {v:016x}"));
                }
                println!("[obj]  +0x00..0x38 ={line}");
            }
        }
    }

    // ── the verdict: did the worker write a CPIM? ────────────────────────
    let olen_v = unsafe { std::ptr::read(olen.cast::<u64>()) };
    println!("[out] olen={olen_v:#x}");
    let out_b = unsafe { std::slice::from_raw_parts(out.cast::<u8>(), 0x120) };
    let nz = out_b.iter().filter(|b| **b != 0).count();
    println!("[out] nonzero in out[0..288]: {nz}");
    if nz > 0 {
        std::fs::write(
            "/opt/data/il/pipeline_cpim.bin",
            &out_b[..olen_v.min(0x120) as usize],
        )
        .unwrap();
        println!(
            "[out] wrote /opt/data/il/pipeline_cpim.bin ({} bytes)",
            olen_v
        );
    }
}
