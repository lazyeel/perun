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
static ZONE_REARM: AtomicBool = AtomicBool::new(false);
static RESEAL: AtomicBool = AtomicBool::new(false);
static HIT_N: AtomicU64 = AtomicU64::new(0);

extern "C" fn on_segv(_sig: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    unsafe {
        let addr = (*info).si_addr() as u64;
        let base = WATCH_BASE.load(Ordering::SeqCst);
        let len = WATCH_LEN.load(Ordering::SeqCst);
        if len == 0 || addr < base || addr >= base.wrapping_add(len) {
            // Not our page: reinstall the default handler and re-raise so
            // the process dies with the real crash context.
            libc::signal(libc::SIGSEGV, libc::SIG_DFL);
            return;
        }
        let uc = &mut *(ctx as *mut libc::ucontext_t);
        let rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
        let off = addr - base;
        let n = HIT_N.fetch_add(1, Ordering::SeqCst);
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
            for off in [0x88, 0xe8, 0x140, 0x310, 0x3c8, 0x4a0, 0x500, 0x508] {
                let v = std::ptr::read_volatile((rsp_v + off) as *const u64);
                msg.push_str(&format!("  [rsp+{off:#x}]={v:#x}\n"));
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
            // One-shot probe: restore, rewind, single-step, disarm.
            // (Re-arming loops with the watch-page TF dance; the entry
            // registers are what we came for.)
            std::ptr::write_volatile(zat as *mut u8, ZONE_PROBE_ORIG.load(Ordering::SeqCst) as u8);
            ZONE_PROBE_AT.store(0, Ordering::SeqCst);
            uc.uc_mcontext.gregs[libc::REG_RIP as usize] = zat as i64;
            let flags = uc.uc_mcontext.gregs[libc::REG_EFL as usize] as u64;
            uc.uc_mcontext.gregs[libc::REG_EFL as usize] = (flags | 0x100) as i64;
            RESEAL.store(true, Ordering::SeqCst);
            return;
        }
        // The single-step after a probe hit: put the 0xcc back.
        if ZONE_REARM.swap(false, Ordering::SeqCst) {
            let zat2 = ZONE_PROBE_AT.load(Ordering::SeqCst);
            std::ptr::write_volatile(zat2 as *mut u8, 0xcc);
            let flags = uc.uc_mcontext.gregs[libc::REG_EFL as usize] as u64;
            uc.uc_mcontext.gregs[libc::REG_EFL as usize] = (flags & !0x100) as i64;
            RESEAL.store(true, Ordering::SeqCst);
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
    let _ = unsafe { cvu(path_page as u64, 0, 0, 0) };
    eprintln!("[ww] cvu rc noted");

    // The honest init (V1): rc=0, the 'not provisioned' contract.
    let init_ctx = region(0x1_0000);
    let init_pkt = region(0x1000);
    unsafe {
        std::ptr::write_volatile(init_pkt.cast::<u32>(), 1);
        let c = init_ctx.cast::<u64>();
        std::ptr::write_volatile(c, init_pkt as u64);
        std::ptr::write_volatile(c.add(1), 0x10);
        let r = op(0xb0eda7af, init_ctx as u64, 0, 0);
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

    // Arm the write-only watch over the packet page and call.
    WATCH_BASE.store(pkt as u64, Ordering::SeqCst);
    WATCH_LEN.store(0x1000, Ordering::SeqCst);
    install_handlers();
    unsafe {
        libc::mprotect(pkt as *mut libc::c_void, 0x1000, libc::PROT_READ);
    }
    let r = unsafe { op(0xcfe0b46a, ctx as u64, 0, 0) };
    eprintln!("[ww] cfg rc={r:#x} ({r})");
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
