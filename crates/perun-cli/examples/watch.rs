// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! watch: mprotect watchpoint tracing for the ADI dispatcher (skeleton).

use perun_core::loader::{DLL_PROCESS_ATTACH, Image};
use perun_shims::table::ShimTable;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

type ExportFn = unsafe extern "win64" fn(u64, u64, u64, u64) -> u64;

static GOT_HIT: AtomicBool = AtomicBool::new(false);
static HIT_RIP: AtomicU64 = AtomicU64::new(0);
static HIT_ADDR: AtomicU64 = AtomicU64::new(0);
static GREGS: [AtomicU64; 23] = [const { AtomicU64::new(0) }; 23];
static WATCH_BASE: AtomicU64 = AtomicU64::new(0);
static WATCH_LEN: AtomicU64 = AtomicU64::new(0);

/// Classify a fault: Some(offset) when addr lands in [base, base+len).
fn page_hit(addr: u64, base: u64, len: u64) -> Option<u64> {
    if len > 0 && addr >= base && addr < base.wrapping_add(len) {
        Some(addr - base)
    } else {
        None
    }
}

extern "C" fn on_segv(_sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    unsafe {
        let addr = (*info).si_addr() as u64;
        let base = WATCH_BASE.load(Ordering::SeqCst);
        let len = WATCH_LEN.load(Ordering::SeqCst);
        if page_hit(addr, base, len).is_some() && !GOT_HIT.swap(true, Ordering::SeqCst) {
            #[cfg(target_arch = "x86_64")]
            {
                let uc = &*(_ctx as *const libc::ucontext_t);
                let rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
                HIT_RIP.store(rip, Ordering::SeqCst);
                HIT_ADDR.store(addr, Ordering::SeqCst);
                for (i, g) in GREGS.iter().enumerate() {
                    g.store(uc.uc_mcontext.gregs[i] as u64, Ordering::SeqCst);
                }
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                HIT_RIP.store(0, Ordering::SeqCst);
                HIT_ADDR.store(addr, Ordering::SeqCst);
            }
            libc::mprotect(
                base as *mut libc::c_void,
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
            );
        }
    }
}

fn install_handler() {
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        // fn-item -> integer is unspecified; go through a data pointer, the same
        // cast the Mach-O shim table uses.
        act.sa_sigaction = on_segv as *const () as usize;
        act.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&raw mut act.sa_mask);
        libc::sigaction(libc::SIGSEGV, &raw const act, std::ptr::null_mut());
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

fn w64(s: &mut [u8], off: usize, v: u64) {
    s[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn usage() -> ! {
    eprintln!("usage: watch <dll> <envelope|inner>");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 || (args[1] != "envelope" && args[1] != "inner") {
        usage();
    }
    let bytes = std::fs::read(&args[0]).unwrap_or_else(|e| {
        eprintln!("read: {e}");
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

    // B-model regions: inner struct + envelope struct.
    let rinner = region(0x1000);
    let renv = region(0x1000);
    unsafe {
        let sin = std::slice::from_raw_parts_mut(rinner, 0x1000);
        w64(sin, 0x00, 0xFFFFFFFFFFFFFFFEu64);
        let se = std::slice::from_raw_parts_mut(renv, 0x1000);
        w64(se, 0x00, rinner as u64);
        w64(se, 0x08, 347);
        w64(se, 0x10, 4096);
        w64(se, 0x18, 0);
    }
    let (wp, wlen) = if args[1] == "envelope" {
        (renv as u64, 0x1000u64)
    } else {
        (rinner as u64, 0x1000u64)
    };
    WATCH_BASE.store(wp, Ordering::SeqCst);
    WATCH_LEN.store(wlen, Ordering::SeqCst);
    install_handler();
    unsafe {
        libc::mprotect(wp as *mut libc::c_void, wlen as usize, libc::PROT_NONE);
    }
    let r = unsafe { op(renv as u64, renv as u64, 0, 0) };
    println!("[watch] returned {r:#x} ({r})");
    if GOT_HIT.load(Ordering::SeqCst) {
        let rip = HIT_RIP.load(Ordering::SeqCst);
        let addr = HIT_ADDR.load(Ordering::SeqCst);
        println!(
            "[watch] FIRST READ rip={rip:#x} (rva={:#x}) addr={addr:#x} (page+{:#x})",
            rip.wrapping_sub(0x7c800000),
            addr.wrapping_sub(wp),
        );
        let mut g = String::new();
        for (i, r) in GREGS.iter().enumerate() {
            g.push_str(&format!("{i}={:#x} ", r.load(Ordering::SeqCst)));
        }
        println!("[watch] gregs {g}");
        println!("[watch] libc::REG_RIP={}", libc::REG_RIP);
    } else {
        println!("[watch] no watch hit (page never read?)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_inside() {
        assert_eq!(page_hit(0x1010, 0x1000, 0x1000), Some(0x10));
    }

    #[test]
    fn hit_outside() {
        assert_eq!(page_hit(0x500, 0x1000, 0x1000), None);
        assert_eq!(page_hit(0x2000, 0x1000, 0x1000), None);
        assert_eq!(page_hit(0x1000, 0x1000, 0), None);
    }
}
