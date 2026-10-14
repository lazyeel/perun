// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! A minimal CoreFP (Keybag.dll) probe: can perun load the wrapper
//! DLL at all? DllMain is the question -- if it initializes under our
//! shim table, the ADI branch of the wrapper is reachable without
//! reading a single line of its obfuscated code.

use perun_core::loader::{DLL_PROCESS_ATTACH, Image};
use perun_shims::table::ShimTable;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/opt/data/adi-pe/extracted/itunes_extracted/iTunes/CoreFP.dll".into());
    let bytes = std::fs::read(&path).expect("read image");
    let mut table = ShimTable::collect();
    let image = Image::load(&bytes, &mut table).expect("load image");
    let _teb = unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
    let dll_main = unsafe { image.entry_dll_main() }.expect("entry");
    let r = unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) };
    println!("[corefp] DllMain({DLL_PROCESS_ATTACH}) -> {r}");
    for name in [
        "WIn9UJ86JKdV4dM",
        "X46O5IeS",
        "YlCJ3lg",
        "dku592fbFAj",
        "fdjkDSAFjklaf2s",
        "lxpgvVMLd0S7uRl",
    ] {
        match image.get_export_by_name(name) {
            Some(p) => println!("[corefp] export {name} @ {:#x}", p as usize),
            None => println!("[corefp] export {name} MISSING"),
        }
    }
    // Invoke one export with zero args (PERUN_COREFP_CALL names it) and
    // read the verdict: the ADI branch of the wrapper either asks the
    // host for CoreADI64 (LoadLibraryA fires, visible in the trace) or
    // answers a code of its own.
    // Load CoreADI64 TOO and register its exports under the module
    // handle our LoadLibraryA shim hands out for that name, so when
    // CoreFP asks GetProcAddress("vdfut768ig") it gets the real
    // dispatcher of the ADI lane -- the two guests in one process.
    if std::env::var_os("PERUN_COREFP_ADI").is_some() {
        let adi_path = "/opt/data/adi-pe/extracted/itunes_extracted/iTunes/CoreADI64.dll";
        let adi_bytes = std::fs::read(adi_path).expect("read adi");
        let mut table2 = ShimTable::collect();
        let adi = Image::load(&adi_bytes, &mut table2).expect("load adi");
        let adi_base = adi.base();
        let dll_main_adi = unsafe { adi.entry_dll_main() }.expect("adi entry");
        assert!(unsafe { dll_main_adi(adi_base, DLL_PROCESS_ATTACH, std::ptr::null_mut()) } != 0);
        let mut h: u64 = 0xAD00_0001;
        for b in b"CoreADI64.dll" {
            h = h.wrapping_mul(31).wrapping_add(*b as u64);
        }
        for exp in ["vdfut768ig", "cvu8io98wun"] {
            if let Some(ptr) = adi.get_export_by_name(exp) {
                perun_shims::runtime_state::register_export(h as usize, exp, ptr.cast());
            }
        }
        println!(
            "[corefp] CoreADI64 loaded @{:#x}; exports registered under {h:#x}",
            adi_base as usize
        );
        // The spy: GetProcAddress('vdfut768ig') now answers the
        // logging trampoline, which dumps args/ctx/packet before and
        // after and forwards to the real dispatcher. CoreFP's first
        // ADI call becomes a complete envelope specimen.
        if let Some(ptr) = adi.get_export_by_name("vdfut768ig") {
            perun_shims::runtime_state::install_spy("vdfut768ig", ptr as *mut core::ffi::c_void);
            println!("[corefp] spy installed on vdfut768ig");
        }
    }
    if let Ok(name) = std::env::var("PERUN_COREFP_CALL") {
        let p = image.get_export_by_name(&name).expect("export");
        let f: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 =
            unsafe { std::mem::transmute(p) };
        // Zero args first; PERUN_COREFP_BUF=1 re-runs the call with
        // four fresh writable pages -- the crash-on-zero exports want
        // buffers, and a buffer-backed call answers a code instead.
        let r = unsafe { f(0, 0, 0, 0) };
        println!("[corefp] call {name}(0,0,0,0) -> {r:#x} ({r})");
        // PERUN_COREFP_ARGS=a,b,c,d: FILE paths loaded into the four
        // call buffers (comma list; empty entries stay zero pages).
        // This is the scalable input probe: the wrapper's services
        // are context-driven, and this feeds real guest data (the
        // ident string, a fresh SPIM, a V1 packet) as the argument
        // slots the DIALOG rounds left as blank pages.
        if let Ok(spec) = std::env::var("PERUN_COREFP_ARGS") {
            fn page() -> u64 {
                unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        0x1_0000,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    ) as u64
                }
            }
            let ab: [u64; 4] = [page(), page(), page(), page()];
            for (slot, path) in spec.split(',').enumerate().take(4) {
                if let Ok(data) = std::fs::read(path.trim()) {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            data.as_ptr(),
                            ab[slot] as *mut u8,
                            data.len().min(0x1_0000),
                        );
                    };
                    println!("[corefp] args[{slot}] <- {path} ({} bytes)", data.len());
                }
            }
            let r = unsafe { f(ab[0], ab[1], ab[2], ab[3]) };
            println!("[corefp] args call -> {r:#x} ({r}) | bufs after:");
            for (slot, b) in ab.iter().enumerate() {
                let pk = unsafe { std::slice::from_raw_parts(*b as *const u8, 64) };
                let nz = pk.iter().filter(|x| **x != 0).count();
                println!(
                    "[corefp] abuf{slot}[0..64] = {} (nz {nz})",
                    pk[..64]
                        .iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<String>()
                );
            }
        }
        if std::env::var_os("PERUN_COREFP_BUF").is_some() {
            // Real writable pages, not magic numbers: the guest writes
            // its OUTPUT PACKET into the buffer the envelope names
            // (measured: mov [rcx], rax with rax = len|flags), so an
            // unmapped magic value is a guaranteed SEGV.
            fn page() -> u64 {
                unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        0x1_0000,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    ) as u64
                }
            }
            let bufs: [u64; 4] = [page(), page(), page(), page()];
            let r2 = unsafe { f(bufs[0], bufs[1], bufs[2], bufs[3]) };
            println!(
                "[corefp] call {name}({:#x},{:#x},{:#x},{:#x}) -> {r2:#x} ({r2})",
                bufs[0], bufs[1], bufs[2], bufs[3]
            );
            // The guest wrote an INPUT-ENVELOPE HEADER into buf1
            // ({hdr=2, flags=0xe, len=0x2e}): it asks for a 46-byte
            // packet of type 2. Feed it ours -- the fold keys and a
            // fresh SPIM tail -- and call again on the same buffers.
            if std::env::var_os("PERUN_COREFP_FEED").is_some() {
                let p1 = bufs[1] as *mut u8;
                unsafe {
                    let len = std::ptr::read(p1.add(8) as *const u32) as usize;
                    println!("[corefp] feeding a {len}-byte packet (hdr 2)");
                    for off in 0..len {
                        let v = match off {
                            3 | 7 => 1u8, // the fold keys
                            _ => 0,
                        };
                        std::ptr::write(p1.add(12 + off), v);
                    }
                }
                let r3 = unsafe { f(bufs[0], bufs[1], bufs[2], bufs[3]) };
                println!("[corefp] fed call -> {r3:#x} ({r3})");
                // The measured sequence: the zero-arg call flips an
                // internal switch (answers -24487), the FIRST buffered
                // call writes the {2|0xe|0x2e} envelope, and a SECOND
                // buffered call is where the protocol continues. Run
                // it: three calls, reading the buffers between each.
                {
                    let r3 = unsafe { f(bufs[0], bufs[1], bufs[2], bufs[3]) };
                    println!("[corefp] 2nd buffered call -> {r3:#x} ({r3})");
                    let pk = unsafe { std::slice::from_raw_parts(bufs[1] as *const u8, 64) };
                    println!(
                        "[corefp] buf1 after 2nd = {}",
                        pk[..64]
                            .iter()
                            .map(|x| format!("{x:02x}"))
                            .collect::<String>()
                    );
                }
                for (i, b) in bufs.iter().enumerate() {
                    let pk = unsafe { std::slice::from_raw_parts(*b as *const u8, 128) };
                    let nz = pk.iter().filter(|x| **x != 0).count();
                    println!(
                        "[corefp] buf{i}[0..128] = {} (nz {nz})",
                        pk[..128]
                            .iter()
                            .map(|x| format!("{x:02x}"))
                            .collect::<String>()
                    );
                }
            }
            // The measured sequence: the zero-arg call flips an
            // internal switch (answers -24487), the FIRST buffered
            // call writes the {2|0xe|0x2e} envelope, and a SECOND
            // buffered call is where the protocol continues. Run
            // it: three calls, reading the buffers between each.
            {
                let r3 = unsafe { f(bufs[0], bufs[1], bufs[2], bufs[3]) };
                println!("[corefp] 2nd buffered call -> {r3:#x} ({r3})");
                let pk = unsafe { std::slice::from_raw_parts(bufs[1] as *const u8, 64) };
                println!(
                    "[corefp] buf1 after 2nd = {}",
                    pk[..64]
                        .iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<String>()
                );
            }
            for (i, b) in bufs.iter().enumerate() {
                let pk = unsafe { std::slice::from_raw_parts(*b as *const u8, 64) };
                let nz = pk.iter().filter(|x| **x != 0).count();
                println!(
                    "[corefp] buf{i}[0..64] = {} (nz {nz})",
                    pk[..64]
                        .iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<String>()
                );
            }
            // PERUN_COREFP_DIALOG=1: the machine's buf1 dialogue.
            // Round 3: feed the LIVE transform packet's 48-byte tail
            // (the fold coefficients) into the packet body and call;
            // round 4: the live SetID#2 packet; each round prints the
            // machine's reply. The buf1 channel is the protocol.
            if std::env::var_os("PERUN_COREFP_DIALOG").is_some() {
                let rounds: &[(&str, &str)] = &[
                    ("tr52", "/opt/data/il/live_tr_pkt52.bin"),
                    ("setid2", "/opt/data/il/live_setid_pkt2.bin"),
                    ("setid1", "/opt/data/il/live_setid_pkt1.bin"),
                    ("setpath", "/opt/data/il/live_setpath_pkt16.bin"),
                ];
                for (tag, path) in rounds {
                    if let Ok(live) = std::fs::read(path) {
                        let p1 = bufs[1] as *mut u8;
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                live.as_ptr(),
                                p1,
                                live.len().min(0x10000),
                            );
                        }
                        let r = unsafe { f(bufs[0], bufs[1], bufs[2], bufs[3]) };
                        let pk = unsafe { std::slice::from_raw_parts(bufs[1] as *const u8, 64) };
                        println!(
                            "[corefp] dialog {tag} -> {r:#x} ({r}) | buf1 = {}",
                            pk[..64]
                                .iter()
                                .map(|x| format!("{x:02x}"))
                                .collect::<String>()
                        );
                    }
                }
                // PERUN_COREFP_ROUND2=<export>: after the fdjk
                // dialogue, a SECOND export with the SAME buffers --
                // the wrapper's other services consume what fdjk
                // queued; the spy watches for the vdfut pull.
                if let Ok(second) = std::env::var("PERUN_COREFP_ROUND2")
                    && let Some(p2) = image.get_export_by_name(&second)
                {
                    let f2: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 =
                        unsafe { std::mem::transmute(p2) };
                    for (tag, path) in rounds {
                        if let Ok(live) = std::fs::read(path) {
                            let p1 = bufs[1] as *mut u8;
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    live.as_ptr(),
                                    p1,
                                    live.len().min(0x10000),
                                );
                            }
                            let r = unsafe { f2(bufs[0], bufs[1], bufs[2], bufs[3]) };
                            let pk =
                                unsafe { std::slice::from_raw_parts(bufs[1] as *const u8, 64) };
                            println!(
                                "[corefp] round2 {second} {tag} -> {r:#x} ({r}) | buf1 = {}",
                                pk[..64]
                                    .iter()
                                    .map(|x| format!("{x:02x}"))
                                    .collect::<String>()
                            );
                        }
                    }
                }
            }
        }
    }
}
