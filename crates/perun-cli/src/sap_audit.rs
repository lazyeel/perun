// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! SAP branch audit under the rdtsc census (research only; needs the
//! `rdtsc-census` feature).
//!
//! The CLI runs one SAP cycle per process, so blocks the command line
//! cannot reach — signing on a half-built context, repeating a context, a
//! full 50-cycle soak in one address space — need an in-process driver.
//! This binary reuses the same modules as `main.rs` and drives
//! [`sap::SapRuntime`] directly, reporting the census union at the end so a
//! newly reached rdtsc site is impossible to miss.
//!
//! The whole module tree is compiled in because SapRuntime lives in a module
//! of a binary crate; most of it is unused from this driver, so the dead-code
//! lints are silenced here rather than sprayed over the shared modules.
#![allow(dead_code)]

mod fetcher;
mod sap;
mod scaffold;
mod store;

use store::primary_mac;

fn snapshot(tag: &str) {
    let (corefp, ck, _) = census();
    let shipped: std::collections::BTreeSet<u32> =
        perun_core::rdtsc_sites::COMMERCEKIT_RDTSC_PATCHES
            .iter()
            .map(|(o, _)| *o)
            .collect();
    let mut extra: Vec<u32> = ck
        .iter()
        .filter_map(|x| u32::from_str_radix(x.trim_start_matches("0x"), 16).ok())
        .filter(|o| !shipped.contains(o))
        .collect();
    extra.sort_unstable();
    println!(
        "  [after {tag}] CoreFP={} CommerceKit={} unpatched={} {extra:?}",
        corefp.len(),
        ck.len(),
        extra.len()
    );
}

fn census() -> (Vec<String>, Vec<String>, usize) {
    let fired = perun_core::census::fired();
    let total = perun_core::census::total();
    let mut corefp = Vec::new();
    let mut ck = Vec::new();
    for (img, off) in fired {
        if img == "CoreFP" {
            corefp.push(format!("{off:#x}"));
        } else {
            ck.push(format!("{off:#x}"));
        }
    }
    (corefp, ck, total)
}

/// Faithful bodies for the two MZFinance requests the store lane signs.
fn real_plists() -> Vec<(&'static str, Vec<u8>)> {
    use store::plist::{Plist, to_xml};
    let mut login = Plist::dict();
    login.set("appleId", Plist::string("auditor@example.com"));
    login.set("attempt", Plist::string("4"));
    login.set("guid", Plist::string("AABBCCDDEEFF"));
    login.set("passwordToken", Plist::string("ZmFrZS10b2tlbi12YWx1ZQ=="));
    login.set("rmp", Plist::string("0"));
    login.set("why", Plist::string("signIn"));
    let mut buy = Plist::dict();
    buy.set("salableAdamId", Plist::Integer(686449807));
    buy.set("pricingParameters", Plist::string("STDQ"));
    buy.set("guid", Plist::string("AABBCCDDEEFF"));
    buy.set("passwordToken", Plist::string("ZmFrZS10b2tlbi12YWx1ZQ=="));
    vec![
        ("authenticate plist", to_xml(&login).into_bytes()),
        ("buyProduct plist", to_xml(&buy).into_bytes()),
    ]
}

fn block_a(rt: &mut sap::SapRuntime) {
    println!("== block A: live StoreKit payloads ==");
    for (label, body) in real_plists() {
        match rt.sign(&body) {
            Ok(sig) => println!("  {label}: {} bytes, rc 0", sig.len()),
            Err(e) => println!("  {label}: ERROR {e}"),
        }
    }
    // A DAAP list-purchases body is not a SAP payload: the store lane signs
    // only signSapSetup, so this is exercised as an opaque sign input.
    let daap: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    match rt.sign(&daap) {
        Ok(sig) => println!("  DAAP-shaped blob: {} bytes, rc 0", sig.len()),
        Err(e) => println!("  DAAP-shaped blob: ERROR {e}"),
    }
    match rt.sign(&[]) {
        Ok(sig) => println!("  empty payload: {} bytes, rc 0", sig.len()),
        Err(e) => println!("  empty payload: ERROR {e}"),
    }
}

/// Block B: the failure branches, each on its own fresh runtime so one
/// poisoned context cannot mask the next.
fn block_b(assets_dir: &str, mac: [u8; 6]) {
    println!("== block B: error paths ==");
    // B1: a truncated / corrupt setup.crt must be rejected, not hang.
    for (label, cert) in [
        ("truncated cert", vec![0x30u8; 32]),
        ("garbage cert", vec![0xDEu8; 512]),
    ] {
        match sap::SapAssets::load_dir(assets_dir).and_then(|a| sap::SapRuntime::new(&a)) {
            Ok(mut rt) => match rt.setup_with_cert(mac, cert) {
                Ok(()) => println!("  B1 {label}: UNEXPECTEDLY ACCEPTED"),
                Err(e) => println!("  B1 {label}: rejected cleanly ({})", first(&e)),
            },
            Err(e) => println!("  B1 {label}: load failed ({})", first(&e)),
        }
    }
    // B3: sign on a context that only completed round 1, and on a runtime
    // that was never initialised at all.
    if let Ok(a) = sap::SapAssets::load_dir(assets_dir)
        && let Ok(mut rt) = sap::SapRuntime::new(&a)
    {
        match rt.sign(b"partial-context") {
            Ok(sig) => println!("  B3 sign before setup: {} bytes (context=0?)", sig.len()),
            Err(e) => println!("  B3 sign before setup: rejected ({})", first(&e)),
        }
    }
}

/// Classify a soak failure: the transport error already carries the
/// HTTP status, so this names the server side rather than the guest.
fn classify(e: &str) -> String {
    let head: String = e.chars().take(160).collect();
    if let Some(p) = head.find("HTTP ") {
        let rest = &head[p + 5..];
        let code: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        return format!("SERVER http {code} — {}", first(e));
    }
    format!("GUEST/LOCAL — {}", first(e))
}

fn first(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(90).collect()
}

/// Block C: soak. 500 signs on one context, then 50 full cycles in this
/// process, so a site reachable only on a later cycle shows up in the union.
fn block_c(assets_dir: &str, mac: [u8; 6]) {
    println!("== block C: soak ==");
    let Ok(assets) = sap::SapAssets::load_dir(assets_dir) else {
        println!("  C: assets unavailable");
        return;
    };
    let cert =
        match fetcher::ensure_cert().and_then(|p| std::fs::read(p).map_err(|e| e.to_string())) {
            Ok(c) => c,
            Err(e) => {
                println!("  C: cert unavailable ({})", first(&e));
                return;
            }
        };
    let mut ok = 0usize;
    let mut bad = 0usize;
    for i in 0..50 {
        let Ok(mut rt) = sap::SapRuntime::new(&assets) else {
            bad += 1;
            continue;
        };
        let r = rt
            .init(mac)
            .and_then(|_| rt.setup_with_cert(mac, cert.clone()))
            .and_then(|_| rt.sign(b"soak payload"));
        match r {
            Ok(sig) if sig.len() == 501 => ok += 1,
            Ok(sig) => {
                bad += 1;
                println!("    C cycle {i}: short signature {} bytes", sig.len());
            }
            Err(e) => {
                bad += 1;
                println!("    C cycle {i}: {}", classify(&e));
            }
        }
        if i == 0 {
            for n in 0..500 {
                if rt.sign(b"repeat").map(|s| s.len() == 501).unwrap_or(false) {
                    ok += 1;
                } else {
                    bad += 1;
                }
                let _ = n;
            }
            println!("  C: 500 repeat signs on one context done");
        }
    }
    println!("  C: 50 full cycles -> {ok} ok, {bad} bad");
}

fn main() {
    // The guest needs the same 256 MiB stack the real command gives it.
    let h = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(audit_main)
        .expect("spawn audit thread");
    match h.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("audit error: {e}"),
        Err(_) => eprintln!("audit thread panicked"),
    }
}

fn audit_main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let dir = args.get(1).cloned().unwrap_or_else(|| {
        format!(
            "{}/.cache/perun/sap",
            std::env::var("HOME").unwrap_or_default()
        )
    });
    let mac = primary_mac();
    println!(
        "sap-audit: assets={dir} mac={mac:02X?} ({})",
        mac.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    );
    unsafe { install_probe() };
    let assets = sap::SapAssets::load_dir(&dir)?;
    let mut rt = sap::SapRuntime::new(&assets)?;
    if let Err(e) = rt.init(mac).and_then(|_| {
        rt.setup_with_cert(mac, {
            match fetcher::ensure_cert().and_then(|p| std::fs::read(p).map_err(|e| e.to_string())) {
                Ok(c) => c,
                Err(e) => return Err(e),
            }
        })
    }) {
        eprintln!("setup failed: {e}");
        return Err(e);
    }
    block_a(&mut rt);
    snapshot("block A");
    drop(rt);
    block_b(&dir, mac);
    snapshot("block B");
    block_c(&dir, mac);
    snapshot("block C");
    let (corefp, ck, total) = census();
    println!("\n== census union over every block ==");
    println!("  sites mined   : {total}");
    println!("  CoreFP fired  : {}", corefp.len());
    println!("  CommerceKit   : {}", ck.len());
    if !corefp.is_empty() {
        println!("  !! CoreFP sites reached: {corefp:?}");
    }
    if ck.len() > 175 {
        println!("  !! CommerceKit grew past 175: {}", ck.len());
    }
    // The decisive check: sites that fired but are NOT in the shipped table.
    // Those are un-neutralised rdtsc reads, i.e. live TSC leaking into the
    // SAP context.
    let shipped: std::collections::BTreeSet<u32> =
        perun_core::rdtsc_sites::COMMERCEKIT_RDTSC_PATCHES
            .iter()
            .map(|(o, _)| *o)
            .collect();
    let mut unpatched: Vec<u32> = ck
        .iter()
        .filter_map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .filter(|o| !shipped.contains(o))
        .collect();
    unpatched.sort_unstable();
    println!(
        "  fired but NOT in shipped table: {} ({unpatched:?})",
        unpatched.len()
    );
    let shipped_cf: std::collections::BTreeSet<u32> = perun_core::rdtsc_sites::COREFP_RDTSC_PATCHES
        .iter()
        .map(|(o, _)| *o)
        .collect();
    for (img, off) in perun_core::census::fired() {
        if !shipped.contains(&off) && !shipped_cf.contains(&off) {
            println!("    OUTSIDER: image={img} off={off:#x}");
        }
    }
    if !unpatched.is_empty() {
        println!("  !! these rdtsc reads a live TSC on the SAP path");
    }
    Ok(())
}

/// The crash handler that turns a census SIGTRAP into a record + RIP advance
/// lives in the real binary; reuse it by installing the same probe here.
unsafe fn install_probe() {
    unsafe {
        static mut ALT: [u8; 64 * 1024] = [0; 64 * 1024];
        let mut ss: libc::stack_t = std::mem::zeroed();
        ss.ss_sp = std::ptr::addr_of_mut!(ALT).cast();
        ss.ss_size = 64 * 1024;
        libc::sigaltstack(&ss, std::ptr::null_mut());
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = census_handler as *const () as usize;
        act.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        libc::sigaction(libc::SIGTRAP, &act, std::ptr::null_mut());
        libc::sigaction(libc::SIGSEGV, &act, std::ptr::null_mut());
        libc::sigaction(libc::SIGFPE, &act, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &act, std::ptr::null_mut());
    }
}

unsafe extern "C" fn census_handler(sig: i32, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    unsafe {
        let uc = ctx as *mut libc::ucontext_t;
        let regs = (*uc).uc_mcontext.gregs.as_mut_ptr();
        let rip = *regs.add(libc::REG_RIP as usize) as u64;
        // The reference thunk returns via `hlt`, which faults as SIGSEGV; the
        // real command bounces that to the landing pad, so the audit must too
        // or the first guest return kills the process.
        const RETURN_HLT: u64 = 0x1_0000_0000;
        if sig == libc::SIGSEGV && (rip == RETURN_HLT + 2 || rip == RETURN_HLT) {
            *regs.add(libc::REG_RIP as usize) = sap::guest_landing_for_signal() as i64;
            return;
        }
        if sig != libc::SIGTRAP {
            return;
        }
        if let Some(next) = perun_core::census::on_trap(rip) {
            *regs.add(libc::REG_RAX as usize) = 0;
            *regs.add(libc::REG_RDX as usize) = 0;
            *regs.add(libc::REG_RIP as usize) = next as i64;
        } else {
            let mut m: [u8; 96] = [0; 96];
            let n = format!("sap-audit: unmined SIGTRAP at rip={rip:#x}\n");
            for (i, b) in n.as_bytes().iter().take(95).enumerate() {
                m[i] = *b;
            }
            libc::write(2, m.as_ptr().cast(), 95);
            libc::_exit(9);
        }
    }
}
