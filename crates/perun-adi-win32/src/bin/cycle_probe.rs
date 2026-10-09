// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! One full legitimate provisioning cycle against the live GSA service,
//! in one process: identity -> lookup -> startMachineProvisioning ->
//! the guest's transform on the SPIM the service just minted for THIS
//! machine -> (if the fold passes) the CPIM and on to finish.
//!
//! The measured reason this is the right experiment: the barrier fold is a
//! hash check over the SPIM and machine state (the t2 trace shows the packet
//! being rewritten from the input before the fold, with edi/ebp terms
//! derived from it). A captured SPIM from another machine fails it
//! (-45020); the only SPIM that can pass is the one issued for this
//! machine's identity, which is exactly what start_provisioning returns.

use perun_core::loader::{DLL_PROCESS_ATTACH, Image};
use perun_shims::table::ShimTable;

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

fn main() {
    let image_path = std::env::args().nth(1).unwrap_or_else(|| {
        "/opt/data/adi-pe/extracted/itunes_extracted/iTunes/CoreADI64.dll".into()
    });

    // 1. Network half, before the guest: mint identity, ask Apple for a SPIM.
    let id = perun_adi_win32::net::identity();
    println!("[id] device-id {} lu {}", id.device_id, id.lu);
    let ep = match perun_adi_win32::net::lookup(&id) {
        Ok(e) => e,
        Err(e) => {
            println!("[net] lookup failed: {e}");
            return;
        }
    };
    println!("[net] endpoints: start {}", ep.start);
    let start = match perun_adi_win32::net::start_provisioning(&id, &ep) {
        Ok(s) => s,
        Err(e) => {
            println!("[net] start failed: {e}");
            return;
        }
    };
    println!(
        "[net] spim {} bytes, ptxid {}",
        start.spim.len(),
        start.ptxid
    );
    std::fs::write("/opt/data/il/fresh_spim.bin", &start.spim).unwrap();

    // 2. Guest half: load the DLL, run the canonical order, feed the fresh SPIM.
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

    let state = page(4096);
    unsafe {
        *state.cast::<u64>() = 0x2000000001;
        // The fold triple: bytes 6,7 = 0,1 -- the measured cvu-scratch key
        // that opens the fold barrier (run_pass.sh's scratch+0x6/0x7 pokes).
        // Without it every route past the fold returns -45020 immediately.
        *state.cast::<u8>().add(6) = 0;
        *state.cast::<u8>().add(7) = 1;
        let r = cvu(state as u64, 0x2000000001, 0, 0);
        println!("[cvu] rc={r}");
    }

    let pkt = page(4096);
    let ctx = page(0x1_0000);
    let spimp = page(0x1000);
    let urlp = page(0x1000);
    let olen = page(64);
    let out = page(0x1000);

    // init, Android-shaped v2 header + this run's 12 fresh bytes: the packet
    // carries no secret, so any non-zero filler is the honest shape. The
    // fresh SPIM is what the fold actually checks, not the packet.
    unsafe {
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for i in 4..16u8 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *pkt.cast::<u8>().add(usize::from(i)) = (seed >> 33) as u8;
        }
        *pkt.cast::<u8>().add(3) = 2;
    }
    unsafe {
        // The Android init envelope, measured in dumprun4 call 1: fifteen
        // populated slots, not the three the probe used to send. The load-
        // bearing one is +0x48, which points at a plain integer 3; +0x10
        // carries a stack-ish 0x7fff00000000; +0x20 is 21; the code-ish
        // slots (+0x28/+0x30/+0x40) get buffer pointers, as the values'
        // only observed use is being non-null.
        let aux1 = page(4096);
        let aux2 = page(4096);
        let aux3 = page(4096);
        let aux4 = page(4096);
        let forty_eight = page(4096);
        *forty_eight.cast::<u64>() = 3;
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        let c = ctx.cast::<u64>();
        std::ptr::write(c.add(0), pkt as u64); // +0x00 packet
        std::ptr::write(c.add(1), 0x10); // +0x08 flags|len, measured
        std::ptr::write(c.add(2), 0x0000_7fff_0000_0000); // +0x10 stack-ish
        std::ptr::write(c.add(3), aux1 as u64); // +0x18 ptr
        std::ptr::write(c.add(4), 0x15); // +0x20 = 21, measured
        std::ptr::write(c.add(5), aux2 as u64); // +0x28
        std::ptr::write(c.add(6), aux3 as u64); // +0x30
        std::ptr::write(c.add(7), 0x0000_7fff_0000_0000); // +0x38 stack-ish
        std::ptr::write(c.add(8), aux4 as u64); // +0x40
        std::ptr::write(c.add(9), forty_eight as u64); // +0x48 -> 3
        let r = f(0xb0eda7af, ctx as u64, 0, 0);
        println!("[init] rc={r:#x} ({r})");
    }

    // transform with the fresh SPIM
    let url = b"https://gsa.apple.com/grandslam/MidService/startMachineProvisioning\0";
    unsafe {
        std::ptr::copy_nonoverlapping(start.spim.as_ptr(), spimp.cast::<u8>(), start.spim.len());
        std::ptr::copy_nonoverlapping(url.as_ptr(), urlp.cast::<u8>(), url.len());
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        // v2 header, filler bytes as above
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for i in 4..16u8 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *pkt.cast::<u8>().add(usize::from(i)) = (seed >> 33) as u8;
        }
        *pkt.cast::<u8>().add(3) = 2;
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        let c = ctx.cast::<u64>();
        std::ptr::write(c.add(0), pkt as u64);
        std::ptr::write(c.add(1), 0x4000_0000_0034);
        std::ptr::write(c.add(2), 0);
        std::ptr::write(c.add(3), start.spim.len() as u64);
        std::ptr::write(c.add(4), urlp as u64);
        std::ptr::write(c.add(5), 2);
        std::ptr::write(c.add(6), spimp as u64);
        std::ptr::write(c.add(7), start.spim.len() as u64);
        std::ptr::write(c.add(8), 4);
        std::ptr::write(c.add(9), 0);
        std::ptr::write(c.add(10), olen as u64);
        std::ptr::write(c.add(11), start.spim.len() as u64);
        std::ptr::write(c.add(12), 0);
        std::ptr::write(c.add(13), spimp as u64);
        std::ptr::write(c.add(14), 0x1d0);
        std::ptr::write(c.add(15), urlp as u64);
        std::ptr::write(c.add(16), out as u64);
        // The measured 24-slot reference (dumprun4 Call 6, the live Android
        // transform): the envelope does NOT end at the out pointer. The live
        // caller carries a stack-ish tag at +0x10, a heap pointer at +0x48,
        // FIVE more pointers at +0x88..+0xa8 (host stack locals that the
        // Windows dispatcher may read as callback slots), and the machine
        // identity as a 16-hex ASCII string at +0xb0..+0xbf -- on the live
        // stand it is SetAndroidID("1A7DC0308887C2D8"). The Windows build
        // has no SetAndroidID export (-45019), so the identity rides in the
        // envelope; derive ours from the same device-id the SPIM was minted
        // under (first 16 hex of X-Mme-Device-Id, dots dropped).
        std::ptr::write(c.add(2), 0x0000_7fff_0000_0000); // +0x10 stack-ish
        let aux5 = page(4096);
        std::ptr::write(c.add(9), aux5 as u64); // +0x48 heap-ish, measured non-null
        let cb1 = page(4096);
        let cb2 = page(4096);
        let cb3 = page(4096);
        let cb4 = page(4096);
        let cb5 = page(4096);
        std::ptr::write(c.add(17), cb1 as u64); // +0x88
        std::ptr::write(c.add(18), cb2 as u64); // +0x90
        std::ptr::write(c.add(19), cb3 as u64); // +0x98
        std::ptr::write(c.add(20), cb4 as u64); // +0xa0
        std::ptr::write(c.add(21), cb5 as u64); // +0xa8
        let idhex: String = id
            .device_id
            .chars()
            .filter(|c| *c != '.')
            .take(16)
            .collect();
        let idb = idhex.as_bytes();
        std::ptr::copy_nonoverlapping(idb.as_ptr(), (ctx as *mut u8).add(0xb0), idb.len() + 1);
        let r = f(0x716bd86c, ctx as u64, 0xffff_ffff, 0);
        println!("[transform] rc={r:#x} ({r})");
    }

    let olen_v = unsafe { std::ptr::read(olen.cast::<u64>()) };
    println!("[out] olen={olen_v:#x}");
    let out_b = unsafe { std::slice::from_raw_parts(out.cast::<u8>(), 0x100) };
    let nz = out_b.iter().filter(|b| **b != 0).count();
    println!("[out] nonzero in out[0..256]: {nz}");
    if nz > 0 {
        std::fs::write(
            "/opt/data/il/fresh_cpim.bin",
            &out_b[..olen_v.min(0x100) as usize],
        )
        .unwrap();
        println!("[out] wrote /opt/data/il/fresh_cpim.bin ({} bytes)", olen_v);
    }
}
