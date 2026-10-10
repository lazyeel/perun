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

fn main() {
    let image_path = std::env::args().nth(1).unwrap_or_else(|| {
        "/opt/data/adi-pe/extracted/itunes_extracted/iTunes/CoreADI64.dll".into()
    });

    // ── node 1: the network half, a live SPIM for this machine ──────────
    let id = perun_adi_win32::net::identity();
    println!("[id] device-id {} lu {}", id.device_id, id.lu);
    let ep = match perun_adi_win32::net::lookup(&id) {
        Ok(e) => e,
        Err(e) => {
            println!("[net] lookup failed: {e}");
            return;
        }
    };
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

    // cvu with the fold triple in the state page.
    let state = page(4096);
    unsafe {
        *state.cast::<u64>() = 0x2000000001;
        *state.cast::<u8>().add(6) = 0;
        *state.cast::<u8>().add(7) = 1;
        let r = cvu(state as u64, 0x2000000001, 0, 0);
        println!("[cvu] rc={r}");
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

    // ── node 2: init with the live Call-1 shape ────────────────────────
    // The live stand carried: V1-word packet (pkt bytes 3 and 7 = 1),
    // len 0x10 with flags 4, a stack tag at +0x10, buffers at
    // +0x18/+0x28/+0x30/+0x40, +0x20=21, +0x48 = the IDENTITY STRING,
    // +0x68 = a PATH buffer, and size fields 0x70/0x80/0x90/0x98/0xa0.
    unsafe {
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        *pkt.cast::<u8>().add(3) = 1;
        *pkt.cast::<u8>().add(7) = 1;
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        let c = ctx.cast::<u64>();
        std::ptr::write(c.add(0), pkt as u64);
        std::ptr::write(c.add(1), 0x0000_0004_0000_0010); // len 0x10 | flags 4
        std::ptr::write(c.add(2), 0x0000_7fff_0000_0000); // stack-ish tag
        std::ptr::write(c.add(3), aux[0] as u64);
        std::ptr::write(c.add(4), 0x15); // 21, measured
        std::ptr::write(c.add(5), aux[1] as u64);
        std::ptr::write(c.add(6), aux[2] as u64);
        std::ptr::write(c.add(7), 0x0000_7fff_0000_0000);
        std::ptr::write(c.add(8), aux[3] as u64);
        std::ptr::write(c.add(9), ident as u64); // +0x48 identity
        std::ptr::write(c.add(13), pathb as u64); // +0x68 path
        std::ptr::write(c.add(16), 0x70); // +0x80 size
        std::ptr::write(c.add(18), 0xc2); // +0x90 size
        std::ptr::write(c.add(19), 0xf4); // +0x98 size
        std::ptr::write(c.add(20), 0x30); // +0xa0 size
        let r = f(0xb0eda7af, ctx as u64, 0, 0);
        println!("[init] rc={r:#x} ({r})");
        peek_state(&image, "init");
    }

    // ── node 3.5: the SECOND init (the live canon's Call 5) ────────────
    // The live cycle ran init AGAIN after the identity/path calls and
    // before the transform; on the Windows lane the identity/path ride in
    // the init envelope itself, so the re-init re-reads them with the
    // session already established.
    unsafe {
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        *pkt.cast::<u8>().add(3) = 1;
        *pkt.cast::<u8>().add(7) = 1;
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        let c = ctx.cast::<u64>();
        std::ptr::write(c.add(0), pkt as u64);
        std::ptr::write(c.add(1), 0x0000_0004_0000_0010);
        std::ptr::write(c.add(2), 0x0000_7fff_0000_0000);
        std::ptr::write(c.add(3), aux[0] as u64);
        std::ptr::write(c.add(4), 0x15);
        std::ptr::write(c.add(5), aux[1] as u64);
        std::ptr::write(c.add(6), aux[2] as u64);
        std::ptr::write(c.add(7), 0x0000_7fff_0000_0000);
        std::ptr::write(c.add(8), aux[3] as u64);
        std::ptr::write(c.add(9), ident as u64);
        std::ptr::write(c.add(13), pathb as u64);
        std::ptr::write(c.add(16), 0x70);
        std::ptr::write(c.add(18), 0xc2);
        std::ptr::write(c.add(19), 0xf4);
        std::ptr::write(c.add(20), 0x30);
        let r = f(0xb0eda7af, ctx as u64, 0, 0);
        println!("[init2] rc={r:#x} ({r})");
    }

    // ── node 3.5: the canon's middle calls, even though they reject ────
    // The live cycle ran SetPath (0xb23c691e) and SetID (0xc774d292)
    // between the two inits and the transform. On the Windows dispatcher
    // both return -45019 (unknownAdiFunction) -- but the measured
    // inter-call dependency (the finish matrix re-keying the OTP's fold)
    // says a call's SIDE EFFECT on the dispatcher cursor can matter more
    // than its return code. Run both, in the live order, and read what
    // the transform behind them does.
    unsafe {
        // Both calls with pkt_pass2's fold keys (bytes 3/7 = 1): without
        // them the header fold rejects at -45018 BEFORE the selector, and
        // the measurement is about the selector's own verdict.
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        *pkt.cast::<u8>().add(3) = 1;
        *pkt.cast::<u8>().add(7) = 1;
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        let c = ctx.cast::<u64>();
        std::ptr::write(c.add(0), pkt as u64);
        std::ptr::write(c.add(1), 0x4000_0000_0010);
        let r = f(0xb23c691e, ctx as u64, 0, 0);
        println!("[setpath] rc={r:#x} ({r})");
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        *pkt.cast::<u8>().add(3) = 1;
        *pkt.cast::<u8>().add(7) = 1;
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        std::ptr::write(c.add(0), pkt as u64);
        std::ptr::write(c.add(1), 0x4000_0000_0014);
        let r2 = f(0xc774d292, ctx as u64, 0, 0);
        println!("[setid] rc={r2:#x} ({r2})");
    }

    // ── node 4: transform with the fresh SPIM ───────────────────────────
    let url = b"https://gsa.apple.com/grandslam/MidService/startMachineProvisioning\0";
    unsafe {
        std::ptr::copy_nonoverlapping(start.spim.as_ptr(), spimp.cast::<u8>(), start.spim.len());
        std::ptr::copy_nonoverlapping(url.as_ptr(), urlp.cast::<u8>(), url.len());
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        *pkt.cast::<u8>().add(3) = 1;
        *pkt.cast::<u8>().add(7) = 1;
        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        let c = ctx.cast::<u64>();
        std::ptr::write(c.add(0), pkt as u64);
        std::ptr::write(c.add(1), 0x4000_0000_0034);
        std::ptr::write(c.add(3), start.spim.len() as u64); // +0x18
        std::ptr::write(c.add(4), urlp as u64); // +0x20
        std::ptr::write(c.add(5), 2); // +0x28
        std::ptr::write(c.add(6), spimp as u64); // +0x30
        std::ptr::write(c.add(7), start.spim.len() as u64); // +0x38
        std::ptr::write(c.add(8), 4); // +0x40
        std::ptr::write(c.add(9), aux[4] as u64); // +0x48 heap-ish
        std::ptr::write(c.add(10), olen as u64); // +0x50
        std::ptr::write(c.add(11), start.spim.len() as u64); // +0x58
        std::ptr::write(c.add(12), 0); // +0x60
        std::ptr::write(c.add(13), spimp as u64); // +0x68
        std::ptr::write(c.add(14), 0x1d0); // +0x70
        std::ptr::write(c.add(15), urlp as u64); // +0x78
        std::ptr::write(c.add(16), out as u64); // +0x80
        let r = f(0x716bd86c, ctx as u64, 0xffff_ffff, 0);
        println!("[transform] rc={r:#x} ({r})");
        peek_state(&image, "transform");
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

    // ── node 3: configuration mints the session objects ────────────────
    let wctx = std::fs::read("/opt/data/il/variants/win_ctx.bin").expect("win_ctx container");
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
        let r = f(0xcfe0b46a, ctx as u64, 0, 0);
        println!("[cfg] rc={r:#x} ({r})");
        peek_state(&image, "cfg");

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
        let r2 = f(0xcfe0b46a, ctx as u64, 0, 0);
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
                let r = f(0x0b2b3196, ctx as u64, 0, 0);
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
        let r = f(0x3e58e7f9, ctx as u64, 0, 0);
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
