// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! `feed_spim`: feed a live GSA spim (+dsId) into CoreADI64.dll via honest
//! in-process pointers. Model A (flat) vs Model B (envelope), opcodes 0..7.
//! Signal: any return outside {5016, 5026} or any `cpim_out` write.
//! Usage: `feed_spim` <dll> <spim.raw> [dsId=-2]
//!
//! Each case runs in its own child process: a wild guest can smash the host
//! stack past the crash probe, so one address space per case.

use perun_core::loader::{DLL_PROCESS_ATTACH, Image};
use perun_shims::table::ShimTable;

type ExportFn = unsafe extern "win64" fn(u64, u64, u64, u64) -> u64;

const KNOWN: [u64; 3] = [0xffff5016, 0xffff5026, 0xffff5036];
const CPIM_CAP: usize = 4096;

fn w64(mem: &mut [u8], off: usize, v: u64) {
    mem[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn w32(mem: &mut [u8], off: usize, v: u32) {
    mem[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
#[cfg(test)]
fn r64(mem: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(mem[off..off + 8].try_into().unwrap())
}

fn layout_a1(dsid: u64, op: u64, spim: u64, spim_len: u64, cpim: u64) -> Vec<u8> {
    let mut s = vec![0u8; 0x30];
    w64(&mut s, 0x00, dsid);
    w64(&mut s, 0x08, op);
    w64(&mut s, 0x10, spim);
    w64(&mut s, 0x18, spim_len);
    w64(&mut s, 0x20, cpim);
    w32(&mut s, 0x28, 0);
    s
}

fn layout_a2(dsid: u64, op: u64, spim: u64, spim_len: u64, cpim: u64) -> Vec<u8> {
    let mut s = vec![0u8; 0x30];
    w64(&mut s, 0x00, op);
    w64(&mut s, 0x08, dsid);
    w64(&mut s, 0x10, spim);
    w64(&mut s, 0x18, spim_len);
    w64(&mut s, 0x20, cpim);
    w32(&mut s, 0x28, 0);
    s
}

fn layout_b(inner: u64, op: u64) -> Vec<u8> {
    let mut s = vec![0u8; 0x20];
    w64(&mut s, 0x00, inner);
    w64(&mut s, 0x08, 347);
    w64(&mut s, 0x10, CPIM_CAP as u64);
    w64(&mut s, 0x18, op);
    s
}

/// Blackwood-envelope hypothesis as honest repr(C): 32-bit sizes, command at
/// +0x10, flags at +0x14. The u32-vs-u64 width is NOT independently provable
/// offline (the session gate masks every discriminator), so the unit tests
/// below pin the COMPILED offsets against this spec instead — if rustc
/// disagrees, the tests fail and the spec, not the code, is wrong.
#[cfg(test)]
#[repr(C)]
struct AdiInvocation {
    args: u64,
    input_size: u32,
    output_size: u32,
    command: u32,
    flags: u32,
}

/// Hypothetical startProvisioning inner block (same honesty rule).
#[cfg(test)]
#[repr(C)]
struct InnerStartProv {
    dsid: u64,
    spim_ptr: u64,
    spim_len: u32,
    _pad: u32,
    session_out: u64,
    cpim_out: u64,
    cpim_len_out: u64,
}

/// vovan2200's `DataPacket` (Android lane, OTP-shaped): 32-byte header
/// (first int32 + 7 pad) then five pointer-or-value arg slots.
#[repr(C)]
#[allow(dead_code)]
struct DataPacket {
    first: u32,
    pad: [u32; 7],
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
}

/// `MainContext` wraps the packet plus result/crc words.
#[repr(C)]
#[allow(dead_code)]
struct MainContext {
    packet: u64,
    res: i32,
    crc: u32,
}

fn layout_inv(inner: u64, cmd: u32, flags: u32) -> Vec<u8> {
    let mut s = vec![0u8; 0x18];
    w64(&mut s, 0x00, inner);
    w32(&mut s, 0x08, 347);
    w32(&mut s, 0x0C, CPIM_CAP as u32);
    w32(&mut s, 0x10, cmd);
    w32(&mut s, 0x14, flags);
    s
}

fn layout_inner(dsid: u64, spim: u64, session_slot: u64, cpim: u64, len_slot: u64) -> Vec<u8> {
    let mut s = vec![0u8; 0x30];
    w64(&mut s, 0x00, dsid);
    w64(&mut s, 0x08, spim);
    w32(&mut s, 0x10, 347);
    w64(&mut s, 0x18, session_slot);
    w64(&mut s, 0x20, cpim);
    w64(&mut s, 0x28, len_slot);
    s
}

/// Build a `DataPacket` region in place: first qword, five arg slots.
fn fill_packet(p: *mut u8, first: u64, args: [u64; 5]) {
    unsafe {
        std::ptr::write_bytes(p, 0, 0x48);
        std::ptr::write_unaligned(p.cast::<u64>(), first);
        for (i, a) in args.iter().enumerate() {
            std::ptr::write_unaligned(p.cast::<u64>().add(4 + i), *a);
        }
    }
}

/// Shared DP pair builder for split-arg models: returns
/// ((`ctx_addr`, `ctx_watches`, `ctx_blob`), (`packet_addr`, `packet_watches`, _)).
#[allow(clippy::type_complexity)]
fn dp_pair(
    opv: u64,
) -> (
    (u64, Vec<(*const u8, usize)>, Vec<u8>),
    (u64, Vec<(*const u8, usize)>, Vec<u8>),
) {
    unsafe fn region(n: usize) -> *mut u8 {
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
                eprintln!("region mmap failed");
                std::process::exit(1);
            }
            std::ptr::write_bytes(p.cast::<u8>(), 0, n);
            p.cast::<u8>()
        }
    }
    unsafe {
        let rpacket = region(0x48);
        let rctx = region(0x10);
        let rmid = region(256);
        let rmidn = region(8);
        let rotp = region(256);
        let rotpn = region(8);
        fill_packet(
            rpacket,
            opv,
            [
                0xFFFFFFFFFFFFFFFF,
                rmid as u64,
                rmidn as u64,
                rotp as u64,
                rotpn as u64,
            ],
        );
        std::ptr::write_unaligned(rctx.cast::<u64>(), rpacket as u64);
        std::ptr::write_unaligned(rctx.cast::<u32>().add(2), 0);
        std::ptr::write_unaligned(rctx.cast::<u32>().add(3), 0);
        let cw = vec![];
        let pw = vec![
            (rmid.cast_const(), 256),
            (rmidn.cast_const(), 8),
            (rotp.cast_const(), 256),
            (rotpn.cast_const(), 8),
        ];
        let cb = std::slice::from_raw_parts(rctx, 0x10).to_vec();
        let pb = std::slice::from_raw_parts(rpacket, 0x48).to_vec();
        ((rctx as u64, cw, cb), (rpacket as u64, pw, pb))
    }
}

/// Flat 6-qword vdfut block (vovan2200's raw dump reread): no pad inside —
/// the pad lives in `sub_1d0120`'s wrapper. [opcode, dsid/value, mid, `mid_len`,
/// otp, `otp_len`]. Opcode 1 = OTP per the dump.
fn layout_flat(opcode: u64, dsid: u64, mid: u64, mid_len: u64, otp: u64, otp_len: u64) -> Vec<u8> {
    let mut s = vec![0u8; 0x30];
    w64(&mut s, 0x00, opcode);
    w64(&mut s, 0x08, dsid);
    w64(&mut s, 0x10, mid);
    w64(&mut s, 0x18, mid_len);
    w64(&mut s, 0x20, otp);
    w64(&mut s, 0x28, otp_len);
    s
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() {
    std::process::exit(real_main());
}

fn real_main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: feed_spim <dll> <spim.raw> [dsId=-2] [model op]");
        return 2;
    }
    // Worker mode: one case, crashes contained by the OS.
    if args.len() > 3 {
        let dsid = args[2].parse::<i64>().unwrap_or(-2) as u64;
        let op: u64 = args[4].parse().unwrap_or(0);
        return single_case(&args[0], &args[1], dsid, &args[3], op);
    }
    // Driver mode: isolate every case in a child process.
    let exe = std::env::current_exe().unwrap();
    let dsid = if args.len() > 2 {
        args[2].clone()
    } else {
        "-2".into()
    };
    let mut hits = 0;
    let mut ran = 0;
    for model in [
        "A1", "A2", "B", "BC", "INV", "DP", "DB", "FLAT", "DP2", "DP3", "DF",
    ] {
        let ops: Vec<u64> = match model {
            // INV sweeps command 0..10 at +0x10 (flags=0), plus flags=1
            // probes encoded as 100+cmd.
            "INV" => (0u64..11).chain([100, 101, 104]).collect(),
            // DP/DB/DP2/DP3/DF sweep the packet first-word.
            "DP" | "DB" | "DP2" | "DP3" | "DF" => {
                vec![0, 1, 2, 3, 4, 5, 0x632b8d6e, 0x85fe63b0]
            }
            // FLAT sweeps the block opcode.
            "FLAT" => vec![0, 1, 2, 3, 4, 5],
            _ => (0u64..8).collect(),
        };
        for op in ops {
            ran += 1;
            let out = std::process::Command::new(&exe)
                .args([&args[0], &args[1], &dsid, model, &op.to_string()])
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    let line = String::from_utf8_lossy(&o.stdout);
                    let line = line.trim();
                    println!("{model} op={op} worker-rc=0 {line}");
                    if line.starts_with("HIT") {
                        hits += 1;
                    }
                }
                Ok(o) => {
                    println!("{model} op={op} worker-died rc={}", o.status);
                    hits += 1;
                }
                Err(e) => println!("{model} op={op} spawn failed: {e}"),
            }
        }
    }
    println!("[feed] done, {hits} hit(s)/crashes out of {ran}");
    0
}

/// Run ONE (model, op) case in this address space; print one result line.
fn single_case(dll: &str, spim_path: &str, dsid: u64, model: &str, opv: u64) -> i32 {
    let spim = std::fs::read(spim_path).unwrap_or_else(|e| {
        eprintln!("read {spim_path}: {e}");
        std::process::exit(1);
    });
    let bytes = std::fs::read(dll).unwrap_or_else(|e| {
        eprintln!("read {dll}: {e}");
        std::process::exit(1);
    });
    let mut table = ShimTable::collect();
    let image = match Image::load(&bytes, &mut table) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("load: {e:?}");
            return 1;
        }
    };
    let _ = unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
    let dll_main = if let Some(f) = unsafe { image.entry_dll_main() } {
        f
    } else {
        eprintln!("no entry");
        return 1;
    };
    if unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) } == 0 {
        eprintln!("DllMain FALSE");
        return 3;
    }
    let op_ptr = if let Some(p) = image.get_export_by_name("vdfut768ig") {
        p
    } else {
        eprintln!("no export");
        return 1;
    };
    let op: ExportFn = unsafe { std::mem::transmute(op_ptr) };
    let init_ptr = if let Some(p) = image.get_export_by_name("cvu8io98wun") {
        p
    } else {
        eprintln!("no init export");
        return 1;
    };
    let init: ExportFn = unsafe { std::mem::transmute(init_ptr) };

    unsafe fn region(n: usize) -> *mut u8 {
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

    let rsp = unsafe { region(spim.len().max(8)) };
    unsafe { std::ptr::copy_nonoverlapping(spim.as_ptr(), rsp, spim.len()) };
    let rcp = unsafe { region(CPIM_CAP) };
    let rstruct = unsafe { region(0x1000) };
    let rinner = unsafe { region(0x1000) };
    let rslots = unsafe { region(16) };
    // Extra watched regions (DP out-buffers); checked for guest writes.
    let mut watches: Vec<(*const u8, usize)> = Vec::new();
    // Split-arg override: some models pass different structs in rcx vs rdx.
    let mut split: Option<(u64, u64)> = None;
    let blob = match model {
        "A1" => layout_a1(dsid, opv, rsp as u64, spim.len() as u64, rcp as u64),
        "A2" => layout_a2(dsid, opv, rsp as u64, spim.len() as u64, rcp as u64),
        "BC" => {
            // cvu-init the inner region first (writes [+0]=0x2000000001,
            // [+8]=0), then wrap the INITIALIZED bytes in the envelope.
            let rc = unsafe { init(rinner as u64, rinner as u64, 0, 0) };
            eprintln!("[feed] BC init rc={rc:#x}");
            layout_b(rinner as u64, opv)
        }
        "DP" => {
            // vovan2200's packet: OTP-shaped args, first-word sweep.
            let rpacket = unsafe { region(0x48) };
            let rctx = unsafe { region(0x10) };
            let rmid = unsafe { region(256) };
            let rmidn = unsafe { region(8) };
            let rotp = unsafe { region(256) };
            let rotpn = unsafe { region(8) };
            fill_packet(
                rpacket,
                opv,
                [
                    0xFFFFFFFFFFFFFFFF,
                    rmid as u64,
                    rmidn as u64,
                    rotp as u64,
                    rotpn as u64,
                ],
            );
            unsafe {
                std::ptr::write_unaligned(rctx.cast::<u64>(), rpacket as u64);
                std::ptr::write_unaligned(rctx.cast::<u32>().add(2), 0);
                std::ptr::write_unaligned(rctx.cast::<u32>().add(3), 0);
            }
            watches.push((rmid.cast_const(), 256));
            watches.push((rmidn.cast_const(), 8));
            watches.push((rotp.cast_const(), 256));
            watches.push((rotpn.cast_const(), 8));
            unsafe { std::slice::from_raw_parts(rctx, 0x10).to_vec() }
        }
        "DP2" => {
            // Split args: rcx=ctx, rdx=packet.
            let (ctx_b, pkt_b) = dp_pair(opv);
            split = Some((ctx_b.0, pkt_b.0));
            watches.extend(ctx_b.1);
            watches.extend(pkt_b.1);
            ctx_b.2
        }
        "DP3" => {
            // Split args: rcx=packet, rdx=ctx.
            let (ctx_b, pkt_b) = dp_pair(opv);
            split = Some((pkt_b.0, ctx_b.0));
            watches.extend(ctx_b.1);
            watches.extend(pkt_b.1);
            pkt_b.2
        }
        "DF" => {
            // MainContext wrapping the flat block: rcx=ctx, rdx=block.
            let rmid = unsafe { region(256) };
            let rmidn = unsafe { region(8) };
            let rotp = unsafe { region(256) };
            let rotpn = unsafe { region(8) };
            let blk = layout_flat(
                opv,
                0xFFFFFFFFFFFFFFFF,
                rmid as u64,
                rmidn as u64,
                rotp as u64,
                rotpn as u64,
            );
            let rblk = unsafe { region(0x30) };
            unsafe {
                std::ptr::copy_nonoverlapping(blk.as_ptr(), rblk, 0x30);
            }
            let rctx = unsafe { region(0x10) };
            unsafe {
                std::ptr::write_unaligned(rctx.cast::<u64>(), rblk as u64);
                std::ptr::write_unaligned(rctx.cast::<u32>().add(2), 0);
                std::ptr::write_unaligned(rctx.cast::<u32>().add(3), 0);
            }
            watches.push((rmid.cast_const(), 256));
            watches.push((rmidn.cast_const(), 8));
            watches.push((rotp.cast_const(), 256));
            watches.push((rotpn.cast_const(), 8));
            split = Some((rctx as u64, rblk as u64));
            unsafe { std::slice::from_raw_parts(rctx, 0x10).to_vec() }
        }
        "DB" => {
            // Envelope around the packet: outer sizes + packet with
            // OTP-shaped args. Tests whether header validation wants BOTH.
            let rpacket = unsafe { region(0x48) };
            let rmid = unsafe { region(256) };
            let rmidn = unsafe { region(8) };
            let rotp = unsafe { region(256) };
            let rotpn = unsafe { region(8) };
            fill_packet(
                rpacket,
                opv,
                [
                    0xFFFFFFFFFFFFFFFF,
                    rmid as u64,
                    rmidn as u64,
                    rotp as u64,
                    rotpn as u64,
                ],
            );
            watches.push((rmid.cast_const(), 256));
            watches.push((rmidn.cast_const(), 8));
            watches.push((rotp.cast_const(), 256));
            watches.push((rotpn.cast_const(), 8));
            layout_b(rpacket as u64, 0)
        }
        "FLAT" => {
            // Flat 6-qword block straight into the call args.
            let rmid = unsafe { region(256) };
            let rmidn = unsafe { region(8) };
            let rotp = unsafe { region(256) };
            let rotpn = unsafe { region(8) };
            let blk = layout_flat(
                opv,
                0xFFFFFFFFFFFFFFFF,
                rmid as u64,
                rmidn as u64,
                rotp as u64,
                rotpn as u64,
            );
            watches.push((rmid.cast_const(), 256));
            watches.push((rmidn.cast_const(), 8));
            watches.push((rotp.cast_const(), 256));
            watches.push((rotpn.cast_const(), 8));
            blk
        }
        "INV" => {
            let (cmd, flags) = if opv >= 100 {
                ((opv - 100) as u32, 1)
            } else {
                (opv as u32, 0)
            };
            let inner = layout_inner(
                dsid,
                rsp as u64,
                rslots as u64,
                rcp as u64,
                (rslots as u64) + 8,
            );
            unsafe {
                std::ptr::copy_nonoverlapping(inner.as_ptr(), rinner, inner.len());
            }
            layout_inv(rinner as u64, cmd, flags)
        }
        _ => {
            let inner = layout_a1(dsid, opv, rsp as u64, spim.len() as u64, rcp as u64);
            unsafe {
                std::ptr::copy_nonoverlapping(inner.as_ptr(), rinner, inner.len());
            }
            layout_b(rinner as u64, opv)
        }
    };
    unsafe {
        std::ptr::copy_nonoverlapping(blob.as_ptr(), rstruct, blob.len());
    }
    let r = match split {
        Some((a0, a1)) => unsafe { op(a0, a1, 0, 0) },
        None => unsafe { op(rstruct as u64, rstruct as u64, 0, 0) },
    };
    let scpim = unsafe { std::slice::from_raw_parts(rcp.cast_const(), CPIM_CAP) };
    let sslots = unsafe { std::slice::from_raw_parts(rslots.cast_const(), 16) };
    let wrote = scpim.iter().any(|&b| b != 0)
        || sslots.iter().any(|&b| b != 0)
        || watches
            .iter()
            .any(|(p, n)| unsafe { std::slice::from_raw_parts(*p, *n).iter().any(|&b| b != 0) });
    if !KNOWN.contains(&r) || wrote {
        print!("HIT {model} op={opv} -> {r:#x} ({r}) cpim_wrote={wrote}");
        if wrote {
            let n = scpim.iter().take_while(|&&b| b == 0).count();
            let show = 32.min(CPIM_CAP - n);
            print!(" cpim[{n}..{}] = {}", n + show, hex(&scpim[n..n + show]));
        }
        println!();
    } else {
        println!("{model} op={opv} -> {r:#x} ({r}) cpim_wrote={wrote}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a1_offsets() {
        let s = layout_a1(0xAABB, 3, 0x1000, 347, 0x2000);
        assert_eq!(r64(&s, 0x00), 0xAABB);
        assert_eq!(r64(&s, 0x08), 3);
        assert_eq!(r64(&s, 0x10), 0x1000);
        assert_eq!(r64(&s, 0x18), 347);
        assert_eq!(r64(&s, 0x20), 0x2000);
        assert_eq!(s.len(), 0x30);
    }

    #[test]
    fn a2_offsets() {
        let s = layout_a2(0xAABB, 5, 0x1000, 347, 0x2000);
        assert_eq!(r64(&s, 0x00), 5);
        assert_eq!(r64(&s, 0x08), 0xAABB);
        assert_eq!(r64(&s, 0x10), 0x1000);
    }

    #[test]
    fn b_envelope_shape() {
        let s = layout_b(0x3000, 4);
        assert_eq!(r64(&s, 0x00), 0x3000);
        assert_eq!(r64(&s, 0x08), 347);
        assert_eq!(r64(&s, 0x10), CPIM_CAP as u64);
        assert_eq!(r64(&s, 0x18), 4);
    }

    #[test]
    fn repr_c_matches_spec() {
        use std::mem::offset_of;
        assert_eq!(offset_of!(AdiInvocation, args), 0x00);
        assert_eq!(offset_of!(AdiInvocation, input_size), 0x08);
        assert_eq!(offset_of!(AdiInvocation, output_size), 0x0C);
        assert_eq!(offset_of!(AdiInvocation, command), 0x10);
        assert_eq!(offset_of!(AdiInvocation, flags), 0x14);
        assert_eq!(offset_of!(InnerStartProv, dsid), 0x00);
        assert_eq!(offset_of!(InnerStartProv, spim_ptr), 0x08);
        assert_eq!(offset_of!(InnerStartProv, spim_len), 0x10);
        assert_eq!(offset_of!(InnerStartProv, session_out), 0x18);
        assert_eq!(offset_of!(InnerStartProv, cpim_out), 0x20);
        assert_eq!(offset_of!(InnerStartProv, cpim_len_out), 0x28);
        // builders emit exactly what the structs declare
        let inv = layout_inv(0x1111, 7, 1);
        assert_eq!(r64(&inv, 0x00), 0x1111);
        assert_eq!(u32::from_le_bytes(inv[0x08..0x0C].try_into().unwrap()), 347);
        assert_eq!(u32::from_le_bytes(inv[0x10..0x14].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(inv[0x14..0x18].try_into().unwrap()), 1);
        let inner = layout_inner(0xAABB, 0x1000, 0x2000, 0x3000, 0x4000);
        assert_eq!(r64(&inner, 0x00), 0xAABB);
        assert_eq!(r64(&inner, 0x08), 0x1000);
        assert_eq!(
            u32::from_le_bytes(inner[0x10..0x14].try_into().unwrap()),
            347
        );
        assert_eq!(r64(&inner, 0x18), 0x2000);
    }

    #[test]
    fn packet_struct_matches_spec() {
        use std::mem::offset_of;
        assert_eq!(offset_of!(DataPacket, first), 0x00);
        assert_eq!(offset_of!(DataPacket, arg1), 0x20);
        assert_eq!(offset_of!(DataPacket, arg5), 0x40);
        assert_eq!(offset_of!(MainContext, packet), 0x00);
        assert_eq!(offset_of!(MainContext, res), 0x08);
        assert_eq!(offset_of!(MainContext, crc), 0x0C);
        assert_eq!(std::mem::size_of::<DataPacket>(), 0x48);
        assert_eq!(std::mem::size_of::<MainContext>(), 0x10);
    }
}
