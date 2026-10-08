// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! One-shot transform probe: cvu8io98wun -> vdfut768ig(0x716bd86c) with the
//! live SPIM, reading the CPIM out-buffers back. Research instrumentation;
//! the production pipeline lives in lib.rs.

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
    let image_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/opt/data/adi-pe/extracted/itunes_extracted/iTunes/CoreADI64.dll".into());
    let spim_path = std::env::args().nth(2).unwrap_or_else(|| "/opt/data/adi-re/live_prov_in.bin".into());
    let bytes = std::fs::read(&image_path).expect("read image");
    let spim = std::fs::read(&spim_path).expect("read spim");
    let url = b"https://gsa.apple.com/grandslam/MidService/startMachineProvisioning\0";

    let mut table = ShimTable::collect();
    let image = Image::load(&bytes, &mut table).expect("load image");
    let _teb = unsafe { perun_core::teb::init_thread_teb(image.base() as u64) };
    let dll_main = unsafe { image.entry_dll_main() }.expect("entry");
    assert!(unsafe { dll_main(image.base(), DLL_PROCESS_ATTACH, std::ptr::null_mut()) } != 0);

    let cvu: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 =
        unsafe { std::mem::transmute(image.get_export_by_name("cvu8io98wun").expect("cvu")) };
    let f: unsafe extern "win64" fn(u64, u64, u64, u64) -> u64 =
        unsafe { std::mem::transmute(image.get_export_by_name("vdfut768ig").expect("vdfut")) };

    let pkt = page(4096);
    let spimp = page(0x1000);
    let urlp = page(0x1000);
    let out = page(0x1000);
    let olen = page(64);
    let ctx = page(0x1_0000);

    unsafe {
        // cvu init half — the measured ABI: a0 = a buffer, a1 = 0x2000000001
        // written INTO the buffer. The buffer must SURVIVE every later call:
        // the seq runs keep it in the scratch page untouched, and the state
        // it leaves is what the session checks key on.
        let state = page(4096);
        *state.cast::<u64>() = 0x2000000001;
        let r = cvu(state as u64, 0x2000000001, 0, 0);
        println!("[cvu] rc={r} state={state:p}");

        // The full measured sequence, every envelope with the Android flag
        // word: init -> setpath -> setid -> (init again). The pass header
        // form (00 00 00 01, byte7=1) is the one this DLL accepts.
        let call = |opcode: u64, pkt_len: u64| {
            std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
            *pkt.cast::<u8>().add(3) = 1;
            // byte7: the 5.8n fold — transform wants 1 (r9d hits 0x4069d333),
            // every other opcode so far measured wants 0.
            // byte7 per opcode, measured: init and transform want 1
            // (the fold hits 0x4069d333 on the third pass), setpath and
            // setid want 0 (measured rc=0 in the seq runs).
            *pkt.cast::<u8>().add(7) = u8::from(matches!(opcode, 0xb0eda7af | 0x716bd86c));
            std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
            let c = ctx.cast::<u64>();
            std::ptr::write(c.add(0), pkt as u64);
            std::ptr::write(c.add(1), pkt_len);
            std::ptr::write(c.add(2), 0);
            let r = f(opcode, ctx as u64, 0, 0);
            println!("[{opcode:#010x}] rc={r:#x} ({r})");
            r
        };
        call(0xb0eda7af, 0x10); // init
        call(0xb23c691e, 0x10); // set provisioning path
        call(0xc774d292, 0x14); // set android id
        call(0xb0eda7af, 0x10); // init again, as the dump shows

        // SPIM + URL
        std::ptr::copy_nonoverlapping(spim.as_ptr(), spimp.cast::<u8>(), spim.len());
        std::ptr::copy_nonoverlapping(url.as_ptr(), urlp.cast::<u8>(), url.len());

        // transform packet: 00 00 00 01, byte7=1 (the pass form measured on this DLL)
        std::ptr::write_bytes(pkt.cast::<u8>(), 0, 4096);
        *pkt.cast::<u8>().add(3) = 1;
        *pkt.cast::<u8>().add(7) = 1;

        std::ptr::write_bytes(ctx.cast::<u8>(), 0, 0x1_0000);
        let c = ctx.cast::<u64>();
        std::ptr::write(c.add(0), pkt as u64);
        std::ptr::write(c.add(1), 0x4000_0000_0034); // len 0x34, flags 4
        std::ptr::write(c.add(2), 0);
        std::ptr::write(c.add(3), spim.len() as u64);
        std::ptr::write(c.add(4), urlp as u64);
        std::ptr::write(c.add(5), 2);
        std::ptr::write(c.add(6), spimp as u64);
        std::ptr::write(c.add(7), spim.len() as u64);
        std::ptr::write(c.add(8), 4);
        // +0x48: the Android envelope carries a pointer to the packer's
        // xform block here — the same encoding `--poke-xform` implements:
        // each 8-byte word is an out-pointer mixed with
        // v = x - (2x & MASK) + ADD, big-endian bytes xored with
        // 31 70 fe a7 95 81 a3 1a. The DLL's worker (0xb5ca0) reads
        // ctx+0x48/+0x20/+0x30, and RVA 0xb49e5 decodes exactly this block
        // before writing the CPIM, so the block must exist and hold the
        // out-buffer addresses, in the order the worker consumes them.
        unsafe {
            const XFORM_MASK: u64 = 0x62e1_fd4f_2b03_4634;
            const XFORM_ADD: u64 = 0x3170_fea7_9581_a31a;
            const XFORM_XOR: [u8; 8] = [0x31, 0x70, 0xfe, 0xa7, 0x95, 0x81, 0xa3, 0x1a];
            let enc = |x: u64| -> [u8; 8] {
                let v = x
                    .wrapping_sub((x.wrapping_mul(2)) & XFORM_MASK)
                    .wrapping_add(XFORM_ADD);
                let mut out = [0u8; 8];
                for (i, k) in XFORM_XOR.iter().enumerate() {
                    out[i] = ((v >> (8 * (7 - i))) & 0xff) as u8 ^ k;
                }
                out
            };
            // Two out-pointers, consumed in order: the CPIM buffer and its
            // length slot.
            let xf = page(64);
            std::ptr::copy_nonoverlapping(enc(out as u64).as_ptr(), xf.cast::<u8>(), 8);
            std::ptr::copy_nonoverlapping(
                enc(olen as u64).as_ptr(),
                (xf as *mut u8).add(8),
                8,
            );
            std::ptr::write(c.add(9), xf as u64);
        }
        std::ptr::write(c.add(10), olen as u64);   // +0x50 CPIM len slot
        std::ptr::write(c.add(11), spim.len() as u64);
        std::ptr::write(c.add(12), 0);
        std::ptr::write(c.add(13), spimp as u64);
        std::ptr::write(c.add(14), 0x1d0);
        std::ptr::write(c.add(15), urlp as u64);
        std::ptr::write(c.add(16), out as u64);    // +0x80 CPIM ptr slot

        let r = f(0x716bd86c, ctx as u64, 0xffff_ffff, 0);
        println!("[transform] rc={r:#x} ({r})");
        let c = ctx.cast::<u64>();
        println!("ctx +0x50={:#x}  +0x80={:#x}", std::ptr::read(c.add(10)), std::ptr::read(c.add(16)));

        let olen_v = unsafe { std::ptr::read(olen.cast::<u64>()) };
        println!("olen qword = {olen_v:#x}");
        let out_b = std::slice::from_raw_parts(out.cast::<u8>(), 0x100);
        println!("out[0..64]: {:02x?}", &out_b[..64]);
        let nz = out_b.iter().filter(|b| **b != 0).count();
        println!("nonzero in out[0..256]: {nz}");
    }
}
