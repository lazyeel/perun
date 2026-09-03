// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! The Apple FairPlay SAP runtime: native, in-process, no emulation.
//!
//! Loads the four binaries Apple ships in the OS X 10.9 update package
//! (CoreFP, CoreFP.icxs, CommerceKit, CommerceCore), relocates them, and
//! drives the five SAP entry points directly on the CPU under the SysV
//! AMD64 convention:
//!
//! ```text
//! SAPInit(&ctx_out, hw_info)                     → int32
//! SAPExchange(ver, hw_info, ctx, in, in_len, &out, &out_len, &rc) → int32
//! SAPSign(ctx, in, in_len, &out, &out_len)       → int32
//! SAPTeardown(ctx)                               → int32
//! DisposeStorage(out_ptr)                        → int32
//! ```
//!
//! The ICXS key material is served through the fake `open`/`read` path in
//! `perun_shims::mach`, exactly as on macOS where CoreFP reads
//! `./../CoreFP.icxs` next to its bundle.

use std::collections::HashMap;

use perun_core::macho_loader::{MachImage, MachImportResolver};

/// Zero a window of stack below the current frame. The obfuscated SAP
/// control flow reads uninitialized locals; with host ASLR the leftovers
/// differ every run, so request buffers (and thus signatures) diverge.
#[path = "guest_stack.rs"]
mod guest_stack;

use guest_stack::guest_trampoline;

/// Call a SAP entry point on the dedicated guest stack, replicating the
/// reference emulator's entry frame (see `guest_stack.rs`).
///
/// # Safety
/// The runtime must have mapped the guest stack and return-thunk pages.
unsafe fn guest_call_on_stack(f: u64, rsp0: u64, args: &[u64]) -> i64 {
    let mut a = [0u64; 8];
    let n = args.len().min(8);
    a[..n].copy_from_slice(&args[..n]);
    guest_trampoline(f, rsp0, n, a)
}

/// Landing-pad address for the signal handler's hlt bounce (async-signal-
/// safe: reads a thread-local Cell, no allocation).
pub fn guest_landing_for_signal() -> u64 {
    guest_stack::get_landing()
}

// Load bases, one fixed span per image — distinct, page-aligned, and far
// from anything the host maps. Same layout discipline as the reference
// emulators, but executed natively.
pub const COREFP_BASE: u64 = 0x7FF8_0400_0000;
pub const COMMERCE_CORE_BASE: u64 = 0x7FF8_0800_0000;
pub const COMMERCE_KIT_BASE: u64 = 0x7FF8_0C00_0000;
// storeagent is deliberately not mapped; see the note in SapRuntime::new.
// Its reference base was 0x7FF8_1000_0000.

/// The six obfuscated CoreFP exports the runtime self-resolves through
/// `_dlsym` (names are Apple's, stable since 2013).
const COREFP_EXPORTS: [&str; 6] = [
    "_WIn9UJ86JKdV4dM",
    "_X46O5IeS",
    "_YlCJ3lg",
    "_dku592fbFAj",
    "_fdjkDSAFjklaf2s",
    "_lxpgvVMLd0S7uRl",
];

/// CommerceKit SAP entry points (same symbol family).
pub const SAP_INIT: &str = "_cp2g1b9ro";
pub const SAP_EXCHANGE: &str = "_Mib5yocT";
pub const SAP_SIGN: &str = "_Fc3vhtJDvr";
pub const SAP_TEARDOWN: &str = "_IPaI1oem5iL";
pub const SAP_DISPOSE: &str = "_jEHf8Xzsv8K";

/// Directory holding the four Apple images used by the runtime (`CoreFP`,
/// `CoreFP.icxs`, `CommerceKit`, `CommerceCore`). Images
/// are read transiently at load time and handed over to the loader (owned
/// buffers, no persistent copies); only the ICXS blob stays resident because
/// the guest reads it through the fake `open`/`read` shim path.
pub struct SapAssets {
    pub dir: String,
}

impl SapAssets {
    pub fn load_dir(dir: &str) -> Result<SapAssets, String> {
        // Validate early so failures surface before any mapping happens.
        // storeagent is intentionally absent: it is not mapped (see the note
        // in SapRuntime::new) and the fetcher does not download it.
        for name in ["CoreFP", "CoreFP.icxs", "CommerceKit", "CommerceCore"] {
            let p = std::path::Path::new(dir).join(name);
            if !p.is_file() {
                return Err(format!("{name}: not found in {dir}"));
            }
        }
        Ok(SapAssets {
            dir: dir.to_string(),
        })
    }

    fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        std::fs::read(std::path::Path::new(&self.dir).join(name))
            .map_err(|e| format!("{name}: {e}"))
    }
}

pub struct SapRuntime {
    _corefp: MachImage,
    _commerce_core: MachImage,
    commerce_kit: MachImage,
    init_addr: u64,
    exchange_addr: u64,
    sign_addr: u64,
    teardown_addr: u64,
    dispose_addr: u64,
    /// Scratch pages handed to the guest as argument buffers.
    scratch: u64,
    /// Top edge (exclusive) of the dedicated guest stack region: the guest
    /// entry RSP for every SAP call.
    guest_stack_top: u64,
    /// Next free page in the bridge region (reference-style page-per-arg
    /// allocation; the cursor only ever grows, like the reference's
    /// nextBridgeAddr).
    bridge_cursor: u64,
    /// Base of the bridge region (for unmap on drop).
    bridge_base: u64,
    /// The live SAP context handle (0 until `init`).
    context: u64,
}

const SCRATCH_BASE: u64 = 0x3000_0000_0000;
const SCRATCH_SIZE: usize = 1 << 20;

/// Bridge pages: argument buffers passed to SAP entry points. The reference
/// emulator maps them sequentially from 0x6000_0000_0000 — a range the
/// obfuscated code folds into its scratch-pointer arithmetic, so the range
/// must match (unlike the scratch arena, which the guest never sees).
const BRIDGE_BASE: u64 = 0x6000_0000_0000;
const BRIDGE_SIZE: usize = 1 << 20;

/// The reference emulator's guest entry thunk page (`callq *%rax; hlt`)
/// lives at 0x1_0000_0000; the guest sees 0x1_0000_0002 as its return
/// address. Replicated by a page that jumps back into the trampoline.
const RETURN_PAGE_BASE: u64 = 0x1_0000_0000;

/// Guest stack: the reference emulator maps an 8 MiB stack ending at
/// 0x7FF7_C000_0000 and enters the guest with RSP at that top edge (its
/// `stackBottomAddr`). The obfuscated code computes scratch pointers as
/// ctx + rbp + magic tuned for rbp in this range; a different stack range
/// lands them off the mapping. The entry RSP stays at
/// GUEST_ENTRY_RSP - 8 to keep the reference frame parity.
const GUEST_STACK_BASE: u64 = 0x7FF7_BF80_0000;
const GUEST_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MiB, reference topology
/// The guest entry RSP: the reference's stackBottomAddr, unchanged.
const GUEST_ENTRY_RSP: u64 = 0x7FF7_C000_0000;

// ── thread-local alt stack ────────────────────────────────────────────────

/// Per-thread sigaltstack for the SAP worker thread. `install_crash_probe`
/// registers handlers with SA_ONSTACK, but sigaltstack is per-thread: a
/// spawned thread inherits nothing. Without this, SIGTRAP raised while the
/// guest has switched RSP onto its own stack runs the handler on whatever
/// stack the fault found — which can be uncommitted guard pages → the
/// handler faults inside itself.
pub unsafe fn install_thread_altstack() {
    // One process-wide buffer; the SAP worker is the only spawned thread, so
    // single registration is enough. mmap'd so it never competes with the
    // guest's fixed-address regions.
    static mut ALT: *mut libc::c_void = std::ptr::null_mut();
    unsafe {
        if ALT.is_null() {
            ALT = libc::mmap(
                std::ptr::null_mut(),
                256 * 1024,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ALT == libc::MAP_FAILED {
                return;
            }
        }
        let mut ss: libc::stack_t = std::mem::zeroed();
        ss.ss_sp = ALT;
        ss.ss_size = 256 * 1024;
        if libc::sigaltstack(&ss, std::ptr::null_mut()) != 0 {
            panic!("sigaltstack failed");
        }
    }
}

impl SapRuntime {
    /// Load all images and resolve entry points. `hw_mac` (6 bytes) seeds
    /// the FairPlay hardware identity.
    pub fn new(assets: &SapAssets) -> Result<SapRuntime, String> {
        // Serve the ICXS blob through the fake file path before CoreFP loads.
        perun_shims::mach::set_icxs(assets.read("CoreFP.icxs")?);

        let image_path =
            |name: &str| -> std::path::PathBuf { std::path::Path::new(&assets.dir).join(name) };

        // Two-stage resolution: CoreFP's exports feed `_dlsym`, which
        // CommerceKit consults during its own init. The metadata parse reads
        // only the header + the LINKEDIT tail (a few hundred KB); the image
        // body itself is never materialized outside its mapping.
        let mut corefp_exports: HashMap<String, u64> = HashMap::new();
        {
            let mut f =
                std::fs::File::open(image_path("CoreFP")).map_err(|e| format!("CoreFP: {e}"))?;
            let corefp_info = perun_core::macho::MachInfo::parse_reader(&mut f)
                .map_err(|e| format!("corefp parse: {e}"))?;
            for name in COREFP_EXPORTS {
                let sym = corefp_info
                    .symbols
                    .iter()
                    .find(|s| s.name == name)
                    .ok_or_else(|| format!("CoreFP is missing {name}"))?;
                corefp_exports.insert(
                    name.to_string(),
                    COREFP_BASE.wrapping_add(sym.addr.wrapping_sub(corefp_info.base)),
                );
            }
        }

        let mut resolver = CoreResolver::new(&corefp_exports);
        let corefp = MachImage::load_file(
            &image_path("CoreFP"),
            COREFP_BASE,
            &mut CoreResolver::new(&corefp_exports),
        )
        .map_err(|e| e.to_string())?;

        let commerce_core = MachImage::load_file(
            &image_path("CommerceCore"),
            COMMERCE_CORE_BASE,
            &mut resolver,
        )
        .map_err(|e| e.to_string())?;
        let commerce_kit =
            MachImage::load_file(&image_path("CommerceKit"), COMMERCE_KIT_BASE, &mut resolver)
                .map_err(|e| e.to_string())?;

        // storeagent is NOT mapped: it defines only two symbols
        // (`__mh_execute_header`, `radr://5614542`), none of the commerce
        // pair's bind or lazy-bind streams reference it, and the protocol
        // runs end-to-end without its mapping (verified against live servers:
        // reference context address, 354/1428-byte exchanges, 501-byte
        // signature). The reference runtime maps it for layout parity only.

        // Publish the dlsym table with final addresses.
        perun_shims::mach::set_dlsym_table(&corefp_exports);

        // All transient load buffers (image reads, parse scratch) are dead by
        // now; glibc's arena still holds them because freeing a large block
        // raises the dynamic mmap threshold and later equally-sized reads
        // came from the brk arena, which free() never returns to the OS.
        // Measured effect: ~20 MB off the peak. Guest mappings are untouched
        // (they are separate mmaps, not malloc).
        unsafe { libc::malloc_trim(0) };

        let find = |img: &MachImage, name: &str| -> Result<u64, String> {
            img.symbol(name).ok_or_else(|| format!("missing {name}"))
        };
        let (init_addr, exchange_addr, sign_addr, teardown_addr, dispose_addr) = (
            find(&commerce_kit, SAP_INIT)?,
            find(&commerce_kit, SAP_EXCHANGE)?,
            find(&commerce_kit, SAP_SIGN)?,
            find(&commerce_kit, SAP_TEARDOWN)?,
            find(&commerce_kit, SAP_DISPOSE)?,
        );

        let scratch = unsafe {
            let p = libc::mmap(
                SCRATCH_BASE as *mut _,
                SCRATCH_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            );
            if p == libc::MAP_FAILED {
                return Err("scratch mmap failed".into());
            }
            p as u64
        };

        // Guest stack: a dedicated 8 MiB region whose TOP is the guest
        // entry RSP, exactly the reference emulator's stack span and
        // stackBottomAddr. The obfuscated sign path writes scratch buffers
        // at rbp+0x4EC0 and above the entry RSP; on the host thread stack
        // those cross the mapping edge.
        let guest_stack_top = unsafe {
            let p = libc::mmap(
                GUEST_STACK_BASE as *mut _,
                GUEST_STACK_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            );
            if p == libc::MAP_FAILED {
                return Err("guest stack mmap failed".into());
            }
            GUEST_ENTRY_RSP
        };

        // Return thunk: the reference emulator enters the guest through
        // `callq *%rax; hlt` at 0x1_0000_0000, so the guest sees the
        // return address 0x1_0000_0002 at [entry_rsp]. Replicate the page,
        // but with an absolute jump back into the trampoline landing pad
        // instead of `hlt` (we are not an emulator; the host must regain
        // control when the guest returns).
        let bridge_base = unsafe {
            let p = libc::mmap(
                BRIDGE_BASE as *mut _,
                BRIDGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            );
            if p == libc::MAP_FAILED {
                return Err("bridge mmap failed".into());
            }
            p as u64
        };

        let return_magic = unsafe {
            let p = libc::mmap(
                RETURN_PAGE_BASE as *mut _,
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            );
            if p == libc::MAP_FAILED {
                return Err("return thunk mmap failed".into());
            }
            let landing = guest_stack::landing_pad_addr();
            // Byte-exact reference thunk: `callq *%rax` (FF D0) then `hlt`
            // (F4), rest zeros. The guest may read these bytes as data; the
            // hlt fault (SIGSEGV at +2, a privileged instruction) is caught
            // by the crash handler and bounced to the landing pad via a
            // ucontext setjmp — see `guest_hlt_catch`.
            let mut code = [0u8; 16];
            code[0] = 0xFF;
            code[1] = 0xD0;
            code[2] = 0xF4;
            std::ptr::copy_nonoverlapping(code.as_ptr(), p as *mut u8, code.len());
            libc::mprotect(p as *mut _, 0x1000, libc::PROT_READ | libc::PROT_EXEC);
            guest_stack::set_landing(landing);
            RETURN_PAGE_BASE + 2 // the `call` in the reference pushes start+2
        };
        unsafe { guest_stack::set_return_magic(return_magic) };

        Ok(SapRuntime {
            _corefp: corefp,
            _commerce_core: commerce_core,
            commerce_kit,
            init_addr,
            exchange_addr,
            sign_addr,
            teardown_addr,
            dispose_addr,
            scratch,
            guest_stack_top,
            bridge_cursor: bridge_base,
            bridge_base,
            context: 0,
        })
    }

    /// Allocate the next bridge page (reference-style one page per argument
    /// buffer; the cursor only grows).
    fn next_bridge_page(&mut self) -> u64 {
        let page = self.bridge_cursor;
        self.bridge_cursor += 0x1000;
        page
    }

    /// FairPlaySAPInit: `(ctx_out, hw_info)` where hw_info is the 24-byte
    /// `FairPlayHWInfo` block (u32 length + up to 20 bytes of MAC).
    pub fn init(&mut self, mac: [u8; 6]) -> Result<u64, String> {
        self.init_inner(mac)
    }

    fn init_inner(&mut self, mac: [u8; 6]) -> Result<u64, String> {
        let mut hw_block = [0u8; 24];
        hw_block[0..4].copy_from_slice(&6u32.to_le_bytes());
        hw_block[4..10].copy_from_slice(&mac);

        // Bridge layout, replicating the reference emulator's page-per-arg
        // allocation: init gets ctx @0x600000000000 and hw @0x600000001000.
        let ctx_field = self.next_bridge_page();
        let hw_addr = self.next_bridge_page();
        unsafe {
            std::ptr::copy_nonoverlapping(hw_block.as_ptr(), hw_addr as *mut u8, 24);
            std::ptr::write_bytes(ctx_field as *mut u8, 0, 8);
        }

        let rc = unsafe {
            guest_call_on_stack(self.init_addr, self.guest_stack_top, &[ctx_field, hw_addr])
        };
        if rc != 0 {
            return Err(format!("SAPInit returned {rc}"));
        }
        let ctx = unsafe { std::ptr::read(ctx_field as *const u64) };
        if ctx == 0 {
            return Err("SAPInit produced a null context".into());
        }
        self.context = ctx;
        Ok(ctx)
    }

    /// FairPlaySAPExchange — the server round-trip envelope. Returns
    /// `(output, state)`.
    pub fn exchange(
        &mut self,
        version: u64,
        mac: [u8; 6],
        input: &[u8],
    ) -> Result<(Vec<u8>, i32), String> {
        if self.context == 0 {
            return Err("SAP not initialized".into());
        }
        let mut hw_block = [0u8; 24];
        hw_block[0..4].copy_from_slice(&6u32.to_le_bytes());
        hw_block[4..10].copy_from_slice(&mac);

        // Bridge pages, mirroring the reference allocation order for
        // exchange: hw, iBuf, oPtr, oLen, rc — one page each.
        if input.len() > 0x1000 {
            return Err("exchange input too large".into());
        }
        let hw_addr = self.next_bridge_page();
        let in_addr = self.next_bridge_page();
        let out_ptr_f = self.next_bridge_page();
        let out_len_f = self.next_bridge_page();
        let rc_f = self.next_bridge_page();
        unsafe {
            std::ptr::copy_nonoverlapping(hw_block.as_ptr(), hw_addr as *mut u8, 24);
            std::ptr::copy_nonoverlapping(input.as_ptr(), in_addr as *mut u8, input.len());
            std::ptr::write_bytes(out_ptr_f as *mut u8, 0, 8);
            std::ptr::write_bytes(out_len_f as *mut u8, 0, 8);
            std::ptr::write_bytes(rc_f as *mut u8, 0, 4);
        }

        let rc = unsafe {
            guest_call_on_stack(
                self.exchange_addr,
                self.guest_stack_top,
                &[
                    version,
                    hw_addr,
                    self.context,
                    in_addr,
                    input.len() as u64,
                    out_ptr_f,
                    out_len_f,
                    rc_f,
                ],
            )
        };
        if rc != 0 {
            return Err(format!("SAPExchange returned {rc}"));
        }
        // Read the output BEFORE disposing: the guest writes the pointer/length
        // pair through the oPtr/oLen bridge pages.
        let (ptr, len) = unsafe {
            (
                std::ptr::read(out_ptr_f as *const u64),
                std::ptr::read(out_len_f as *const u64),
            )
        };
        let out = if len == 0 {
            Vec::new()
        } else if ptr == 0 || len > 16 << 20 {
            return Err(format!("bad output block ptr={ptr:#x} len={len}"));
        } else {
            let mut v = vec![0u8; len as usize];
            unsafe {
                std::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len as usize)
            };
            v
        };
        // Dispose with the BRIDGE PAGE address — exactly the reference's
        // `FairPlayDisposeStorage(oPtrBridge.Addr())`, not the returned heap
        // pointer: the guest's dispose classifies its argument (heap vs
        // non-heap bridge page), and that classification feeds the obfuscated
        // state spray (observed: a heap-pointer arg leaves state+0x2e8's
        // low byte at 0x90 where the reference has 0x02).
        let rc2 =
            unsafe { guest_call_on_stack(self.dispose_addr, self.guest_stack_top, &[out_ptr_f]) };
        if rc2 != 0 {
            return Err(format!("DisposeStorage returned {rc2}"));
        }
        let state = unsafe { std::ptr::read(rc_f as *const i32) };
        Ok((out, state))
    }

    /// FairPlaySAPSign over arbitrary bytes.
    pub fn sign(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        if self.context == 0 {
            return Err("SAP not initialized".into());
        }
        // Bridge pages, mirroring the reference allocation order for sign:
        // iBuf, oPtr, oLen — one page each.
        if input.len() > 0x1000 {
            return Err("sign input too large".into());
        }
        let in_addr = self.next_bridge_page();
        let out_ptr_f = self.next_bridge_page();
        let out_len_f = self.next_bridge_page();
        unsafe {
            std::ptr::copy_nonoverlapping(input.as_ptr(), in_addr as *mut u8, input.len());
            std::ptr::write_bytes(out_ptr_f as *mut u8, 0, 8);
            std::ptr::write_bytes(out_len_f as *mut u8, 0, 8);
        }

        let rc = unsafe {
            guest_call_on_stack(
                self.sign_addr,
                self.guest_stack_top,
                &[
                    self.context,
                    in_addr,
                    input.len() as u64,
                    out_ptr_f,
                    out_len_f,
                ],
            )
        };
        if rc != 0 {
            return Err(format!("SAPSign returned {rc}"));
        }
        // Read the output block, then dispose with the BRIDGE PAGE address
        // (the reference's FairPlaySAPSign disposes oPtrBridge.Addr(), same
        // convention as exchange — see the comment there).
        let (ptr, len) = unsafe {
            (
                std::ptr::read(out_ptr_f as *const u64),
                std::ptr::read(out_len_f as *const u64),
            )
        };
        let out = if len == 0 {
            Vec::new()
        } else if ptr == 0 || len > 16 << 20 {
            return Err(format!("bad output block ptr={ptr:#x} len={len}"));
        } else {
            let mut v = vec![0u8; len as usize];
            unsafe {
                std::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len as usize)
            };
            v
        };
        let rc2 =
            unsafe { guest_call_on_stack(self.dispose_addr, self.guest_stack_top, &[out_ptr_f]) };
        if rc2 != 0 {
            return Err(format!("DisposeStorage returned {rc2}"));
        }
        Ok(out)
    }

    /// Tear down the live context.
    pub fn teardown(&mut self) -> Result<(), String> {
        if self.context == 0 {
            return Ok(());
        }
        let rc = unsafe {
            guest_call_on_stack(self.teardown_addr, self.guest_stack_top, &[self.context])
        };
        self.context = 0;
        if rc != 0 {
            return Err(format!("SAPTeardown returned {rc}"));
        }
        Ok(())
    }

    pub fn entry_report(&self) -> String {
        format!(
            "SAPInit={:#x} SAPExchange={:#x} SAPSign={:#x} SAPTeardown={:#x} DisposeStorage={:#x} (CommerceKit @ {:#x})",
            self.init_addr,
            self.exchange_addr,
            self.sign_addr,
            self.teardown_addr,
            self.dispose_addr,
            self.commerce_kit.base() as u64
        )
    }
}

// ── the server protocol ──────────────────────────────────────────────────
//
// Endpoints mirror Apple's Store bag (majd/ipatool carries the same wiring):
//   sign-sap-setup-cert: https://s.mzstatic.com/sap/setupCert.plist
//   sign-sap-setup:      https://fpinit.itunes.apple.com/v1/signSapSetup/legacy
// The plist envelope holds the exchange buffers under fixed keys.

const SETUP_CERT_URL: &str = "https://s.mzstatic.com/sap/setup.crt";
const SETUP_URL: &str = "https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/signSapSetup";
const SETUP_KEY: &str = "sign-sap-setup-buffer";

fn plist_extract(buffer: &[u8], key: &str) -> Option<Vec<u8>> {
    // Minimal plist <data> extraction: find <key>K</key><data>BASE64</data>.
    let text = String::from_utf8_lossy(buffer);
    let key_pat = format!("<key>{key}</key>");
    let k = text.find(&key_pat)?;
    let rest = &text[k + key_pat.len()..];
    let d = rest.find("<data>")?;
    let e = rest[d + 6..].find("</data>")?;
    let b64 = rest[d + 6..d + 6 + e].replace(['\n', '\r', ' '], "");
    base64_decode(b64.as_bytes())
}

fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in input {
        let v = if b == b'=' {
            break;
        } else {
            TABLE.iter().position(|&t| t == b)? as u32
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn http_get(url: &str) -> Result<Vec<u8>, String> {
    // Minimal HTTPS GET without pulling a TLS stack into the CLI: shell out
    // to curl. The protocol step is not perf-critical.
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "--fail",
            "-H",
            "User-Agent: Configurator/2.15 (Macintosh; OS X 14.2; 16C68)",
            url,
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "GET {url}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

fn http_post_plist(url: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let body = format!(
        "<?xml version=\"1.0\"?><plist><dict><key>{SETUP_KEY}</key><data>{}</data></dict></plist>",
        base64_encode(data),
    );
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "--fail",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/x-plist",
            "-H",
            "User-Agent: Configurator/2.15 (Macintosh; OS x 14.2; 16C68)",
            "--data-binary",
            &body,
            url,
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "POST {url}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(TABLE[(n >> 18 & 63) as usize] as char);
        out.push(TABLE[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

impl SapRuntime {
    /// Full SAP setup: certificate fetch + two exchange rounds. After this,
    /// the context holds session keys and `sign` produces real signatures.
    /// The CLI uses [`Self::setup_with_cert`] with a speculatively fetched
    /// certificate; this synchronous variant stays part of the public API.
    #[allow(dead_code)]
    pub fn setup(&mut self, mac: [u8; 6]) -> Result<(), String> {
        self.setup_inner(mac)
    }

    /// Variant of [`Self::setup`] consuming an already-fetched certificate
    /// (see the CLI's speculative download thread). Same validation and
    /// exchange flow; the only difference is where the bytes come from.
    pub fn setup_with_cert(
        &mut self,
        mac: [u8; 6],
        prefetched_cert: Vec<u8>,
    ) -> Result<(), String> {
        if prefetched_cert.len() < 64 {
            return Err(format!(
                "setup.crt is suspiciously short: {}",
                prefetched_cert.len()
            ));
        }
        self.setup_with_cert_inner(mac, prefetched_cert)
    }

    fn setup_inner(&mut self, mac: [u8; 6]) -> Result<(), String> {
        // Legacy 10.9 protocol: the certificate is a raw DER blob served
        // straight from the CDN; no plist envelope at this step.
        let cert = http_get(SETUP_CERT_URL)?;
        if cert.len() < 64 {
            return Err(format!("setup.crt is suspiciously short: {}", cert.len()));
        }
        self.setup_with_cert_inner(mac, cert)
    }

    fn setup_with_cert_inner(&mut self, mac: [u8; 6], cert: Vec<u8>) -> Result<(), String> {
        let (req1, st1) = self.exchange(200, mac, &cert)?;
        if st1 != 1 {
            return Err(format!("exchange(cert) state {st1} != 1"));
        }
        eprintln!("[sap] exchange round 1 ok ({} bytes)", req1.len());

        let reply_plist = http_post_plist(SETUP_URL, &req1)?;
        let reply = plist_extract(&reply_plist, SETUP_KEY)
            .ok_or("setup reply is missing the exchange buffer")?;
        eprintln!("[sap] round 2 reply: {} bytes", reply.len());

        let (_req2, st2) = self.exchange(200, mac, &reply)?;
        if st2 != 0 {
            return Err(format!("exchange(setup) state {st2} != 0"));
        }
        Ok(())
    }
}

impl Drop for SapRuntime {
    fn drop(&mut self) {
        let _ = self.teardown();
        unsafe {
            libc::munmap(self.scratch as *mut _, SCRATCH_SIZE);
            libc::munmap(GUEST_STACK_BASE as *mut _, GUEST_STACK_SIZE);
            libc::munmap(self.bridge_base as *mut _, BRIDGE_SIZE);
            libc::munmap(RETURN_PAGE_BASE as *mut _, 0x1000);
        }
    }
}

struct CoreResolver {
    /// The shim table is fully deterministic once the CoreFP export
    /// addresses are known, so it is built once and reused for every import
    /// lookup instead of being reconstructed per bind (the fixup pass walks
    /// tens of thousands of entries per image).
    table: HashMap<String, usize>,
}

impl CoreResolver {
    fn new(corefp_exports: &HashMap<String, u64>) -> Self {
        Self {
            table: perun_shims::mach::mach_shim_table(corefp_exports),
        }
    }
}

impl MachImportResolver for CoreResolver {
    fn resolve(&self, symbol: &str) -> Option<usize> {
        self.table.get(symbol).copied()
    }
}
