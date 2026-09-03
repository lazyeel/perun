// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! macOS libSystem shim surface for Mach-O guests, mirroring the Win32
//! translation matrix for PE guests.
//!
//! Three layers, matching what the 2013 CoreFP/CommerceKit pair actually
//! imports:
//!
//! 1. **libc passthrough** — `malloc`, `memcpy`, `pthread_*`, `getenv`…
//!    forwarded straight to the host libc: same SysV ABI on both sides, so
//!    a direct function pointer works.
//! 2. **CoreFoundation / IOKit / DiskArbitration stubs** — the reference
//!    interposer for these binaries (t0rr3sp3dr0/sapsigner) proved the guest
//!    only needs degenerate answers here: null handles, empty strings,
//!    fake-but-stable registry entries. We return the same shape natively.
//! 3. **The ICXS service** — CoreFP reads its key material through
//!    `open()`/`read()` on `./../CoreFP.icxs`; the shim serves those two
//!    calls from an in-memory copy and fails everything else.
//!
//! Unimplemented imports land on SysV trap micro-stubs (see `stub.rs`),
//! so the first guest call reports the missing symbol instead of crashing.

use std::collections::HashMap;
use std::sync::Mutex;

/// The full ICXS blob served through the fake `open`/`read` path.
pub struct Icxs {
    pub data: Vec<u8>,
}

/// Descriptor CoreFP gets from `open("./../CoreFP.icxs")`.
const ICXS_FD: i32 = 3;

struct MachState {
    icxs: Vec<u8>,
    icxs_cursor: usize,
    /// IOKit iterator toggle: the guest loops until IOIteratorNext returns 0.
    iterator: u64,
}

static STATE: Mutex<Option<MachState>> = Mutex::new(None);

fn with_state<T>(f: impl FnOnce(&mut MachState) -> T) -> T {
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let st = guard.get_or_insert_with(|| MachState {
        icxs: Vec::new(),
        icxs_cursor: 0,
        iterator: 0,
    });
    f(st)
}

/// Install the ICXS blob before loading CoreFP.
pub fn set_icxs(data: Vec<u8>) {
    with_state(|st| {
        st.icxs = data;
        st.icxs_cursor = 0;
    });
}

// ── libc passthrough ───────────────────────────────────────────────────────
//
// Same SysV ABI on host and guest: export the host symbol directly.

unsafe extern "C" {
    #[link_name = "memcpy"]
    fn host_memcpy(
        dst: *mut core::ffi::c_void,
        src: *const core::ffi::c_void,
        n: usize,
    ) -> *mut core::ffi::c_void;
    #[link_name = "memmove"]
    fn host_memmove(
        dst: *mut core::ffi::c_void,
        src: *const core::ffi::c_void,
        n: usize,
    ) -> *mut core::ffi::c_void;
    #[link_name = "memset"]
    fn host_memset(dst: *mut core::ffi::c_void, c: i32, n: usize) -> *mut core::ffi::c_void;
    #[link_name = "memcmp"]
    fn host_memcmp(a: *const core::ffi::c_void, b: *const core::ffi::c_void, n: usize) -> i32;
    #[link_name = "strlen"]
    fn host_strlen(s: *const core::ffi::c_char) -> usize;
    #[link_name = "strcmp"]
    fn host_strcmp(a: *const core::ffi::c_char, b: *const core::ffi::c_char) -> i32;
    #[link_name = "strncmp"]
    fn host_strncmp(a: *const core::ffi::c_char, b: *const core::ffi::c_char, n: usize) -> i32;
}

/// Delegate the symbol to the host libc function with the same name.
/// Registers `(name, ptr)` pairs for the passthrough set.
macro_rules! passthrough {
    ($map:expr, $name:expr, $sym:expr) => {
        $map.insert(
            $name.to_string(),
            $crate::mach::pinned_shim($sym as *const () as usize, $name),
        );
    };
}

/// Build the full Mach-O import resolution table. `corefp_exports` maps the
/// six obfuscated FairPlay names (leading underscore included) to their
/// native addresses inside the loaded CoreFP image — this is how
/// `_dlsym` answers CoreFP's runtime self-lookup.
pub fn mach_shim_table(corefp_exports: &HashMap<String, u64>) -> HashMap<String, usize> {
    let mut m: HashMap<String, usize> = HashMap::new();

    // Heap family: the reference runtime's arena model (fixed span, size
    // prefix, malloc_good_size alignment), because CoreFP calls
    // malloc_size/free with expectations about the allocator's layout.
    m.insert(
        "_malloc".to_string(),
        pinned_shim(shim_malloc as *const () as usize, "shim_malloc"),
    );
    m.insert(
        "_calloc".to_string(),
        pinned_shim(shim_calloc as *const () as usize, "shim_calloc"),
    );
    m.insert(
        "_realloc".to_string(),
        pinned_shim(shim_realloc as *const () as usize, "shim_realloc"),
    );
    m.insert(
        "_reallocf".to_string(),
        pinned_shim(shim_realloc as *const () as usize, "shim_realloc"),
    );
    m.insert(
        "_free".to_string(),
        pinned_shim(shim_free as *const () as usize, "shim_free"),
    );
    m.insert(
        "_malloc_good_size".to_string(),
        pinned_shim(
            shim_malloc_good_size as *const () as usize,
            "shim_malloc_good_size",
        ),
    );
    m.insert(
        "_malloc_size".to_string(),
        pinned_shim(shim_malloc_size as *const () as usize, "shim_malloc_size"),
    );

    passthrough!(m, "_memcpy", host_memcpy);
    passthrough!(m, "_memmove", host_memmove);
    passthrough!(m, "_memset", host_memset);
    passthrough!(m, "_memcmp", host_memcmp);
    passthrough!(m, "_strlen", host_strlen);
    passthrough!(m, "_strcmp", host_strcmp);
    passthrough!(m, "_strncmp", host_strncmp);
    // __bzero(s, n) is TWO-argument — a naive passthrough to host_memset
    // consumed (dst, c=n, len=rdx-garbage): the length became the fill
    // byte and the count came from whatever rdx held (observed: a single
    // 0x06 written into the SAP state block at 0x7ff7b0000580 where the
    // reference's __bzero writes six zero bytes — the one-byte divergence
    // that cascaded into the SAPSign SIGSEGV).
    m.insert(
        "___bzero".to_string(),
        pinned_shim(shim_bzero as *const () as usize, "shim_bzero"),
    );
    passthrough!(m, "___memcpy_chk", host_memcpy);
    passthrough!(m, "___memset_chk", host_memset);

    // pthread / misc process state — one stable pointer each.
    for (name, f) in [
        (
            "_pthread_mutex_lock",
            shim_return_zero as *const () as usize,
        ),
        (
            "_pthread_mutex_unlock",
            shim_return_zero as *const () as usize,
        ),
        (
            "_pthread_rwlock_init",
            shim_return_zero as *const () as usize,
        ),
        (
            "_pthread_rwlock_wrlock",
            shim_return_zero as *const () as usize,
        ),
        (
            "_pthread_rwlock_unlock",
            shim_return_zero as *const () as usize,
        ),
        ("_pthread_self", shim_pthread_self as *const () as usize),
        ("_pthread_once", shim_pthread_once as *const () as usize),
        ("_getenv", shim_getenv as *const () as usize),
        ("_gettimeofday", shim_gettimeofday as *const () as usize),
        ("_arc4random", shim_arc4random as *const () as usize),
        ("_sysctl", shim_return_minus_one as *const () as usize),
        ("_sysctlbyname", shim_sysctlbyname as *const () as usize),
        (
            "_OSAtomicCompareAndSwap32Barrier",
            shim_compare_and_swap32 as *const () as usize,
        ),
        ("___stack_chk_fail", shim_abort as *const () as usize),
        ("_abort", shim_abort as *const () as usize),
        ("_dyld_stub_binder", shim_abort as *const () as usize),
    ] {
        m.insert(name.to_string(), f);
    }
    // errno + stack guard data symbols
    m.insert(
        "___error".to_string(),
        pinned_shim(shim_errno_ptr as *const () as usize, "shim_errno_ptr"),
    );
    m.insert(
        "___stack_chk_guard".to_string(),
        pinned_data_slot("stack_chk_guard", 0xA5713CD98642EF10),
    );
    // CoreFoundation / IOKit / DiskArbitration degenerate answers.
    for (name, f) in [
        (
            "_CFBundleGetMainBundle",
            shim_return_zero as *const () as usize,
        ),
        ("_CFDataGetBytePtr", shim_return_zero as *const () as usize),
        ("_CFDataGetLength", shim_return_zero as *const () as usize),
        (
            "_CFDictionaryGetValue",
            shim_return_fake_handle as *const () as usize,
        ),
        ("_CFRelease", shim_return_zero as *const () as usize),
        (
            "_CFStringCreateWithCString",
            shim_cfstring_create as *const () as usize,
        ),
        (
            "_CFStringCreateWithCStringNoCopy",
            shim_return_zero as *const () as usize,
        ),
        (
            "_CFStringGetCString",
            shim_cfstring_getcstring as *const () as usize,
        ),
        ("_CFStringGetLength", shim_return_zero as *const () as usize),
        (
            "_CFStringGetMaximumSizeForEncoding",
            shim_return_zero as *const () as usize,
        ),
        (
            "_CFUUIDCreateString",
            shim_return_zero as *const () as usize,
        ),
        (
            "_DADiskCopyDescription",
            shim_return_fake_handle as *const () as usize,
        ),
        (
            "_DADiskCreateFromBSDName",
            shim_return_fake_handle as *const () as usize,
        ),
        (
            "_DASessionCreate",
            shim_return_fake_handle as *const () as usize,
        ),
        (
            "_IORegistryEntryFromPath",
            shim_return_zero as *const () as usize,
        ),
        (
            "_IORegistryEntrySearchCFProperty",
            shim_return_zero as *const () as usize,
        ),
        ("_IOServiceMatching", shim_return_zero as *const () as usize),
        (
            "_IOIteratorNext",
            shim_io_iterator_next as *const () as usize,
        ),
        ("_IOObjectRelease", shim_return_zero as *const () as usize),
        (
            "_IORegistryEntryCreateCFProperty",
            shim_return_fake_handle as *const () as usize,
        ),
        (
            "_IORegistryEntryGetParentEntry",
            shim_io_registry_parent as *const () as usize,
        ),
        (
            "_IOServiceGetMatchingServices",
            shim_return_zero as *const () as usize,
        ),
        (
            "_IOServiceGetMatchingService",
            shim_return_uint32_max as *const () as usize,
        ),
        ("_objc_msgSend", shim_objc_msgsend as *const () as usize),
    ] {
        m.insert(name.to_string(), f);
    }
    // Data symbols the guest dereferences.
    for name in [
        "_kCFAllocatorDefault",
        "_kCFAllocatorNull",
        "_kDADiskDescriptionVolumeUUIDKey",
        "_kIOMasterPortDefault",
    ] {
        m.insert(name.to_string(), zero_qword_ptr() as usize);
    }
    // File I/O: the ICXS service.
    m.insert(
        "_open".to_string(),
        pinned_shim(shim_open as *const () as usize, "shim_open"),
    );
    m.insert(
        "_close".to_string(),
        pinned_shim(shim_return_zero as *const () as usize, "shim_return_zero"),
    );
    m.insert(
        "_read".to_string(),
        pinned_shim(shim_read as *const () as usize, "shim_read"),
    );
    m.insert(
        "_fcntl".to_string(),
        pinned_shim(
            shim_return_minus_one as *const () as usize,
            "shim_return_minus_one",
        ),
    );
    m.insert(
        "_lstat$INODE64".to_string(),
        pinned_shim(shim_statfs as *const () as usize, "shim_statfs"),
    );
    m.insert(
        "_statfs".to_string(),
        pinned_shim(shim_statfs as *const () as usize, "shim_statfs"),
    );
    m.insert(
        "_statfs$INODE64".to_string(),
        pinned_shim(shim_statfs as *const () as usize, "shim_statfs"),
    );
    // dyld: CoreFP self-lookup.
    m.insert(
        "_dlopen".to_string(),
        pinned_shim(shim_dlopen as *const () as usize, "shim_dlopen"),
    );
    m.insert(
        "_dlsym".to_string(),
        pinned_shim(shim_dlsym as *const () as usize, "shim_dlsym"),
    );
    // CoreFP's own obfuscated exports, for its runtime self-lookup.
    for (name, addr) in corefp_exports {
        m.insert(name.clone(), *addr as *const () as usize);
    }

    m
}

// ── shim implementations ─────────────────────────────────────────────────

const FAKE_HANDLE: usize = u64::MAX as usize;

unsafe extern "C" fn shim_return_zero() -> i64 {
    0
}

unsafe extern "C" fn shim_return_fake_handle() -> usize {
    FAKE_HANDLE
}

unsafe extern "C" fn shim_return_uint32_max() -> u32 {
    u32::MAX
}
unsafe extern "C" fn shim_return_minus_one() -> i64 {
    -1
}
unsafe extern "C" fn shim_pthread_self() -> usize {
    0
}

/// statfs(path, buf): the reference emulator's guest stack pages are zero-
/// filled, so an untouched output buffer reads as all zeros there; native
/// execution reuses host stack pages with old contents. Zero the buffer so
/// the guest's volume probing sees the same deterministic emptiness.
unsafe extern "C" fn shim_statfs(
    _path: *const core::ffi::c_char,
    buf: *mut core::ffi::c_void,
) -> i32 {
    if !buf.is_null() {
        std::ptr::write_bytes(buf as *mut u8, 0, 432);
    }
    0
}

unsafe extern "C" fn shim_errno_ptr() -> *mut i32 {
    // Fixed-address cell: __error hands the guest a pointer it may fold into
    // its key material, so the address must be run-independent. One immutable
    // zero cell, at a pinned address.
    pinned_data_slot("errno_cell", 0) as *mut i32
}

/// Fixed-address zero qword: allocator/IOKit constants fold into guest
/// key material, so the pointer value must be run-independent.
fn zero_qword_ptr() -> *const u64 {
    pinned_data_slot("zero_qword", 0) as *const u64
}

unsafe extern "C" fn shim_abort() -> ! {
    eprintln!("[perun] guest called abort/dyld_stub_binder — unreachable path");
    std::process::abort();
}

unsafe extern "C" fn shim_getenv(_name: *const core::ffi::c_char) -> *const core::ffi::c_char {
    // The guest only branches on presence; null is the honest answer for a
    // non-Mac environment.
    core::ptr::null()
}

unsafe extern "C" fn shim_gettimeofday(tv: *mut u8, tz: *mut u8) -> i32 {
    if !tv.is_null() {
        // Fixed timestamp, mirroring the reference interposer: SAP
        // key material must be reproducible across runs.
        tv.cast::<u64>().write_unaligned(1_717_000_000);
        tv.add(8).cast::<u32>().write_unaligned(0);
    }
    if !tz.is_null() {
        std::ptr::write_bytes(tz, 0, 8);
    }
    0
}

unsafe extern "C" fn shim_arc4random() -> u32 {
    // Deterministic zero, matching the reference interposer: the flattened
    // control flow feeds guest entropy into path decisions, so real
    // randomness makes the dispatcher choose branches whose state was never
    // initialized. The SAP protocol supplies its own key material via the
    // server exchange; this value only steers the obfuscated CFG.
    0
}

unsafe extern "C" fn shim_sysctlbyname(
    name: *const core::ffi::c_char,
    _old: *mut core::ffi::c_void,
    oldlen: *mut usize,
    _new: *const core::ffi::c_void,
    _newlen: usize,
) -> i32 {
    // "How many bytes would you like?" — "zero" keeps the guest's UUID
    // plumbing happy without fabricating a serial number.
    if !oldlen.is_null() {
        std::ptr::write(oldlen, 0);
    }
    0
}

unsafe extern "C" fn shim_compare_and_swap32(old: i32, new: i32, ptr: *mut i32) -> bool {
    if ptr.is_null() {
        return false;
    }
    let cur = ptr.read();
    if cur == old {
        ptr.write(new);
        true
    } else {
        false
    }
}

/// CFStringCreateWithCString(alloc, cStr, encoding): hand back a stable
/// fake handle keyed by content; the guest asks for the same keys later
/// via CFStringGetCString and object identity checks.
unsafe extern "C" fn shim_cfstring_create(
    _alloc: *mut core::ffi::c_void,
    cstr: *const core::ffi::c_char,
    _enc: u32,
) -> usize {
    if cstr.is_null() {
        return 0;
    }
    // Mirror the reference interposer: a fake non-null CFString only for
    // the IOPlatform identity keys the FairPlay code probes; everything
    // else gets NULL so the guest takes its absence branches.
    const KEYS: [&[u8]; 3] = [b"IOPlatformSerialNumber", b"IOPlatformUUID", b"board-id"];
    let len = host_strlen(cstr);
    let bytes = std::slice::from_raw_parts(cstr as *const u8, len);
    if KEYS.contains(&bytes) {
        return FAKE_HANDLE;
    }
    0
}

/// CFStringGetCString(cfstr, buffer, bufferSize, encoding): the reference
/// interposer returns true unconditionally and leaves the buffer as the
/// caller prepared it. Not touching the buffer is load-bearing: the guest
/// re-reads buffer bytes it wrote before the call, and zeroing them skews
/// downstream state (observed: state+0x2e8 flips 0x02→0x90, sign picks a
/// fatal scratch-pointer template). Pure passthrough, zero side effects.
unsafe extern "C" fn shim_cfstring_getcstring(
    _cfstr: *const core::ffi::c_void,
    _buffer: *mut core::ffi::c_char,
    _size: usize,
    _enc: u32,
) -> bool {
    true
}

unsafe extern "C" fn shim_io_iterator_next() -> u32 {
    // Mirror the reference interposer exactly: `return --o % 2` with a
    // monotonically decreasing counter. First call yields -1, which as
    // an io_object_t (u32) is 0xFFFFFFFF — a truthy, non-null registry
    // entry; the second yields 0 and terminates the guest's loop. The
    // exact entry value matters: the guest folds it into platform
    // bookkeeping, and a plain 1 diverges from the reference flow.
    with_state(|st| {
        st.iterator = st.iterator.wrapping_sub(1);
        ((st.iterator as i64) % 2) as u32
    })
}

unsafe extern "C" fn shim_io_registry_parent(_entry: u32, parent: *mut u32) -> i32 {
    if parent.is_null() {
        return -1;
    }
    std::ptr::write(parent, u32::MAX);
    0
}

/// objc_msgSend: the only selector the guest sends during SAP signing is
/// `objectForKey:`; answer with the fake handle so dictionary lookups
/// succeed degenerately.
unsafe extern "C" fn shim_objc_msgsend(
    _self: *mut core::ffi::c_void,
    sel: *const core::ffi::c_char,
) -> usize {
    // NOTE: never dereference the guest's selector pointer here — the
    // obfuscated control flow probes shims with junk arguments, and a
    // bounded compare needs raw byte access, not CStr.
    if !sel.is_null() {
        let s = std::ffi::CStr::from_ptr(sel).to_bytes();
        if s == b"objectForKey:" {
            return FAKE_HANDLE;
        }
    }
    0
}

unsafe extern "C" fn shim_dlopen(path: *const core::ffi::c_char, _mode: i32) -> usize {
    if path.is_null() {
        return 0;
    }
    let s = std::ffi::CStr::from_ptr(path).to_bytes();
    if s == b"/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP" {
        FAKE_HANDLE
    } else {
        0
    }
}

/// dlsym(handle, name): answer CoreFP's own six obfuscated exports from the
/// table built at load time.
unsafe extern "C" fn shim_dlsym(_handle: usize, name: *const core::ffi::c_char) -> usize {
    if name.is_null() {
        return 0;
    }
    let s = std::ffi::CStr::from_ptr(name).to_bytes();
    let key = format!("_{}", String::from_utf8_lossy(s));
    DLSYM_TABLE
        .with(|t| t.borrow().get(&key).copied())
        .unwrap_or(0)
}

thread_local! {
    static DLSYM_TABLE: std::cell::RefCell<HashMap<String, usize>> =
        std::cell::RefCell::new(HashMap::new());
}

/// Point `_dlsym` answers at the loaded CoreFP export table.
pub fn set_dlsym_table(corefp_exports: &HashMap<String, u64>) {
    DLSYM_TABLE.with(|t| {
        let mut map = t.borrow_mut();
        map.clear();
        for (name, addr) in corefp_exports {
            map.insert(name.clone(), *addr as usize);
        }
    });
}

// ── the guest heap ────────────────────────────────────────────────────────
//
// Mirrors the reference interposer's allocator: a fixed arena carved out of
// an mmap at a deterministic address, every block prefixed by its size,
// malloc_good_size rounding to alignment. CoreFP's DisposeStorage calls
// free() on pointers this heap handed out, and malloc_size() reads the
// prefix — a host-libc heap would work for free() but not for malloc_size.

const HEAP_BASE: u64 = 0x7FF7_B000_0000;
const HEAP_SIZE: u64 = 0x400_0000; // 64 MB, same span as the reference (0x7FF7B0000000..0x7FF7B4000000)

// Byte-parity port of the reference C allocator: the C interposer keeps
// heap_head/tail/size as plain statics in its own __bss — no TLS, nothing
// implicit — because the obfuscated guest folds shim-frame stack residue
// into its state spray, so the shim's codegen shape is observable.
static HEAP_HEAD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static HEAP_TAIL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// ── fixed-address shim jump table ──────────────────────────────────────────
//
// The obfuscated SAP code reads bound function slots as DATA (pointer
// identity feeds its control-flow decisions), so shims living at
// ASLR-random host addresses make every run diverge from the reference.
// Every shim gets a fixed-address slot: a 12-byte trampoline
// `movabs r11, <real fn>; jmp r11`, and binds point at the slot.

use std::collections::BTreeMap;

const SHIM_TABLE_BASE: u64 = 0x4000_0000_0000;
const SHIM_SLOT_SIZE: usize = 16;

struct ShimTableInner {
    /// Fixed page region, mapped once.
    page: *mut u8,
    /// symbol name -> fixed slot address.
    slots: BTreeMap<String, u64>,
    /// Number of slots allocated.
    count: usize,
}

unsafe impl Send for ShimTableInner {}

static SHIM_TABLE: Mutex<Option<ShimTableInner>> = Mutex::new(None);

fn shim_slot_for(real_fn: usize, name: &str) -> u64 {
    let mut guard = SHIM_TABLE.lock().unwrap_or_else(|e| e.into_inner());
    let inner = guard.get_or_insert_with(|| unsafe {
        let p = libc::mmap(
            SHIM_TABLE_BASE as *mut libc::c_void,
            0x1000 * 32, // 32 pages: 8192 slots, far more than we bind
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        assert!(p != libc::MAP_FAILED, "shim table mmap failed");
        ShimTableInner {
            page: p.cast(),
            slots: BTreeMap::new(),
            count: 0,
        }
    });
    if let Some(&addr) = inner.slots.get(name) {
        return addr;
    }
    let idx = inner.count;
    inner.count += 1;
    let addr = SHIM_TABLE_BASE + (idx as u64) * SHIM_SLOT_SIZE as u64;
    unsafe {
        let slot = inner.page.add(idx * SHIM_SLOT_SIZE);
        let mut code = [0u8; 16];
        code[0..2].copy_from_slice(&[0x49, 0xBB]); // movabs r11, imm64
        code[2..10].copy_from_slice(&(real_fn as u64).to_le_bytes());
        code[10..13].copy_from_slice(&[0x41, 0xFF, 0xE3]); // jmp r11
        std::ptr::copy_nonoverlapping(code.as_ptr(), slot, 13);
    }
    inner.slots.insert(name.to_string(), addr);
    addr
}

/// Wrap a shim in a fixed-address trampoline slot. Use for every guest
/// import resolution so bound pointer VALUES are run-independent.
pub fn pinned_shim(real_fn: usize, name: &str) -> usize {
    shim_slot_for(real_fn, name) as usize
}

/// A fixed-address data slot holding `value`, for symbols the guest
/// dereferences as data (errno cell, allocator constants, guards).
/// Slots live in the same fixed region, past the trampolines.
fn pinned_data_slot(name: &str, value: u64) -> usize {
    use std::sync::OnceLock;
    static SLOTS: OnceLock<std::sync::Mutex<std::collections::BTreeMap<String, u64>>> =
        OnceLock::new();
    let slots = SLOTS.get_or_init(Default::default);
    let mut guard = slots.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(&addr) = guard.get(name) {
        return addr as usize;
    }
    // Carve a zeroed qword in the shim region (trampolines never reach
    // the last page: max 8192 slots × 16B = 128KB < 32 pages minus one).
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    let idx = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let addr = SHIM_TABLE_BASE + 0x1000 * 31 + (idx as u64) * 8;
    unsafe {
        std::ptr::write_unaligned(addr as *mut u64, value);
    }
    guard.insert(name.to_string(), addr);
    addr as usize
}

/// The reference keeps malloc_good_size a separate (never-inlined) function —
/// its call frame is part of the observable shim residue.
#[inline(never)]
fn good_size(size: usize) -> usize {
    // Same rounding as the reference: up to alignof(max_align_t).
    const ALIGN: usize = 16;
    size + (ALIGN - size % ALIGN) % ALIGN
}

unsafe extern "C" fn shim_malloc_good_size(size: usize) -> usize {
    good_size(size)
}

/// __bzero(s, n) — TWO arguments (SysV). Byte-parity port of the reference
/// interposer (`for (it = s; it != s + n; ++it) *it = 0;`); a passthrough to
/// host memset would misread the ABI (length as fill byte, count from rdx).
unsafe extern "C" fn shim_bzero(s: *mut core::ffi::c_void, n: usize) {
    let p = s as *mut u8;
    for i in 0..n {
        unsafe {
            p.add(i).write(0);
        }
    }
}

/// Byte-parity port of the reference C malloc:
///   size_t aligned_size_t_size = malloc_good_size(sizeof(size_t));
///   size_t aligned_size = malloc_good_size(size);
///   if (heap_tail + .. > heap_head + heap_size) { abort(); }
///   *(size_t*)heap_tail = size; ptr = heap_tail + prefix;
///   heap_tail = ptr + aligned; return ptr;
/// No logging, no TLS, no closure — every register-move of the compiled
/// C shape is part of the guest-observable stack residue. The user-block
/// zeroing the old shim did is DROPPED: the reference never zeroes, and
/// fresh mmap pages are already zero.
unsafe extern "C" fn shim_malloc(size: usize) -> *mut core::ffi::c_void {
    let aligned_size_t_size = good_size(core::mem::size_of::<usize>());
    let aligned_size = good_size(size);
    let head = HEAP_HEAD.load(std::sync::atomic::Ordering::Relaxed);
    let tail = HEAP_TAIL.load(std::sync::atomic::Ordering::Relaxed);
    if head == 0 {
        // First call maps the arena, exactly like the emulator's setupHeap.
        unsafe {
            let p = libc::mmap(
                HEAP_BASE as *mut _,
                HEAP_SIZE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            );
            assert!(p != libc::MAP_FAILED, "SAP guest heap mmap failed");
        }
        HEAP_HEAD.store(HEAP_BASE, std::sync::atomic::Ordering::Relaxed);
        HEAP_TAIL.store(HEAP_BASE, std::sync::atomic::Ordering::Relaxed);
        return shim_malloc(size);
    }
    if tail + (aligned_size_t_size as u64) + (aligned_size as u64) > head + HEAP_SIZE {
        return core::ptr::null_mut();
    }
    unsafe {
        let p = tail as *mut usize;
        p.write_unaligned(size);
        let user = tail + aligned_size_t_size as u64;
        HEAP_TAIL.store(
            user + aligned_size as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        user as *mut core::ffi::c_void
    }
}

unsafe extern "C" fn shim_calloc(count: usize, size: usize) -> *mut core::ffi::c_void {
    let total = count.wrapping_mul(size);
    shim_malloc(total)
}

/// Read the size prefix of a heap block.
unsafe fn block_size(user: *mut core::ffi::c_void) -> Option<usize> {
    if user.is_null() {
        return None;
    }
    let prefix = good_size(core::mem::size_of::<usize>()) as u64;
    let base = (user as u64).checked_sub(prefix)?;
    if !(HEAP_BASE..HEAP_BASE + HEAP_SIZE).contains(&base) {
        return None;
    }
    Some(unsafe { (base as *const usize).read_unaligned() })
}

unsafe extern "C" fn shim_malloc_size(ptr: *mut core::ffi::c_void) -> usize {
    unsafe { block_size(ptr).unwrap_or(0) }
}

unsafe extern "C" fn shim_free(_ptr: *mut core::ffi::c_void) {}

unsafe extern "C" fn shim_realloc(
    ptr: *mut core::ffi::c_void,
    new_size: usize,
) -> *mut core::ffi::c_void {
    if ptr.is_null() {
        return shim_malloc(new_size);
    }
    let old = unsafe { block_size(ptr).unwrap_or(0) };
    let dst = shim_malloc(new_size);
    if !dst.is_null() && old > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(ptr as *const u8, dst as *mut u8, old.min(new_size));
        }
    }
    dst
}

// ── the ICXS file service ─────────────────────────────────────────────────

unsafe extern "C" fn shim_open(path: *const core::ffi::c_char, _flags: i32) -> i32 {
    if path.is_null() {
        return -1;
    }
    let s = std::ffi::CStr::from_ptr(path).to_bytes();
    if s == b"./../CoreFP.icxs" {
        with_state(|st| st.icxs_cursor = 0);
        return ICXS_FD;
    }
    -1
}

unsafe extern "C" fn shim_read(fd: i32, buf: *mut core::ffi::c_void, count: usize) -> isize {
    if fd != ICXS_FD || buf.is_null() {
        return -1;
    }
    with_state(|st| {
        let remaining = st.icxs.len().saturating_sub(st.icxs_cursor);
        let n = remaining.min(count);
        if n > 0 {
            std::ptr::copy_nonoverlapping(st.icxs.as_ptr().add(st.icxs_cursor), buf as *mut u8, n);
            st.icxs_cursor += n;
        }
        n as isize
    })
}

/// pthread_once(control, init): run the guest's one-time initializer.
/// The 2013 CommerceKit computes its control-flow-flattening moduli inside
/// these routines; skipping them leaves the dispatch divisors at zero and
/// the first flattened function SIGFPEs. Mirrors the reference interposer:
/// if the control word is nonzero, clear it and call the routine.
///
/// Frame-geometry contract: the obfuscated once-init reads "uninitialized"
/// slots of the CALLING shim's frame, so this function must compile to the
/// O2-C interposer's shape — push rbp, call init, pop rbp, 0x10 total —
/// with zero locals of its own. Debug Rust padded the frame by 0x80 and
/// skewed the guest's scratch-pointer arithmetic past the stack edge;
/// `[profile.dev.package.perun-shims] opt-level = 2` makes LLVM emit the
/// same 16-byte frame as O2 C. Never add logging, allocation, or locals
/// to this function.
#[inline(never)]
unsafe extern "C" fn shim_pthread_once(control: *mut core::ffi::c_void, init: usize) -> i32 {
    if control.is_null() {
        return 0;
    }
    let ctl = control as *mut u64;
    if ctl.read_unaligned() != 0 {
        ctl.write_unaligned(0);
        if init != 0 {
            let f: unsafe extern "C" fn() = std::mem::transmute(init);
            f();
        }
    }
    0
}
