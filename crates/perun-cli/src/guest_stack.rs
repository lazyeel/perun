// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Guest-stack trampoline: run a SAP entry point on a dedicated mmap'd
//! stack, replicating the reference emulator's entry state byte for byte.
//!
//! The reference emulator enters the guest through a one-page thunk:
//! `callq *%rax; hlt` mapped at 0x1_0000_0000. Its `call` pushes the
//! return address 0x1_0000_0002 — the value the guest sees at [rsp] on
//! entry — and the SAP arguments live in registers (≤6 args) or in stack
//! slots the reference pushed just below. The obfuscated CommerceKit
//! code folds these entry-frame bytes into its scratch-pointer
//! arithmetic (measured: a 16-byte entry shift moves every later frame),
//! so the entry frame must match exactly:
//!
//! - ≤6 guest args: entry_rsp = rsp0-8,  [rsp0-8]  = RETURN_MAGIC
//! - 7 args:        entry_rsp = rsp0-16, [rsp0-16] = MAGIC, [rsp0-8] = a6
//! - 8 args:        entry_rsp = rsp0-24, [rsp0-24] = MAGIC, [rsp0-16] = a6,
//!                  [rsp0-8] = a7
//!
//! `RETURN_MAGIC` is a mapped thunk page whose code jumps back to the
//! landing pad, so a guest `ret` lands in the trampoline epilogue.
//!
//! Host ABI (SysV): (fn, rsp0, nargs, a0, a1, a2, a3, a4, a5, a6, a7) —
//! fn=rdi, rsp0=rsi, nargs=rdx, a0=rcx, a1=r8, a2=r9, a3..a7 on the host
//! stack after the return address (a3 at [rbp+16]).
core::arch::global_asm!(
    "
    .text
    .globl perun_guest_trampoline_ex
    .type perun_guest_trampoline_ex, @function
perun_guest_trampoline_ex:
    // ---- host prologue: frame + callee-saved ----
    push   rbp
    mov    rbp, rsp
    push   rbx
    push   r12
    push   r13
    push   r14
    push   r15
    // rbx = fn, r12 = rsp0, r14 = nargs
    mov    rbx, rdi
    mov    r12, rsi
    mov    r14, rdx
    // guest args: a0..a5 -> rdi, rsi, rdx, rcx, r8, r9
    mov    rdi, rcx               // a0
    mov    rsi, r8                // a1
    mov    rdx, r9                // a2
    mov    rcx, [rbp + 16]        // a3
    mov    r8,  [rbp + 24]        // a4
    mov    r9,  [rbp + 32]        // a5
    mov    r13, [rbp + 40]        // a6
    mov    r15, [rbp + 48]        // a7
    // r11 = stack-arg bytes: 0 (nargs<=6), 8 (==7), 16 (==8)
    xor    r11d, r11d
    cmp    r14, 6
    jbe    .Lperun_guest_entry
    mov    r11d, 8
    cmp    r14, 7
    jbe    .Lperun_guest_entry
    mov    r11d, 16
.Lperun_guest_entry:
    // r10 = entry_rsp = rsp0 - 8 - stack_arg_bytes
    lea    r10, [r12 - 8]
    sub    r10, r11
    // [entry_rsp] = RETURN_MAGIC (a raw address kept in a data symbol)
    lea    rax, [rip + perun_guest_return_magic]
    mov    rax, [rax]
    mov    [r10], rax
    // a6 at [entry_rsp+8] when nargs >= 7
    cmp    r14, 7
    jb     .Lperun_guest_go
    mov    [r10 + 8], r13
    // a7 at [entry_rsp+16] when nargs == 8
    cmp    r14, 8
    jb     .Lperun_guest_go
    mov    [r10 + 16], r15
.Lperun_guest_go:
    // Mirror the reference emulator register state at entry: Unicorn
    // starts every guest run with all registers zero; the obfuscated
    // dispatcher reads uninitialized registers, so host leftovers change
    // the flattened control flow. Zero everything except guest args and
    // the entry stack pointer. rax = fn (the reference leaves the
    // callq-rax operand in rax). The host frame pointer is stashed in
    // a data slot; the guest zeroes rbp, and the landing pad needs the
    // host frame to unwind back.
    lea    r11, [rip + perun_guest_host_rsp]
    mov    [r11], rbp
    mov    rax, rbx
    xor    ebx, ebx
    xor    ebp, ebp
    xor    r11d, r11d
    xor    r12d, r12d
    xor    r13d, r13d
    xor    r14d, r14d
    xor    r15d, r15d
    mov    rsp, r10                // entry_rsp lives in r10; zero it after
    xor    r10d, r10d
    jmp    rax                     // enter the guest

.Lperun_guest_landing:
    // ---- guest returned; rax holds the result ----
    lea    r11, [rip + perun_guest_host_rsp]
    mov    rbp, [r11]
    lea    rsp, [rbp - 40]        // back to the saved rbx/r12/r13/r14/r15
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    pop    rbx
    pop    rbp
    ret

    .globl perun_guest_landing
perun_guest_landing = .Lperun_guest_landing

    .data
    .align 8
    .globl perun_guest_return_magic
perun_guest_return_magic:
    .quad 0
    .globl perun_guest_host_rsp
perun_guest_host_rsp:
    .quad 0
    ",
);

extern "C" {
    static perun_guest_return_magic: u64;
    // Referenced from the inline-asm trampoline below (lea r11, [rip +
    // perun_guest_host_rsp]); the compiler cannot see that use.
    #[allow(dead_code)]
    static perun_guest_host_rsp: u64;
}

extern "C" {
    fn perun_guest_landing();
}

/// The trampoline's landing-pad address (the code the guest returns into).
pub fn landing_pad_addr() -> u64 {
    perun_guest_landing as *const () as u64
}

thread_local! {
    static LANDING: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Record the landing-pad address for the SIGSEGV hlt catch.
pub fn set_landing(addr: u64) {
    LANDING.with(|l| l.set(addr));
}

/// The recorded landing-pad address (0 until `set_landing`).
pub fn get_landing() -> u64 {
    LANDING.with(|l| l.get())
}

/// Set the magic return address the guest sees at [entry_rsp]. Must point
/// at a mapped thunk (`jmp .Lperun_guest_landing` equivalent).
///
/// # Safety
/// The thunk page must stay mapped for the process lifetime.
pub unsafe fn set_return_magic(addr: u64) {
    unsafe {
        core::ptr::write_volatile((&raw const perun_guest_return_magic) as *mut u64, addr);
    }
}

/// Enter `fn` with the guest SysV ABI on the dedicated guest stack,
/// replicating the reference emulator's entry frame.
///
/// # Safety
/// `rsp0` must be the 16-byte-aligned top edge of a mapped region of at
/// least 8 MiB, and the guest function must return normally.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn guest_trampoline(f: u64, rsp0: u64, nargs: usize, a: [u64; 8]) -> i64 {
    extern "C" {
        fn perun_guest_trampoline_ex();
    }
    let go: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) -> i64 =
        unsafe { std::mem::transmute(perun_guest_trampoline_ex as *const ()) };
    unsafe {
        go(
            f,
            rsp0,
            nargs as u64,
            a[0],
            a[1],
            a[2],
            a[3],
            a[4],
            a[5],
            a[6],
            a[7],
        )
    }
}
