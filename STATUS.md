# STATUS: Perun native PE micro-runtime

## What works

`perun run <image.dll>` on Apple's `CoreADI64.dll` (iTunes for Windows,
x86_64, statically linked MSVC CRT):

- PE32+ headers and all 7 sections mapped at the preferred base `0x7c800000`
  via `mmap(MAP_FIXED)`, per-page protections applied.
- Base relocations applied (delta is 0 when the preferred base is free).
- All imports resolved against the shim table; unresolved ones land on
  absolute-jump trap micro-stubs that report the missing symbol instead of
  crashing.
- Per-thread FakeTEB installed behind `GS_BASE` (`arch_prctl(ARCH_SET_GS)`);
  `FS` left untouched for glibc. FLS backed by the TEB inline TLS slots.
- `DllMain(DLL_PROCESS_ATTACH)` returns **TRUE** with zero unresolved-import
  traps. 106 Win32 APIs implemented.
- `cargo test`: 9/9 passing. Debug and release profiles both build clean.

## Invariants

- No Wine, no QEMU, no instruction emulation. Guest code executes natively on
  the CPU; overhead exists only at each Win32 boundary crossing.
- Shims are plain Rust functions compiled as `extern "win64"`; a resolved
  import is a direct `call`. No per-call trampoline for implemented APIs.
- Trap stubs use an absolute `jmp [rip+0]` with an embedded 64-bit target,
  never `jmp rel32` (the RWX stub page and the dispatcher can be terabytes
  apart under ASLR; rel32 only reaches ±2 GB).
- The proprietary DLL is never committed or distributed; it is obtained
  locally by the user (see `prototype/README.md`).

## The wall (resolved)

The original blocker was `DllMain` returning `FALSE` in the C prototype. The
Rust rewrite got past it: the failure was not guest logic but two runtime
defects, both now fixed.

1. **Trap-stub reach.** Stubs jumped to the dispatcher with `jmp rel32`, but
   the RWX stub page (`mmap(NULL)`) and the main binary land far apart under
   ASLR (measured ~34 TB). The rel32 displacement overflowed and the jump
   landed in unmapped memory → SIGSEGV. Fixed by switching to an absolute
   `jmp [rip+0]` with the dispatcher address embedded in the stub.
2. **Missing CRT APIs.** `GetStartupInfoW`, `GetACP`, `FlsAlloc/GetValue/
   SetValue/Free`, and `InitializeCriticalSectionEx` were unimplemented; the
   MSVC CRT needs them during DLL init. All implemented.

## Ways forward

- Call the ADI dispatcher export (`cvu8io98wun`, RVA `0xe4b00`) with
  provisioning parameters once DllMain init is confirmed stable across
  repeated runs.
- Grow the shim surface as real guests exercise more APIs (the trap reporter
  names each missing symbol with its arguments).
- `perun scaffold` command to generate a ready-to-fill shim stub from a trap
  report.

## Repo map

- `crates/perun-core` — PE32+ parser, loader, relocations, IAT patching,
  TEB/PEB, trap-stub pool.
- `crates/perun-shims` — Win32→POSIX translation matrix (memory, files, sync,
  strings/env, registry, process, SEH/TLS/FLS).
- `crates/perun-cli` — `perun run` / `perun info` runner.
- `prototype/` — historical C proof of concept (reference only, not built by
  cargo).

## Reproduce

```bash
cargo build --release -p perun-cli
./target/release/perun info  /path/to/CoreADI64.dll
./target/release/perun run   /path/to/CoreADI64.dll --verbose
```

---

## Legal & Research License

The reverse-engineering documentation, protocol invariant analysis, and
architectural research in this document are licensed under
[Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
The code implementation is licensed under the
[Apache License, Version 2.0](LICENSE) with [`NOTICE`](NOTICE).
