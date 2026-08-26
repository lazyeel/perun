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
  Stack bounds derived from pthread so MSVC `__chkstk` probes the real stack.
- `DllMain(DLL_PROCESS_ATTACH)` returns **TRUE** with zero unresolved-import
  traps. 111 Win32 APIs implemented.
- `cargo test`: 9/9 passing. Debug and release profiles both build clean.

`perun call <image.dll> <export> [args...]` invokes an export through the
Win64 ABI after init. A `scratch` argument token supplies a clean zeroed page
for pointer-backed parameters.

## The ADI dispatcher now runs end-to-end

`perun call CoreADI64.dll vdfut768ig <cmd> scratch` executes the dispatcher's
full provisioning logic and returns a clean ADI error code instead of
crashing. Observed behavior:

- Resolves `<CommonAppData>\Apple Computer\iTunes\adi` via
  `SHGetFolderPathW(CSIDL_COMMON_APPDATA)` + `PathAppendW` +
  `PathIsDirectoryW` + `GetFileAttributesW`, confirming each directory.
- Returns `0xffff5016` (not provisioned) for every command code tested
  (0..255), with no file, registry, mutex, or enumeration access.

This is the trap-and-scaffold design paying off: each missing Win32 API was
surfaced by the trap reporter and implemented in turn until the dispatcher
ran its full logic.

## The provisioning gate (current wall)

The `0xffff5016` result is checked **before** command dispatch and is uniform
across all commands, so it is an in-memory provisioning-state flag, not a
per-command result. The dispatcher's control flow is control-flow-flattened
(obfuscated), but the entry sequence is decoded:

- First-level dispatch is a pure `rdx` NULL check (param present vs null).
- The command code (`rcx`) is run through an obfuscated arithmetic transform
  and stored for a second-level dispatch that only runs once provisioning
  passes.
- Default error `0xffff5036` is loaded at entry; `0xffff5016` overrides it on
  the not-provisioned path.

The provisioning blob is device-specific cryptographic material issued by
Apple during a provisioning handshake. On a fresh offline system there is no
blob, so ADI faithfully reports not-provisioned. This is the SAP/PAT commerce
gate the project exists to understand.

## Invariants

- No Wine, no QEMU, no instruction emulation. Guest code executes natively on
  the CPU; overhead exists only at each Win32 boundary crossing.
- Shims are plain Rust functions compiled as `extern "win64"`; a resolved
  import is a direct `call`. No per-call trampoline for implemented APIs.
- Trap stubs use an absolute `jmp [rip+0]` with an embedded 64-bit target,
  never `jmp rel32` (the RWX stub page and the dispatcher can be terabytes
  apart under ASLR; rel32 only reaches ±2 GB).
- The proprietary DLL is never committed or distributed; it is obtained
  locally by the user (extraction steps are in the README).

## Ways forward

- Feed the dispatcher a valid provisioning context (param struct) to pass the
  in-memory gate, or locate the command that loads/creates the blob.
- Grow the shim surface as real guests exercise more APIs (the trap reporter
  names each missing symbol with its arguments).
- `perun scaffold` command to generate a ready-to-fill shim stub from a trap
  report.

## Repo map

- `crates/perun-core` — PE32+ parser, loader, relocations, IAT patching,
  TEB/PEB, trap-stub pool.
- `crates/perun-shims` — Win32→POSIX translation matrix (memory, files, sync,
  strings/env, registry, process, SEH/TLS/FLS, shell/path).
- `crates/perun-cli` — `perun run` / `perun info` / `perun call` runner.

## Reproduce

```bash
cargo build --release -p perun-cli
./target/release/perun info  /path/to/CoreADI64.dll
./target/release/perun run   /path/to/CoreADI64.dll --verbose
./target/release/perun call  /path/to/CoreADI64.dll vdfut768ig 0 scratch
```

---

## Legal & Research License

The reverse-engineering documentation, protocol invariant analysis, and
architectural research in this document are licensed under
[Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
The code implementation is licensed under the
[Apache License, Version 2.0](LICENSE) with [`NOTICE`](NOTICE).
