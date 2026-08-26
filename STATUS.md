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
  param NULL -> `0xffff5036` (invalid param); param non-null -> provisioning
  loader path.
- The command code (`rcx`) is run through an obfuscated arithmetic transform
  and stored for a second-level dispatch that only runs once provisioning
  passes.
- Default error `0xffff5036` is loaded at entry; `0xffff5016` overrides it on
  the not-provisioned path.

### What the gate actually is (measured, not guessed)

- The gate global is the qword at RVA `0x19dda0` (.data). It is read via an
  obfuscated pointer table at RVA `0x17eca0` (entry `[0x157]` =
  `real + 0x4f7e9322`). The check at RVA `0x5b20f` is a double dereference:
  `cmp qword ptr [table[idx] - 0x4f7e9322], 0`.
- At runtime the global holds a host heap pointer to a 0x28-byte object the
  guest allocates during the call itself (`HeapAlloc(0x28, flags=0)`, one of
  three consecutive same-size allocations before the dir walk). The object's
  first qword is the flag the gate reads; `[0x8]` is set to 1 by the guest
  right after allocation; `[0x10]`, `[0x18]`, `[0x20]` are pointers into a
  small graph of sub-allocations.
- Late-fill experiment (PERUN_HEAP_FILL + re-write at the last pre-gate shim
  call): writing a sentinel into every candidate object leaves `[0]=sentinel`
  in the exact object the global points at, yet the return stays
  `0xffff5016`. So trampoline `0x66c2d` is the shared failure exit of a
  multi-object validation: the context is a small object graph and the gate
  validates it as a whole, not as a single flag.
- The provisioning loader walks `<CommonAppData>\Apple Computer\iTunes\adi`
  (via `SHGetFolderPathW` + `PathAppendW` + `PathIsDirectoryW` +
  `GetFileAttributesW`) but returns `0xffff5016` whether or not `adi` exists,
  and never opens a file. The blob filename is built at runtime (obfuscated);
  it is not a static string.
- All real file I/O (`CreateFileW`/`ReadFile`/`WriteFile`/`SetFilePointerEx`)
  is concentrated in routines at RVA `0x1339d0`-`0x13f6c5`, reached only after
  the gate passes.

### Cross-reference with prior ADI/FairPlay research

This matches the documented ADI error family: `0xffff5016` = signed `-45034`,
adjacent to `-45061 kADINotProvisioned` ("ADI machine not provisioned,
expected pre-init"). The circular dependency is already characterized:

```
bag-request -> needs FairPlay context
InitContext -> needs FPDICreate
FPDICreate  -> needs subscription bag from server
bag-request -> needs context        <- cycle
```

The real app breaks the cycle by calling
`fpinit.itunes.apple.com/v1/fpdi/init` and `/v1/fpdi/setup` (with GSA session
tokens) **before** any native FairPlay call. The provisioning blob is
device-specific cryptographic material issued during that handshake. On a
fresh offline system there is no blob, so ADI faithfully reports
not-provisioned. This is the SAP/PAT commerce gate the project exists to
understand.

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

The gate cannot be passed offline by poking memory (verified). Two
error-reporting trampolines were identified and neutralized in memory:
`mov edi,0xffff5016` at RVA `0x66c2d` (executed; found via sentinel patching,
the only one of 37 sites that runs for cmd=0) and `mov edi,0xffff5026` at RVA
`0xb5b49` (the next failure exit, exposed once the first was zeroed). Zeroing
both makes cmd=0 return `0x0`, but the success is hollow: no output is
written and no additional API fires — the trampolines are reporting stubs on a
fixed not-provisioned path, not branch selectors. CoreADI64.dll also imports
no network APIs (KERNEL32/ADVAPI32/SHLWAPI/SHELL32 only): the fpinit handshake
lives in the caller (iTunes), not here. Realistic paths:

1. **Obtain a real provisioning blob** from a provisioned machine
   (`C:\ProgramData\Apple Computer\iTunes\adi\`), then feed it to the loader.
   This is the direct oracle: it reveals every context field the dispatcher
   reads after the gate.
2. **Replicate the server handshake** (`fpinit.itunes.apple.com/v1/fpdi/init`
   + `/setup`) in the caller layer to provision a fresh machine, matching how
   the real app breaks the circular dependency. Requires GSA session tokens
   and the exact request format (see the AMSKit Java-layer notes).
3. **Reconstruct the context object graph**: the gate object references three
   sub-allocations; mapping every field the validator touches across the graph
   would enumerate what a real blob must contain — expensive against control-
   flow flattening.
4. Grow the shim surface as real guests exercise more APIs (the trap reporter
   names each missing symbol with its arguments).
5. `perun scaffold` command to generate a ready-to-fill shim stub from a trap
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
