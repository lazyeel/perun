# STATUS: Perun native PE micro-runtime

*Phase-1 document (Windows/PE, CoreADI64.dll). The Mach-O FairPlay SAP work
of phase 2 is covered by RESEARCH.md; this file tracks the PE side. Every
claim below reproduces with the shipped binary and stock system tools —
nothing requires rebuilding, patching the source, or one-off scripts. The
verification log at the end gives the exact command for each claim.*

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
- `cargo test`: 11/11 passing. Debug and release profiles both build clean;
  clippy passes with `-D warnings`.

`perun call <image.dll> <export> [arg0..arg3] [--verbose]` invokes an export
through the Win64 ABI after init. `--verbose` prints the image summary
(entry, base, section count) before loading. A `scratch` argument token
supplies a clean zeroed page for pointer-backed parameters; `ctx` supplies a
larger zeroed region to stand in for a guest context struct.

## The ADI dispatcher now runs end-to-end

`perun call CoreADI64.dll vdfut768ig <cmd> scratch` executes the dispatcher's
full provisioning logic and returns a clean ADI error code instead of
crashing. Observed behavior:

- Resolves `<CommonAppData>\Apple Computer\iTunes\adi` via
  `SHGetFolderPathW(CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE)` — csidl
  `0x8023` — plus `PathAppendW` + `PathIsDirectoryW` + `GetFileAttributesW`,
  confirming each directory.
- Returns `0xffff5016` (not provisioned) for every command code tested,
  0..255 inclusive — with no file, registry, mutex, or enumeration access.
- The DLL exports exactly two symbols: `vdfut768ig` and `cvu8io98wun`
  (the second is the sibling entry point; the dispatch tests use the first).
- Before the dispatcher runs, the statically linked CRT startup probes
  `LoadLibraryExW("api-ms-win-core-synch-l1-2-0")` and
  `("api-ms-win-core-fibers-l1-1-1")` (two calls each); the shim answers
  both with the main-module token during the static-init phase.

This is the trap-and-scaffold design paying off: each missing Win32 API was
surfaced by the trap reporter and implemented in turn until the dispatcher
ran its full logic.

## The provisioning gate (current wall)

The `0xffff5016` result is checked **before** command dispatch and is uniform
across all commands (verified over the full 0..255 sweep), so it is an
in-memory provisioning-state flag, not a per-command result. The dispatcher's
control flow is control-flow-flattened (obfuscated), but the entry sequence
is decoded:

- First-level dispatch is a pure `rdx` NULL check (`test %rdx,%rdx` early in
  the export): param NULL -> `0xffff5036` (invalid param, the default error
  loaded at entry); param non-null -> provisioning loader path.
- The command code (`rcx`) is run through an obfuscated arithmetic transform
  and stored for a second-level dispatch that only runs once provisioning
  passes.

### What the gate actually is (measured, not guessed)

- The gate global is the qword at RVA `0x19dda0` (.data). It is read via an
  obfuscated pointer table at RVA `0x17eca0` (entry `[0x157]` stores
  `ImageBase + real + 0x4f7e9322`; subtracting the base and the key yields
  the target). The check at RVA `0x5b20f` is a double dereference:
  `cmp qword ptr [rcx - 0x4f7e9322], 0`.
- At runtime the global holds a host heap pointer to a 0x28-byte object the
  guest allocates during the call itself — observable live with the shipped
  `--peek-ptr=0x19dda0`: the object's first qword is the flag the gate reads
  (zeroed at allocation), `[0x8]`, `[0x10]`, `[0x18]` are pointers into a
  small graph of sub-allocations.
- The provisioning loader walks `<CommonAppData>\Apple Computer\iTunes\adi`
  (via `SHGetFolderPathW` + `PathAppendW` + `PathIsDirectoryW` +
  `GetFileAttributesW`) but returns `0xffff5016` whether or not `adi` exists
  (re-verified with the directory present and absent, and with a dummy blob
  file inside — identical result, and no CreateFile fires). The blob filename
  is built at runtime (obfuscated); the only "adi" string in the image is the
  named-object prefix `Global\adi-pb-unique`.
- All real file I/O (`CreateFileW`/`ReadFile`/`WriteFile`/`SetFilePointerEx`)
  is concentrated in routines at RVA `0x1339d0`-`0x13f6c5` (15 indirect call
  sites total), reached only after the gate passes.

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

The real app breaks the cycle by calling the `fpinit.itunes.apple.com/v1/fpdi`
endpoints (init/setup) **before** any native FairPlay call — both endpoints
are live (HTTP 405 on bare GET, i.e. present and POST-expecting). The
provisioning blob is device-specific cryptographic material issued during
that handshake. On a fresh offline system there is no blob, so ADI faithfully
reports not-provisioned. This is the provisioning layer of the same Apple
client-attestation family the project exists to understand.

*(Scope note: the August-2026 commerce gate on storefront traffic is a
different, later thing — see RESEARCH.md. This section describes the classic
ADI provisioning cycle, unchanged since the iTunes era.)*

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

The gate cannot be passed offline by poking memory. Two error-reporting
trampolines sit at RVA `0x66c2d` (`mov edi,0xffff5016` — the only one of 37
sites that runs for cmd=0) and `0xb5b49` (`mov edi,0xffff5026`, the next
failure exit). Neutralizing the immediates with the shipped `--patch` token
(5 bytes each, instruction lengths preserved) makes cmd=0 return `0x0`, but
the success is hollow: the API trace is byte-identical to the unpatched run
— no additional API fires, so the trampolines are reporting stubs on a fixed
not-provisioned path, not branch selectors. CoreADI64.dll also imports no
network APIs (KERNEL32 93 / ADVAPI32 7 / SHLWAPI 2 / SHELL32 1 — none of the
103 imports is network-related): the fpinit handshake lives in the caller
(iTunes), not here. Realistic paths:

1. **Obtain a real provisioning blob** from a provisioned machine
   (`C:\ProgramData\Apple Computer\iTunes\adi\`), then feed it to the loader.
   This is the direct oracle: it reveals every context field the dispatcher
   reads after the gate.
2. **Replicate the server handshake** (`fpinit.itunes.apple.com/v1/fpdi/init`
   + `/setup`) in the caller layer to provision a fresh machine, matching how
   the real app breaks the circular dependency. Requires GSA session tokens
   and the exact request format.
3. **Reconstruct the context object graph**: the gate object references
   sub-allocations reachable via the shipped `--peek-ptr`; mapping every field
   the validator touches would enumerate what a real blob must contain —
   expensive against control-flow flattening.
4. Grow the shim surface as real guests exercise more APIs (the trap reporter
   names each missing symbol with its arguments).
5. `perun scaffold` command to generate a ready-to-fill shim stub from a trap
   report.

## Repo map

- `crates/perun-core` — PE32+ parser, loader, relocations, IAT patching,
  TEB/PEB, trap-stub pool; Mach-O x86_64 parsing and projection (phase 2).
- `crates/perun-shims` — Win32→POSIX translation matrix (memory, files, sync,
  strings/env, registry, process, SEH/TLS/FLS, shell/path); macOS
  libSystem/Mach shims for SAP guests (phase 2).
- `crates/perun-cli` — `perun run` / `perun info` / `perun call` runner;
  `perun mach` inspector; `perun sap` session driver (phase 2).

## Reproduce

```bash
cargo build --release -p perun-cli
./target/release/perun info  /path/to/CoreADI64.dll
./target/release/perun run   /path/to/CoreADI64.dll --verbose
./target/release/perun call  /path/to/CoreADI64.dll vdfut768ig 0 scratch --verbose

# live object behind the provisioning gate:
./target/release/perun call  /path/to/CoreADI64.dll vdfut768ig 0 scratch \
    --peek=0x19dda0 --peek-ptr=0x19dda0

# the two-trampoline experiment (immediates zeroed, lengths preserved):
./target/release/perun call  /path/to/CoreADI64.dll vdfut768ig 0 scratch \
    --patch=0x66c2d=bf00000000 --patch=0xb5b49=bf00000000
```

## Verification log (2026-09-03, tree at the current HEAD)

Each claim reproduces with the shipped binary or a stock tool; the method
column names it. No source modification, no one-off instrumentation.

| # | Assertion | Method (command family) | Result |
|---|---|---|---|
| 1 | PE32+ x86_64, 7 sections, base 0x7c800000 | `perun info` / `perun call --verbose` | Confirmed (entry 0x131b00, sections .text .rdata .data .pdata .gfids .rsrc .reloc) |
| 2 | Statically linked MSVC CRT, no network imports | `objdump -x` import tables | Confirmed (kernel32 93 / advapi32 7 / shlwapi 2 / shell32 1; zero network names; zero CRT DLLs) |
| 3 | Exports: vdfut768ig + cvu8io98wun | `perun call` on both names resolves | Confirmed (2 exports) |
| 4 | DllMain TRUE, 0 traps, 111 APIs | `perun run --verbose` | Confirmed ("DllMain returned TRUE", no trap lines, "shim table 111 APIs") |
| 5 | cargo test 11/11, clippy clean, fmt clean | `cargo test/clippy/fmt` | Confirmed |
| 6 | cmd 0..255 → 0xffff5016, uniform; no file/registry/mutex/enum API in the trace | 256 × `perun call <cmd> scratch`, trace scan | Confirmed (256/256 uniform; all forbidden families absent) |
| 7 | NULL param → 0xffff5036 | `perun call` without scratch | Confirmed |
| 8 | Trampoline bytes: `bf 16 50 ff ff` @ 0x66c2d, `bf 26 50 ff ff` @ 0xb5b49, each followed by `jmp rcx` | `objdump -d --start-address` | Confirmed |
| 9 | 37 sites of the 5016 immediate in .text | `objdump -d` textual scan | Confirmed (37) |
| 10 | Gate: `test %rdx,%rdx` early; default error `0xffff5036` | `objdump -d` entry region | Confirmed |
| 11 | Gate check double deref: `cmp qword ptr [rcx − 0x4f7e9322], 0` @ 0x5b20f | `objdump -d --start-address` | Confirmed |
| 12 | Runtime gate global → heap object; live dump | `perun call ... --peek=0x19dda0 --peek-ptr=0x19dda0` | Confirmed (object[0..64]: first qword 0, then sub-object pointers) |
| 13 | adi dir present/absent/dummy-blob → same 0xffff5016, no CreateFile | create/remove directory + `perun call` | Confirmed |
| 14 | File I/O concentrated at 0x1339d0–0x13f6c5 (15 indirect sites) | `objdump -x` IAT + `objdump -d` call-site scan | Confirmed (CreateFileW 5, ReadFile 3, WriteFile 6, SetFilePointerEx 1 — all inside the span) |
| 15 | Single-trampoline zeroing → 0xffff5026; both → 0x0, hollow success | `--patch=0x66c2d=…` / both `--patch=` | Confirmed (returns 0xffff5026 / 0x0; API trace identical to baseline) |
| 16 | fpinit fpdi endpoints live | `curl` GET probe | Confirmed (HTTP 405 — present, POST-expecting) |
| 17 | −45034 = 0xffff5016 (signed); −45061 = kADINotProvisioned per prior ADI research | arithmetic + project's Android-ADI research notes | Confirmed |
| 18 | Only "adi" string in image: `Global\adi-pb-unique` | `strings`/binary scan | Confirmed |
| 19 | Trap stubs absolute `jmp [rip+0]`; FakeTEB via ARCH_SET_GS, FS untouched | source inspection (stub.rs, teb.rs) | Confirmed |

Artifacts kept in `tmp/` (untracked, diagnostic): the 256-command sweep
histogram and the objdump-based verifiers.

## Legal & Research License

The reverse-engineering documentation, protocol invariant analysis, and
architectural research in this document are licensed under
[Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
The code implementation is licensed under the
[Apache License, Version 2.0](LICENSE) with [`NOTICE`](NOTICE).
