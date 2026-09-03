# STATUS: Perun native PE micro-runtime

*Phase-1 document (Windows/PE, CoreADI64.dll). The Mach-O FairPlay SAP work
of phase 2 is covered by RESEARCH.md; this file tracks the PE side. Every
claim below was re-verified on 2026-09-03 against the current tree (build
ea6d01a) — see "Verification log" at the end for the exact commands and
results of each check.*

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
- `cargo test`: **11/11 passing** (2 core + 9 shim; the core suite grew by
  the Mach-O parser/loader tests of phase 2). Debug and release profiles
  both build clean; clippy passes with `-D warnings`.

`perun call <image.dll> <export> [args...]` invokes an export through the
Win64 ABI after init. A `scratch` argument token supplies a clean zeroed page
for pointer-backed parameters.

## The ADI dispatcher now runs end-to-end

`perun call CoreADI64.dll vdfut768ig <cmd> scratch` executes the dispatcher's
full provisioning logic and returns a clean ADI error code instead of
crashing. Observed behavior (re-verified 2026-09-03):

- Resolves `<CommonAppData>\Apple Computer\iTunes\adi` via
  `SHGetFolderPathW(CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE)` — csidl
  `0x8023` — plus `PathAppendW` + `PathIsDirectoryW` +
  `GetFileAttributesW`, confirming each directory.
- Returns `0xffff5016` (not provisioned) for every command code tested —
  the full sweep of cmd = 0..255 on 2026-09-03 returned `0xffff5016` in
  256/256 runs — with no file, registry, mutex, or enumeration access.
- The DLL exports exactly two symbols: `vdfut768ig` and `cvu8io98wun`
  (the second is the sibling entry point; all dispatch tests here use the
  first).
- Before the dispatcher runs, the statically linked CRT startup probes
  `LoadLibraryExW("api-ms-win-core-synch-l1-2-0")` and
  `("api-ms-win-core-fibers-l1-1-1")` (two calls each); the shim answers
  both with the main-module token during the static-init phase.

This is the trap-and-scaffold design paying off: each missing Win32 API was
surfaced by the trap reporter and implemented in turn until the dispatcher
ran its full logic.

## The provisioning gate (current wall)

The `0xffff5016` result is checked **before** command dispatch and is uniform
across all commands (verified: 256/256), so it is an in-memory
provisioning-state flag, not a per-command result. The dispatcher's control
flow is control-flow-flattened (obfuscated), but the entry sequence is
decoded:

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
  obfuscated pointer table at RVA `0x17eca0` (entry `[0x157]` stores
  `ImageBase + real + 0x4f7e9322`; subtracting the base and the key yields
  the target RVA). The check at RVA `0x5b20f` is a double dereference:
  `cmp qword ptr [rcx - 0x4f7e9322], 0` — byte-verified in the image.
- At runtime the global holds a host heap pointer to a 0x28-byte object the
  guest allocates during the call itself. The object's first qword is the
  flag the gate reads; `[0x8]` is set to 1 by the guest right after
  allocation; `[0x10]`, `[0x18]`, `[0x20]` are pointers into a small graph of
  sub-allocations. *(The "three consecutive HeapAlloc(0x28) calls" wording
  and the late-fill sentinel experiment below were observed with the
  phase-1 heap instrumentation, which has since been removed from the tree;
  the object-graph conclusion they support still stands.)*
- Late-fill experiment (phase-1 instrumentation, since removed): writing a
  sentinel into every candidate object leaves `[0]=sentinel` in the exact
  object the global points at, yet the return stays `0xffff5016`. So
  trampoline `0x66c2d` is the shared failure exit of a multi-object
  validation: the context is a small object graph and the gate validates it
  as a whole, not as a single flag.
- The provisioning loader walks `<CommonAppData>\Apple Computer\iTunes\adi`
  (via `SHGetFolderPathW` + `PathAppendW` + `PathIsDirectoryW` +
  `GetFileAttributesW`) but returns `0xffff5016` whether or not `adi` exists
  (re-verified 2026-09-03 with the directory present and absent, and with a
  dummy blob file inside — identical result, and no CreateFile fires). The
  blob filename is built at runtime (obfuscated); the only "adi" string in
  the image is the named-object prefix `Global\adi-pb-unique`.
- All real file I/O (`CreateFileW`/`ReadFile`/`WriteFile`/`SetFilePointerEx`)
  is concentrated in routines at RVA `0x1339d0`-`0x13f6c5`, reached only after
  the gate passes.

### Cross-reference with prior ADI/FairPlay research

This matches the documented ADI error family: `0xffff5016` = signed `-45034`,
adjacent to `-45061 kADINotProvisioned` ("ADI machine not provisioned,
expected pre-init" — the −45061 constant is confirmed by this project's
independent Android-side ADI research, which maps −45001 invalid params /
−45061 not provisioned / −45063 pending session). The circular dependency is
already characterized:

```
bag-request -> needs FairPlay context
InitContext -> needs FPDICreate
FPDICreate  -> needs subscription bag from server
bag-request -> needs context        <- cycle
```

The real app breaks the cycle by calling the `fpinit.itunes.apple.com/v1/fpdi`
endpoints (init/setup) **before** any native FairPlay call — both endpoints
are live as of 2026-09-03 (HTTP 405 on bare GET, i.e. present and
POST-expecting). The provisioning blob is device-specific cryptographic
material issued during that handshake. On a fresh offline system there is no
blob, so ADI faithfully reports not-provisioned. This is the provisioning
layer of the same Apple client-attestation family the project exists to
understand.

*(2026-09-03 correction of scope: the August-2026 commerce gate on
storefront traffic is a different, later thing — see RESEARCH.md. This
section describes the classic ADI provisioning cycle, unchanged since the
iTunes era.)*

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
`mov edi,0xffff5016` at RVA `0x66c2d` (executed; the only one of 37 sites —
all enumerated by byte pattern `bf 16 50 ff ff` — that runs for cmd=0) and
`mov edi,0xffff5026` at RVA `0xb5b49` (the next failure exit, exposed once
the first was zeroed). Zeroing the immediates of both (leaving each
instruction's length intact: `bf 00 00 00 00`) makes cmd=0 return `0x0`, but
the success is hollow: the API trace is byte-identical to the unpatched run
— no additional API fires, so the trampolines are reporting stubs on a fixed
not-provisioned path, not branch selectors. *(Patch-surgery note: the
immediate is 5 bytes; overwriting 6 as NOPs shears the following `jmp rcx`
and crashes the flattened dispatcher — the `--patch` token takes `rva=hex`
and applies exact bytes.)* CoreADI64.dll also imports no network APIs
(KERNEL32 93 / ADVAPI32 7 / SHLWAPI 2 / SHELL32 1 — none of the 103
imports is network-related): the fpinit handshake lives in the caller
(iTunes), not here. Realistic paths:

1. **Obtain a real provisioning blob** from a provisioned machine
   (`C:\ProgramData\Apple Computer\iTunes\adi\`), then feed it to the loader.
   This is the direct oracle: it reveals every context field the dispatcher
   reads after the gate.
2. **Replicate the server handshake** (`fpinit.itunes.apple.com/v1/fpdi/init`
   + `/setup`) in the caller layer to provision a fresh machine, matching how
   the real app breaks the circular dependency. Requires GSA session tokens
   and the exact request format (the request format is not documented here;
   the earlier reference to external Java-layer notes has been dropped as
   unverifiable from this tree).
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
./target/release/perun call  /path/to/CoreADI64.dll vdfut768ig 0 scratch

# the two-trampoline experiment (immediates zeroed, lengths preserved):
./target/release/perun call /path/to/CoreADI64.dll vdfut768ig 0 scratch \
    --patch=0x66c2d=bf00000000 --patch=0xb5b49=bf00000000
```

## Verification log (2026-09-03, tree at ea6d01a)

Every claim above was re-tested today. Assertion → method → result:

| # | Assertion | Method | Result |
|---|---|---|---|
| 1 | PE32+ x86_64, 7 sections, base 0x7c800000 | `perun info` + independent Python struct parser over the PE headers | Confirmed (sections: .text .rdata .data .pdata .gfids .rsrc .reloc; machine 0x8664; magic 0x20b) |
| 2 | Statically linked MSVC CRT | Import table scan: no msvcp/vcruntime/ucrtbase/api-ms DLLs among imports | Confirmed (only kernel32=93, advapi32=7, shlwapi=2, shell32=1 imports) |
| 3 | No network imports | Same scan, network-name filter | Confirmed (zero matches) |
| 4 | Export vdfut768ig exists | Export-directory parse | Confirmed (plus sibling `cvu8io98wun`; 2 exports total) |
| 5 | DllMain returns TRUE, 0 traps | `perun run --verbose` | Confirmed ("DllMain returned TRUE"; no trap lines) |
| 6 | 111 Win32 APIs | shim-table count printed by the binary | Confirmed ("shim table 111 APIs") |
| 7 | cargo test 9/9 | Full workspace run | **Corrected: 11/11** (phase-2 tests added) |
| 8 | cmd 0..255 → 0xffff5016, uniform | 256 sequential `perun call` runs, return-code histogram | Confirmed (256/256 uniform) |
| 9 | Null param → 0xffff5036 | `perun call` without scratch | Confirmed |
| 10 | No file/registry/mutex/enum access during dispatch | API trace of a full run, forbidden-family filter (CreateFile/RegOpenKey/CreateMutex/FindFirstFile/…) | Confirmed (all families absent) |
| 11 | Trampoline bytes: mov edi,0xffff5016 @ 0x66c2d; mov edi,0xffff5026 @ 0xb5b49 | Capstone disassembly at exact RVAs | Confirmed (`bf 16 50 ff ff` / `bf 26 50 ff ff`, both followed by `jmp rcx`) |
| 12 | 37 sites of the 5016 immediate | Byte-pattern scan over .text | Confirmed (37; 0x66c2d among them; full list in the sweep artifacts) |
| 13 | Gate check: double deref through table [0x157] | Disasm at 0x5b20f + pointer-table decode | Confirmed (`cmp qword ptr [rcx - 0x4f7e9322], 0`; entry stores ImageBase+RVA+key; subtracting yields 0x19dda0) |
| 14 | Single-trampoline zeroing exposes 0xffff5026 | `--patch=0x66c2d=bf00000000` | Confirmed (returns 0xffff5026) |
| 15 | Both zeroed → cmd=0 returns 0x0 | `--patch=0x66c2d=… --patch=0xb5b49=…` | Confirmed (returns 0x0, rc=0) |
| 16 | Hollow success: no extra API fires | API-trace diff patched vs baseline | Confirmed (traces identical) |
| 17 | adi dir present/absent/dummy-blob → same 0xffff5016, no CreateFile | Directory created with and without a dummy blob file, re-run | Confirmed (identical result; no CreateFile in trace) |
| 18 | Blob filename not a static string | String scan of the image | Confirmed (only "adi"-bearing string is `Global\adi-pb-unique`) |
| 19 | −45034 adjacency to −45061 (kADINotProvisioned) | Signed-int arithmetic + this project's independent Android-ADI research notes | Confirmed (0xffff5016 ≡ −45034; −45061 documented as "machine not provisioned") |
| 20 | fpinit fpdi endpoints live | Bare GET probes | Confirmed (HTTP 405 — present, POST-expecting; not a 404) |
| 21 | Trap stubs: absolute jmp [rip+0] | Source inspection (stub.rs) | Confirmed (FF 25 00 00 00 00, embedded 64-bit target) |
| 22 | FakeTEB via ARCH_SET_GS, FS untouched | Source inspection (teb.rs) | Confirmed |
| 23 | scratch token = zeroed page | Source inspection (main.rs) | Confirmed |

Artifacts of the sweep: 256-run histogram `/tmp/sweep256.json`; the two
Python verifiers live in `tmp/verify_status.py`, `tmp/sweep256.py`,
`tmp/disas_verify2.py`, `tmp/disas_crash.py` (untracked, diagnostic).

## Legal & Research License

The reverse-engineering documentation, protocol invariant analysis, and
architectural research in this document are licensed under
[Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
The code implementation is licensed under the
[Apache License, Version 2.0](LICENSE) with [`NOTICE`](NOTICE).
