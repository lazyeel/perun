# RESEARCH.md — Perun: Native Binary-Projection Runtime for Apple Client Attestation (FairPlay SAP and ADI)

**Project:** [lazyeel/perun](https://github.com/lazyeel/perun) · **Document class:** Interoperability research specification & reverse-engineering report · **Status:** Working end-to-end implementation (SAP protocol closed 2026-08-31; **Anisette v3 generated locally 2026-09-27 — § 5.8a**; ADI dispatcher end-to-end to its provisioning gate 2026-09-03, Windows lane frozen 2026-09-26 — § 5.8; live StoreKit client lane E2E 2026-09-07; store-command parity and resumable downloads 2026-09-13/14; mmap-bounded IPA replication) · **License:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

---

## 1. Scope, Purpose, and Interoperability Basis

This document is a technical specification and research report for **Perun**, a native user-space runtime that projects and executes Apple's binary images directly on a Linux host — no CPU emulation — covering two target families:

- the 2013-vintage x86_64 **Mach-O** commerce images (CoreFP, CommerceCore, CommerceKit) that run the StoreKit client-attestation handshake (FairPlay **SAP**) end-to-end against Apple's live storefront endpoints;
- the Windows **PE32+** image `CoreADI64.dll` (iTunes for Windows, x86_64), whose ADI v3 attestation dispatcher runs end-to-end up to its provisioning gate (§ 5.8, open);
- the **x86_64** engine from Apple Music (`libstoreservicescore.so` + `libCoreADI.so`, taken from Apple's universal 4.9.6 APK), which generates Anisette v3 headers natively on this host — no Wine, no QEMU, no remote re-signing server (§ 5.8a, closed 2026-09-27). An arm64 copy of the same engine also runs, under `qemu-aarch64-static`, as a fallback.

It documents the binary maps, calling interfaces, memory invariants, network protocols, and measured performance of both lanes, and the verification commands that reproduce every claim with the shipped binary and stock tools.

The purpose of this work is **interoperability**: enabling an independently created program (a native Linux runtime) to interoperate with the public storefront protocol by identifying and analyzing those interface elements of a lawfully obtained, publicly distributed program that are necessary for interoperation. This is the classical reverse-engineering-for-compatibility activity contemplated by 17 U.S.C. § 1201(f) (reverse engineering for interoperability) and Directive 2009/24/EC Art. 5(3)/6 (observation, study, testing, and decompilation indispensable for interoperability of an independently created program), and it stays inside those boundaries:

- **No content decryption.** The documented protocol is a client-attestation session handshake; it neither decrypts nor circumvents any content-protection measure. The signature attests the *client*, not any media file.
- **No protection-defeat.** No anti-tampering, anti-debugging, or integrity self-check exists anywhere on the documented path (verified — the poison experiment of § 4.2 plants `int3` at 156 sites and no integrity check fires). Where the guest's environment assumptions conflict with the host's (segment registers, timestamp instructions, libc ABI), Perun adjusts the *environment* (binary projection, static timing normalization), never any protection logic.
- **No redistribution.** The proprietary images are never committed or shipped; users obtain them locally from Apple's public update servers (§ 2).
- **Minimum interface surface.** The runtime answers the guest's imports with deterministic degenerate responses (null handles, empty structures) rather than reimplementing any protected expression.

Terminology throughout follows this framing: *binary projection* / *compatibility layer* (not "emulator crack"), *static timing normalization for deterministic execution* (not "anti-check patch"), *client-attestation protocol implementation* (not "DRM bypass"), *native execution environment* (not "protection circumvention"). All Apple marks and names are used strictly descriptively and remain the property of Apple Inc.

---

## 2. Ground-Truth Binary Map

Target corpus: the commerce pair from Apple's public OS X 10.9 Mavericks update package `OSXUpd10.9.pkg` (package `041-98128-A_SYPWICN3KH`, `swcdn.apple.com`; also mirrored in howett.net's software update catalogs). The same obfuscated export family has shipped in every macOS release since 2013.

| Image | Load base (vmaddr) | Size (B) | SHA-256 | Role |
|---|---|---|---|---|
| `CoreFP` | `0x7FF8_0400_0000` | 29 014 912 | `f19141336be4198d0f8991bb00017c915efc7aeaece36c345f7faa1237ea6074` | FairPlay cryptographic engine (obfuscated exports, key material) |
| `CommerceCore` | `0x7FF8_0800_0000` | 207 744 | `c5401e57402230f3c876409d295319ddf1e61287bc882683c5d61277be7bc1f2` | Storefront configuration helpers (`_get_mac_address`) |
| `CommerceKit` | `0x7FF8_0C00_0000` | 3 271 840 | `b84ff12c21987856c0a17b78f1ad82b73195a6dec5f3b208a17d245555a2c8a2` | SAP session orchestration; public entry points (this doc's § 3) |
| `CoreFP.icxs` | served via shim `open()`/`read()` | 5 288 352 | `473e78af86979f5bd4f6269561caf770b3d16c098d918846eeac8cdd2fe6566a` | Key-container blob CoreFP reads via `./../CoreFP.icxs` |

`storeagent` is **not mapped** (measured 2026-09-02): its symbol table defines only `__mh_execute_header` and `radr://5614542`, and a cross-reference of every bind and lazy-bind entry across the other three images resolves zero imports against it — the protocol runs end-to-end without its mapping (verified against live endpoints with reference-identical context, exchanges, and signature). The reference runtimes map it for layout parity only.

Asset acquisition is zero-config: on first use the built-in fetcher (§ 6.4) downloads the four images by range-reading ~32 MB of the public 1.28 GB update package and verifies each SHA-256 against the table above. Nothing proprietary ships with Perun; users without the fetcher may extract the same files from the public package by hand (the pinned digests are the acceptance criteria).

### 2.1 The `_fp_dh_*` symbol family and the state anchor `0x2bbe90`

CommerceKit's symbol table contains **734 exported symbols named `_fp_dh_<hex32>`** (n_type `0xf` = N_SECT|N_EXT), distributed: 623 in `__TEXT,__const`, 78 in `__TEXT,__text`, 15 in `__TEXT,__cstring`, 7 in `__DATA,__const`, 5 in `__DATA,__data`, 6 in `__DATA,__common`. Two of them sit exactly at the addresses of interest:

- `0x2bbe90` → **`_fp_dh_ac0942c4ee826d185e125f123fffe9b1`** (`__DATA,__common`, zero-initialized at load; 12 code cross-references `lea reg,[rip+…]`).
- `0x2bba90` → **`_fp_dh_2735339b87dfe0d4277c8821598c4081`** (`__DATA,__data`, initialized content `2f 00 00 00 … c0 ba 2b 00 … ba bc b1 30 …`; 14 code cross-references). The initial content is `2f 00 00 00 …` (= 47); the next qwords hold pointers into the same table region (`c0 ba 2b 00 …`, `ba bc b1 30 …`). This is the obfuscated dispatcher's selector-table head; the `200` passed to `SAPExchange` is a caller-side protocol version, distinct from this image-internal constant.

These are the internal state anchor (context/session pointer chain) and the dispatch-selector table of the obfuscated control flow, respectively. The names are Apple's obfuscation, not my labels.

**Stamper.** At `CommerceKit+0x94191`: `mov dword ptr [rax+0x2d8], ecx` — the exchange round-2 completion stamp; the reference run writes `0x12db3c9a` there at session-key finalization. Byte-verified: opcode bytes `89 88 d8 02 00 00` at file offset `0x94191` in `__TEXT,__text` (vaddr == file offset for this image's `__TEXT`).

### 2.2 The PE32+ target: `CoreADI64.dll`

The Windows-side target is Apple's `CoreADI64.dll` from iTunes for Windows (x86_64, statically linked MSVC CRT). Ground truth, all reproduced with `perun info` / `perun call --verbose` and `objdump -x` on the shipped binary:

- PE32+ x86_64 image, **7 sections** (`.text .rdata .data .pdata .gfids .rsrc .reloc`), preferred load base `0x7c800000` (entry at `0x131b00`).
- **Exactly two exports**: `vdfut768ig` (the ADI operation entry) and `cvu8io98wun` (the init entry: writes `[rcx+0] = 0x2000000001`, `[rcx+8] = 0`, returns `0x0`; `rdx` ignored — § 5.8).
- Import surface: **KERNEL32 93 / ADVAPI32 7 / SHLWAPI 2 / SHELL32 1** — 103 imports total, statically linked CRT, zero CRT DLLs, and **zero network-related imports** (the fpinit provisioning handshake lives in the caller, iTunes, not in this DLL).
- Before the dispatcher runs, the statically linked CRT startup probes `LoadLibraryExW("api-ms-win-core-synch-l1-2-0")` and `("api-ms-win-core-fibers-l1-1-1")` (two calls each); the shim answers both with the main-module token during the static-init phase.
- The iTunes 12.13.11 build (1,720,672 bytes) reproduces the same ground truth: identical gate behavior, identical 37/1/46 immediate counts, and the same 4-DLL/103-import/2-export surface.

The DLL is not committed or distributed; users obtain it locally from Apple's public iTunes distribution (extraction steps in the README).

---


## 3. Entry-Point Specification (CommerceKit, System V AMD64 ABI)

All five entry points are exported symbols; Perun resolves them from the image's classic symbol table (the 10.9 images do not carry these entries in the export trie) and calls them on a dedicated guest stack (§ 4.1). Argument order and out-parameter conventions verified against the reference interposer behavior.

| Export | Role | File offset (`__TEXT`) | Signature (inferred) |
|---|---|---|---|
| `_cp2g1b9ro` | **SAPInit** | `0xa40b0` | `int32 f(u64 *ctx_out, const FairPlayHWInfo *hw)` |
| `_Mib5yocT` | **SAPExchange** | `0x88cd0` | `int32 f(u32 ver, const FairPlayHWInfo *hw, u64 ctx, const void *in, u64 in_len, u64 *out_ptr, u64 *out_len, i32 *state)` |
| `_Fc3vhtJDvr` | **SAPSign** | `0x123af0` | `int32 f(u64 ctx, const void *in, u64 in_len, u64 *out_ptr, u64 *out_len)` |
| `_IPaI1oem5iL` | **SAPTeardown** | `0xba0e0` | `int32 f(u64 ctx)` |
| `_jEHf8Xzsv8K` | **DisposeStorage** | `0xa1250` | `int32 f(u64 out_ptr_bridge)` |

Entry bytes verified in-image (identical across all reference-correct runs):

```
_cp2g1b9ro  @ 0xa40b0 : 55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 98 02 …
_Mib5yocT   @ 0x88cd0 : 55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 98 18 …
_Fc3vhtJDvr @ 0x123af0: 55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 38 1d …
_jEHf8Xzsv8K@ 0xa1250 : 55 48 89 e5 53 48 83 ec 28 48 89 fb c7 45 f4 d9 5b ff ff …
_IPaI1oem5iL@ 0xba0e0 : 55 48 89 e5 41 57 41 56 41 54 53 48 81 ec 90 02 …
```

`FairPlayHWInfo` — the 24-byte hardware-fingerprint block passed to init and exchange: `u32le length (=6) ‖ MAC[6] ‖ zero padding to 24 bytes`.

The **CoreFP** engine is reached through `dlsym`-table lookups of six obfuscated exports (`_WIn9UJ86JKdV4dM`, `_X46O5IeS`, `_YlCJ3lg`, `_dku592fbFAj`, `_fdjkDSAFjklaf2s`, `_lxpgvVMLd0S7uRl`); the shim `dlsym` answers from the loaded CoreFP image, exactly as the reference runtime does. `CommerceCore` contributes `_get_mac_address`. None of these names are invented here; all exist natively in the 10.9 binaries and are byte-searchable.

---

## 3.1 SAPInit — context creation

- **Input:** `hw` = the 24-byte `FairPlayHWInfo` block (§ 3).
- **Behavior:** allocates and initializes the session context in the guest heap (first allocation at `0x7FF7_B000_0250` in the reference layout — an address Perun reproduces exactly); formats internal state anchors (including the `0x2bbe90` chain head) and seeds the obfuscated dispatcher.
- **Return:** `0`; `*ctx_out` = context handle (observed `0x7ff7b0000250`).
- **Measured:** 0.598–0.623 ms (mean **0.613 ms**, N=3 release runs, reported by the shipped binary; § 6.2).

## 3.2 SAPExchange — two-round key establishment

Perun drives exchange as the reference does: two calls with the same context.

- **Round 1** input: the DER root certificate downloaded from `https://s.mzstatic.com/sap/setup.crt` (2 385 bytes total: 6-byte envelope `01 02 00 00 04 16` + 2 379 bytes DER beginning `30 82 04 12`; live-verified 2026-09-01, HTTP 200 via the Configurator UA). Output: **354-byte client request `req1`**; guest state slot transitions to **1**.
- **Round 2** input: the 1 428-byte server reply extracted from the plist response. Output: empty/disposable buffer; state slot transitions to **0** and the stamper at `+0x94191` writes the finalization value (reference: `0x12db3c9a`). Session keys are now established in the context.

Per-call return code: `0` on success; non-zero aborts.

## 3.3 SAPSign — action signature

- **Input:** arbitrary payload bytes (Perun's smoke test: a 27-byte ASCII string; production use: the serialized login/purchase POST body).
- **Output:** a **501-byte** binary signature block (first 4 bytes `02 ce 1a 46`, stable header across sessions; remainder session-ephemeral). Serialized as Base64 and sent as the `X-Apple-ActionSignature` HTTP header on storefront requests.
- **Measured:** 1.00–1.20 ms (mean **1.09 ms**, N=3 release runs; § 6.2).

## 3.4 Teardown / disposal

`SAPTeardown(ctx)` destroys the session; `DisposeStorage(oPtrBridgeAddr)` frees guest-heap output buffers. DisposeStorage's argument convention is a Perun discovery: the guest expects the **bridge-page address** (the out-pointer cell), not the returned heap pointer — passing the heap pointer leaves a detectable state residue (`state+0x2e8` low byte `0x90` vs. reference `0x02`). The reference interposer's convention is reproduced exactly.

---

## 4. System Invariants

### 4.1 Virtual-memory topology

```
0x0000_0000_0000_1000   (page-zero guard)
0x0000_0000_1000_0000   ZERO_DATA_PAGE        (RO, zero-filled; inert data imports)
0x0000_0001_0000_0000   RETURN_PAGE           (RWX thunk `FF D0 F4 00…`; magic 0x1_0000_0002)
0x0000_3000_0000_0000   SCRATCH               (1 MiB RW)
0x0000_4000_0000_0000   SHIM_TABLE             (import resolution slots)
0x0000_6000_0000_0000   BRIDGE pages          (4 KiB per pointer argument, monotone)
0x0000_7FF7_B000_0000   guest heap bottom     (64 MiB arena, 16-byte align, C semantics)
0x0000_7FF7_B400_0000   guest heap top
0x0000_7FF7_BF80_0000   guest stack bottom    (8 MiB)
0x0000_7FF7_C000_0000   guest stack top  = GUEST_ENTRY_RSP (rsp0 = top − 8)
0x0000_7FF8_0400_0000   CoreFP
0x0000_7FF8_0800_0000   CommerceCore
0x0000_7FF8_0C00_0000   CommerceKit
0x0000_7FF8_1000_0000   (storeagent's reference base — not mapped, see § 2)
```

Key invariants:

1. **Guest stack.** The reference emulator maps 8 MiB ending exactly at `0x7FF7_C000_0000` and enters the guest with RSP at that top edge. The obfuscated code folds entry-frame bytes into its scratch-pointer arithmetic (a 16-byte entry shift moves every later frame), so the entry frame must match the reference byte-for-byte: `[rsp0−8] = 0x1_0000_0002` (the `call`-pushed return address into the return thunk at `0x1_0000_0000`, whose bytes are `FF D0 F4` — `call rax; hlt`). Guest `ret` lands on the `hlt`, which faults as SIGSEGV with RIP inside the thunk; Perun's SIGSEGV handler recognizes the exact RIP (0x1_0000_0000 or +2) and bounces to the trampoline landing pad, restoring the host frame. **Return page = `0x1_0000_0000`, return magic = `0x1_0000_0002`.** (Do not confuse with `ZERO_DATA_PAGE = 0x1000_0000`, a separate read-only zero page for inert data imports — pinned fixed, not ASLR-random, because data slot values end up in key material.)
2. **Guest heap.** Fixed 64 MiB arena `[0x7FF7_B000_0000, 0x7FF7_B400_0000)`, custom allocator reproducing C `malloc` semantics: 16-byte alignment (`ALIGN = 16`), a 16-byte (aligned `size_t`) size prefix per block, `free`/`malloc_size` walk the prefix, user blocks **not** zeroed on allocation (fresh mmap pages are zero; the reference never zeroes — an early shim that zeroed on alloc corrupted the parity, and a later one that zeroed via `calloc` diverged from the reference heap walk). Host `malloc` is unusable here: CoreFP calls `malloc_size` on pointers it did not allocate, and `DisposeStorage` frees pointers from the arena.
3. **Bridge pages.** One 4 KiB page per pointer argument, allocated monotonically from `0x6000_0000_0000` in the reference's exact order (init: `ctx`, `hw`; exchange: `hw`, `iBuf`, `oPtr`, `oLen`, `rc`; sign: `iBuf`, `oPtr`, `oLen`). The guest writes results through these cells; the runtime reads them back after return. Sign/dispose pass the bridge address of the out-pointer cell (§ 3.4).
4. **Stack-cursor discipline.** Guest frames interleave with shim frames; the obfuscated dispatcher reads "uninitialized" stack slots, so **every shim on the hot path must be compiled with the same frame geometry as the reference** (`opt-level=2` for the shim crate in dev profiles; no allocation, no logging in production shims). The guest zeroes the frame pointer on entry; the trampoline stashes the host RBP in a data slot and restores it at the landing pad.

### 4.2 Segment registers — the Darwin/Linux TLS conflict, resolved by measurement

x86_64 Darwin uses **GS** for user TLS; x86_64 Linux glibc uses **FS** for its TCB. A Mach-O guest running natively under Linux therefore carries latent `mov reg, fs:[rbp−disp]` sites that, if executed, would read the host glibc TCB (errno, stack-guard, pthread state…), and `gs:` sites that would read whatever the host left at GS_BASE — in both cases corrupting either the guest's expectations or the host's process state. On the PE side (Phase 1 of this project) the conflict is real and solved by installing a per-thread FakeTEB behind `GS_BASE` via `arch_prctl(ARCH_SET_GS)` while leaving `FS` untouched for glibc.

For the Mach-O SAP path, the question "must FS/GS accesses be neutralized?" was **answered empirically, and the answer is no** — a fact with two independent proofs:

1. **Static census (capstone, restart-mode linear disassembly of `__TEXT,__text`).** CommerceKit contains 69 byte-level `0x64`-prefixed decode sites, of which **29 are semantic FS memory ops** (`mov r, fs:[rbp±disp]` loads/stores of 32/64-bit width; the remaining 40 are mid-instruction byte artifacts of obfuscated data). CoreFP: 558/45 semantic; storeagent: 12/2; CommerceCore: 0/0. GS twins: 41/31 (CK), 534/49 (CoreFP). The semantic sites live in functions off the SAP path (storefront configuration, UI-adjacent code) — they are the general-purpose TLS accesses of a framework binary, not part of the attestation flow.
2. **Poison experiment (the decisive test).** Perun rebuilds each image copy with `int3` (0xCC) planted at **every semantic FS site — 76 sites across CommerceKit/CoreFP/storeagent** — plus, separately, every semantic GS site (80). Control for method validity: planting `int3` at `0x95fd7` (a site known-executed in the 95f-wave of the key schedule) traps immediately (`SIGTRAP at rip=0x7ff80c095fd8`), proving the poisoning is actually reached. Result: **all-poisoned runs complete the full protocol** — init → exchange×2 → 354-byte req1 → 1428-byte reply processing → sign → **501-byte signature** — with byte-identical context address (0x7ff7b0000250) and byte-identical 95f-wave FNV state (0x6094ba41ca7bf5a8). Therefore **zero FS/GS-prefixed instructions execute on the SAP path**, and no FS/GS neutralization (static or dynamic) is required. The runtime simply leaves the host's FS and GS bases alone; the guest never touches them.

*Note on the "FS paradox" of earlier status reports:* the hypothesis that "obfuscated `mov %fs:-0x…` instructions destroy host memory" was a plausible reading of phase-1 crash patterns, but the poison experiment falsifies it for the SAP path — no such instruction executes. The actual host-corruption crashes of the earlier sessions were traced to the `___bzero` ABI bug (§ 5.3) and to debug-frame stack pollution (§ 4.1), not to segment prefixes. The paradox is resolved: there is nothing to neutralize on this path.

### 4.3 RDTSC — static timing normalization

The 2013 images read wall-clock time via `rdtsc` idioms. Under native execution these are harmless (the host TSC is a fixed counter), but for **deterministic, reproducible signing** — and to mirror the reference emulator, which forces RAX=RDX=0 for `rdtsc` — Perun statically rewrites the three observed idioms in the `__TEXT,__text` working copy, **strictly limited to `__TEXT,__text`** (the same byte patterns occur ~6 269 times in CoreFP's raw segments — mostly inside `__const` crypto material — and rewriting there corrupts the engine's constants):

| Idiom | Original bytes | Replacement | Semantics |
|---|---|---|---|
| A (9 B) | `0F 31 48 C1 E2 20 48 09 C2` (`rdtsc; shl rdx,32; or rdx,rax`) | `31 C0 31 D2 90×5` | `xor eax,eax; xor edx,edx; nops` |
| B (12 B) | `0F 31 48 89 D1 48 C1 E1 20 48 09 C1` | `31 C0 31 D2 90×8` | same |
| C (10 B) | `0F 31 48 C1 E0 04 48 83 E0 70` | `31 C0 31 D2 90×6` | same |

Site counts (measured): CommerceKit A=246, B=4, C=1 (251 sites); CoreFP A=6256, B=13, C=0 (6 269 sites); storeagent A=566, B=3, C=0; CommerceCore 0. **Shipped: CommerceKit's full 251, CoreFP none** — an execution census (archived as the tag `archive/rdtsc-census`) plus a capstone call graph from the five SAP entry points established that CoreFP reaches none of its 6 269 on any path that has been driven, so patching them cost 10.5 MiB of resident `__TEXT` for nothing. See HANDOVER §3.2b. No runtime hooking; the rewrite happens once at load, in memory, on the working copy — the on-disk images are never modified. Timing normalization is an environment-compatibility measure (deterministic execution), not a protection-defeat: no anti-tampering or integrity check exists on this path (verified — see § 5.2).

### 4.4 `___bzero` — a two-argument ABI pitfall

`___bzero(void *s, size_t n)` is **two-argument** (SysV: rdi, rsi). Binding it to host `memset` (`memset(rdi, rsi→c, rdx→n)` misreads) — the original bug — turned `___bzero(p, 6)` into "write one byte 0x06 at p with garbage length": a single `0x06` byte appeared in a state block where the reference had six zeros, and the divergence cascaded through the key schedule into a walker-`bzero` beyond the heap mapping → SIGSEGV in sign. The fix is a dedicated `shim_bzero(s, n)` that byte-for-byte mirrors the reference interposer's loop. This is the classic dual-argument-vs-three-argument libc ABI trap of cross-OS binary projection, and it is documented here as a hazard for anyone implementing the same layer.

### 4.5 POSIX/libc surface (the import matrix)

The guest imports resolve to three tiers, mirroring what the reference interposer proved sufficient in 2024 (§ 8):

1. **Host-libc passthrough** (same SysV ABI both sides): `memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `strcmp`, `strncmp`.
2. **Reference-semantics shims** (deterministic degenerate responses): `gettimeofday → {1717000000, 0}` (fixed timestamp for reproducible key material), `arc4random → 0`, `sysctl → −1` (`sysctlbyname → *oldlenp=0, ret 0`), `getenv → NULL`, `statfs → 0` + zeroed 432-byte buffer, `lstat/fcntl → −1`, CF family (`CFStringCreateWithCString → ~0` only for `IOPlatformSerialNumber` / `IOPlatformUUID` / `board-id`, else NULL; `CFDictionaryGetValue → ~0`; `CFDataGetBytePtr/GetLength → NULL/0`; `CFStringGetCString → true` without touching the buffer; etc.), IOKit (`IORegistryEntryFromPath → 0`, `IOServiceGetMatchingService → ~0`, `IOIteratorNext → (--o) % 2` …), DiskArbitration (`DASessionCreate/DADiskCreate* → ~0`), `objc_msgSend → ~0` for `objectForKey:`, `dlopen → ~0` only for the CoreFP path, `dlsym →` the CoreFP export table, `pthread_once` (Rust, O2-compiled, exact C frame shape), `pthread_self → 0`, rwlock family → 0, real `OSAtomicCompareAndSwap32Barrier`, `___stack_chk_guard` = fixed data, `___error → &errno` slot.
3. **Custom heap** (§ 4.1) and **ICXS service**: CoreFP reads its key container via `open("./../CoreFP.icxs")` + `read()`; the shim serves both calls from an in-memory copy (fd 3) and fails everything else. Any import not in the table lands on a trap micro-stub that reports the missing symbol instead of crashing (fail-closed design).

### 4.6 Register-zeroing entry (Unicorn parity)

The reference emulator enters guests with all registers zero. The obfuscated dispatcher reads uninitialized registers; leftover host values change its flattened control flow. Perun's trampoline therefore zeroes RBX/RBP/R10–R15 and loads RAX with the target (mirroring the reference's `callq *%rax` thunk) before `jmp` into the guest — then restores the host frame at the landing pad. Dispatch parity was verified decision-by-decision: 2 353/2 353 obfuscated-CFG dispatch choices match the oracle across init/x1/sign (2127+218+8), and the FNV wave seeds match byte-for-byte (0x6094ba41ca7bf5a8 at x1; 0x12db3c9a stamper at x2).

### 4.7 Win32/PE32+ runtime invariants (the ADI lane)

The PE32+ lane runs the same native-execution doctrine with Win64 semantics:

- **FakeTEB behind `GS_BASE`.** A per-thread fake TEB/PEB pair is installed via `arch_prctl(ARCH_SET_GS)`; `FS` is left untouched because glibc owns it. FLS slots are backed by the TEB inline TLS slots.
- **Real stack bounds.** Stack limits are derived from pthread so MSVC `__chkstk` probes the real stack rather than a fiction.
- **113 Win32 APIs** implemented as shims — plain Rust functions compiled as `extern "win64"`, so a resolved import is a direct `call` with no per-call trampoline. `DllMain(DLL_PROCESS_ATTACH)` returns TRUE on `CoreADI64.dll` with zero unresolved-import traps.
- **Trap micro-stubs are absolute `jmp [rip+0]`** with an embedded 64-bit target, never `jmp rel32`: the RWX stub page and the guest image can be terabytes apart under ASLR, and rel32 only reaches ±2 GB. An unresolved import lands on such a stub, which reports the missing symbol with its arguments instead of crashing (fail-closed design).
- Base relocations are applied when the load address slides (DIR64 and HIGHLOW types; ordinal imports trap, forwarded exports are unsupported); headers and sections map with `mmap(MAP_FIXED_NOREPLACE)` at the preferred base, falling back to any address, with per-section `mprotect` after binding.
- No Wine, no QEMU, no instruction emulation anywhere; overhead exists only at each Win32 boundary crossing.

---

## 5. StoreKit / FairPlay SAP Protocol Specification

### 5.1 Overview

```
 Client (Perun host)                     Apple endpoints
 ─────────────────────────────────────────────────────────────────────
 1  SAPInit(hw)                          —
      ctx ← guest heap
 2  GET  s.mzstatic.com/sap/setup.crt
     ← 2 385 B envelope (6 B hdr + 2 379 B DER payload)
 3  SAPExchange(v=200, hw, ctx, cert)    → state=1
      req1 (354 B) ← guest heap
 4  POST play.itunes.apple.com/WebObjects/MZPlay.woa/wa/signSapSetup
      Content-Type: application/x-plist
      UA: Configurator/2.15 (Macintosh; OS X 14.2; 16C68)
      body: plist{sign-sap-setup-buffer: base64(req1)}
      ← plist reply (envelope: 1 428 B)
 5  SAPExchange(v=200, hw, ctx, reply)   → state=0
      session keys finalized in ctx
 6  SAPSign(ctx, payload)
      ← 501 B action signature
 7  (usage) Base64(sig) → header `X-Apple-ActionSignature`
      on storefront login/purchase POSTs
```

The flow above is the bare `perun sap` path: fixed legacy endpoints compiled into the binary. The production store lane (§ 5.9) runs the same guest contract through per-session URLs from the live URL bag instead. Same 24-byte hardware block, same `200` version, same 1-then-0 state assertions — only the transport differs: the certificate arrives as a plist envelope (`sign-sap-setup-cert`), and the setup round POSTs to the bag's `sign-sap-setup` URL.

### 5.2 What the protocol is and is not

The handshake is a **client-attestation session establishment**: the server validates that the request came from something possessing the 2013 engine's key material (embedded in the images and the `.icxs` container), and both sides derive session keys. It is the software attestation family that Apple's commerce endpoints began enforcing on third-party clients in July–August 2026 (the "empty 403 / 204" gate on `MZFinance`/`MZPlay` requests lacking the signature). It is **not** content DRM: the signature attests the client, not any particular media file, and the protocol neither decrypts nor circumvents any content-protection measure. No anti-tampering, anti-debugging, or integrity self-check was encountered anywhere on the documented path (the poison-control experiment of § 4.2 doubles as the proof: the engine executes with 0xCC planted at 156 TLS-segment sites without any integrity check firing).

### 5.3 Wire details

- **Certificate fetch.** `GET https://s.mzstatic.com/sap/setup.crt` — raw response, no plist envelope: 2 385 bytes = 6-byte binary header `01 02 00 00 04 16` followed by a 2 379-byte DER payload (`30 82 04 12 …` = certificate sequence of 1 042 content bytes, plus trailing concatenated objects to the full 2 379 bytes). The entire 2 385-byte response is fed to round 1 unchanged. Live-verified 2026-09-01 (HTTP 200, exact size match).
- **Setup exchange.** `POST https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/signSapSetup`, `Content-Type: application/x-plist`, UA `Configurator/2.15 (Macintosh; OS X 14.2; 16C68)`. Body: `<plist><dict><key>sign-sap-setup-buffer</key><data>base64(req1)</data></dict></plist>`. Reply: same-key plist containing the 1 428-byte exchange buffer.
- **State machine.** Exchange transitions the guest state slot 0→1 (round 1) and 1→0 (round 2); Perun asserts both states and aborts on mismatch. The `version` argument to SAPExchange is `200` on both rounds (caller-side protocol version; distinct from the image-internal `0x2f` selector at `0x2bba90`).
- **Signature block.** 501 bytes; header `02 ce 1a 46` … (session-ephemeral body). No published validation algorithm is reimplemented here; the block is produced by the guest engine itself and used opaque, as the reference tools do.

### 5.4 Placement in the modern Apple stack (terminology audit, 2026-09)

To pre-empt terminology drift, the current distinctions — verified against the live ecosystem state as of September 2026 — are:

- **ADI (Apple Device Identity)** — the provisioning library family (`libCoreADI.so` on Android, `CoreADI64.dll` on Windows, `AppleADITool` on macOS) that yields one-time-pads for **GrandSlam/GSA** authentication ("anisette" headers: `X-Apple-I-MD`, `X-Apple-I-MD-M`, `X-Apple-I-MD-RINFO`). Apple-signature-checking **commerce** endpoints do not consume anisette; the **GSA/SRP login layer** still does. Perun's Phase-1 ADI research on `CoreADI64.dll` (§ 5.8; reopened 2026-09-28 — of the three gates, `unknownAdiCallFlags` and the `0x19db98` NULL check are passed, `invalidParams2` is not) remains the reference analysis for that layer.
- **Anisette** — the data **derived from** ADI provisioning (OTP + machine UID), not a protocol itself. Post-2026-08 commerce reality: anisette is dead for commerce, alive for GSA.
- **FairPlay** — Apple's content-and-runtime protection family. **FairPlay SAP** (Secure Authentication Protocol) is the session/signature protocol run by CoreFP/CommerceKit — the subject of this document. Content FairPlay (the per-title encryption of downloaded packages) is a different mechanism, untouched by this work.
- **StoreKit** — the client framework family for storefront transactions. Third-party tools integrate at its wire level (storefront APIs); the signature under discussion is named for its role in that integration (`X-Apple-ActionSignature`), and the 10.9 engine predates the modern StoreKit 2 / App Attest (`AppAttest`/DCI) family — those are server-validated device attestation systems, not what runs here.
- **SAP vs. PAT** — August-2026 community RE (thegaiko et al.) described a P-384 **PAT** flow bound to the Secure Enclave in the modern client stack; the commerce gate, however, accepts signatures from the 2013 software SAP family, which is what both the reference tools and Perun drive. Confusing the two led the community to wrongly conclude the gate was unpassable without hardware.
- **MZFinance / MZPlay** — Apple's storefront web objects; the commerce endpoints requiring the action signature. `fpinit.itunes.apple.com/v1/fpdi/*` belongs to the ADI/FPDI provisioning family, a different layer.

### 5.5 Provenance and naming hygiene

The obfuscated export names, entry offsets, and protocol endpoints documented here are **facts about Apple's published binaries and observable network behavior**, byte-verifiable by anyone with the public update package; they are not copied from any third-party project. Where Perun's implementation reproduces reference tool behavior (shim return values, bridge-page order, the dispose convention), the prior art is credited in § 9.

---

### 5.6 What the signature actually gates on the storefront path (live-verified 2026-09-07)

The StoreKit client lane built on this runtime (Phase 3) exercises the full storefront path against live Apple endpoints. Which requests require the action signature and which do not — established empirically, not from upstream documentation:

- **MZFinance `authenticate` (login) — signature-gated.** The login body is the payload SAPSign signs; it rides as `X-Apple-ActionSignature` (base64 of the 501-byte block). Without it the request dies in the empty-403/204 gate; with it, the endpoint answers protocol-level (BadLogin on bad credentials, a 2FA challenge on good ones, `passwordToken` on completion). The signature is *only* required on the login body: the retry round with the 2FA code appended to the password is signed fresh per attempt.
- **`buyProduct` / `volumeStoreDownloadProduct` — cookie+token, not signed.** Once MZFinance authentication has run, purchase and download requests ride on the established session (`mz_at_ssl`/`mz_at0_fr` cookies, `X-Token` header) with no per-request action signature. The attestation is a *session-establishment* gate, not a per-call toll.
- **The DAAP purchase-history endpoint — signature-gated.** The `pd.itunes.apple.com` history request (per-account) requires the signature on its body, same as login. This is the second signed call site found behind the commerce gate.
- **The rest of the storefront surface — open.** Bag fetch (`init.itunes.apple.com/bag.xml`), iTunes Search/lookup (public APIs), and the signed-asset download host (`iosapps.itunes.apple.com`) all answer anonymous or session-authenticated requests without the signature.

In sum: the August-2026 gate is a login-shape gate on the two identity/ownership endpoints (authenticate, DAAP history), not a blanket requirement across the storefront API surface.

### 5.7 A 5005 post-script: account state, not protocol state

Live testing surfaced one more operational fact worth recording for anyone reproducing this path. A freshly created Apple ID that has never completed first-login terms acceptance can pass 2FA (correct code, server-accepted) and still be refused a `passwordToken` with `failureType 5005` — the endpoint's answer for "2FA invalid **or** account not yet provisioned for storefront use." The account-state cause dominates: completing ToS acceptance once (any Apple web property, e.g. music.apple.com) immediately turns the same credentials+code flow into a working login. The failure code maps to two distinct conditions; do not debug the protocol when the account is simply unprovisioned.

### 5.8b Resuming after a context reset (2026-09-28)

Written for a session that starts with no memory of this work. The barrier map above is the state; this is how to confirm it still holds and what to do next. `HANDOVER.md` §10a carries the same and more, but it is gitignored and does not ship — **this section is the part that travels with the repository**, along with `FINDINGS.md`, which lives outside it.

**Verify before trusting.** Both of these were re-run from a cold build immediately before the reset and both reproduce. A fresh session should run them before acting on anything in §5.8:

    D="$ITUNES_TREE"        # the extracted iTunes tree holding CoreADI64.dll
    ./target/release/perun call $D/CoreADI64.dll vdfut768ig 0xcfe0b46a ctx 0 0 \
        --poke=scratch+0x3=0x2 --poke=ctx+0x0=scratch --poke=ctx+0x8=0x10 \
        --poke=ctx+0xc=0x0 --poke=0x19db98=scratch
    # -> 0xffff5036 (-45002), the barrier

    PERUN_SEAL_DATA=1 ./target/release/perun call $D/CoreADI64.dll vdfut768ig 0xcfe0b46a ctx 0 0 \
        --poke=scratch+0x3=0x2 --poke=ctx+0x0=scratch --poke=ctx+0x8=0x10 \
        --poke=ctx+0xc=0x0 --poke=0x19db98=scratch
    # -> 42 accesses over 36 addresses: 0x19d088, 0x19db98, 0x19dba0..0x19dd90
    #    (one memcpy at 0x70d51), 0x19dda0, 0x19dda8, 0x19e9c8. The re-seal needs
    #    the walk armed; without it a page is reported once and then stays open.

    PERUN_SEAL_DATA=1 PERUN_STOP_CODE=0xffff5036 PERUN_STEPS=400000 \
        ./target/release/perun call $D/CoreADI64.dll vdfut768ig 0xcfe0b46a ctx 0 0 \
        --poke=scratch+0x3=0x2 --poke=ctx+0x0=scratch --poke=ctx+0x8=0x10 \
        --poke=ctx+0xc=0x0 --poke=0x19db98=scratch
    # -> the walk stops at instruction 57, rip 0x5b0ae, edi=0xffff5036
    #    PERUN_STOP_CODE selects which ADI code the walk halts on; it defaults
    #    to -45018, and pinning that default is what made the -45002 publisher
    #    unfindable.

    # The real dispatcher, from a watchpoint on the gate global. Needs ptrace,
    # so run under sudo; see the note on that below.
    sudo gdb -q -batch -x /tmp/gw.gdb --args ./target/release/perun call \
        $D/CoreADI64.dll vdfut768ig 0xcfe0b46a ctx 0 0 --poke=scratch+0x3=0x2 \
        --poke=ctx+0x0=scratch --poke=ctx+0x8=0x10 --poke=ctx+0xc=0x0 \
        --poke=0x19db98=scratch
    # -> 0x5b517  lock cmpxchg %rcx,(%rbx)  installing a host heap pointer

**Inputs, all present on disk and none of them shipped.** The working Android dumper and its naked stubs sit beside the eight-call capture it produced, in the Android working directory used for this phase. The x86_64 `libstoreservicescore.so` and `libCoreADI.so` are in `crates/perun-cli/examples/adi-android/libs/`, with the Bionic `linker64` under `sysroot/bin/` and the system image it was extracted from alongside. The three Windows binaries — `CoreADI64.dll`, `CoreFP.dll`, `iTunes.exe` — are in the extracted iTunes tree this project has been running against. The day-by-day log, including the reproduction commands, is `FINDINGS.md`.

**The open question, restated after the 2026-09-29 re-measurement.** It is no longer "what fills the object at `0xd6560`", because that question was attached to the wrong address: the block at `0xd6560` decodes obfuscated state on the stack, publishes no error, and has no rejection branch, and `0xd6560` is not where `-45002` is formed. What is established is narrower and better posed:

- `-45002` is a precondition of `vdfut768ig` itself. Two different opcodes, seven frame shapes and a preceding `cvu8io98wun` all produce it identically, and the value is already in `edi` by the 57th instruction with `rdx` walking the caller's frame.
- The library allocates the gate object itself, at `0x5b517`, with `lock cmpxchg` from null into a host heap block. It is not a host-supplied object and no host is expected to supply one.
- So the question is **what the freshly allocated object must contain for the prologue to accept the call**, and the whole caller-supplied input space is now measured inert: opcode, frame, payload, `r8`/`r9`, call order, the state slot and the version export.

**Next steps, in order of value.** (1) **The initialiser is now known, so the question moves one level up: what are `r12`, `r15` and `rax` at `0x5b321`, and where do they come from?** The five stores at `0x5b321`–`0x5b32f` are unconditional, which means the object's three pointers are whatever the CFF computed before them, and those are the only values in the whole investigation that have not been traced to a source. Watching the registers at that block, or reading them in the same run that watches the block, turns "the object holds host pointers" into "the object holds *these* pointers, computed *there*". (2) The 256-byte block at `0x19dba0` is copied in one instruction from a **563-entry table of 8-byte records at `.rdata 0x17eca0`** — a static template in the image, not something derived from the call; whether that copy is a decode step decides whether the object is data or code. (3) The six obfuscated `CoreFP.dll` exports return `-42023` and `-42408` uniformly behind an argument guard; that guard is the nearest thing to a real caller this runtime has, and it has never been reversed. (4) The reference caller in `iTunes.exe` is **not** reachable by string search: that binary is a .NET ReadyToRun image, so its ADI call site is in managed code and a native rip-relative xref returns zero structurally. Look in the managed metadata, not in `.text`.

**Two shim blind spots, both now closed, both of which had been read as knowledge.** `PERUN_TRACE` did not cover the memory shims, so the earlier statements that `HeapAlloc`/`HeapSize` were "tolerated" rested on an instrument that could not see them. With `HeapSize` and `HeapAlloc` traced: **`HeapSize` is never called on this path at all** — zero times, and the return code is unchanged, so the constant 16 it used to return was load-bearing for nothing this project ever measured. `HeapAlloc` is called dozens of times, which is what sized the gate object. And `HeapSize` used to be described as returning 16 as a tolerated prototype; it now returns the real usable size, and a NULL pointer returns `(SIZE_T)-1` with `ERROR_INVALID_PARAMETER` as the real API does.


**Before trusting any single run.** Five instrument defects each produced a confident false result before being caught, and three theories in a row were refuted by a sweep that took seconds. Every claim in §5.8 has a control; a site that does not trap is evidence of nothing until a control that must trap does trap in the same run, and `--patch` values need their `0x` prefix or the run exits 2 and a live site reads as dead. The four named in the 2026-09-28 log were a window printing the oldest ring entries, a re-arm setting `RIP` to the faulting address, a trigger sampling registers before the instruction ran, and `--patch` needing its `0x` prefix. The fifth is the one that cost the most and it is the reason two claims in this section are being withdrawn now: **`PERUN_SEAL_DATA` reported one access per page rather than per address**, so for as long as it stood it could not distinguish "the body reads two globals" from "the body opens two pages" — and three globals on the same 4 KiB page, plus a 32-qword `memcpy`, were invisible for that reason. Any sealing instrument that un-protects a page must re-seal it after the retried instruction retires, or its output is a page census wearing the costume of an address log.

**Ptrace is available, and the runbook now uses it.** The custom trap-flag walker was written when `ptrace` was refused by the sandbox; that is no longer true, and hardware watchpoints are a strictly better instrument for the questions that remain. Three details are worth keeping because each cost a round. The agent's own shell has an empty `CapEff`, so `ptrace` fails for it and only `sudo` works — there is no seccomp filter involved, it is a capability. A breakpoint must be a **hardware** breakpoint: `break` writes `0xcc` into the page and perun rewrites the image sections during its own load, which silently erases the trap byte, so the site reads as never executed. And since perun maps the guest image itself, the dynamic loader never tells gdb where it is, so the breakpoint is armed from an `mprotect` hook once the target page is actually readable — the first `mprotect` is perun's own setup, long before the image exists.

### 5.8 ADI provisioning gate — the barrier map (2026-09-28, corrected 2026-09-29)

**Read this first: the front recorded below as `-45002` for several days was an artefact of this project's own probe, and every conclusion drawn from it is withdrawn.**

The probe used `--poke=0x19db98=scratch`, which writes a host pointer into a slot inside the library's own state. With that poke the call returns `0xffff5036` (`-45002`); **remove it and the same call returns `0xffff5024` (`-45020`)**. Removing every `--poke` gives `0xffff5016` (`-45034`). So the ordering is:

| probe | return | meaning |
|---|---|---|
| nothing poked | `0xffff5016` | `-45034` `unknownAdiCallFlags` |
| header and frame poked, **no** `0x19db98` | `0xffff5024` | `-45020` `invalidInputDataParamBody` — **the real front** |
| plus `--poke=0x19db98=scratch` | `0xffff5036` | `-45002` `invalidParams2` — **manufactured** |

Everything this file said about `-45002` — the "front" at `0x5b0a9`, the `test edi,edi` at `0x66bb8`, the 80 457-instruction walk, the gate object, the `lock cmpxchg` singleton, the three blocks and everything read out of them — describes the library's unwinding after it was handed a bogus internal pointer. It is not evidence about the barrier, and it must not be cited as such.

**The real front is `-45020`.** It is reached only with a correct version header: a real 16-byte payload whose first four bytes are `00 00 00 02` gives `-45020`, while the same call with that 16-byte buffer zeroed gives `-45018` instead, because `00 00 00 00` fails the version check first. The twelve bytes after the header make no difference: the real payload and a header-only frame both return `-45020`.

**Where `-45020` is published, on the clean path.** The walk stops at 222 374 instructions, and the publishing store is unconditional, exactly like the artefact it resembles:

    0x8ff00  lea  rsi,[rip-0x29]      # 0x8fede, the per-site base
    0x8ff07  add  rsi,rax             # target = base + rax, rax signed
    0x8ff0a  mov  edi,0xffff5024      # the code, materialised
    0x8ff0f  jmp  rsi

There is no `cmp`, `test` or `jcc` on the segment that decides it. The nearest conditional that follows is `0x8ff25 cmp QWORD PTR [rsp+0x80],0x0` — a **stack slot**, not the caller's packet and not the 96-byte frame — so the payload and the frame are not what selects the path; the routing was decided earlier in the flattened body. That is where the next search belongs, and the ring is now trustworthy enough to start it.

**The caller-supplied parameter body is not yet shown to matter.** Seven frame shapes, `r8`/`r9` over eight combinations, the pointer slot, the payload after byte 3, and the call order were all measured inert — on the `-45002` path, which this section has just established is not the barrier, so those results need re-running against `-45020` before they are believed.

**Not withdrawn, and still measured.** The seal instrument defect and its repair; the re-seal giving 42 accesses over 36 addresses; the frame sweep on the manufactured path; `0x19e9c8` being the heap handle; `0x19dda0` being read on **both** the clean and the poked path; `HeapSize` being called zero times; `cvu8io98wun` being called zero times across a complete Android run; and the cluster corrections in the CoreFP section below, which do not depend on the poke.

**The three real payloads, captured from the working Android engine** (`crates/perun-cli/examples/adi-android/`, files in `/opt/data/apk/x86/`):

| file | call | opcode | size | first four bytes |
|---|---|---|---|---|
| `payload_init_1.bin` | 1 | `0xb0eda7af` | 16 | `00 00 00 02` |
| `payload_init_2.bin` | 5 | `0xb0eda7af` | 16 | `00 00 00 02` |
| `payload_prov.bin` | 6 | `0xcfe0b46a` | 48 | `00 00 00 02` |

Calls 1 and 5 are byte-identical, and the bytes after the header differ between runs, so the tail is not a constant to guess at. **Every Windows-side hypothesis about the body rested on a synthetic frame with a synthetic header until now.**

**Nobody imports CoreADI statically.** A sweep of all 220 PE files under the extracted iTunes tree finds no import-table entry for `CoreADI` or `CoreADI64`, and the string `CoreADI.dll` occurs only inside the two copies of the library itself. The module is therefore loaded dynamically, with its name assembled or obfuscated at run time — which is why every name-based search for the caller has come back empty, and why a search in managed metadata (the binary is a .NET ReadyToRun image) is the remaining route.



The gate is a chain of checks, not one. On the clean path, without the `0x19db98` poke, three are passed and the fourth is the front.

| # | Code | Name | Status | Rule |
|---|---|---|---|---|
| 1 | `-45034` | `unknownAdiCallFlags` | **PASSED** | localized at RVA `0x66c2d`: `input_len >= cursor + 4` and `flags >= 8` |
| 2 | `-45018` | `invalidInputDataParamHeader` | **PASSED** | 4-byte big-endian packet header `00 00 00 01` or `00 00 00 02` — bytes 0..2 zero, byte 3 in {1, 2} |
| 3 | `-45019` | `unknownAdiFunction` | **PASSED** | the operation opcode is passed in `RCX`; five recognised magics below |
| — | **current front** | `-45020` `invalidInputDataParamBody` | **OPEN** | published at RVA `0x8ff0a` on the clean path, unconditionally; what routes there is not yet known |

`0x19db98` is **not** a gate. It was read as one because writing a host pointer into it moved the answer from `-45034` to `-45002`, and the conclusion drawn — that it is a NULL check the library needs — described the damage rather than the requirement. Nothing in the chain depends on it.

**Recognised opcodes (five of nine tested).** `0x632b8d6e`, `0x85fe63b0`, `0x3e58e7f9`, `0xcfe0b46a`, `0xb0eda7af`. **Not recognised (→ `-45019`):** `0xb23c691e`, `0xc774d292`, `0x4069d332`, `0x4069d333`, `0`. The match is exact and by equality: `0x632b8d6e − 1` and `+ 1` both fail.

**The success opcode is `0xcfe0b46a`.** The ordered Android phase dump puts the `SUCCESS` banner after call 6, which carries `0xcfe0b46a` and a 48-byte payload; calls 7 and 8 are `0x3e58e7f9` and run *after* the success. Most of this phase was spent on the wrong opcode, and that is why the convention question took as long as it did.

**The packet is four bytes.** Nothing past byte 3 is read: a big-endian body length in bytes 4..7, the `OtpPayload` struct, a 48-byte payload, 28 bytes of padding and a real 347-byte SPIM all produce the identical result, as does setting any single byte from `+0x04` to `+0x2c`. `frame[+0x00]` is a **pointer to the packet** and `frame[+0x08]` is its length; the earlier reading of those as an output buffer and a capacity is retired.

**`r8`/`r9` are read but inert** — eight combinations over `{0, 1, scratch, ctx}` each give identical results.

**What the body actually reads — the earlier claim of two globals was an instrument defect, and is withdrawn.** `PERUN_SEAL_DATA=1` seals the image's `.data` pages and reports each access as it faults. As first written it un-protected a page on its first fault and left it open, so it reported **one access per 4 KiB page, not one per address**; because `0x19dba0`, `0x19dda0` and `0x19db98` all sit on the page at `0x19d000`, a log of "two globals" was a log of "two pages". Re-sealing after each fault — the walker is already armed, so the retried instruction raises a trap that closes the page again — and printing the faulting `RIP` as well as the address gives **42 accesses over 36 distinct addresses**:

| address | count | faulting site |
|---|---|---|
| `0x19d088` | 1 | `0x5bcaf` |
| `0x19db98` | 1 | — (the slot `--poke=0x19db98=` writes, **and it is read**) |
| `0x19dba0` … `0x19dd90` | 32 | `0x70d51`, a single `memcpy`/`memmove` of 0x100 bytes |
| `0x19dda0` | 3 | `0x5b20f`, `0x5b517`, `0x5b720` |
| `0x19dda8` | 2 | `0x5bd0b`, `0x66035` |
| `0x19e9c8` | 2 | `0x1353ae` |

So the body does consult far more than two globals, the NULL slot the project has been poking is itself read back, and the 256-byte block at `0x19dba0` is written in one bulk copy rather than field by field.

**What writes `0x19dda0`, and what it is not.** A hardware write watchpoint on that address fires in the dispatcher at RVA `0x5b51c`, and the surrounding code is aligned and readable:

    0x5b510  mov    0x710(%rsp), %rbx     ; the global's address comes off the stack
    0x5b517  lock cmpxchg %rcx, (%rbx)    ; install if still null: 0 -> 0x56202830
    0x5b51c  sete   %dl
    0x5b51f  imul   $0x5ce7ce98, %edx, %eax
    0x5b525  lea    0x5ce7da08(%rsi,%rdx,1), %ecx

**The library allocates the gate object itself, during the call, and installs it with an atomic compare-and-swap from null.** The stored value is a host heap address, so this is the library's own allocation rather than anything a host supplied. Two consequences. The earlier statement in `FINDINGS.md` that `0x19dda0` holds a host-provided pointer that perun never supplies is **withdrawn** — the library supplies it from its own heap, 104 instructions into the call. And the address is not a literal anywhere in the binary: it is computed into a stack slot, which is why a rip-relative search for the global finds nothing and why the static scanners in the log read as "no writer". The remaining problem is therefore not a missing object but the contents of a freshly allocated one.

**The object is `HeapAlloc(flags=0, size=0x28)`, and the library initialises it itself.** With `HeapAlloc` in the trace, the address the `cmpxchg` publishes matches one line of the allocation log exactly, in the same process — the correlation is by address, not by inference:

    [perun] HeapAlloc(flags=0x0, size=0x28) = 0x555556201f70
    singleton 0x7c99dda0 -> 0x555556201f70

`flags=0x0` is not `HEAP_ZERO_MEMORY`, so the block arrives with whatever the allocator had in it — a recycled chunk, not a clean one. That matters only for how the readings below were obtained, and it is why the block has to be watched at the allocation rather than after: the address is fixed by gdb's ASLR being off, which makes a second run reproducible, and the writing is caught by a hardware watchpoint filtered to guest addresses.

**All five fields are written by five consecutive instructions at `0x5b321`–`0x5b32f`**, with the object in `r13`:

    0x5b321  pxor   %xmm0,%xmm0
    0x5b321  movdqu %xmm0,0x00(%r13)    ; +0x00 and +0x08 in one 16-byte store
    0x5b327  mov    %r12,0x10(%r13)     ; first host pointer
    0x5b32b  mov    %r15,0x18(%r13)     ; second
    0x5b32f  mov    %rax,0x20(%r13)     ; third

Straight-line, no dispatch, nothing conditional. **An earlier note in this section said the two zero qwords were what a fresh glibc arena returned and not something the library wrote. That is withdrawn: the `pxor`/`movdqu` pair zeroes them deliberately, and the emptiness an emptiness test would read here is the library's own act rather than an artefact of the host allocator.** That correction matters, because the other reading would have made the host's allocator part of the explanation of a guest's decision.

A 40-byte block is five qwords, `+0x00`…`+0x20`: **there is no qword at `+0x28`**, and any reading that names one is reading past the allocation. Two later writes touch the object, at `0x5b951` and `0x8cb1e`; the `+0x10`/`+0x18`/`+0x20` pointers visible at publication are the ones from the initialiser, and the second pointer is revised once after it.


**The caller cluster, corrected (2026-09-29).** The range the log gives as `CoreFP.dll` RVA `0x1b5da30`–`0x1b67b3d` **is not code**: `.text` ends at `0x196aa10` and that range is inside `.rdata`. The logged address is a VA with the base not subtracted; RVA `0x155da30` is code, and it holds a dense run of exactly eight `call rsi` at `0x155e592, 0x155e5b5, 0x155e5dd, 0x155e600, 0x155e628, 0x155e653, 0x155e676, 0x155e69e`.

**The two claims the log makes about it are both inverted.** `rcx` is *not* varying — `mov rcx,r12` precedes every one of the eight, and `r12` is `lea r12,[rsp+0xd8]` at `0x155e539`, a stack address. What varies is the first qword of the struct that `rcx` points at, and those eight values are **pointers to eight different sources, not opcodes**:

| # | call | written to `[rsp+0xd8]` by | source |
|---|---|---|---|
| 1 | `0x155e592` | `mov [rsp+0xd8],r8` | `r8` |
| 2 | `0x155e5b5` | `mov [rsp+0xd8],r15` | `r15` = the **incoming rdx** (`mov r15,rdx`, `0x155e529`) |
| 3 | `0x155e5dd` | `mov rax,[rsp+0x28]` | parent slot `+0x28` |
| 4 | `0x155e600` | `mov [rsp+0xd8],r14` | `r14` = the **incoming rdi** (`mov r14,rdi`, `0x155e54e`) |
| 5 | `0x155e628` | `mov rax,[rsp+0x68]` | parent slot `+0x68` |
| 6 | `0x155e653` | `mov rcx,[rsp+0xf0]` | parent slot `+0xf0` |
| 7 | `0x155e676` | `mov [rsp+0xd8],r13` | `r13` |
| 8 | `0x155e69e` | `mov rax,[rsp+0x30]` | parent slot `+0x30` |

**The parent frame is 20 bytes at `rsp+0xd8`, with three fields**: `+0x00` the pointer above, `+0x08` a dword computed as `[rbp-0x42ae2992] - edi`, `+0x0c` a dword `ebx = r13d - edi + 7`. The four parent slots the calls read are filled immediately before, at `0x155e4db`–`0x155e509`, and all four come from just two registers — `mov [rsp+0x28],rbp`, `mov [rsp+0x30],rbp`, `mov [rsp+0xf0],r14`, and `mov [rsp+0x68],rax` where `rax` was just read back from `[rsp+0x68]`. `r14` itself was loaded from `[rsp+0xf0]` much earlier at `0x155e380`, so these are the flattened dispatcher's own state being shuffled, not a caller's arguments: iTunes never writes this frame.

**And the eight opcodes are not recoverable from here.** The call target itself is computed, not stored — `rsi = 0xffffffffd1fb9bc9 + [0x1fe4270 + r13*8]` — and the table at `0x1fe4270` holds high-entropy values rather than code addresses in the file, so it is not a function-pointer table as it stands on disk.

 **What the object's three pointers hold, and how big they are (2026-09-29).** Read at the initialiser, sizes from `malloc_usable_size`:

| field | size | contents |
|---|---|---|
| `+0x10` | **88 bytes** | `0x8000000000000002`, three zero qwords, then a UTF-16 string reading `8=0x10 --poke=ctx+0x0=scratch --a…=0x19db9` |
| `+0x18` | **104 bytes** | `0x8000000000000001`, zeros, the caller's `scratch` (`0x7ffff7fb6000`), the lengths `0x8`/`0x10`/`0xc`, and at `+0x70` the ASCII **`vdfut768ig`** |
| `+0x20` | **120 bytes** | header, `0x0000010000000000`, zeros, then `0000000 00:00`, a run of spaces, `\n[vdso]\n`, `lock]\n`, `n/libgcc_s.so.1` |

**This is the host's live command line, and that is worth stating carefully because two wrong readings sat on top of it.** The `+0x10` text is unmistakably ours — `8=0x10 --poke=ctx+0x0=scratch --a…=0x19db9` — and `[vdso]` with `libgcc_s.so.1` in `+0x20` is perun's own process map. A native Windows PE cannot know about Linux `/proc` or about this harness's flags out of nowhere, so the only question is how it gets them, and two mechanisms were considered and one survives.

The first candidate was a stale allocator chunk: `HeapAlloc` takes `malloc`, glibc hands back a recycled block, and the host's freed CLI buffers show through. **Tested with a rebuild that forces `HeapAlloc` to `calloc` — every block zeroed at allocation, nothing stale to inherit — and the text stays, byte for byte.** So that mechanism is out, and the `vdfut768ig` in `+0x18` even becomes correctly spelled where a recycled chunk had produced `vdut768ig`.

The second candidate is that the block is filled once, at start-up, from a snapshot. **Also out.** Changing one argument on the command line, `--poke=ctx+0x8=0x10` to `0x20`, changes the corresponding characters at the corresponding offset inside `+0x10` — `0x002d00200030003 1` to `...0 3 2` — so the text is read *during* the call and tracks the current argv rather than a copy of it.

**So the library does read the host's own process state on this path**, which is host-context collection after all — the reading originally written here was right in substance. What is *not* established is the mechanism: the guest reaches no file, registry or process API through the shim table here, so the read does not go through anything this project intercepts, and whether it is a raw syscall or a walk of its own address space is not known. Recorded that way rather than as a result either way. The `+0x20` map text is the same class of thing and has not been tested for liveness the same way.

None of the three is a direct `HeapAlloc` return: 28 allocations are logged in a run and none lands on these addresses, which fits the earlier finding that the static CRT reaches the allocator without going through the IAT. They are arena blocks of its own.

**An intermediate note in this file over-corrected**: it withdrew the host-context reading on the strength of the `calloc` test, which only refuted the stale-chunk mechanism. Withdrawn no further; the calloc result stands on its own and is what the text above records.

**The first 57 instructions, and why that reframes everything (2026-09-29).** `PERUN_STEPS=60` prints the whole opening, because the ring window covers a walk that short. It is a straight line with **no conditional branch anywhere in it**:

| steps | RVA | what |
|---|---|---|
| 0–9 | `0x5afc0`–`0x5afd1` | prologue, `mov eax,0x16a8` |
| 10–23 | `0x131760`–`0x1317af` | stack-probe thunk |
| 24–30 | `0x5afd6`–`0x5b001` | `movaps` saves |
| 31–55 | `0x5b00b`–`0x5b0a9` | dense block, then `lea ebp,[rax+4]`, `lea rbx,[0x15fc90]`, `movsxd rbp,[rbx+rbp*4]`, `lea rbx,[0x5b07c]`, `add rbx,rbp` |
| 56 | `0x5b0ae` | `jmp rbx` — and `edi` has just become `0xffff5036` |
| 57 | `0x5b11f` | next block, still `edi = 0xffff5036` |

**So `-45002` is not selected by a test — it falls into place.** There is no `cmp`/`test`/`jcc` on the segment that decides it, which is stronger than "the decision is early": there is no decision there at all. The remaining 80 400 instructions are the flattened body's unwinding, and the `test edi,edi` at `0x66bb8` near the end is only asking whether a result was staged, not which one.

**The incoming `rax` is not the selector either.** The dispatch index is `eax+4`, so the obvious lever is the register `rax` on entry — and sweeping it over `0, 1, 2, 3, 4, 5, 8, 0x10, 0x40, 0xa3, 0xfffffffe` under a hardware breakpoint at `0x5afc0` returns `0xffff5036` for every one of them. `rax` is overwritten before the index is formed, so this measurement says nothing about the gate and is recorded as a negative result rather than a lead.

**What is left is narrow and stated as such:** the first block is reached by an index computed in the prologue's own arithmetic, and the thing that decides which block that is has not been located. The walk to the epilogue and the ring around it are now trustworthy, so the search can start from instruction 0 with 57 steps of context rather than from a guessed address.

**The exit, and the branch that chose it (2026-09-29).** The epilogue is the only frame restore in the image: `add rsp,0x16a8` at `0x5b10b`, unique in the whole of `.text`, reached after 80 457 instructions — the `.pdata` end at `0xb5c98` is not the path taken. The last 128 instructions before it are visible once the ring folds correctly, and they read:

    0x66bb8  test   edi,edi                 ; <- the decision
    0x66bba  sete   al
    0x66bbd  lea    ecx,[rax+0xa8b]         ; index 0xa8b if edi!=0, 0xa8c if edi==0
    0x66bc3  lea    rdx,[rip+0xf90c6]       # 0x15fc90, the CFF block table
    0x66bca  movsxd rcx,[rdx+rcx*4]
    0x66bce  lea    rdx,[rip-0x1f]          # per-site base 0x66bb6
    0x66bd5  add    rdx,rcx
    0x66bd8  jmp    rdx

    0x5b0a9  mov    edi,0xffff5036         ; unconditional, on the other path
    0x5b0ae  jmp    rbx
    0x5b0b0  mov    eax,edi                 ; the path actually taken
    0x5b0b3..0x5b109  movaps xmm6..xmm15
    0x5b10b  add    rsp,0x16a8
    0x5b112..0x5b11e  pop×7 ; ret

**So the answer to "which branch returned the error instead of zero" is `test edi,edi` at `0x66bb8`, and the operand is the register `edi` — not a memory operand and not the input frame.** What that makes `edi` is more useful than the name: **the pending result code.** The walker's ring has `edi = 0xffff5036` already at the test, and the dispatch then reads index `0xa8b`, fetches `table[0xa8b] = 0xffffffffffff44fb` (a negative, sign-extended offset), adds the site base `0x66bb6`, and jumps to `0x5b0b1` — straight into the frame teardown, *skipping* the `mov edi,0xffff5036` at `0x5b0a9`, because the code was already in hand.

The flattened dispatcher therefore branches on **whether a result has been staged**, not on which result it is; the materialising store at `0x5b0a9` is the path taken when nothing is staged yet, and `mov eax,edi` at `0x5b0b0` is what turns the staged register into the return value. This also settles why hunting for a `cmp`/`jne` at the exit finds nothing: the exit is unconditional, and the decision is one CFF-table index earlier.

**The ring had to be fixed before any of this was visible, and the fix is one line of arithmetic.** The slot index is a bitmask and the reader folded with a modulo, and at 160 000 the two disagree — `160000-1` is `0x270FF`, bits 8..11 clear — so every index with any of those bits set landed on a small slot while the slots being read stayed empty. It reported 128 zero entries after 80 457 instructions, and shortening the walk changed nothing, which is what a systematic fold mismatch looks like and not what a too-small window looks like. The ring is a power of two now. Two wrong diagnoses were made before that, both from reasoning and neither tested; the arithmetic was the thing that settled it.

 Four hardware write watchpoints on the first four qwords, armed at `0x5b51c`, are live to the end of the call and none fires. The scheme is build-then-publish, and the fields are final when the `cmpxchg` retires — so the object does not need filling, it needs *assembling correctly* before publication.

**`0x19e9c8` is the heap handle, not a CFF table.** gdb's decoder — not objdump's linear sweep, which is not instruction-aligned in this body and whose operand annotations have already produced one wrong conclusion this phase — reads it directly:

    0x1353ae: mov  0x69613(%rip),%rcx    # 0x7c99e9c8   -> rcx = hHeap
    0x1353b5: mov  %rbx,%r8                       -> dwBytes
    0x1353b8: xor  %edx,%edx                       -> dwFlags = 0
    0x1353ba: call *0xce68(%rip)                   # HeapAlloc

The observed `rbx = 0x228` matches the logged `HeapAlloc(flags=0x0, size=0x228)` exactly. The imports are reached by direct `call [rip+disp]` rather than through a thunk chain — `HeapAlloc` at `0x1353ba` and `0x1354e9`, `HeapFree` at `0x135352`, `HeapReAlloc` at `0x13f32d` — and `HeapSize` has a thunk at `0x13f2c7` that is never reached, which agrees with the shim-side count of zero calls. Note that this route covers only a fraction of the allocations: dozens are made and the gate object is not among the ones these sites serve, so the static CRT allocates largely without going through the IAT and **static IAT analysis does not find the site for a given allocation**. Tracing does.


**`-45002` is raised before the opcode is dispatched, and is not about the frame.** Three measurements, each against the same baseline:

- the init opcode `0xb0eda7af` and the provisioning opcode `0xcfe0b46a` both return `0xffff5036`, so the code is a precondition of the export rather than a per-operation check;
- seven frame shapes — cursor 0 and 4, seven pointer slots filled, the Android caller's 16-byte payload at `+0x50`, length `0x58`, length 0, length 4 — all return `0xffff5036`;
- `cvu8io98wun` returns 0 and changes nothing that follows.

`cvu8io98wun` is settled from the other build as well, and the two agree. A GOT hook on its slot (`0x255818`), installed and confirmed, captured **no call at all** across a complete successful Android provisioning run: eight `vdfut768ig` calls, the `SUCCESS` banner and both `X-Apple-I-MD` headers, with zero `cvu8io98wun` entries in the log. So the "missing initialisation step" account of this gate is **refuted from both directions** — the function is not called by `libstoreservicescore.so` at all, and on Windows calling it first changes nothing.

At the 57th instruction, where the value first appears, `rdx` points at the caller's frame plus one, so the code is formed while the body is walking what it was handed.

**The `0xd6560` block is not the front, and there is no vector there.** `%r11` is the incoming `rcx` — the disassembly is `mov r11, rcx` as the sixth instruction — and at RVA `0xd6583` it holds a **stack address** (`rsp + 0x370` in the guest), not a heap block and not the poked scratch. There is no vtable at `[r11+0x00]`. The two fields that the older note read as `_Myfirst`/`_Mylast` are **byte-for-byte equal and non-zero** (`0x3b334ef6f339c6bb`), and `[r11+0x20]` is a copy of the derived key `rax = (rax ^ r11) * 0x49255e13`, with the low dword of `[r11+0x00]` differing from `rax` by exactly one. So the block decodes an obfuscated value and writes `[r11+0x28]`; it publishes no error code, has no rejection branch, and ends in a bare `ret`. The emptiness test that anchored seven independent accounts of this code is an interpretation of two equal obfuscated values, not a measured predicate.

**The caller.** In `libstoreservicescore.so` — which is not flattened — the region `0x1dbbf3`–`0x1dbd2d` stamps the version-2 header (`00 00 00 02`), advances the cursor at `0xc(%r9)` by 4, and calls through the GOT slot at `0x255820`:

    1dbbf3: mov  (%r9),%rdx
    1dbbf6: movw $0x0,(%rdx)
    1dbbfb: movb $0x0,0x2(%rdx)
    1dbbff: mov  %r8b,0x3(%rdx)
    1dbc03: addl $0x4,0xc(%r9)
    ...
    1dbd23: mov  %r15d,%edi
    1dbd26: mov  -0x220(%rbp),%rsi
    1dbd2d: call *0x79aed(%rip)      # 0x255820

The strings `vdfut768ig` and `cvu8io98wun` are present in both `iTunes.exe` (38 MB) and `CoreFP.dll` (33 MB), and **neither string can be used to find the caller.** A rip-relative `lea` scan of every code section returns zero, there is no 8-byte absolute pointer to the string, and it is not part of a name table. For `iTunes.exe` the reason is now known rather than merely observed: that binary carries an `RT_CODE` section, so it is a **.NET ReadyToRun image** and its ADI call site lives in managed code, where the resolution runs through metadata rather than through a native xref. A zero xref count there is structural, not a failed search, and the next place to look is the managed metadata's `DllImport`/`ManagedNativeMethod` entries. `CoreFP.dll` imports only KERNEL32 and ADVAPI32 despite being 36 MB, and both modules have garbage export-name tables — the same obfuscation as CoreADI64.

**The recognised opcode list is a sample, not the set.** A byte scan of the whole image finds **none of the five recognised values as a raw dword anywhere** in `CoreADI64.dll`, so the comparison is computed rather than stored; the five were recovered by sweeping, and nothing bounds the set from above. The asymmetry is real and unexplained: the four *rejected* values do appear, and `0x4069d333` appears 17 times, at least some of them as genuine `cmp ecx, imm32`. So the dispatcher explicitly knows the values it refuses and computes the ones it accepts. Any name assigned to an opcode from a sweep — "init", "provisioning" — is an inference, and `0xb0eda7af` being called "init" rests on the Android ordering rather than on anything in the Windows binary.

**The Android and Windows opcode sets differ, which the sweep above can now be read against.** In the recorded Android session `0xb23c691e` and `0xc774d292` both return 0 — they are valid there — while the same two return `-45019` on the Windows build. So "not recognised" in the table above means "not recognised *by this build*", and the Android list cannot be used to guess the Windows one. The full recorded session is six calls on one address space: `0xb0eda7af`, `0xb23c691e`, `0xc774d292`, `0xc774d292`, `0xb0eda7af`, `0xcfe0b46a`; the first and fifth share an opcode and differ only in payload, so the sequence is not a simple ordered list of operations.

**`CoreFP.dll` loads and runs here, and has not yet been pushed.** It needed `GetModuleFileNameW` and `IsValidCodePage` to get through `DllMain`, and now loads at `0x7c800000` with `DllMain` TRUE and all 113 shims resolved. Its six obfuscated exports return `-42023` and `-42408` uniformly — a shared argument guard — and none of them reaches `GetProcAddress` for either export name, so the name-based route into the caller is closed from both directions. That guard is the nearest thing to a real caller this runtime has and it has never been reversed.

**Three doors, closed by measurement rather than by argument.** The guest makes no filesystem call, no dynamic load and no hardware query on this path, so: an `adi.pb` from the Android run cannot be decrypted here and every theory that depends on its key predicts a failure at a point the call never reaches; and a hardware-identifier vector cannot be built because the collection never happens. The `ADIErrorCode` enum names every code, and the check at `0x66bfc` is flag arithmetic rather than the size test it was read as for most of the phase.

**Two methods, both paid for.** A sweep is a measurement and a single run is a hypothesis — three consecutive theories were refuted by a sweep that took seconds and would have killed each at formulation. And on the instrument side, a site that does not trap is evidence of nothing until a control site that must trap does trap in the same run: four instrument defects each produced a confident false result first (a window printing the oldest ring entries, a re-arm setting `RIP` to the faulting address, a trigger sampling registers before the instruction ran, and `--patch` needing its `0x` prefix).

### 5.8c The transform exists and is state-dependent; it is not the barrier (2026-09-30)

**Corrected later the same day: the closed form below was measured under one
configuration and does not hold in general. Read the correction before the
result.**

The flattened body at RVA `0x6783f` runs a byte loop over the caller's packet.
The loop is real: 16 iterations, cursor `r9 = 0x0 .. 0xf`, source `[rsp+0x40]`,
destination reloaded at `0x67888c` from `[rsp+0x48]`, store at `0x67891`. The
body is MBA-obfuscated — `add dl,0x3e` and `xor dl,0x3e` annihilate, and `r11` and
`esi` are computed on `0x67886b`–`0x678883` and never read.

Under an armed walk, where `rax` at `0x6785c` measured `0xe827d80b`, the output
was exactly

```
out[i] = ( in[i] + 0x63 + 0xe7*i ) mod 256
```

verified on three runs of 16 bytes each: an all-zero input, the payload the
Android engine hands the init call, and an input derived from the formula. By the
disassembly the only inputs to the stored byte are `rax` and the source byte, and
`0xe7` is the immediate of the `imul` at `0x6782c` — so for a **fixed** `rax` the
formula is right.

**The same input with the walk disarmed gives a different answer.** Input
`9d b6 cf e9` at buffer bytes 4..7, four consecutive runs at different ASLR
bases:

| configuration | bytes 4..7 after the call |
|---|---|
| walk armed | `00 00 00 01` |
| walk disarmed | `cc 3a 2e dd` (identical in all four runs) |

and in the disarmed configuration the output is **not** affine in the input
byte: `in=0x01 → 0x74` implies a constant term of `0x73`, while `in=0x9d → 0xcc`
implies `0x2f`. Since `rax` and the source byte are the only inputs the
disassembly admits, the source byte at cursor 0 in that configuration is not the
byte that was supplied, and that is unresolved.

So the closed form is a property of one guest state, not of the code, and the
constant `0x63` is not established as a constant. The output is nonetheless
deterministic within a configuration.

**What holds regardless: feeding the transform does not move the barrier.** With
the walk disarmed, three inputs — `9d b6 cf e9`, `01 1a 33 4c`, and zeros at
bytes 4..7 — all return `0xffff5024`. The marker is not what is being rejected,
which is consistent with two further measurements: `00 00 00 01` appears in
**every** Android call including the one returning `-45001`, so it is not a
success flag; and the publisher of `-45020` is at RVA `0x905c2`, not `0x8ff0a`
(see 5.8d -- `0x8ff0a` was an address that publishes no error code, and the
claim that it "never executes" was drawn from traces that stop at step 109,205
and never covered the step where any publisher runs).

**The 12 bytes `c9 34 19 2e 14 f2 ae 3f 98 49 66 ca` are `payload_init_1.bin[4:16]`** —
the packet tail past the 4-byte header, captured by the dumper in this tree. The
block is absent from `libstoreservicescore.so` as bytes; the earlier reading of it
as "origin unknown" was wrong because the search looked in `.rodata` for
something that lives in our own Android dump. `kq56gsgHG6` computes a *different*
12 bytes on its own stack, from the address of its own local, with `0x2442a4` =
`0x848` as the salt that cancels the address mixing — the consumer at `0x1d09f0`
subtracts the same 32 bits, so the jump target is `0x1d0a3b` for every stack
address. It is not `ADILoadLibraryWithPath`, and it is not this project's caller.

**Where `-45020` comes from is still open.** The publisher never executes, so the
value is set where the walk does not attribute it, and the transform's
state-dependence says the seeded state is the live variable rather than the
packet. `CoreFP.dll` is the only remaining candidate for a real caller.

Full report, with the two disassemblies, the four repeated runs and the
reproduction commands: `REPORT-0x6783f-kq56gsgHG6.md` in the analyst's tree.


**WITHDRAWN 2026-10-01 — the block at `0x8f064` was never there.** The only real
`mov edi, 0` in the CFF region is at RVA **`0x140f44`**; the bytes at `0x8f064`
are `9f c0 31 c9 81 ff 8b 1f`, i.e. mid-instruction. The earlier figure came from a
linear sweep that matched an unaligned offset, and it was reported as the round's
headline result on the strength of a byte pattern nobody checked against the file.
The address is corrected everywhere; the finding stands only as "the CFF contains a
`mov edi,0` at 0x140f44", which is not yet shown to be on this path.


**And it is not on our path either.** Counting executed RVAs over the whole
recorded walk: `0x905c2` appears **once**, the epilogue `0x5b0b1` once, and both
`0x8f064` and the real `mov edi, 0` at `0x140f44` appear **zero** times. So there
is no known success site on this path at all — not at the address that was
claimed, and not at the real one. Any statement that a success block has been
"located" is wrong; what exists is that the CFF region we execute publishes error
codes and we have not found where it would publish zero.

**Both candidates are data, not code.** Disassembling `0x140f44` yields
`add byte ptr [rax], al` repeated -- a run of zero bytes in a data region -- so the
`bf 00 00 00 00` there is a byte-pattern coincidence, not a publisher. And
`0x8f050..0x8f078` decodes to overlapping MBA garbage. Neither address is code,
neither has a `jmp` to answer for, and neither is reached on this path.

**Across the whole walk, exactly one code is published.** The walk executes
11 593 distinct RVAs, and of the blocks that publish a return value only one is
reached: `0x905c2`, once. Nothing else in the error set is entered. So the graph
does not "choose an error over a success" on this path -- it reaches one
publisher and stops, and whether another block is reachable at all is not shown by
this run.

**`aslgmuibau` is a dispatch stub, not the spim packer.** At RVA `0x1d1a70`, 77
bytes, and the same shape as `kq56gsgHG6`: a value derived from the address of its
own stack local, mixed with a table load at `rip+0x72832`, 12 bytes stored, then a
call to `0x1ddeb0`. Whatever packs the SPIM is below that call, so the plan that
read the contract out of `aslgmuibau` has to follow `0x1ddeb0` instead.

**How the header and the cursor are packed** (RVA `0x1dbbf3` in
`libstoreservicescore.so`):

```
1dbbf3  mov   rdx, qword ptr [r9]      ; r9 = the output cursor block
1dbbf6  mov   word  ptr [rdx], 0         ; bytes 0..1 = 0
1dbbfb  mov   byte  ptr [rdx + 2], 0     ; byte 2 = 0
1dbbff  mov   byte  ptr [rdx + 3], r8b   ; byte 3 = version, 1 or 2
1dbc03  add   dword ptr [r9 + 0xc], 4    ; advance the cursor by 4
```

So the header is exactly `00 00 00 <version>`, which is the four-byte header
measured on our own runs, and the cursor block carries an **output pointer at
`+0x00`** and a **byte offset at `+0x0c`**. Where the SPIM body and its length
enter this block is not yet located; `aslgmuibau` and `0x1ddeb0` are both CFF
trampolines and neither packs anything.

**Still open in step 1: the SPIM body and its length.** Searching `.text` for the
exact little-endian dword `0x15b` (347) gives six hits -- `0xdc411`, `0x126462`,
`0x13255a`, `0x1403c8`, `0x1487b6`, `0x1c0869` -- and **none of them is near
`0x1dbbf3`**, where the header is packed. So the block that writes the header and
the block that carries the body are different, and the cursor is passed on
through another register rather than `r9`. The four points in that window that
touch `r9` are the header write and the offset bump; nothing else does.

**The search for 347 was itself invalid.** Disassembling the six sites the byte
search returned shows every one of them is a false positive: at `0x1c0867` and
`0x1403c6` the bytes `5b 01 00 00` are the *displacement* of a `jne`/`je`, not a
length constant. So the SPIM length is **not a literal in the code** -- it is
computed, or passed in, and cannot be found by scanning for 347. This is the
fourth time this round a byte pattern was promoted to a finding without
disassembling around it; the rule that finally holds is: read the instruction, not
the bytes.

**Linear disassembly of this region is not usable.** Sweeping
`0x1db800..0x1dd000` decodes nothing at all -- not even the two instructions at
`0x1dbbf3` that decode correctly when the sweep starts at `0x1dbbd0`. The flattened
body has no instruction alignment a linear sweep can find, so the only two
`r9` writes previously reported survived on a lucky start offset and nothing else
in the region can be read this way.

**So step 1 has to be answered dynamically, not statically.** The Android engine
already runs natively in this tree and answers `ec: 0`; a breakpoint or a dump at
its call into `vdfut768ig` yields the SPIM pointer, its length and the output
buffer **from the real caller**, which is precisely what step 2 needs and what no
amount of decoding of this region can supply.

**To run the engine again, `ANDROID_NDK` must point at `/opt/data/ndk`.**
`run-native.sh` looks under `$HOME/ndk/android-ndk-*`, `CC` resolves empty, and the
script exits before it builds or runs anything -- silently, with no output. The NDK
is at `/opt/data/ndk/android-ndk-r27c`. This is the lane where the real caller
executes, so it is where step 1 has to be answered.

**The engine runs again, and hangs on the network.** Two things blocked it and
both are now pinned. `run-native.sh` globs `$ANDROID_NDK/android-ndk-*/...`, so
`ANDROID_NDK` must be the **parent** -- `/opt/data/ndk`, not
`/opt/data/ndk/android-ndk-r27c`; with the wrong value `CC` is empty and the script
exits before building, printing nothing at all. With
`ANDROID_NDK=/opt/data/ndk SYS_IMG=/opt/data/x86sys/system.img` the engine
**builds, repoints `PT_INTERP` at the Bionic loader and starts** -- and then emits
no output and does not exit. It reaches provisioning, which is a network round
trip to Apple; in this sandbox that call does not return. So the lane for step 1
is restored, and its remaining obstacle is reachability, not tooling.

**Where the engine stops, and why it is not yet diagnosed.** After
`PT_INTERP -> /tmp/pa.so` the process starts and emits nothing, sitting in
`futex_do_wait` with a single thread. Two diagnostics were tried and neither
closed it: `strace` without privilege is refused (`ptrace` is unavailable to the
agent, as it is throughout this runtime), and under `sudo` the trace fails at
`execve` with `EACCES` on the repointed binary. So the block is located to
"running, silent" and no further; the next probe has to be something other than
`strace` -- reading `/proc/<pid>/stack` and `/proc/<pid>/syscall`, or running
the engine under `gdb`, which this runtime does support with `sudo`.

**The block is before the network, not in it.** Listing `/proc/<pid>/fd` for the
live engine: four descriptors -- `/dev/null`, the log twice, and **`/proc/stat`**,
which it opened and read. There is **no socket open at all**. It never reached
provisioning and never dialled GSA, so the silence has nothing to do with
reachability. `entropy_avail` is 256 and `/dev/urandom` reads, so it is not
entropy starvation either. It opens `/proc/stat`, then blocks on a futex in a
single thread: a **lock**, not a syscall wait, inside the Apple crypto seeding
path. That is the last barrier in front of step 1, and it is now specific
enough to name a frame at with `sudo gdb` and a hardware breakpoint.

**Corrected twice more. The block is a futex wait inside Bionic's libc.**
Attaching `sudo gdb` to the live process and unwinding it gives frame 0 in
`syscall` and frame 1 in `__futex_wait_ex` (`pthread_mutex.cpp`), both in
`libc.so`. It is **not** the loader: the load was wrong twice, first to crypto
seeding and then to the Bionic loader. What survives verification is narrow and
worth stating as such: one thread, `wchan=futex_do_wait`, no socket, no
entropy starvation, blocked inside the C library rather than inside anything
Apple wrote. The frames above it are unrecoverable here -- Bionic carries no
debug symbols and two return addresses are outside every mapping -- so **which
lock is being waited on, and by whom, is not yet established.**

Note the method note this round earned twice: `wchan` and a file-descriptor
list narrow a hang but do not identify it. The unwind is what identified it, and
only after attaching. `strace` was refused here for a reason that had nothing
to do with `ptrace` -- the failure was `execve`, not the tracer -- and that was
another conclusion reached before checking.
**Corrected: it is stuck in the loader, before any Apple code runs.** The
previous entry blamed the crypto seeding path. `/proc/<pid>/maps` settles it:
mapped are `adi_native`, `linker64`, `libc.so`, `libm.so`, `libz.so`,
`libnetd_client.so`, `libc++_shared.so` and `libcurl.so` -- and **nothing else**.
`libCoreADI.so`, `libCoreFP.so` and `libstoreservicescore.so` are never loaded,
so the engine never reaches a single line of the code under study, never loads
the ADI library at all, and the futex is the Bionic loader resolving or
initialising its dependency list. `libnetd_client.so` being present is the tell:
it is a late Bionic dependency, and the process is inside loader setup rather
than inside anything Apple wrote.

So the lane is not "running and silent" -- it never ran. The observable
`wrap_vdfut` will not fire on this lane until the loader finishes, and the
loader is where the work has to start.

**Attaching works; launching under the debugger does not.** Two mechanisms, one
usable. `sudo gdb -p <pid>` reaches the running engine and the unwind names the
block. Launching the same binary *under* gdb does not: without privilege gdb needs
ptrace for the child and the runtime denies it, and under `sudo` the exec of the
repointed binary fails `EACCES` although the file is 0755, `linker64` is 0777,
`/tmp/pa.so` resolves and sudo works. The same `EACCES` under `strace` is what
finally showed the earlier refusal had nothing to do with the tracer.

So breaking on `__futex_wait_ex` *before* the wait is unavailable, and the lock
holder must be read out of the already-blocked process instead. The futex
address is the syscall's `rdi`: `0x75683cdabd18`, inside libc.so's data.
**The futex has no owner and no queued waiter.** Read out of the blocked
process, since catching the wait would need a launch under gdb:

    futex word   = 0xd1274002
    owner  (+4)  = 0
    neighbours   = all zero
    rsi = 0x80   r8 = 0x30   threads = 1

Nothing holds the lock and nobody is queued behind it. One thread, parked on
a wake that was never sent -- not a contended mutex and not a lock held by a
peer, because there is no peer. It is a one-shot synchronisation whose
signaller never ran, which fits a library waiting on a callback or a second
participant that this build never reaches. Above the wait the frames are
unrecoverable (no Bionic symbols) and two values on the stack, `r9 =
0x3770ac57` among them, are not mapped code.

That is the limit of interrogating the process from outside. Answering it
properly needs the process started under a debugger, which this runtime
refuses for the two measured reasons above. That boundary is now named
rather than assumed.
**Root cannot exec these binaries at all -- that is the launch boundary.**
Measured four ways, the first that isolates it from my own errors:
`sudo -n ./adi_native` fails, and so does a byte-identical copy at `/tmp` with
mode 0755, while `hermes` runs the original without complaint. `sudo -n id` is
uid=0 and the Bionic `linker64` in the same tree execs fine under root, so it
is not the filesystem, not the interpreter and not sudo: a sandbox policy stops
root from exec'ing these binaries. Attaching to a running engine works
precisely because that needs no new exec.

`LD_PRELOAD` is not an alternative either: `libc.so` carries 67 Bionic markers
and `linker64` 8, and `LD_PRELOAD` is read only by glibc. `/etc/ld.so.preload`
does not exist.
**The wait is `pthread_mutex_lock`, on a mutex that was never initialised.**
`libc.so` carries 2 666 FUNC symbols, so this was decided statically, with no
exec and no privilege. Only two direct calls to `__futex_wait_ex` (`0x282e0`)
exist in the whole image:

    call at 0x28563  ->  pthread_mutex_lock     + 0x103
    call at 0x289a8  ->  pthread_mutex_timedlock + 0x1b8

So it is not a condition variable and not a barrier -- it is a mutex lock. And
the mutex does not look initialised:

    futex word   0xd1274002   (neither unlocked=0 nor a Bionic owner value)
    owner  (+4)  0
    queued       none
    threads      1

A mutex with no owner, nothing queued, and a `__lock` word that is not a valid
lock value is a struct nobody initialised. The thread sleeps on a lock that
cannot be signalled -- consistent with the Apple stack waiting on an
initialisation callback or a second participant this build never reaches, and
with the fact that it never loads `libCoreADI.so` at all. This is as far as
the process can be interrogated; naming the caller of `pthread_mutex_lock` is
the next step and needs no new privilege.
**The wait is unsatisfiable by construction.** Read from the blocked process --
the same registers the kernel had:

    rdi = uaddr   0x70d29f3bdd18
    rsi = op      0x80            128 = FUTEX_WAIT_PRIVATE
    rdx = val     0xd93f4002
    *uaddr        0xd93f4002      <- already equal to val
    *(uaddr+4)    0               owner
    *(uaddr+8)    0               queued

`FUTEX_WAIT` blocks until the word differs from `val`. It already equals `val`,
so no wake can satisfy it and the wait cannot end. That is the whole block: not
contention, not a lost signal, not entropy, not the loader.

The low 16 bits are `0x4002` in every process measured -- `0xd1274002` in one,
`0xd93f4002` in the next -- while the upper half varies per run. So the upper
half carries per-run state and the low half is a constant this build writes
into a mutex nobody initialised: a non-zero `__lock` with `__owner == 0`, which
is not what a correct `pthread_mutex_init` produces.

The remaining question is which of the 265 callers of the `pthread_mutex_lock`
stub at `0x154e0` is on this path, and it is not answerable by choosing one.
### 5.8d The buffer has two writers, and the marker is overwritten (2026-09-30)

**The packet buffer is written twice, by two unrelated code regions, and only
the second one's output survives.** This is the correction that matters: the
marker `00 00 00 01` that the transform produces is not what ends up in the
buffer, and reading the buffer after the call attributes the second writer's
bytes to the first.

| | writer | count | steps | result |
|---|---|---|---|---|
| layer 1 | RVA `0x67891` `mov byte ptr [rax + r9], dl` | 16 | 109 212+ | `00 00 00 01` — the marker |
| layer 2 | RVA `0x6fa2c`…`0x6ffe3`, `mov byte ptr [r12 + reg], al/cl` | 16 | 217 409–217 687 | `cc 3a 2e dd 9f b0 4b 28 d8 d2 a5 65 19 c3 b7 ed` |

All 16 sites of layer 2 were matched against the buffer as it stood after the
call: **16 of 16, no mismatches.** The three sites addressing `[r12+rax]` were
recovered from `CL`, and the other thirteen from `AL`. So the formula of 5.8c was
not wrong about the transform — it was applied to a buffer the transform no
longer owns.

**Neither layer compares anything.** Both are unconditional stores. There is no
marker check in either.

**`-45020` is published at RVA `0x905c2`**, not `0x8ff0a`:

```asm
0905b8  lea    rsi, [rip - 0x29]
0905bf  add    rsi, rax
0905c2  mov    edi, 0xffff5024     ; the publisher
0905c7  jmp    rsi
```

A sweep of `.text` finds **113** `mov edi/eax, 0xffff50xx` sites, densely packed
in `0x8eb00…0x90800` with `-45002`, `-45034` and `-45020` interleaved. There is
no single publisher: the flattened dispatcher picks which one runs. The index
is chosen at

```asm
090584  movsxd rax, dword ptr [rcx + rax*4]
090588  lea    rcx, [rip - 0x32]
09058f  add    rcx, rax
090592  jmp    rcx
```

Entry into `0x905c2` is at step **222 911**, by fall-through from `0x905bf`.
Three instructions earlier sits `cmp r9d, 0x4069d333` — and `0x4069d333` is one of
the **rejected** opcodes in this file's own sweep. A rejected opcode used as a
branch condition near the publisher is the first such sighting in this project.

**The window between layer 2 and the publisher is 5,236 instructions** (not the
5,225 first estimated, and `0x905c2` is not its end -- execution continues into
`0x5b0b1`…`0x5b0bb`, where the code is picked up into `rax` and travels on).
Within it: 992 references below the packet, 374 other host references, **34 reads
of the packet buffer itself**, and one read of the context.

**The context base is `0x5a8dfe4b5840`** (read 28 times at `+0x00`). Fields read
inside the window, once each: `+0x05`, `+0x0c`, `+0x18`, `+0x19`, `+0x2c`,
`+0x2d`, `+0x39`, `+0x40`, `+0x4d`, `+0x54`.

**`ctx[+0x18]` — the provisioning path — is read exactly once, inside the
decision window.** `ctx[+0x48]`, the UUID slot, is not read at all there. This
is the first place where a caller-supplied field and the transformed buffer are
both read in the same stretch that ends in the publisher, and it is where to look
next.

### 5.8e How the publisher is chosen: a byte of the packet, at an intermediate (2026-10-01)

**There is a single instruction that decides which of the 113 publisher blocks
runs, and it reads one byte of the caller's buffer.** RVA `0xb15c8` executes
three times in the recorded walk (steps 96 034, 108 763, 222 764); the third is
the decision, 147 steps before `0x905c2`.

```asm
0b15c3  add    eax, 0xe9357510      ; eax becomes the offset
0b15c8  movzx  eax, byte ptr [rcx + rax]
0b15cc  mov    ecx, eax
0b15ce  xor    ecx, 0x773bf45f
0b15d4  and    eax, 0x5f
0b15d7  lea    eax, [rcx + rax*2 - 0x773bf45f]
0b15de  or     eax, edi
0b15e0  or     eax, ebp              ; ebp = rbp + rbx*2 + 0x1600211
0b15e2  mov    ecx, eax
0b15e4  xor    ecx, 0x527df37e
0b15ea  and    eax, 0x527df37e
0b15ef  lea    r9d, [rcx + rax*2 - 0x1214204c]
```

At the decision, `rcx = 0x718c79a9e000` -- the caller's scratch base -- and
`eax = 0x7`, so the byte read is `scratch[7]`, which is buffer byte `+3`. The
loaded value was `0x55`.

**Two things follow, and the second is the one that matters.**

First, the index is not a raw byte: it is mixed with `edi` and with `ebp`, and
`ebp` is derived from the guest frame pointer (`rbp + rbx*2 + 0x1600211`). So the
dispatch is a function of the buffer byte **and** of frame state.

Second, and this corrects the previous reading: **the dispatcher reads the
finished buffer.** The byte at `scratch[7]` is `0xdd` when `0xb15c8` runs, there
are **zero** writes to it in the last 8,000 steps, and `0xdd` is exactly the
byte layer 2 left there. An earlier reading of `0x55` at this point came from a
mis-indexed trace column and is **withdrawn**.

So the chain is: layer 1 writes the marker `00 00 00 01` at buffer bytes 0..3,
layer 2 overwrites all sixteen, and the dispatcher reads the overwritten byte.
The packet does reach the decision -- but only through layer 2's output. That is
why feeding different bytes 4..7 does not move `-45020`: the input reaches the
dispatcher transformed twice, and layer 2 is what arrives.

**`ebp` carries layer 2's bytes into the index as well.** At the decision
`rbp = 0xcc3a0000`, built from buffer bytes 0 and 1 (`0xcc`, `0x3a`), which are
layer 2's output too. `0xb15e0` does `or eax, ebp`, so the dispatch index depends
on layer 2 through two independent channels: the byte at `+3`, and `rbp`.

Also in flight at the decision: `r9 = 0x4069d332`, one of the **rejected**
opcodes from this file's own sweep, folded in a third time by `0xb15ef`.

**Why no input can move it: layer 2 is keyed from the stack, not the packet.**
Three runs, same binary, differing only in the 16 supplied bytes:

```
A  9d b6 cf e9 14 f2 ae 3f 98 49 66 ca  ->  0e ac 0f 9c 93 c1 88 41 82 ea 15 35 21 35 bc cc
B  01 02 03 04 05 06 07 08 09 0a 0b 0c  ->  c2 ef 0f 20 9d e5 f4 48 37 42 8b 02 c9 f9 5c 49
C  00 00 00 00 00 00 00 00 00 00 00 00  ->  b0 5c 02 55 f6 37 46 c9 88 49 9e 03 e8 a9 33 9b
```

All three return `0xffff5024`, but the sixteen bytes differ, so the packet
**does** reach the output. The decisive observation is the other direction:
**repeating the same input in a different invocation gives different output
again.** Four consecutive runs within one shell were identical, and a fifth in a
different shell was not. Layer 2 is therefore a keyed transform whose key comes
from whatever lies below the guest frame -- the stack residue of the host --
and the packet only perturbs it.

That is the whole reason 9 months of packet-shaped attempts failed. The knob is
not in the argument block.

**A deterministic oracle exists, and this is what makes the barrier reachable.**
Isolating the guest stack alone is not enough -- three runs gave 221 863, 221 367
and 221 367 instructions. Adding `setarch -R` (ASLR off) makes the walk
bit-reproducible: two consecutive runs both stop at **221 615**, and layer 2
writes byte-for-byte identical output:

```
PERUN_PE_STACK=1 setarch $(uname -m) -R perun call ... 
  layer 2 -> c1 1c 64 57 95 fd 65 59 17 c2 7f 21 e2 48 14 cd   (both runs)
```

So the variable was the host heap address of the buffer, not the stack alone:
the buffer is heap-allocated and ASLR moved it, and the key mixed that address
in. With both pinned, the run is reproducible.

**That converts the problem from measurement into search.** Everything measured
so far varied under us -- the dispatch byte, the publisher, the output -- and
every conclusion drawn from one run had to be re-taken. Now the same command
gives the same bytes, so the sixteen bytes of seeded guest stack can be varied
deliberately and the effect on the publisher observed without guessing whether a
difference came from the input or from the run. The gate to look for is the one
already measured: the dispatcher at `0xb15c8` reads buffer byte `+3` and folds
`ebp` and `r9`, and the publisher it lands on is visible as the block entered a
few hundred steps later.

**The key word is located, and it steers the path but not the result.** Layer 2
enters with `mov rbp, qword ptr [rsp + 0x70]`, then `lea edi,[rbp-0x517]` and
`mov r14, q14 [r11 + rdi*8]`. On the isolated stack that word is at
`0x7ff7cfffe960` (guest top `0x7ff7d0000000`, frame `0x1710`), i.e.
`PERUN_PE_STACK_SEED_AT=0x16a0`, and **no instruction in the walk ever writes
it** -- it is whatever the stack held. Seeding it does change the path taken:

```
seed 0x00*16   221,367 instructions
seed 0x01      219,351
seed 0x02      221,367
seed 0xff*16   221,615
seed 01..10    221,367
```

but layer 2's sixteen output bytes are **identical in all five**. So that word
selects a branch inside the region, not the value the region produces.

**What that leaves, stated exactly.** With ASLR off and the stack isolated, a
walk is bit-reproducible; the output varies with the packet (three inputs, three
outputs, verified) and is now independent of everything else that was varying
before. `-45020` is a pure function of the 16 packet bytes in this configuration.
The remaining question is therefore not "what else feeds the decision" but
"which packet, if any, steers the dispatcher off `0x905c2`" -- and the
dispatcher reads buffer byte `+3`, whose value the region computes.

### 5.8f The Android lane is whole, and it never had a wall (2026-10-02)

**Two lanes, do not conflate them.** `run-native.sh` drives Apple's **Android**
engine (`libstoreservicescore.so` / `libCoreADI.so`, x86_64, run natively under
a Bionic linker, no emulation). That is the lane §5.8a opened and the lane this
section is about. The **Windows** lane is `CoreADI64.dll` executed through
perun's PE32+ runtime, and it is the lane the `-45020` barrier belongs to.
Nothing in this section says anything about `-45020`; the Windows barrier is
still open and still where §5.8b--§5.8e left it.

On the Android lane `run-native.sh` provisions end to end with no edits to the
script:

    [prov] PROVISIONING COMPLETE
    [adi]  re-check ADIGetLoginCode=0
    === SUCCESS ===
    X-Apple-I-MD-M: dp+14uJa5KDz4OxueI4Rav3cfuq3nUaJBT+HaksvYSUaMQk03PzK...

Verified 5/5 cold runs, each after `rm -rf adi-data`, so every run was a full
network round trip rather than a cached load. The same result reproduces on the
untouched 27-Sep binary in `/opt/data/apk/x86/` under plain `hermes`, with no
root, no `sudo` and no patched library.

What read as a barrier here was never one. Every symptom appeared as one of only
two observables -- hang forever, or exit 0 with zero output -- and all of them
came from the environment:

| symptom | actual cause |
|---|---|
| hangs, `strace` ends at `futex(FUTEX_WAIT_PRIVATE)` on `/proc/stat` | nothing: `fgets` under `sysconf(_SC_NPROCESSORS_ONLN)` inside Bionic's first `malloc`. The process was healthy; the trace was just read at the wrong moment |
| exits 0, no output | `env` on `PATH` was a 328-byte shell shim that rewrites `PATH` and never `exec`s its argv. Exit code 0, zero effect |
| `CANNOT LINK EXECUTABLE: libcurl.so not found` | `sudo -E` strips `LD_LIBRARY_PATH` regardless of `env_keep += "*"`. `env` must be passed *after* `sudo`, not before |
| `Unable to locate package gdb-llvm` | not in Debian 13. `apt-get install` aborts entirely on one unlocatable name, so a single bad entry installs nothing |
| root cannot `exec` the engine | root cannot follow a symlink in `/tmp` (sticky dir, foreign owner). The interpreter has to live outside `/tmp` |

The futex row is the one to keep: a `futex(FUTEX_WAIT_PRIVATE)` seen after a
`read("/proc/stat")` is Bionic's `stdio` lock inside the allocator's first
`sysconf`, and it says nothing about Apple code, in either lane.

**The `libc.so` patch was wrong and has been reverted.** Patching
`__sysconf_nprocessors_onln` to `mov eax,4; ret` at `0x2b230` was a reasonable
reading of the futex trace and a plausible fix. It is not required:
`/opt/data/x86sys/lib64/libc.so` matches the pristine
`/opt/data/il/libc.so.orig` (`dc55254e238c54c16bf9c1a22fe422b0`) and the lane
provisions. The patched build was also confirmed working, so the patch was
neither necessary nor harmful -- it was simply not the cause. Recorded here so
nobody re-derives it.

**A negative control is now part of the Android lane.** `doctor.sh` checks all
seven preconditions and exits non-zero on any failure, so a green run means the
chain was actually verified rather than absent:

    ./doctor.sh            # check only
    ./doctor.sh --run      # check, then run

It verifies the Bionic sysroot, the APK libraries and the `libstdc++.so` alias,
the NDK path, the TLS pin against a live `gsa.apple.com`, the `ADI_RESOLVE`
address, the `PT_INTERP` marker in `adi_native.raw`, and -- the check that would
have caught the worst fault -- that `env` resolves to a real `env` and is not
shadowed by a wrapper. The TLS and reachability checks are the MITM tripwire:
if a proxy ever enters the path, the pin verification fails there and names
itself, instead of surfacing later as an unexplained provisioning error.

### 5.8g The publisher table was wrong, and the clean path is now observable (2026-10-02)

The barrier map in §5.8b lists one "publisher" per ADI code (`0x8ffbd`→`-45020`,
`0x905c2`→`-45018`, `0x8ef2d`→`-45002`, `0x8ef22`→`-45034`). **That table does not
survive a check, and the check was possible only after two things changed.**

**The baseline ladder reproduces verbatim**, from a cold run of the shipped script:

| rung | invocation | return |
|---|---|---|
| 1 | `vdfut768ig 0xcfe0b46a ctx 0 0`, no poke | `0xffff5016` (`-45034`) |
| 2 | same frame, `--poke=0x19db98=scratch` | `0xffff5036` (`-45002`) |
| 3 | same frame, gate not poked | `0xffff5024` (`-45020`) |

All three rungs need all four positional arguments (`HANDOVER.md` § 9, note on
`perun call`): with `r8`/`r9` left zero the call silently narrows and returns
`-45002` whatever the gate holds, which reads like the clean result.

**The clean path is now observable, which it was not before.** `HANDOVER.md` records
that a trace cannot be taken in the configuration that returns `-45020`: the ring
dump sits inside the `STEP_ARMED` branch, and arming the walk changes the state it
measures. Hardware breakpoints fix that, because they write a debug register rather
than patching the page and never single-step. The release binary is stripped, so
neither `break mprotect` nor any symbol resolves, and gdb's Python API refuses
`BP_CATCHPOINT`; the working arming point is a `catch syscall write`, which fires
after the image is mapped and after its first print, when the page is readable.

Mechanism proven on the guest export entry, with the frame intact:

    HIT export entry vdfut768ig 0x7c85afc0
    rcx 0xcfe0b46a   rdx 0x7ffff7bde000
    #0  0x7c85afc0 in ?? ()      <- guest
    #1  0x55555562ae80 in ?? ()  <- perun

**`0x8ff0a` is not reached on the clean path.** Armed, with the run returning
`-45020`, it never fires. §5.8e's "the only success site" is therefore not
executed in this configuration at all.

**The publisher table is wrong, and the `-45018` entry cannot exist.** Sweeping
`objdump` for the immediate idiom:

| code | sites loading it into `edi` |
|---|---|
| `-45020` `0xffff5024` | **14** |
| `-45018` `0xffff502c` | **0** |
| `-45002` `0xffff5036` | **46** |
| `-45034` `0xffff5016` | **37** |

There is no `mov $0xffff502c,%edi` anywhere in the image, so "`0x905c2` publishes
`-45018`" cannot be right as stated. Each code is loaded at many sites — this is the
body's repeating shape, not a set of single publishers — and the table took one
arbitrary instance of each idiom and named it the publisher. `0x8ffbd` is the first
of the fourteen `-45020` sites; `0x8ff0a`, listed as a success site, is the fifth
and carries the *same* `mov $0xffff5024,%edi`, i.e. it is an `-45020` site and not a
success site at all.

**What the clean path actually executes.** On the `-45020` run one publisher fires,
`0x905c2`, which by disassembly loads `$0xffff5024` — `-45020`, not `-45018`. On the
poked `-45002` run it does not fire. So the two paths diverge before publishing, and
the divergence is now located on the publishing step itself rather than inferred.

All fourteen `-45020` sites lie in `0x8f000..0x91000`, below the opaque smear region
`0x189000..0x1a5500`, so they are ordinary linear-disassembly code and not smear
artefacts.

**Still open.** Where the two paths diverge before the publish step, and what selects
`-45020`. What is established here is narrower and firmer: the clean path's return
value now has a known publishing site, and the site is not the one the map named.
### 5.8h One publisher of fourteen runs, and the CFF dispatcher does not run at all (2026-10-02)

Continuing §5.8g on the same clean-path instrument. x86_64 has four debug
registers, so the fourteen `-45020` sites were covered in four batches of four;
gdb stops in execution order, so the first reported hit is the first executed.

**Exactly one of the fourteen executes.** `0x905c2`, once. The other thirteen do
not execute at all on the clean path — not later, not conditionally, not at all:

| batch | sites | result |
|---|---|---|
| 1 | `0x8f722` `0x8f96c` `0x8fb8a` `0x8fd94` | no hit |
| 2 | `0x8ff0a` `0x900cd` `0x9029d` `0x90443` | no hit |
| 3 | `0x905c2` `0x90780` `0x9090a` `0x90a96` | **`0x905c2` hit, once** |
| 4 | `0x90b60` `0xb469c` | no hit |

So the thirteen alternatives are not "reached but bypassed at the last step". On
this configuration they are never entered.

**The CFF dispatcher does not execute.** `0xb15c8` was armed in the same run and
never fired, while `0x905c2` fired "after 0 dispatcher hits". The address is
validated by disassembly, and it is the documented instruction:

    7c8b15c8:  0f b6 04 01    movzbl (%rcx,%rax,1),%eax

This matters more than the `-45020` bookkeeping it carries. §5.8b–§5.8e describe a
113-block dispatcher that selects among publishers by an index folded from packet
byte `+3`, and that is the mechanism a large part of this project has been
reconstructing. On the clean path that dispatcher is not in the execution chain at
all. Whatever selects `-45020` here, it is not the CFF index.

**`0x905c2` is not a return site either.** Its shape:

    7c8905b4:  48 63 04 87       movslq (%rdi,%rax,4),%rax
    7c8905b8:  48 8d 35 d7 ff ff ff   lea    -0x29(%rip),%rsi   # 0x7c890596
    7c8905bf:  48 01 c6          add    %rax,%rsi
    7c8905c2:  bf 24 50 ff ff    mov    $0xffff5024,%edi
    7c8905c7:  ff e6             jmp    *%rsi

It arms the code in `edi` and then tail-jumps through a second, independent
jump table. The `-45020` value is therefore *carried*, not returned, and the
return happens further down that chain. The four bytes above it are themselves a
table dispatcher — same shape as the CFF one — so `0x905c2` is a target it
selected, not its origin.

**No static predecessor exists.** Sweeping the disassembly finds zero direct
branches to `0x905c2` and zero references to the address as an immediate, which is
consistent with arrival by computed jump. At the hit `rsp` is `0x7fffffffb4c0` and
the four stack words are all zero, so the block carries no recoverable frame: it is
entered with a stack that does not describe the chain that led to it. Reading the
predecessor statically is therefore not available, and the walk-arming trace cannot
be used here because it changes the state being measured.

**What this leaves.** Established: on the clean path exactly one `-45020` publishing
site executes, the CFF dispatcher is not executed, and `0x905c2` hands off through
a jump table rather than returning. Open: which code selects `0x905c2`, and where
the chain that carries `-45020` in `edi` finally returns it. The next cheap step is
the same instrument applied to the jump table at `0x890596` — the entry index in
`rdi`/`rax` at entry to `0x905b4` names the chosen block, and that index is what
has to be explained.
### 5.8i The return is a shared epilogue, and the CFF dispatcher never runs (2026-10-02)

Third round on the clean path with the same hardware-breakpoint instrument.

**The clean path does not execute the CFF dispatcher.** `0xb15c8` armed in the
same run as `0x905c2` reported `after 0 dispatcher hits`: the publisher fired with
the dispatcher count still at zero. The address is validated by disassembly and is
the documented instruction —

    7c8b15c8:  0f b6 04 01    movzbl (%rcx,%rax,1),%eax

§5.8b–§5.8e reconstruct a 113-block dispatcher that chooses among publishers by an
index folded from packet byte `+3`. That mechanism is not in the clean path's
execution chain. Whatever selects `-45020` there, it is not the CFF index.

**One publisher of fourteen executes, once.** Four batches of four hardware
breakpoints, gdb stopping in execution order: batch 1 (`0x8f722` `0x8f96c` `0x8fb8a`
`0x8fd94`) no hit, batch 2 (`0x8ff0a` `0x900cd` `0x9029d` `0x90443`) no hit, batch 3
(`0x905c2` `0x90780` `0x9090a` `0x90a96`) hit on `0x905c2`, batch 4 (`0x90b60`
`0xb469c`) no hit. The thirteen alternatives are not reached and then bypassed; they
are never entered.

**`0x905c2` is not a return site. The value is carried, then moved to `eax` by an
epilogue every publisher shares.** Read at the `jmp`:

    7c8905b4:  48 63 04 87          movslq (%rdi,%rax,4),%rax
    7c8905b8:  48 8d 35 d7 ff ff ff  lea    -0x29(%rip),%rsi   # 0x7c890596
    7c8905bf:  48 01 c6             add    %rax,%rsi
    7c8905c2:  bf 24 50 ff ff       mov    $0xffff5024,%edi
    7c8905c7:  ff e6                jmp    *%rsi

    at the jmp:  rsi=0x7c85b0b1  rax=0xfffffffffffcab1b  rdi=0xffff5024

    7c85b0b1:  89 f8                mov    %eax,%edi
    7c85b0b3:  0f 10 35 00 16 00 00 movaps xmm6,XMMWORD PTR [rsp+0x1600]
    7c85b0bb:  0f 10 3d 10 16 00 00 movaps xmm7,XMMWORD PTR [rsp+0x1610]
    ...                                    (xmm8..xmm10 likewise)

So the sequence is: publish into `edi`, jump to `0x7c85b0b1`, and that common tail
copies `edi` into `eax` and restores the callee-saved XMM registers before returning.
`0x905c2` is one of several entry points into that shared epilogue, and the code the
caller receives is decided entirely by which entry point was taken.

This is why the publisher framing of §5.8b never produced a return address to read:
there is no per-code return to find. There is one return, shared.

**On the instrumentation limit.** The walk-armed configuration and gdb cannot be used
together: with `PERUN_STEPS` set, perun drives its own single-step and consumes
`SIGTRAP`, and gdb takes the same trap first, so the process stops under the debugger
before the walk runs. The 147-step window between dispatcher and publisher exists only
in that walk-armed configuration, and perun's own ring is the instrument that can read
it there. Ring capture for the `-45020` run is in progress.

**Open.** What decides which of the entry points is taken. At the dispatch the index
is a signed 32-bit table offset (`0xfffcab1b` into a table based at `0x7c890596`),
and nothing measured so far says what sets it — the caller-reachable inputs were
already swept (§5.8e) and none of them moved the result.
### 5.8j The decision is one compare, and it is on the table index (2026-10-02)

The walk-armed run for `-45020` completed: 222 935 steps written, ring capacity
`1 << 18` = 262 144 so nothing wrapped and the whole trace from step 0 is on disk.
The three dispatcher hits land where the project had them, one off:

    dispatcher 0x7c8b15c8 : steps 96035, 108764, 222765
    publisher  0x7c8905c2 : step  222912
    shared epilogue       : step  222913

The window between the last dispatcher hit and the publisher is **147 steps**,
exactly the figure the walk-armed chronology predicted. Full listing in
`/opt/data/adi-re/decision_147_steps.txt`.

**The decision is a single compare, and it selects the table index.** Steps
222903–222912:

    222903  7c89059a  cmp    $0x4069d333,%r9d
    222904  7c8905a1  setne  %cl
    222905  7c8905a4  sete   %bpl
    222906  7c8905a8  lea    (%rdx,%rbp,1),%eax      ; eax = rdx + (r9d == 0x4069d333 ? 1 : 0)
    222907  7c8905ab  cltq
    222908  7c8905ad  lea    0xcf6dc(%rip),%rdi      # 0x7c95fc90   the jump table
    222909  7c8905b4  movslq (%rdi,%rax,4),%rax
    222910  7c8905b8  lea    -0x29(%rip),%rsi        # 0x7c890596   the table's base
    222911  7c8905bf  add    %rax,%rsi
    222912  7c8905c2  mov    $0xffff5024,%edi

with `rdx = 0x651`. So the outcome is a **one-slot choice** in the table at
`0x7c95fc90`, resolved against a fixed base `0x7c890596`:

| condition | index | table entry | target | meaning |
|---|---|---|---|---|
| `r9d != 0x4069d333` | `0x651` | `0xfffcab1b` | `0x7c85b0b1` | shared epilogue, returns `-45020` |
| `r9d == 0x4069d333` | `0x652` | `0x00000034` | `0x7c8905ca` | computation continues, nothing published |

The table entry for the failing slot matches the runtime value exactly, and the
target it yields is the shared epilogue identified in §5.8i. The two slots differ
by one, so the whole difference between `-45020` and continuing is this compare.

**What `r9` actually is.** At the dispatcher entry `r9 = 0x4069d332`; by step 222776
it has become `0xf0c5d587`, and that is the value the compare rejects. The
`0x4069d33x` family therefore appears on both sides: `0x4069d332` enters the
dispatcher, and `0x4069d333` is the constant that would let the call proceed. The
project's §5.8e "five recognised versus four unrecognised, exact comparison"
describes this same family; what was missing was that the comparison selects the
**index**, not the code directly, and that the code itself is reached through the
table plus the shared epilogue of §5.8i.

**One correction to the expectation this was checked against.** `0x8f064` is not a
target of this table at all — scanning indices `0..0x6ff`, no entry resolves to
`0x7c88f064`. It is reached, but not as the neighbour of this decision, so it cannot
be the success half of it. The actual other half is `0x652 → 0x7c8905ca`.

**Still open, and now narrow.** What sets `r9` between the dispatcher (`0x4069d332`)
and the compare (`0xf0c5d587`): 147 steps, and `0x4069d332 → 0x4069d333` is a
difference of one in the low byte of a value already in the selector family at the
dispatcher boundary. That is where the next measurement belongs.
### 5.8a Anisette v3 runs locally (2026-09-27) — and what the `-45075` wall actually was

**Anisette v3 client headers are generated natively on this x86_64 host: no Wine, no QEMU, no emulation layer of any kind, and no remote re-signing server.** The engine is an x86_64 Android binary and the host is x86_64, so the Apple libraries execute directly. Artefact `run-native.sh` (`crates/perun-cli/examples/adi-android/`, commit `43f16eb`), two consecutive clean runs:

    [prov] PROVISIONING COMPLETE
    [adi]  re-check ADIGetLoginCode=0
    === SUCCESS ===
    X-Apple-I-MD:   AAAABQAAABCD2VMydR0aP5z/n/T6xDdcAAAABA==
    X-Apple-I-MD-M: PoaEPJnI5dOPGux58kIVfjvsa+ppLP8d13CEX4aNygVT+mTT1sA6n21nZrHHaFxYfa7q0E3CekDOWAGJ

Acceptance, checked rather than asserted: `<key>ec</key><integer>0</integer>` in Apple's `startMachineProvisioning` response with `ed` and `em` both empty, all three hops HTTP 200, reproduced 3/3 runs. `X-Apple-I-MD-M` is stable across runs and `X-Apple-I-MD` rotates per token pair, which is the pair's intended behaviour. The earlier qemu-aarch64 route (`run.sh`) reached the same result and is kept for the arm64 kit; it is not what the end state depends on. This is a separate lane from the SAP/FairPlay work above and shares no code with it.

**The engine is the Android `libstoreservicescore.so`, not the PE above.** The harness is `adi_test.c` from ipatool's `adi-engine` branch, driving the classic obfuscated exports of Apple Music 4.9.6 (§ 5.8a source note): `kq56gsgHG6` = LoadLibraryWithPath, `Sph98paBcz` = SetAndroidID, `nf92ngaK92` = SetProvisioningPath, `aslgmuibau` = GetLoginCode, `rsegvyrt87` = ProvisioningStart, `uv5t6nhkui` = ProvisioningEnd.

**The cause of `-45075`, and why it is not the `-45018` wall.** `libstoreservicescore.so` builds its provisioning state out of the libc underneath it and passes a pointer to that state as the flattened dispatcher's second argument. Under glibc that state is a few KB while the index derived from the call seed is ~168 MB, so the table read leaves the process and the library returns `-45075`. Under Bionic the index lands in range:

| | glibc host | Bionic host |
|---|---|---|
| `ADILoadLibraryWithPath` | `-45075` | `0` |
| `ADISetAndroidID("4C4848FC386C00D6")` | `-45075` | `0` |
| `ADIGetLoginCode` | never reached | `0` |

No Apple code is patched. The same `.so` files behave differently only because the libc under them differs. Provision's `adi.d` names the code `libraryLoadingFailed`, which is exactly what it is; it was mistaken for a state gate for several turns, and a stub `dlopen` returning success is what let the engine run on into data built for a libc that was not there.

**Obtaining the runtime.** A real Bionic is not in the AOSP source mirrors, which are unreachable from here in any case. It is in the `sys-img` repository: `dl.google.com/android/repository/sys-img/android/sys-img2-1.xml` lists `system-images;android-21;default;arm64-v8a` as a 211 MB zip. Its `system.img` is plain ext4, so `debugfs` extracts a real `linker64` and the real Bionic `.so` set from it with no mount and no privileges. A trivial Bionic binary built with the NDK clang runs under the result, and then so does the engine. Two traps cost time: Bionic does not propagate `$ORIGIN`-rpath to a dependency's own `DT_NEEDED`, so the Apple library directory must also be on `LD_LIBRARY_PATH`; and `libstdc++.so` does not exist in the Apple Music APK, being the NDK's alias for `libc++_shared.so`, which a symlink satisfies.

**Deviations from the stock `adi_test.c`, both recorded inline in the committed source.** `CURLOPT_RESOLVE`, driven by an `ADI_RESOLVE` environment variable, because Bionic does not read `resolv.conf` on this path — `android_getaddrinfo` goes to netd over the `dnsproxyd` socket and there is no netd under qemu-user — so resolving inside curl leaves the TLS path and the Host header untouched. And `ADI_DUMP_LOOKUP` / `ADI_DUMP_START`, which write the raw GrandSlam response bodies so `ec` can be read rather than trusted. Worth reporting upstream separately: `adi_test.c` reads `r2` after `free(r2)` in the `finishMachineProvisioning` branch; error path only, so it did not bite, but it is a use-after-free.

**Not vendored.** The Apple libraries, the extracted sysroot and the system image are inputs, not sources; `.gitignore` in that directory enforces it. The Apple certificate chain is `apple_chain.pem` from the same repository, since the Apple root is absent from the Mozilla bundles.

**Open.** The tokens are generated and the provisioning round trip completes, but an authenticated Store request carrying them has not been made — that needs credentials. `ADI_RESOLVE` with pinned addresses is a patch, not a design: the durable fix is a `dnsproxyd` resolver shim, or reading the server name from the TLS `CERT_COMMON_NAME`, which removes the address dependency entirely. The Windows `CoreADI64.dll` `-45018` wall in § 5.8 is untouched by all of this: a different library, a different gate, still open.

**How the native x86_64 run works, since it contains no emulator at all.** The engine is an x86_64 Android ELF and the host is x86_64, so the Apple libraries execute directly; there is nothing to translate. The one Linux-specific step is that an Android binary names its interpreter `/system/bin/linker64`, which does not exist on this host. `run-native.sh` repoints `PT_INTERP` at a real `linker64` extracted from an Android system image with `debugfs`, and the kernel loads that as the interpreter — the ordinary mechanism, used for its ordinary purpose, not an emulation layer. The arm64 kit still goes through `run.sh` and `qemu-aarch64-static` and reaches the same result; it is not what the end state depends on.

**Resolved 2026-09-28: the calling convention is measured, and the dumper works.** Both of the open threads in the original version of this section are closed.

*The convention.* `vdfut768ig` takes its selector in `rdi` and the frame in `rsi` — the ordinary SysV pair, read directly off the caller rather than inferred. `libstoreservicescore.so` is not flattened, so the three instructions before the call are plain MSVC output:

    1dbd23: mov  %r15d,%edi
    1dbd26: mov  -0x220(%rbp),%rsi
    1dbd2d: call *0x79aed(%rip)        # 0x255820

*The dumper.* It interposed `dlsym` and could not work: the caller resolves the entry with `dlsym(handle, …)`, and a handle-scoped lookup never consults an `LD_PRELOAD` export, so the library's own definition always wins. That is structural, not a bootstrap bug, and the three failures recorded in the ADI call-site log outside this repository (`RTLD_NEXT` not skipping the preload, no `__loader_dlsym` at API 21, a null `st_name` ending the hand-parsed walk) are all real but beside the point. What replaced it is a **single store into the GOT slot the caller calls through**: writing a wrapper address at RVA `0x255820` captures every invocation with no symbol resolution anywhere. It runs, the engine provisions, and sixteen dumps are captured in one run.

*What the dumps settled.* Eight calls per session. `rdi` carries a 32-bit value that changes per phase and is compared by equality — the ADI selectors, five of nine recognised, four not. `rsi` is a caller stack address, so the frame is the caller's own stack, not an output buffer. The library writes **one 32-bit field** into that frame, at `+0x0c`, overwriting the caller's value `4` with `16` on the call that produces a token — the length of the body it wrote. Nothing else in the frame is touched: a 24-byte identifier elsewhere in the frame is identical before and after.

*What it did not settle.* The Android opcode `0xc774292`, which the phase dump attributed to `SetAndroidID`, is not in the Windows selector set at all (§5.8, row 24). The two builds dispatch on different tables. The success path is `0xcfe0b46a`; `0x3e58e7f9` runs after the success banner, and most of the Windows campaign was spent on it before the ordered dump was read closely.


### 5.9 The StoreKit client lane (production use of this runtime)

The store lane turns the session above into a working App Store client (`perun store`, or the `ipatool` persona's strict grammar). Endpoint discovery is bag-driven: each session fetches `init.itunes.apple.com/bag.xml?guid=…` and reads `authenticateAccount`, `sign-sap-setup`, `sign-sap-setup-cert`, and `sign-sap-version` (the string `"200"`) from the `urlBag` sub-dict — hardcoded fallback defaults exist, but no request proceeds on a missing key. The signer runs the § 5.1 guest contract against the bag URLs and emits `X-Apple-ActionSignature` per signed body; login and the DAAP history call are the two signed call sites (§ 5.6).

Authentication is MZFinance password auth with out-of-band 2FA: the code the user receives by push/SMS is appended to the password on the retry round and signed fresh per attempt. One ambiguous shape: `MZFinance.BadLogin` with empty failureType and no code in play is a hard failure, but it does not prove wrong credentials — the correct password can draw it (with the 2FA code arriving anyway), so the error names the `--auth-code` retry path; the full failure mapping is unit-tested in `classify_auth_failure`. Pod redirects (3xx with `Location`) re-POST the original body without incrementing the attempt counter; shed load (204, 404, 5xx, 429 with `Retry-After`) backs off and resends up to three attempts. Credentials persist in an AES-256-GCM vault bound to the pinned machine address (PBKDF2-HMAC-SHA256, 100 000 iterations); `auth revoke` wipes vault and cookie jar, while session reset clears cookies only.

Search runs the public iTunes Search/Lookup APIs in the account's storefront country, with client-side scopes on top of the plain search: `--developer` (artist/seller name), `--id` (developer catalog by artist id), and `--description` (description text). Every `country=` parameter (search, both lookups, artist catalog, MDM/visionOS version resolution) derives from the login's `storeFront` — there is no region override flag or variable, so an app absent from the account's storefront (verified: US-only Hulu invisible to an RU account, `resultCount: 0` vs `1` for `country=US`) fails at lookup before any byte flows. Scopes probe at backend maximum and apply the requested limit after filtering. Purchase is free-license only (`price > 0` aborts); Arcade titles retry once under GAME pricing, and the known already-licensed shapes map to success.

Downloads survived the 2026 download migration through a three-stage fallback chain — legacy `volumeStoreDownloadProduct`, then DownloadDispatch `redownload` on an empty song list, then `updateProduct` on an empty-500 — with the latest external version id resolved per platform when the caller does not pin one (the MDM lockup API for tvOS, the `apps.apple.com` product page for visionOS, memoized per process). Bodies stream into a `.tmp` file behind a strict `Range` gate (206 continuation checks, 416-means-complete, a 200 after resume truncates the partial to 0 before the fresh body streams). Purchase history is a three-stage DAAP flow (login/update/items, the latter two SAP-signed), newest-first with page/max-results pagination.

The downloaded OTA stream is restreamed into a standard `.ipa` without ever being decompressed: local headers are rebuilt byte-identical (source extra preserved, with a ZIP64 block added when an entry overflows 32 bits), deflated entries gain a data descriptor (16-byte, or 24-byte with 64-bit sizes for ZIP64 entries), central-directory extras carry over with stale ZIP64 stripped and fresh structural values regenerated, and FairPlay `.sinf` blobs from `SC_Info/Manifest.plist` are injected per replication path, with `iTunesMetadata.plist` and `iTunesArtwork` added. Archives that overflow 32-bit sizes, offsets, or the 64K entry count emit real ZIP64 structures (ZIP64 EOCD + locator, `0xFFFFFFFF` placeholders) instead of truncating. Input is streamed through a `File` with a single 66 KB tail read for the EOCD, one read for the central directory, 30 bytes per local header, and entry bodies moved through a fixed 512 KiB buffer; the custom pure-Rust inflate serves only the small metadata reads. macOS `.pkg` downloads and paid apps are explicit errors, not silent gaps. The README owns the command grammar; this section records the wire behavior underneath it.

**Replication peak RSS is a function of the central directory, not of the package.** The package size is irrelevant to it: entry bodies never accumulate, only the parsed directory does, three times over (the directory bytes, the parsed records, and the rebuilt records held for the write). Measured on 24 synthetic and 16 real packages, a least-squares fit over four anchor points (12 entries to 65 534, directory 1 KiB to 19.3 MiB) gives

```
peak RSS ≈ 2.8 MiB + 165 B × entries + 2.95 × cd_size
```

and predicts every measured point to within 8 %. The consequences are worth stating plainly, because they are not what the size of the download suggests. Real App Store packages stay well under 32 MiB: the largest measured is 31.96 MiB for 47 007 entries in 3.14 GB (Tanks Blitz), and 16 packages spanning 107 to 47 007 entries and 4.6 MB to 3.14 GB all land between 3.8 and 32.0 MiB. The 3.14 GB package and a 4.6 MB package differ by a factor of 683 in size and by a factor of 10.6 in resident set. What the formula does **not** give is a 35 MiB guarantee over the whole input space: an archive at the ZIP64 boundary of 65 534 entries with maximum-length (255-byte) names carries a 19.3 MiB directory and measures **70.2 MiB**, twice the budget. The bound is on the directory, so the honest statement is per-entry-count and per-directory-size, not per-package, and any cap expressed in MiB of package size says nothing about it.

## 6. Benchmarks

### 6.1 Methodology

- Host: AMD EPYC 7742 (4 vCPU visible), Linux 7.1.10-xanmod1. Perun built with Rust 1.98.0, release profile; the oracle built with Go 1.24.4 against the Unicorn 2.1.1 blob its upstream Makefile pins and vendors. Live network (Apple endpoints, HTTPS) for both sides.
- Both sides run their public, unmodified artifacts. The oracle is t0rr3sp3dr0/sapsigner, cloned fresh from GitHub for these measurements (commit `883ede5`) and built with its own `make vendor build`; not one line of it was touched. Perun is the release binary built from this repository exactly as shipped. Every number in this section comes from one command per side (§ 6.6) — neither binary contains any instrumentation.
- Perun's per-phase figures are read from its own stdout reports. The stock oracle prints no phase timings at all; it reads the payload on stdin and writes the signature to stdout, so its costs are compared at the process level only. An earlier revision of this file carried per-round, compute-only oracle figures taken from temporary in-source timers; they are gone. Numbers that require patched sources cannot be reproduced from the public artifacts, so they do not belong in a public table.
- Process-level accounting comes from the kernel's `rusage` via `wait4(2)`: `ru_maxrss` is the kernel-tracked peak-RSS high-water mark, CPU time is `ru_utime + ru_stime`, wall is the monotonic clock across the whole process. N=3 runs per side, sequential, live endpoints.
- Both sides run the same image corpus (§ 2) and the same 27-byte payload through the same protocol steps. Perun parity criteria: context address 0x7ff7b0000250, 354-byte request, FNV state 0x6094ba41ca7bf5a8, 1428-byte reply acceptance, 501-byte signature — every perun run passed every criterion. The oracle derives its hardware identity from the host's network interfaces; in this container the interface it selects carries no hardware address, so its block measures 485 bytes instead of the 501 a MAC-bearing host produces. It executed the identical protocol steps and exited 0 on every run.

### 6.2 Per-phase latency (perun, from the tool's own reports)

| Phase, as the release binary reports it | Mean (N=10) | Min–max |
|---|---|---|
| Image mapping (4 images, streaming loader) | 31.6 ms | 27.0–44.6 ms |
| SAPInit | 0.640 ms | 0.558–0.881 ms |
| SAPExchange (Round 1 + Round 2 combined) | 215.1 ms | 180.6–252.7 ms |
| SAPSign | 1.06 ms | 0.962–1.211 ms |

Re-measured 2026-09-24 at N=10 (the previous N=3 figures were 39.8 / 0.613 / 201.5 / 1.09 ms); every run returned the 501-byte signature and the reference context address `0x7ff7b0000250`. Perun is the only side here, so this table is a single-session measurement. The SAPExchange row is the complete two-round window exactly as the shipped binary reports it: round-1 guest computation, the HTTPS POST to `signSapSetup`, and round-2 guest computation, end to end. The rounds are not split. Splitting them would take in-source timers the public binary does not carry, and this table holds only numbers a reader can reproduce with the commands of § 6.6. The window's spread (181–253 ms over ten runs) moves with the network round-trip to Apple's endpoint, not with guest work. The image-mapping row is context from the same command, not a protocol step.

### 6.3 Whole-process resources (kernel `rusage`)

| Metric | Oracle (N=3, 2026-09-02) | Perun (N=10, 2026-09-24) |
|---|---|---|
| Wall clock, whole process | 8.97–9.28 s (mean 9.09 s) | 0.222–0.312 s (mean **0.259 s**) |
| Peak RSS (`ru_maxrss`) | 225.1–252.8 MiB (mean 234.4 MiB) | 9.4–9.6 MiB (mean **9.5 MiB**) |
| CPU time, user + sys | 7.42–7.53 s (mean 7.46 s) | 0.074–0.107 s (mean **0.083 s**) |

**The two columns come from different sessions, so treat the ratios as an order of magnitude, not a measurement.** Perun was re-measured at N=10 on 2026-09-24 against the live endpoints; the oracle column is the 2026-09-02 session at N=3 and could not be re-run — its build vendors a pinned Unicorn 2.1.1 blob from `ghcr.io`, which now answers `401` to an anonymous pull, so the reference binary cannot be rebuilt in this environment without a registry token. Against those carried-over figures perun is ~35× faster on wall clock, ~89× on CPU and ~8.6× smaller on peak RSS. Every run in the fresh perun set exited 0 and produced the 501-byte signature.

Both sides talked to the live endpoints during every run of their own session. The stock oracle's wall and CPU include a full asset fetch on every run — upstream `sapsigner` ships no cache, so each run re-streams the same ~32 MB tail slice of the public package that perun fetches once and keeps (§ 6.4). Perun's figures are its warm path: images and certificate from the on-disk cache, one live protocol POST. Its 9.5 MiB peak is the guest mappings (CommerceKit's 1.4 MiB, since CoreFP's `__TEXT` is no longer touched), the runtime, and the pinned rdtsc tables. It is 9.5 MiB and not 27.1 because CoreFP is no longer patched and the ICXS blob is no longer resident: the census emptied the first table and the icxs service preads on demand. The oracle's is the Unicorn engine plus five mapped guest images.

### 6.4 Cold start and the two asset models

Both tools read the same ~32 MB tail slice of the public 1.28 GB update package (2.5% of it), but they pay for it differently. Perun pays once: the first run on a machine with no assets resolves the package's xar table of contents (a few KB), locates the compressed payload, range-reads the tail slice holding the commerce images, verifies all four SHA-256 pins, and writes the cache (~/.cache/perun/sap/ or $PERUN_SAP_DIR) — measured live on two days, **8.4 s and 8.1 s wall for ~32 MB** transferred. Every later run is warm; § 6.2 and § 6.3 are warm numbers. The stock oracle pays on every run: upstream ships no cache, so its 9.09 s mean wall in § 6.3 carries the same fetch each time. The measured tail geometry (block boundary, cpio prefix skip) is pinned in perun's fetcher and re-validated per run by the same SHA-256 constants the loader enforces, so a changed upstream layout fails loudly instead of producing a bad mapping.

### 6.5 Comparative table

| Tool | Engine | Whole-process cost (this host, N=3) | Deps |
|---|---|---|---|
| Perun (this work) | native Mach-O projection | 0.259 s wall / 0.083 s CPU / 9.5 MiB peak (warm) | pure Rust + libc |
| sapsigner (2024, stock, the measured oracle) | Unicorn TCG | 9.09 s wall / 7.46 s CPU / 234.4 MiB peak | Go + cgo + libunicorn 2.1.1 |
| majd/ipatool ≥ 2.4.0 | Unicorn TCG (purego) | same engine family; not re-benched here | Go + prebuilt unicorn |
| Signum `sapsigner.exe` (2026-08) | Unicorn TCG (sapsigner lineage) | same engine family; not re-benched here | closed GUI shell |

Only the stock sapsigner oracle was re-benched on this host; the ipatool and Signum rows cite engine-family equivalence (the same Unicorn TCG core running the same guest corpus) and are marked as such rather than measured.

### 6.6 Reproduction

Everything above reproduces from two public artifacts, one command per side.

```bash
# Oracle: the reference Unicorn signer, stock build from a fresh clone.
# It reads the payload on stdin and writes the signature to stdout.
git clone https://github.com/t0rr3sp3dr0/sapsigner && cd sapsigner/impl/emu
make vendor build          # vendors the pinned Unicorn 2.1.1 blob, builds sapsigner.out
printf 'perun native SAP smoke test' | ./sapsigner.out > sig.bin

# Perun: the release binary from this repository, explicit assets directory.
cd <perun-checkout> && cargo build --release -p perun-cli
./target/release/perun sap <assets-dir> --mac AA:BB:CC:DD:EE:FF

# Process-level accounting for either side, from the same rusage source the
# kernel hands to wait4(2) — wall, user+sys CPU, peak RSS:
/usr/bin/time -v <command> 2>&1 | grep -E 'Elapsed|User time|System time|Maximum resident'
```

The first perun command without an assets directory fetches the images itself (~32 MB from the public package, one-time, § 6.4); every later run is warm.

### 6.7 ADI lane: reproduction and the verification log (2026-09-03, tree at the then-HEAD)

### 6.7 ADI lane: reproduction and the verification log (2026-09-03; current commands 2026-09-28)

**Current reproduction, replacing the ones below where they disagree.** These produce every result in §5.8; `D` is the `CoreADI64.dll` path and `L` its `libs` directory.

```bash
cargo build --release -p perun-cli

# stage 1 and 2, and the barrier: the shape that reaches invalidParams2.
#   flags >= 8, a non-NULL pointer at 0x19db98, and a 4-byte version header.
./target/release/perun call "$D" vdfut768ig 0xcfe0b46a ctx 0 0 \
    --poke=scratch+0x3=0x2 --poke=ctx+0x8=0x10 --poke=ctx+0xc=0x0 \
    --poke=ctx+0x0=scratch --poke=0x19db98=scratch

# the three recognised selectors differ from the four unrecognised ones, and the
# comparison is exact: only 0x632b8d6e passes, its neighbours do not.
./target/release/perun call "$D" vdfut768ig 0x632b8d6e ctx 0 0 \
    --poke=ctx+0x0=scratch --poke=ctx+0x8=0x10 --poke=ctx+0xc=0x0 \
    --poke=scratch+0x3=0x2 --poke=0x19db98=scratch

# what the flattened body reads: two globals, named in the order it reads them.
PERUN_SEAL_DATA=1 ./target/release/perun call "$D" vdfut768ig 0xcfe0b46a ctx 0 0 \
    --poke=ctx+0x0=scratch --poke=ctx+0x8=0x10 --poke=ctx+0xc=0x0 \
    --poke=scratch+0x3=0x2 --poke=0x19db98=scratch

# the register-triggered walk: 1.2 s, stops where -45018 was being published.
PERUN_STEPS=2000000 ./target/release/perun call "$D" vdfut768ig 0xcfe0b46a ctx 0 0 \
    --poke=ctx+0x0=scratch --poke=ctx+0x8=0x10 --poke=ctx+0xc=0x0 \
    --poke=scratch+0x3=0x2 --poke=0x19db98=scratch

# proof that a code site executes at all -- 0x6602d is the control that traps,
# 0x8f69d is the -45020 publisher that does not.
./target/release/perun call "$D" vdfut768ig 0xcfe0b46a ctx 0 0 \
    --poke=ctx+0x0=scratch --poke=ctx+0x8=0x10 --poke=ctx+0xc=0x0 \
    --poke=scratch+0x3=0x2 --poke=0x19db98=scratch --patch=0x6602d=cc90909090

# the caller, which now loads and runs here.
./target/release/perun run /path/to/iTunes/CoreFP.dll
```

Two properties of this harness that cost real time and will do so again: **`--patch` needs its `0x` prefix** (`--patch=6602d=…` exits 2 with "bad --patch rva"), and **`perun seq` ignores `--patch` entirely**, so an `int3` probe run through `seq` reports a site as not executing when the patch was never applied.

Every Phase-1 claim reproduces with the shipped binary or a stock tool; the method column names it. No source modification, no one-off instrumentation.

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

# a multi-call session in one process (§ 5.8):
./target/release/perun seq   /path/to/CoreADI64.dll vdfut768ig --script=session.txt
```

`perun call` reports each invocation as `call#N <export>(...)` and dumps every non-zero qword of the scratch page as `scratch[<offset>] = <value>`, or a single `scratch: all zero (no output written)` line when the guest wrote nothing. An earlier form printed only `scratch[0..64]` as a hexdump; sweeps that filter the dump by the offsets they poked themselves must filter per-qword lines instead.

| # | Assertion | Method (command family) | Result |
|---|---|---|---|
| 1–20 | **2026-09-03, against the earlier single-gate model. Rows 6, 8–13 are superseded: the gate is three stages, not one (§5.8, rows 21–27). Kept because the byte-level facts they record still hold — the disassembly, the import census and the sweep methodology were not invalidated, only the conclusion drawn from them.** | | |
| 1 | PE32+ x86_64, 7 sections, base 0x7c800000 | `perun info` / `perun call --verbose` | Confirmed (entry 0x131b00, sections .text .rdata .data .pdata .gfids .rsrc .reloc) |
| 2 | Statically linked MSVC CRT, no network imports | `objdump -x` import tables | Confirmed (kernel32 93 / advapi32 7 / shlwapi 2 / shell32 1; zero network names; zero CRT DLLs) |
| 3 | Exports: vdfut768ig + cvu8io98wun | `perun call` on both names resolves | Confirmed (2 exports) |
| 4 | DllMain TRUE, 0 traps, 113 APIs | `perun run --verbose` | Confirmed ("DllMain returned TRUE", no trap lines, "shim table 113 APIs") |
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
| 20 | Multi-call session driver: one image load, one `DllMain`, scripted calls in one process; `--load` buffer usable as a token in any option order; `PERUN_SEQ=N` repeats one call in-process | `perun seq … --script=FILE`, `perun call … --load=NAME=FILE`, `PERUN_SEQ=3 perun call …` | Confirmed (DllMain TRUE, 113 shim APIs, spim-first block reaches the header validator at `0xffff5026`; three repeats execute in one process) |

| 21 | Gate is three stages: `unknownAdiCallFlags` → NULL check at `0x19db98` → `invalidParams2` | sweep each field with a control | Confirmed (`+0x08` ≥ 8 passes stage 1; any non-NULL at `0x19db98` passes stage 2; stage 3 returns `0xffff5036` regardless of packet) |
| 22 | `-45034` is `unknownAdiCallFlags`; `struct[+0x08]` is a flag word, not a size | `AdiErrorCode` enum, then bit-by-bit sweep of `+0x08` with `+0x0c`=0 | Confirmed (bits 0/1/2 each return `-45034` alone; every value with bit 3 set passes) |
| 23 | The packet is four bytes: `+0x00..+0x02` zero, `+0x03` = 1 or 2 | single-byte sweep over `+0x04`..`+0x2c` and over `+0x00`..`+0x03` | Confirmed (no byte past the header changes the result; a BE length in `+0x04`..`+0x07`, a 48-byte struct, 28 bytes of padding and a real 347-byte SPIM all give `0xffff5024`) |
| 24 | Five selectors recognised, matched by equality | 9 candidates × one call each | Confirmed (`0xb0eda7af`, `0xcfe0b46a`, `0x3e58e7f9`, `0x632b8d6e`, `0x85fe63b0` → `-45020`; `0xb23c691e`, `0xc774d292`, `0x4069d332`, `0x4069d333`, `0` → `-45019`). `0x632b8d6e−1`, `+1` → `-45019` |
| 25 | The success opcode is `0xcfe0b46a`; `0x3e58e7f9` runs after success | the ordered Android dump: the `SUCCESS` banner follows call 6 | Confirmed (call 6 is `0xcfe0b46a` with a 48-byte payload; calls 7–8 are `0x3e58e7f9`) |
| 26 | The body consults far more than two globals: `0x19d088`, `0x19db98`, `0x19dba0`…`0x19dd90`, `0x19dda0`, `0x19dda8`, `0x19e9c8` | `PERUN_SEAL_DATA=1` — seal `.data`, report each faulting access, then **re-seal** so the next one also faults | **Corrected 2026-09-29.** 42 accesses over 36 addresses. The earlier "exactly two globals" was an instrument defect: the page was unprotected on first fault and left open, so the log counted *pages*, and three globals share the page at `0x19d000` |
| 27 | `0x19db98` opens the path; `0x19d088` selects the other branch; `0x19dda0` faults when non-NULL | sweep of `.data` `0x19d000`–`0x19f0a0`, one qword at a time | Confirmed (3 of 85 qwords change the result) |
| 28 | No filesystem, dynamic-load or hardware call on the Windows path | `PERUN_TRACE=1` over `DllMain` and every call shape | Confirmed (only `LoadLibraryExW`, loader static phase; no `CreateFileW`/`ReadFile`/`PathAppend`/`GetFileAttributesW`/`SHGetFolderPathW`; no `GetProcAddress`) |
| 29 | Hardware APIs are statically imported but never called; note the ANSI forms | import table scan of `CoreADI64.dll` + `PERUN_TRACE=1` | Confirmed (`RegOpenKeyExA`, `RegQueryValueExA`, `RegCloseKey`, `GetVolumeInformationW` imported; `GetAdaptersAddresses` absent from the image; none called) |
| 30 | `CoreADI64.dll` loads `DllMain` TRUE, 113 shims, no unresolved import | `perun run` | Confirmed (two shims added this round: `GetModuleFileNameW`, `IsValidCodePage`) |
| 31 | The Android convention transfers: `rcx` selector, `rdx` frame | unobfuscated caller `libstoreservicescore.so` at RVA `0x1dbd23`–`0x1dbd2d`, plus the GOT-slot dumper | Confirmed (`mov %r15d,%edi ; mov -0x220(%rbp),%rsi ; call *0x255820`; 16 dumps in one run) |
| 32 | `dlsym` interposition cannot work on this caller | the caller resolves with `dlsym(handle, …)` | Confirmed by construction: a handle-scoped lookup never consults an `LD_PRELOAD` export. The GOT-slot swap at `0x255820` is the working mechanism |
| 33 | `r8`/`r9` are read but inert | 8 combinations over `{0, 1, scratch, ctx}` each | Confirmed (all identical) |
| 34 | The `-45002` front is at `0x5b094`–`0x5b7xx`, not `0xd6560` | `PERUN_STOP_CODE=0xffff5036` walk, then a hardware breakpoint on the CFF table load | Confirmed (the value is in `edi` by instruction 57 at RVA `0x5b0ae`; `0x15fc90` has 1 324 rip-relative references) |
| 35 | The gate object is allocated by the library, not supplied by the host | hardware **write** watchpoint on `0x19dda0` | Confirmed (`0x5b517 lock cmpxchg %rcx,(%rbx)`, 0 → a host heap pointer; the address comes from `[rsp+0x710]`, never a literal) |
| 36 | `-45002` is a precondition of the export | two opcodes × seven frame shapes, plus `cvu8io98wun` first | Confirmed (all fourteen runs return `0xffff5036`; `cvu8io98wun` returns 0 and changes nothing) |
| 37 | `%r11` at `0xd6560` is a guest stack local; no vector is present | hardware breakpoint at `0xd6583` | Confirmed (`r11 = rsp + 0x370`; `[+0x08] == [+0x10]` byte-for-byte and non-zero; `[r11+0x20]` is a copy of the derived key) |
| 38 | The five recognised opcodes are a sweep sample, not a set | byte scan of the whole image | Confirmed (none of the five appears as a raw dword; `0x4069d333` appears 17 times, some as `cmp ecx,imm32`) |
| 39 | The gate object is `HeapAlloc(flags=0, size=0x28)` and is not zeroed | `HeapAlloc` in the trace, correlated by address against a gdb run in the same process | Confirmed (`flags=0x0` → `malloc`, so the two zero qwords are the arena's, not the library's; a 40-byte block has no qword at `+0x28`) |
| 40 | Nothing writes the gate object after the `cmpxchg` publishes it | four hardware write watchpoints on `+0x00`…`+0x18`, armed at `0x5b51c` | Confirmed (armed to the end of the call, zero hits — build-then-publish) |
| 41 | `0x19e9c8` is the heap handle, not a CFF offsets table | gdb decode at `0x1353ae`, with the observed `rbx` matched against the allocation log | Confirmed (`mov rcx, [0x19e9c8]` then `call HeapAlloc`; `rbx=0x228` matches `HeapAlloc(flags=0x0, size=0x228)`) |
| 42 | `cvu8io98wun` is not part of the provisioning path | GOT hook on `0x255818` over a complete successful Android run | Confirmed (slot swapped, hook armed, **zero calls**: eight `vdfut768ig` calls, `SUCCESS`, both headers) |
| 43 | `HeapSize` is never called on this path | `HeapSize` in the trace, the shim-side count | Confirmed (0 calls, return code unchanged — the old constant 16 was load-bearing for nothing measured) |
| 44 | The gate object is initialised by the library, at `0x5b321`–`0x5b32f` | hardware write watchpoints on the block, armed before `run` at the address ASLR fixes, filtered to guest addresses | Confirmed (`pxor`/`movdqu` zeroes `+0x00`/`+0x08` in one store, then three register moves fill `+0x10`/`+0x18`/`+0x20`; straight-line, unconditional) |

Artifacts from the sweep (the 256-command histogram and the objdump-based verifiers) are diagnostic and untracked; none ships with the repository.


---

## 7. Ecosystem Context

The August-2026 enforcement wave ("empty 403 / 204 on login") broke every third-party storefront client that lacked the action signature. Three independent solution families emerged within days of each other:

| Family | Representative | Engine | Status |
|---|---|---|---|
| Emulated SAP (Unicorn TCG over the 10.9 images) | reference signer (2024, § 8); majd/ipatool v2.4.0 (2026-08-28) | QEMU-derived JIT | works, minutes-scale first login, external C dependency |
| Native system CommerceKit | ipatool-sapfix (macOS-only, cgo `CKSigningSession`) | host OS | macOS-only, intermittent |
| Rust rewrites of the reference tool | ipatool-rs (uncor3, Kosthi) | vendored emulator / native | early-stage (2026-09); drive the same wire |
| **Native projection (this work)** | Perun | Linux `mmap` + SysV shims, pure Rust | same protocol, 0.26 s warm session incl. live network (see § 6.3); full StoreKit client lane on top (login+2FA → search → purchase → download, live E2E 2026-09-07) |

The commerce gate is a client-attestation gate, not a content-decryption mechanism, and the same 2013 engine satisfies it — the August community consensus that a hardware Secure Enclave was mandatory was falsified on 2026-08-28 when emulated software signatures were accepted by the live endpoints.

## 8. Prior Art, Credits, and Acknowledgments

This work stands on prior research it did not invent, and claims priority only for what it measured itself (the native-projection runtime, the memory invariants of § 4, the poison-test falsification of the FS/GS hazard, the `DisposeStorage` bridge-address convention, and the benchmarks of § 6):

1. **t0rr3sp3dr0/sapsigner** (public since 2024-05, Apache-2.0) — the original open demonstration that the 10.9 commerce pair, driven through a Unicorn interposer with degenerate CF/IOKit/DiskArbitration answers, performs the complete SAP handshake against live Apple endpoints. Perun's shim semantics (§ 4.5) deliberately reproduce its interposer's return values, and its tooling served as this project's differential oracle throughout. Without this prior art the project would have started from a much darker room.
2. **majd/ipatool** (MIT) (and its v2.4.0 SAP runtime, merged 2026-08-28) — the production-grade client that restored third-party storefront access at ecosystem scale, and the de-facto reference for asset acquisition (HTTP-range download of the public update package, SHA-256-pinned extraction of the images). Its Unicorn runtime independently confirms the protocol steps of § 5.
3. **unicorn-engine/unicorn** (GPL-2.0) — the CPU-emulation framework the reference oracle of § 6 runs on (version 2.1.1, vendored by the oracle's own build). It is credited here because the measurements of § 6 compare against it; no Unicorn code is linked into, derived from, or redistributed with perun. The runtime exists precisely because that engine's cost profile did not fit the target use.
4. **The 2026-08 community RE wave** — issue threads on the commerce gate (#513/#520/#522/#523/#526/#528) and the Secure-Enclave PAT analysis that correctly described the modern client while (transiently) mispredicting the server's enforcement; both threads shaped the terminology audit of § 5.4.
5. **lazyeel** — Perun itself: the native loader/shim runtime, the phase-1 ADI provisioning-gate analysis (`CoreADI64.dll`), and this document.

Perun's implementation shares no code with the above; the obfuscated names, offsets, and protocol facts are independently derived from Apple's public binaries and live endpoints (byte-verifiable with § 2's digests).

### 8.1 Third-party crates: runtime and compile-time

The dependency set, read from `cargo metadata` at the target triple, with each licence taken from the crate's own manifest. The split matters for compliance scanners (FOSSA, Black Duck) and for NOTICE obligations under Apache-2.0/MIT, which attach to code compiled into the distributed binary (object form). The two tables below are generated — `python3 tools/gen_license_tables.py`, and `--check` to detect drift — so a dependency bump cannot add a crate that no notice names.

<!-- BEGIN GENERATED: license-tables -->
**Runtime — compiled into the `perun` ELF (36 crates):**

| Crate | Version | License | Author / repository | Role |
|---|---|---|---|---|
| `adler2` | 2.0.1 | MIT | Jonas Schievink, oyvindln (oyvindln/adler2) | transitive under ureq |
| `base64` | 0.23.1 | MIT | Marshall Pierce (marshallpierce/rust-base64) | transitive under ureq |
| `bytes` | 1.12.1 | MIT | Carl Lerche, Sean McArthur (tokio-rs/bytes) | transitive under ureq |
| `bzip2` | 0.6.1 | MIT | trifectatechfoundation/bzip2-rs | bzip2 for the first-run asset fetcher; 0.6 resolves to `libbz2-rs-sys`, a pure-Rust libbzip2, so this is not a C dependency |
| `cfg-if` | 1.0.4 | MIT | Alex Crichton (rust-lang/cfg-if) | transitive under ureq |
| `crc32fast` | 1.5.1 | MIT | Sam Rijs, Alex Crichton (srijs/rust-crc32fast) | transitive under ureq |
| `flate2` | 1.1.10 | MIT | Alex Crichton, Josh Triplett (rust-lang/flate2-rs) | gzip and zlib behind ureq's `gzip` feature |
| `getrandom` | 0.2.17 | MIT | The Rand Project Developers (rust-random/getrandom) | OS entropy for the account vault's salt and the SAP signature |
| `http` | 1.5.0 | MIT | Alex Crichton, Carl Lerche, Sean McArthur (hyperium/http) | the HTTP/1.1 message model under ureq |
| `httparse` | 1.10.1 | MIT | Sean McArthur (seanmonstar/httparse) | transitive under ureq |
| `itoa` | 1.0.18 | MIT | David Tolnay (dtolnay/itoa) | transitive under ureq |
| `libbz2-rs-sys` | 0.2.5 | bzip2-1.0.6 | trifectatechfoundation/libbzip2-rs | transitive under bzip2 |
| `libc` | 0.2.189 | MIT | The Rust Project (rust-lang/libc) | host libc ABI: mmap, sigaction, ucontext, wait4 |
| `linkme` | 0.3.37 | MIT | David Tolnay (dtolnay/linkme) | `distributed_slice` — the shim-table registration macro; the emitted linker sections and runtime slices land in the binary |
| `linkme-impl` | 0.3.37 | MIT | David Tolnay (dtolnay/linkme) | proc macro for `linkme`; the code it generates is linked in |
| `log` | 0.4.34 | MIT | The Rust Project Developers (rust-lang/log) | transitive under ureq |
| `memchr` | 2.8.3 | MIT | Andrew Gallant, bluss (BurntSushi/memchr) | transitive under ureq |
| `miniz_oxide` | 0.9.1 | MIT | Frommi, oyvindln, Rich Geldreich richgel99@gmail.com (Frommi/miniz_oxide/tree/master/miniz_oxide) | the DEFLATE decompressor under flate2 |
| `once_cell` | 1.21.4 | MIT | Aleksey Kladov (matklad/once_cell) | transitive under ureq |
| `percent-encoding` | 2.3.2 | MIT | The rust-url developers (servo/rust-url) | transitive under ureq |
| `ring` | 0.17.14 | Apache-2.0 AND ISC | briansmith/ring | crypto primitives under rustls: SHA-256, HMAC, AES-GCM, ECDSA |
| `rustls` | 0.23.45 | MIT | rustls/rustls | TLS 1.2/1.3 for every App Store and CDN connection |
| `rustls-pki-types` | 1.15.1 | MIT | rustls/pki-types | transitive under ureq |
| `rustls-webpki` | 0.103.15 | ISC | rustls/webpki | certificate chain verification under rustls |
| `serde` | 1.0.229 | MIT | Erick Tryzelaar, David Tolnay (serde-rs/serde) | transitive under ureq |
| `serde_core` | 1.0.229 | MIT | Erick Tryzelaar, David Tolnay (serde-rs/serde) | transitive under ureq |
| `serde_json` | 1.0.151 | MIT | Erick Tryzelaar, David Tolnay (serde-rs/json) | transitive under ureq |
| `simd-adler32` | 0.3.10 | MIT | Marvin Countryman (mcountryman/simd-adler32) | transitive under ureq |
| `subtle` | 2.6.1 | BSD-3-Clause | Isis Lovecruft, Henry de Valence (dalek-cryptography/subtle) | transitive under ureq |
| `untrusted` | 0.9.0 | ISC | Brian Smith (briansmith/untrusted) | transitive under ureq |
| `ureq` | 3.4.2 | MIT | Martin Algesten, Jacob Hoffman-Andrews (algesten/ureq) | HTTP client for the Store lane and the asset fetcher, replacing the external curl binary |
| `ureq-proto` | 0.6.4 | MIT | Martin Algesten (algesten/ureq-proto) | transitive under ureq |
| `utf8-zero` | 0.8.1 | MIT | Simon Sapin, Martin Algesten (algesten/utf8-zero) | transitive under ureq |
| `webpki-roots` | 1.0.9 | CDLA-Permissive-2.0 | rustls/webpki-roots | the compiled Mozilla root store rustls anchors against |
| `zeroize` | 1.9.0 | MIT | The RustCrypto Project Developers (RustCrypto/utils) | transitive under ureq |
| `zmij` | 1.0.23 | MIT | David Tolnay (dtolnay/zmij) | transitive under ureq |

**Compile-time only — executed by rustc during the build, absent from the binary (4 crates):**

| Crate | Version | License | Author / repository |
|---|---|---|---|
| `proc-macro2` | 1.0.107 | MIT | David Tolnay, Alex Crichton (dtolnay/proc-macro2) |
| `quote` | 1.0.47 | MIT | David Tolnay (dtolnay/quote) |
| `syn` | 3.0.5 | MIT | David Tolnay (dtolnay/syn) |
| `unicode-ident` | 1.0.24 | MIT AND Unicode-3.0 | David Tolnay (dtolnay/unicode-ident) |

<!-- END GENERATED: license-tables -->

The runtime set is small and, apart from one crate, uniformly permissive. Thirty-four of the 36 object-form crates are under MIT (31), ISC (2) or BSD-3-Clause (1) — the License column states the licence perun takes, which for an `MIT OR Apache-2.0` disjunction is the `MIT` term. The other two are worth naming:

* **`webpki-roots` 1.0.9 — `CDLA-Permissive-2.0`.** The compiled Mozilla root store under rustls. Permissive in effect, with a patent grant and a notice condition, but not OSI-approved, which is why a compliance scanner flags it where it would pass the others.
* **`ring` 0.17.14 — `Apache-2.0 AND ISC`.** The crypto provider under rustls. Both terms are permissive, and both are required: an `AND` is a requirement, not a choice, so there is nothing to resolve and nothing is taken.

Neither requires perun to disclose its own source or to relicence its code, and both are compatible with distributing perun under Apache-2.0. What they do require is that the notices travel with the binary, which is what the two generated tables exist to make possible.

**This set used to be materially worse, and the difference is the point.** It was 71 crates, and 15 of them were the ICU4X slice under `Unicode-3.0` — a copyleft licence. They arrived through a single edge that had nothing to do with cookies: `cookie_store` → `idna` → `idna_adapter` → `icu_normalizer`, where `idna` validates public suffixes so a cookie jar can decide whether `evilapple.com` is a parent of `apple.com`. Perun only ever talks to `*.apple.com` and `*.itunes.apple.com`, so that entire Unicode normalisation corpus — including two large generated data tables — was linked into the binary to answer a question it could not get wrong. ureq's `cookies` feature is now off and `store::cookie_jar` reads the same curl-format file in 200 lines of std, which removed 25 crates, every `Unicode-3.0` obligation from the object form, and the `idna`-drives-ICU4X edge that caused it. The crates are consumed from the crates.io registry, not vendored, so each crate's full licence text lives in its registry payload rather than in this repository.

## 9. License and Revision History

**Documentation license.** The reverse-engineering documentation, protocol analysis, and architectural research in this file are licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). The code implementation is licensed separately under the Apache License 2.0 with a NOTICE file (see the repository root).

**Revision history.**

| Date | Revision |
|---|---|
| 2026-09-01 | Initial public specification. Protocol closed end-to-end (init → exchange ×2 → sign, 501-byte signature) since 2026-08-31; all facts re-verified against binaries and live endpoints on 2026-09-01 (symbol-table audit, FS/GS census + poison experiment, cert re-fetch, benchmark re-run). |
| 2026-09-02 | Optimization pass + zero-config fetcher. Streaming image loader (full image bytes never materialized; peak RSS 26.8 MiB), storeagent dropped from the mapped set (bind-graph cross-reference, live-verified), speculative certificate fetch with a 24 h on-disk cache, and a first-run asset fetcher that range-reads ~32 MB of the public 1.28 GB update package (8.4 s cold start, all digests pinned). |
| 2026-09-03 | Benchmark hardening. Both sides re-benched against their public, unmodified artifacts: the oracle re-cloned from GitHub (commit 883ede5) and built with its own upstream Makefile (vendored Unicorn 2.1.1), perun as the shipped release binary. Per-round exchange rows retired — the stock oracle prints no phase timers and perun's release carries none for the split, so the public table now reports SAPExchange as the single combined Round 1 + Round 2 window and compares the oracle at the process level only (wall / CPU / peak RSS, N=3 per side, kernel rusage). Superseded instrumented figures (per-phase oracle timings, per-round exchange splits) removed; § 6.6 reproduces every number with one command per side. Third-party credits trimmed to what the law and the analysis actually require: NOTICE and § 8.1 now list only code compiled into the binary (runtime vs compile-time split, with unicode-ident's dual license kept distinct), and § 8 keeps the projects the work measured against or built on. Release profile hardened: no DWARF, stripped binaries, no build-host paths in distributed artifacts. |
| 2026-09-07 | Storefront-path additions from the live StoreKit client lane (built on this runtime, E2E the same day: login+2FA → search → purchase → download). New § 5.6 maps which requests the action signature actually gates (login body and the DAAP history body — and nothing else on the storefront surface; purchase/download ride the session cookies+token). New § 5.7 records the 5005 account-state lesson: the code covers both invalid-2FA and unprovisioned-account, and ToS acceptance on any Apple web property flips the same flow to a working login. § 7 gains the 2026-09 Rust-rewrite family (ipatool-rs) and this work's StoreKit client status. |
| 2026-09-07 | Unified specification: the Phase-1 document (STATUS.md) merged into this file and retired. The ADI/PE32+ lane is now first-class here — § 2.2 (CoreADI64.dll ground truth), § 4.7 (Win32 runtime invariants: FakeTEB/ARCH_SET_GS, 113 shims, absolute-jmp trap stubs), § 5.8 (the provisioning-gate analysis: status 0xffff5016, the RVA chain 0x19dda0/0x17eca0/0x5b20f with key 0x4f7e9322, the circular fpdi dependency, the two-trampoline experiment, ways forward), and § 6.7 (the 19-row verification log with reproduction commands). All facts, addresses, and measurements carried over verbatim; nothing dropped. |
| 2026-09-19 | Store-lane specification and factual corrections. New § 5.9 specifies the production StoreKit client (bag-driven signer, MZFinance auth with 2FA and machine-bound vault, search scopes, free-license purchase, three-stage download fallback with per-platform version resolution, DAAP history, OTA restreaming with sinf injection); § 5.1 now distinguishes the bare `perun sap` legacy path from the bag-driven store path. Corrections against the implementation: guest-heap size prefix is 16 bytes (aligned `size_t`), not 8 (§ 4.1); `sysctl` returns −1 while only `sysctlbyname` zeroes `*oldlenp` (§ 4.5); the trampoline zeroes RBX/RBP/R10–R15 (§ 4.6); PE mapping is `MAP_FIXED_NOREPLACE` with fallback, relocations cover DIR64 and HIGHLOW (§ 4.7); the `scaffold` hint names a command that does not exist (§ 5.8). Dependency table: tinyvec 1.13.2, new memmap2 row, pinned proc-macro2/quote/syn versions (§ 8.1). |
| 2026-09-28 | **Read this before the dated rows below.** They are a working log for one day, written in the order the work happened, and several of them are superseded by later ones in the same block. Where a row is wrong, a later row in this block says so and says why; the state that is actually current is §5.8, not any single row here. What the block establishes, in the order the corrections landed: the `dlsym`-interposition dumper is dead, replaced by a pointer swap on the GOT slot at RVA `0x255820`; the Android call convention was read wrongly and then re-read correctly, with `rcx` a masked selector; `-45034` is a flag word, not a size; the packet is four bytes; the gate has three stages and two are passed; the diff group is teardown, not state; the callers are `iTunes.exe` and `CoreFP.dll`, and `CoreFP.dll` runs here. Four instrument defects were found in the walker's own reporting along the way — a window that showed the oldest entries instead of the newest, a re-arm that set `RIP` to the faulting address, a trigger that sampled registers before the instruction ran, and a `--patch` that needs a `0x` prefix — each of which had produced a confident false result first. The rows that survive as current findings are the ones backed by a sweep with a control; treat any row that rests on a single run as a hypothesis. |
| 2026-09-28 | **The `0xd731c` jump is a compiler switch, not an import call, and the -45020 envelope hypothesis is refuted (2026-09-28).** A brief asserted the sequence `movslq (%r10,%rcx,4),%rdx ; add %r12,%rdx ; jmp *%rdx` at RVA `0xd731c` is a tail call into an import, with the nearby constants `0x102` and `0x103` being `WAIT_TIMEOUT` and `ERROR_NO_MORE_ITEMS` so a shim's return value would decide the branch. Both parts are wrong. The table is indexed by a 32-bit sign-extended entry and combined with a 32-bit displacement, which is the shape of an MSVC switch jump table, and the target it reaches is RVA `0xe4c1b` -- inside the library, not a host shim. A shim call would leave the image, and it does not: the guest continues in the library. The two constants are range bounds on a value the flattened code carries between blocks (`sil = rdx > 0x102`, `dil = rdx < 0x103`), folded into the next block's selector; there is no preceding call whose return they could be reading. **The envelope hypothesis is also refuted.** The brief predicted `-45020` would clear once Output Size at `+0x0c` were set to 8, on the reasoning that the routing result needs somewhere to go. Measured: with the command recognised, `+0x0c` swept over 0, 1, 4, 8, 12, 16, 32, 64, 256 and 4096 with `+0x08` fixed at 16 returns `-45020` in every case, and so does a block holding only the version field. The input/output pair is the check already decoded at `0x66bfc` and it is passed; `-45020` is decided elsewhere, and the live publisher for it is the single site at `0x8f69d`. Two of my own readings are corrected here as well. The guest does not leave the image at `0xd731c`; what ended was the walker's ring window, and I attributed the walk's end to a host transition. And the block after a call on this path is the library's own scratch rather than the caller's argument block -- `scratch[0x0]` reads `0xfffffffe01000000` because the environment id and the version were written adjacently, not because the header was rewritten.
| 2026-09-20 | Recorded-defect fixes. Six contained fixes, none touching the SAP/store happy path: 200-after-resume now truncates the partial to 0 inside the HTTP layer before the fresh body streams (§ 5.9); the zip writer emits real ZIP64 structures (EOCD + locator, `0xFFFFFFFF` placeholders, regenerated extra blocks) instead of truncating sizes/counts (§ 5.9); `--limit`/`--max-results`/`--page` reject garbage and out-of-range with a usage error instead of a silent default or wrapping cast (§ 5.9); `--trace-file` redirects stderr to the file so shim/trap trace lines actually land there; the trap message no longer names the nonexistent `scaffold` subcommand (§ 5.8); `perun info` lists imports (DLL, named + ordinal, IAT fallback) and exports alongside headers and sections. The ambiguous `MZFinance.BadLogin` with empty failureType and no code in play stays a hard failure but now names the 2FA path (`--auth-code`) instead of implying wrong credentials — live fire showed the correct password drawing this shape, a code arriving, and password+code succeeding; the failure mapping lives in test-covered `classify_auth_failure`. Doc corpses corrected: no store-level `--mac` flag, bare-`sap` endpoint comment matches the compiled constants, the CD-tail `madvise(DONTNEED)` the comment promised now exists, the inflate header test no longer cites a live download. |
| 2026-09-22 | Gate re-verified from zero without trusting prior notes (stock `objdump` + live runs): the `cmpq` at `0x5b20f`, both trampolines, the 37-site count (both DLL builds), and the table/key mechanism confirmed byte-exact; a first ZF-forcing variant crashed mechanically (register clobber — corrected by the clean rerun in the next row). Calling convention corrected in place: `vdfut768ig` takes two pointers (`rcx` NULL-or-valid, `rdx` required struct with a `+0xc` write), no command-code register exists, the 0..255-uniformity claim is withdrawn; `cvu8io98wun` is the init half (`[+0]=0x2000000001`, `[+8]=0`, `rdx` ignored); the directory walk is stepwise with zero enumeration past `adi/`; registry silence verified against instrumented shims. |
| 2026-09-22 | Clean ZF-flip rerun at `0x5b20f` (`pushf` + mask + `popf`, all registers and flags intact): both ZF values return `0xffff5016` via different routes (ZF=0 skips the directory walk, ZF=1 walks it), so the exit is funneled, not decided, at this `cmp` — single-point flag flip is dead as a bypass. Corrects the dirty `xor ecx,ecx` variant (mechanical crash, not branch evidence) and notes the `eax`-as-state-counter hang plus ~225 table-base consultations scoping way 3. |
| 2026-09-22 | In-process chaining harness (`crates/perun-cli/examples/chain.rs`, 3 unit tests): init leaves 0 `.data` bytes changed, warmed op call still `0xffff5016`, op mutates ~218 bytes in 43 runs, cold control identical — init sequencing eliminated as the missing piece. |
| 2026-09-22 | fpdi transport emulator (`crates/perun-cli/examples/fpdi_emul.rs`, 6 unit tests, 16/16 self-checks byte-exact, live parity verified): GET→405, unknown→404, POST→500 Jersey HTML, non-JSON Content-Type→415, other methods→403. Bodies never discriminate; entity format must come from the caller. |
| 2026-09-22 | Live spim from GSA (`MidService/startMachineProvisioning`, ec=0, 347 bytes, no Apple ID needed for step one) + gateway split (GSA midStart/midFinish vs Windows fpdi, which rejects the same plist); (dsId, spim) by-value feeds never leave -45034 — the Windows arm wants pointers, next via the in-process harness. Machine-ID module (`perun-shims/machine_id.rs`, clean-room MD5, Blackwood modern/legacy pins, Linux collectors, 5 tests). |
| 2026-09-22 | In-process spim feed (`feed_spim`, child-per-case): envelope shape accepted for all ops (always -45018 invalidInputDataParamHeader — arithmetic correction, not -45026), flat/session arms confirm the union model; Ghidra table-xref blindness quantified (24/438). cvu-init chained into the envelope (BC) still -45018. repr(C) invocation (command@+0x10, cmds 0–10, both flags): always -45018, no writes. vovan2200 DataPacket/MainContext shapes return -45034 (flags gate first); DB hybrid (envelope sizes + packet) moves all first-words to -45018; op called twice: no accumulation. Split args (DP2/DP3) still -45034, DF dies. New codes -45041/-45035/-45028 mapped. |
| 2026-09-22 | Header validator decoded (4 byte-reads + OR-fold, INT3-live, exact-match gate) + flat/split-arg matrix: pointer-first confirmed. |
| 2026-09-22 | Header outcome gates on missing state (ZF/r9d/content all funnel): valid header unobtainable offline, proven. |
| 2026-09-22 | P-code struct-touch map: only 27+28 memrefs, listing ends ~0x66c1f (validator region has no Ghidra function at all). |
| 2026-09-22 | Caller architecture (CoreFP 8-call session cluster 0x1b5da30, 4-arg convention, R8/R9 sweep inert, zero direct callers). |
| 2026-09-22 | Status checkpoint: envelope accepted (outer -45034 passed); -45018 is header parse of *Arguments; first header read at RVA 0xb151d (MOVZX EBP,[RCX+RDX]); GSA gateway live (ec:0, 347-byte spim). |
| 2026-09-22 | `perun scaffold` implemented (ways-forward item 5 closed, SAP/store happy path untouched): the new perun-persona subcommand parses Win64 and SysV trap lines — including the hint's quoted `DLL!func(args)` payload pasted back verbatim — and emits a compiling `win32_api!` skeleton with the observed arguments and the owning source-file hint (§ 5.8 item amended in place, README command block extended); both trap reporters name the command again. Proven live: a synthetic PE32+ with one unresolved import fires a real TRAP, the hint feeds `scaffold`, and the emitted stub compiles inside `perun-shims`. |
| 2026-09-24 | IPA replication re-measured end to end. Verified live across 31 production packages up to 3.89 GB (PUBG Mobile) and 47,007 entries in a single archive (Tanks Blitz) with zero errors. 32.3 GB downloaded in total. The `ipa.rs` note was wrong twice: `3.14 GiB` should read 3.14 GB (2.92 GiB), and its "under tens of MiB" RSS claim does not hold — measured 1.0-1.1 GiB peak with wait4/ru_maxrss.
| 2026-09-24 | Multi-call session driver for the ADI lane (§ 5.8, § 6.7 row 20): `perun seq` loads one image and runs one `DllMain`, then drives a script of export calls in a single process (verbs `load` / `poke` / `call` / `zero` / `dump`); `perun call` gains `--load=NAME=FILE` for feeding a file as a named guest buffer, and `PERUN_SEQ=N` repeats one identical call in-process. Option values now resolve after the whole command line is parsed, so a `--load`-registered buffer name works as a `--poke` value in any order — at the cost of a malformed poke value being rejected only after parsing, and `--poke-ptr` writes applying in resolution order. The `call` output format follows: invocations print as `call#N <export>(…)` and the scratch page dumps per non-zero qword (`scratch[<offset>] = <value>`, or an explicit all-zero line) instead of a `scratch[0..64]` hexdump. Verified live against `CoreADI64.dll`; the SAP and store lanes are untouched. |
| 2026-09-24 | Formatting baseline. The whole workspace is formatted with `cargo fmt --all`, so `cargo fmt --all -- --check` exits 0. The formatting landed as its own commit and `.git-blame-ignore-revs` (repo root) lists it, so `git blame` attributes reformatted lines to the commit that last changed them logically instead of to the reformat. The file is honored by GitHub natively; a local clone needs one command once per clone: `git config blame.ignoreRevsFile .git-blame-ignore-revs`. |

| 2026-09-25 | **SAP peak RSS 57.9 → 9.2 MiB: `cache_complete` was reading every pinned asset whole.** It called `std::fs::read` on each of `CoreFP`, `CoreFP.icxs` and `CommerceKit` purely to compare `len()` and a SHA-256 — 35.8 MiB of transient heap, one 27.7 MiB buffer at a time. A `smaps` snapshot at the peak showed exactly that: two anonymous `rw-p` regions of 28 336 kB resident each, 55.4 MiB of the 58.1 MiB total anonymous, and **no guest mapping present at all** — the peak is reached during cache verification, before any image is mapped. `malloc_trim` could not help, because a high-water mark that has already been recorded does not come back down. Size now comes from `metadata()` and the digest is streamed through a 64 KiB buffer with `perun_core::sha256::Sha256`, so the buffers never exist. Warm peak 9 308–9 492 KiB over five runs, against 59 316 KiB before; the store lane already measured 9.7 MiB because a plain `download` never touches the SAP assets at all, so this is what puts the two lanes on the same figure. `streamed_digest_matches_the_pinned_one` pins the streamed hash to the same digests the whole-file path verified, so the optimisation cannot start accepting a corrupt cache. The `malloc_trim(0)` in `SapRuntime::new` is kept for the cold path and its comment no longer claims 20 MB: measured, 9.2 MiB with it and 9.2 MiB without. |
| 2026-09-25 | SAP peak RSS 27.1 → 9.5 MiB, and the rdtsc patch set cut to what a session reaches. An execution census (`archive/rdtsc-census`) showed CoreFP reaches **none** of its 6 269 rdtsc sites on any path that has been driven, so its table ships empty and its 10.5 MiB of resident `__TEXT` disappears; CommerceKit ships all 251. Separately, the image load was spending 198 of its 206 ms re-deriving a SHA-256 the fetcher had already verified, which is now passed in (images 206 → 8.9 ms), and `perun sap` went 402.6 → 231.7 ms. The 485-byte signature that appeared intermittently in a soak was the `IOIteratorNext` parity counter surviving across sessions; `reset_shim_state` per `SapRuntime` removed it (550/550). Full LTO plus one codegen unit took the binary from 4 139 648 to 3 289 328 bytes. |
| 2026-09-25 | IPA replicator no longer maps its input. It was mmap'ing the whole archive and leaning on `MADV_SEQUENTIAL`, which left peak RSS to the kernel: identical runs of one binary swung 532..1012 MiB on a 3.62 GiB package and climbed as the page cache warmed. `replicate()` now streams through a `File` — 66 KB tail read for the EOCD, one read for the central directory, 30 bytes per local header, entry bodies through a 512 KiB buffer. PUBG 3.62 GiB: 691 676 → 13 148 KiB; Tanks Blitz 2.92 GiB: 625 992 → 32 688 KiB (median, N=5). Output verified: 47 008 entries and CRC clean on Tanks Blitz, 1 079 entries / 14 sinfs / all executables 16 KiB aligned and CRC clean on a live Telegram download. |
| 2026-09-25 | IPA replicator correctness fixes from a 24-package synthetic fuzz corpus and 16 real packages, all four verified by mutation (each test re-broken and confirmed red). **F1:** `parse_central_at` read the record as `(time, date)` while `add_stored` and `finish` write `(date, time)`, so every *copied* entry landed its two halves in each other's field — the modification timestamp of every entry of every package was transposed. One-line reader fix, no writer change. **F3:** `replicate()` now writes to `<dst>.partial` and publishes by `rename`, so a failure anywhere in the copy loop can no longer leave a truncated package at the path the caller was promised a finished one at; the partial is removed on every failure path, including the `Ok(false)` no-bundle case. **F4:** the multi-disk check read `eocd[20..22]`, which is the *comment length*, so every archive carrying an EOCD comment was rejected as multi-disk; the disk numbers are at `eocd[4..8]` and the comment length is now only what it is. **F7:** the EOCD scan believed the last `PK\x05\x06` it saw, which a forgery in a comment or entry data can displace; a candidate is now believed only when the directory it names ends at or before the candidate itself. That made the absolute offsets inside a record a live hazard, so `find_eocd` takes the window's own offset (`find_eocd_at`) — the 66 KB tail of a 3 GB package starts three gigabytes in. Separately, the documented memory model is now empirical: `peak ≈ 2.8 MiB + 165 B × entries + 2.95 × cd_size`, measured over 40 packages, which replaces the previously implied guarantee of a flat ceiling — real packages stay ≤ 32 MiB, but the accepted input space reaches 70.2 MiB at 65 534 entries with 255-byte names. |
| 2026-09-25 | **25 crates out of the object form, and with them the whole ICU4X slice.** `cookie_store` existed for one reason: it is a cookie jar, and it was the only direct source of perun's `mz_at0` session. It also dragged `psl-types`, `publicsuffix`, `idna`, `idna_adapter` and fifteen ICU4X crates, all under the copyleft `Unicode-3.0` — linked into the binary so a cookie jar could decide whether `evilapple.com` is a parent of `apple.com`, a question that cannot arise when the only hosts are `*.apple.com` and `*.itunes.apple.com`. The removal is one manifest line: ureq enables `url` only from its `cookies` feature, so dropping that feature drops `cookie_store`, `url`, `idna` and the corpus behind it. `store::cookie_jar` replaces it in about 200 lines of `std` — the same curl-format file, `Set-Cookie` folding, RFC 6265 path matching, and a per-hop `Cookie` header recomputed so a suffix cookie does not follow the IPA download's 302 onto Apple's CDN. Object form: 71 crates → 36, and no `Unicode-3.0` obligation is left in it. `unicode-ident` keeps that licence build-time only, which it always was. Verified live: the 16-cookie session survives a load/save round trip with identical fields, and `list-purchases` returns all 41 purchases over DAAP, which is the endpoint that 401s first when cookies are lost. Note that Cargo.lock still *lists* the removed crates as optional dependencies no enabled feature requests — that is the resolver's bookkeeping, not the build graph, so the licence generator reads the build graph (`cargo tree`) rather than the resolve graph, which is a superset. |
| 2026-09-25 | **F8** in `strip_zip64_extra`, and the `memmap2` dependency removed. On an extra whose last field declares a size running past the end of the buffer, the truncated branch appended the tail and `break`, and the trailing `if i < extra.len()` then appended the same bytes again — a 9-byte extra came back as 18, silently, on both the local and the central path, and near the `u16` ceiling the doubling crossed the length limit and refused the entry as "local extra too long", naming a size constraint instead of the malformed field. The branch now returns. Pinned by `truncated_extra_tail` and by `strip_zip64_extra_never_grows`, which asserts the general property (output no longer than input, and every surviving byte present in the input in order) over 2 000 pseudo-random extras; both mutation-checked. `memmap2` was declared but never used — it has not been linked into the binary since the replicator stopped mapping its input — so it is out of `Cargo.toml`, out of `Cargo.lock` (nothing pulls it transitively), out of NOTICE, and out of both third-party crate tables. It is removed, not re-attributed: the NOTICE line described a mapping that the streaming rewrite had already deleted, and leaving it would have been a false statement about the distributed object rather than a stale one. |
| 2026-09-27 | **Anisette v3 generated locally, on x86_64 Linux, no Wine and no remote re-signing server (§ 5.8a).** Headers are produced against the real Apple endpoints: `GsService2/lookup` and `MidService/{start,finish}MachineProvisioning` all HTTP 200, Apple answers `<key>ec</key><integer>0</integer>` with `ed`/`em` empty, and `ADIGetLoginCode` is 0 afterwards — reproduced 3/3, `X-Apple-I-MD-M` stable and `X-Apple-I-MD` rotating per token pair. Artefact `43f16eb` on `rnd/phase1-standalone-anisette`. **The engine is the Android `libstoreservicescore.so`, not the PE in § 5.8, and it must be an x86_64 build. The engine source is Apple's own APK (`apps.mzstatic.com/.../applemusic.apk`, Apple Music 4.9.6, versionCode 1447), a universal release whose `lib/x86_64/` carries all eleven classic ADI exports and the same three `libCoreADI.so` symbols. An earlier mirror kit (3.9.0-beta) is no longer used. The 4.x line is not arm-only — 4.9.6 ships x86_64 as well, and it is fetched by HTTP range at run time, never vendored.
| 2026-09-28 | **The `invalidParams2` comparison is a field-to-field bounds check on the object, and the object is not the one at `0x19db98` (2026-09-28).** Walking the `-45002` path with both gates open runs 79 970 guest instructions and ends in the block at RVA `0xd6560`, which reads four fields of a structure through `r11` — `obj[+0x08]` into `rcx`, `obj[+0x10]` into `rdi`, `obj[+0x18]` into `edx`, `obj[+0x2c]` into `ebp` — and then compares `obj[+0x08]` against `obj[+0x10]` with `setne`, and a second pair with `setae`, folding the two into `rax`. That is a bounds and consistency test on an object, the same shape as the `unknownAdiCallFlags` check but one level down. What is new is that the object is not reached through the `0x19db98` slot: populating that slot's target, its `+0x08`, `+0x10`, `+0x18` and `+0x2c` in every combination leaves the return at `-45002`, so `r11` is loaded from a register that the flattened path derived rather than from the slot. The pointer the comparison needs is therefore produced inside the body, and the object it describes is whatever the library builds for itself on the way. That is why seeding four fields of a caller-supplied object does nothing: the value being validated is not the caller's. **The practical consequence is that `-45002` is a self-consistency check on library-internal state, not a missing argument**, and no input the caller controls reaches it. Static analysis agrees it is unreadable from outside: the `.data` globals in this image are addressed only through the obfuscation table, so neither `objdump` nor Ghidra's decompilation resolves them — Ghidra's own output warns it could not recover the jump table ("Could not recover jumptable ... Too many branches") and renders the body as a bare indirect call. |
| 2026-09-28 | **The walker's ring window was showing the oldest entries, not the newest (2026-09-28).** Two rounds of conclusions this project drew about a walk were drawn from a report that printed a window starting at the oldest stored entry rather than the one ending at the last, so the tail of every walk was missing and what was printed had already scrolled out of the ring by the time the run finished. With `n = STEP_IDX` and `slot = (idx + k)`, adding `k` to an index that already points past the newest entry walks forward into slots the ring never wrote. Fixed to end at `STEP_IDX - 1` and start at `STEP_IDX - count`, verified against a walk of 80 218 steps. Two consequences: the window is now the true tail, and in the `-45002` walk the final guest instructions end well before the call returns — the last 128 steps are host code in the epilogue, so the block at RVA `0xd6560` where the comparison happens is not adjacent to the return. This does not change the finding itself, which stands on the walk reaching that block and on the field-to-field comparison decoded there, but it does mean any earlier reading of "the last N steps" from this tool was a reading of the wrong window. |
| 2026-09-28 | **`iTunes.exe` and `CoreFP.dll` are the Windows callers, and CoreFP runs under the same runtime (2026-09-28).** Both `iTunes.exe` (38 MB) and `CoreFP.dll` (33 MB) contain the strings `vdfut768ig` and `cvu8io98wun`; so do the two ADI libraries themselves, which is the export table. `iTunes.exe` is the application, but the more useful caller is **`CoreFP.dll`**: its image base is `0x7c801000`, the same layout this project's runtime already maps and whose `vdfut768ig` path has been walked all along, and it is the module that owns the FairPlay signing path Anisette feeds. A caller that already runs under perun-shims, with no Bionic and no QEMU, is the shortest possible route to the real invocation shape. What could not be done in this round: Ghidra's headless analysis of a 38 MB binary does not finish inside the time budget here, and a static reference search for the string in `iTunes.exe` finds **no** `lea` and no pointer-table entry reaching it — the bytes immediately before the string are a high-entropy run, so that name is obfuscated in the application even though it is plain in the DLLs. The search therefore has to be done on the module where the name is not obfuscated, or inside the decompiler once a smaller module is the target. The interpretation offered for the `0xd6560` check -- `obj[+0x08]` and `obj[+0x10]` being an MSVC vector's `begin` and `end`, so the test is "are the provisioning keys non-empty" -- is consistent with the measurement and with the `-45002` position in the sequence, but it is an interpretation, not something decoded here: nothing in this project has shown what fills that vector. || 2026-09-28 | **The body consults exactly two globals, measured by sealing `.data` and unprotecting on each fault (`PERUN_SEAL_DATA`) (2026-09-28).** The walker could not say what the flattened body reads, only which instruction it was on, so a different instrument was built: mark the image's `.data` pages `PROT_NONE` before the call, let the first read of a global fault, report the address, unprotect that one page, and continue. Each fault names a global in the order the body consults it, with no decoding and no `ptrace`. Over the whole call on the `-45002` path there are exactly two reads: RVA `0x19dda0`, the state pointer, and RVA `0x19e9c8`, which holds a repeating arithmetic sequence and is the second-level indirection table, matching the double-dereference this file already recorded with its `0x4f7e9322` key. **That is the complete set of global inputs to the rejection.** Nothing else in `.data` is consulted, so the `-45002` decision is a function of those two values alone, and the second is an obfuscation artefact rather than state — the first is the object the call allocates and zeroes. This also confirms that the global sweep earlier in this file, which found `0x19db98` and `0x19d088`, was a real sweep: those two slots live in the same region the body actually reads. Building the instrument took two corrections, both recorded in the tooling: the handler must not rewrite `RIP` to the faulting address, since the instruction has not executed and returning re-runs it and faults again, and the ring window must end at the last store rather than start at the oldest. || 2026-09-28 | **`0xcfe0b46a`, not `0x3e58e7f9`, is the operation that returns success, and the priority was backwards (2026-09-28).** The eight-call Android dump this project captured is ordered, and the `=== SUCCESS ===` banner follows call 6, whose opcode is `0xcfe0b46a` with a 48-byte payload; calls 7 and 8 are `0x3e58e7f9` and run *after* the success, so they cannot be the operation being driven. Nearly all of this campaign's effort went into `0x3e58e7f9`. The frame is also read differently than assumed: `frame[+0x00]` is a **pointer to the payload**, `frame[+0x08]` is its length `0x30`, and the 48 bytes themselves live at the address that pointer holds, which the dumper never printed -- it dumped the envelope and called that the arguments. The call-6 envelope decodes as `+0x00` payload pointer, `+0x08` 48, `+0x0c` 4, `+0x18` 0x226564, `+0x20` 1, and three library-internal pointers. Replaying that whole shape on the Windows lane changes nothing: `0xcfe0b46a` and `0x3e58e7f9` both return `-45002` with the flags gate passed, the `0x19db98` gate passed, and the full envelope populated. So the correct opcode was the wrong lead, and `frame[+0x00]` is a payload pointer rather than an output buffer -- which also retires the output-buffer reading of the brief's layout. Both statements are recorded because the previous revision leaned on the opposite of each. |
| 2026-09-28 | **The Windows gate re-measured, and the shared-convention claim refuted (2026-09-28).** The Android `vdfut768ig` convention does **not** transfer to `CoreADI64.dll`, and the difference is not a register-order detail. Direct measurement on the shipped binary: the DLL's own init export `cvu8io98wun` returns 0, `vdfut768ig` in the same process then returns `0xffff5016` = **-45034**, and the check that produces it is `cmp qword ptr [rcx - 0x4f7e9322], 0` — a pure memory test evaluated before any file I/O, so no input reaches it. The object it tests is the 0x28-byte `HeapAlloc` behind the global at RVA `0x19dda0`, and that object is reallocated on every call, which is why writing it between calls changes nothing: seeding its first qword at allocation is overwritten by the guest before the gate runs. Placing the real `adi.pb` from the Android lane under `<CommonAppData>\Apple Computer\iTunes\adi` produces zero `CreateFile`/`ReadFile` calls, so the gate is not a file-presence test. **The decisive point: `rcx` is a pointer in the Windows build, not an opcode.** Passing `0x3e58e7f9` in `rcx` *crashes* by dereferencing it, while the opcodes above `2^31` are masked and all return -45034 unchanged — the opposite of a command dispatch. A `poke-ptr` verb was added to `perun seq` for this work: `call --poke-ptr` applies every write before the call loop, which cannot reach state the guest allocates during the call, and the gate object is exactly that. |
| 2026-09-28 | **§4.1 guest-heap arena: 64 MiB, not 1 GiB.** The previous row of this changelog reported the arena as 1 GiB ending at `0x7FF7_F000_0000`. That was wrong and had never been true: `HEAP_SIZE` in `crates/perun-shims/src/mach.rs` is `0x400_0000` and has read that way since the first implementation, so the arena is `[0x7FF7_B000_0000, 0x7FF7_B400_0000)`. The 1 GiB figure is the PE lane's `region_name` labelling range in `stub.rs`, a trap-report string rather than a mapping, and it was carried into the Mach-O section. Both the address table and invariant 2 are restored to the code. | **Uniformity of the gate behind it, measured the same way.** With the frame laid down, every input value tried — the real 347-byte spim prefix, all-ones, a byte ramp, the Android envelope words `5`/`0x10`/`4`, and a plain `0x02000000` — returns `0xffff5026` = `-45018` with no divergence. (An earlier pass of that sweep reported three patterns as differing; that was a defect in the harness, which matched the substring `core` inside `CoreADI64.dll` and announced a trap that never happened. The uniformity is the real result.) The two gates are therefore distinct: `-45034` is a caller-argument check that any well-formed frame satisfies, and `-45018` is a header validator that nothing tried satisfies. The wall is unchanged; what changed is that it is now reached for the first time and shown to be the only thing standing between here and the dispatcher. **The gdb route is closed by the sandbox, not by the project.** Installing GNU gdb 16.3 into a private prefix and running it against the shipped binary works up to the point of attaching: `ptrace` is denied, so gdb reports "Could not trace the inferior process", and the container also refuses hardware breakpoints ("No hardware breakpoint support in the target"). A software breakpoint is no better, because it needs the same ptrace. Any future plan to walk the flattened dispatcher instruction by instruction must either bring its own tracer (a `ptrace`-based in-process recorder in Rust, which needs no gdb) or accept the int3-probe coverage already used here, which is enough to prove which sites execute but not to read the state behind them. The installed prefix was removed again so the tree does not carry a tool that is present and unusable. **Ghidra on the same two sites, which is the strongest negative result here.** Ghidra 12.1.4 was brought up (it is unpacked on this host; it needs a JRE, and one installs into a private prefix from the Debian archive with no root). It decompiles the *entry* of `vdfut768ig` cleanly and independently confirms the dynamic findings: `param_1` is consumed arithmetically, `param_2` is dereferenced at `+0xc`, and a null `param_2` returns `0xffff5036`. It cannot read the gate itself. Both gate regions decompile to a bare `(*(code *)(param_1 + in_RAX))(...)` with the diagnostic **"Could not recover jumptable ... Too many branches"**, because the flattening indirects through a computed table that the decompiler will not reconstruct. That is the same wall the earlier P-code work hit, now confirmed on a different tool: a static decompiler cannot follow this control flow, and `ptrace` is refused by the sandbox, so neither static decompilation nor dynamic single-stepping is available for the body. The `int3` probe remains the only instrument that reaches these sites, and it proves execution without reading the state behind it. The tools are all in place and the block is real. **The `-45018` site only publishes the decision; it does not make it.** With `PERUN_TRAP_REGS=1` the signal handler now reports the full register file and the top of stack at an int3, which is the one instrument that reaches these sites. At the live `-45018` site (RVA `0xb5b4a`) the state is `rcx=0x7c85b0b1`, `rdx=0x6bd`, `r8=4`, `r9=0x4069d332`. `rcx` is the address `0x5b0b1`, and the bytes there are the function epilogue (`mov %edi,%eax` followed by six `movaps` restores of the callee-saved xmm registers); the block above it at `0x5b0a9` loads `edi` with `0xffff5036` and dispatches. So the guest is already on its way out when the trap fires, and `r9=0x4069d332` is the CFF state token this project's earlier work named. The consequence for the search is concrete: the branch that chooses `-45018` is upstream of `0xb5b4a`, and every probe aimed at that address was aimed at the messenger. **Uniformity explained.** The frame sweep could not move the result because the decision is taken before the frame is consulted in any way this project can influence from outside. **The flattened body is walkable, and an earlier claim that it was not was wrong.** A previous revision of this row said the x86 trap flag could not be used, and put the blame on the kernel: that Linux clears TF from the context restored into a signal handler. That is not what was happening, and the claim was a rationalisation of a bug in the code that was testing it. The priming handler was written as `eflags & !TF`, which removes the bit, when its only job was to install it; the trace stayed at zero and the zero was explained as kernel behaviour. **With the bit set it works.** `PERUN_STEPS=N` single-steps the call from inside the process: TF is installed once, the handler logs RIP, flags, rax and rdi and leaves TF set, and the walk is self-sustaining. Measured: the walk begins exactly at the export entry `0x5afc0`, visits 1 292 distinct basic blocks within 60 000 instructions, and reaches the live `-45034` gate at `0x66c2d` after 109 066 instructions in 1.3 s. So the whole of this analysis rested on an assumption about the kernel that was never true, and the assumption was made by the same process that had the bug in front of it. `PERUN_STEP_UNTIL=<rva>` stops the walk at an address of interest, which is what makes a body this size affordable at roughly ten thousand instructions a second. **This changes what is possible here, not only what is known:** the branch that selects the return code is reachable, and the next step is a walk to it. **How far the walk actually gets, measured.** It starts exactly at the export entry `0x5afc0` and reaches the live `-45034` gate at `0x66c2d` after 109 066 instructions in 1.3 s, so the flattened prologue is fully traversable. The `-45018` site at `0xb5b4a` is not reached within 3.9 million instructions in 400 s, and the bottleneck is the trap itself: single-stepping costs roughly ten thousand instructions a second, and a call that returns `-45018` visits far more of the body than the gate does. That is a throughput limit, not a reachability one -- an unfiltered run completes and returns `0xffff5026`, so the site is executed by the real call, the walk just does not arrive inside the budget. The next thing that would help is a cheaper instrument than a trap per instruction: an int3 planted on the *edges* of the flattened blocks would sample the path rather than trace it, and the block starts are recoverable statically even though the jump table is not. **The CFF jump table is readable, and inverting it finds the predecessors.** The flattened dispatch is `lea table; movslq (table,index,4); lea this_block; add; jmp *reg`, so a target is `block_base + table[index]` and the table at RVA `0x15fc90` is plain signed 32-bit data. Inverting it over every `lea` base in the function yields exactly **three** dispatch sites that can reach the `-45018` site at `0xb5b4a`: `0xb2e6f`, `0xb472d`, `0xb55a0`. Planting an int3 at each shows **none of them executes**. So the `-45018` site is not reached through that table from those bases, which means the edge into it is built some other way -- a second table, or a register moved across blocks, as the chain at the site itself does (`lea 0xaa17d(%rip),%r11` then `mov %r11,%rcx` in one place, and the register arriving pre-loaded in another). The cost of a static inversion is under a second against a walk that needs minutes, and it is the method to extend: the same inversion over every table in the image maps the flattened graph completely. **The decision is reached, and the path to it is now known.** The throughput problem was the handler, not the guest: it did a `write(2)` and a `format!` per instruction, and it kept TF set while the guest was inside a host shim, so one `HeapAlloc` cost tens of thousands of traps. With the handler reduced to two ring stores and the stop taken on a *register* rather than an address, the walk is cheap: **109 458 guest instructions in 1.2 s**, against 3.9 million in 400 s before. `edi == 0xffff5026` is the trigger, so the walk stops wherever the flattened body arrives at the code it is about to publish, independent of where this build stores it. **Stopping on the register is what made the address unnecessary**; the earlier difficulty was largely an artifact of trying to hit a fixed address by walking toward it. The last 256 instructions are the answer: the final edge is `0x7c866d8f -> 0x7c8b5b2b`, and immediately before it `0x7c866d5e: cmp $0x4069d333,%edx`. So `edx` is a selector compared for equality against a family of `0x4069d3xx` tokens -- a command chain, and a different one from the brief's opcodes. Two ways of resuming the walk into host code were tried and are both wrong: clearing TF for a shim means the shim never traps again, and planting an int3 on the shim's return address corrupts the guest, because that byte can be the second byte of an instruction and a return address can be re-entered. Leaving TF on and simply not recording the instructions that are not ours is what works.   **The size gate is on the caller's frame after all — the previous two rows on this are both wrong, and the measurement that settles it is a capacity threshold.** The size check at `0x66bfc` compares one frame field against another plus four. With the cursor field left at zero, sweeping the capacity gives a clean threshold: **capacity 1 and 2 return `-45034`; capacity 4 and above return `-45018`.** Four is exactly `cursor + 4`, so the fields being compared are the caller's own. The buffer pointer at `+0x00` must be readable or the call faults writing through it, and the *contents* of that buffer are irrelevant: zeroed, a byte ramp, and all-ones are indistinguishable. The cursor field at `+0x0c` does not affect the outcome at all. **So, superseding the two rows before it.** The `rbx` register at the stop, `0x74dd4cf41000`, is not the `ctx` that was passed, and that was taken to mean the check reads the library's own object. It does not: the library copies the caller's frame to a heap buffer and reads the copy, which is why the register differs while the semantics are the caller's. An earlier row in this series attributed the uniformity to the frame being consulted in a way this project could not reach, and then corrected itself in the other direction; both were inferences, and the threshold is the measurement that replaces them. What survives is the part that was always right: past the size gate the walk is byte-identical for every frame, the selector `edx = 0x6bb` is computed internally, and **no capacity, cursor, pointer or buffer content supplied by the caller changes the `-45018` result.** The brief's model, an opcode in a register with a frame in the next, still does not describe this entry point. **Correction to the claim of a byte-identical walk, and the full-order trace.** Two rows in this series assert that different frames produce identical walks. They do not. The ring was enlarged to hold the whole traversal -- 109 210 guest instructions in 1.4 s, printed in order -- and the step count *depends on the capacity field*: capacity 4 gives 109 458 steps, 0x10 gives 106 936, 0x100 gives 109 210. The earlier comparison used two values and treated the difference as noise. It was not noise, and the claim was wrong. What is uniform is the *outcome*: **fourteen capacities from 4 to 1 MiB, every combination of cursor, pointer and buffer content tried, and the init export called first or not, all return `-45018`.** The frame changes the path the library walks and does not change what it concludes. The full-order trace also locates where the selector is born: `edx` holds `0xa8d` and is reduced to `0x0a8a` by the `sub`/`add` pair at `0x66c11`/`0x66c13`, from which the `imul` at `0x66cf7` produces `0x4069d332` for the equality chain to consume. So the chain is not entered by the caller and is not adjustable by one; the caller's frame selects among paths *inside* the flattened body, and every path available to it ends in the same answer. **This is the honest state: the input space reachable from the outside has been swept and it is a single point.** **The whole traversal, and what it rules out.** Letting the walk run to the budget rather than stopping at the error gives the complete picture: **80 055 guest instructions**, then the function returns, and the output buffer is never written to. The `-45018` decision is taken at instruction about 59 000, and the remaining 21 000 instructions are 1 536 distinct blocks, **all of them in `.text`** -- rollback and cleanup, with no access to `.data` and no write to the caller's buffer. So the library does not decline to produce a token because it ran out of work: it decides early, then unwinds. The only state it consults on the way is its own, and the only state the caller supplies is the frame, which has been swept. **That closes the search over inputs.** The remaining requirement is not a better frame, a different argument, or a fuller call sequence -- all three are swept and all three converge on `-45018`. It is prior state: something the library must already hold before this entry point is entered, laid down by a code path this walk never reaches because the gate turns it away first. Finding it means finding what would have run *before* step 59 000 on a provisioned host, and this entry point will not show it. The Android lane reaches the same state through real Bionic libc underneath it; reproducing that here is the remaining work, and it is a different problem from the one this walk was solving.   **The header is a 4-byte field, and the published `AdiOtpPacket` layout is refuted by measurement.** An earlier row in this series called the switch a single byte at offset 3. That was a per-bit sweep of one little-endian word and it was not the whole field: the surrounding bytes matter too. Sweeping the packet a byte at a time finds **exactly one** offset in 48 that changes anything, and sweeping that byte over all 256 values gives **1 or 2 and nothing else**. Bytes 0..2 must be zero: with byte 0 set to 1, 0x12 or 0xff and byte 3 at 1, the call is back to `-45018`. So the packet begins with a **4-byte big-endian value equal to 1 or 2**, and the remainder of the buffer is irrelevant. **This corrects the brief.** Its `AdiOtpPacket` has `version: u64` at `+0x00` with the value 1. Read as a little-endian u64 that puts a 1 at byte 0 and a zero at byte 3, which is the configuration that returns `-45018`; only the big-endian reading of a 32-bit field puts the 1 at byte 3, and then the field is not a u64 and not a version. The rest of the published layout was tested against the measured header and does not advance anything: `+0x08` over six values including `-1`, and `+0x10` over three including real buffer addresses, all give `-45025`. The published layout may be right for the Android build, which is a different library; it is not what this one parses. **What is now known about the input is a 4-byte field, its two accepted values, and that no other byte of a 48-byte packet changes the outcome.** `-45025` is still not a token: the function dispatch is entered and the selector it dispatches on has not been found, and the walk cannot yet be aimed at that path.
| 2026-09-28 | **The published Anisette sources, reviewed, and what they do and do not settle (2026-09-28).** `Blackwood-4NT` and the 4PDA thread were read in full against the measurements in the rows above. **What they support.** The common `ADI` header — arguments pointer, input size, output size, flags — is the shape this project found independently: the size check at RVA `0x66bfc` is exactly `input_size >= output_size + 4` on the caller's block. The six exports, the `cvu8io98wun` (version and protocol) / `vdfut768ig` (worker) split, and the environment table (`IdMS` `-2` production, `IdMS1` `-3` UAT, `IdMS2` `-4` QA, `IdMS3` `-5` QA2) all match what is here. The source places a per-operation magic in the first argument, *ECX*, and describes the worker as `__fastcall` on x86 with `ECX:EDX` as inputs and the regular x64 ABI otherwise; that is consistent with the measured behaviour, where the first argument is consumed arithmetically and any small value in it faults. **What they do not settle.** `Blackwood-4NT` says `CoreADI` is heavily obfuscated with FairPlay DRM and that, because the protected material is commercially sensitive, *"no additional details on how FairPlay can be bypassed will be explained here"*. So the per-operation magics are named only for two non-provisioning calls (`0x632b8d6e` for `ADIGetIDMSRouting`, `0x85fe63b0` for `ADISetIDMSRouting`); the provisioning magics are not given, and neither source documents the 4-byte field measured in the previous row. That field is a property of the *arguments block*, is one of two values, and is not either named magic — so "the magic in ECX" and the measured argument-block field are two different things. Passing the documented magics as the first argument faults, which is what the entry does with every small value, and `0x632b8d6e` is above `2^31` so the entry masks it before use. **The packet layout supplied for this phase is refuted by measurement on this build.** It specifies `version: u64 = 1` at `+0x00`, which the library rejects: the first dword must have bytes 0..2 zero and byte 3 equal to 1 or 2, and `1` as a little-endian `u64` cannot satisfy that. The same layout's `dsid` and buffer pointers are irrelevant here — sweeping `+0x08` and `+0x10` over 9 and 3 values changes nothing once the 4-byte field is right. The sources are worth having in the tree for the structure they do confirm; they are not a specification of this entry point, and the field that gates it is in neither.
| 2026-09-28 | **The command selector is the first argument, matched exactly, so five of the reported magics are recognised (2026-09-28).** The brief for this phase and `Blackwood-4NT` both place a per-operation magic in the first argument (`ECX` on x86, `RCX` on x64) and describe the worker as `__fastcall` with `ECX:EDX` as inputs. A row in this file had read that as wrong, on the grounds that the first argument is consumed arithmetically and a small value in it faults. **The observation was right and the reading was wrong.** Those two facts are consistent with a magic: the entry computes `lea eax,[rcx+rcx]`, masks, and *indexes*, so a value below `2^31` is not a valid command and faults, while a value above it is preserved and compared. Testing settles it. With the version-1 header in the arguments block -- four bytes `00 00 00 01` -- the return code depends **entirely** on the first argument, and it is an exact-value match, not a mask: `0x632b8d6c`, `0x632b8d6d`, `0x632b8d6f` and `0x632b8d70` all return `0xffff5025`, while `0x632b8d6e` alone returns `0xffff5024`. Of the reported values, `0x632b8d6e` (`ADIGetIDMSRouting`), `0x85fe63b0` (`ADISetIDMSRouting`), `0x3e58e7f9`, `0xcfe0b46a` and `0xb0eda7af` give `-45020`; `0xc774d292`, `0xb23c691e` and the `0x4069d3xx` tokens give `-45019`; 24 uniformly random 32-bit values all give `-45019`. So the dispatcher recognises a small closed set of commands and answers `-45020` for them, which is a *further* stage than `-45019` (`unknownAdiFunction`): the command is accepted and the call then fails on its arguments. Both codes are new to this project -- the error table had `-45019` and `-45018` and nothing below. **The four-byte field and the first argument are two different things**, which is why sweeping the arguments block alone never moved the result past `-45025`: the version field is necessary to reach the dispatcher, and the command lives in the register. On a confound that cost a run: an earlier part of this work left a real `adi.pb` under the virtual `CommonAppData` tree, and its presence suppressed the `-45019` / `-45020` split entirely, so every sweep after it read `-45018`. The directory was removed and the split reproduced. Any future sweep of this entry point must start from a clean virtual appdata.
| 2026-09-28 | **The `-45020` body check does not read the argument block, and its publishing site is located (2026-09-28).** `-45020` (`invalidInputDataParamBody`) is in the canonical `ADIError` enum, so the code the dispatcher now reaches is a real one and not an artefact. Hypothesis tested and refuted: that the body validator wants an *Environment* field, the signed value `-2` (production), `-3` (UAT), `-4` or `-5` (QA) that `Blackwood-4NT` documents, placed immediately after the version header. Both byte orders were tried at `+0x04`, and every signed value was then swept at every qword from `+0x08` to `+0x38`: all 60 byte positions set to `0xff` one at a time, and `0, +1, +2, -2, -3, -4, -5` at each of seven qwords. **Every one of them returns `-45020` unchanged.** So the check does not read the argument block as a caller lays it out, and the documented Environment field is not where this build looks for it. The `-45020` publisher is nonetheless pinned: of the fourteen `mov $0xffff5024,%edi` sites in the function, an `int3` probe over the `call` harness — which does honour `--patch`, unlike `seq` — shows exactly one executes, RVA `0x8f69d`, and the bytes there are `bf 24 50 ff ff ff`, the same instruction. So the check is a branch immediately upstream of `0x8f69d`, in the same `cmp $imm32,%edi` chain the CFF uses, and the predicate it evaluates is not over the argument block. That is the next thing to read, and the walk is the tool for it: the harness now used cannot pass a magic in the first register, which is the one thing this path needs, so the harness has to grow before the walk can follow it.
| 2026-09-28 | **On the `-45020` path the library writes into the caller's block, and that write is the first observable output (2026-09-28).** The harness gap that blocked the walk is closed: `perun call` takes the command as a literal first argument and a literal or `scratch` / `ctx` second, and the `call` path — not `seq`, which silently ignores `--patch` — carries both `--poke` and `--patch`. With `rcx = 0x632b8d6e`, `rdx` = the frame, `ctx[0]` = a buffer whose first dword is `00 00 00 01`, the call **returns `0xffff5024`** and then faults in host code afterwards, on the magic value as an address. Three things follow. **The command is read from `rcx` and the argument block from `rdx`, which is the published shape**, and the earlier reading that a magic in the first register was refuted was wrong. **The fault is after the return**, not during the call: the return value is printed first, the library then walks its epilogue and touches a pointer it left behind, and `addr` equals the magic that was passed in. That is a defect in the runtime's call path on this branch, and it is why the walk could not follow the path. **And the library writes into the caller's argument block**: `scratch[0]` reads `0x01000000` afterwards, where the version header `00 00 00 01` was before, so the first dword was replaced. A recognised command therefore mutates the caller's buffer before the body check completes, which is why the body sweeps could not distinguish a well-formed argument from a malformed one: the body is validated against a block the library has already rewritten. That also means `-45020` is reported on a partially consumed block, and the correct shape of the request is whatever the library leaves in the block on the success path, not what a caller writes into it beforehand. Establishing that needs the post-return fault fixed, since it truncates the run.
| 2026-09-28 | **A harness defect fixed: `perun call` read through a literal argument, and two of this file's claims were wrong about it (2026-09-28).** Passing a command selector such as `0x632b8d6e` as the first argument made `perun call` fault *after* the guest had already returned, with `addr` equal to the selector. The post-call dump probed the argument for readability and then read it anyway: the probe is a `write(2)` to `/dev/null`, which returns `EFAULT` for a bad range rather than faulting, so it was never a guarantee, and the `from_raw_parts` that followed was unguarded. The dump is now restricted to the ranges `call` actually handed out — the scratch page, the context region, and the image — and anything else is reported as a literal. With that, the `-45020` call completes: `rc 0`, no fault. **Two claims in the previous row are withdrawn.** The library does *not* write into the caller's argument block: the header bytes `00 00 00 01` are what a little-endian `qword` read of that address displays as `0x01000000`, and the harness printed it in that form, so the apparent rewrite was a misreading of a correct value. And the fault was never inside the guest — the return value is printed before the fault line, and both are host-side. **The walk now runs the `-45020` path**, which it could not before: with the crash fixed it traces 83 927 guest instructions before the library leaves the image, at RVA `0xd731c`, through `jmp *%rdx` after `cmp $0x102` / `cmp $0x103` — Win32 error codes, and a dispatch through the import table. The walker does not follow the call, so the trace ends there. That is the next thing to read: the `-45020` decision is somewhere in those 83 927 steps, and the ring holds all of them, so it can be located the way the `-45034` publisher was.
| 2026-09-28 | **The `-45020` path's last guest block, and what the walk now records (2026-09-28).** The walk records `rip` and the low half of `edx`; `rdx` is added to the ring because the flattened dispatcher ends every import call with `movslq (%r10,%rcx,4),%rdx ; add %r12,%rdx ; jmp *%rdx`, so `rdx` at the step before the jump *is* the import address, and recording it names the API without needing the import table read. The `0xd731c` block that the previous row ended on decodes as: a carried value in `rdx` is range-checked against `0x102` and `0x103` (`cmp $0x102,%rdx ; seta %sil` and `cmp $0x103,%rdx ; setb %dil`), the two boolean results are folded into the next selector, the carried value is spilled to `0x15c(%rsp)`, and the block tail-jumps through `(%r10 + rcx*4) + r12`. **So `0x102` and `0x103` are not Win32 error codes and not return values** — they are bounds on a value the CFF carries between blocks, and nothing about them is a timeout or an enumeration error. That was worth separating: reading them as `WAIT_TIMEOUT` and `ERROR_NO_MORE_ITEMS` fits the constants and explains nothing, because the guest has not called anything at that point — the jump is what *makes* the call, from the block after the comparisons. With `rdx` in the ring the tail of the path is visible: the last guest blocks sit at RVA `0xe4c1b`..`0xe4c60` with `edx` stepping `0x14e39c01 -> 0x1a1 -> 0x0 -> 0xdace`, and the `rdx` values along it are the CFF's own state tokens (`0x32f88e9214e39c01`, `0x01fed4c698c3ba3a`), not host addresses. The guest is not sitting on a shim slot at the moment it leaves, so the import it is about to call is not yet determined by the ring — `r10` and `r12`, the table base, are set at entry and never change, and neither is recorded. That is the next field the walk needs.
| 2026-09-28 | **The `-45020` publisher is not any `mov` site, and one of my own negative results was an unvalidated tool failure (2026-09-28).** Fourteen `mov $0xffff5024,%edi` sites exist in the body and every one of them was probed with an int3 on the recognised-command path. None traps. The control site does trap at the same time, so the negative is real and not a mechanism failure: **the return code is computed, not loaded.** The same shape as the `-45034` case, where the live producer was a `sub`/`add` pair rather than any of the thirty-seven `mov $0xffff5016` sites. **A previous row's claim that a single `-45020` site was live is withdrawn.** It was measured with `--patch=6602d` — a bare hex string — which `parse_num` rejects; the run exited 2 before doing anything and the sweep read that as "no publisher". With the `0x` prefix the control traps as expected. Every such probe in this project needs a control before its negative is believed, and the lesson is the one the file already states: a negative from an instrument is evidence about the instrument until the instrument is shown to work on a case that must fire. Two harness facts also fell out. `perun call` needs `0x` on `--patch`; and the walker's ring report is emitted only from the handler's stop path, so a run where the guest returns before the budget prints nothing at all, which reads as "the ring is empty" when the ring is in fact full. The call on this path completes at roughly 110 000 steps, between a 105 000-step budget that fills the ring and a 120 000-step budget that reports nothing.
| 2026-09-28 | **The published OtpPayload layout is inert past the first word, on both recognised commands (2026-09-28).** A brief supplied an `OtpPayload` for the OTP command `0x3e58e7f9`: `version_be` as a `u64` whose byte 3 is 1, `dsid` as -1, then `ptr_mdm`, `size_mdm_ptr`, `ptr_md` and `size_md_ptr` as real pointers, with the envelope carrying an input size of 48 and an output size of 16. Built exactly and run: `-45020` (invalidInputDataParamBody), and the payload is byte-for-byte unchanged after the call, so nothing past the header is even written. A `dsid` sweep over -1, -2, 0, 1, 2 and 3 is uniform. Sweeping each qword of the 48-byte payload to `0xff` one at a time moves the result only for `+0x00` -- overwriting the version header gives `-45018` -- and leaves `+0x08` through `+0x28` completely inert. The same is true of the routing command: with `0x632b8d6e`, a sweep of `+0x0c` over 0 through 4096 and of every byte position 0..47 is uniform. **What these two codes have in common is that the body is validated from the first four bytes and then, whatever follows, is rejected on something the caller does not supply.** The environment id, the dsid, the output capacity and the output pointers are all inert in this build, so the shape the published layouts describe is not what this binary reads. Recorded also: a routing command cannot succeed on an unprovisioned machine by construction, so `0x632b8d6e` is the wrong probe for the happy path, and the OTP command is the right one -- both nevertheless stop at the same body check, which is now the single remaining obstacle and is known to be neither a size check nor a field of the supplied payload.
| 2026-09-28 | **The arguments do not start at +0x20 either, and the -45020 path never publishes the code in edi (2026-09-28).** A second published layout, from a different dissection of the OTP entry point, puts a 4-byte `global_header` at `+0x00` followed by 28 bytes of padding and the arguments at `+0x20` -- `dsid`, `ptr_MDM`, `size_MDM`, `ptr_MD`, `size_MD` -- on the reasoning that the caller's own test had put them at `+0x08` and `+0x10` and the library ignored everything between 4 and 32 as padding. Built and run: `-45020`, unchanged. The padding length is therefore not the discriminator, and the observation that drove it -- arguments at `+0x08` and `+0x10` being ignored -- is a property of the build, not of the format. **The OTP path does not publish its return code in `edi` at any sampled instruction.** The walker's stop trigger fires within 1.2 s of tracing on the `-45018` path, where `mov $0xffff5026,%edi` is what the trap catches. On the `-45020` path, with the OTP command and the same trigger, the walk runs the full traversal and the call returns without ever matching, even though the return value is `0xffff5024`. The two codes are therefore not published the same way: `-45018` is a constant loaded into `edi` on a path the walk visits, and `-45020` reaches `rax` by a route the register trigger does not sample. Locating it means following the value rather than the code, and the walker as built samples registers, not memory -- so the next instrument records writes to the guest-visible output range, which is where a computed code must pass through before it is returned.
| 2026-09-28 | **The register trigger is an unreliable instrument, and a control run is needed before any negative from it (2026-09-28).** The walker's stop condition tests the argument and result registers for the code being published, and it did fire on the `-45018` path in earlier runs. It no longer does. The mechanism is visible in the code: the value is published by an instruction, and TF traps *before* that instruction executes, so the register sampled at the trap still holds the previous instruction's result. Whether the trap observes the new value therefore depends on how many instructions follow the store before the walk leaves the image -- which is a property of the path, not of the instrument. On a path that publishes and returns immediately, the trap never sees it. This invalidates one claim in the preceding row. The statement that the OTP path never holds `0xffff5024` in `edi` was taken from sweeps with this trigger and is not evidence; the trigger could not have fired on that path for the reason above. `rax` is now sampled as well, and the same problem applies. **What survives is the part that did not depend on the trigger**: the fourteen `mov $0xffff5024,%edi` sites, each probed with an int3 against a control site that traps at the same time, none of them executes. That negative is sound because the control ran. **The rule this keeps restating has to be applied to the instrument, not only to the disassembly: a negative result needs a positive control in the same run, and a trigger that has not been seen to fire on the case under test proves nothing about that case.** The next instrument watches the guest-visible output range rather than a register, because a value on its way to `rax` must pass through memory.
| 2026-09-28 | **The packet header is exactly four bytes, confirmed in both directions (2026-09-28).** Sweeping the payload from an all-zero block with the version field set, one byte at a time, gives a clean split: a non-zero value at `+0x00`, `+0x01` or `+0x02` gives `-45018`, while a non-zero value anywhere from `+0x04` to `+0x2f` gives `-45020`. The header is therefore a four-byte field that must be `00 00 00 01` -- a version or a command count in network byte order -- and **nothing after it is examined**. The same split holds for the routing command. Two earlier claims in this file are narrower than this and are superseded by it. One said the switch is a single byte at offset 3; that was measured from a zeroed buffer and happened to be right, and it is right for a different reason than it looks: the three bytes before it must be zero, so the discriminator is the 32-bit field, not a byte. The other said every payload byte was inert, which is also wrong in the other direction -- bytes 0..2 are very much not inert, they must be zero, and a set byte there changes the result. The corrected statement is that the check reads four bytes and then stops, which is what makes every published layout that places arguments at `+0x08` or `+0x20` produce the same answer: there is nothing there for it to read.
| 2026-09-28 | **The init export does not populate the state object; the OTP call allocates it, and that is the -45020 subject (2026-09-28).** The body check reads four bytes of the packet and then rejects, and the two exports populate different things. Read at the gate global `0x19dda0` after each: after `cvu8io98wun` it is `0x0` -- the init export returns 0 and leaves no state object at all -- while after a single OTP call it holds a host pointer to a 0x28-byte block whose first qword is zero. So the object the body check consults is created by the operation itself, and the init export is not what fills it. That is consistent with the two exports' published roles: the init export yields version and protocol data, the operation export does the work, and neither is a substitute for the other in the same process. It also relocates the remaining question. The check is not over the caller's packet (four bytes, fully characterised) and not over a global the init export should have set (it is null after the init). It is over a field of the 0x28-byte object the call allocates, and the first qword of that object is the field the earlier walk named as the gate. **The next step is to fill that object**, which the runtime can do at the point of allocation the way the earlier seeding attempt did, and the earlier attempt failed for a reason now understood: it seeded the first qword, which is the flag, but the guest re-zeroes it immediately after allocation and before the check. Seeding a *different* field, or seeding after the zeroing, is the untried case.
| 2026-09-28 | **Filling the state object does not clear -45020, and the object is smaller than its allocation (2026-09-28).** The next step proposed in the previous row was to seed a field other than the first in the 0x28-byte object the operation allocates. `PERUN_GATE_SEED=<field>:<value>` now writes one qword of that block at allocation. Seeding each of its first four qwords with 1, and field 1 with 2, 0x11, 0x7fffffff, -1 and the image base, every run returns `-45020` -- no value, and no field, changes the outcome. The guest's own zeroing of the flag was therefore not what stood in the way; the block is simply not what the check reads. Incidental and worth recording because it sizes the object: seeding the fifth qword aborts inside glibc with a sysmalloc assertion. The allocation is 0x28 bytes but the object is **four** qwords, 32 bytes, so the fifth qword lands past it. The earlier `--peek-ptr` dump showed 0x28-byte allocations and the walker's register dumps showed a 0x28-sized request; the block itself is 32 bytes and the difference is tail padding. Consequence for the goal: `-45020` is not a state flag in this object and not a field of the caller's packet -- the packet contributes four bytes and the object contributes nothing that a caller can set. What remains is a check over something neither the frame nor this object holds, which is the same place the -45018 wall turned out to be before the version header was found.
| 2026-09-28 | **The session sequence was never replayed: the opcodes split cleanly, and the body check is what refuses (2026-09-28).** Every probe so far issued a single opcode in a cold process -- the equivalent of stepping straight to step 7 of the eight the Android run performs. Replaying all eight in one process through `perun seq` is possible and was done, and it changes the picture in one respect and not in another. With the version header laid down, five of the ten opcodes reach the body check and five do not: `0xb0eda7af`, `0xcfe0b46a`, `0x3e58e7f9`, `0x632b8d6e` and `0x85fe63b0` return `-45020`, while `0xb23c691e`, `0xc774d292`, `0x4069d332`, `0x4069d333` and `0` return `-45019`. The two session-init opcodes the Android dump shows first, `0xb0eda7af` and `0xb23c691e`, are **not a matching pair here**: the first is recognised, the second is not, and `0xc774d292` -- the opcode the Android dump attributes to SetMachineID -- is not recognised either. The opcode table of `CoreADI64.dll` and of the Android `libstoreservicescore.so` are therefore not the same set, and the Android call order does not transfer as a sequence. What the replay does confirm is that the body check is a per-call gate on a session that is still empty: the order does not change any outcome, and seeding the state object does not either. The three recognised opcodes that matter -- the OTP request `0x3e58e7f9`, provisioning `0xcfe0b46a` and `0xb0eda7af` -- all reach it and all are refused.
| 2026-09-28 | **What the call writes into the image, which is where the -45020 subject is (2026-09-28).** `PERUN_DIFF=1` snapshots the image before a call and reports every qword it changes. One `0xb0eda7af` call changes 47 qwords, in three groups: `0x19d020..0x19d058` (eight qwords replaced with what look like encoded values, and `0x19d050` loses the CFF token `0x4069d332`), a lone `0x19d088` that goes from `0x13284975` to `0x13284976`, and a block at `0x19dba0..0x19ddb0` that goes from all-zero to a run of distinct 32-bit-looking values, immediately followed by the state pointer `0x19dda0` being set from zero to a host heap address. The `0x19dba0` group is the finding: a 48-byte structure of per-call data the library builds for itself, written *after* the packet is rejected. It is not an input the caller supplies and it is not the 0x28-byte object the earlier seeding attempt filled -- different address, different size, written by the call rather than allocated by it. That is consistent with everything measured so far: the body check refuses because the state it consults is not yet populated, and the population happens later in the same call, in a structure the caller has no handle on. Also recorded because it invalidates a step: the counter at `0x19ddb8` goes from `0x0000000100000000` to `...003f` in a single call, so it is not a call count and the earlier plan to replay a longer sequence is not expected to change on its own. The five recognised opcodes remain refused, and this is the first account of what the library writes when it refuses.
| 2026-09-28 | **The diff structure is not per-call state, and the packet is read past the header only as input to it (2026-09-28).** The previous row read the group at `0x19dba0` as state the library builds for itself. Tested, that reading is wrong in a way worth recording: across three different recognised opcodes the group is written identically, 47 qwords each time, and its values differ between runs of the same input, so it is derived per run and not per call. It does change when a single packet byte changes, so the library reads the packet beyond the four-byte header -- but the return code does not, and a non-zero byte at `+0x00` alone still gives `-45018` while every other offset in the 48-byte packet gives `-45020`. So the header is still the only thing the decision depends on, and the group is a downstream product of the whole packet, not its subject. The five recognised opcodes all change the same 47 qwords and are all refused identically, which is the cleanest statement yet of the remaining barrier: a recognised command with a correct header is refused on something that is the same for every command, and the caller's packet does not reach it.
| 2026-09-28 | **Two corrections: the diff group is command-specific, and the callback-vtable hypothesis is refuted (2026-09-28).** The previous two rows read the 47 qwords at `0x19dba0` in opposite and both wrong ways. It is not a per-run constant: the set of changed addresses is the same for all five recognised opcodes, but **38 of the 47 values differ between them**, so it is a fixed scratch area the library fills with command-specific data. It is also not the subject of the decision -- it is written during the teardown that follows the refusal, and reading it explains nothing about why the call was refused. That remains the honest description and the earlier framing is withdrawn. The Android frame's `+0x18` and `+0x20` hold code pointers, and the hypothesis that they are host callbacks whose absence is what the body validator rejects is refuted by measurement, not by argument. Setting either or both to 1, to the image base, or to the address of the export's own entry -- three distinct kinds of value, non-null and pointed at code -- changes nothing: every combination returns `-45020`. A null check would have moved on the first, and a call through the slot would have crashed on the third. Neither happened, so the frame is not read past the header at all, which is what the byte sweep had already said.
| 2026-09-28 | **Every caller-reachable input is measured and inert; the barrier is not a payload (2026-09-28).** Closing out the input search. `r8` and `r9` were the last two arguments never given a real test: the cookie in `r9` was tried as zero, as the `vdfut768ig` entry, as the `cvu8io98wun` entry, and as a mid-`.text` address, with `r8` at zero as the Android dump shows, and all four give `-45020`. A real 347-byte SPIM from the Android run was then placed in the packet after the four-byte header and offered to the provisioning opcode `0xcfe0b46a`, the initialiser `0xb0eda7af` and the OTP opcode `0x3e58e7f9`; all three still return `-45020`. So the barrier is not a missing payload and not a missing cookie. The full measured set, every item with a control: the opcode in `rcx` (five values recognised, four not); the four-byte version header (byte 3 must be 1 or 2, bytes 0..2 must be zero); the size pair at `+0x08`/`+0x0c` (threshold exactly cursor+4); the buffer pointer at `+0x00`; the packet body past the header; `r8`; `r9`; the caller's own memory, into which the library writes nothing; the call order, replayed through `perun seq`; the state object, seeded in all four of its qwords across six values; the virtual filesystem, walked by the loader with and without a real `adi.pb`; and the two exports the library has, which are the only entry points that exist. None of them changes `-45020` once the opcode and version byte are right. What remains is a condition inside the flattened body of `vdfut768ig` that is satisfied on a real Windows host by something this environment does not reproduce — the state a provisioned machine carries, since `ADIGetLoginCode` is documented as reporting whether provisioning information was cached on the machine. Two independent oracles agree that the caller does not supply it: the un-obfuscated `libstoreservicescore.so` stamps only the version byte and never assembles a body, and `CoreADI64.dll` exports no wrapper that could. **The `-45020` barrier is therefore characterised but not passed, and `perun adi headers` is not implemented, because shipping the Android engine under that name would be a substitution and not the Windows path the acceptance criterion names.** |
| 2026-09-29 | **The `-45002` front was manufactured by this project's own probe, and the real front is `-45020` (2026-09-29).** `--poke=0x19db98=scratch` writes a host pointer into a slot inside the library's state. With it the call returns `0xffff5036`; remove it and the same call returns `0xffff5024` (`-45020`); remove every poke and it returns `0xffff5016`. **Everything recorded for `-45002` — the `0x5b0a9` front, the `test edi,edi` at `0x66bb8`, the 80 457-instruction walk, the gate object, the `lock cmpxchg` singleton and the three blocks read out of them — describes the library's unwinding after being handed a bogus pointer, and is withdrawn.** `0x19db98` is not a gate. The seven frame shapes and the `r8`/`r9` sweep were measured on that manufactured path and must be re-run against `-45020` before they are believed. |
| 2026-09-29 | **`-45020` is published unconditionally at `0x8ff0a`, and the real payloads are captured (2026-09-29).** On the clean path with a real 16-byte payload the walk runs 222 374 instructions and `0x8ff0a mov edi,0xffff5024` materialises the code with no `cmp`/`test`/`jcc` on the segment; the nearest conditional is `0x8ff25 cmp QWORD PTR [rsp+0x80],0x0`, a stack slot rather than the packet or the frame, so the routing was decided earlier. The three payloads from the working Android engine are saved as `payload_init_1.bin`, `payload_init_2.bin` (both 16 bytes, byte-identical) and `payload_prov.bin` (48 bytes), all starting `00 00 00 02`; a zeroed 16-byte buffer gives `-45018` instead, so the header is load-bearing and the twelve bytes after it are not. Every hypothesis about the body had rested on a synthetic header until now. |
| 2026-09-29 | **Nobody imports CoreADI statically; the module name is assembled at run time (2026-09-29).** All 220 PE files under the extracted iTunes tree were swept: no import-table entry for `CoreADI` or `CoreADI64`, and the string `CoreADI.dll` occurs only inside the two copies of the library itself. The name is the internal one, not the file name, which is why every name-based search for the caller has come back empty. |
| 2026-09-28 | **The packet packer is `0x1dbfd0`, and it reads the frame's five argument slots at `+0x20`..`+0x40` (2026-09-28).** `qi864985u0` is a five-line wrapper: it copies its five register arguments to `-0x38`..`-0x18(%rbp)`, points `-0x10(%rbp)` at the struct at `-0x58(%rbp)`, and tail-calls the packer. The packer at `0x1dbfd0` reserves `0x1278` bytes of stack, takes that struct pointer in `rcx`, and loads `+0x20`, `+0x28`, `+0x30`, `+0x38`, `+0x40` into `r11`, `rdi`, `rsi`, `rdx`, `r8` — which are exactly the five arguments in order: `dsid`, `out_mdm`, `out_mdm_len`, `out_md`, `out_md_len`. It then dispatches on `ebx = 0xfffff8d2 + *(frame+0x00)`, so the pointer at `+0x00` selects the path. **These five slots are past `+0x10`, where the frame built for the Windows lane was empty**, and the Android frame dump confirms they are populated there — `+0x28` and `+0x30` are a heap pointer and a matching length, `+0x38` and `+0x40` likewise. Filling all five in the Windows lane as a plausible OTP request, together and one at a time, does not move the return from `-45020`; a big-endian body length in bytes 4..7 of the packet does not move it either. The TLV hypothesis is refuted by measurement, as is the reading that the packet is four bytes and nothing more: the caller stamps the version and the packer serialises the five arguments, but where it puts them is in the later blocks of the packer, which the dispatcher reaches only after the `0x19db98` NULL check passes. || 2026-09-28 | **All six `CoreFP.dll` exports reject their arguments before touching ADI (2026-09-28).** Called with null arguments, five of the six return `0xffff5bd9` (`-42023`) identically and `YlCJ3lg` returns `0xffff5a58` (`-42408`); `dku592fbFAj` faults. None of them reaches the ADI path: the seal experiment records no read of `.data`, and no export attempts `LoadLibrary` on `CoreADI64.dll` or a `GetProcAddress` for either export name — the only shim activity anywhere in the run is the static-phase `LoadLibraryExW` that the loader itself performs. The uniform return across five distinct entry points is the signature of a shared argument guard, not of five different code paths: these are the FairPlay entry points, and they are refusing input before any work happens, so the caller this project needed is loaded and callable but not yet driven far enough to resolve `vdfut768ig`. That is a narrower and more honest statement than the previous row's "answering rather than refusing" — the module answers, but the answer is a rejection at the door. What driving it needs is a correctly shaped first argument, and nothing in this project has established what that shape is: the module is obfuscated FairPlay code, unlike the Android caller, whose five-argument signature was decoded from the library that wraps it. The remaining route is unchanged and is now the only one: find the argument shape this module wants. || 2026-09-28 | **`CoreFP.dll` now loads and runs under the runtime, and its export returns a FairPlay code (2026-09-28).** Two shims were missing for it — `GetModuleFileNameW` and `IsValidCodePage`, both named by the runtime's own scaffold output — and adding them was enough: the module loads at its preferred base `0x7c800000`, `DllMain` returns TRUE, and the shim table reports 113 resolved APIs with no unresolved import left. Its six exports are obfuscated, and calling one, `X46O5IeS`, returns `0xffff5bd9`, which is `-42023` and therefore outside the ADI range: a FairPlay status, not an ADI error. So the caller that was missing from this project is now running, and it is answering rather than refusing. The seal experiment on it reports no reads of `.data` from that entry, so the arguments, not the module's globals, are what it is short of. This makes `CoreFP.dll` the first live lead that has not been refuted: unlike the packet shape, the `adi.pb` key and the hardware vector, it is a component that demonstrably executes here. Driving it to the point where it resolves `vdfut768ig` by `GetProcAddress` and builds the frame for real is the remaining route to the invocation shape, and it needs a search for which of the six exports is the Anisette entry, plus working arguments for it. || 2026-09-28 | **The hardware-vector theory is refuted: the DLL imports none of the hardware APIs and calls none (2026-09-28).** A theory was offered that `vdfut768ig` builds a vector of hardware identifiers — MAC addresses, volume serial, `MachineGuid` — before generating a token, that our shims answer with nothing, that the vector is therefore empty, and that the `setne` at RVA `0xd6560` is `if (vector.empty()) return -45002`. The shims make this testable, and they answer it. `CoreADI64.dll` imports 103 symbols from KERNEL32 and ADVAPI32, and **`GetAdaptersAddresses`, `GetAdaptersInfo`, `GetVolumeInformationW`, `RegQueryValueExW`, `GetCurrentHwProfileW`, `GetComputerNameW` and `GetSystemInfo` are not among them.** Six of the seven are not even present as strings anywhere in the 1.7 MB image, so it cannot resolve them dynamically either. The seventh, `GetVolumeInformationW`, is present but never called: across the whole invocation the only shim the guest reaches is `LoadLibraryExW`. A vector built from those sources could not be built, and no answer the runtime gave to a hardware query could matter, because the query is never made. **The empty vector is not a shim failure; the collection is not on this path.** This is the third theory in a row that attributed `-45002` to something the guest never touches, after the packet shape and the `adi.pb` key, and the common error is the same each time: an interpretation of one block, treated as the whole story. The measurements that hold are the ones that watched what the guest actually did. What remains unexplained is real and narrow: the `setne` compares two fields of an object the library builds, the object is not the caller's packet, and nothing in this project has shown what fills it. || 2026-09-28 | **The provisioning blob is never read on this path, so its key is beside the point (2026-09-28).** A theory was offered that `adi.pb` from the Android run fails because the Windows build decrypts it with a key derived from `MachineGuid`, CPU and BIOS, so the session vector stays empty and `-45002` follows. The file I/O shims make that testable rather than arguable, and they answer it: across `DllMain` and across every call shape exercised, **not one filesystem call is made** — no `CreateFileW`, no `ReadFile`, no `PathAppend`, no `PathIsDirectoryW`, no `GetFileAttributesW`, and not even the `SHGetFolderPathW` that the earlier round recorded while walking the directory. The `Global\adi-pb-unique` string is present in the image, so the named-object path exists, but on the paths reached here the library never gets as far as looking. A wrong key could only matter if the file were read at all. This retires the whole class of theories about `adi.pb` provenance -- Android-generated versus Windows-generated, encrypted with the wrong key -- as unmeasurable here: they all predict a decrypt failure at a point the call never reaches. It also sharpens what the `-45002` gate is. The check at RVA `0xd6560` compares `obj[+0x08]` against `obj[+0x10]`, and the seal experiment shows the body consults exactly two globals, the state pointer and one indirection table. Whatever fills that object is filled before the check and without the filesystem, which in a library that otherwise reads no external state at this stage points at something derived from the machine rather than from disk. That is an inference, and it is recorded as one: what the vector is filled with has still not been shown by anything in this project. || 2026-09-28 | **The suggested provisioning shape does not move the call past `-45002`, and two earlier readings are corrected (2026-09-28).** A shape for `0xcfe0b46a` was proposed on the reasoning that `ProvisioningStart` must return a CPIM, so `Output Size` at `+0x0c` was zero and the body validator had nowhere to write. Built exactly: envelope `+0x00` to the packet, `+0x08` input 48, `+0x0c` output 512; packet `00 00 00 02`, `dsid` `-1`, the 347-byte SPIM pointer and length at `+0x10`/`+0x18`, a 512-byte CPIM buffer pointer at `+0x20` and the length slot at `+0x28`. It returns `-45002` — and so does every variation: output size 0, 16, 512; with and without the CPIM pointer pair; the SPIM pointer present or absent; the header present or absent. **The `-45020` to `-45002` step came earlier and from something else** — the `0x19db98` NULL gate, not the packet shape. With that gate the call lands on `-45002` whatever the packet contains, which is consistent with the seal result: the body reads the state pointer and one indirection table, and no field of the caller's packet is consulted after the header. Two corrections to earlier rows. The `unknownAdiCallFlags` reading stands and is re-verified here: `+0x08` of 0, 1 or 4 returns `-45034`, while 8, 16 and 32 pass it. But the statement that the gate "is decided by the packet" is not supported — the gate and the flags are independent of every packet field swept. And the row claiming `0xcfe0b46a` had no special status is confirmed rather than corrected: all five recognised opcodes behave identically at every stage. The conclusion of the previous row stands unchanged — `-45002` is the empty-provisioning-keys check over library-built state, not a missing argument — and this round is the direct test of the alternative, with a control at every step. |
| 2026-09-28 | **The `0xd731c` jump is a compiler switch, not an import call, and the -45020 envelope hypothesis is refuted (2026-09-28).** A brief asserted the sequence `movslq (%r10,%rcx,4),%rdx ; add %r12,%rdx ; jmp *%rdx` at RVA `0xd731c` is a tail call into an import, with the nearby constants `0x102` and `0x103` being `WAIT_TIMEOUT` and `ERROR_NO_MORE_ITEMS` so a shim's return value would decide the branch. Both parts are wrong. The table is indexed by a 32-bit sign-extended entry and combined with a 32-bit displacement, which is the shape of an MSVC switch jump table, and the target it reaches is RVA `0xe4c1b` -- inside the library, not a host shim. A shim call would leave the image, and it does not: the guest continues in the library. The two constants are range bounds on a value the flattened code carries between blocks (`sil = rdx > 0x102`, `dil = rdx < 0x103`), folded into the next block's selector; there is no preceding call whose return they could be reading. **The envelope hypothesis is also refuted.** The brief predicted `-45020` would clear once Output Size at `+0x0c` were set to 8, on the reasoning that the routing result needs somewhere to go. Measured: with the command recognised, `+0x0c` swept over 0, 1, 4, 8, 12, 16, 32, 64, 256 and 4096 with `+0x08` fixed at 16 returns `-45020` in every case, and so does a block holding only the version field. The input/output pair is the check already decoded at `0x66bfc` and it is passed; `-45020` is decided elsewhere, and the live publisher for it is the single site at `0x8f69d`. Two of my own readings are corrected here as well. The guest does not leave the image at `0xd731c`; what ended was the walker's ring window, and I attributed the walk's end to a host transition. And the block after a call on this path is the library's own scratch rather than the caller's argument block -- `scratch[0x0]` reads `0xfffffffe01000000` because the environment id and the version were written adjacently, not because the header was rewritten.
| 2026-09-20 | Recorded-defect fixes. Six contained fixes, none touching the SAP/store happy path: 200-after-resume now truncates the partial to 0 inside the HTTP layer before the fresh body streams (§ 5.9); the zip writer emits real ZIP64 structures (EOCD + locator, `0xFFFFFFFF` placeholders, regenerated extra blocks) instead of truncating sizes/counts (§ 5.9); `--limit`/`--max-results`/`--page` reject garbage and out-of-range with a usage error instead of a silent default or wrapping cast (§ 5.9); `--trace-file` redirects stderr to the file so shim/trap trace lines actually land there; the trap message no longer names the nonexistent `scaffold` subcommand (§ 5.8); `perun info` lists imports (DLL, named + ordinal, IAT fallback) and exports alongside headers and sections. The ambiguous `MZFinance.BadLogin` with empty failureType and no code in play stays a hard failure but now names the 2FA path (`--auth-code`) instead of implying wrong credentials — live fire showed the correct password drawing this shape, a code arriving, and password+code succeeding; the failure mapping lives in test-covered `classify_auth_failure`. Doc corpses corrected: no store-level `--mac` flag, bare-`sap` endpoint comment matches the compiled constants, the CD-tail `madvise(DONTNEED)` the comment promised now exists, the inflate header test no longer cites a live download. |
| 2026-09-22 | Gate re-verified from zero without trusting prior notes (stock `objdump` + live runs): the `cmpq` at `0x5b20f`, both trampolines, the 37-site count (both DLL builds), and the table/key mechanism confirmed byte-exact; a first ZF-forcing variant crashed mechanically (register clobber — corrected by the clean rerun in the next row). Calling convention corrected in place: `vdfut768ig` takes two pointers (`rcx` NULL-or-valid, `rdx` required struct with a `+0xc` write), no command-code register exists, the 0..255-uniformity claim is withdrawn; `cvu8io98wun` is the init half (`[+0]=0x2000000001`, `[+8]=0`, `rdx` ignored); the directory walk is stepwise with zero enumeration past `adi/`; registry silence verified against instrumented shims. |
| 2026-09-22 | Clean ZF-flip rerun at `0x5b20f` (`pushf` + mask + `popf`, all registers and flags intact): both ZF values return `0xffff5016` via different routes (ZF=0 skips the directory walk, ZF=1 walks it), so the exit is funneled, not decided, at this `cmp` — single-point flag flip is dead as a bypass. Corrects the dirty `xor ecx,ecx` variant (mechanical crash, not branch evidence) and notes the `eax`-as-state-counter hang plus ~225 table-base consultations scoping way 3. |
| 2026-09-22 | In-process chaining harness (`crates/perun-cli/examples/chain.rs`, 3 unit tests): init leaves 0 `.data` bytes changed, warmed op call still `0xffff5016`, op mutates ~218 bytes in 43 runs, cold control identical — init sequencing eliminated as the missing piece. |
| 2026-09-22 | fpdi transport emulator (`crates/perun-cli/examples/fpdi_emul.rs`, 6 unit tests, 16/16 self-checks byte-exact, live parity verified): GET→405, unknown→404, POST→500 Jersey HTML, non-JSON Content-Type→415, other methods→403. Bodies never discriminate; entity format must come from the caller. |
| 2026-09-22 | Live spim from GSA (`MidService/startMachineProvisioning`, ec=0, 347 bytes, no Apple ID needed for step one) + gateway split (GSA midStart/midFinish vs Windows fpdi, which rejects the same plist); (dsId, spim) by-value feeds never leave -45034 — the Windows arm wants pointers, next via the in-process harness. Machine-ID module (`perun-shims/machine_id.rs`, clean-room MD5, Blackwood modern/legacy pins, Linux collectors, 5 tests). |
| 2026-09-22 | In-process spim feed (`feed_spim`, child-per-case): envelope shape accepted for all ops (always -45018 invalidInputDataParamHeader — arithmetic correction, not -45026), flat/session arms confirm the union model; Ghidra table-xref blindness quantified (24/438). cvu-init chained into the envelope (BC) still -45018. repr(C) invocation (command@+0x10, cmds 0–10, both flags): always -45018, no writes. vovan2200 DataPacket/MainContext shapes return -45034 (flags gate first); DB hybrid (envelope sizes + packet) moves all first-words to -45018; op called twice: no accumulation. Split args (DP2/DP3) still -45034, DF dies. New codes -45041/-45035/-45028 mapped. |
| 2026-09-22 | Header validator decoded (4 byte-reads + OR-fold, INT3-live, exact-match gate) + flat/split-arg matrix: pointer-first confirmed. |
| 2026-09-22 | Header outcome gates on missing state (ZF/r9d/content all funnel): valid header unobtainable offline, proven. |
| 2026-09-22 | P-code struct-touch map: only 27+28 memrefs, listing ends ~0x66c1f (validator region has no Ghidra function at all). |
| 2026-09-22 | Caller architecture (CoreFP 8-call session cluster 0x1b5da30, 4-arg convention, R8/R9 sweep inert, zero direct callers). |
| 2026-09-22 | Status checkpoint: envelope accepted (outer -45034 passed); -45018 is header parse of *Arguments; first header read at RVA 0xb151d (MOVZX EBP,[RCX+RDX]); GSA gateway live (ec:0, 347-byte spim). |
| 2026-09-22 | `perun scaffold` implemented (ways-forward item 5 closed, SAP/store happy path untouched): the new perun-persona subcommand parses Win64 and SysV trap lines — including the hint's quoted `DLL!func(args)` payload pasted back verbatim — and emits a compiling `win32_api!` skeleton with the observed arguments and the owning source-file hint (§ 5.8 item amended in place, README command block extended); both trap reporters name the command again. Proven live: a synthetic PE32+ with one unresolved import fires a real TRAP, the hint feeds `scaffold`, and the emitted stub compiles inside `perun-shims`. |
| 2026-09-24 | IPA replication re-measured end to end. Verified live across 31 production packages up to 3.89 GB (PUBG Mobile) and 47,007 entries in a single archive (Tanks Blitz) with zero errors. 32.3 GB downloaded in total. The `ipa.rs` note was wrong twice: `3.14 GiB` should read 3.14 GB (2.92 GiB), and its "under tens of MiB" RSS claim does not hold — measured 1.0-1.1 GiB peak with wait4/ru_maxrss.
| 2026-09-24 | Multi-call session driver for the ADI lane (§ 5.8, § 6.7 row 20): `perun seq` loads one image and runs one `DllMain`, then drives a script of export calls in a single process (verbs `load` / `poke` / `call` / `zero` / `dump`); `perun call` gains `--load=NAME=FILE` for feeding a file as a named guest buffer, and `PERUN_SEQ=N` repeats one identical call in-process. Option values now resolve after the whole command line is parsed, so a `--load`-registered buffer name works as a `--poke` value in any order — at the cost of a malformed poke value being rejected only after parsing, and `--poke-ptr` writes applying in resolution order. The `call` output format follows: invocations print as `call#N <export>(…)` and the scratch page dumps per non-zero qword (`scratch[<offset>] = <value>`, or an explicit all-zero line) instead of a `scratch[0..64]` hexdump. Verified live against `CoreADI64.dll`; the SAP and store lanes are untouched. |
| 2026-09-24 | Formatting baseline. The whole workspace is formatted with `cargo fmt --all`, so `cargo fmt --all -- --check` exits 0. The formatting landed as its own commit and `.git-blame-ignore-revs` (repo root) lists it, so `git blame` attributes reformatted lines to the commit that last changed them logically instead of to the reformat. The file is honored by GitHub natively; a local clone needs one command once per clone: `git config blame.ignoreRevsFile .git-blame-ignore-revs`. |
| 2026-09-25 | **SAP peak RSS 57.9 → 9.2 MiB: `cache_complete` was reading every pinned asset whole.** It called `std::fs::read` on each of `CoreFP`, `CoreFP.icxs` and `CommerceKit` purely to compare `len()` and a SHA-256 — 35.8 MiB of transient heap, one 27.7 MiB buffer at a time. A `smaps` snapshot at the peak showed exactly that: two anonymous `rw-p` regions of 28 336 kB resident each, 55.4 MiB of the 58.1 MiB total anonymous, and **no guest mapping present at all** — the peak is reached during cache verification, before any image is mapped. `malloc_trim` could not help, because a high-water mark that has already been recorded does not come back down. Size now comes from `metadata()` and the digest is streamed through a 64 KiB buffer with `perun_core::sha256::Sha256`, so the buffers never exist. Warm peak 9 308–9 492 KiB over five runs, against 59 316 KiB before; the store lane already measured 9.7 MiB because a plain `download` never touches the SAP assets at all, so this is what puts the two lanes on the same figure. `streamed_digest_matches_the_pinned_one` pins the streamed hash to the same digests the whole-file path verified, so the optimisation cannot start accepting a corrupt cache. The `malloc_trim(0)` in `SapRuntime::new` is kept for the cold path and its comment no longer claims 20 MB: measured, 9.2 MiB with it and 9.2 MiB without. |
| 2026-09-25 | SAP peak RSS 27.1 → 9.5 MiB, and the rdtsc patch set cut to what a session reaches. An execution census (`archive/rdtsc-census`) showed CoreFP reaches **none** of its 6 269 rdtsc sites on any path that has been driven, so its table ships empty and its 10.5 MiB of resident `__TEXT` disappears; CommerceKit ships all 251. Separately, the image load was spending 198 of its 206 ms re-deriving a SHA-256 the fetcher had already verified, which is now passed in (images 206 → 8.9 ms), and `perun sap` went 402.6 → 231.7 ms. The 485-byte signature that appeared intermittently in a soak was the `IOIteratorNext` parity counter surviving across sessions; `reset_shim_state` per `SapRuntime` removed it (550/550). Full LTO plus one codegen unit took the binary from 4 139 648 to 3 289 328 bytes. |
| 2026-09-25 | IPA replicator no longer maps its input. It was mmap'ing the whole archive and leaning on `MADV_SEQUENTIAL`, which left peak RSS to the kernel: identical runs of one binary swung 532..1012 MiB on a 3.62 GiB package and climbed as the page cache warmed. `replicate()` now streams through a `File` — 66 KB tail read for the EOCD, one read for the central directory, 30 bytes per local header, entry bodies through a 512 KiB buffer. PUBG 3.62 GiB: 691 676 → 13 148 KiB; Tanks Blitz 2.92 GiB: 625 992 → 32 688 KiB (median, N=5). Output verified: 47 008 entries and CRC clean on Tanks Blitz, 1 079 entries / 14 sinfs / all executables 16 KiB aligned and CRC clean on a live Telegram download. |
| 2026-09-25 | IPA replicator correctness fixes from a 24-package synthetic fuzz corpus and 16 real packages, all four verified by mutation (each test re-broken and confirmed red). **F1:** `parse_central_at` read the record as `(time, date)` while `add_stored` and `finish` write `(date, time)`, so every *copied* entry landed its two halves in each other's field — the modification timestamp of every entry of every package was transposed. One-line reader fix, no writer change. **F3:** `replicate()` now writes to `<dst>.partial` and publishes by `rename`, so a failure anywhere in the copy loop can no longer leave a truncated package at the path the caller was promised a finished one at; the partial is removed on every failure path, including the `Ok(false)` no-bundle case. **F4:** the multi-disk check read `eocd[20..22]`, which is the *comment length*, so every archive carrying an EOCD comment was rejected as multi-disk; the disk numbers are at `eocd[4..8]` and the comment length is now only what it is. **F7:** the EOCD scan believed the last `PK\x05\x06` it saw, which a forgery in a comment or entry data can displace; a candidate is now believed only when the directory it names ends at or before the candidate itself. That made the absolute offsets inside a record a live hazard, so `find_eocd` takes the window's own offset (`find_eocd_at`) — the 66 KB tail of a 3 GB package starts three gigabytes in. Separately, the documented memory model is now empirical: `peak ≈ 2.8 MiB + 165 B × entries + 2.95 × cd_size`, measured over 40 packages, which replaces the previously implied guarantee of a flat ceiling — real packages stay ≤ 32 MiB, but the accepted input space reaches 70.2 MiB at 65 534 entries with 255-byte names. |
| 2026-09-25 | **25 crates out of the object form, and with them the whole ICU4X slice.** `cookie_store` existed for one reason: it is a cookie jar, and it was the only direct source of perun's `mz_at0` session. It also dragged `psl-types`, `publicsuffix`, `idna`, `idna_adapter` and fifteen ICU4X crates, all under the copyleft `Unicode-3.0` — linked into the binary so a cookie jar could decide whether `evilapple.com` is a parent of `apple.com`, a question that cannot arise when the only hosts are `*.apple.com` and `*.itunes.apple.com`. The removal is one manifest line: ureq enables `url` only from its `cookies` feature, so dropping that feature drops `cookie_store`, `url`, `idna` and the corpus behind it. `store::cookie_jar` replaces it in about 200 lines of `std` — the same curl-format file, `Set-Cookie` folding, RFC 6265 path matching, and a per-hop `Cookie` header recomputed so a suffix cookie does not follow the IPA download's 302 onto Apple's CDN. Object form: 71 crates → 36, and no `Unicode-3.0` obligation is left in it. `unicode-ident` keeps that licence build-time only, which it always was. Verified live: the 16-cookie session survives a load/save round trip with identical fields, and `list-purchases` returns all 41 purchases over DAAP, which is the endpoint that 401s first when cookies are lost. Note that Cargo.lock still *lists* the removed crates as optional dependencies no enabled feature requests — that is the resolver's bookkeeping, not the build graph, so the licence generator reads the build graph (`cargo tree`) rather than the resolve graph, which is a superset. |
| 2026-09-25 | **F8** in `strip_zip64_extra`, and the `memmap2` dependency removed. On an extra whose last field declares a size running past the end of the buffer, the truncated branch appended the tail and `break`, and the trailing `if i < extra.len()` then appended the same bytes again — a 9-byte extra came back as 18, silently, on both the local and the central path, and near the `u16` ceiling the doubling crossed the length limit and refused the entry as "local extra too long", naming a size constraint instead of the malformed field. The branch now returns. Pinned by `truncated_extra_tail` and by `strip_zip64_extra_never_grows`, which asserts the general property (output no longer than input, and every surviving byte present in the input in order) over 2 000 pseudo-random extras; both mutation-checked. `memmap2` was declared but never used — it has not been linked into the binary since the replicator stopped mapping its input — so it is out of `Cargo.toml`, out of `Cargo.lock` (nothing pulls it transitively), out of NOTICE, and out of both third-party crate tables. It is removed, not re-attributed: the NOTICE line described a mapping that the streaming rewrite had already deleted, and leaving it would have been a false statement about the distributed object rather than a stale one. |
| 2026-09-27 | **Anisette v3 generated locally, on x86_64 Linux, no Wine and no remote re-signing server (§ 5.8a).** Headers are produced against the real Apple endpoints: `GsService2/lookup` and `MidService/{start,finish}MachineProvisioning` all HTTP 200, Apple answers `<key>ec</key><integer>0</integer>` with `ed`/`em` empty, and `ADIGetLoginCode` is 0 afterwards — reproduced 3/3, `X-Apple-I-MD-M` stable and `X-Apple-I-MD` rotating per token pair. Artefact `43f16eb` on `rnd/phase1-standalone-anisette`. **The engine is the Android `libstoreservicescore.so`, not the PE in § 5.8, and it must be an x86_64 build. The engine source is Apple's own APK (`apps.mzstatic.com/.../applemusic.apk`, Apple Music 4.9.6, versionCode 1447), a universal release whose `lib/x86_64/` carries all eleven classic ADI exports and the same three `libCoreADI.so` symbols. An earlier mirror kit (3.9.0-beta) is no longer used. The 4.x line is not arm-only — 4.9.6 ships x86_64 as well, and it is fetched by HTTP range at run time, never vendored.
| 2026-09-28 | **The `invalidParams2` comparison is a field-to-field bounds check on the object, and the object is not the one at `0x19db98` (2026-09-28).** Walking the `-45002` path with both gates open runs 79 970 guest instructions and ends in the block at RVA `0xd6560`, which reads four fields of a structure through `r11` — `obj[+0x08]` into `rcx`, `obj[+0x10]` into `rdi`, `obj[+0x18]` into `edx`, `obj[+0x2c]` into `ebp` — and then compares `obj[+0x08]` against `obj[+0x10]` with `setne`, and a second pair with `setae`, folding the two into `rax`. That is a bounds and consistency test on an object, the same shape as the `unknownAdiCallFlags` check but one level down. What is new is that the object is not reached through the `0x19db98` slot: populating that slot's target, its `+0x08`, `+0x10`, `+0x18` and `+0x2c` in every combination leaves the return at `-45002`, so `r11` is loaded from a register that the flattened path derived rather than from the slot. The pointer the comparison needs is therefore produced inside the body, and the object it describes is whatever the library builds for itself on the way. That is why seeding four fields of a caller-supplied object does nothing: the value being validated is not the caller's. **The practical consequence is that `-45002` is a self-consistency check on library-internal state, not a missing argument**, and no input the caller controls reaches it. Static analysis agrees it is unreadable from outside: the `.data` globals in this image are addressed only through the obfuscation table, so neither `objdump` nor Ghidra's decompilation resolves them — Ghidra's own output warns it could not recover the jump table ("Could not recover jumptable ... Too many branches") and renders the body as a bare indirect call. |
| 2026-09-28 | **The walker's ring window was showing the oldest entries, not the newest (2026-09-28).** Two rounds of conclusions this project drew about a walk were drawn from a report that printed a window starting at the oldest stored entry rather than the one ending at the last, so the tail of every walk was missing and what was printed had already scrolled out of the ring by the time the run finished. With `n = STEP_IDX` and `slot = (idx + k)`, adding `k` to an index that already points past the newest entry walks forward into slots the ring never wrote. Fixed to end at `STEP_IDX - 1` and start at `STEP_IDX - count`, verified against a walk of 80 218 steps. Two consequences: the window is now the true tail, and in the `-45002` walk the final guest instructions end well before the call returns — the last 128 steps are host code in the epilogue, so the block at RVA `0xd6560` where the comparison happens is not adjacent to the return. This does not change the finding itself, which stands on the walk reaching that block and on the field-to-field comparison decoded there, but it does mean any earlier reading of "the last N steps" from this tool was a reading of the wrong window. |
| 2026-09-28 | **`iTunes.exe` and `CoreFP.dll` are the Windows callers, and CoreFP runs under the same runtime (2026-09-28).** Both `iTunes.exe` (38 MB) and `CoreFP.dll` (33 MB) contain the strings `vdfut768ig` and `cvu8io98wun`; so do the two ADI libraries themselves, which is the export table. `iTunes.exe` is the application, but the more useful caller is **`CoreFP.dll`**: its image base is `0x7c801000`, the same layout this project's runtime already maps and whose `vdfut768ig` path has been walked all along, and it is the module that owns the FairPlay signing path Anisette feeds. A caller that already runs under perun-shims, with no Bionic and no QEMU, is the shortest possible route to the real invocation shape. What could not be done in this round: Ghidra's headless analysis of a 38 MB binary does not finish inside the time budget here, and a static reference search for the string in `iTunes.exe` finds **no** `lea` and no pointer-table entry reaching it — the bytes immediately before the string are a high-entropy run, so that name is obfuscated in the application even though it is plain in the DLLs. The search therefore has to be done on the module where the name is not obfuscated, or inside the decompiler once a smaller module is the target. The interpretation offered for the `0xd6560` check -- `obj[+0x08]` and `obj[+0x10]` being an MSVC vector's `begin` and `end`, so the test is "are the provisioning keys non-empty" -- is consistent with the measurement and with the `-45002` position in the sequence, but it is an interpretation, not something decoded here: nothing in this project has shown what fills that vector. || 2026-09-28 | **The body consults exactly two globals, measured by sealing `.data` and unprotecting on each fault (`PERUN_SEAL_DATA`) (2026-09-28).** The walker could not say what the flattened body reads, only which instruction it was on, so a different instrument was built: mark the image's `.data` pages `PROT_NONE` before the call, let the first read of a global fault, report the address, unprotect that one page, and continue. Each fault names a global in the order the body consults it, with no decoding and no `ptrace`. Over the whole call on the `-45002` path there are exactly two reads: RVA `0x19dda0`, the state pointer, and RVA `0x19e9c8`, which holds a repeating arithmetic sequence and is the second-level indirection table, matching the double-dereference this file already recorded with its `0x4f7e9322` key. **That is the complete set of global inputs to the rejection.** Nothing else in `.data` is consulted, so the `-45002` decision is a function of those two values alone, and the second is an obfuscation artefact rather than state — the first is the object the call allocates and zeroes. This also confirms that the global sweep earlier in this file, which found `0x19db98` and `0x19d088`, was a real sweep: those two slots live in the same region the body actually reads. Building the instrument took two corrections, both recorded in the tooling: the handler must not rewrite `RIP` to the faulting address, since the instruction has not executed and returning re-runs it and faults again, and the ring window must end at the last store rather than start at the oldest. || 2026-09-28 | **`0xcfe0b46a`, not `0x3e58e7f9`, is the operation that returns success, and the priority was backwards (2026-09-28).** The eight-call Android dump this project captured is ordered, and the `=== SUCCESS ===` banner follows call 6, whose opcode is `0xcfe0b46a` with a 48-byte payload; calls 7 and 8 are `0x3e58e7f9` and run *after* the success, so they cannot be the operation being driven. Nearly all of this campaign's effort went into `0x3e58e7f9`. The frame is also read differently than assumed: `frame[+0x00]` is a **pointer to the payload**, `frame[+0x08]` is its length `0x30`, and the 48 bytes themselves live at the address that pointer holds, which the dumper never printed -- it dumped the envelope and called that the arguments. The call-6 envelope decodes as `+0x00` payload pointer, `+0x08` 48, `+0x0c` 4, `+0x18` 0x226564, `+0x20` 1, and three library-internal pointers. Replaying that whole shape on the Windows lane changes nothing: `0xcfe0b46a` and `0x3e58e7f9` both return `-45002` with the flags gate passed, the `0x19db98` gate passed, and the full envelope populated. So the correct opcode was the wrong lead, and `frame[+0x00]` is a payload pointer rather than an output buffer -- which also retires the output-buffer reading of the brief's layout. Both statements are recorded because the previous revision leaned on the opposite of each. |
| 2026-09-28 | **The Windows gate re-measured, and the shared-convention claim refuted (2026-09-28).** The Android `vdfut768ig` convention does **not** transfer to `CoreADI64.dll`, and the difference is not a register-order detail. Direct measurement on the shipped binary: the DLL's own init export `cvu8io98wun` returns 0, `vdfut768ig` in the same process then returns `0xffff5016` = **-45034**, and the check that produces it is `cmp qword ptr [rcx - 0x4f7e9322], 0` — a pure memory test evaluated before any file I/O, so no input reaches it. The object it tests is the 0x28-byte `HeapAlloc` behind the global at RVA `0x19dda0`, and that object is reallocated on every call, which is why writing it between calls changes nothing: seeding its first qword at allocation is overwritten by the guest before the gate runs. Placing the real `adi.pb` from the Android lane under `<CommonAppData>\Apple Computer\iTunes\adi` produces zero `CreateFile`/`ReadFile` calls, so the gate is not a file-presence test. **The decisive point: `rcx` is a pointer in the Windows build, not an opcode.** Passing `0x3e58e7f9` in `rcx` *crashes* by dereferencing it, while the opcodes above `2^31` are masked and all return -45034 unchanged — the opposite of a command dispatch. A `poke-ptr` verb was added to `perun seq` for this work: `call --poke-ptr` applies every write before the call loop, which cannot reach state the guest allocates during the call, and the gate object is exactly that. |
| 2026-09-28 | **§4.1 guest-heap arena: 64 MiB, not 1 GiB.** The previous row of this changelog reported the arena as 1 GiB ending at `0x7FF7_F000_0000`. That was wrong and had never been true: `HEAP_SIZE` in `crates/perun-shims/src/mach.rs` is `0x400_0000` and has read that way since the first implementation, so the arena is `[0x7FF7_B000_0000, 0x7FF7_B400_0000)`. The 1 GiB figure is the PE lane's `region_name` labelling range in `stub.rs`, a trap-report string rather than a mapping, and it was carried into the Mach-O section. Both the address table and invariant 2 are restored to the code. | **Uniformity of the gate behind it, measured the same way.** With the frame laid down, every input value tried — the real 347-byte spim prefix, all-ones, a byte ramp, the Android envelope words `5`/`0x10`/`4`, and a plain `0x02000000` — returns `0xffff5026` = `-45018` with no divergence. (An earlier pass of that sweep reported three patterns as differing; that was a defect in the harness, which matched the substring `core` inside `CoreADI64.dll` and announced a trap that never happened. The uniformity is the real result.) The two gates are therefore distinct: `-45034` is a caller-argument check that any well-formed frame satisfies, and `-45018` is a header validator that nothing tried satisfies. The wall is unchanged; what changed is that it is now reached for the first time and shown to be the only thing standing between here and the dispatcher. **The gdb route is closed by the sandbox, not by the project.** Installing GNU gdb 16.3 into a private prefix and running it against the shipped binary works up to the point of attaching: `ptrace` is denied, so gdb reports "Could not trace the inferior process", and the container also refuses hardware breakpoints ("No hardware breakpoint support in the target"). A software breakpoint is no better, because it needs the same ptrace. Any future plan to walk the flattened dispatcher instruction by instruction must either bring its own tracer (a `ptrace`-based in-process recorder in Rust, which needs no gdb) or accept the int3-probe coverage already used here, which is enough to prove which sites execute but not to read the state behind them. The installed prefix was removed again so the tree does not carry a tool that is present and unusable. **Ghidra on the same two sites, which is the strongest negative result here.** Ghidra 12.1.4 was brought up (it is unpacked on this host; it needs a JRE, and one installs into a private prefix from the Debian archive with no root). It decompiles the *entry* of `vdfut768ig` cleanly and independently confirms the dynamic findings: `param_1` is consumed arithmetically, `param_2` is dereferenced at `+0xc`, and a null `param_2` returns `0xffff5036`. It cannot read the gate itself. Both gate regions decompile to a bare `(*(code *)(param_1 + in_RAX))(...)` with the diagnostic **"Could not recover jumptable ... Too many branches"**, because the flattening indirects through a computed table that the decompiler will not reconstruct. That is the same wall the earlier P-code work hit, now confirmed on a different tool: a static decompiler cannot follow this control flow, and `ptrace` is refused by the sandbox, so neither static decompilation nor dynamic single-stepping is available for the body. The `int3` probe remains the only instrument that reaches these sites, and it proves execution without reading the state behind it. The tools are all in place and the block is real. **The `-45018` site only publishes the decision; it does not make it.** With `PERUN_TRAP_REGS=1` the signal handler now reports the full register file and the top of stack at an int3, which is the one instrument that reaches these sites. At the live `-45018` site (RVA `0xb5b4a`) the state is `rcx=0x7c85b0b1`, `rdx=0x6bd`, `r8=4`, `r9=0x4069d332`. `rcx` is the address `0x5b0b1`, and the bytes there are the function epilogue (`mov %edi,%eax` followed by six `movaps` restores of the callee-saved xmm registers); the block above it at `0x5b0a9` loads `edi` with `0xffff5036` and dispatches. So the guest is already on its way out when the trap fires, and `r9=0x4069d332` is the CFF state token this project's earlier work named. The consequence for the search is concrete: the branch that chooses `-45018` is upstream of `0xb5b4a`, and every probe aimed at that address was aimed at the messenger. **Uniformity explained.** The frame sweep could not move the result because the decision is taken before the frame is consulted in any way this project can influence from outside. **The flattened body is walkable, and an earlier claim that it was not was wrong.** A previous revision of this row said the x86 trap flag could not be used, and put the blame on the kernel: that Linux clears TF from the context restored into a signal handler. That is not what was happening, and the claim was a rationalisation of a bug in the code that was testing it. The priming handler was written as `eflags & !TF`, which removes the bit, when its only job was to install it; the trace stayed at zero and the zero was explained as kernel behaviour. **With the bit set it works.** `PERUN_STEPS=N` single-steps the call from inside the process: TF is installed once, the handler logs RIP, flags, rax and rdi and leaves TF set, and the walk is self-sustaining. Measured: the walk begins exactly at the export entry `0x5afc0`, visits 1 292 distinct basic blocks within 60 000 instructions, and reaches the live `-45034` gate at `0x66c2d` after 109 066 instructions in 1.3 s. So the whole of this analysis rested on an assumption about the kernel that was never true, and the assumption was made by the same process that had the bug in front of it. `PERUN_STEP_UNTIL=<rva>` stops the walk at an address of interest, which is what makes a body this size affordable at roughly ten thousand instructions a second. **This changes what is possible here, not only what is known:** the branch that selects the return code is reachable, and the next step is a walk to it. **How far the walk actually gets, measured.** It starts exactly at the export entry `0x5afc0` and reaches the live `-45034` gate at `0x66c2d` after 109 066 instructions in 1.3 s, so the flattened prologue is fully traversable. The `-45018` site at `0xb5b4a` is not reached within 3.9 million instructions in 400 s, and the bottleneck is the trap itself: single-stepping costs roughly ten thousand instructions a second, and a call that returns `-45018` visits far more of the body than the gate does. That is a throughput limit, not a reachability one -- an unfiltered run completes and returns `0xffff5026`, so the site is executed by the real call, the walk just does not arrive inside the budget. The next thing that would help is a cheaper instrument than a trap per instruction: an int3 planted on the *edges* of the flattened blocks would sample the path rather than trace it, and the block starts are recoverable statically even though the jump table is not. **The CFF jump table is readable, and inverting it finds the predecessors.** The flattened dispatch is `lea table; movslq (table,index,4); lea this_block; add; jmp *reg`, so a target is `block_base + table[index]` and the table at RVA `0x15fc90` is plain signed 32-bit data. Inverting it over every `lea` base in the function yields exactly **three** dispatch sites that can reach the `-45018` site at `0xb5b4a`: `0xb2e6f`, `0xb472d`, `0xb55a0`. Planting an int3 at each shows **none of them executes**. So the `-45018` site is not reached through that table from those bases, which means the edge into it is built some other way -- a second table, or a register moved across blocks, as the chain at the site itself does (`lea 0xaa17d(%rip),%r11` then `mov %r11,%rcx` in one place, and the register arriving pre-loaded in another). The cost of a static inversion is under a second against a walk that needs minutes, and it is the method to extend: the same inversion over every table in the image maps the flattened graph completely. **The decision is reached, and the path to it is now known.** The throughput problem was the handler, not the guest: it did a `write(2)` and a `format!` per instruction, and it kept TF set while the guest was inside a host shim, so one `HeapAlloc` cost tens of thousands of traps. With the handler reduced to two ring stores and the stop taken on a *register* rather than an address, the walk is cheap: **109 458 guest instructions in 1.2 s**, against 3.9 million in 400 s before. `edi == 0xffff5026` is the trigger, so the walk stops wherever the flattened body arrives at the code it is about to publish, independent of where this build stores it. **Stopping on the register is what made the address unnecessary**; the earlier difficulty was largely an artifact of trying to hit a fixed address by walking toward it. The last 256 instructions are the answer: the final edge is `0x7c866d8f -> 0x7c8b5b2b`, and immediately before it `0x7c866d5e: cmp $0x4069d333,%edx`. So `edx` is a selector compared for equality against a family of `0x4069d3xx` tokens -- a command chain, and a different one from the brief's opcodes. Two ways of resuming the walk into host code were tried and are both wrong: clearing TF for a shim means the shim never traps again, and planting an int3 on the shim's return address corrupts the guest, because that byte can be the second byte of an instruction and a return address can be re-entered. Leaving TF on and simply not recording the instructions that are not ours is what works.   **The size gate is on the caller's frame after all — the previous two rows on this are both wrong, and the measurement that settles it is a capacity threshold.** The size check at `0x66bfc` compares one frame field against another plus four. With the cursor field left at zero, sweeping the capacity gives a clean threshold: **capacity 1 and 2 return `-45034`; capacity 4 and above return `-45018`.** Four is exactly `cursor + 4`, so the fields being compared are the caller's own. The buffer pointer at `+0x00` must be readable or the call faults writing through it, and the *contents* of that buffer are irrelevant: zeroed, a byte ramp, and all-ones are indistinguishable. The cursor field at `+0x0c` does not affect the outcome at all. **So, superseding the two rows before it.** The `rbx` register at the stop, `0x74dd4cf41000`, is not the `ctx` that was passed, and that was taken to mean the check reads the library's own object. It does not: the library copies the caller's frame to a heap buffer and reads the copy, which is why the register differs while the semantics are the caller's. An earlier row in this series attributed the uniformity to the frame being consulted in a way this project could not reach, and then corrected itself in the other direction; both were inferences, and the threshold is the measurement that replaces them. What survives is the part that was always right: past the size gate the walk is byte-identical for every frame, the selector `edx = 0x6bb` is computed internally, and **no capacity, cursor, pointer or buffer content supplied by the caller changes the `-45018` result.** The brief's model, an opcode in a register with a frame in the next, still does not describe this entry point. **Correction to the claim of a byte-identical walk, and the full-order trace.** Two rows in this series assert that different frames produce identical walks. They do not. The ring was enlarged to hold the whole traversal -- 109 210 guest instructions in 1.4 s, printed in order -- and the step count *depends on the capacity field*: capacity 4 gives 109 458 steps, 0x10 gives 106 936, 0x100 gives 109 210. The earlier comparison used two values and treated the difference as noise. It was not noise, and the claim was wrong. What is uniform is the *outcome*: **fourteen capacities from 4 to 1 MiB, every combination of cursor, pointer and buffer content tried, and the init export called first or not, all return `-45018`.** The frame changes the path the library walks and does not change what it concludes. The full-order trace also locates where the selector is born: `edx` holds `0xa8d` and is reduced to `0x0a8a` by the `sub`/`add` pair at `0x66c11`/`0x66c13`, from which the `imul` at `0x66cf7` produces `0x4069d332` for the equality chain to consume. So the chain is not entered by the caller and is not adjustable by one; the caller's frame selects among paths *inside* the flattened body, and every path available to it ends in the same answer. **This is the honest state: the input space reachable from the outside has been swept and it is a single point.** **The whole traversal, and what it rules out.** Letting the walk run to the budget rather than stopping at the error gives the complete picture: **80 055 guest instructions**, then the function returns, and the output buffer is never written to. The `-45018` decision is taken at instruction about 59 000, and the remaining 21 000 instructions are 1 536 distinct blocks, **all of them in `.text`** -- rollback and cleanup, with no access to `.data` and no write to the caller's buffer. So the library does not decline to produce a token because it ran out of work: it decides early, then unwinds. The only state it consults on the way is its own, and the only state the caller supplies is the frame, which has been swept. **That closes the search over inputs.** The remaining requirement is not a better frame, a different argument, or a fuller call sequence -- all three are swept and all three converge on `-45018`. It is prior state: something the library must already hold before this entry point is entered, laid down by a code path this walk never reaches because the gate turns it away first. Finding it means finding what would have run *before* step 59 000 on a provisioned host, and this entry point will not show it. The Android lane reaches the same state through real Bionic libc underneath it; reproducing that here is the remaining work, and it is a different problem from the one this walk was solving.   **The header is a 4-byte field, and the published `AdiOtpPacket` layout is refuted by measurement.** An earlier row in this series called the switch a single byte at offset 3. That was a per-bit sweep of one little-endian word and it was not the whole field: the surrounding bytes matter too. Sweeping the packet a byte at a time finds **exactly one** offset in 48 that changes anything, and sweeping that byte over all 256 values gives **1 or 2 and nothing else**. Bytes 0..2 must be zero: with byte 0 set to 1, 0x12 or 0xff and byte 3 at 1, the call is back to `-45018`. So the packet begins with a **4-byte big-endian value equal to 1 or 2**, and the remainder of the buffer is irrelevant. **This corrects the brief.** Its `AdiOtpPacket` has `version: u64` at `+0x00` with the value 1. Read as a little-endian u64 that puts a 1 at byte 0 and a zero at byte 3, which is the configuration that returns `-45018`; only the big-endian reading of a 32-bit field puts the 1 at byte 3, and then the field is not a u64 and not a version. The rest of the published layout was tested against the measured header and does not advance anything: `+0x08` over six values including `-1`, and `+0x10` over three including real buffer addresses, all give `-45025`. The published layout may be right for the Android build, which is a different library; it is not what this one parses. **What is now known about the input is a 4-byte field, its two accepted values, and that no other byte of a 48-byte packet changes the outcome.** `-45025` is still not a token: the function dispatch is entered and the selector it dispatches on has not been found, and the walk cannot yet be aimed at that path.
| 2026-09-28 | **The published Anisette sources, reviewed, and what they do and do not settle (2026-09-28).** `Blackwood-4NT` and the 4PDA thread were read in full against the measurements in the rows above. **What they support.** The common `ADI` header — arguments pointer, input size, output size, flags — is the shape this project found independently: the size check at RVA `0x66bfc` is exactly `input_size >= output_size + 4` on the caller's block. The six exports, the `cvu8io98wun` (version and protocol) / `vdfut768ig` (worker) split, and the environment table (`IdMS` `-2` production, `IdMS1` `-3` UAT, `IdMS2` `-4` QA, `IdMS3` `-5` QA2) all match what is here. The source places a per-operation magic in the first argument, *ECX*, and describes the worker as `__fastcall` on x86 with `ECX:EDX` as inputs and the regular x64 ABI otherwise; that is consistent with the measured behaviour, where the first argument is consumed arithmetically and any small value in it faults. **What they do not settle.** `Blackwood-4NT` says `CoreADI` is heavily obfuscated with FairPlay DRM and that, because the protected material is commercially sensitive, *"no additional details on how FairPlay can be bypassed will be explained here"*. So the per-operation magics are named only for two non-provisioning calls (`0x632b8d6e` for `ADIGetIDMSRouting`, `0x85fe63b0` for `ADISetIDMSRouting`); the provisioning magics are not given, and neither source documents the 4-byte field measured in the previous row. That field is a property of the *arguments block*, is one of two values, and is not either named magic — so "the magic in ECX" and the measured argument-block field are two different things. Passing the documented magics as the first argument faults, which is what the entry does with every small value, and `0x632b8d6e` is above `2^31` so the entry masks it before use. **The packet layout supplied for this phase is refuted by measurement on this build.** It specifies `version: u64 = 1` at `+0x00`, which the library rejects: the first dword must have bytes 0..2 zero and byte 3 equal to 1 or 2, and `1` as a little-endian `u64` cannot satisfy that. The same layout's `dsid` and buffer pointers are irrelevant here — sweeping `+0x08` and `+0x10` over 9 and 3 values changes nothing once the 4-byte field is right. The sources are worth having in the tree for the structure they do confirm; they are not a specification of this entry point, and the field that gates it is in neither.
| 2026-09-28 | **The command selector is the first argument, matched exactly, so five of the reported magics are recognised (2026-09-28).** The brief for this phase and `Blackwood-4NT` both place a per-operation magic in the first argument (`ECX` on x86, `RCX` on x64) and describe the worker as `__fastcall` with `ECX:EDX` as inputs. A row in this file had read that as wrong, on the grounds that the first argument is consumed arithmetically and a small value in it faults. **The observation was right and the reading was wrong.** Those two facts are consistent with a magic: the entry computes `lea eax,[rcx+rcx]`, masks, and *indexes*, so a value below `2^31` is not a valid command and faults, while a value above it is preserved and compared. Testing settles it. With the version-1 header in the arguments block -- four bytes `00 00 00 01` -- the return code depends **entirely** on the first argument, and it is an exact-value match, not a mask: `0x632b8d6c`, `0x632b8d6d`, `0x632b8d6f` and `0x632b8d70` all return `0xffff5025`, while `0x632b8d6e` alone returns `0xffff5024`. Of the reported values, `0x632b8d6e` (`ADIGetIDMSRouting`), `0x85fe63b0` (`ADISetIDMSRouting`), `0x3e58e7f9`, `0xcfe0b46a` and `0xb0eda7af` give `-45020`; `0xc774d292`, `0xb23c691e` and the `0x4069d3xx` tokens give `-45019`; 24 uniformly random 32-bit values all give `-45019`. So the dispatcher recognises a small closed set of commands and answers `-45020` for them, which is a *further* stage than `-45019` (`unknownAdiFunction`): the command is accepted and the call then fails on its arguments. Both codes are new to this project -- the error table had `-45019` and `-45018` and nothing below. **The four-byte field and the first argument are two different things**, which is why sweeping the arguments block alone never moved the result past `-45025`: the version field is necessary to reach the dispatcher, and the command lives in the register. On a confound that cost a run: an earlier part of this work left a real `adi.pb` under the virtual `CommonAppData` tree, and its presence suppressed the `-45019` / `-45020` split entirely, so every sweep after it read `-45018`. The directory was removed and the split reproduced. Any future sweep of this entry point must start from a clean virtual appdata.
| 2026-09-28 | **The `-45020` body check does not read the argument block, and its publishing site is located (2026-09-28).** `-45020` (`invalidInputDataParamBody`) is in the canonical `ADIError` enum, so the code the dispatcher now reaches is a real one and not an artefact. Hypothesis tested and refuted: that the body validator wants an *Environment* field, the signed value `-2` (production), `-3` (UAT), `-4` or `-5` (QA) that `Blackwood-4NT` documents, placed immediately after the version header. Both byte orders were tried at `+0x04`, and every signed value was then swept at every qword from `+0x08` to `+0x38`: all 60 byte positions set to `0xff` one at a time, and `0, +1, +2, -2, -3, -4, -5` at each of seven qwords. **Every one of them returns `-45020` unchanged.** So the check does not read the argument block as a caller lays it out, and the documented Environment field is not where this build looks for it. The `-45020` publisher is nonetheless pinned: of the fourteen `mov $0xffff5024,%edi` sites in the function, an `int3` probe over the `call` harness — which does honour `--patch`, unlike `seq` — shows exactly one executes, RVA `0x8f69d`, and the bytes there are `bf 24 50 ff ff ff`, the same instruction. So the check is a branch immediately upstream of `0x8f69d`, in the same `cmp $imm32,%edi` chain the CFF uses, and the predicate it evaluates is not over the argument block. That is the next thing to read, and the walk is the tool for it: the harness now used cannot pass a magic in the first register, which is the one thing this path needs, so the harness has to grow before the walk can follow it.
| 2026-09-28 | **On the `-45020` path the library writes into the caller's block, and that write is the first observable output (2026-09-28).** The harness gap that blocked the walk is closed: `perun call` takes the command as a literal first argument and a literal or `scratch` / `ctx` second, and the `call` path — not `seq`, which silently ignores `--patch` — carries both `--poke` and `--patch`. With `rcx = 0x632b8d6e`, `rdx` = the frame, `ctx[0]` = a buffer whose first dword is `00 00 00 01`, the call **returns `0xffff5024`** and then faults in host code afterwards, on the magic value as an address. Three things follow. **The command is read from `rcx` and the argument block from `rdx`, which is the published shape**, and the earlier reading that a magic in the first register was refuted was wrong. **The fault is after the return**, not during the call: the return value is printed first, the library then walks its epilogue and touches a pointer it left behind, and `addr` equals the magic that was passed in. That is a defect in the runtime's call path on this branch, and it is why the walk could not follow the path. **And the library writes into the caller's argument block**: `scratch[0]` reads `0x01000000` afterwards, where the version header `00 00 00 01` was before, so the first dword was replaced. A recognised command therefore mutates the caller's buffer before the body check completes, which is why the body sweeps could not distinguish a well-formed argument from a malformed one: the body is validated against a block the library has already rewritten. That also means `-45020` is reported on a partially consumed block, and the correct shape of the request is whatever the library leaves in the block on the success path, not what a caller writes into it beforehand. Establishing that needs the post-return fault fixed, since it truncates the run.
| 2026-09-28 | **A harness defect fixed: `perun call` read through a literal argument, and two of this file's claims were wrong about it (2026-09-28).** Passing a command selector such as `0x632b8d6e` as the first argument made `perun call` fault *after* the guest had already returned, with `addr` equal to the selector. The post-call dump probed the argument for readability and then read it anyway: the probe is a `write(2)` to `/dev/null`, which returns `EFAULT` for a bad range rather than faulting, so it was never a guarantee, and the `from_raw_parts` that followed was unguarded. The dump is now restricted to the ranges `call` actually handed out — the scratch page, the context region, and the image — and anything else is reported as a literal. With that, the `-45020` call completes: `rc 0`, no fault. **Two claims in the previous row are withdrawn.** The library does *not* write into the caller's argument block: the header bytes `00 00 00 01` are what a little-endian `qword` read of that address displays as `0x01000000`, and the harness printed it in that form, so the apparent rewrite was a misreading of a correct value. And the fault was never inside the guest — the return value is printed before the fault line, and both are host-side. **The walk now runs the `-45020` path**, which it could not before: with the crash fixed it traces 83 927 guest instructions before the library leaves the image, at RVA `0xd731c`, through `jmp *%rdx` after `cmp $0x102` / `cmp $0x103` — Win32 error codes, and a dispatch through the import table. The walker does not follow the call, so the trace ends there. That is the next thing to read: the `-45020` decision is somewhere in those 83 927 steps, and the ring holds all of them, so it can be located the way the `-45034` publisher was.
| 2026-09-28 | **The `-45020` path's last guest block, and what the walk now records (2026-09-28).** The walk records `rip` and the low half of `edx`; `rdx` is added to the ring because the flattened dispatcher ends every import call with `movslq (%r10,%rcx,4),%rdx ; add %r12,%rdx ; jmp *%rdx`, so `rdx` at the step before the jump *is* the import address, and recording it names the API without needing the import table read. The `0xd731c` block that the previous row ended on decodes as: a carried value in `rdx` is range-checked against `0x102` and `0x103` (`cmp $0x102,%rdx ; seta %sil` and `cmp $0x103,%rdx ; setb %dil`), the two boolean results are folded into the next selector, the carried value is spilled to `0x15c(%rsp)`, and the block tail-jumps through `(%r10 + rcx*4) + r12`. **So `0x102` and `0x103` are not Win32 error codes and not return values** — they are bounds on a value the CFF carries between blocks, and nothing about them is a timeout or an enumeration error. That was worth separating: reading them as `WAIT_TIMEOUT` and `ERROR_NO_MORE_ITEMS` fits the constants and explains nothing, because the guest has not called anything at that point — the jump is what *makes* the call, from the block after the comparisons. With `rdx` in the ring the tail of the path is visible: the last guest blocks sit at RVA `0xe4c1b`..`0xe4c60` with `edx` stepping `0x14e39c01 -> 0x1a1 -> 0x0 -> 0xdace`, and the `rdx` values along it are the CFF's own state tokens (`0x32f88e9214e39c01`, `0x01fed4c698c3ba3a`), not host addresses. The guest is not sitting on a shim slot at the moment it leaves, so the import it is about to call is not yet determined by the ring — `r10` and `r12`, the table base, are set at entry and never change, and neither is recorded. That is the next field the walk needs.
| 2026-09-28 | **The `-45020` publisher is not any `mov` site, and one of my own negative results was an unvalidated tool failure (2026-09-28).** Fourteen `mov $0xffff5024,%edi` sites exist in the body and every one of them was probed with an int3 on the recognised-command path. None traps. The control site does trap at the same time, so the negative is real and not a mechanism failure: **the return code is computed, not loaded.** The same shape as the `-45034` case, where the live producer was a `sub`/`add` pair rather than any of the thirty-seven `mov $0xffff5016` sites. **A previous row's claim that a single `-45020` site was live is withdrawn.** It was measured with `--patch=6602d` — a bare hex string — which `parse_num` rejects; the run exited 2 before doing anything and the sweep read that as "no publisher". With the `0x` prefix the control traps as expected. Every such probe in this project needs a control before its negative is believed, and the lesson is the one the file already states: a negative from an instrument is evidence about the instrument until the instrument is shown to work on a case that must fire. Two harness facts also fell out. `perun call` needs `0x` on `--patch`; and the walker's ring report is emitted only from the handler's stop path, so a run where the guest returns before the budget prints nothing at all, which reads as "the ring is empty" when the ring is in fact full. The call on this path completes at roughly 110 000 steps, between a 105 000-step budget that fills the ring and a 120 000-step budget that reports nothing.
| 2026-09-28 | **The published OtpPayload layout is inert past the first word, on both recognised commands (2026-09-28).** A brief supplied an `OtpPayload` for the OTP command `0x3e58e7f9`: `version_be` as a `u64` whose byte 3 is 1, `dsid` as -1, then `ptr_mdm`, `size_mdm_ptr`, `ptr_md` and `size_md_ptr` as real pointers, with the envelope carrying an input size of 48 and an output size of 16. Built exactly and run: `-45020` (invalidInputDataParamBody), and the payload is byte-for-byte unchanged after the call, so nothing past the header is even written. A `dsid` sweep over -1, -2, 0, 1, 2 and 3 is uniform. Sweeping each qword of the 48-byte payload to `0xff` one at a time moves the result only for `+0x00` -- overwriting the version header gives `-45018` -- and leaves `+0x08` through `+0x28` completely inert. The same is true of the routing command: with `0x632b8d6e`, a sweep of `+0x0c` over 0 through 4096 and of every byte position 0..47 is uniform. **What these two codes have in common is that the body is validated from the first four bytes and then, whatever follows, is rejected on something the caller does not supply.** The environment id, the dsid, the output capacity and the output pointers are all inert in this build, so the shape the published layouts describe is not what this binary reads. Recorded also: a routing command cannot succeed on an unprovisioned machine by construction, so `0x632b8d6e` is the wrong probe for the happy path, and the OTP command is the right one -- both nevertheless stop at the same body check, which is now the single remaining obstacle and is known to be neither a size check nor a field of the supplied payload.
| 2026-09-28 | **The arguments do not start at +0x20 either, and the -45020 path never publishes the code in edi (2026-09-28).** A second published layout, from a different dissection of the OTP entry point, puts a 4-byte `global_header` at `+0x00` followed by 28 bytes of padding and the arguments at `+0x20` -- `dsid`, `ptr_MDM`, `size_MDM`, `ptr_MD`, `size_MD` -- on the reasoning that the caller's own test had put them at `+0x08` and `+0x10` and the library ignored everything between 4 and 32 as padding. Built and run: `-45020`, unchanged. The padding length is therefore not the discriminator, and the observation that drove it -- arguments at `+0x08` and `+0x10` being ignored -- is a property of the build, not of the format. **The OTP path does not publish its return code in `edi` at any sampled instruction.** The walker's stop trigger fires within 1.2 s of tracing on the `-45018` path, where `mov $0xffff5026,%edi` is what the trap catches. On the `-45020` path, with the OTP command and the same trigger, the walk runs the full traversal and the call returns without ever matching, even though the return value is `0xffff5024`. The two codes are therefore not published the same way: `-45018` is a constant loaded into `edi` on a path the walk visits, and `-45020` reaches `rax` by a route the register trigger does not sample. Locating it means following the value rather than the code, and the walker as built samples registers, not memory -- so the next instrument records writes to the guest-visible output range, which is where a computed code must pass through before it is returned.
| 2026-09-28 | **The register trigger is an unreliable instrument, and a control run is needed before any negative from it (2026-09-28).** The walker's stop condition tests the argument and result registers for the code being published, and it did fire on the `-45018` path in earlier runs. It no longer does. The mechanism is visible in the code: the value is published by an instruction, and TF traps *before* that instruction executes, so the register sampled at the trap still holds the previous instruction's result. Whether the trap observes the new value therefore depends on how many instructions follow the store before the walk leaves the image -- which is a property of the path, not of the instrument. On a path that publishes and returns immediately, the trap never sees it. This invalidates one claim in the preceding row. The statement that the OTP path never holds `0xffff5024` in `edi` was taken from sweeps with this trigger and is not evidence; the trigger could not have fired on that path for the reason above. `rax` is now sampled as well, and the same problem applies. **What survives is the part that did not depend on the trigger**: the fourteen `mov $0xffff5024,%edi` sites, each probed with an int3 against a control site that traps at the same time, none of them executes. That negative is sound because the control ran. **The rule this keeps restating has to be applied to the instrument, not only to the disassembly: a negative result needs a positive control in the same run, and a trigger that has not been seen to fire on the case under test proves nothing about that case.** The next instrument watches the guest-visible output range rather than a register, because a value on its way to `rax` must pass through memory.
| 2026-09-28 | **The packet header is exactly four bytes, confirmed in both directions (2026-09-28).** Sweeping the payload from an all-zero block with the version field set, one byte at a time, gives a clean split: a non-zero value at `+0x00`, `+0x01` or `+0x02` gives `-45018`, while a non-zero value anywhere from `+0x04` to `+0x2f` gives `-45020`. The header is therefore a four-byte field that must be `00 00 00 01` -- a version or a command count in network byte order -- and **nothing after it is examined**. The same split holds for the routing command. Two earlier claims in this file are narrower than this and are superseded by it. One said the switch is a single byte at offset 3; that was measured from a zeroed buffer and happened to be right, and it is right for a different reason than it looks: the three bytes before it must be zero, so the discriminator is the 32-bit field, not a byte. The other said every payload byte was inert, which is also wrong in the other direction -- bytes 0..2 are very much not inert, they must be zero, and a set byte there changes the result. The corrected statement is that the check reads four bytes and then stops, which is what makes every published layout that places arguments at `+0x08` or `+0x20` produce the same answer: there is nothing there for it to read.
| 2026-09-28 | **The init export does not populate the state object; the OTP call allocates it, and that is the -45020 subject (2026-09-28).** The body check reads four bytes of the packet and then rejects, and the two exports populate different things. Read at the gate global `0x19dda0` after each: after `cvu8io98wun` it is `0x0` -- the init export returns 0 and leaves no state object at all -- while after a single OTP call it holds a host pointer to a 0x28-byte block whose first qword is zero. So the object the body check consults is created by the operation itself, and the init export is not what fills it. That is consistent with the two exports' published roles: the init export yields version and protocol data, the operation export does the work, and neither is a substitute for the other in the same process. It also relocates the remaining question. The check is not over the caller's packet (four bytes, fully characterised) and not over a global the init export should have set (it is null after the init). It is over a field of the 0x28-byte object the call allocates, and the first qword of that object is the field the earlier walk named as the gate. **The next step is to fill that object**, which the runtime can do at the point of allocation the way the earlier seeding attempt did, and the earlier attempt failed for a reason now understood: it seeded the first qword, which is the flag, but the guest re-zeroes it immediately after allocation and before the check. Seeding a *different* field, or seeding after the zeroing, is the untried case.
| 2026-09-28 | **Filling the state object does not clear -45020, and the object is smaller than its allocation (2026-09-28).** The next step proposed in the previous row was to seed a field other than the first in the 0x28-byte object the operation allocates. `PERUN_GATE_SEED=<field>:<value>` now writes one qword of that block at allocation. Seeding each of its first four qwords with 1, and field 1 with 2, 0x11, 0x7fffffff, -1 and the image base, every run returns `-45020` -- no value, and no field, changes the outcome. The guest's own zeroing of the flag was therefore not what stood in the way; the block is simply not what the check reads. Incidental and worth recording because it sizes the object: seeding the fifth qword aborts inside glibc with a sysmalloc assertion. The allocation is 0x28 bytes but the object is **four** qwords, 32 bytes, so the fifth qword lands past it. The earlier `--peek-ptr` dump showed 0x28-byte allocations and the walker's register dumps showed a 0x28-sized request; the block itself is 32 bytes and the difference is tail padding. Consequence for the goal: `-45020` is not a state flag in this object and not a field of the caller's packet -- the packet contributes four bytes and the object contributes nothing that a caller can set. What remains is a check over something neither the frame nor this object holds, which is the same place the -45018 wall turned out to be before the version header was found.
| 2026-09-28 | **The session sequence was never replayed: the opcodes split cleanly, and the body check is what refuses (2026-09-28).** Every probe so far issued a single opcode in a cold process -- the equivalent of stepping straight to step 7 of the eight the Android run performs. Replaying all eight in one process through `perun seq` is possible and was done, and it changes the picture in one respect and not in another. With the version header laid down, five of the ten opcodes reach the body check and five do not: `0xb0eda7af`, `0xcfe0b46a`, `0x3e58e7f9`, `0x632b8d6e` and `0x85fe63b0` return `-45020`, while `0xb23c691e`, `0xc774d292`, `0x4069d332`, `0x4069d333` and `0` return `-45019`. The two session-init opcodes the Android dump shows first, `0xb0eda7af` and `0xb23c691e`, are **not a matching pair here**: the first is recognised, the second is not, and `0xc774d292` -- the opcode the Android dump attributes to SetMachineID -- is not recognised either. The opcode table of `CoreADI64.dll` and of the Android `libstoreservicescore.so` are therefore not the same set, and the Android call order does not transfer as a sequence. What the replay does confirm is that the body check is a per-call gate on a session that is still empty: the order does not change any outcome, and seeding the state object does not either. The three recognised opcodes that matter -- the OTP request `0x3e58e7f9`, provisioning `0xcfe0b46a` and `0xb0eda7af` -- all reach it and all are refused.
| 2026-09-28 | **What the call writes into the image, which is where the -45020 subject is (2026-09-28).** `PERUN_DIFF=1` snapshots the image before a call and reports every qword it changes. One `0xb0eda7af` call changes 47 qwords, in three groups: `0x19d020..0x19d058` (eight qwords replaced with what look like encoded values, and `0x19d050` loses the CFF token `0x4069d332`), a lone `0x19d088` that goes from `0x13284975` to `0x13284976`, and a block at `0x19dba0..0x19ddb0` that goes from all-zero to a run of distinct 32-bit-looking values, immediately followed by the state pointer `0x19dda0` being set from zero to a host heap address. The `0x19dba0` group is the finding: a 48-byte structure of per-call data the library builds for itself, written *after* the packet is rejected. It is not an input the caller supplies and it is not the 0x28-byte object the earlier seeding attempt filled -- different address, different size, written by the call rather than allocated by it. That is consistent with everything measured so far: the body check refuses because the state it consults is not yet populated, and the population happens later in the same call, in a structure the caller has no handle on. Also recorded because it invalidates a step: the counter at `0x19ddb8` goes from `0x0000000100000000` to `...003f` in a single call, so it is not a call count and the earlier plan to replay a longer sequence is not expected to change on its own. The five recognised opcodes remain refused, and this is the first account of what the library writes when it refuses.
| 2026-09-28 | **The diff structure is not per-call state, and the packet is read past the header only as input to it (2026-09-28).** The previous row read the group at `0x19dba0` as state the library builds for itself. Tested, that reading is wrong in a way worth recording: across three different recognised opcodes the group is written identically, 47 qwords each time, and its values differ between runs of the same input, so it is derived per run and not per call. It does change when a single packet byte changes, so the library reads the packet beyond the four-byte header -- but the return code does not, and a non-zero byte at `+0x00` alone still gives `-45018` while every other offset in the 48-byte packet gives `-45020`. So the header is still the only thing the decision depends on, and the group is a downstream product of the whole packet, not its subject. The five recognised opcodes all change the same 47 qwords and are all refused identically, which is the cleanest statement yet of the remaining barrier: a recognised command with a correct header is refused on something that is the same for every command, and the caller's packet does not reach it.
| 2026-09-28 | **Two corrections: the diff group is command-specific, and the callback-vtable hypothesis is refuted (2026-09-28).** The previous two rows read the 47 qwords at `0x19dba0` in opposite and both wrong ways. It is not a per-run constant: the set of changed addresses is the same for all five recognised opcodes, but **38 of the 47 values differ between them**, so it is a fixed scratch area the library fills with command-specific data. It is also not the subject of the decision -- it is written during the teardown that follows the refusal, and reading it explains nothing about why the call was refused. That remains the honest description and the earlier framing is withdrawn. The Android frame's `+0x18` and `+0x20` hold code pointers, and the hypothesis that they are host callbacks whose absence is what the body validator rejects is refuted by measurement, not by argument. Setting either or both to 1, to the image base, or to the address of the export's own entry -- three distinct kinds of value, non-null and pointed at code -- changes nothing: every combination returns `-45020`. A null check would have moved on the first, and a call through the slot would have crashed on the third. Neither happened, so the frame is not read past the header at all, which is what the byte sweep had already said.
| 2026-09-28 | **Every caller-reachable input is measured and inert; the barrier is not a payload (2026-09-28).** Closing out the input search. `r8` and `r9` were the last two arguments never given a real test: the cookie in `r9` was tried as zero, as the `vdfut768ig` entry, as the `cvu8io98wun` entry, and as a mid-`.text` address, with `r8` at zero as the Android dump shows, and all four give `-45020`. A real 347-byte SPIM from the Android run was then placed in the packet after the four-byte header and offered to the provisioning opcode `0xcfe0b46a`, the initialiser `0xb0eda7af` and the OTP opcode `0x3e58e7f9`; all three still return `-45020`. So the barrier is not a missing payload and not a missing cookie. The full measured set, every item with a control: the opcode in `rcx` (five values recognised, four not); the four-byte version header (byte 3 must be 1 or 2, bytes 0..2 must be zero); the size pair at `+0x08`/`+0x0c` (threshold exactly cursor+4); the buffer pointer at `+0x00`; the packet body past the header; `r8`; `r9`; the caller's own memory, into which the library writes nothing; the call order, replayed through `perun seq`; the state object, seeded in all four of its qwords across six values; the virtual filesystem, walked by the loader with and without a real `adi.pb`; and the two exports the library has, which are the only entry points that exist. None of them changes `-45020` once the opcode and version byte are right. What remains is a condition inside the flattened body of `vdfut768ig` that is satisfied on a real Windows host by something this environment does not reproduce — the state a provisioned machine carries, since `ADIGetLoginCode` is documented as reporting whether provisioning information was cached on the machine. Two independent oracles agree that the caller does not supply it: the un-obfuscated `libstoreservicescore.so` stamps only the version byte and never assembles a body, and `CoreADI64.dll` exports no wrapper that could. **The `-45020` barrier is therefore characterised but not passed, and `perun adi headers` is not implemented, because shipping the Android engine under that name would be a substitution and not the Windows path the acceptance criterion names.** |
| 2026-09-28 | **The packet packer is `0x1dbfd0`, and it reads the frame's five argument slots at `+0x20`..`+0x40` (2026-09-28).** `qi864985u0` is a five-line wrapper: it copies its five register arguments to `-0x38`..`-0x18(%rbp)`, points `-0x10(%rbp)` at the struct at `-0x58(%rbp)`, and tail-calls the packer. The packer at `0x1dbfd0` reserves `0x1278` bytes of stack, takes that struct pointer in `rcx`, and loads `+0x20`, `+0x28`, `+0x30`, `+0x38`, `+0x40` into `r11`, `rdi`, `rsi`, `rdx`, `r8` — which are exactly the five arguments in order: `dsid`, `out_mdm`, `out_mdm_len`, `out_md`, `out_md_len`. It then dispatches on `ebx = 0xfffff8d2 + *(frame+0x00)`, so the pointer at `+0x00` selects the path. **These five slots are past `+0x10`, where the frame built for the Windows lane was empty**, and the Android frame dump confirms they are populated there — `+0x28` and `+0x30` are a heap pointer and a matching length, `+0x38` and `+0x40` likewise. Filling all five in the Windows lane as a plausible OTP request, together and one at a time, does not move the return from `-45020`; a big-endian body length in bytes 4..7 of the packet does not move it either. The TLV hypothesis is refuted by measurement, as is the reading that the packet is four bytes and nothing more: the caller stamps the version and the packer serialises the five arguments, but where it puts them is in the later blocks of the packer, which the dispatcher reaches only after the `0x19db98` NULL check passes. |
| 2026-09-29 | **The front was at the wrong address, and the walker's stop code is why it stayed there (2026-09-29).** The canonical `-45002` front had been recorded as RVA `0xd6560`, an `obj[+0x08] == obj[+0x10]` emptiness test. It is not. The block at `0xd6560` publishes no error code, has no rejection branch, and ends in a bare `ret`; it decodes an obfuscated value and writes `[r11+0x28]`. `PERUN_STOP_CODE` now selects which ADI code the walk halts on, because it had been pinned to `0xffff5026` and no other code could be searched for: with it set to `0xffff5036` the walk stops at **instruction 57, RVA `0x5b0ae`, with `edi = 0xffff5036`**, 238 bytes past the export's prologue. By instruction 104 (`0x5b20f`) the register has been overwritten again, so the value is a reused CFF constant rather than the publication path, and the statement is narrowed accordingly. The dispatcher proper is `0x5b094`–`0x5b7xx`: it loads the CFF block table at `0x15fc90` — 84 signed dword offsets, 1 324 rip-relative references — and reads the gate global at `0x5b20f`, `0x5b517` and `0x5b720`. The recorded front and the recorded publication site were never the same place, and neither is at `0xd6560`. |
| 2026-09-29 | **`PERUN_SEAL_DATA` reported one access per page, not per address; the re-seal withdraws the "two globals" result (2026-09-29).** The seal un-protected a page on its first fault and left it open, so a page already opened by an earlier address reported nothing further. Since `0x19dba0`, `0x19dda0` and `0x19db98` all sit on the page at `0x19d000`, the long-standing conclusion that the body "consults exactly two globals" was a page census wearing the costume of an address log, and it is **withdrawn**. The seal now re-protects the page on the trap that follows the retried instruction — the walker is already armed, so that trap exists — and prints the faulting `RIP` beside the address, which also retires the "read" wording: `mprotect` cannot distinguish a load from a store, so the instruction should decide that, not the log. Corrected, the call makes **42 accesses over 36 distinct addresses**: `0x19d088` once at `0x5bcaf`; `0x19db98` once, so the slot the project has been poking is itself read back; `0x19dba0`…`0x19dd90` in 32 consecutive touches from the single instruction at `0x70d51`, a `memcpy` of 0x100 bytes; `0x19dda0` three times; `0x19dda8` twice; `0x19e9c8` twice. This is the fifth instrument defect this project has produced, and the most expensive, because the conclusion it supported survived a line-by-line read. The general rule is added to §5.8: **a sealing instrument that un-protects a page must re-seal it, or its output is not an address log.** |
| 2026-09-29 | **The library allocates the gate object itself: `lock cmpxchg` from null into its own heap block (2026-09-29).** A hardware write watchpoint on `0x19dda0` fires at RVA `0x5b51c`, and there the code is aligned and readable: `0x5b510 mov 0x710(%rsp),%rbx` / `0x5b517 lock cmpxchg %rcx,(%rbx)` / `0x5b51c sete %dl` / `0x5b51f imul $0x5ce7ce98,%edx,%eax`. The old value is 0 and the new value is `0x56202830`, a **host** heap address and therefore the product of this project's own `HeapAlloc` shim. So the object is created by the library during the call and installed with an atomic install-if-null; it is not a host-provided object, and no host is expected to provide one. `FINDINGS.md`'s standing statement that `0x19dda0` holds a host-provided pointer that perun never supplies is **withdrawn**. The address of the global is itself computed into a stack slot rather than appearing as a literal, which is why every rip-relative search for it returns zero and why the static scanners read as "no writer" — an instance of the obfuscation this project keeps meeting, and the first time it has produced a false negative in a scanner rather than in a runtime. Consequence for the goal: the remaining question is not a missing object but **what a freshly allocated object must contain** for the prologue to accept the call. |
| 2026-09-29 | **`-45002` is a precondition of the export, not a per-operation or per-frame check (2026-09-29).** Three measurements, each against the same baseline and each with the `-45002` return as the control. **The opcode does not matter:** `0xcfe0b46a` and the init opcode `0xb0eda7af` both return `0xffff5036`. **The frame does not matter:** seven shapes — cursor 0 and 4, seven pointer slots filled with real addresses, the recorded Android caller's 16-byte payload at `+0x50`, length `0x58`, length 0, length 4 — all return `0xffff5036`. **And the version export does not matter:** `cvu8io98wun` returns 0 on the Windows build, called first on the same frame, and changes nothing that follows, which refutes the hypothesis from the 2026-09-28 log that the missing step was a `cvu8io98wun` call before the operation. At the 57th instruction, where the code first appears, `rdx` points at `ctx + 1`, so the value is formed while the body is walking the caller's frame. Together with the row above, the caller-supplied input space is now closed on this path: opcode, frame shape, payload, `r8`/`r9`, call order, the state slot and the version export have all been measured, each with a control, and none moves the result. What is left is a condition inside the prologue that a correctly allocated object must satisfy. `perun seq`'s script syntax is corrected in the same pass: it is `call EXPORT A0 A1 A2 A3`, not `call A0 A1 A2 A3` as the docstring said, and naming the export is what allows one session to drive both exports in the order the real host uses. |
| 2026-09-29 | **Two more corrections: `%r11` at `0xd6560` is a stack local with no vector in it, and the opcode list is a sweep sample (2026-09-29).** The register the front was built on is the incoming argument — the disassembly is `mov r11, rcx` as the sixth instruction — and a hardware breakpoint at `0xd6583` shows it holding **`0x7fffffffcd70`, a guest stack address at `rsp + 0x370`**, not a heap block, not the poked scratch and not a global. There is no vtable at `[r11+0x00]`. The two fields read as `_Myfirst` and `_Mylast` are **byte-for-byte equal and non-zero** (`0x3b334ef6f339c6bb`), `[r11+0x20]` is a copy of the derived key `rax = (rax ^ r11) * 0x49255e13`, and the low dword of `[r11+0x00]` differs from `rax` by exactly one — so the block decodes an obfuscated value rather than testing a container, and the emptiness test that anchored seven independent accounts of this code is an interpretation, not a measurement. Separately, a byte scan of the whole image finds **none of the five recognised opcodes as a raw dword anywhere in `CoreADI64.dll`**, so the comparison is computed; the five came from a sweep and nothing bounds the set from above, while the four rejected values do appear, `0x4069d333` seventeen times and at least sometimes as a genuine `cmp ecx,imm32`. So the dispatcher explicitly knows what it refuses and computes what it accepts, and every name attached to an opcode — "init", "provisioning" — is an inference. Finally, the reference caller in `iTunes.exe` is unreachable by string search **for a structural reason now identified**: that binary carries an `RT_CODE` section and is a .NET ReadyToRun image, so its ADI call site is managed code and a native rip-relative xref returns zero by construction. Look in the managed metadata, not in `.text`. |

| 2026-09-29 | **The gate object is `HeapAlloc(flags=0, size=0x28)`, unzeroed, and nothing writes it after publication (2026-09-29).** With `HeapAlloc` in the trace, the pointer the `lock cmpxchg` at `0x5b517` publishes matches one logged allocation by address in the same process: a 40-byte block. `flags=0x0` is not `HEAP_ZERO_MEMORY`, so the two zero qwords the object is seen holding are what a fresh glibc arena returns rather than something the library wrote — and they are the two an emptiness test would compare, so on this host that reading can be an artefact of the allocator. A 40-byte block is five qwords, so there is **no qword at `+0x28`**; an earlier note that named one had walked past the allocation. Four hardware write watchpoints on the first four qwords, armed at `0x5b51c`, stay live to the end of the call and never fire: the object is assembled before publication and its fields are final when the `cmpxchg` retires. The remaining question is what assembles it. |
| 2026-09-29 | **`0x19e9c8` is the heap handle, `cvu8io98wun` is not on the path, and `HeapSize` is never called (2026-09-29).** gdb's own decoder at `0x1353ae` — not objdump's linear sweep, which is not instruction-aligned in this body and whose operand annotations had already produced one wrong conclusion this phase — shows `mov rcx, [0x19e9c8]` feeding `call HeapAlloc`, and the observed `rbx=0x228` matches the logged `HeapAlloc(flags=0x0, size=0x228)` exactly. The imports are reached by direct `call [rip+disp]`, not a thunk chain, and that route covers only a fraction of the allocations: the static CRT allocates largely without going through the IAT, so static IAT analysis does not find the site for a given allocation and a trace does. A GOT hook on the `cvu8io98wun` slot captured **zero calls** across a complete successful Android provisioning run — eight `vdfut768ig` calls, the `SUCCESS` banner, both headers — so the "missing initialisation step" account is refuted from both builds. And `HeapSize` turned out to be called zero times on this path, which means the constant 16 it returned for the length of this project was load-bearing for nothing that was ever measured. |
*Apple, macOS, OS X, StoreKit, FairPlay, iTunes and related marks are trademarks of Apple Inc. This independent research project is not affiliated with, endorsed by, or sponsored by Apple Inc. All binary images referenced are obtained by users directly from Apple's public distribution servers and are never redistributed with this project.**`f` is a full-avalanching block transform.** Sixteen runs, base packet from
the Android engine, one input byte raised by one each time:

```
base  c1 1c 64 57 95 fd 65 59 17 c2 7f 21 e2 48 14 cd
+byte4   db 20 5d 0d dc 43 15 9e ee dd c7 a4 84 f9 35 81
+byte5   fe 56 a0 32 94 71 ea 0e 34 b4 65 9c fe 46 02 78
+byte6   8d 35 10 0c 9b b9 18 55 6d 78 cd 6b a0 d4 a2 49
+byte7   4c 4c 10 b3 0d d5 c7 16 be 12 ee d8 b5 3e a5 a3
+byte8   75 b0 8a 49 f5 36 ff 22 80 47 03 04 c8 5b 59 8a
```

One input byte moved, **all sixteen outputs changed.** So `f` avalanches in
every byte and cannot be inverted per byte; the packet has to be searched as a
whole. What does move independently is `out[+3]` -- the byte the dispatcher
reads -- which took `57, 0d, 32, 0c, b3, 49` across these runs.

**Every one of those still returned `-45020`,** which is itself the finding: a
wildly varying dispatch input lands on the same publisher. The dispatcher's
table at RVA `0x9055d` is 256 signed dwords with **196 distinct targets**, and
those targets are *not* publisher blocks -- they are further dispatcher stages.
The chain is multi-stage, so the index-to-code map cannot be resolved by
decoding alone; it has to be observed.

**The decisive negative result: the payload cannot move the barrier.** Twelve
packets, deterministic configuration, only the supplied bytes differing:

```
header byte 3 = 0        -45018  (header check, ~107,000 instructions)
header byte 3 = 3        -45018
header byte 3 = 4        -45018
header byte 3 = 1        -45020  (105,151 instructions, short path)
header byte 3 = 2        -45020  (221,694 instructions, full path)
```

and with a valid header, eight payloads that share nothing:

```
9d b6 cf e9 14 f2 ae 3f 98 49 66 ca   -45020
01 1a 33 4c 00 ... (zeros)             -45020
ff ff ... ff (all ones)                -45020
de ad be ef 01 23 45 67 89 ab cd fe 02  -45020
three further random payloads          -45020
```

**Bytes 4..15 did not influence the return code in any of the runs tried.**
Stated precisely, because it was stated too strongly first: twelve packets
proves those twelve fail, not that no packet can pass. The systematic part is
that in the fmap runs each of bytes 4..15 was raised by one in turn and every
one still ended at `-45020`, while raising any of bytes 0..3 changed only
whether the `-45018` check passed. That makes the payload the wrong place to
look -- but it does not make the barrier unreachable.

**It is not unreachable. The library publishes success.** The earlier count of
113 sites was for the `0xffff50xx` error codes only. Sweeping every
`mov edi, IMM` in `.text` gives **3,099 publisher sites over 2,448 distinct
codes**, and among them **99 sites publish `0x00000000`** -- success. The
alphabet contains the answer; the barrier is a question of which of those
blocks this opcode's path can be steered onto, not of whether a success code
exists.

The useful consequence is that the problem stops being a search over packets.
It becomes: locate the zero-publishing block that belongs to this opcode's
success path, and work backwards from it through the dispatcher to find what
selects it. That is a graph question with a bounded answer, and the
deterministic oracle makes each step of it exact.

**What that leaves.** The barrier is not a packet check. The only caller-supplied
value that moves the outcome is header byte 3, and only in the direction of
passing or failing the `-45018` check. Everything after that -- the 400
instruction region, the 16-byte avalanche, the byte the dispatcher reads -- is
reached identically for every valid packet, and always lands on `0x905c2`.

So the question is no longer "which packet". It is **what the dispatcher reads
that we cannot supply**, and the candidates are now few and concrete: the
`[rsp+0x70]` word (read, never written, and shown not to change the result), the
heap address of the buffer (pinned by ASLR, and it does change the result), and
whatever a genuine caller puts in the frame. `CoreFP.dll` is the only candidate
for the last, and it runs under this runtime.

**The success block is located, and it is a single site.** Restricting the sweep
to the region the walk actually runs through, `0x8e000..0x91000`, gives 71
publishers over 33 codes:

```
-45034  0xffff5016   x14
-45002  0xffff5036   x14
-45020  0xffff5024   x13
  0     0x00000000   x1   at RVA 0x8f064     <-- SUCCESS
```

Exactly one block in the whole flattened region publishes zero. It is a sibling
of the `-45020` block we land on, in the same dispatcher, which is the
strongest statement available about the shape of the problem: the success path
is not elsewhere in the library, it is **the same CFF choosing differently**.

**What the dispatch table does and does not give.** The table at `0x9055d` is
256 signed dwords resolving to 196 distinct targets, and no first-stage entry
lands on `0x8f064` or on `0x905c2` -- it leads to further dispatcher stages, so
the chain is multi-stage and the index-to-code map cannot be read off one
table. Index aliasing is heavy at the first stage: the most-referenced block
takes 8 of the 256 indices, and 37 blocks take 2 each. So the index space is
small and highly redundant, which is why so many different packets land on the
same publisher.

**The dispatch is a general CFG, not a chain of tables -- and that closes the
static route.** Resolving the 196 first-stage targets shows they are ordinary
MBA-laden blocks (`sar edi,0xe1; sbb dword ptr [rax-0x75],ecx; ...`), not
further dispatchers. So the CFF is one control-flow graph, and reading an
index-to-code map out of it is not a bounded walk. It has to be observed.

**The guest is provisioning, and the shim is dropping one of the seven
ingredients.** With the provisioned directory absent, the guest's own sequence
is:

```
PathIsDirectoryW(.../iTunes/adi)  -> false
  ... it creates the directory itself ...
GetFileAttributesW(.../iTunes/adi) -> 0x90
returned 0xffff5024
```

The directory appeared with mode `drwxr-xr-x` (0755), which is what this
runtime's `CreateDirectoryW` shim passes to `mkdir`. So the guest **is** taking
the provisioning path, creating where it expects data, and then stopping without
writing anything. The two path APIs appeared to contradict each other; they did
not -- the guest created the directory between the two calls.

**Correction to the previous entry: the shims do not lie.** `GetFileAttributesW`
stats the path and returns `INVALID_FILE_ATTRIBUTES` on failure, as Windows does.
What looked like a shim answering "yes" unconditionally was the guest having
created the directory one call earlier.

**No network is involved.** `CoreADI64.dll` imports only `KERNEL32`, `ADVAPI32`,
`SHLWAPI` and `SHELL32` -- no `winhttp`, `wininet` or `ws2_32`. Anisette is
generated locally, so the failure is a local computation.

**And a real shim defect sat in the fingerprint path -- and fixing it did not
move the barrier.** The device fingerprint is an MD5 over seven components, one
of them the volume serial. This runtime's `GetVolumeInformationW` took the
serial as `_serial: *mut DWORD` and never wrote to it, so the guest received
whatever was on its own stack. The parameter is now `serial` and is filled with
a stable non-zero value derived from the volume label the shim already
reports.

With that fixed, the call still returns `-45020`, and the guest still creates
the provisioning directory and still writes no file. **So the dropped serial
was a genuine fidelity bug but it is not the barrier**, and the record says so
rather than leaving the fix looking like progress towards the goal.

That also means the remaining fingerprint components deserve the same
treatment rather than this one being special: the registry values read through
`ADVAPI32` (`RegQueryValueExA` on `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
for `ProductId` and `ProcessorNameString`, `SystemBiosVersion`), the machine name
and the hardware profile GUID. `Blackwood-4NT` documents all seven and how they
are combined, which is the specification to work from.

**A contract fact, verified twice: `cvu8io98wun` takes a buffer, not a magic.**
It has been called with the opcode in `arg0` in the belief that it takes the
same selector `vdfut768ig` does. It does not. Called that way it faults
dereferencing the opcode itself (`addr=0xcfe0b46a`, `rip=0x8e4b4d`); called
with a guest pointer in `arg0` it returns **0**. So its signature is a buffer to
be filled with the initial version and protocol data, and the selector belongs
elsewhere. This also means the init export has never actually been run
successfully in this project, and every conclusion drawn from "init then
provision" runs rests on a call that faulted.

**Not established, and deliberately not written down as fact:** whether calling
it properly changes the `-45020` outcome. The `perun seq` script grammar takes
arguments in a different order from `perun call`, and the two orders were not
reconciled before the context ran out, so a before/after could not be measured
cleanly. What is solid is the ABI itself -- buffer in, 0 out -- and the fault
on the old calling convention.

**And the fingerprint question is answered, negatively.** `PERUN_TRACE=1` on
this path shows the guest calls **no data-gathering API at all**: no
`RegQueryValueExA`, no `GetVolumeInformationW`, no `GetComputerNameW`, no
`GetCurrentHwProfileW`, no `GetAdaptersAddresses`, no `CreateFileW` or
`WriteFile`. What it does call is TLS and FLS setup, a dozen `HeapAlloc`s, and
the path probe. So the volume-serial fix was in a code path the guest never
reaches, which is a second, independent reason it could not have moved the
barrier -- and the earlier guess that the fingerprint was being assembled and
came out wrong is **withdrawn**: no fingerprint is being assembled here.

That places the `-45020` **before** any data collection, which is new and
narrows the field to the part of the body that runs from argument validation to
the first filesystem probe.



**What `edi` is before the index folds it in.** Probed at `0xb15b3` with the walk
off: `edi = 0xff57eb`, and `(edi << 8) + 0xa8d100 = 0xbc00`, exactly the value
read at the dispatcher three instructions later -- so the two observations are
consistent and the chain is confirmed rather than assumed. `edi` is a 20-bit
value that is not packet-derived, and `rbp` at the same point is `0x51cfdef`,
updated by `lea ebp,[rbp+rbx*2+0x1600211]`. Neither is a function of anything
the caller has been shown to supply. Linear disassembly backwards through the
body does not decode -- CFF has no instruction boundary there -- so this had to
come from breakpoints rather than from the reader.
**A trace cannot be taken in the configuration that matters.** `PERUN_TRACE_FILE`
writes the ring, but the ring is only filled by the walk and the dump sits inside
the branch guarded by `STEP_ARMED` -- so with the walk off, which is exactly the
configuration `perun call` runs in and the one that returns `-45020`, no trace file
is produced at all. Every trace this project has examined was therefore taken with
the walk armed, and the walk demonstrably changes the state: it alters the number of
instructions to the return and, with it, the transform's own output. **There has
never been an observation of the production path's register file.**

Hardware breakpoints supply the missing one, because they do not single-step. Armed
at `0xb15c8` through the `mprotect` hook, on the isolated stack and with the walk
off, the three inputs to the dispatch index read:

| input | value |
|---|---|
| `eax` before the load (the byte offset) | `0x3` -- buffer byte `+3`, as before |
| `edi` | `0xbc00` |
| `rbp` | `0xfb830000` |

The last two are the ones the packet cannot reach directly: `edi` is produced by
`shl edi,8; add edi,0xa8d100` and `rbp` by `lea ebp,[rbp+rbx*2+0x1600211]`, both
from state the caller has not been shown to supply. That is the next thing to
attack, and it is finally observable.

**The predicate steers the publisher, and it was forced.** `0x9059a`
`cmp r9d, 0x4069d333` is executed once, at step 222 902, and the value in `r9d`
there is **`0xf0c5d587`** -- not `0x4069d332`; that value belongs to a different
site. Its ZF feeds `setne cl` and `sete bpl`, and `bpl` goes into
`lea eax,[rdx + rbp]` at `0x905a8`, so this comparison does move the dispatch
index.

A hardware breakpoint that rewrites the register on the stop and continues
(`/opt/data/adi-re/force_probe.py`) gives the result directly:

```
r9 at the predicate, measured            0xf0c5d587
r9 forced to                             0x4069d333
call returns                             0xffff5016   (-45034, not -45020)
```

**So the answer to the question that was put to this section is no.** The
difference between `-45020` and success is not one bit at that comparison:
flipping it moves the call to `unknownAdiCallFlags`, the *first* gate, which is
earlier in the body than the publisher we were on. What the experiment does
prove is more useful than what it refutes: **a register written at the predicate
selects which publisher runs, and this runtime can now steer that choice.**
Whether any value of `r9` reaches `0x8f064` is now a question with an instrument
that can answer it.

**`DllMain` really runs, so the library is initialised.** The obvious remaining
explanation -- that the loader fakes `DLL_PROCESS_ATTACH` and the globals are
never set -- is false: `cmd_call` resolves `entry_dll_main()` and calls it with the
image base and `DLL_PROCESS_ATTACH`, and the returned value is checked. Both
`perun call` and `perun seq` do this. So the state the CFF reads is post-init,
and "the loader skipped initialisation" is withdrawn before anyone spends a
round on it.

**The three remaining exports fault whatever they are given.** `WIn9UJ86JKdV4dM`,
`YlCJ3lg` and `dku592fbFAj` were tried with `arg0` as the buffer, as the context,
both in each order, and the same pointer twice. All six combinations fault in all
three. They need a caller's frame, not an argument we can synthesise, so the
caller side is exhausted from this side too.

**Where that leaves the goal, stated plainly.** Every input reachable from a
caller has been varied and measured: the packet, the opcode, every context field,
the stack word, the filesystem, the volume serial, both `CoreADI64` exports, and
all six `CoreFP` exports run first in the same process. None moves `-45020`.
What is left is state the library expects to already hold -- set by a real Windows
process before the first call, or by host state this runtime does not reproduce.
That is a larger piece of work than anything attempted here, and it is where the
next round should start.

**A real caller, run first, does not move it either.** `PERUN_AUX_IMAGE` loads a
second image into the same process, so a `CoreFP.dll` export can be executed and
then `CoreADI64.dll`'s `vdfut768ig` in one process -- the experiment that had been
unrunnable because every command loaded exactly one image. All six exports, each
followed by the real call:

```
caller export      result            then vdfut768ig
WIn9UJ86JKdV4dM    crash              -
X46O5IeS           0xffff5bd9        0xffff5024
YlCJ3lg            crash              -
dku592fbFAj        crash              -
fdjkDSAFjklaf2s    0x0               0xffff5024
lxpgvVMLd0S7uRl    0xffff5bd9        0xffff5024
```

So the one export that succeeds, and the two that run to a code, change nothing.
Combined with the packet, the context, the stack word, the filesystem and both
exports: **no caller-reachable input has been found that moves `-45020`.**

**A `CoreFP.dll` export succeeds, and the guard was ours.** Six obfuscated exports
return `-42023` uniformly when called with a literal argument -- which is how they
were always called. Given a real guest pointer they behave differently:

```
WIn9UJ86JKdV4dM   crash
X46O5IeS          0xffff5bd9
YlCJ3lg           crash
dku592fbFAj       crash
fdjkDSAFjklaf2s   0x0      <- success, reproducible over three runs
lxpgvVMLd0S7uRl   0xffff5bd9
```

With `arg0` a literal `0` the same export returns `0xffff5bd9`, so the guard is
on the argument being a real pointer, and **the earlier statement that all six
return `-42023` is withdrawn: it described the arguments we passed, not the
functions.** This is the only execution of the real caller we have that does not
fault.

It cannot yet be used, because `perun call` and `perun seq` each load exactly one
image, so there is no way to run a `CoreFP.dll` export and then call
`CoreADI64.dll`'s `vdfut768ig` in the same process. Until that exists, the
experiment that matters -- does a successful caller export move `-45020` -- cannot
be run.

**The dispatch state is not caller-seeded at all, and there is no entry we missed.**

Probing `0xb15b3` again with the context filled the way the Android engine fills
it -- `+0x10`, `+0x18`, `+0x20`, `+0x28`, `+0x30`, `+0x40`, `+0x48` all set, and
version 4 at `+0x0c` -- gives values identical to the plain context:

```
context      edi        rbp       rbx
plain        0xff57eb   0x51cfdef 0x7a830000
full         0xff57eb   0x51cfdef 0x7a830000
```

So the CFF state is invariant to the packet *and* to the context. And the export
table has **exactly two entries**, `cvu8io98wun` and `vdfut768ig`, and both are
called. There is no initialiser we skipped.

**What that leaves.** Everything a caller can supply has been varied and measured:
payload, opcode, every context field, the stack word, the filesystem, the volume
serial, both exports. The dispatch index does not move. The success block
`0x8f064` is real and is this same graph choosing differently, and nothing we can
reach from outside the guest chooses it. The remaining candidates are a real
caller's frame and host state this runtime does not reproduce -- `CoreFP.dll`
runs here but its six obfuscated exports all return `-42023` -- and that is no
longer a packet problem, which is the only thing that changed in eleven rounds.

**And those inputs do not move with the packet either.** Probing `0xb15b3` on three
radically different packets -- the Android one, all zeros, all `0xff` -- gives
byte-identical values every time:

```
payload   edi        rbp       r9
base      0xff57eb   0x51cfdef  0x1
zeros     0xff57eb   0x51cfdef  0x1
ones      0xff57eb   0x51cfdef  0x1
```

The literal `0xff57eb` does not occur anywhere in the image, so it is computed by
the dispatcher's own mixing rather than loaded. And the computed value is the same
for every packet. **Taken with the rest, this closes the packet direction:** the
index that selects the success block is built from a packet byte that does change
and two components that do not, and the result is `-45020` for every packet tried.
Searching the packet space is therefore not merely unproductive, it is provably
so.

### The engine lane, and the block that stops it (2026-10-01)

The Android engine is the only place the real caller executes, so the SPIM
packing can only be read from the code that actually does it. Four separate
things had the lane blocked, all now pinned, all of them mine:

1. `ANDROID_NDK` must be the **parent** (`/opt/data/ndk`), because
   `run-native.sh` globs `$ANDROID_NDK/android-ndk-*/…`. Pointing it at the NDK
   itself leaves `CC` empty and the script exits before building, silently.
2. A stale `adi_native` must be killed first: the repoint fails with
   `Text file busy`, the binary then runs on its original
   `/system/bin/linker64`, and it hangs with no diagnostic at all.
3. With both fixed the engine builds, repoints `PT_INTERP -> /tmp/pa.so` and
   starts, and then **emits nothing and never exits**.
4. `LD_PRELOAD` is not an alternative: `libc.so` carries 67 Bionic markers and
   `linker64` 8, and `LD_PRELOAD` is read only by glibc.

**The block, established and then narrowed three times.** Attaching
`sudo gdb -p` to the live engine and unwinding gives frame 0 in `syscall` and
frame 1 in `__futex_wait_ex`, both in `libc.so`. `libc.so` carries 2 666 FUNC
symbols, so the rest was decided statically: only two direct calls to
`__futex_wait_ex` (`0x282e0`) exist in the whole image, at `0x28563` inside
`pthread_mutex_lock` and `0x289a8` inside `pthread_mutex_timedlock`. So it is a
mutex, not a condition variable and not a barrier.

And the wait is **unsatisfiable by construction**:

    rdi = uaddr   0x70d29f3bdd18
    rsi = op      0x80            128 = FUTEX_WAIT_PRIVATE
    rdx = val     0xd93f4002
    *uaddr        0xd93f4002      <- already equal to val
    *(uaddr+4)    0               owner
    *(uaddr+8)    0               queued

`FUTEX_WAIT` blocks until the word differs from `val`. It already equals
`val`, so nothing can ever wake it. The low 16 bits are `0x4002` in every
process measured (`0xd1274002`, then `0xd93f4002`) while the upper half varies
per run: a non-zero `__lock` with `__owner == 0`, which is not a state a
correct `pthread_mutex_init` produces. The Apple code is waiting on a mutex
nobody initialised.

Three earlier diagnoses were wrong and are withdrawn: crypto seeding, the
Bionic loader, and "waiting on the network" — `gsa.apple.com:443` is reachable,
and no socket is ever opened. Two of the three came from reading `wchan` and an
fd list as if they identified the block; only the unwind did.

**What remains.** The block is a `pthread_mutex_lock` stub at `0x154e0` with
265 callers, so which one is on this path cannot be answered by picking. It
needs the executed path, and this lane does not record one. Root cannot exec
these binaries at all — a byte-identical copy at `/tmp` with mode 0755 fails
under `sudo` while `hermes` runs the original — so launching under a debugger,
which would settle it, is unavailable. Attaching works precisely because it
needs no new exec.

**What step 1 did yield.** At RVA `0x1dbbf3` the caller writes
`00 00 00 <version>` into the output pointer at `+0x00` of a cursor block, then
adds 4 to the offset at `+0x0c` — the header our own runs measure. The SPIM
body and its length are not there: only two instructions in
`0x1db800..0x1dd000` touch `r9`, and that window does not linear-disassemble
at all. `aslgmuibau` and `0x1ddeb0` are CFF trampolines and pack nothing.
