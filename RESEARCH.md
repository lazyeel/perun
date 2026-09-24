# RESEARCH.md — Perun: Native Binary-Projection Runtime for Apple Client Attestation (FairPlay SAP and ADI)

**Project:** [lazyeel/perun](https://github.com/lazyeel/perun) · **Document class:** Interoperability research specification & reverse-engineering report · **Status:** Working end-to-end implementation (SAP protocol closed 2026-08-31; ADI dispatcher end-to-end to its provisioning gate 2026-09-03; live StoreKit client lane E2E 2026-09-07; store-command parity and resumable downloads 2026-09-13/14; mmap-bounded IPA replication) · **License:** [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

---

## 1. Scope, Purpose, and Interoperability Basis

This document is a technical specification and research report for **Perun**, a native user-space runtime that projects and executes Apple's binary images directly on a Linux host — no CPU emulation — covering two target families:

- the 2013-vintage x86_64 **Mach-O** commerce images (CoreFP, CommerceCore, CommerceKit) that run the StoreKit client-attestation handshake (FairPlay **SAP**) end-to-end against Apple's live storefront endpoints;
- the Windows **PE32+** image `CoreADI64.dll` (iTunes for Windows, x86_64), whose ADI v3 attestation dispatcher runs end-to-end up to its provisioning gate.

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

Site counts (measured): CommerceKit A=246, B=4, C=1 (251 sites); CoreFP A=64, B=0, C=0; storeagent A=566, B=3, C=0; CommerceCore 0. No runtime hooking; the rewrite happens once at load, in memory, on the working copy — the on-disk images are never modified. Timing normalization is an environment-compatibility measure (deterministic execution), not a protection-defeat: no anti-tampering or integrity check exists on this path (verified — see § 5.2).

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
- **111 Win32 APIs** implemented as shims — plain Rust functions compiled as `extern "win64"`, so a resolved import is a direct `call` with no per-call trampoline. `DllMain(DLL_PROCESS_ATTACH)` returns TRUE on `CoreADI64.dll` with zero unresolved-import traps.
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

- **ADI (Apple Device Identity)** — the provisioning library family (`libCoreADI.so` on Android, `CoreADI64.dll` on Windows, `AppleADITool` on macOS) that yields one-time-pads for **GrandSlam/GSA** authentication ("anisette" headers: `X-Apple-I-MD`, `X-Apple-I-MD-M`, `X-Apple-I-MD-RINFO`). Apple-signature-checking **commerce** endpoints do not consume anisette; the **GSA/SRP login layer** still does. Perun's Phase-1 ADI research on `CoreADI64.dll` (the provisioning gate at `0xffff5016`) remains the reference analysis for that layer.
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

### 5.8 ADI provisioning-gate analysis (`CoreADI64.dll`, Phase 1)

The ADI lane stops at a provisioning gate, fully characterized by measurement (the PE-side companion to the SAP protocol above; every claim here reproduces with the shipped binary and stock tools — § 6.7).

**The wall.** `perun call CoreADI64.dll vdfut768ig <ptr> <struct>` executes the dispatcher's full provisioning logic and returns a clean ADI error code instead of crashing: `0xffff5016`, uniform across every struct variation probed (offsets `0x0`–`0x40` with values 0–0xff, with and without the init header below). The trace shows the directory walk but no blob opens or reads and no registry calls (the file/path/registry shims all log their calls; mutex logging is thin, so mutex traffic cannot be fully excluded), and no enumeration. The result is checked **before** command dispatch, so it is an in-memory provisioning-state flag, not a per-command result. The dispatcher's control flow is control-flow-flattened (obfuscated), but the entry sequence is decoded:

- First-level dispatch takes two pointers. `rdx` is the required param struct: NULL → `0xffff5036` (invalid param); a non-pointer (e.g. `1`) crashes writing at struct offset `+0xc` (`movq $0x0,0xc(%rdx)` in the prologue at RVA `0x5b1cf` — the fault address `0xd` reproduces exactly). `rcx` is NULL-or-valid: `0`, `scratch` and `ctx` all return `0xffff5016`, while small integers crash dereferencing the value itself — pointer semantics, not a command code. There is no `test %rdx,%rdx` at the entry; the entry reads `rcx` arithmetically (`lea eax,[rcx+rcx]`, masked and negated) and the NULL checks resolve downstream in the flattened flow.
- No command-code register exists: sweeping `rcx` over 1–255 crashes (it is not an index), and sweeping struct fields with the init header present never leaves `0xffff5016`, so the command — if it is a struct field at all — is read only after the gate. The earlier 0..255-uniformity claim is withdrawn: it cannot have been produced through `rcx`.

**What the gate actually is (measured, not guessed).**

- The gate global is the qword at RVA `0x19dda0` (`.data`). It is read via an obfuscated pointer table at RVA `0x17eca0` (entry `[0x157]` stores `ImageBase + real + 0x4f7e9322`; subtracting the base and the key yields the target). The check at RVA `0x5b20f` is a double dereference: `cmp qword ptr [rcx - 0x4f7e9322], 0`.
- At runtime the global holds a host heap pointer to a 0x28-byte object the guest allocates during the call itself — observable live with the shipped `--peek-ptr=0x19dda0`: the object's first qword is the flag the gate reads (zeroed at allocation); `[0x8]`, `[0x10]`, `[0x18]` are pointers into a small graph of sub-allocations.
- The provisioning loader walks `<CommonAppData>\Apple Computer\iTunes\adi` (resolved via `SHGetFolderPathW(CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE)` — csidl `0x8023` — plus `PathAppendW` + `PathIsDirectoryW` + `GetFileAttributesW`, confirming each directory) but returns `0xffff5016` whether or not `adi` exists — re-verified with the directory present and absent, and with a dummy blob file inside: identical result, and no `CreateFile` fires — but the traces differ: with the tree present the walk confirms every level (`Common` → `Apple Computer` → `iTunes` → `adi`, each `PathIsDirectoryW` true with attributes) and stops after `adi` with zero enumeration; with it absent the walk ends at the first missing level. The blob filename is built at runtime (obfuscated); the only "adi" string in the image is the named-object prefix `Global\adi-pb-unique`.
- All real file I/O (`CreateFileW`/`ReadFile`/`WriteFile`/`SetFilePointerEx`) is concentrated in routines at RVA `0x1339d0`–`0x13f6c5` (15 indirect call sites total: CreateFileW 5, ReadFile 3, WriteFile 6, SetFilePointerEx 1), reached only after the gate passes.

**Cross-reference with prior ADI/FairPlay research.** `0xffff5016` = signed `-45034`, adjacent to `-45061 kADINotProvisioned` ("ADI machine not provisioned, expected pre-init") — the documented ADI error family. The circular dependency is already characterized:

```
bag-request -> needs FairPlay context
InitContext -> needs FPDICreate
FPDICreate  -> needs subscription bag from server
bag-request -> needs context        <- cycle
```

The real app breaks the cycle by calling the `fpinit.itunes.apple.com/v1/fpdi` endpoints (init/setup) **before** any native FairPlay call — both endpoints are live (HTTP 405 on bare GET, i.e. present and POST-expecting). Live 2026-09-22: the GSA lane has its own door — `GsService2/lookup` (akd UA) yields `MidService/startMachineProvisioning`, and posting Provision's empty plist there returns ec=0 with a live 347-byte spim (no Apple ID needed for step one). Feeding (dsId, spim) by value into the Windows struct at 20 placements times cmds 0..3 never leaves -45034: the Windows arm wants pointers (Blackwood's Arguments/sizes/flags shape), unexpressible through one-shot pokes — next via the in-process harness. fpinit's fpdi/init rejects the same plist with the frozen 500. Two different doors. The provisioning blob is device-specific cryptographic material issued during that handshake; on a fresh offline system there is no blob, so ADI faithfully reports not-provisioned. This is the provisioning layer of the same Apple client-attestation family the project exists to understand. (Scope note: the August-2026 commerce gate on storefront traffic — § 5.6 — is a different, later thing; this section describes the classic ADI provisioning cycle, unchanged since the iTunes era.)

**The two-trampoline experiment.** Two error-reporting trampolines sit at RVA `0x66c2d` (`mov edi,0xffff5016` — the only one of 37 sites that runs for cmd=0) and `0xb5b49` (`mov edi,0xffff5026`, the next failure exit). Neutralizing the immediates with the shipped `--patch` token (5 bytes each, instruction lengths preserved) makes cmd=0 return `0x0`, but the success is hollow: the API trace is byte-identical to the unpatched run — no additional API fires, so the trampolines are reporting stubs on a fixed not-provisioned path, not branch selectors. Zeroing only the first trampoline yields `0xffff5026` (the next exit fires). The gate cannot be passed offline by poking memory. Flipping the gate result cleanly — `pushf` + `or`/`and $0x40,(%rsp)` + `popf` at `0x5b20f` (ZF forced either way with all registers and every other flag intact, instruction lengths preserved) — changes the route but not the outcome: ZF=0 skips the directory walk entirely (only `SHGetFolderPathW` fires), ZF=1 walks it, and both return `0xffff5016`. The not-provisioned exit is funneled from multiple paths, so no single-point flag flip passes it. (An earlier dirty variant that also zeroed `ecx` crashed at RVA `0x5b517` — mechanical, the post-`cmp` `lea` needs `rcx` intact; zeroing the live `eax` counter hangs the rax-stepped dispatch loop instead. Neither variant tests the branch itself.) The table base `0x17eca0` is consulted at ~225 sites across the dispatcher, so mapping which entries feed the outcome is the full context-graph reconstruction (way 3 below), not a follow-up patch.

**The sibling export is the init half.** `cvu8io98wun` (RVA `0xe4b00`) takes the struct in `rcx` and ignores `rdx`: NULL `rcx` → `0xffff5036`; otherwise it writes `[rcx+0] = 0x2000000001`, `[rcx+8] = 0` and returns `0x0` with no shim calls at all (decoded entry: `test %rcx,%rcx`, flattened dispatch, `movabs $0x2000000001,%rdx; mov %rdx,(%rcx); movl $0x0,0x8(%rcx); xor %eax,%eax`). The two-step handshake transfers mechanically across processes (`--poke=scratch+0=0x2000000001` into the next call), but `vdfut768ig` on the inited struct still returns `0xffff5016` — provisioning state is global, not carried in the param.

**In-process chaining changes nothing.** A dedicated harness (`crates/perun-cli/examples/chain.rs`) calls both exports back-to-back in one address space — heap included — with `.data` snapshots around each call: the init call leaves 0 bytes changed in `.data`, and the operation call on the warmed process still returns `0xffff5016` with the same walk. The op call itself mutates ~218 bytes in 43 runs (state expansion with heap pointers); the cold control (`--skip-init`) lands in the same 43 runs with pointer-value noise. Init sequencing is not the missing piece — the cross-process `--poke` transferred everything observable.

**Feeding a live spim.** The `feed_spim` harness (`crates/perun-cli/examples/feed_spim.rs`, one child process per case since a wild guest can smash past the crash probe) carries a GSA-issued 347-byte spim plus dsId through honest pointers in two layouts: flat A (`[+0]=dsId`, `[+8]=op`, …) and envelope B (`[+0]=inner`, `[+8]=347`, `[+10]=4096`, `[+18]=op`). Flat 0–3 returns -45034, flat 4–7 and every shifted layout die dereferencing `[+0]` — the session arm reads it as a pointer, confirming the union model a third way. Envelope parses without crashing for all ops 0–7 but always answers -45018 invalidInputDataParamHeader (0xffff5026 — an arithmetic correction: -45026 emptySession is 0xffff501e, never observed here): the shape passes the flags check but fails header validation, so session content is never even read. Chaining cvu-init into the envelope (BC) changes nothing — still -45018. The repr(C) invocation layout (`args/u32-sizes/command@+0x10/flags`, inner with dsId/spim/session/cpim slots, offsets compiler-pinned by `offset_of!` tests) parses for commands 0–10 with both flag values — always -45018, never a write. The vovan2200 DataPacket (`first` int32 + 7 pad + five arg slots at +0x20, wrapped in MainContext{packet,res,crc}) with OTP-shaped args returns -45034 for every first-word 0–5 and both magics: without outer sizes the flags check fires first. Wrapping the same packet in the B envelope (DB: outer sizes + packet args) moves every first-word to -45018 — sizes pass the flags gate, content fails header validation. Split-arg variants (DP2/DP3: ctx/packet split across rcx/rdx) still return -45034, DF (ctx wrapping the flat block) dies like the other wild-pointer arms. The vovan2200 structs (DataPacket/MainContext, OTP-shaped args) come from a 4PDA RE post whose Frida attachment sits behind a login wall; the post's example call bytes match our shape byte-for-byte in layout. Calling the op twice in one process changes nothing (second call: same code, zero new .data bytes — no cross-call accumulation). New codes mapped by decode: -45041 (0xffff500f) ×1, -45035 (0xffff5015) ×10, -45028 (0xffff5024) ×14 — all unlisted in prior tables. Ghidra sees only 24 of the 438 table consultations (plus 8 to the second table, 0 to the post-gate file routines) — analyzer blindness on flattening, quantified. Next milestone per the enum order (header → function → body): -45019 unknownAdiFunction (0xffff5025, site decoded at 0xb5b21), reachable only past a valid header. P-code map (Ghidra listing): 27 loads + 28 stores total, all within 0x5afc0–0x66c1f — the analyzer discovered no instructions past ~0x66xxx, so the validator region (0xb15xx) has no function and no P-code; force-disassembly of the gaps is the remaining RE step. ZF forced to 0 inside the envelope arm still returns -45018; r9d canaries (1/FF/FFFF/FFFFFFFF/12345678) never move it: the outcome gates on missing provisioned state, not on any forgeable input — valid header unobtainable offline, proven over ~200 surgical probes. The -45018 validator itself is decoded (anchored Capstone from 0xb151d, INT3-proven live): four byte-reads `MOVZX r32, byte [RCX+idx]` at 0xb151d/51/a1/c8 with per-byte xor/and masks, OR-folded into r9d with exit via computed `jmp rdx`; removing any single OR keeps -45018, so the gate needs an exact state match — unforgeable without the target values. Watchpoint tracing (`examples/watch.rs`: mprotect + SIGSEGV handler) attributes first touches precisely: envelope[+0xc] written at 0x5b1cf, inner[+0] byte-read at 0xb151d (`MOVZX EBP,[RCX+RDX]`, RDX=0) with full register context. Live spim bytes placed inside inner change nothing — content is never the discriminator.

**Driving a multi-call session.** The CoreFP caller is a session, not a single call (§ below), and the CLI ships two ways to reproduce that shape. `perun seq <dll> <export> --script=FILE` loads the image once, runs `DllMain` once, then drives a script of calls in the same process so guest state carries between them; its verbs are `load NAME FILE`, `poke TARGET VALUE` (target = `scratch+OFF` | `ctx+OFF` | RVA), `call [EXPORT] A0 A1 A2 A3` (arguments are tokens — buffer names, `scratch`/`ctx` with optional `+OFF`, or numbers; the export defaults to `vdfut768ig`), `zero scratch|ctx`, and `dump` (every non-zero qword of scratch and ctx). The single-call path gained the same buffer primitive as `perun call --load=NAME=FILE`, which reads a file into a fresh guest-visible mapping and registers NAME as a token, plus `PERUN_SEQ=N` to repeat one identical call in-process. Options are collected before any value resolves, so a buffer name is usable as a `--poke` value regardless of where its `--load` sits on the command line. The cost of that ordering: a malformed `--poke` value is rejected only after the whole command line is parsed, and `--poke-ptr` writes land in resolution order rather than typed order. Verified against `CoreADI64.dll`: one image load, `DllMain TRUE`, 111 shim APIs, and the export reaching the header validator (`0xffff5026`) with a spim-first parameter block.

**The caller (iTunes 12.13 distribution).** No PE imports CoreADI64.dll — it is loaded dynamically. The caller is CoreFP.dll (21 references to the loader-data cluster: `InstallDir`, both export names, the CoreADI registry key): a module-table loop calls LoadLibraryExW, resolves both exports via GetProcAddress, caches ror/xor-encoded pointers keyed at 0x7eaec148, and issues repeated calls through the decoded pointer with struct args (seven-call session shape). Struct bytes are computed at runtime through obfuscated arithmetic (no static initializer exists to screenshot); the hook point for live capture is the decoded-pointer call sites. The 8-call session cluster lives in CoreFP function 0x1b5da30–0x1b67b3d (65 KB, not an export — 6 exports total, nearest X46O5IeS @ 0x1ab7180; zero direct callers, reached via computed dispatch): eight calls through ONE resolved pointer (rsi set once), rcx varying per call (rdi/[rsp+0x78]/[rsp+0xd0]/rdi/rbp/[rsp+0x160]/rbx/r14) with rdx/r8/r9 constant from the parent frame — a session sequence, not a function multiplex. Consequence: vdfut768ig takes four live registers (RCX/RDX/R8/R9); our harness historically left R8/R9 zero. Sweeping R8/R9 (0, 1, pointers, sizes, header) in the envelope arm changes nothing — still -45018.

1. Obtain a real provisioning blob from a provisioned machine (`C:\\ProgramData\\Apple Computer\\iTunes\\adi\\`), then feed it to the loader — the direct oracle: it reveals every context field the dispatcher reads after the gate.
2. Replicate the server handshake (`fpinit.itunes.apple.com/v1/fpdi/init` + `/setup`) in the caller layer to provision a fresh machine, matching how the real app breaks the circular dependency. Requires GSA session tokens and the exact request format. Transport rules measured cell by cell and frozen in `crates/perun-cli/examples/fpdi_emul.rs` (local stub + live probe + self-check): GET on a known path → 405 JSON, unknown path → 404 JSON; POST on a known path → 500 Jersey HTML with the URI echoed unless Content-Type is present and not `application/json*` (edge 415 JSON); other methods → 403 Akamai HTML. Bodies never matter — every body shape 500s identically, so the entity format must come from the caller, not from probing. The GSA lane has its own door (`GsService2/lookup` → `MidService/startMachineProvisioning`, live 347-byte spim with no Apple ID); fpinit rejects the same plist — two different doors.

3. Reconstruct the context object graph: the gate object references sub-allocations reachable via the shipped `--peek-ptr`; mapping every field the validator touches would enumerate what a real blob must contain — expensive against control-flow flattening.
4. Grow the shim surface as real guests exercise more APIs (the trap reporter names each missing symbol with its arguments).
5. A `perun scaffold` command generates a ready-to-fill shim stub from a trap report: `perun scaffold '<trap line>'` parses the Win64 and SysV trap shapes — including the hint's quoted `DLL!func(args)` payload pasted back verbatim — and emits a compiling `win32_api!` skeleton with the observed arguments and the owning source-file hint. Both trap reporters name the command.

### 5.9 The StoreKit client lane (production use of this runtime)

The store lane turns the session above into a working App Store client (`perun store`, or the `ipatool` persona's strict grammar). Endpoint discovery is bag-driven: each session fetches `init.itunes.apple.com/bag.xml?guid=…` and reads `authenticateAccount`, `sign-sap-setup`, `sign-sap-setup-cert`, and `sign-sap-version` (the string `"200"`) from the `urlBag` sub-dict — hardcoded fallback defaults exist, but no request proceeds on a missing key. The signer runs the § 5.1 guest contract against the bag URLs and emits `X-Apple-ActionSignature` per signed body; login and the DAAP history call are the two signed call sites (§ 5.6).

Authentication is MZFinance password auth with out-of-band 2FA: the code the user receives by push/SMS is appended to the password on the retry round and signed fresh per attempt. One ambiguous shape: `MZFinance.BadLogin` with empty failureType and no code in play is a hard failure, but it does not prove wrong credentials — the correct password can draw it (with the 2FA code arriving anyway), so the error names the `--auth-code` retry path; the full failure mapping is unit-tested in `classify_auth_failure`. Pod redirects (3xx with `Location`) re-POST the original body without incrementing the attempt counter; shed load (204, 404, 5xx, 429 with `Retry-After`) backs off and resends up to three attempts. Credentials persist in an AES-256-GCM vault bound to the pinned machine address (PBKDF2-HMAC-SHA256, 100 000 iterations); `auth revoke` wipes vault and cookie jar, while session reset clears cookies only.

Search runs the public iTunes Search/Lookup APIs in the account's storefront country, with client-side scopes on top of the plain search: `--developer` (artist/seller name), `--id` (developer catalog by artist id), and `--description` (description text). Every `country=` parameter (search, both lookups, artist catalog, MDM/visionOS version resolution) derives from the login's `storeFront` — there is no region override flag or variable, so an app absent from the account's storefront (verified: US-only Hulu invisible to an RU account, `resultCount: 0` vs `1` for `country=US`) fails at lookup before any byte flows. Scopes probe at backend maximum and apply the requested limit after filtering. Purchase is free-license only (`price > 0` aborts); Arcade titles retry once under GAME pricing, and the known already-licensed shapes map to success.

Downloads survived the 2026 download migration through a three-stage fallback chain — legacy `volumeStoreDownloadProduct`, then DownloadDispatch `redownload` on an empty song list, then `updateProduct` on an empty-500 — with the latest external version id resolved per platform when the caller does not pin one (the MDM lockup API for tvOS, the `apps.apple.com` product page for visionOS, memoized per process). Bodies stream into a `.tmp` file behind a strict `Range` gate (206 continuation checks, 416-means-complete, a 200 after resume truncates the partial to 0 before the fresh body streams). Purchase history is a three-stage DAAP flow (login/update/items, the latter two SAP-signed), newest-first with page/max-results pagination.

The downloaded OTA stream is restreamed into a standard `.ipa` without ever being decompressed: local headers are rebuilt byte-identical (source extra preserved, with a ZIP64 block added when an entry overflows 32 bits), deflated entries gain a data descriptor (16-byte, or 24-byte with 64-bit sizes for ZIP64 entries), central-directory extras carry over with stale ZIP64 stripped and fresh structural values regenerated, and FairPlay `.sinf` blobs from `SC_Info/Manifest.plist` are injected per replication path, with `iTunesMetadata.plist` and `iTunesArtwork` added. Archives that overflow 32-bit sizes, offsets, or the 64K entry count emit real ZIP64 structures (ZIP64 EOCD + locator, `0xFFFFFFFF` placeholders) instead of truncating. Input is memory-mapped with sequential advise, so multi-gigabyte packages replicate at tens of megabytes of RSS; the custom pure-Rust inflate serves only the small metadata reads. macOS `.pkg` downloads and paid apps are explicit errors, not silent gaps. The README owns the command grammar; this section records the wire behavior underneath it.

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
| Peak RSS (`ru_maxrss`) | 225.1–252.8 MiB (mean 234.4 MiB) | 27.0–27.3 MiB (mean **27.1 MiB**) |
| CPU time, user + sys | 7.42–7.53 s (mean 7.46 s) | 0.074–0.107 s (mean **0.083 s**) |

**The two columns come from different sessions, so treat the ratios as an order of magnitude, not a measurement.** Perun was re-measured at N=10 on 2026-09-24 against the live endpoints; the oracle column is the 2026-09-02 session at N=3 and could not be re-run — its build vendors a pinned Unicorn 2.1.1 blob from `ghcr.io`, which now answers `401` to an anonymous pull, so the reference binary cannot be rebuilt in this environment without a registry token. Against those carried-over figures perun is ~35× faster on wall clock, ~89× on CPU and ~8.6× smaller on peak RSS. Every run in the fresh perun set exited 0 and produced the 501-byte signature.

Both sides talked to the live endpoints during every run of their own session. The stock oracle's wall and CPU include a full asset fetch on every run — upstream `sapsigner` ships no cache, so each run re-streams the same ~32 MB tail slice of the public package that perun fetches once and keeps (§ 6.4). Perun's figures are its warm path: images and certificate from the on-disk cache, one live protocol POST. Its 27.1 MiB peak is the guest mappings (~21 MiB), the resident ICXS blob (~5 MiB), and the runtime itself (~1 MiB); the oracle's is the Unicorn engine plus five mapped guest images.

### 6.4 Cold start and the two asset models

Both tools read the same ~32 MB tail slice of the public 1.28 GB update package (2.5% of it), but they pay for it differently. Perun pays once: the first run on a machine with no assets resolves the package's xar table of contents (a few KB), locates the compressed payload, range-reads the tail slice holding the commerce images, verifies all four SHA-256 pins, and writes the cache (~/.cache/perun/sap/ or $PERUN_SAP_DIR) — measured live on two days, **8.4 s and 8.1 s wall for ~32 MB** transferred. Every later run is warm; § 6.2 and § 6.3 are warm numbers. The stock oracle pays on every run: upstream ships no cache, so its 9.09 s mean wall in § 6.3 carries the same fetch each time. The measured tail geometry (block boundary, cpio prefix skip) is pinned in perun's fetcher and re-validated per run by the same SHA-256 constants the loader enforces, so a changed upstream layout fails loudly instead of producing a bad mapping.

### 6.5 Comparative table

| Tool | Engine | Whole-process cost (this host, N=3) | Deps |
|---|---|---|---|
| Perun (this work) | native Mach-O projection | 0.259 s wall / 0.083 s CPU / 27.1 MiB peak (warm) | pure Rust + libc |
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
| 20 | Multi-call session driver: one image load, one `DllMain`, scripted calls in one process; `--load` buffer usable as a token in any option order; `PERUN_SEQ=N` repeats one call in-process | `perun seq … --script=FILE`, `perun call … --load=NAME=FILE`, `PERUN_SEQ=3 perun call …` | Confirmed (DllMain TRUE, 111 shim APIs, spim-first block reaches the header validator at `0xffff5026`; three repeats execute in one process) |

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

The dependency set (Cargo.lock), with licenses read from each crate's own manifest. The split matters for compliance scanners (FOSSA, Black Duck) and for NOTICE obligations under Apache-2.0/MIT, which attach to code compiled into the distributed binary (object form):

**Runtime — compiled into the `perun` ELF:**

| Crate | Version | License | Author / repository | Role |
|---|---|---|---|---|
| `libc` | 0.2.189 | MIT OR Apache-2.0 | The Rust Project (rust-lang/libc) | host libc ABI: mmap, sigaction, ucontext, wait4 |
| `linkme` + `linkme-impl` | 0.3.37 | MIT OR Apache-2.0 | David Tolnay (dtolnay/linkme) | `distributed_slice` — the shim-table registration macro; the emitted linker sections and runtime slices land in the binary |
| `bzip2-rs` | 0.1.2 | MIT OR Apache-2.0 | Paolo Barbolini (paolobarbolini/bzip2-rs) | pure-Rust bzip2 decoder in the first-run asset fetcher |
| `crc32fast` | 1.5.1 | MIT OR Apache-2.0 | srijs (srijs/rust-crc32fast) | checksum primitive under bzip2-rs |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 | Alex Crichton (rust-lang/cfg-if) | conditional compilation under crc32fast |
| `tinyvec` | 1.13.2 | Zlib OR Apache-2.0 OR MIT | Lokathor (Lokathor/tinyvec) | small-vector abstraction under bzip2-rs |
| `memmap2` | 0.9.11 | MIT OR Apache-2.0 | Dan Burkert, Yevhenii Reizner | memory-mapped IPA input in the streaming replicator |

**Compile-time only — executed by rustc during the build, absent from the binary:**

| Crate | Version | License | Author | Role |
|---|---|---|---|---|
| `proc-macro2`, `quote`, `syn` | 1.0.107, 1.0.47, 3.0.5 | MIT OR Apache-2.0 | David Tolnay | macro machinery behind linkme's `distributed_slice` |
| `unicode-ident` | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | David Tolnay | identifier tables for the macro crates |

All runtime licenses are MIT, Apache-2.0, or Zlib — permissive and compatible with the Apache-2.0 terms perun's own code is distributed under. The crates are consumed from the crates.io registry, not vendored; their license notices live in each crate's registry payload. The NOTICE file mirrors the runtime set for anyone distributing binaries.

## 9. License and Revision History

**Documentation license.** The reverse-engineering documentation, protocol analysis, and architectural research in this file are licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). The code implementation is licensed separately under the Apache License 2.0 with a NOTICE file (see the repository root).

**Revision history.**

| Date | Revision |
|---|---|
| 2026-09-01 | Initial public specification. Protocol closed end-to-end (init → exchange ×2 → sign, 501-byte signature) since 2026-08-31; all facts re-verified against binaries and live endpoints on 2026-09-01 (symbol-table audit, FS/GS census + poison experiment, cert re-fetch, benchmark re-run). |
| 2026-09-02 | Optimization pass + zero-config fetcher. Streaming image loader (full image bytes never materialized; peak RSS 26.8 MiB), storeagent dropped from the mapped set (bind-graph cross-reference, live-verified), speculative certificate fetch with a 24 h on-disk cache, and a first-run asset fetcher that range-reads ~32 MB of the public 1.28 GB update package (8.4 s cold start, all digests pinned). |
| 2026-09-03 | Benchmark hardening. Both sides re-benched against their public, unmodified artifacts: the oracle re-cloned from GitHub (commit 883ede5) and built with its own upstream Makefile (vendored Unicorn 2.1.1), perun as the shipped release binary. Per-round exchange rows retired — the stock oracle prints no phase timers and perun's release carries none for the split, so the public table now reports SAPExchange as the single combined Round 1 + Round 2 window and compares the oracle at the process level only (wall / CPU / peak RSS, N=3 per side, kernel rusage). Superseded instrumented figures (per-phase oracle timings, per-round exchange splits) removed; § 6.6 reproduces every number with one command per side. Third-party credits trimmed to what the law and the analysis actually require: NOTICE and § 8.1 now list only code compiled into the binary (runtime vs compile-time split, with unicode-ident's dual license kept distinct), and § 8 keeps the projects the work measured against or built on. Release profile hardened: no DWARF, stripped binaries, no build-host paths in distributed artifacts. |
| 2026-09-07 | Storefront-path additions from the live StoreKit client lane (built on this runtime, E2E the same day: login+2FA → search → purchase → download). New § 5.6 maps which requests the action signature actually gates (login body and the DAAP history body — and nothing else on the storefront surface; purchase/download ride the session cookies+token). New § 5.7 records the 5005 account-state lesson: the code covers both invalid-2FA and unprovisioned-account, and ToS acceptance on any Apple web property flips the same flow to a working login. § 7 gains the 2026-09 Rust-rewrite family (ipatool-rs) and this work's StoreKit client status. |
| 2026-09-07 | Unified specification: the Phase-1 document (STATUS.md) merged into this file and retired. The ADI/PE32+ lane is now first-class here — § 2.2 (CoreADI64.dll ground truth), § 4.7 (Win32 runtime invariants: FakeTEB/ARCH_SET_GS, 111 shims, absolute-jmp trap stubs), § 5.8 (the provisioning-gate analysis: status 0xffff5016, the RVA chain 0x19dda0/0x17eca0/0x5b20f with key 0x4f7e9322, the circular fpdi dependency, the two-trampoline experiment, ways forward), and § 6.7 (the 19-row verification log with reproduction commands). All facts, addresses, and measurements carried over verbatim; nothing dropped. |
| 2026-09-19 | Store-lane specification and factual corrections. New § 5.9 specifies the production StoreKit client (bag-driven signer, MZFinance auth with 2FA and machine-bound vault, search scopes, free-license purchase, three-stage download fallback with per-platform version resolution, DAAP history, OTA restreaming with sinf injection); § 5.1 now distinguishes the bare `perun sap` legacy path from the bag-driven store path. Corrections against the implementation: guest-heap size prefix is 16 bytes (aligned `size_t`), not 8 (§ 4.1); `sysctl` returns −1 while only `sysctlbyname` zeroes `*oldlenp` (§ 4.5); the trampoline zeroes RBX/RBP/R10–R15 (§ 4.6); PE mapping is `MAP_FIXED_NOREPLACE` with fallback, relocations cover DIR64 and HIGHLOW (§ 4.7); the `scaffold` hint names a command that does not exist (§ 5.8). Dependency table: tinyvec 1.13.2, new memmap2 row, pinned proc-macro2/quote/syn versions (§ 8.1). |
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

*Apple, macOS, OS X, StoreKit, FairPlay, iTunes and related marks are trademarks of Apple Inc. This independent research project is not affiliated with, endorsed by, or sponsored by Apple Inc. All binary images referenced are obtained by users directly from Apple's public distribution servers and are never redistributed with this project.*