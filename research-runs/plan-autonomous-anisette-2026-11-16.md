# Final plan — replace the Apple ADI engine with an independent Rust implementation (Android lane)

Date: 2026-11-16 · Branch: `rnd/phase1-standalone-anisette` · Status: active campaign plan

Synthesised from six independent review opinions (2026-11-16) plus the repository's own
audit trail (`anisette-input-provenance-audit-2026-11-10.md`, RESEARCH.md §5.11f–h and the
2026-11-13 strategy correction). Every claim below is anchored to code, a measured RVA/opcode,
or a run already in `research-runs/`.

## 0. What "replace the ADI engine" means, exactly

The Anisette headers are NOT produced by CPIM assembly. The producer is `ADI_OTPRequest`
(`qi864985u0`) running over the persisted state file (`adi.pb`):

| Stage | Export | Dispatch opcodes | Rust status |
|---|---|---|---|
| ProvisioningStart | `rsegvyrt87` | `0x716bd86c` | oracle-anchored assembler (CPIM anatomy, depot unloader, body-A mixer math, digest arithmetic are real; session16, Body B, WeaveFeeds transition, mixer-14 pre-tail, digest word producers, `expand_planter` are not) |
| ProvisioningEnd | `uv5t6nhkui` | `0x0b2b3196` | nothing |
| OTPRequest | `qi864985u0` | `0xcfe0b46a`, `0x3e58e7f9` ×2 | nothing |
| GetLoginCode | `aslgmuibau` | status check | protocol-level only (not needed for tokens) |

Two distinct "autonomies", tracked separately:

- **Warm autonomy (product):** provision once (oracle or Rust), then a pure-Rust
  OTPRequest over `adi.pb` produces `X-Apple-I-MD` / `X-Apple-I-MD-M` forever.
  This is what anisette servers actually need. Does NOT require planter genesis.
- **Cold autonomy (research frontier):** Rust performs the full
  Start→End→OTP cycle from a fresh SPIM and Apple accepts it (`ec=0`).

Both are in scope (the stated goal is full engine replacement); warm-first because it is
the shortest path to a shippable deliverable and is the author's own 2026-11-13 correction.

## 1. Ground truth established on 2026-11-16 (local rig)

The capture rig was rebuilt locally and the full live cycle succeeded on the first run:

- Apple Music 4.9.6 APK (136 MB, sha256 `9aab4e3bfd44b509…`) → 18 x86_64 libs
  (`libCoreADI.so` 1,596,128 B; `libstoreservicescore.so` 2,391,768 B).
- Android x86_64 system image `x86_64-21_r05` → Bionic sysroot (linker64 + 195 libs) via debugfs.
- NDK r27c (`android-ndk-r27c`, clang 18.0.3) builds the harness.
- Apple trust anchors verified against the CI-pinned SHA-256 fingerprints
  (`b0b1730e…`, `63343abf…`).
- Live run: GSA lookup 200 (25,682 B) → startMachineProvisioning 200 (1,109 B) →
  SPIM 347 B → CPIM 276 B (session=1827188078) → finishMachineProvisioning 200 (1,440 B)
  → ptm/tk → ProvisioningEnd rc=0 → `GetLoginCode=0` → OTP minted. Exit 0.

Consequences: captures no longer depend on CI, `ADI_CAPTURE_AGE_RECIPIENT`, or GDB;
the multi-session corpus can be grown locally under the usual privacy rules
(0700 dirs, 0600 files, raw bytes never committed — hashes/sizes only).

## 2. Gate 0 — determinism (blocks everything differential)

Replays with fixed inputs still differ in ~207/276 CPIM bytes while Body B is stable
(run #106/#111 lineage). Only `gettimeofday` was frozen; `getrandom`, `/dev/urandom`,
`clock_gettime`, vDSO, `getpid/gettid`, ASLR and stack junk were not controlled.
Method (from the reviews, adopted as-is):

1. **Full entropy freeze** as a native ptrace tool (NOT gdb — hw-watchpoints crash on
   Bionic, and vDSO never raises syscalls):
   - child spawned with `PTRACE_TRACEME` + `personality(ADDR_NO_RANDOMIZE)`;
   - `getrandom`, `openat(/dev/urandom)` + reads → deterministic stream;
   - `clock_gettime`, `gettimeofday`, `time` → fixed epoch;
   - vDSO pages patched after execve (COW via `PTRACE_POKEDATA`);
   - `getpid/gettid` → fixed values;
   - per-source **hit counters reported** — a zero-hit freeze is not a controlled source.
2. **Bisection per source**: freeze one source at a time; a collapse of CPIM/OTP variance
   identifies the causal input. Reject the hypothesis `session16 = RNG` or confirm it.
3. **Warm seed correctness**: replay seeded with the exact post-End state
   (`adi-state-after-end.bin` + identity), not a mutated `WORK/adi-data` after OTP probes.

Acceptance: on a fixed warm state, N ≥ 5 replays produce byte-identical CPIM (276/276)
AND byte-identical MID (60) / OTP (28). Any residual drift = named uncontrolled source.

## 3. Track A — lift `OTPRequest` (first deliverable)

Smallest surface: warm `adi.pb` (fingerprint-stable across OTP calls per run #121),
outputs 60+28 B, dispatch opcodes known. No planter, no network needed for parity.

1. **Behavioural matrix** (existing `ADI_CAPTURE_DIR` + `ADI_OTP_REPEAT_PROBE`):
   same state × {t+0, +1s, +31s, +62s}, across ≥3 independent warm states, frozen-time
   runs, restored-state reruns. Classify: MID static per provisioning? OTP = f(state,
   time) or f(state, time, counter) or f(state, entropy)? (state fingerprint stability
   already excludes a persisted counter).
2. **Whole-function dynamic trace** of the OTP dispatch region (0xcfe0b46a + 2×0x3e58e7f9):
   batch instruction trace (ip+regs) over the call, then backward def-use from the
   final stores to the 60/28-byte output buffers. Tools: new ptrace batch tracer
   (`tools/adi_step_trace.c`) with a Python def-use analyser; gdb only for spot anchors.
3. **Lift to Rust**: `perun-adi-core/src/state.rs` (adi.pb reader: which bytes are read)
   and `perun-adi-core/src/otp.rs`. Captured registers/memory may be the TEST oracle,
   never the production input.

Acceptance: byte-exact MID(60)+OTP(28) vs native, on ≥3 independent warm states × ≥3
time points, both in-process replays and fresh-process replays. Then a live GSA request
with Rust-generated headers on a state provisioned by the oracle.

## 4. Track B — `ProvisioningEnd` + `adi.pb` format

1. Trace `uv5t6nhkui` (0x0b2b3196) from entry to the state-file write on disk;
   capture which bytes of session/ptm(487)/tk(16)/identity flow into which output bytes.
2. Resolve the `session: u32` returned by Start into the actual internal StartContext
   (the saved handle is NOT the context; take End's real read-set).
3. Rust serializer for the state. Cross-validation both ways:
   - Rust-produced `adi.pb` fed to native OTPRequest → byte-identical MID/OTP;
   - native-produced `adi.pb` fed to Rust OTPRequest → byte-identical.
   A pragmatic note (opinion #6): byte-compatibility with Apple's disk format is useful
   for hybrid testing but the end product only needs Rust-End ⇆ Rust-OTP agreement on a
   versioned own format. Apple disk-format fidelity is NOT a hard requirement.

Acceptance: two-way parity as above, plus load/save round-trip invariance.

## 5. Track C — Start/CPIM genesis (cold autonomy; runs in parallel)

Per-byte GDB reverse is retired as the primary method (traces #95–#111 proved it:
CFF produces many equivalent blocks per logical write and routes per-session). The
replacement is whole-function batch trace + automated def-use lifting over a
multi-SPIM corpus:

1. **Planter genesis** (`expand_planter(spim, identity)`): trace the phase between
   transform entry (0x87554) and the mixer phase (0xE6B54), covering the five known
   writers (`0xE2441`, `0xE2508`, `0xE25C2`, `0xE26AA`, `0xE24C9`) and the fam1 source
   producer `mov [rbp-0x11a8], rcx @0xdd511`. The value-transforms are bijective
   (fam1 x^0x3B, fam2 x^0x67, fam3 (x^1)+0xC7), so permutation structure comes from the
   SOURCE — lift the producer of `[rbp-0x11a8]`, not the per-window relabels. Corpus:
   ≥3 fresh SPIMs × ≥3 identities (explains sparse-vs-256/256 window variance).
   SiMBA/Z3 reduction over the linearised slice (pattern after `tools/transpile_simd.py`).
2. **Six oracle-anchored boundaries to close**, each with its own differential test:
   (a) WeaveFeeds 11-word round transition; (b) mixer-14 pre-tail input (remove the
   `if mixer == 13 { Some(inp.mul) }` tape feed); (c) 8 digest word producers (anchor
   measurement on the eight block stores, not on post-write register snapshots matched
   against reference CPIM sums); (d) session16; (e) Body B (52 B); (f) planter windows.
3. Final form: `generate_cpim(spim, identity, state)` with zero reads of reference
   CPIM, tapes, or captured planter; `selectors()`/`WeaveFeeds` on the production path.

Acceptance: byte-exact CPIM on ≥3 fresh SPIMs not used during formula derivation,
plus a live `finishMachineProvisioning` `ec=0` with a Rust CPIM for a fresh SPIM.

## 6. Track D — integration + live verdict

- API: `perun-adi-core`: `provision(identity) -> state`, `otp(state) -> MID+OTP`;
  CLI `perun anisette` serves headers with NO libCoreADI.so / Bionic / C stand in the
  runtime path (the Bionic oracle remains as an explicitly invoked research tool).
- Live ladder per stage: cold provisioning → fresh-SPIM CPIM accepted (ec=0) →
  Rust End → Rust OTP → a real GSA sign-in consuming the headers.
- Final acceptance run happens in a clean environment where the Apple `.so`s, Bionic
  linker and capture dirs are physically absent.
- Server-side notes that shape the live harness (Oct–Nov 2026): `X-Mme-Client-Info`
  platform must match the ADI platform (Android lane = Android profile);
  `gsd.apple.com` rejects `text/x-xml-plist` (use `text/xml`); `apptokens` developer
  flow has separate platform checks. Not blockers for this lane, but avoid misreading
  edge-403 as a crypto failure.
- CI split: offline golden vectors (committed, from the private corpus, as
  sizes/hashes with raw kept private) as the regression gate; live smoke as an optional
  manual job (rate limits / WAF).

## 7. Standing rules

- Evidence ladder: Observed → Reproduced → Explained → Independently implemented →
  Accepted live. Only the last two count as progress toward the goal.
- No oracle-anchored selection in the product: digest sum-matching, session16/Body B
  copies, mixer-14 tape feeds must die before integration.
- One instrument, one variable: every capture binds library SHA, identity, SPIM,
  state, CPIM, tapes, MID/OTP in the private manifest; public reports carry only
  sizes/hashes/RVAs/opcodes/counts.
- Byte-parity with the oracle ≠ acceptance by Apple. Track the ec/live ladder separately.
- Known traps: Bionic gdb hw-watchpoint crash (use ptrace tools), loader-deadlock
  under held linker-mutex (container restart), two-libc boundary (oracle stays a
  separate process in its own mount namespace), vDSO invisible to syscall tracers.

## 8. Instrumentation built for this plan

- `tools/adi_freeze.c` — native ptrace entropy freezer with per-source hit counters (Gate 0).
- `tools/adi_step_trace.c` + `tools/step_trace_defuse.py` — whole-function batch
  instruction tracer (ip+regs) and offline def-use analyser for Tracks A–C.
- Existing: `adi_lifecycle_trace_gdb.py` (entry/return correlation), JSONL validators,
  `capture_manifest.py` — retained for the capture contract, now driven by local runs.

## 9. Sequencing

| Order | Item | Gate |
|---|---|---|
| 0 | local rig (done 2026-11-16) | live ec=0 |
| 1 | Gate 0 freeze + bisect — **DONE 2026-11-16**, see `research-runs/gate0-determinism-2026-11-16.md` | N≥5 byte-identical warm replays ✅ |
| 2 | Track A: OTP matrix → trace → lift | byte-exact on ≥3 states × ≥3 times |
| 3 | Track B: End trace → state format → lift | two-way parity |
| 4 | Track C: planter genesis → six boundaries | CPIM without reference inputs |
| 5 | Track D: integration + live verdict | GSA sign-in with pure-Rust headers |

Tracks A and B are strictly sequential in verification (A's read-set maps the state
format B must write). Track C proceeds in parallel against its own criteria.
