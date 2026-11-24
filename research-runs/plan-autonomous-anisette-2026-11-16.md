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

---

## 10. Status and corrections — 2026-11-21 (measured, not re-planned)

This section supersedes any earlier row it contradicts. It is a status report on the
plan as written, not a new plan. Measurements are by replay of `gcore` checkpoints
on the Android `libCoreADI.so` oracle in Unicorn, plus direct inspection of
`crates/perun-adi-core` and `crates/perun-adi-bionic`. The plan text above is left
intact so the delta is auditable.

### Tracks, against evidence

| Plan item | Plan said | Measured now |
|---|---|---|
| Gate 0 | done | done (N=5 warm replays byte-identical; MID=f(state), OTP=f(state, epoch), 60 s quantum, entropy reads dead). |
| Track A, `OTPRequest` | "closed" (RESEARCH 2026-11-18) | **Not closed as specified.** §3.3 asks for `state.rs` + `otp.rs`; there is no `otp.rs`. What exists is `warmvm.rs`, an interpreter for a lifted IR of one captured execution, with libc call-site replays and 4.79 MiB of memory seeds. That is a trace verifier, not a generator. Its `otp()` only reads VM memory at `otp_addr`; I verified the OTP bytes are *not* pre-seeded there (`pre_seeded_equals_native=False` on all five cases), so the VM does compute them, but the computation is a transcription of the recorded stream, not an independent algorithm. |
| Track B, `ProvisioningEnd` + format | measured | `state.rs` implements the PERUNST v1 container and the Apple codec. There is **no Rust ProvisioningEnd** (`fp_dh_38fa04bb` is not lifted), so §4.3's two-way parity cannot be run yet. |
| Track C, Start/CPIM genesis | six boundaries open | SPIM anatomy and the Body B splice are closed. `session16` is entropy-derived but its KDF is not identified, so it is not implementable. The digest is assembled by comparing candidate words against the reference CPIM (oracle-anchored selection). The planter *window law* is now closed; the *producer* is not. |
| Track D, integration + live | live ladder | `perun adi-android headers` spawns `sudo unshare -m --propagation private` + the native `adi_native` with Apple's own libraries. §6's acceptance (clean env with no Apple `.so`, Bionic or capture dirs) therefore cannot be demonstrated today. |

### Corrections to specific lines

1. **§5.1, the value-transform model is wrong and must be rewritten.** It reads
   "the value-transforms are bijective (fam1 x^0x3B, fam2 x^0x67, fam3 (x^1)+0xC7), so
   permutation structure comes from the SOURCE — lift the producer of `[rbp-0x11a8]`,
   not the per-window relabels".
   On seven captured lineages every canonical window is exactly
   `w[i] = c ^ XOR_{k : bit k of i set} basis[k]`, with basis bytes of GF(2) rank 8.
   So a window is a full affine map with **eight** basis bytes, not a constant XOR
   relabel, and `w[i] = i ^ K` does not hold anywhere: the basis is *not* powers of two
   on any of A1, A2, B, C, D, E, F. The named constants also mismatch measurement:
   fam2's constant is `0x07`, not `0x67`; fam3's is `0x39`, not `(x^1)+0xC7`.
   The inference "permutation structure comes from the source" is backwards: replaying
   random arenas keeps the same affine law with the same constants but drops the basis
   below rank 8, and the tables then repeat. **Bijectivity is a property of the basis,
   not of the source.** The `[rbp-0x11a8]` producer is not the source of the windows:
   at the checkpointed instruction `0xDD511` (`mov [rbp-0x11a8], rcx`) the slot holds
   `0xd`, while the measured input is a 240-byte arena in `libCoreADI+0x19B600`.
2. **§5.1, the corpus design answers a non-question.** "≥3 fresh SPIMs × ≥3 identities
   (explains sparse-vs-256/256 window variance)". The sparse snapshots are the *pre-loop*
   dumps: at `0xDD511` the windows at `+0xC50`, `+0xD60`, `+0x1280`, `+0x1390`, `+0x1A00`
   are all zero and are trivially affine. Sample only after the loop tail `0xE26DE`.
   Identity is also not an input to this stage: the read census shows the stage reads
   the arena (240 bytes), its own frame (16 bytes) and static image tables, with zero
   reads of any identity buffer, and `arena == SPIM[8:248]` byte for byte.
3. **Window count.** "four 256-byte windows" / "five known writers" is stale. Seven
   windows are written by one-byte stores inside a single 256-iteration loop
   (`0xE1F74..0xE26DE`): the five canonical affine ones plus two extras. The fifth
   window at `+0x1F30` is therefore *proven canonical* by mechanism, which retires the
   earlier "a fifth S-box candidate, not a proven fifth member" note. Both extras are
   complete permutations on every capture and never obey the affine law.
4. **§3.3 names a file that does not exist.** There is no `crates/perun-adi-core/src/otp.rs`.
5. **§5.3's acceptance is not met.** `generate_body_from_tapes` still requires
   `zone26_tape.txt`, `pair_wp_words.txt`, `live_prov_out.bin`, and `pair_depot.bin`;
   `generate_digest_from_tapes` still selects candidates by matching the reference CPIM
   (oracle-anchored); `assemble_cpim_from_oracle_capture` still copies session16 and
   Body B from the reference CPIM. So "zero reads of reference CPIM, tapes, or captured
   planter" is not achieved.
6. **§7's standing rule is currently violated in code.** Digest sum-matching against
   the reference CPIM is still in `digest.rs`; session16 and Body B are still copied in
   `OracleCaptureInputs`; and `if mixer == 13 { Some(inp.mul) }` is still present at five
   sites in `body_a.rs` (lines 160, 472, 1054, 1302, 1520). Either those lines change or
   the plan must say plainly that integration has not started.
7. **§8 lists an instrument that is not in the repo.** `tools/adi_step_trace.c` is absent
   (only `step_trace_defuse.py` is present). Either it is restored or removed from the list.
8. **§6's CI split has no committed golden vectors.** The golden-vector regression gate
   named in §6 does not exist yet: the corpus-consuming tests are env-gated and skip in
   CI. That is also how `matrix3.rs` was able to fail on every run from `fb713f7` to
   `0ec829f`/`8a93d9a` before being fixed at `9010444`.

### What actually closed since the plan

- The arena slice is exact: `arena = SPIM[8:248]`, 240/240 across A1/A2/C/D, and only
  `arena[160:240]` reaches the windows (all 160 prefix bytes individually inert).
- The stage is a fixed straight-line circuit: 171 016 instructions, identical `RBP`/`RSP`,
  1852 frame stores and one SHA-256 of the executed PC sequence, identical for the real
  arena and for unrelated random arenas. The earlier reading of `0xDD946` as an S-box
  round is withdrawn: it sits inside the CFF dispatcher.
- The schedule is read back, not dead: 16 dword loads at `0xE0C1F..0xE117D` consume
  `schedule[0xB0..0xF0)`. Patching that slice moves 51 of 63 canonical parameters;
  patching `schedule[0x00..0xB0)` moves none.
- The cross-block coupling is one byte at `p ^ 3`, affine at 16/16 positions, with a
  linear part that depends only on `q % 4` and is identical across blocks, lineages and
  random contexts (four rank-8 tables). Only the affine constant varies with context.
- The canonical window law is closed: nine bytes per window, rank 8 on all seven
  captures, with a byte-exact `Window::from_params` round trip. `Params`,
  `Window::params`, `PlanterWindows::canonical_params` and `canonical_basis_ranks` are
  in the crate and gated by the corpus test.

### Remaining queue, in plan order

1. The fifteen round maps `R_b` that turn an arena block into a schedule block, i.e.
   `arena[160:240]` (80 bytes) → the 64 live bytes at `planter+0x18D0`. Everything after
   them is closed. This is the whole of the planter genesis still open.
2. Decide what Track A is: keep `warmvm` as a named trace verifier, or write `otp.rs`.
   Right now there is no Rust OTP implementation to validate.
3. Rust `ProvisioningEnd` serializer, then the Rust-End ⇄ Rust-OTP parity gate.
4. Track D's real acceptance: a run whose process contains no `libCoreADI.so`, no Bionic
   linker and no capture directory. The current CLI cannot pass it.
5. Restore or delete `tools/adi_step_trace.c`, and add the committed golden vectors §6
   calls for, so that a green CI run stops meaning "all parity checks skipped".

---

## 11. Planter implementation closed — 2026-11-22

The planter item in §10's Track-C row and item 1 of its remaining queue is now
**done**. `expand_planter(spim) -> Result<PlanterWindows, PlanterError>` is a
pure-Rust function in `perun-adi-core`; it takes no identity and reads no native
image, capture, clock or external state. `schedule_from_arena` and
`window_tables_from_arena` expose the intermediate boundaries for differential
tests and for synthetic, possibly non-permutation outputs.

The implementation is generated by `tools/transpile_planter.py` from the Android
oracle's executed streams (development only). It transcribes 3,092 shared-round
instructions, 1,138 setup instructions and one 479-instruction window body;
unsupported semantics fail generation. The production files contain no Apple
machine code, ELF, Bionic or capture dependency. Static, non-executable lookup
tables are Rust arrays. The original CFF dispatch is represented by structured
Rust control flow only where the executed successor was measured invariant.

Verification changes the §10 status as follows:

* schedule: byte-exact on A1/A2/B/C/D/E/F, 240/240 for every case;
* full expansion: byte-exact on all seven windows for every case, including both
  non-affine extras (12,544 window bytes total, zero differences);
* committed CI: three synthetic schedule SHA-256 vectors and three synthetic
  concatenated-seven-window SHA-256 vectors run without the private corpus;
* private inputs: the seven SPIM links and captures remain local `0600/0700` and
  are not committed.

This also corrects §10's shorthand "everything after them is closed": the tail
had a measured law but no producer implementation. It is now transcribed too,
so there is no remaining planter `R_b` or schedule-to-window task. The rest of
§10's queue is unchanged: independent OTP, Rust `ProvisioningEnd`, removal of
oracle-anchored CPIM/digest inputs, Track-D clean execution, and broader golden
coverage are still open. The planter goldens satisfy §6 for this component, not
for the whole ADI/Anisette corpus.

---

## 12. `session16` measured producer status — 2026-11-22

Track C's `session16` item is now decomposed but **not closed**. Full formulas,
validation counts and open gates are in `research-runs/session16-kdf-2026-11-22.md`.
The raw entropy/session artifacts remain local `0600/0700`.

* The final sixteen-store loop is isolated and byte-exact. It uses 83,566 dynamic
  instructions but only 457 unique PCs. Its entire input is the generated
  624-word state page plus `R14`, established by two-way transplantation.
* The 40-byte entropy draw initializes Bionic `arc4random`: ChaCha20 with a
  32-byte key and 8-byte IV, 1,024-byte buffer, reinitialization from its first
  40 bytes, and LE words from offset 40. The initial and next three native
  returns match this construction exactly on the sequential controlled draw.
* The 624-word MT19937-shaped initializer is measured, not guessed from standard
  KDFs. The exact initial recurrence matches 624/624 words; the 624-iteration
  first mix and 623-iteration second mix match all 50 captured snapshots each.
  The second loop preserves `i=2` from the first loop's wrap. The formulas and
  buffer-update masks are committed in the note.
* Plain digest/`init_by_array`/`seed_seq` candidates are rejected. The twist now
  reproduces the native post-twist state **on all 624 words** for the sequential
  draw; all first/second-loop stores and the final store match too. Exact opcode
  and matrix corrections are in `session16-kdf-2026-11-22.md` § 7.
* Output is still not closed: post-XOR `R14` is not reproduced at the session
  checkpoint from the same replay, held-out final-word parity/`y` state remains
  to be proven, and the fourth key-buffer slot is still open. No `session16.rs`
  or CPIM autonomy is claimed.

Next: reconcile replay/output and final-word parity on held-out draws, close the
fourth slot, implement `session16_from_entropy([u8;40])` in pure Rust with
hash-only CI goldens, then return to WeaveFeeds, mixer-14 and the eight digest
words. Track A's independent OTP and Track B's Rust `ProvisioningEnd` remain
open as stated in §10.

---

## 13. `session16` key/output reconciliation — later 2026-11-22

Two items marked open in §12 are now resolved, with the evidence boundary kept
explicit:

* The fourth key slot is `B(out1)`; the full native order is seed `A(out0)` and key
  `[B(out4), B(out2), B(out3), B(out1)]`. The pure-Rust `session.rs` implements
  the measured ChaCha/`arc4random` and seed/key component, including RFC and
  hash-only tests. It is not yet the complete `session16` generator.
* Correctly selected native twist-start checkpoints now replay through all sixteen
  session stores byte-exactly on sequential and `0xA5` (102,025 instructions, 457
  unique PCs each). The former post-XOR `R14` mismatch was an invocation-boundary
  error, not an additional missing output transform.

Track C is still open: the compact formula must work from raw entropy without a
captured twist checkpoint, including repeated-twist final-word behavior, matrix
parity and cursor state, then pass held-out `0x11`/`0x22`. Only after that gate
may `session16_from_entropy([u8;40])` replace the copied CPIM field. The remaining
queue is otherwise unchanged: WeaveFeeds, mixer-14, eight digest-word producers,
Rust `ProvisioningEnd`, independent OTP, and clean-environment integration.

---

## 14. Track C `session16` component closed — final 2026-11-22

The `session16` item is now **independently implemented**:
`session16_from_entropy([u8;40]) -> [u8;16]` in `perun-adi-core/src/session.rs`.
It has no production capture/native dependency. The final model contains:

* the entropy/ChaCha seed and four-word key schedule;
* 32 exact rounds of the first twist family (624/624 on every measured round);
* the `0xA65F9` family with general old-final-word upper/new-first-word parity,
  the executed final add and exact non-textbook temper MBA;
* the **120-byte predecessor** whose nonzero-advance rule derives the 31/32 (and
  potentially later) session boundary instead of accepting a captured count;
* the same nonzero-advance session output, including the measured 17-store/five-
  word reverse-sequential case and immediate termination at destination zero.

Acceptance for this component: 12/12 distinct native inputs and 13/13 captures
match byte-for-byte, including held-out `0x11`/`0x22`, both predecessor lengths
and both session store counts. Public CI uses twelve SHA-256-only goldens;
`PERUN_SESSION16_DIR` enables a separate full-byte private gate (12/12 green).
Workspace tests and Clippy are green. See `session16-kdf-2026-11-22.md` § 9.

This changes only the Track-C `session16` row. CPIM integration has not yet
consumed the function, and `OracleCaptureInputs` still represents the old copied
boundary. Next in Track C: WeaveFeeds, mixer-14 and the eight digest-word
producers, then zero-reference CPIM integration. Track A's independent OTP,
Track B's Rust `ProvisioningEnd` and Track D's clean-environment run remain open.

---

## 15. Mixer 14 shortcut removed — 2026-11-23

The mixer-14 item is now closed. The executed pre-tail formula is
`v = planter_1A00[x] ^ 0x8D`, `mul = low8(v²)`, followed by the ordinary lane-B
zone tail and `0xF2`. The legacy tape selector is `DH ^ 0x5D`, so no finalized
output byte is consumed. `mixer14_inputs` implements the boundary and all five
`Some(inp.mul)` exceptions have been removed from production and tests.

Verification: native pre-tail parity 10/10, private Rust differential gate 10/10,
hermetic synthetic unit test, workspace tests and Clippy green. The next Track-C
item is the WeaveFeeds transition. It is measured as one identical 2,546-PC
circuit per round on sequential and `0xA5` (624 reads, 86 writes, all 160 mixer
stores observed), but is not yet implemented. Digest-word producers and full
CPIM integration remain open; Tracks A/B/D are unchanged.

---

## 16. Digest answer-side oracle removed — 2026-11-24

The digest resolver no longer selects words by matching reference CPIM sums.
Three depot watchpoints yielded 24 real write events on each of sequential and
`0xA5`. Eight named post-store RIP/register pairs now construct `DigestInputs`
directly (`0xFBDFB/RCX`, `0xFBE18/W8`, `0xFBEC2/W6`, `0xFBF12/W2`,
`0xFBF85/W1`, `0xFBFFE/W3`, `0xFC044/W5`, `0xFC110/W4`).

`generate_digest_from_tapes` reads only the store-time tape, never the reference
CPIM. The old candidate loops were removed from production and ignored tests;
`read_paired_cpim` is test-only. Both captures pass 32/32 digest bytes, and the
new private gate passes 2/2. Synthetic fail-closed tests, workspace tests and
Clippy are green.

This closes the answer-side selection issue, not upstream SPIM/entropy genesis of
the digest state. WeaveFeeds and the initial mixer key-state are still required
before zero-reference CPIM integration. Tracks A/B/D are unchanged.

---

## 17. WeaveFeeds round circuit closed — 2026-11-24

The WeaveFeeds transition is now implemented in pure Rust as
`mixer::body_a(&mut MixerState) -> [u8;160]`. Sequential and `0xA5` execute one
identical 2,546-PC straight-line circuit per round, with two CFF jumps and no
calls/libc. `tools/transpile_mixer.py` validates both streams and ten static data
pages, then emits exact arithmetic and read-only arrays. It does not emit Apple
machine code, an image or capture reads.

The full private gate passes 2/2 inputs and 160/160 body-A bytes on each, covering
all ten rounds and all sixteen 16-byte heap blocks. Workspace tests and Clippy
are green. This is a generic algorithm over `MixerState`, not a CPIM playback or
answer-side candidate lookup.

The remaining Track-C boundary is the **genesis of `MixerState`** from
SPIM/entropy: 16 registers, the 0x6000-byte frame/key/planter state and 160 heap
bytes. The circuit takes that state explicitly, so it must not be mistaken for a
complete SPIM-only CPIM generator. M14, session16 and digest store-time selection
are already closed. Next: initial mixer genesis and zero-reference integration;
Tracks A/B/D remain open.

---

## 18. Capture-free CPIM over semantic state — 2026-11-24

`start::generate_cpim_from_state(StartInputs)` now produces the complete 276-byte
CPIM from a validated SPIM, 40-byte entropy draw, `MixerState` and
`DigestInputs`. It computes session16, all 160 body-A bytes and the 32-byte
digest, then splices Body B from SPIM. No reference CPIM, depot, zone/mixer tape,
Apple image or native process is read on the generation path.

The new same-run corpus proves **276/276 bytes on sequential and `0xA5`. An
initial 32-byte mismatch was a test-lineage error (mixer and digest captured in
different runs), corrected by atomically capturing core + watchpoints + CPIM.
Workspace tests and Clippy are green.

This completes the capture-free integration over explicit semantic state, not
its cold genesis. Remaining Track C: produce `MixerState` and the subsequent
digest state from SPIM/entropy. Rust `ProvisioningEnd`, independent OTP and
Track-D clean-environment acceptance remain open.
