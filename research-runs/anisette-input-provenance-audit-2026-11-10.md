# Android Anisette input-provenance audit — 2026-11-10

Scope: the current `rnd/phase1-standalone-anisette` branch at parent
`3eb4241d673efe72e90dd6c682825c4f7beed068`. This audit inspects the
current source, not the claims in historical campaign entries. It keeps
the Android `libCoreADI.so` lane separate from the Windows
`CoreADI64.dll` experiments.

## Executive result

The current `body_a::generate_cpim` implementation is an oracle-backed
container assembler, not a function deriving CPIM from SPIM + identity.
Its pure in-memory packing function receives a depot assembled from
capture tapes and copies two fields from the reference CPIM. The SPIM
content is not consumed by the derivation; only its 347-byte length is
checked. The old `SessionInputs` also carried a hard-coded identity,
a planter dump and first-round feeds that the CPIM packing function never
read.

The source API is renamed to make this boundary explicit:
`OracleCaptureInputs::from_capture_dir` and
`assemble_cpim_from_oracle_capture`. Deprecated compatibility aliases
remain, so existing external callers are not broken immediately. This is
a naming/provenance correction, not a new cryptographic derivation.

## CPIM field provenance

| CPIM range | Length | Current source | Status |
|---|---:|---|---|
| `[0x00..0x04)` | 4 | BE integer 5 written by Rust | Structural constant observed from reference |
| `[0x04..0x14)` | 16 | Copied from `live_prov_out.bin[0x04..0x14]` | Oracle-derived; session algorithm not implemented here |
| `[0x14..0x18)` | 4 | BE integer 0xA0 written by Rust | Structural length constant |
| `[0x18..0xB8)` | 160 | `generate_body_from_tapes`: ten rounds assembled from `zone26_tape.txt`, `sel34_tape.txt`, baked zone files and measured mixer rules | Mixed: arithmetic is in Rust, but selectors/feeds and ten M14 post-tail bytes remain capture-derived |
| `[0xB8..0xD8)` | 32 | `generate_digest_from_tapes` + `generate_digest` | Arithmetic is in Rust; candidate words are selected by matching their sums to the reference CPIM, so selection is oracle-anchored |
| `[0xD8..0xDC)` | 4 | BE integer 0x34 written by Rust | Structural length constant |
| `[0xDC..0xE0)` | 4 | BE integer 4 written by Rust | Structural version constant |
| `[0xE0..0x114)` | 52 | Copied from `live_prov_out.bin[0xE0..0x114]` | Oracle-derived; Body B algorithm not implemented here |

The 192-byte depot is not generated from raw SPIM by the current public
capture path. Its first 160 bytes are reconstructed from measured tapes;
the last 32 bytes use a CPIM-anchored resolver. The depot-to-CPIM unloader
law is a separate measured property and does not generate the depot.

## Input and artifact ledger

| Input / artifact | Read or produced by | Consumed by current CPIM assembly? | Provenance / limitation |
|---|---|---|---|
| Captured SPIM | `OracleCaptureInputs::from_capture_dir` | Length only | Exact bytes are retained for the live runner's equality check, not used to derive CPIM bytes |
| Fresh SPIM | `examples/live_provision.rs` | Compared with captured SPIM | Prevents sending the old capture after SPIM rotation; does not prove every tape came from that same SPIM |
| Identity | Previously hard-coded in `SessionInputs::from_tapes`; also constants in network runner | No | Not an input to the old packing function; no identity-to-CPIM derivation demonstrated |
| `planter34.bin` | Previously read by `SessionInputs::from_tapes`; separately used by weave parity test | No, not by CPIM packing | Session planter genesis is still unresolved; remove from the CPIM input struct rather than imply consumption |
| `sel34_tape.txt` | Body-A tape backfill; separately parsed by `RoundOneFeeds::from_sel_tape` | Yes, in body-A assembler; parsed `RoundOneFeeds` field itself was unused by the packer | Tape values are measured inputs, not derived from SPIM in this path |
| `zone26_tape.txt` | Body-A assembler | Yes | Same-session capture convention; not independently cryptographically bound to SPIM |
| `pair_wp_words.txt` | Digest resolver | Yes | Candidate word selection consults reference CPIM sums |
| `pair_depot.bin` | `read_paired_cpim` guard | Indirectly | Confirms first 192 bytes match CPIM `[0x18..0xD8)`; it does not authenticate every input tape |
| Baked `fam*_zone.bin` | `Zones::from_files` fallback | Yes | Source comments claim load-stable/cross-session; this is a measured invariant, not a proof of planter genesis |
| `live_prov_out.bin` | Capture loader and digest resolver | Yes | Supplies session16, Body B and target sums used for word resolution |

The previous `SessionInputs` fields `planter` and `feeds` were never read
by `generate_cpim`; `identity` was a hard-coded string and also unused.
They have been removed from the active container input type. The
`RoundOneFeeds` tape parser remains as a diagnostic helper, but is no
longer presented as a required field of the CPIM packer.

## Separate Windows-side chain

`chain.rs::generate_cpim` is a different experiment and must not be
folded into the Android graph. Its `Entry::measured()` uses a fixed
measured frame/register vector and four measured T-table words; the
SPIM argument is length-checked, not used to derive this entry. Without
an `early` drive, Body A and digest are zero placeholders, the 16-byte
session block is `REFERENCE_SESSION`, and Body B is 52 zero bytes.
The parity test demonstrates a measured word chain and CPIM anatomy,
not fresh SPIM + identity to CPIM.

## Tracer / trace #94 correction

The v33 tracer source installs 16 mixer-read breakpoints and counts
writer callback entries separately from callback sampling/errors.
Trace run `42372297431` did not reach the first mixer read, had no
slot-anchored capture and did not observe the trace-only
`ProvisioningStart` return. The separate native non-GDB control did
return `rc=0, cpim_len=276`. These are separate executions; they must
not be described as one run that generated CPIM while skipping all mixer
reads. The candidate snapshot's low uniqueness counts are an early
candidate capture, not a final planter measurement.

The tracer's source docstring still says v30 while its emitted run
manifest says v33; `tools/planter_trace.md` also has a v30 opening
paragraph followed by later v32 details. This is documentation drift,
not proof that the run used v30.

## CI meaning

`.github/workflows/ci-gate.yml` runs workspace clippy and workspace
tests. Capture-dependent end-to-end tests are ignored/gated because their
private tapes and reference artifacts are not in CI. A green generic CI
therefore checks compilation and unit-level arithmetic; it does not
establish fresh-session autonomy or live provisioning acceptance.

## Next falsifiable work

1. Build a per-capture manifest binding library hash/build, exact SPIM,
   identity, state seed, CPIM, and each tape/snapshot. Keep raw secrets
   and device/session material out of committed reports.
2. Make the tracer prove the execution path in a single process:
   positive-control breakpoints, PC/load-bias/opcode records, hit counts,
   all mixer-read samples, and the trace-process ProvisioningStart return.
3. Find the first differing state in repeated fixed-input CPIM runs;
   do not assume time, RDTSC, ASLR or randomness until the relevant
   intercept/site hit is observed.
4. Restore the producer/dataflow chain for planter and feeds from
   actual consumer reads back to SPIM/identity or a measured additional
   input. Treat `source+0x20` as a same-run relationship unless proven
   across builds and sessions.
5. Recover session16 and Body B producers independently; remove the
   CPIM-anchored digest candidate selection; then test a genuinely new
   SPIM session without tapes or reference CPIM.

## Status labels

Use these states consistently:
- **Observed** — present in one trace or capture.
- **Reproduced** — repeated under controlled inputs.
- **Explained** — dataflow/algorithm and input provenance are established.
- **Independently implemented** — Rust computes it without oracle-derived
  intermediate values.
- **Accepted live** — the backend accepts the fresh-session result.

A byte-parity result from one captured session must not be promoted to
"autonomous" without satisfying the later states.
