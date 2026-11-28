# End tail: same-run provenance and an independent 34-block Rust circuit

Date: 2026-11-25 · Branch: `rnd/phase1-standalone-anisette` · Track: B

## Result

`end_tail::transform_tail` now executes the native 34-block transformation in
pure Rust over an explicit `TailState`. Two independent semantic states match
**544/544 output bytes each**. This is an independently implemented component,
not a complete `ProvisioningEnd`, not an Apple `adi.pb` serializer, and not a
`ProvisioningRecord -> CaseBundle` loader.

Production contains no Apple machine code or ELF/Bionic image, no capture reads
and no native subprocess. `end_tail_core.rs` contains 3,370 arithmetic
instructions; `end_tail_tables.rs` contains nine static non-executable 4 KiB
lookup pages. Private initial/final states remain under
`target/private-cores/end-tail` with mode `0700/0600` and are used only by the
env-gated differential test.

## Reproducible offline oracle

The development harness now accepts:

- `ADI_OFFLINE_SPIM=/path/spim.bin`, preserving the old Start-only mode;
- `ADI_OFFLINE_FINISH=/path/to/capture`, loading matching `ptm.bin` and `tk.bin`
  and continuing through End and OTP;
- `ADI_TRACE_END_ONLY=1`, stopping after End so a one-shot trace cannot re-arm.

Online and offline End paths share `complete_provisioning` and capture
`provisioned-at.bin`, a 16-byte native timespec measured immediately after the
call. `adi_state seal --capture` consumes that timestamp (explicit `--at` still
wins), and `open --capture` exports it again.

For the two inputs used here, offline Start reproduced CPIM/session exactly and
offline Start→End reproduced the native post-End state exactly. No network or
new provisioning attempt was needed. The relevant epochs are 1,794,997,800 and
1,794,999,600; the latter has a different SPIM/PTM/TK and identity.

## End call-path decomposition

The public export `uv5t6nhkui` is a 764-byte marshalling wrapper at
libstoreservicescore RVA `0x1c58c0`. Its measured public ABI is
`End(session: u32, ptm, ptm_len, tk, tk_len)` in `rdi/rsi/rdx/rcx/r8`.
At public End entry, 608 of 617 final state bytes are not yet present.

The useful boundaries are:

| Stage | Records | What the measurements establish |
|---|---:|---|
| `libCoreADI 0x170de0` | 437,589 / 437,611 | Produces the 544-byte region `state[0x35..0x255)`; leaves 20 later bytes for subsequent stages. |
| `libCoreADI 0x149170` | 52,066 per input | Identical PC stream on both inputs; changes 16 bytes at `state[0x255..0x265)` plus two 1,024-byte heap blocks. It is not the complete serializer. |
| Straight-line tail `0xbcece..0xc7e45` | 1,570, 524 unique PCs | Identical PC stream; changes the final four bytes at `state[0x265..0x269)` and reaches the state write call. |

The first `0x35` state bytes are produced earlier than the measured `0x170de0`
boundary. Their producer and the 16+4-byte trailer producers remain separate
work.

## From write watch to a small circuit

A software write watch on the 617-byte state buffer reduced `0x170de0` to 17
store sites and 1,086 events. The first site writes all 544 bytes consecutively.
The next sixteen sites cover sixteen residue classes with stride 16: 34 blocks
of 16 bytes. A one-byte perturbation at the second pass changes its containing
block and every later block, demonstrating forward chaining rather than 34
independent block outputs.

The repeated block circuit is exactly **3,370 instructions**. In a 7,002-record
stream, all 3,632 records after the first period repeat the preceding period.
Both independent inputs execute the same first-period PC stream. There are no
calls, conditional branches or libc operations in this circuit; only two CFF
`jmp` instructions are replaced by structured Rust control flow. Existing
`transpile_planter.emit` supports everything after the general addition of
`cmova`/`cmovb`.

## Semantic state and lineage

`TailState` contains:

- 16 initial GP registers;
- a `0x500`-byte frame;
- a `0x4000`-byte read-only dynamic heap region;
- a `0x5000`-byte relocated CoreADI RW region;
- 560 state bytes: 544 output bytes plus a 16-byte chaining/trailer input.

Eleven remaining lookup pages are genuinely static data. Relocated RW/GOT bytes
must not be copied from the ELF file: the first generator attempt failed at
`0x181c58` for exactly that reason and is superseded by the per-case RW state.
The final corpus captures trace, stack, heap and RW bytes in the same process.
An earlier mixed-lineage attempt with different frame bases was rejected by the
generator and is not used for parity claims.

The private gate is:

```text
PERUN_END_TAIL_DIR=target/private-cores/end-tail \
  cargo test -p perun-adi-core --test end_tail_corpus -- --nocapture
```

It passes 2/2 states and 544/544 bytes per state. Workspace tests, Clippy,
`test_planter_trace.py`, capture/lifecycle tool tests and C harness compilation
are green.

## Pre-tail is independent too

`end_pretail::transform_pretail` now closes the preceding 544-byte producer as
well. Its measured circuit is **137 instructions**, repeated 543 times, followed
by the final measured one-byte store. A 75,002-record capture confirms the
137-PC period through record 74,506; later divergence is the next native stage,
not another circuit. Both inputs have identical PC streams and match 544/544
intermediate bytes. Only one static lookup page is required.

The source and destination are distinct: `PretailState.source` is a read-only
544-byte region at native state offset `0x280`, while `PretailState.tail` holds
the output region at `0x35`. Executing 544 full circuits would incorrectly read
one byte past the source; 543 circuits plus the measured final store is the
exact output boundary. The generated `last_core` encodes that boundary without
clamping a memory error. `transpile_end_tail.py --mode pretail` shares the same
validated emitter and same-run state pipeline as the 34-block mode.

The private gate is:

```text
PERUN_END_PRETAIL_DIR=target/private-cores/end-pretail \
  cargo test -p perun-adi-core --test end_pretail_corpus -- --nocapture
```

Both pre-tail and tail gates pass 2/2 states and 544/544 bytes per state. The
intermediate snapshots also equal the independently captured second-pass input.

## Source-60 and a 384-byte direct copy — 2026-11-26

`end_source60::transform_source60` adds the first source-generation component:
42 arithmetic instructions, 59 full circuits plus the final measured store, and
**2/2 independent states at 60/60 bytes**. Destination is the native range
`0x7ffff78a22e8..0x7ffff78a2323`; the independent source range is
`0x7ffff780f25c..0x7ffff780f297`. Four static lookup pages are used.

The 42-record period holds through record 2,490; later instructions belong to
the next native stage. Executing the final full circuit would therefore be as
incorrect as in pre-tail, so `last_core` encodes the exact final-store boundary.

Two related producers were reduced semantically without a circuit:

- `0xcea3d` is a verified direct copy of **384/384 bytes** from the separate
  dynamic buffer `0x7ffff78d9180`.
- `0xcddf5` is the measured `index*0x73 XOR sil XOR four_source_bytes` stage;
  three sources are static image data and one is dynamic heap data. The formula
  matches consecutive native stores before the source-60 circuit was generated.

The initial wrong destination/source ranges (`22f4`/`f25d`) were rejected by the
Rust memory guard and corrected from all 60 effective addresses, not hidden by
widening the buffer. After a host restart reset `kernel.pid_max`, subsequent
oracle captures used a dedicated PID namespace and returned to the `admin` user
inside it; no global sysctl or production behavior was changed.

## Linked source-32 stages — 2026-11-26

`end_source32a` and `end_source32b` now implement two linked source stages and
pass **2/2 independent states at 32/32 bytes per stage**. The first uses 53
instructions (31 circuits plus final store) and the second 156 (31 plus final
store). A combined test also proves that A's output is B's input on both states.

Their native source/destination range is
`0x7ffff78a22a4..0x7ffff78a22c3`. Source-32a additionally consumes dynamic bytes
at `0x7ffff780f2a4..0x7ffff780f2c3`; source-32b transforms the first stage's
buffer in place. They use three static lookup pages and one static lookup page
respectively.

These stages required two model corrections, both caught by fail-closed tests:
their frame includes a parent region above RBP (`RBP-0x500..RBP+0x4000`), and
static lookup pages must be collected across all repeated circuits, not only the
first one. The generated core still contains only one circuit per stage.

## Third linked source-32 stage — later 2026-11-26

`end_source32c` continues the same buffer after source-32b and passes **2/2
states at 32/32 bytes**, with a separate B → C integration assertion. Its input
at `0x7ffff78a22a4..0x7ffff78a22c3` equals B's independently generated output on
both captures. The implementation executes a 3,416-instruction pass, the
measured 20-instruction bridge, then the same pass once more. Ten static
lookup pages are used; the shared emitter now also handles `movabs` and
width-limited `rol`.

A compliance audit also corrected the shared census: LEA computes an address
but does not read it, so its target must not contribute a lookup page. Removing
those false reads eliminated every executable-text page from all six generated
End table modules. Generation now fails closed if a requested static page lies
outside the read-only image region. The resulting current page counts are
9/1/4/3/1/10 for tail/pre-tail/source60/source32a/source32b/source32c; all byte
gates remained unchanged and green after regeneration.

The long trace corrects an earlier store-width description: the stage has
**sixteen unique byte-store RVAs, each executed twice**, not sixteen two-byte
stores. The two passes cover the first and second sixteen-byte halves
respectively, for 32 distinct byte positions total. The old source32b-only
captures stopped before this stage; two new same-run captures at `0x145d13`
provide identical 6,856-record streams on independent inputs.

## The 64-round tag subcircuit is independent — 2026-11-27

`end_tag_round::transform_tag_round` implements the repeated SSE component of
`0x149170`: **321 instructions × 64 rounds**, matching **2/2 states and two
1,024-byte buffers per state**. The exact circuit starts at `0x156780` and ends
before `0x156e7f`. A first capture at `0x15678d` was rejected because it was
three instructions into the period; recapturing at the real boundary gave two
identical 20,548-record streams with no period mismatch.

The semantic input contains sixteen GP registers, sixteen XMM registers, a
0x700-byte frame, 0x4000 dynamic heap bytes and 0x5000 relocated RW bytes.
Portable byte-lane Rust helpers implement the measured SSE semantics and have
synthetic unit tests. Six read-only lookup pages plus twelve sparse page-zero
ranges are sufficient; page zero is sparse specifically so no ELF header or
program headers enter production. Every memory read is classified during
generation, and write-only operands and LEA are excluded from the read census.

The private gate is enabled by `PERUN_END_TAG_ROUND_DIR` and passes both outputs
on both states. This closes only the repeated producer of two intermediate
buffers. The preceding 12,060 records and unique middle suffix remain open; no
MD5/SHA/HMAC/AES identification is claimed.

## Final 16-byte tag serializer — later 2026-11-27

`end_tagfinal::transform_tagfinal` implements the final **432-instruction**
serializer at `0x16b72a..0x16bded` and passes **2/2 states at 16/16 bytes**.
The circuit includes its own flag-producing `cmp`, all intermediate MBA and all
sixteen final byte stores, stopping before the following native call. Four
static read-only pages are used. `PERUN_END_TAGFINAL_DIR` enables its private
gate.

A late breakpoint at `0x16b72a` did not hit because it changed the selected CFF
route. Full `0x149170` traces reproduced the earlier 52,066-record streams
exactly, so record-indexed dumps at record 51,362 supplied the correct same-run
boundary state without forcing execution or mixing lineages. A regression test
also covers the `trace_slice` record-zero external-seed boundary fixed during
this analysis.

The repeated producer and final serializer are now independent components, but
the middle suffix that connects them is still open. This is not yet a complete
16-byte tag producer or a complete `ProvisioningEnd`.

## Fixed 0x35-byte header and suffix slicing status — later 2026-11-27

`end_header::end_header` supplies the fixed **53-byte structural prefix**. It
matches **185/185 valid post-End snapshots** in the local corpus, including two
independent gated states, and has a hermetic SHA-256 unit test. The sole other
snapshot was the unannotated `tb-mut` mutation with a changed declared-length
byte, not a valid post-End counterexample. No identity, session, CPIM, PTM, TK
or SPIM bytes are copied on this path.

A backward register/flag/dynamic-memory slice from the final tag to the SSE-loop
boundary retained **18,573 of 19,190 instructions**. Global def-use therefore
does not provide an honest small middle circuit. The remaining suffix must be
decomposed into measured semantic stages rather than renaming an almost
monolithic lift as a slice.

## First middle-tag checkpoint stage and same-run chain — later 2026-11-27

`end_tag_middle0::transform_tag_middle0` implements the first **204 straight-line
instructions** after the repeated circuit (`0x156e7f` through the initial
limb/XOR mixing). It matches complete GP/XMM/frame/heap/RW checkpoint states on
**2/2 independent runs**. `tools/transpile_end_middle.py` provides the generic
record-boundary/checkpoint generator for subsequent stages.

The integration gate uses one native process per input with checkpoints at loop
entry, loop exit and middle-stage exit. It proves **tag_round → middle0** with
full register and memory equality on both runs. The tag-round frame model was
expanded from 0x500 to 0x700 because this stage reads through `RBP-0x6a8`; its
original 2×1024-byte gate remains green. Cross-process stack-geometry comparison
was correctly rejected instead of weakening the state assertions.

This is the first semantic-stage result inside the 18,573-live-instruction middle
suffix. The remaining middle stages are still open, as are full tag genesis and
`ProvisioningEnd`.

## Second middle-tag stage and a three-stage chain — 2026-11-28

`end_tag_middle1::transform_tag_middle1` implements the next **288 straight-line
instructions** of masked/shift mixing. It matches complete checkpoint states on
**2/2 runs**. A four-checkpoint same-process corpus proves the full
**tag_round → middle0 → middle1** chain with GP/XMM/frame/heap/RW equality on
both inputs. No cross-process stack-state substitutions are used.

The generic middle transpiler now derives stage-specific state/core names and
removes unused arithmetic helpers and empty-table fallbacks without warnings.
The remaining middle suffix and final-four producer are still open.

## Final-four producer closed — 2026-11-28

`end_final4::transform_final4` implements the true last producer: **28
instructions × 20 iterations**. It matches complete checkpoint state on **2/2
runs**, produces all 20 output bytes, and its last four bytes equal the native
`adi.pb` final word. The destination is the measured RBP-relative 20-byte
buffer; a separate 20-byte source and four static read-only pages are used.
`end_final4::final4` exposes the finalizer's input word.

The proven `0xb7e6b` store is shared by all iterations. Earlier `0xb618d` and
`0xb75xx` groups are precursor stages, not the final producer. Full-gap captures
from `0xcddf5` through `0x149170` established the correct same-run interval and
also exposed that `dump-rec=N` addresses file record N+1 because of the entry
record. Corrected initial/final snapshots are therefore used here, while short
late-breakpoint captures with equivalent-but-different CFF routes were rejected.

## Remaining Track-B work

1. Derive the initial pre-tail/tail semantic states from
   session/CPIM/PTM/TK/identity, including their key/frame setup.
2. Complete the 16-byte stage at `0x149170` through its remaining middle suffix.
   The 0x35-byte header and final-four producer are now closed.
3. Assemble those components into real `ProvisioningEnd`, then construct warm
   semantic state from the own PERUNST record and prove Rust-End ⇄ Rust-OTP.

None of these is claimed by the completed components. Track-C cold `MixerState`
genesis and Track-D native CLI removal are independent open items.
