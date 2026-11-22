# The planter arena: the genesis pipeline, measured

Date: 2026-11-19 → 2026-11-21
Lane: Android x86_64, offline-SPIM harness (`ADI_OFFLINE_SPIM`,
`ADI_FORCE_START=1`), `rig/WORK/libs` oracle.
Status: the pipeline is closed end to end (arena → schedule → live tail →
window parameters) except for one explicit unknown: the fifteen 16-byte round
maps themselves. The constants, the wiring, the read order, the live slice and
the affine window law are measured.

Raw bytes (SPIM, planter, core dumps, gdb logs) stay in `/tmp/opencode` and are
**not** committed. This note records only sizes, RVAs, offsets and laws.

## 1. The planter is not seed-driven

A hardware read watchpoint on the 12-byte prefill seed at
`planter+0x94` (armed at the transform entry `0x87554`) fires **once** per run
in the generator store at `0xB608A`, and then **not again until `0xE3D44`**,
which is *after* the 256-iteration window loop. The window loop is
`0xE1F74..0xE26DE`, so the seed is not an input of the windows.
Patching the seed in memory at `0xDD511` changes nothing in the planter.

## 2. The actual input: a 240-byte arena

The seven permutation windows (offsets `+0x0C50`, `+0xD60`, `+0x1280`,
`+0x1390`, `+0x1A00`, `+0x1F30`, `+0x2460`) are written by the straight-line
block `0xE1F74..0xE26DE`, executed 256 times. Its coefficients come from a
240-byte buffer in `libCoreADI`'s writable image at

    libCoreADI + 0x19B600   (0x7ffff7814600 at the measured base)

(not from the stack).

Measured with Unicorn replay of `gcore` checkpoints taken at `0xDD511`
(the checkpoint-raised privilege is not a factor: every replay starts from the
saved register file and a full rewrite of every `PT_LOAD`):

* The replay is cartesian-exact: 171 016 instructions to the 256th hit of the
  loop tail `0xE26DE`; it reproduces the A1 windows byte for byte
  (`0xD60 c=3b basis=cc19f442a86e5eeb`, `0x1390 c=64 d61b182b5fe32725`,
  `0x1A00 c=07 909c4f7dcf031a52`, `0x1F30 c=57 92b2e4e715ab2714`,
  `0x2460 c=39 066e315a9df49125`, plus `+0x0C50 c=20 737c7dadf98e20ca` and
  `+0x1280 c=15 cec017afa3d50192`) and the C lineage likewise.
* Transplanting only the 240 arena bytes from the C checkpoint into the A1
  checkpoint turns all seven A1 windows into the C windows (7/7).
* Transplanting the seed, the 52-byte prefill, the 40 session-dependent prefill
  bytes (A limb B), or the global SPIM buffer changes nothing.
* Only the suffix `arena[160:240]` (= `SPIM[168:248]`) influences the windows;
  replacing `arena[0:160]` leaves them bit-identical.
* Zeroing the arena changes all seven windows.

## 3. The arena is literally `SPIM[8:248]`

Across A1, A2, C and D, the 240 bytes at the arena address equal
`spim[8:248]` byte for byte (240/240 exact positions, not a permutation).
A1/A2 share it; C and D differ from A1. That matches the window equality
pattern (A1 = A2 = B, all others distinct).

So the only SPIM slice the planter windows consume is

    arena = spim[8 : 8 + 240]

and, because the 347-byte SPIM tail is 3 ignored padding bytes, this is
`spim[8:248]`, i.e. the 240 bytes after the 8-byte SPIM header.

The `0xA958D..0xA966E` unrolled copy block writes these 240 bytes into the
global arena, 60 dword stores in the order `+0,+12,+4,+8` within each 16-byte
block.

## 4. The stage is one straight line, not a branch network

Executed-instruction count, final `RBP`/`RSP`, and the number of frame writes are
**identical** for the real A1 arena and for four independent random arenas:

| arena | instructions | final RBP | final RSP | frame writes |
|---|---|---|---|---|
| A1 | 171 016 | `0x7fffffffa1b0` | `0x7fffffff5ce0` | 1852 |
| random ×4 | 171 016 | same | same | 1852 |

The **SHA-256 of the whole executed-PC sequence** is the same on A1 and on
three random arenas (`c6dcf41b34d4453a…`). The stage is therefore a fixed
data-independent circuit; all of its structure is memory accesses observed at
run time, and all data dependence is in the values loaded.

The 1852 frame writes decompose exactly:

    7 windows x 256 bytes        = 1792
    60 schedule dwords x 4 bytes  =   240
                        total    = 1852

and there are **zero** writes back into the arena. So the arena is a pure input Keeping the
and the seven windows + schedule are the only outputs.

The 1792 window stores are one byte each, from **seven** store PCs inside one
256-iteration loop (`0xE1F74..0xE26DE`), one PC per window:

| window | store PC |
|---|---|
| `+0xD60`  | `0xE2441` |
| `+0x1F30` | `0xE24C9` |
| `+0x1A00` | `0xE2508` |
| `+0x0C50` | `0xE25A4` |
| `+0x2460` | `0xE25C2` |
| `+0x1280` | `0xE2626` |
| `+0x1390` | `0xE26AA` |

A 256-iteration loop with one store per window is an **affine evaluator over
the loop index**: the eight bits of `i` are the only thing that distinguishes
iteration `i` from any other. That is the mechanism behind the measured
`w[i] = c ^ XOR_{k : bit k(i)} basis[k]` law of § 6.

The schedule, by contrast, has 60 dword stores from four PCs
(`0xE090F` at `+0`, `0xE09B7` at `+0xC`, `0xE09D5` at `+0x4`, `0xE09F5` at
`+0x8`), fired 15 times each in a fixed rotation, three rounds per block.
It is written **before** the window loop and is not written by it.

## 5. The schedule is block-local, then handed to the windows as 64 bytes

The 240 arena reads are exactly 15 rounds × 16 bytes, and each round reads
exactly one block's worth of positions:

| round | arena byte offsets read (mod 16) |
|---|---|
| 0 | `01 06 03 0a 00 04 09 0f 08 0b 02 05 07 0c 0e 0d` |
| 3 | same set, block 3 |
| … | identical in every round, every lineage |

Every arena byte is read **exactly once** (read census: min = max = 1).
The same 16 store PCs write the round's 4 dwords into `schedule[16b..16b+16)`,
with block offsets `+0x00, +0x0C, +0x04, +0x08`.

At the end of the schedule phase the stage **reads back** the schedule:
16 dword loads at `0xE0C1F..0xE117D`, consuming `schedule[0xB0..0xF0)`
(64 bytes) and nothing else. The first 176 bytes of the schedule are dead
output.

This was measured by patching schedule bytes at the first read-back
instruction and diffing the seven windows:

| patched region | differing window parameters (of 63) |
|---|---|
| `schedule[0x00..0xB0)` | **0** |
| `schedule[0xB0..0xF0)` | **51** |

and by varying one byte of the live 64 at a time, which moves between 0 and 6
parameters. The 64 live bytes are therefore the **only** channel from the
arena into the windows: only the last five arena blocks
(`arena[160:240]` = `SPIM[168:248]`) can reach them. That is why randomising
`arena[0:160]` is a no-op for the windows, verified on all 160 prefix bytes.

## 6. The window law is affine and it is a bijection

Every canonical window is, byte for byte on all seven captures:

    w[i] = c ^ XOR_{k : bit k of i is set} basis[k]

so a window is nine bytes: its constant `c` and an eight-byte basis.
The constants are lineage-invariant:

    0xC50=20  0xD60=3b  0x1280=15  0x1390=64
    0x1A00=07 0x1F30=57  0x2460=39

(canonical roles read `fam1=3b`, `fam4=64`, `fam2=07`, `fifth=57`, `fam3=39`)
and the eight canonical bases have GF(2) rank 8 on every capture, which is
exactly why `w` is a permutation. Rank 8 <=> bijection; the law holds whenever
the basis is independent.

The two extras are the exception: on all seven captures they are permutations,
but they **never** obey the affine law (`affine_matches_table` is false for
`+0x0C50` and `+0x1280` on A1, A2, B, C, D, E and F). They are not written by
the canonical evaluator and their role is still open. The earlier note that
put them in the same "affine" class was an artefact of reading the
intermediate `pre-A1` replay, where they are not yet filled (see § 8).

## 7. The 15 round maps are the only unknown substance

The stage is a fixed circuit over 240 input bytes, so it is exactly fifteen
16-byte → 16-byte maps:

    schedule[16b .. 16b+16) = R_b( arena[16b .. 16b+16) )   for b = 0..14

with the measured cross-round coupling

    S[b][q] depends on arena block b, and on exactly one byte
    of arena block b-1, at position q ^ 3.

Measured on the fixed lab:

* for each source byte `p` of a block, flipping it moves all 16 bytes of
  `S[b]` and exactly one byte of `S[b+1]`, at `p ^ 3` -- 0 deviations over 224
  probes (`verify_genesis.py`);
* the value map on that one byte, `v -> S[b+1][p^3]`, is GF(2)-affine at
  **16/16** positions;
* the **linear part** of that map is not context-dependent: at 30 (block, q)
  positions and 4 unrelated random contexts it is a fixed 8x8 matrix
  determined only by `q mod 4`, and the four matrices are rank 8, hence
  bijections (`ctx_free2.py`, `masks.py`);
* the same four matrices come back on the **A1 and the C checkpoints** and at
  every block measured -- so they are lineage-invariant and block-invariant
  and are four 256-byte tables of the port (`masks.py`);
* it is the affine **constant** that varies with context: it carries `R_b`'s
  dependence on the whole block, which is why the map is not a separable
  per-byte table;
* none of the four is a xorshift or a GF(2^8) multiply form in the polynomials
  tried, so the four tables are carried as data where they are needed,
  not regenerated by a formula;
* the full 240-byte map is therefore not GF(2)-affine and not a per-byte XOR
  bundle, but every observed structure (16-byte blocks, 4-dword stores,
  one-byte `p^3` back-coupling with a 4-table mask) is consistent with fifteen
  applications of one round function;

so `R_b` is the right object to lift: 15 × 16 × 16 = 3840 byte-outputs, each a
function of 16 byte-inputs, and with `S[b]` separable (measured mixed
difference = 0 on all 15 blocks) it is 15 × 16 independent 16 → 1 byte maps.

## 8. The extras are not a later path -- they are the same loop, non-affine

A tempting reading is that the two extras at `+0x0C50`/`+0x1280` are filled by a
different routine, because they are the only windows that break the affine law.
The measured store PCs refute that: all seven windows are written by one-byte
stores inside the *same* 256-iteration loop `0xE1F74..0xE26DE` (§ 4).

The apparent "extras are affine before the loop" reading comes from comparing the
wrong objects. The `pre-*` dumps are taken at `0xDD511`, before the evaluator has
filled the windows, and they are almost entirely unwritten:

| window | pre-A1 distinct bytes | pre-A1 first eight |
|---|---|---|
| `+0x0C50` | 1 (all zero) | `00 …` |
| `+0x0D60` | 1 (all zero) | `00 …` |
| `+0x1280` | 1 (all zero) | `00 …` |
| `+0x1390` | 1 (all zero) | `00 …` |
| `+0x1A00` | 1 (all zero) | `00 …` |
| `+0x1F30` | 13 | `00 …` |
| `+0x2460` | 9 | `5c e9 b3 5f …` |

An all-zero table passes any affine test trivially, so the pre-fix labels say
nothing about the generator. The only object that does is the final snapshot,
and there the split is sharp and stable across A1..F: the five canonical windows
are affine, both extras are complete permutations that are not affine.

So the extras are written by the same index loop but their stored value is not an
affine function of the index. They are genuine 256-byte key-dependent tables,
not nine-byte schedules; that is why the port carries them as tables and closes
the *law* only for the canonical five.

## 9. What this means for the port

    windows(arena) = E( schedule_final(arena[160:240]) )

where `schedule_final` is the last 64 bytes the stage leaves in
`planter+0x18D0`, and `E` is the affine evaluator of § 6 for the five
canonical windows.

* `arena_from_spim(spim) = spim[8:248]` -- `ARENA_LEN = 240`, exact, 240/240.
* `windows_from_arena(arena) = E(schedule_final(arena[160:240]))` -- `E` is
  a nine-byte affine table per canonical window; implemented as
  [`perun_adi_core::planter::Window::from_params`] and pinned by the
  `params_round_trip_reproduces_the_window` and
  `canonical_basis_ranks` tests.
* `expand_planter(spim)` = the above composition, **gated on the native
  oracle** only until the fifteen `R_b` are transcribed. It is not gated on
  the window law; the window law is closed.

The remaining work is exactly the fifteen round maps. A first port attempt
that lifted them as a single 256-byte S-box was wrong and is withdrawn: the
`0xDD946` block is not a round function, it is the flattened dispatcher of the
round (`movsxd rax, [r14+rax*4]; lea rcx; add rcx, rax; jmp rcx`), and its
`r8/r9/r13` loads are the CFF tables it dispatches through. The next probe
walks the dispatcher once per round with the round's 16 bytes fixed, which is
the same method that closed the Windows CFF body.

## Data channels

- Unicorn replay: `/tmp/opencode/replay_lab.py` (`Lab.run_windows` = full
  stage, `Lab.run_arena` = to the schedule loop tail).
- Read/write census: `readset.py`, `stripes.py`, `round_map.py`, `writers.py`,
  `sched_reads.py`.
- Coupling and law: `influence.py`, `verify_genesis.py`, `coupling_law.py`,
  `coupling_bank.py`, `caps_law.py`, `extra_law.py`, `pre_vs_fin.py`.
- A failed probe is retained in the name only if it still tells a reader what
  not to repeat.

## 10. Implementation closure (2026-11-22)

Sections 7 and 9 described the state before transcription. The fifteen `R_b`
maps and the evaluator are no longer open. Exact executed-trace liveness reduced
the shared schedule body to 3,092 instructions invoked fifteen times, with four
output-dependent dword masks carried through the short link. The post-schedule
part is 1,138 instructions once plus a 479-instruction body invoked 256 times.

`tools/transpile_planter.py` now emits `planter_core.rs` and `planter_tables.rs`.
It is strict (unsupported semantics abort), preserves arithmetic/flags/stores,
and emits no x86 machine code. `planter::expand_planter` is implemented in pure
Rust; `schedule_from_arena` and `window_tables_from_arena` expose the measured
boundaries. Static lookup data is non-executable Rust data, and production has
no Apple/Bionic/capture dependency.

Results: the 240-byte schedule matches byte for byte on all seven captures, and
all seven 256-byte windows match byte for byte on all seven captures (12,544
window bytes, including both extras). Three synthetic schedule digests and three
synthetic full-window-set digests are committed and run without captures.

The earlier statement in § 6 that the extras were "not written by the canonical
evaluator" was too strong and is withdrawn. § 8 has the correct mechanism: all
seven are written in one loop; only five satisfy the affine position law. The
complete port transcribes that loop rather than approximating the extras.
