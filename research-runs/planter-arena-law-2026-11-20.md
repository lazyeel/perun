# The planter arena: measured input law for the window schedule

Date: 2026-11-19 → 2026-11-20
Lane: Android x86_64, offline-SPIM harness (`ADI_OFFLINE_SPIM`,
`ADI_FORCE_START=1`), `rig/WORK/libs` oracle.
Status: late stage closed as an executable oracle; early stage measured to a
240-byte input; closed form still open.

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

Measured with Unicorn replay of `gcore` checkpoints taken at `0xDD511`:

* The replay is cartesian-exact: 171 017 instructions to the 256th hit of the
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

The `0xA958D..0xA966E/0x?` unrolled copy block writes these 240 bytes into the
global arena (writes arrive in reverse with stride; final contents are the
faithful slice above).

## 4. The late stage is a 16-byte block recurrence

Diffusion map (240 probes of one byte each, zero arena, read out of the 240-byte
planter schedule):

* block size 16, 15 blocks (240 bytes);
* input block `b` changes output blocks `b` and `b+1` only - no other block,
  no long-range propagation;
* within block `b` all 16 output bytes move;
* in block `b+1` exactly one byte moves: position `p XOR 3` for input byte `p`;
* block 14 has no `b+1`;
* the window constants `c` are identical on all seven lineages
  (`20 3b 15 64 07 57 39`); only the eight basis bytes vary.

Point probes `put X in block k` (X = 01..10, all other blocks zero) give

    S[0]   = P(X) ^ IV
    S[k]   = P(X) ^ Q(0)      for k = 1..14
    S[k+1] = P(0) ^ Q(X Short)  for k = 1..13

with `P(0) ^ Q(0) = cbd0a5c2a3867086e70081ade60d568b` and the same
`P(X) ^ Q(0)` for every `k >= riv virt 1`, i.e. the schedule is the separable
recurrence

    S[b] = P(in[b]) ^ Q(in[b-1])

(`S[0] = P(in[0]) ^ IV`, `IV` constant). This matches the suite's known
"one same-structure block per step" behaviour of the fold engine, but here it is
measured for the planter.

## 5. Open

* Closed form of `P` and `Q` (16-byte ->r 16-byte each). They are not
* GF(2)-affine on the full 240-byte input, and not per-byte XOR bundles.
* Whether `P`/`Q` are "XOR of 16 byte S-box lookups" (the classic 16x16
  table shape) is the natural next probe: difference-invariance
  **P(x|p:=a) ^=P(x|p:=b)** against context `x`.
* Rust port: `expand_planter(spim) = windows_from_arena(spim[8:248])`
  is now the correct signature; the seed is off the planter path.

## 6. Verification pass (2026-11-20, corrected lab)

**Lab bug found and fixed.** The first replay lab installed a `UC_HOOK_CODE`
callback on every `run()` and never removed it, so every "repeat" probe was
stopped by the *first* invocation's counter at the first loop tail. All
structural numbers produced before the fix are void (including a spurious
"per-byte XOR bundle" and a spurious "not separable"). The lab now builds one
hook at construction, resets the machine by rewriting every PT_LOAD from the
core image plus the saved register file, and zeroes the hit counter per probe.

**Lab verification (`lab_check.py`).**
- A1 replay schedule == the independent gdb dump `pre-A1-pre/planter.bin`
  at `+0x18D0..+0x19C0` (True).
- Three consecutive probes on one machine are bit-identical (True).
- All seven windows are permutations with the same constants as gdb (True).
- C replay reproduces all seven C windows of the gdb dump (True).

**Diffusion map in the real A1 context (`diffusion_real.json`).**
For every one of the 240 arena bytes `i`, flipping `i` in the *real* A1 arena
changes:
- all 16 bytes of schedule block `i // 16` (220/240 do exactly 16; the rest
  15 or 16 of the same block),
- exactly one byte of block `i // 16 + 1`, at position `(i % 16) ^ 3`, for
  every block `b < 14` (0 deviations over 224 probes),
- nothing else. No input reaches a non-adjacent block.

Only the degenerate all-zero arena changes all 240 (a branch/`if` artifact of
the zero context), which is why the real-context map is the one to trust.

**Separability (`sep_test.py`).** For every block `b = 0..14`, with random
16-byte `z, w` and all other arena blocks at the real A1 values:
`H(z,w) ^ H(z,0) ^ H(0,w) ^ H(0,0) = 0` on all 16 output bytes.
So the schedule is fifteen separable 16-byte mixers with a one-block XOR
feed-forward:

    S[b] = P_b(x_b) ^ R_b(x_{b-1})

with `P_b`, `R_b` independent 16->16 maps (and the diffusion map says `R_b` is
only a single byte `p^3` of its argument).

**Suffix sufficiency, re-confirmed on the corrected lab.** Replacing
`arena[160:240]` by C's suffix in the A1 arena reproduces all C windows
(`== C True`, 56 differing bytes vs A1), while replacing `arena[0:160]`
leaves the A1 windows bit-identical (0 differing bytes). Random suffix changes
the windows density. This reproduces the earlier conclusion on a lab that is
now known-deterministic, so it stands.

**What this means for the port.** The genesis is
`windows(arena) = f(spim[168:248])` through fifteen 16-byte mixers whose
`R_b` are literally "copy byte p^3 of the previous block". The only remaining
unknown substance is the 16-byte map `P_b` (one per block, or one reused);
it is not GF(2)-affine and not a per-byte XOR bundle, so it is a byte-level
S-box network over 16 bytes. The next probe measures `P_b` as a 16x16 table
of 256-entry byte curves to expose its S-box layer and byte wiring.
