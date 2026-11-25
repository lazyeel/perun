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
instructions; `end_tail_tables.rs` contains eleven static non-executable 4 KiB
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

## Remaining Track-B work

1. Derive the intermediate 544+16-byte state from session/CPIM/PTM/TK/identity.
2. Close the earlier `0x35`-byte header, the 16-byte stage at `0x149170`, and the
   final four bytes before the write.
3. Assemble those components into real `ProvisioningEnd`, then construct warm
   semantic state from the own PERUNST record and prove Rust-End ⇄ Rust-OTP.

None of these is claimed by the 34-block component. Track-C cold `MixerState`
genesis and Track-D native CLI removal are independent open items.
