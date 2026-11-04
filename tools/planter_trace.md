# Android CoreADI planter-genesis trace

This note describes the live research instrumentation for the Android x86_64
`libCoreADI.so` build used by the `adi-android` harness. Earlier GDB 12.1
captures completed trace-only `ProvisioningStart rc=0` with a 276-byte CPIM
from a 347-byte SPIM (run `41363826141`). The latest v30 run
`41379301060` reached the first mixer read and captured all four canonical
tables as permutations, but its GDB-side `ProvisioningStart` result was not
observed. The native non-GDB control returned `rc=0`, `cpim_len=276`.
The active planter base is identified independently of table shape by the
`[RBP-0x30]` slot, its equality to `source+0x20`, and the writer base.
Window shape is capture-dependent: earlier runs had sparse fam2/fam4
snapshots; the latest v30 snapshot has 256/256 unique bytes in all four
canonical windows.


## Tracer lifecycle (v32)

A valid planter snapshot is a capture milestone, **not** a reason to stop the
inferior. Earlier v30 stopped on the first mixer-read breakpoint that happened
to satisfy the four-window signature. That could preserve the object while
preventing the remaining mixer-read sites and the trace-only
`ProvisioningStart` result from being observed.

The current tracer writes `planter.final.bin` once, keeps all mixer-read
breakpoints observational, and continues the harness to completion. The
`final_dumped` flag now means only "the validated snapshot has been written";
it does not disable later probes. `reader_events.csv` / `MIXER ACCESS` records
and the slot samples must therefore be interpreted across the full completed
call, not just the first valid object observation. A trace is still incomplete
when the harness times out or exits before its own `ProvisioningStart` result.

## Frame-slot pointer watchpoint (v32)

The source-slot breakpoint now arms a dedicated hardware write watchpoint on the
8-byte stack qword at [RBP-0x30], before the three established sparse-window
probes. The slot is captured at the source-slot event; every write records only
the post-write instruction RVA and the old/new offsets relative to the captured
source pointer. It also records whether the new value equals source+0x20 and
whether a readable RW span of 0x2700 bytes begins there.

The watchpoint is accepted only when info breakpoints explicitly identifies
it as a hardware watchpoint. A software fallback is deleted and recorded as
software-rejected; it is never allowed to single-step the inferior. The probe
has a 128-hit safety cap. Its CSV contains no absolute process pointers and is
suitable for the redacted report builder. A post-write PC is not claimed to be
the store instruction address without independent instruction-boundary evidence.

The three sparse byte probes are armed after the slot watchpoint, giving the
frame-slot transition priority among x86 hardware debug registers. On x86-64,
the expected configuration is one 8-byte slot watchpoint plus three 1-byte
window probes; actual GDB allocation is still verified at runtime.

## Current measured model

The four-window permutation signature is not an invariant of every capture.
Run `41203625495` directly anchored the active planter through
`[RBP-0x30]`, while fam2 and fam4 were sparse; run `41379301060` later
captured all four canonical windows as 256/256 permutations. Therefore
window contents must be recorded independently of object identity: the
signature is useful as a per-capture property, not as the sole acceptance
predicate for the active planter.

| Family | Planter offset | First known writer site(s) |
|---|---:|---|
| fam1 | `0xD60` | `0xFB05B`, `0xFB075` |
| fam2 | `0x1A00` | `0xE2508` (confirmed) |
| fam3 | `0x2460` | `0xE25C2` (confirmed) |
| fam4 | `0x1390` | `0xE26AA` (confirmed) |

**Sparse-window writer audit (six runs, 2026-11-02).** The new one-byte
hardware probes were armed on the final byte of fam2 (`+0x1AFF`), fam4
(`+0x148F`), and the dense fam3 control (`+0x255F`). Across runs
`41366750762`, `41367491679`, `41367797173`, `41368451440`,
`41369189704`, and `41369503883`, each probe was confirmed as a hardware
watchpoint and fired once. The post-write stop RVAs were stable:
fam2 `0xE2510`, fam4 `0xE26B2`, and fam3 `0xE25CA`. A stop RVA is
the observed post-write instruction pointer, not the store instruction's
address.

The previous fam2 candidate `0xE250C` is rejected: it decodes as
`add BYTE PTR [rdx],bl`, its computed effective address does not equal the
watched byte, and the PC-after check does not place the stop immediately
after that instruction. The actual fam2 writer is `0xE2508`:
`mov BYTE PTR [rdi+rcx*1+0x1a00],r14b`. Run `41378982858` matched its
effective address to the hardware probe at `+0x1AFF`; run
`41379301060` then observed 256 direct-breakpoint callbacks, 256 unique
indices `0x00..0xFF`, and base-minus-source delta `+0x20`.

The previous fam4 candidate `0xE26AE` is also rejected: it decodes as
`nop`, and its candidate effective address does not equal the watched byte.
The actual fam4 writer is `0xE26AA`:
`mov BYTE PTR [r8+rax*1+0x1390],r13b`. Run `41378982858` matched its
effective address to the hardware probe at `+0x148F`; run
`41379301060` recorded 256 direct-breakpoint callbacks, 256 unique indices
`0x00..0xFF`, and base-minus-source delta `+0x20`. Fam3's `0xE25C2`
was independently matched to the `+0x255F` control probe and also recorded
256 callbacks over 256 indices in the final run. The exact store sites for
fam2/fam3/fam4 are now established. These measurements identify the byte
stores and their index coverage; they do not yet derive the register
recurrences that generate each index and stored value.

**Latest v30 capture (2026-11-02, run `41379301060`).** All four
canonical windows were 256/256 unique in the slot-anchored
`0x2700`-byte object: fam1 `+0xD60`, fam2 `+0x1A00`, fam3 `+0x2460`,
fam4 `+0x1390`; the fifth `+0x1F30` window was also a permutation.
The byte-aligned scan found seven 256-byte permutations at
`+0x0C50`, `+0x0D60`, `+0x1280`, `+0x1390`, `+0x1A00`,
`+0x1F30`, and `+0x2460`. The extra windows at `+0x0C50` and
`+0x1280` have no established role.

Direct writer callback audit: fam2 `0xE2508`, fam3 `0xE25C2`, fam4
`0xE26AA`, and fifth `0xE24C9` each resolved and fired 256 times in the
target transform, with 256 unique indices and zero sample errors. All four
writer bases were `source+0x20`. The fam1 window was present in the
slot-anchored final snapshot, but this run's direct-writer summary does not
claim an equivalent 256-hit direct-site census for the fam1 transport loop.

**Sampling boundary.** This run reached only one of sixteen mixer-read
sites/samples; it is not a replacement for the earlier 160-stop census.
No GDB signal location was recorded, and the GDB-side trace-only
`ProvisioningStart` result was not observed. Native control independently
exited 0 with `ProvisioningStart rc=0` and `cpim_len=276`; Apple returned
HTTP 200 twice and the SPIM decoded to 347 bytes. The global process-memory
signature scan did not run, although the captured 9984-byte object itself
was scanned byte-aligned. Workflow success therefore validates the run
and its redacted artifact, not a full GDB-side provisioning completion.

The source pointer is first saved at `0xDD511` from `RCX` into
`[RBP-0x11A8]`. The measured relation in the corrected capture is
`source[32:256] == planter[0:224]`; the source begins 32 bytes before the
planter base. This is a same-run relation, not a universal fixed address.

`malloc(0xC8)` is called at `0xDD826`, and its result is saved to
`[RBP-0x3F8]` at `0xDD83B`. The request is 200 bytes. The fam1 copy path reads
256 bytes, so the final 56 bytes must be treated as adjacent mapped memory
unless allocator metadata establishes that they belong to the same allocation.

Two known dynamic byte stores write through that staging pointer:

- `0xFA9C1`: `mov byte [r9+rsi], bl`
- `0xFAA8F`: `mov byte [r11+rdx], sil`

The fam1 loop at `0xFB05B`/`0xFB075` transports bytes into the planter; it is
not, by itself, the permutation generator. The staging/source/planter writes
are interleaved in the CFF stream.

A separate store at `0xE24C9` writes to `[RDI+R15+0x1F30]`. In live run
`41202921615`, this site executed 256 times over all 256 indices
(`0x00..0xFF`), and the resulting 256-byte window contained 256 unique values.
That establishes a permutation-shaped output for this run, but not yet its
semantic role: it is a fifth S-box candidate, not a proven fifth member of the
four-family mixer model.

**Direct slot-anchor result (2026-10-31, run `41203625495`).**
At the source-slot store (`0xDD511`), `[RBP-0x30]` had not yet become
`source+0x20`; this is an initialization-order observation, not a rejection
of the candidate. At every one of 160 later mixer-read samples, the
`0x2700`-byte span at `[RBP-0x30]` was mapped, the slot equaled both
`source+0x20` and the writer-base candidate, and the pointer did not change.
This confirms `source+0x20` as the active planter-object base during the
mixer phase.

The same slot-anchored object measured `fam1=256/256`,
`fam2=53/256`, `fam3=256/256`, `fam4=196/256`, and
`+0x1F30=256/256` unique values. These counts remained stable through the
160 samples. The base is therefore no longer ambiguous; the mismatch is in
the older four-permutation structural model. Tracer v21 preserves this exact
slot-anchored object as `planter.slot_anchored.bin` without falsely requiring
all four historical windows to be bijections.

**Index topology (2026-10-31, run `41204128058`, first mixer read).**
The pre-transform snapshot had one unique byte per legacy window; the live
object changed these positions:

| Window | Unique | Zero bytes | Changed indices | Runs |
|---|---:|---:|---:|---:|
| fam1 | 256/256 | 1 | 255, range 0..255 | 2 |
| fam2 | 53/256 | 204 | 52, range 204..255 | 1 |
| fam3 | 256/256 | 1 | 255, range 0..255 | 2 |
| fam4 | 196/256 | 61 | 195, range 60..255 | 2 |
| +0x1F30 | 256/256 | 1 | 255, range 0..255 | 2 |

The `fam2` pattern is consistent with a 256-byte table beginning at
`+0x1ACC` (204 bytes after the old `+0x1A00` boundary): its first 52 bytes
would be the observed suffix, with the remaining 204 bytes in the next region.
The `fam4` pattern motivates testing a table beginning at `+0x1354` (60 bytes
before the old `+0x1390` boundary). These are testable offset hypotheses,
not identifications. The v22 full-object census checks every byte-aligned
256-byte window across the entire anchored object, including windows crossing
the old partition boundaries.

## Running the trace

The tracer is intended for the same Bionic x86_64 `adi_native` process used by
`crates/perun-cli/examples/adi-android/run-native.sh`.

1. Prepare the x86_64 Apple Music libraries and Android/Bionic sysroot as
   described in `crates/perun-cli/examples/adi-android/README.md`. The build
   script creates `adi_native` and repoints its interpreter to `/tmp/pa.so`.
2. Use a fresh working directory for `adi-data`, so an old provisioning cache
   cannot make the harness skip the transform. Set the runtime environment:

   ```sh
   export LIBS=/absolute/path/to/libs
   export SYSROOT=/absolute/path/to/sysroot
   ln -sf "$SYSROOT/bin/linker64" /tmp/pa.so
   export LD_LIBRARY_PATH="$LIBS:$SYSROOT/lib64"
   export ANDROID_ROOT=/system ANDROID_DATA=/data
   export ANDROID_RUNTIME_ROOT=/apex/com.android.runtime
   export CA_BUNDLE=/absolute/path/to/apple_chain.pem
   export ADI_OFFLINE_SPIM=/absolute/path/to/live_prov_in.bin
   ```

   `ADI_OFFLINE_SPIM` avoids a fresh network provisioning request and replays a
   previously captured 347-byte SPIM. Do not commit SPIM, CPIM, identity, cache,
   memory dumps, or trace logs to the public repository.
3. From that fresh working directory, launch GDB with the already-built
   harness and the library directory as its argument:

   ```sh
   gdb -q --args /absolute/path/to/adi_native "$LIBS"
   ```

4. At the GDB prompt:

   ```gdb
   (gdb) set pagination off
   (gdb) source /absolute/path/to/perun/tools/planter_trace_gdb.py
   (gdb) run
   ```

5. The script creates a unique directory under
   `/tmp/perun-planter-trace/run-...`. Analyze that *run directory*:

   ```sh
   python3 /absolute/path/to/perun/tools/analyze_planter_trace.py \
       /tmp/perun-planter-trace/run-... 
   ```

The script arms breakpoints at the function entry, source-slot store,
post-malloc point, known base-load sites, all known family/tail writer sites,
and all sixteen known mixer-read sites. The active capture deliberately uses
**no software watchpoints** and no `gdb.post_event(...continue...)`: tests showed
that the wide software-watchpoint path destabilized the inferior, while direct
RVA breakpoints with GDB command-list continuation produced stable CPIM output.

At a mixer-read breakpoint, the tracer first captures mapped candidates, then
scans `rw-p` process mappings for a contiguous `0x2700` object whose four
documented windows are each 256-byte permutations. The current implementation
uses a fast 16-byte-aligned pass over RW mappings up to 16 MiB, followed (when
needed) by a byte-aligned exhaustive pass over RW mappings up to 32 MiB. It
prioritizes the active stack mapping and checks whether the candidate is
referenced by `[RBP-0x30]`. Independently, when the live slot equals both `source+0x20`
and the writer-base candidate, the tracer stores that exact object as
`planter.slot_anchored.bin`, even if the old four-window predicate fails. Only
a candidate passing all four windows becomes `planter.final.bin`.

## Output files

- `trace.log`: timestamped breakpoints, direct writer events, scan decisions,
  register snapshots, and validation decisions.
- `writer_events.csv`: one row per known direct store, including effective
  address, index, old byte and new byte. This captures same-value stores that
  a value-change watchpoint would not report.
- `writer_callback_events.csv`: setup, resolution, callback entry and result
  for each direct writer breakpoint, separating an unhit breakpoint from a
  callback that failed during sampling.
- `sparse_write_events.csv`: setup and hit records for the three one-byte
  hardware probes, including post-write PC and candidate-store diagnostics.
- `run.json`: run id and the measured memory-layout partition.
- `planter.slot_anchored.bin`: the full 0x2700-byte object captured at the
  active `[RBP-0x30]` slot when it agrees with both `source+0x20` and the
  writer-base candidate; it does not require all four legacy windows to be
  permutations. This file is ephemeral and must not be committed.
- `source.final.bin`, `staging.copy_entry.*.bin`, `staging.final.*.bin`,
  `planter.final.bin`, family snapshots and unknown-range snapshots: memory
  captures from this process only.
- `writer_stats.txt`: direct-writer coverage when either the strict
  four-window signature or the active slot anchor is confirmed.

The analyzer checks the four known permutations, cycle lengths, byte-level
source/planter overlap, candidate bijection windows in unknown ranges, writer
index coverage, and competing source/staging/fam1 relationships.

## Interpretation and limitations

- A `0x2700` readable span is only a mapped candidate. The primary active
  object anchor is the independently correlated `[RBP-0x30]` slot,
  `source+0x20`, and writer base. Four-window permutation status is
  capture-dependent (sparse in some sessions, complete in run
  `41379301060`) and must not be used as the sole object-identity filter.
- A `+0x20` writer-base delta alone is only correlation. In run
  `41203625495`, the stronger identity check held at all 160 mixer samples:
  `[RBP-0x30] == source+0x20 == writer-base`, with no pointer transitions.
- The `+0x1F30` writer covered all 256 indices (`0x00..0xFF`) and produced
  256 unique bytes in the live run. It is therefore a fifth permutation-shaped
  window in this session; its role in the mixer remains unproven.
- The 56 bytes beyond the requested 200-byte allocation are recorded only
  when they are readable in the same RW mapping. This does not establish
  allocator ownership or prove an out-of-bounds bug.
- The no-software-watchpoint path has completed a full live trace-only
  provisioning start in earlier run `41363826141`. Latest run
  `41379301060` reached the first mixer read but did not record the GDB-side
  ProvisioningStart result. The global process-memory signature scan remains
  distinct from the byte-aligned scan of the already anchored 0x2700 object.
- The trace logs register values and dumps stack/heap-adjacent memory. Treat
  generated run directories as sensitive research artifacts; keep them local
  and inspect/redact before sharing.