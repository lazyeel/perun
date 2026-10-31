# Android CoreADI planter-genesis trace

This note describes the live research instrumentation for the Android x86_64
`libCoreADI.so` build used by the `adi-android` harness. The GDB 12.1 path has
now completed a real Apple provisioning start: the native control and GDB run
both reached `ProvisioningStart rc=0` with a 276-byte CPIM from a 347-byte SPIM.
The live planter base is now identified by the active-frame slot
`[RBP-0x30]`: run `41203130396` measured the same mapped object at all 160
mixer-read stops, with the slot equal to both `source+0x20` and the writer
base, and no pointer transitions. The unresolved question is the object's
internal table layout and the genesis of its session-dependent contents:
the older four-permutation signature does not hold for two windows in this
fresh session.

## Current measured model

Earlier corrected captures showed four 256-byte permutations. That remains a
historical observation, not a universal acceptance predicate: fresh run
`41203130396` directly anchored the active planter through `[RBP-0x30]`,
while two of the four previously named windows were not permutations. The
window values are therefore measured independently rather than used to reject
an object whose base pointer is independently confirmed:

| Family | Planter offset | First known writer site(s) |
|---|---:|---|
| fam1 | `0xD60` | `0xFB05B`, `0xFB075` |
| fam2 | `0x1A00` | `0xE250C` |
| fam3 | `0x2460` | `0xE25C2` |
| fam4 | `0x1390` | `0xE26AE` |

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

**Direct slot-anchor result (2026-10-31, run `41203130396`).**
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
the older four-permutation structural model. Tracer v20 preserves this exact
slot-anchored object as `planter.slot_anchored.bin` without falsely requiring
all four historical windows to be bijections.

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
referenced by `[RBP-0x30]`. Only a candidate passing all four windows becomes
`planter.final.bin`; a merely readable `0x2700` region remains a candidate.

## Output files

- `trace.log`: timestamped breakpoints, direct writer events, scan decisions,
  register snapshots, and validation decisions.
- `writer_events.csv`: one row per known direct store, including effective
  address, index, old byte and new byte. This captures same-value stores that
  a value-change watchpoint would not report.
- `run.json`: run id and the measured memory-layout partition.
- `source.final.bin`, `staging.copy_entry.*.bin`, `staging.final.*.bin`,
  `planter.final.bin`, family snapshots and unknown-range snapshots: memory
  captures from this process only.
- `writer_stats.txt`: direct-writer coverage once a valid four-window
  planter signature has been obtained.

The analyzer checks the four known permutations, cycle lengths, byte-level
source/planter overlap, candidate bijection windows in unknown ranges, writer
index coverage, and competing source/staging/fam1 relationships.

## Interpretation and limitations

- A `0x2700` readable span is only a mapped candidate. The four documented
  256-byte windows must each contain all 256 byte values before the tracer
  calls it a final planter.
- Writer-base deltas of `+0x20` relative to source are useful correlation, not
  proof of object identity. The direct byte-overlap check is required.
- The `+0x1F30` writer is still unclassified. Its name in the CSV is a label
  for the observed instruction site, not evidence that it is a fifth S-box.
- The 56 bytes beyond the requested 200-byte allocation are recorded only
  when they are readable in the same RW mapping. This does not establish
  allocator ownership or prove an out-of-bounds bug.
- The current no-watchpoint path is operationally verified for the live
  provisioning start. The full-memory signature scan is still being validated;
  a negative scan means the exact planter location or the four-window model
  remains unresolved, not that the current mapped candidate is the planter.
- The trace logs register values and dumps stack/heap-adjacent memory. Treat
  generated run directories as sensitive research artifacts; keep them local
  and inspect/redact before sharing.