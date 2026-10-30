# Android CoreADI planter-genesis trace

This note describes the research instrumentation for the Android x86_64
`libCoreADI.so` build used by the `adi-android` harness. It is not a claim that
the current trace has completed successfully: the GDB script has been syntax-
checked and startup-smoke-tested against a small GDB API stub, but a live run
against Apple's shared object is still required.

## Current measured model

The family windows observed at the first mixer are four 256-byte permutations:

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
are interleaved in the CFF stream. A separate store at `0xE24C9` writes to
`[RDI+R15+0x1F30]`; it is intentionally called an *unclassified writer*, not a
fifth S-box, until the live index range and final data structure are measured.

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
post-malloc point, known planter-base loads, all known family/tail writer
sites, and all sixteen known mixer-read sites. At the first verified planter
base it installs software watchpoints over a non-overlapping partition of the
entire `0x2700` object: the head, four known windows, and five unknown gaps.
The mutable `[RBP-0x30]` frame slot is watched starting at the earlier
`0xDD511` source-pointer point.

## Output files

- `trace.log`: timestamped breakpoints, watchpoint deltas, register snapshots,
  and validation decisions.
- `writer_events.csv`: one row per known direct store, including effective
  address, index, old byte and new byte. This captures same-value stores that
  a value-change watchpoint would not report.
- `run.json`: run id and the measured memory-layout partition.
- `source.final.bin`, `staging.copy_entry.*.bin`, `staging.final.*.bin`,
  `planter.final.bin`, family snapshots and unknown-range snapshots: memory
  captures from this process only.
- `writer_stats.txt`: direct-writer coverage once a valid first-mixer snapshot
  has been obtained.

The analyzer checks the four known permutations, cycle lengths, byte-level
source/planter overlap, candidate bijection windows in unknown ranges, writer
index coverage, and competing source/staging/fam1 relationships.

## Interpretation and limitations

- Software watchpoints are implemented by single-stepping and comparing the
  watched expression. They can be dramatically slower than ordinary execution
  and report value changes, not every store. This is why exact writer-site
  breakpoints and `writer_events.csv` are also present.
- GDB's software watchpoint callback reports the next statement/PC after the
  observed change; the script labels it `pc_after` and does not misattribute it
  to the exact store instruction.
- The watchpoint regions partition the full `0x2700` planter without overlap.
  The `+0x1F30` writer may index into the fam3 region or another region; the
  direct writer log, not its comment/name, determines the real effective
  address.
- The 56 bytes beyond the requested 200-byte allocation are recorded only
  when they are readable in the same RW mapping. This does not establish
  allocator ownership or prove an out-of-bounds bug.
- GDB's `gdb.post_event` callback and automatic `continue` sequence has not yet
  been exercised against the target Bionic process in this environment. A
  real target run is still needed before treating the capture as operationally
  verified.
- The trace logs register values and dumps stack/heap-adjacent memory. Treat
  generated run directories as sensitive research artifacts; keep them local
  and inspect/redact before sharing.