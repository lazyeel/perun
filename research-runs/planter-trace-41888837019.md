# Android CoreADI planter-genesis trace

- GitHub run: `41888837019`
- Source revision: `480ea89682f0ada86b1cf75b7495fb6f74bae2bc`
- GDB: `GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1`
- Harness/GDB exit code: `0`
- Trace directory created: `no`

This report is intentionally redacted: no SPIM/CPIM, device identifier, raw memory bytes, pointer values, or register snapshots are published.

## Result

No trace directory was created. Inspect the safe runner diagnostics below.

## Safe runner diagnostics

- `== building the engine for x86_64`
- `== repointing PT_INTERP at the Bionic loader`
- `PT_INTERP -> /tmp/pa.so`
- `== running`
- `== running under GDB (gdb), script=/home/runner/work/perun/perun/tools/rdtsc_freeze_gdb.py`


## Fixed-input CPIM determinism probe

Four offline runs reused the same saved SPIM, device identity, and restored adi-data seed. Two baseline runs used native execution; two frozen runs used GDB to replace the gettimeofday return value and the three confirmed RDTSC sites. Raw inputs, outputs, and digests remain private.

- SPIM input length: 347 bytes
- Baseline CPIM lengths: 276 / 276 bytes; equal: no
- Frozen CPIM lengths: 276 / 276 bytes; equal: no
- Frozen gettimeofday interceptions: 1
- Frozen RDTSC bypasses: 0
- Process exit codes (baseline A/B, frozen A/B): 0/0/0/0

Interpretation is conditional on all four runs producing CPIM and nonzero freeze-hit counts. Equal frozen outputs after differing baseline outputs support time/counter dependence; otherwise other entropy sources or state/input issues remain possible.