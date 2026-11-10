# Android CoreADI planter-genesis trace

- GitHub run: `42897538965`
- Source revision: `f5ee38e3ba23136dce4fdab3c0340cea0bc9a372`
- GDB: `GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1`
- Harness/GDB exit code: `0`
- Trace directory created: `yes`

This report is intentionally redacted: no SPIM/CPIM, device identifier, raw memory bytes, pointer values, or register snapshots are published.

- Trace run id: `run-1794343338379161-11384`
- Tracer version: `v33`

## Early planter anchor

- Source+0x20 span mapped before transform: yes
- [rbp-0x30] equaled source+0x20 at source-slot store: no

## Window evolution (pre-transform → mixer read)

No source-anchored window comparisons were recorded.

## Live [rbp-0x30] slot sampling

No direct slot samples were recorded.

## Slot-anchored object capture

- Slot-anchored object captured: no
No slot-anchored window statistics were recorded.

## Slot window index topology (first mixer read)

No slot window index-topology metrics were recorded.
## Full-object 256-byte permutation census

No slot-anchored object dump was available for a full-object scan.

## GDB installation steps

| Stage | Reached |
|---|---:|
| global writer probes requested | yes |
| global installer entered | yes |
| source-slot breakpoint created | yes |
| post-malloc breakpoint created | yes |
| copy-entry breakpoint created | yes |
| writer breakpoints created | yes |
| target transform probes requested | yes |
| target installer entered | yes |
| target mixer-read breakpoint created | yes |
- global writer breakpoints created: 8
- base-load breakpoints created: 2
- mixer-read breakpoints created: 16

## Tracer progress

| Checkpoint | Reached |
|---|---:|
| Tracer initialized | yes |
| First vdfut768ig entry | yes |
| Global writer probes installed | yes |
| Target mixer probes installed | yes |
| Subsequent vdfut768ig entry logged | yes |
| Transform opcode observed | yes |
| Source pointer captured | yes |
| malloc result captured | yes |
| Planter base candidate observed | yes |
| Source/planter overlap measured | yes |
| First mixer read reached | no |
| Signal location captured | no |

## Tracer errors

- Breakpoint installation errors: 0
- Watchpoint setup errors: 0
- Watchpoint callback errors: 0

## Crash-site backtrace

No signal-stop location was recorded.

## Native non-GDB control

- Exit code: 0
- SPIM decoded lengths: 347 bytes
- ProvisioningStart results: rc=0, cpim_len=276
- C harness signal handler: not observed

## Apple network/provisioning progression

- HTTP responses: 200 (25691 bytes) -> 200 (1109 bytes)
- SPIM decoded lengths: 347 bytes
- Provisioning fatal classifications: none observed

## Harness branch results

- ADIGetLoginCode results: -45061, -45061
- Trace-only ProvisioningStart result: not observed

## Live provisioning path

- ProvisioningStart path entered: yes
- SPIM decoded from live Apple response: yes
## vdfut768ig opcode sequence

- 0x12db31c5 -> 0xb0eda7af -> 0xb23c691e -> 0xc774d292 -> 0xc774d292 -> 0xb0eda7af -> 0x716bd86c
- Entry breakpoint command-list actions: global-writers, skip 0x12db31c5, skip 0xb0eda7af, skip 0xb23c691e, skip 0xc774d292, skip 0xc774d292, skip 0xb0eda7af, target-mixers

## GDB console status

No allow-listed GDB console diagnostic matched.

## Full-memory signature scan

The memory signature scan did not run or did not record a result.

## Capture checkpoints

- Software watchpoints armed: `yes`
- Frame-slot hardware pointer watchpoint: `hardware` (1 writes; 1 writes to source+0x20)
- Planter base candidate logged: `yes`
- Mapped 0x2700 candidate snapshots: `1`
- Independent writer-window snapshots: `0`
- Final four-permutation snapshot: `no`
- Source/planter overlap check executed: `yes`
- Snapshot selected for byte statistics: `candidate:planter.at_base_load.bin`

## Mapped candidate object snapshots

| Snapshot | Bytes | fam1 unique | fam2 unique | fam3 unique | fam4 unique |
|---|---:|---:|---:|---:|---:|
| planter.at_base_load.bin | 9984 | 1/256 | 1/256 | 9/256 | 1/256 |
| fam1 | 1/256 | no | 256 | n/a |
| fam2 | 1/256 | no | 256 | n/a |
| fam3 | 9/256 | no | 248 | n/a |
| fam4 | 1/256 | no | 256 | n/a |

## Unknown regions

| Region | Size | Unique byte values |
|---|---:|---:|
| unknown_e60_1390 | 0x530 | 1 |
| unknown_1490_1a00 | 0x570 | 157 |
| unknown_1b00_1f30 | 0x430 | 24 |
| unknown_1f30_2460 | 0x530 | 68 |
| unknown_2560_2700 | 0x1a0 | 16 |

## Dynamic mixer memory operands

No dynamic memory-operand samples were recorded.

## Runtime zone-data comparison

The live module-relative region was not captured.

## fam1 candidate writer site (RVA 0xE2441)

- Instruction boundary: verified from the decode beginning at 0xE243D.

| vdfut opcode | Mnemonic | Destination width | Memory-destination semantics | Hits | Fam1 byte-write hits | Distinct byte-write indices | Index min..max |
|---|---|---:|---|---:|---:|---:|---:|
| 0x716bd86c | mov | 1 | writes-memory-destination | 1 | 1 | 1 | 0x0..0x0 |
- Source operand(s): r10b
- Source GPR(s): r10
- Source-byte unique values: 1/256
- Source-byte permutation: no
- No exact affine or pairwise byte relation was found among captured index, GPR byte lanes, or frame-state byte lanes.
- Candidate callback errors: 0
- GDB reverse-recording: started (full; bounded 500,000-instruction history).
- Latest r10b producer: status=found; reverse steps=5; producer RVA=0xe2432; mnemonic=add; forward check=yes.
- Producer instruction (static disassembly): \`add_r10b,0x3b\`; dst=r10b; src=0x3b; destination GPR=r10; source GPR=na.


## Direct writer coverage by opcode

| Writer | vdfut opcode | Hits | Distinct indices | Index min..max | Base−source delta |
|---|---|---:|---:|---:|---:|

## Frame-slot pointer hardware watchpoint

- Setup status: `hardware`
- Observed writes: 1
- Writes to source+0x20: 1
- Distinct post-write stop RVAs: 0xdd659
- New pointer values with a mapped 0x2700-byte span: 1

| # | PC after (RVA) | Old source-relative offset | New source-relative offset | New = source+0x20 | 0x2700 span mapped | Value changed |
|---:|---|---:|---:|---|---|---|
| 1 | 0xdd659 | n/a | +0x20 | yes | yes | yes |

## Sparse-window hardware write probes

- fam2_tail: offset 0x1aff, setup hardware, write hits 0, distinct post-write stop RVAs: none
- fam4_tail: offset 0x148f, setup hardware, write hits 0, distinct post-write stop RVAs: none
- fam3_control_tail: offset 0x255f, setup hardware, write hits 0, distinct post-write stop RVAs: none
- A post-write stop RVA is the instruction pointer observed after the watched write; it is not asserted to be the store instruction's own RVA.

## Direct writer breakpoint callback audit

- fam2: setup enabled, resolution resolved, callback enters 0 (target transform 0, other opcodes 0), samples 0, sample errors 0
- fam4: setup enabled, resolution resolved, callback enters 0 (target transform 0, other opcodes 0), samples 0, sample errors 0
- fam3: setup enabled, resolution resolved, callback enters 0 (target transform 0, other opcodes 0), samples 0, sample errors 0
- fifth_1f30: setup enabled, resolution resolved, callback enters 0 (target transform 0, other opcodes 0), samples 0, sample errors 0

## Status

Captured 1 mapped 0x2700-byte candidate snapshots, but no final four-permutation planter signature was validated.


## Fixed-input CPIM determinism probe

Four offline runs reused the same saved SPIM, device identity, and restored adi-data seed. Two baseline runs used native execution; two frozen runs used GDB to replace the gettimeofday return value and the three confirmed RDTSC sites. Raw inputs, outputs, and digests remain private.

- SPIM input length: 347 bytes
- Baseline CPIM lengths: 276 / 276 bytes; equal: no
- Frozen CPIM lengths: 276 / 276 bytes; equal: no
- Frozen gettimeofday interceptions: 1
- Frozen RDTSC bypasses: 0
- Process exit codes (baseline A/B, frozen A/B): 0/0/0/0

Interpretation is conditional on all four runs producing CPIM and nonzero freeze-hit counts. Equal frozen outputs after differing baseline outputs support time/counter dependence; otherwise other entropy sources or state/input issues remain possible.

## Capture provenance manifest

- Fingerprint manifest: `capture-manifest-42897538965.json`
- Contains SHA-256 fingerprints and sizes only; raw captures, absolute paths, identity values and state filenames are excluded.
- Native-control SPIM/CPIM, offline replay outputs, and the separate GDB live run are recorded as distinct process groups.