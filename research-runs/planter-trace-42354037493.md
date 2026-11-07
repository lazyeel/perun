# Android CoreADI planter-genesis trace

- GitHub run: `42354037493`
- Source revision: `2a2cb4557ef5a35718d52684f82273d9d077fa1f`
- GDB: `GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1`
- Harness/GDB exit code: `0`
- Trace directory created: `yes`

This report is intentionally redacted: no SPIM/CPIM, device identifier, raw memory bytes, pointer values, or register snapshots are published.

- Trace run id: `run-1794038878553864-11026`
- Tracer version: `v33`

## Early planter anchor

- Source+0x20 span mapped before transform: yes
- [rbp-0x30] equaled source+0x20 at source-slot store: no

## Window evolution (pre-transform → mixer read)

| Window | Mixer samples | First changed | Final changed | Final unique | Final permutation |
|---|---:|---:|---:|---:|---:|
| fam1 | 160 | 255/256 | 255/256 | 256/256 | yes |
| fam2 | 160 | 255/256 | 255/256 | 256/256 | yes |
| fam3 | 160 | 255/256 | 255/256 | 256/256 | yes |
| fam4 | 160 | 255/256 | 255/256 | 256/256 | yes |
| fifth_1f30 | 160 | 255/256 | 255/256 | 256/256 | yes |

## Live [rbp-0x30] slot sampling

- Mixer-read samples: 160
- 0x2700-byte RW span mapped (first → last): yes → yes
- Slot equals source+0x20 (first → last): yes → yes
- Slot equals writer-base candidate (first → last): yes → yes
- Slot pointer transitions between samples: 0

| Window | First unique | Final unique |
|---|---:|---:|
| fam1 | 256/256 | 256/256 |
| fam2 | 256/256 | 256/256 |
| fam3 | 256/256 | 256/256 |
| fam4 | 256/256 | 256/256 |
| fifth_1f30 | 256/256 | 256/256 |

## Slot-anchored object capture

- Slot-anchored object captured: yes

| Window | Unique values |
|---|---:|
| fam1 | 256/256 |
| fam2 | 256/256 |
| fam3 | 256/256 |
| fam4 | 256/256 |
| fifth_1f30 | 256/256 |

## Slot window index topology (first mixer read)

| Window | Unique | Zero count | Max multiplicity | Changed | Changed index range | Runs |
|---|---:|---:|---:|---:|---:|---:|
| fam1 | 256/256 | 1 | 1 | 255 | 0..255 | 2 |
| fam2 | 256/256 | 1 | 1 | 255 | 0..255 | 2 |
| fam3 | 256/256 | 1 | 1 | 255 | 0..255 | 2 |
| fam4 | 256/256 | 1 | 1 | 255 | 0..255 | 2 |
| fifth_1f30 | 256/256 | 1 | 1 | 255 | 0..254 | 1 |
## Full-object 256-byte permutation census

- Slot-anchored object bytes scanned: 9984
- Byte-aligned 256-byte permutation windows: 8

| Object offset | Cycles | Fixed points | Cycle-length histogram |
|---:|---:|---:|---|
| 0x0C50 | 12 | 2 | 1:2, 2:1, 3:1, 15:4, 17:1, 40:1, 50:1, 82:1 |
| 0x0D60 | 8 | 0 | 8:4, 56:4 |
| 0x1280 | 7 | 3 | 1:3, 3:1, 6:1, 10:1, 234:1 |
| 0x1390 | 8 | 0 | 8:2, 40:6 |
| 0x1A00 | 6 | 1 | 1:1, 51:5 |
| 0x1F2F | 9 | 3 | 1:3, 4:1, 6:1, 19:1, 26:1, 31:1, 167:1 |
| 0x1F30 | 6 | 1 | 1:1, 51:5 |
| 0x2460 | 2 | 0 | 2:1, 254:1 |

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
| First mixer read reached | yes |
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

- HTTP responses: 200 (25682 bytes) -> 200 (1109 bytes)
- SPIM decoded lengths: 347 bytes
- Provisioning fatal classifications: none observed

## Harness branch results

- ADIGetLoginCode results: -45061, -45061
- Trace-only ProvisioningStart: rc=0, cpim_len=276

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
- Mapped 0x2700 candidate snapshots: `33`
- Independent writer-window snapshots: `64`
- Final four-permutation snapshot: `yes`
- Source/planter overlap check executed: `yes`
- Snapshot selected for byte statistics: `final`

## Mapped candidate object snapshots

| Snapshot | Bytes | fam1 unique | fam2 unique | fam3 unique | fam4 unique |
|---|---:|---:|---:|---:|---:|
| planter.at_base_load.bin | 9984 | 1/256 | 1/256 | 9/256 | 1/256 |
| mixer_slot_candidate_e6b54.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6b54.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6bab.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6bab.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6bf7.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6bf7.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6c76.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6c76.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6cde.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6cde.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6d16.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6d16.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6d53.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6d53.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6daa.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6daa.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6e01.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6e01.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6e38.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6e38.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6e74.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6e74.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6ecd.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6ecd.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6f20.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6f20.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6f4e.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6f4e.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e6f84.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e6f84.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_slot_candidate_e7004.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |
| mixer_writer_base_candidate_e7004.bin | 9984 | 256/256 | 256/256 | 256/256 | 256/256 |

## Independent writer-window snapshots

| Window | Unique bytes | Permutation |
|---|---:|---:|
| window_fam2_at_e6b54.final_candidate | 256/256 | yes |
| window_fam2_at_e6bab.final_candidate | 256/256 | yes |
| window_fam2_at_e6bf7.final_candidate | 256/256 | yes |
| window_fam2_at_e6c76.final_candidate | 256/256 | yes |
| window_fam2_at_e6cde.final_candidate | 256/256 | yes |
| window_fam2_at_e6d16.final_candidate | 256/256 | yes |
| window_fam2_at_e6d53.final_candidate | 256/256 | yes |
| window_fam2_at_e6daa.final_candidate | 256/256 | yes |
| window_fam2_at_e6e01.final_candidate | 256/256 | yes |
| window_fam2_at_e6e38.final_candidate | 256/256 | yes |
| window_fam2_at_e6e74.final_candidate | 256/256 | yes |
| window_fam2_at_e6ecd.final_candidate | 256/256 | yes |
| window_fam2_at_e6f20.final_candidate | 256/256 | yes |
| window_fam2_at_e6f4e.final_candidate | 256/256 | yes |
| window_fam2_at_e6f84.final_candidate | 256/256 | yes |
| window_fam2_at_e7004.final_candidate | 256/256 | yes |
| window_fam3_at_e6b54.final_candidate | 256/256 | yes |
| window_fam3_at_e6bab.final_candidate | 256/256 | yes |
| window_fam3_at_e6bf7.final_candidate | 256/256 | yes |
| window_fam3_at_e6c76.final_candidate | 256/256 | yes |
| window_fam3_at_e6cde.final_candidate | 256/256 | yes |
| window_fam3_at_e6d16.final_candidate | 256/256 | yes |
| window_fam3_at_e6d53.final_candidate | 256/256 | yes |
| window_fam3_at_e6daa.final_candidate | 256/256 | yes |
| window_fam3_at_e6e01.final_candidate | 256/256 | yes |
| window_fam3_at_e6e38.final_candidate | 256/256 | yes |
| window_fam3_at_e6e74.final_candidate | 256/256 | yes |
| window_fam3_at_e6ecd.final_candidate | 256/256 | yes |
| window_fam3_at_e6f20.final_candidate | 256/256 | yes |
| window_fam3_at_e6f4e.final_candidate | 256/256 | yes |
| window_fam3_at_e6f84.final_candidate | 256/256 | yes |
| window_fam3_at_e7004.final_candidate | 256/256 | yes |
| window_fam4_at_e6b54.final_candidate | 256/256 | yes |
| window_fam4_at_e6bab.final_candidate | 256/256 | yes |
| window_fam4_at_e6bf7.final_candidate | 256/256 | yes |
| window_fam4_at_e6c76.final_candidate | 256/256 | yes |
| window_fam4_at_e6cde.final_candidate | 256/256 | yes |
| window_fam4_at_e6d16.final_candidate | 256/256 | yes |
| window_fam4_at_e6d53.final_candidate | 256/256 | yes |
| window_fam4_at_e6daa.final_candidate | 256/256 | yes |
| window_fam4_at_e6e01.final_candidate | 256/256 | yes |
| window_fam4_at_e6e38.final_candidate | 256/256 | yes |
| window_fam4_at_e6e74.final_candidate | 256/256 | yes |
| window_fam4_at_e6ecd.final_candidate | 256/256 | yes |
| window_fam4_at_e6f20.final_candidate | 256/256 | yes |
| window_fam4_at_e6f4e.final_candidate | 256/256 | yes |
| window_fam4_at_e6f84.final_candidate | 256/256 | yes |
| window_fam4_at_e7004.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6b54.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6bab.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6bf7.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6c76.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6cde.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6d16.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6d53.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6daa.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6e01.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6e38.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6e74.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6ecd.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6f20.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6f4e.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e6f84.final_candidate | 256/256 | yes |
| window_fifth_1f30_at_e7004.final_candidate | 256/256 | yes |
| fam1 | 256/256 | yes | 1 | 8 |
| fam2 | 256/256 | yes | 1 | 6 |
| fam3 | 256/256 | yes | 1 | 2 |
| fam4 | 256/256 | yes | 1 | 8 |

## Unknown regions

| Region | Size | Unique byte values |
|---|---:|---:|
| unknown_e60_1390 | 0x530 | 256 |
| unknown_1490_1a00 | 0x570 | 256 |
| unknown_1b00_1f30 | 0x430 | 256 |
| unknown_1f30_2460 | 0x530 | 256 |
| unknown_2560_2700 | 0x1a0 | 225 |

## Dynamic mixer memory operands

| Read site | Operands | Planter reads | External mapped reads | Location(s) | Base/index evidence | Width(s) | Expressions |
|---|---:|---:|---:|---|---|---|---|
| 0xe6b54 | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0xa..+0xe0, 10 unique | 1 | rcx+rax*1+0xd60 |
| 0xe6bab | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0x3f..+0xfa, 10 unique | 1 | rcx+rax*1+0x1a00 |
| 0xe6bf7 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0x1d..+0xab, 10 unique | 1 | rcx+rax*1+0x2460 |
| 0xe6c76 | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0xb..+0xf8, 10 unique | 1 | r14+rax*1-0x6da8b117 |
| 0xe6cde | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0x35..+0xf1, 10 unique | 1 | rcx+rax*1+0xd60 |
| 0xe6d16 | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0x24..+0xdf, 10 unique | 1 | rcx+rax*1+0x1a00 |
| 0xe6d53 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0xd..+0xfa, 10 unique | 1 | rcx+rax*1+0x2460 |
| 0xe6daa | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0x5..+0xdd, 10 unique | 1 | r14+rax*1-0x6da8b117 |
| 0xe6e01 | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0x1a..+0xf8, 9 unique | 1 | rcx+rax*1+0xd60 |
| 0xe6e38 | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0x18..+0xf1, 10 unique | 1 | rcx+rax*1+0x1a00 |
| 0xe6e74 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0x2b..+0xed, 10 unique | 1 | rcx+rax*1+0x2460 |
| 0xe6ecd | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0x68..+0xfa, 10 unique | 1 | r14+rax*1-0x6da8b117 |
| 0xe6f20 | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0xa..+0xff, 10 unique | 1 | r15+rax*1+0xd60 |
| 0xe6f4e | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0x30..+0xfd, 10 unique | 1 | r15+rax*1+0x1a00 |
| 0xe6f84 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0x10..+0xda, 10 unique | 1 | r15+rax*1+0x2460 |
| 0xe7004 | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0x17..+0xe9, 10 unique | 1 | r14+rax*1-0x6da8b117 |

## Runtime zone-data comparison

- Runtime capture: 0x300 bytes at libCoreADI.so+0x24070
- Runtime region SHA-256: 61f0336ab04a61f1f80a207ee98981cef7cad042231cc3fc1bdf27d6ef0d0f8c
- First 256-byte lookup table SHA-256: 2c7288c1e94fa04ff724ae26eb3cd3bb7950df9b8701cf1bf3be12559625d457

| Baked zone | Size | Exact 256-byte window offsets | Best equal bytes / 256 | Best offset | Whole 768-byte exact |
|---|---:|---|---:|---:|---|
| fam1_zone.bin | 0x300 | none | 5/256 | 0x21 | no |
| fam2_zone.bin | 0x300 | none | 6/256 | 0x81 | no |
| fam3_zone.bin | 0x300 | none | 6/256 | 0xbe | no |
| fam4_zone.bin | 0x300 | 0x8e | 256/256 | 0x8e | no |

## fam1 candidate writer site (RVA 0xE2441)

- Instruction boundary: verified from the decode beginning at 0xE243D.

| vdfut opcode | Mnemonic | Destination width | Memory-destination semantics | Hits | Fam1 byte-write hits | Distinct byte-write indices | Index min..max |
|---|---|---:|---|---:|---:|---:|---:|
| 0x716bd86c | mov | 1 | writes-memory-destination | 256 | 256 | 256 | 0x0..0xff |
- Source operand(s): r10b
- Source GPR(s): r10
- Source-byte unique values: 256/256
- Source-byte permutation: yes
- No exact affine or pairwise byte relation was found among captured index, GPR byte lanes, or frame-state byte lanes.
- Candidate callback errors: 0


## Direct writer coverage by opcode

| Writer | vdfut opcode | Hits | Distinct indices | Index min..max | Base−source delta |
|---|---|---:|---:|---:|---:|
| fam1_a | 0x716bd86c | 4 | 4 | 0x0..0x6 | +0x20..+0x20 |
| fam1_b | 0x716bd86c | 4 | 4 | 0x1..0x7 | +0x20..+0x20 |
| fam2 | 0x716bd86c | 256 | 256 | 0x0..0xff | +0x20..+0x20 |
| fam3 | 0x716bd86c | 256 | 256 | 0x0..0xff | +0x20..+0x20 |
| fam4 | 0x716bd86c | 256 | 256 | 0x0..0xff | +0x20..+0x20 |
| fifth_1f30 | 0x716bd86c | 256 | 256 | 0x0..0xff | +0x20..+0x20 |
| staging_write_a | 0x716bd86c | 160 | 160 | 0x0..0x9f | -0x8733550..-0x8733550 |
| staging_write_b | 0x716bd86c | 16 | 16 | 0xa0..0xaf | -0x8733550..-0x8733550 |

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

- fam2_tail: offset 0x1aff, setup hardware, write hits 1, distinct post-write stop RVAs: 0xe2510
- fam4_tail: offset 0x148f, setup hardware, write hits 1, distinct post-write stop RVAs: 0xe26b2
- fam3_control_tail: offset 0x255f, setup hardware, write hits 1, distinct post-write stop RVAs: 0xe25ca
- A post-write stop RVA is the instruction pointer observed after the watched write; it is not asserted to be the store instruction's own RVA.
- fam3_control_tail: candidate writer 0xe25c2, instruction mov    BYTE PTR [rdi+rax*1+0x2460],r8b, software breakpoint enabled yes, candidate EA equals watched byte yes, PC-after is next decoded instruction yes; observed store 0xe25c2 mov    BYTE PTR [rdi+rax*1+0x2460],r8b, width 1, EA match yes, method linear-from-confirmed-E24C9:explicit, PC instruction mov    r8,rdi, nearby decode +0xe254a inc    DWORD PTR [rcx+0x2]; +0xe254d or     al,0x11; +0xe254f xor    eax,0x52bd3046; +0xe2554 lea    edx,[rax+rax*1]; +0xe2557 add    edx,0x4; +0xe255a and    edx,0x10; +0xe255d neg    edx; +0xe255f lea    ebx,[rax+rdx*1]; +0xe2562 add    ebx,0xfa; +0xe2568 xor    ebx,esi; +0xe256a mov    rdx,r11; +0xe256d xor    bl,0xce; +0xe2570 xor    rdx,0x52bd30be; +0xe2577 mov    eax,edx; +0xe2579 mul    dl; +0xe257b add    al,bl; +0xe257d xor    r8b,0x73; +0xe2581 lea    ebx,[r8+r8*1]; +0xe2585 and    bl,0x72; +0xe2588 sub    r8b,bl; +0xe258b xor    r14b,0xcf; +0xe258f add    cl,r14b; +0xe2592 mov    ebx,ecx; +0xe2594 xor    bl,0x76; +0xe2597 add    cl,cl; +0xe2599 and    cl,0xe0; +0xe259c add    cl,bl; +0xe259e add    cl,0xb0; +0xe25a1 mov    rsi,r15; +0xe25a4 mov    BYTE PTR [rdi+r15*1+0xc50],cl; +0xe25ac add    al,BYTE PTR [r9+rdx*1]; +0xe25b0 xor    r10d,0x9b
- fam4_tail: candidate writer 0xe26aa, instruction mov    BYTE PTR [r8+rax*1+0x1390],r13b, software breakpoint enabled yes, candidate EA equals watched byte yes, PC-after is next decoded instruction yes; observed store 0xe26aa mov    BYTE PTR [r8+rax*1+0x1390],r13b, width 1, EA match yes, method linear-from-confirmed-E24C9:explicit, PC instruction mov    rax,QWORD PTR [rbp-0xd8], nearby decode +0xe2632 xor    BYTE PTR [rbp-0x49f0bdae],bh; +0xe2638 add    al,0x1f; +0xe263a or     r11b,0x75; +0xe263e sub    al,r11b; +0xe2641 movzx  eax,al; +0xe2644 imul   ecx,eax,0x4a; +0xe2647 imul   eax,eax,0xffffffa5; +0xe264a and    cl,0x2; +0xe264d sub    al,cl; +0xe264f lea    ecx,[rdx+rdx*1]; +0xe2652 add    ecx,0x2; +0xe2655 add    al,0x1; +0xe2657 and    ecx,0xa57a60ce; +0xe265d neg    ecx; +0xe265f lea    edi,[rdx+rcx*1]; +0xe2662 add    edi,0x52bd3068; +0xe2668 mov    ecx,eax; +0xe266a shr    cl,0x2; +0xe266d and    cl,0x5; +0xe2670 mov    edx,edi; +0xe2672 xor    edx,0x52bd3000; +0xe2678 xor    esi,esi; +0xe267a cmp    edx,0xff; +0xe2680 seta   sil; +0xe2684 mov    ebx,eax; +0xe2686 shr    bl,1; +0xe2688 and    bl,0x2; +0xe268b sub    cl,bl; +0xe268d add    cl,0x1; +0xe2690 xor    r13b,0xe2; +0xe2694 xor    cl,al; +0xe2696 lea    eax,[r13+r13*1+0x0]
- fam2_tail: candidate writer 0xe2508, instruction mov    BYTE PTR [rdi+rcx*1+0x1a00],r14b, software breakpoint enabled yes, candidate EA equals watched byte yes, PC-after is next decoded instruction yes; observed store 0xe2508 mov    BYTE PTR [rdi+rcx*1+0x1a00],r14b, width 1, EA match yes, method linear-from-confirmed-E24C9:explicit, PC instruction xor    eax,r12d, nearby decode +0xe2490 add    BYTE PTR [rax],al; +0xe2492 mov    r9,QWORD PTR [rbp-0xa0]; +0xe2499 movzx  ecx,BYTE PTR [r9+rax*1]; +0xe249e xor    r14b,0x60; +0xe24a2 lea    esi,[r14+r14*1]; +0xe24a6 and    sil,0xe; +0xe24aa sub    r14b,sil; +0xe24ad mov    ebx,eax; +0xe24af or     bl,0x2; +0xe24b2 mov    edx,ecx; +0xe24b4 sub    dl,bl; +0xe24b6 shl    dl,0x4; +0xe24b9 or     al,0x22; +0xe24bb sub    cl,al; +0xe24bd shr    cl,0x4; +0xe24c0 or     cl,dl; +0xe24c2 xor    cl,0xea; +0xe24c5 mov    r15,QWORD PTR [rbp-0x40]; +0xe24c9 mov    BYTE PTR [rdi+r15*1+0x1f30],cl; +0xe24d1 mov    rax,r11; +0xe24d4 xor    rax,0x52bd30d8; +0xe24da movzx  ecx,BYTE PTR [r9+rax*1]; +0xe24df mov    edx,eax; +0xe24e1 or     dl,0x2; +0xe24e4 mov    ebx,ecx; +0xe24e6 sub    bl,dl; +0xe24e8 or     al,0x22; +0xe24ea sub    cl,al; +0xe24ec mov    eax,r12d; +0xe24ef shr    eax,0x8; +0xe24f2 add    r14b,0x7; +0xe24f6 shl    bl,0x4

## Direct writer breakpoint callback audit

- fam2: setup enabled, resolution resolved, callback enters 256 (target transform 256, other opcodes 0), samples 256, sample errors 0
- fam4: setup enabled, resolution resolved, callback enters 256 (target transform 256, other opcodes 0), samples 256, sample errors 0
- fam3: setup enabled, resolution resolved, callback enters 256 (target transform 256, other opcodes 0), samples 256, sample errors 0
- fifth_1f30: setup enabled, resolution resolved, callback enters 256 (target transform 256, other opcodes 0), samples 256, sample errors 0

## Status

A final 0x2700-byte planter snapshot passed the four-permutation signature check.


## Fixed-input CPIM determinism probe

Four offline runs reused the same saved SPIM, device identity, and restored adi-data seed. Two baseline runs used native execution; two frozen runs used GDB to replace the gettimeofday return value and the three confirmed RDTSC sites. Raw inputs, outputs, and digests remain private.

- SPIM input length: 347 bytes
- Baseline CPIM lengths: 276 / 276 bytes; equal: no
- Frozen CPIM lengths: 276 / 276 bytes; equal: no
- Frozen gettimeofday interceptions: 1
- Frozen RDTSC bypasses: 0
- Process exit codes (baseline A/B, frozen A/B): 0/0/0/0

Interpretation is conditional on all four runs producing CPIM and nonzero freeze-hit counts. Equal frozen outputs after differing baseline outputs support time/counter dependence; otherwise other entropy sources or state/input issues remain possible.