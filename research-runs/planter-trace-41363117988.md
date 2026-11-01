# Android CoreADI planter-genesis trace

- GitHub run: `41363117988`
- Source revision: `4bcb520b14393892190ec76497e7d0282a2c7a89`
- GDB: `GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1`
- Harness/GDB exit code: `0`
- Trace directory created: `yes`

This report is intentionally redacted: no SPIM/CPIM, device identifier, raw memory bytes, pointer values, or register snapshots are published.

- Trace run id: `run-1793576395122080-4234`
- Tracer version: `v25`

## Early planter anchor

- Source+0x20 span mapped before transform: yes
- [rbp-0x30] equaled source+0x20 at source-slot store: no

## Window evolution (pre-transform → mixer read)

| Window | Mixer samples | First changed | Final changed | Final unique | Final permutation |
|---|---:|---:|---:|---:|---:|
| fam1 | 160 | 255/256 | 255/256 | 256/256 | yes |
| fam2 | 160 | 52/256 | 52/256 | 53/256 | no |
| fam3 | 160 | 255/256 | 255/256 | 256/256 | yes |
| fam4 | 160 | 195/256 | 195/256 | 196/256 | no |
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
| fam2 | 53/256 | 53/256 |
| fam3 | 256/256 | 256/256 |
| fam4 | 196/256 | 196/256 |
| fifth_1f30 | 256/256 | 256/256 |

## Slot-anchored object capture

- Slot-anchored object captured: yes

| Window | Unique values |
|---|---:|
| fam1 | 256/256 |
| fam2 | 53/256 |
| fam3 | 256/256 |
| fam4 | 196/256 |
| fifth_1f30 | 256/256 |

## Slot window index topology (first mixer read)

| Window | Unique | Zero count | Max multiplicity | Changed | Changed index range | Runs |
|---|---:|---:|---:|---:|---:|---:|
| fam1 | 256/256 | 1 | 1 | 255 | 0..255 | 2 |
| fam2 | 53/256 | 204 | 204 | 52 | 204..255 | 1 |
| fam3 | 256/256 | 1 | 1 | 255 | 0..255 | 2 |
| fam4 | 196/256 | 61 | 61 | 195 | 60..255 | 2 |
| fifth_1f30 | 256/256 | 1 | 1 | 255 | 0..255 | 2 |
## Full-object 256-byte permutation census

- Slot-anchored object bytes scanned: 9984
- Byte-aligned 256-byte permutation windows: 5

| Object offset | Cycles | Fixed points | Cycle-length histogram |
|---:|---:|---:|---|
| 0x0C50 | 8 | 1 | 1:1, 2:1, 3:1, 23:1, 45:1, 48:1, 63:1, 71:1 |
| 0x0D60 | 6 | 1 | 1:1, 3:1, 63:4 |
| 0x1280 | 5 | 2 | 1:2, 3:1, 12:1, 239:1 |
| 0x1F30 | 24 | 0 | 4:4, 12:20 |
| 0x2460 | 4 | 0 | 2:1, 14:1, 30:1, 210:1 |

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

- HTTP responses: 200 (25685 bytes) -> 200 (1109 bytes)
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

- Four-permutation candidate: no
- RW regions scanned: 62
- Bytes inspected: 8970752

## Capture checkpoints

- Software watchpoints armed: `no`
- Planter base candidate logged: `yes`
- Mapped 0x2700 candidate snapshots: `33`
- Independent writer-window snapshots: `32`
- Final four-permutation snapshot: `no`
- Source/planter overlap check executed: `yes`
- Snapshot selected for byte statistics: `candidate:mixer_writer_base_candidate_e7004.bin`

## Mapped candidate object snapshots

| Snapshot | Bytes | fam1 unique | fam2 unique | fam3 unique | fam4 unique |
|---|---:|---:|---:|---:|---:|
| planter.at_base_load.bin | 9984 | 1/256 | 1/256 | 9/256 | 1/256 |
| mixer_slot_candidate_e6b54.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6b54.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6bab.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6bab.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6bf7.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6bf7.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6c76.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6c76.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6cde.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6cde.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6d16.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6d16.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6d53.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6d53.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6daa.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6daa.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6e01.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6e01.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6e38.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6e38.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6e74.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6e74.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6ecd.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6ecd.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6f20.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6f20.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6f4e.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6f4e.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e6f84.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e6f84.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_slot_candidate_e7004.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |
| mixer_writer_base_candidate_e7004.bin | 9984 | 256/256 | 53/256 | 256/256 | 196/256 |

## Independent writer-window snapshots

| Window | Unique bytes | Permutation |
|---|---:|---:|
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
| fam1 | 256/256 | yes | 1 | 6 |
| fam2 | 53/256 | no | 204 | n/a |
| fam3 | 256/256 | yes | 1 | 4 |
| fam4 | 196/256 | no | 61 | n/a |

## Unknown regions

| Region | Size | Unique byte values |
|---|---:|---:|
| unknown_e60_1390 | 0x530 | 256 |
| unknown_1490_1a00 | 0x570 | 256 |
| unknown_1b00_1f30 | 0x430 | 256 |
| unknown_1f30_2460 | 0x530 | 256 |
| unknown_2560_2700 | 0x1a0 | 228 |

## Dynamic mixer memory operands

| Read site | Operands | Planter reads | External mapped reads | Location(s) | Base/index evidence | Width(s) | Expressions |
|---|---:|---:|---:|---|---|---|---|
| 0xe6b54 | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0xe..+0xee, 10 unique | 1 | rcx+rax*1+0xd60 |
| 0xe6bab | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0x8..+0xf6, 10 unique | 1 | rcx+rax*1+0x1a00 |
| 0xe6bf7 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0x4..+0xf9, 10 unique | 1 | rcx+rax*1+0x2460 |
| 0xe6c76 | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0x5..+0xa1, 6 unique | 1 | r14+rax*1-0x6da8b117 |
| 0xe6cde | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0x8..+0xf5, 10 unique | 1 | rcx+rax*1+0xd60 |
| 0xe6d16 | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0xf..+0xfe, 9 unique | 1 | rcx+rax*1+0x1a00 |
| 0xe6d53 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0xb..+0xf5, 9 unique | 1 | rcx+rax*1+0x2460 |
| 0xe6daa | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0x7..+0xea, 8 unique | 1 | r14+rax*1-0x6da8b117 |
| 0xe6e01 | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0x36..+0xe3, 10 unique | 1 | rcx+rax*1+0xd60 |
| 0xe6e38 | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0x5..+0xfa, 10 unique | 1 | rcx+rax*1+0x1a00 |
| 0xe6e74 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0x12..+0xdd, 10 unique | 1 | rcx+rax*1+0x2460 |
| 0xe6ecd | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0x9..+0xdd, 6 unique | 1 | r14+rax*1-0x6da8b117 |
| 0xe6f20 | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0x1..+0xff, 10 unique | 1 | r15+rax*1+0xd60 |
| 0xe6f4e | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0x2..+0xed, 10 unique | 1 | r15+rax*1+0x1a00 |
| 0xe6f84 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0x9..+0xf6, 10 unique | 1 | r15+rax*1+0x2460 |
| 0xe7004 | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0x48..+0xe1, 6 unique | 1 | r14+rax*1-0x6da8b117 |

## Direct writer coverage by opcode

| Writer | vdfut opcode | Hits | Distinct indices | Index min..max | Base−source delta |
|---|---|---:|---:|---:|---:|
| fam1_a | 0x716bd86c | 4 | 4 | 0x0..0x6 | +0x20..+0x20 |
| fam1_b | 0x716bd86c | 4 | 4 | 0x1..0x7 | +0x20..+0x20 |
| fam3 | 0x716bd86c | 256 | 256 | 0x0..0xff | +0x20..+0x20 |
| fifth_1f30 | 0x716bd86c | 256 | 256 | 0x0..0xff | +0x20..+0x20 |
| staging_write_a | 0x716bd86c | 160 | 160 | 0x0..0x9f | -0x8733540..-0x8733540 |
| staging_write_b | 0x716bd86c | 16 | 16 | 0xa0..0xaf | -0x8733540..-0x8733540 |

## Status

Captured 33 mapped 0x2700-byte candidate snapshots, but no final four-permutation planter signature was validated.
