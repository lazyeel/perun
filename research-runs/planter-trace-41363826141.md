# Android CoreADI planter-genesis trace

- GitHub run: `41363826141`
- Source revision: `8fad385ec35f1ef2a26ac503cf839b907a6c039e`
- GDB: `GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1`
- Harness/GDB exit code: `0`
- Trace directory created: `yes`

This report is intentionally redacted: no SPIM/CPIM, device identifier, raw memory bytes, pointer values, or register snapshots are published.

- Trace run id: `run-1793576930117712-4887`
- Tracer version: `v26`

## Early planter anchor

- Source+0x20 span mapped before transform: yes
- [rbp-0x30] equaled source+0x20 at source-slot store: no

## Window evolution (pre-transform → mixer read)

| Window | Mixer samples | First changed | Final changed | Final unique | Final permutation |
|---|---:|---:|---:|---:|---:|
| fam1 | 160 | 255/256 | 255/256 | 256/256 | yes |
| fam2 | 160 | 52/256 | 52/256 | 53/256 | no |
| fam3 | 160 | 255/256 | 255/256 | 256/256 | yes |
| fam4 | 160 | 196/256 | 196/256 | 197/256 | no |
| fifth_1f30 | 160 | 256/256 | 256/256 | 256/256 | yes |

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
| fam4 | 197/256 | 197/256 |
| fifth_1f30 | 256/256 | 256/256 |

## Slot-anchored object capture

- Slot-anchored object captured: yes

| Window | Unique values |
|---|---:|
| fam1 | 256/256 |
| fam2 | 53/256 |
| fam3 | 256/256 |
| fam4 | 197/256 |
| fifth_1f30 | 256/256 |

## Slot window index topology (first mixer read)

| Window | Unique | Zero count | Max multiplicity | Changed | Changed index range | Runs |
|---|---:|---:|---:|---:|---:|---:|
| fam1 | 256/256 | 1 | 1 | 255 | 0..255 | 2 |
| fam2 | 53/256 | 204 | 204 | 52 | 204..255 | 1 |
| fam3 | 256/256 | 1 | 1 | 255 | 0..255 | 2 |
| fam4 | 197/256 | 60 | 60 | 196 | 60..255 | 1 |
| fifth_1f30 | 256/256 | 1 | 1 | 256 | 0..255 | 1 |
## Full-object 256-byte permutation census

- Slot-anchored object bytes scanned: 9984
- Byte-aligned 256-byte permutation windows: 5

| Object offset | Cycles | Fixed points | Cycle-length histogram |
|---:|---:|---:|---|
| 0x0C50 | 6 | 2 | 1:2, 2:1, 13:1, 67:1, 172:1 |
| 0x0D60 | 4 | 1 | 1:1, 85:3 |
| 0x1280 | 5 | 0 | 3:1, 8:2, 114:1, 123:1 |
| 0x1F30 | 4 | 0 | 4:2, 124:2 |
| 0x2460 | 16 | 2 | 1:2, 2:1, 3:2, 4:1, 6:1, 7:2, 12:1, 14:1, 21:2, 28:1, 42:1, 84:1 |

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

- HTTP responses: 200 (25691 bytes) -> 200 (1109 bytes)
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
| mixer_slot_candidate_e6b54.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6b54.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6bab.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6bab.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6bf7.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6bf7.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6c76.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6c76.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6cde.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6cde.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6d16.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6d16.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6d53.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6d53.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6daa.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6daa.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6e01.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6e01.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6e38.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6e38.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6e74.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6e74.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6ecd.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6ecd.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6f20.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6f20.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6f4e.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6f4e.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e6f84.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e6f84.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_slot_candidate_e7004.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |
| mixer_writer_base_candidate_e7004.bin | 9984 | 256/256 | 53/256 | 256/256 | 197/256 |

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
| fam1 | 256/256 | yes | 1 | 4 |
| fam2 | 53/256 | no | 204 | n/a |
| fam3 | 256/256 | yes | 1 | 16 |
| fam4 | 197/256 | no | 60 | n/a |

## Unknown regions

| Region | Size | Unique byte values |
|---|---:|---:|
| unknown_e60_1390 | 0x530 | 256 |
| unknown_1490_1a00 | 0x570 | 256 |
| unknown_1b00_1f30 | 0x430 | 256 |
| unknown_1f30_2460 | 0x530 | 256 |
| unknown_2560_2700 | 0x1a0 | 216 |

## Dynamic mixer memory operands

| Read site | Operands | Planter reads | External mapped reads | Location(s) | Base/index evidence | Width(s) | Expressions |
|---|---:|---:|---:|---|---|---|---|
| 0xe6b54 | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0x30..+0xfc, 9 unique | 1 | rcx+rax*1+0xd60 |
| 0xe6bab | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0x4..+0xdd, 10 unique | 1 | rcx+rax*1+0x1a00 |
| 0xe6bf7 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0x36..+0xf6, 10 unique | 1 | rcx+rax*1+0x2460 |
| 0xe6c76 | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0x5..+0xf5, 7 unique | 1 | r14+rax*1-0x6da8b117 |
| 0xe6cde | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0x18..+0xff, 10 unique | 1 | rcx+rax*1+0xd60 |
| 0xe6d16 | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0xd..+0xf6, 10 unique | 1 | rcx+rax*1+0x1a00 |
| 0xe6d53 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0x6..+0xf6, 10 unique | 1 | rcx+rax*1+0x2460 |
| 0xe6daa | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0x7..+0xff, 8 unique | 1 | r14+rax*1-0x6da8b117 |
| 0xe6e01 | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0x27..+0xea, 9 unique | 1 | rcx+rax*1+0xd60 |
| 0xe6e38 | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0x27..+0xef, 10 unique | 1 | rcx+rax*1+0x1a00 |
| 0xe6e74 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0x3..+0xdc, 10 unique | 1 | rcx+rax*1+0x2460 |
| 0xe6ecd | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0xe..+0xf2, 9 unique | 1 | r14+rax*1-0x6da8b117 |
| 0xe6f20 | 10 | 10 | 0 | planter only | planter+0xd60 (10); indices +0x8..+0xfc, 10 unique | 1 | r15+rax*1+0xd60 |
| 0xe6f4e | 10 | 10 | 0 | planter only | planter+0x1a00 (10); indices +0x5..+0xe5, 10 unique | 1 | r15+rax*1+0x1a00 |
| 0xe6f84 | 10 | 10 | 0 | planter only | planter+0x2460 (10); indices +0x40..+0xe2, 10 unique | 1 | r15+rax*1+0x2460 |
| 0xe7004 | 10 | 0 | 10 | libCoreADI.so:module-rva (10) | libCoreADI.so+0x24070 (10); indices +0x48..+0xfa, 8 unique | 1 | r14+rax*1-0x6da8b117 |

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
