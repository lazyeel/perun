# Android CoreADI planter-genesis trace

- GitHub run: `41110283258`
- Source revision: `78d9175a552f27d9f554c9e6cea96d660abe188d`
- GDB: `GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1`
- Harness/GDB exit code: `139`
- Trace directory created: `yes`

This report is intentionally redacted: no SPIM/CPIM, device identifier, raw memory bytes, pointer values, or register snapshots are published.

- Trace run id: `run-1793386292645211-3026`
- Tracer version: `v7`

## Tracer progress

| Checkpoint | Reached |
|---|---:|
| Tracer initialized | yes |
| First vdfut768ig entry | yes |
| Transform opcode observed | no |
| Source pointer captured | no |
| malloc result captured | no |
| Planter base candidate observed | no |
| Source/planter overlap measured | no |
| Planter watches armed | no |
| First mixer read reached | no |

## Tracer errors

- Breakpoint installation errors: 0
- Watchpoint setup errors: 0
- Watchpoint callback errors: 0

## GDB console status

- Segmentation fault reported by launcher/child

## Capture checkpoints

- Planter watches armed: `no`
- First-mixer snapshot: `no`
- Source/planter overlap check executed: `no`

## Known family windows

| Family | Unique bytes | Permutation | Zero bytes | Cycles |
|---|---:|---:|---:|---:|
| fam1 | 0/256 | no | n/a | n/a |
| fam2 | 0/256 | no | n/a | n/a |
| fam3 | 0/256 | no | n/a | n/a |
| fam4 | 0/256 | no | n/a | n/a |

## Unknown regions

| Region | Size | Unique byte values |
|---|---:|---:|
| unknown_e60_1390 | 0x530 | n/a |
| unknown_1490_1a00 | 0x570 | n/a |
| unknown_1b00_1f30 | 0x430 | n/a |
| unknown_1f30_2460 | 0x530 | n/a |
| unknown_2560_2700 | 0x1a0 | n/a |

## Direct writer coverage

| Writer | Hits | Distinct indices | Index min..max |
|---|---:|---:|---:|

## Status

The run did not produce a complete planter snapshot. Raw traces remain on the ephemeral runner and are not published.
