# Android CoreADI planter-genesis trace

- GitHub run: `41197287670`
- Source revision: `c17c0eddbcf8a2ca55cd713b283a0d53bf39840e`
- GDB: `GNU gdb (Ubuntu 12.1-0ubuntu1~22.04.2) 12.1`
- Harness/GDB exit code: `0`
- Trace directory created: `yes`

This report is intentionally redacted: no SPIM/CPIM, device identifier, raw memory bytes, pointer values, or register snapshots are published.

- Trace run id: `run-1793446435874061-3898`
- Tracer version: `v12`

## GDB installation steps

| Stage | Reached |
|---|---:|
| target opcode requested installation | yes |
| command list entered installer | yes |
| language configured | yes |
| software watchpoints selected | yes |
| source-slot breakpoint created | no |
| post-malloc breakpoint created | no |
| copy-entry breakpoint created | no |
| command list returned to continue | yes |
- base-load breakpoints created: 0
- writer breakpoints created: 0
- mixer-read breakpoints created: 0

## Tracer progress

| Checkpoint | Reached |
|---|---:|
| Tracer initialized | yes |
| First vdfut768ig entry | yes |
| RVA breakpoints installed | no |
| Subsequent vdfut768ig entry logged | yes |
| Transform opcode observed | yes |
| Source pointer captured | no |
| malloc result captured | no |
| Planter base candidate observed | no |
| Source/planter overlap measured | no |
| Planter watches armed | no |
| First mixer read reached | no |
| Signal location captured | no |

## Tracer errors

- Breakpoint installation errors: 1
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
- Entry breakpoint command-list actions: skip 0x12db31c5, skip 0xb0eda7af, skip 0xb23c691e, skip 0xc774d292, skip 0xc774d292, skip 0xb0eda7af, install

## GDB console status

No allow-listed GDB console diagnostic matched.

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

The harness exited successfully, but no complete planter snapshot was recorded.
