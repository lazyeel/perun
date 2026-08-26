# Roadmap

## Phase 1 — Rust port of the working prototype

- [ ] PE32+ parser (headers, sections, data directories) in safe Rust where possible
- [ ] Section mapping with page-aligned protections (W^X aware)
- [ ] Base relocations (`DIR64`, `HIGHLOW`)
- [ ] Import resolution against the shim table
- [ ] Export lookup by name/ordinal
- [ ] `extern "win64"` shim plumbing; IAT filled with direct pointers
- [ ] Micro-stub pool for unresolved imports (`mov r10d, <idx>; jmp dispatcher`)
- [ ] Per-thread FakeTEB (`GS:[0x30]` self, `+0x58` TLS array, `+0x60` PEB,
      `+0x68` last error, stack bounds), installed via `arch_prctl(ARCH_SET_GS)`
- [ ] DllMain invocation from Rust; parity check against the C prototype

## Phase 2 — Runtime completeness

- [ ] Full UTF-16 ↔ UTF-8 conversion layer (surrogate pairs, best-fit for A-suffix APIs)
- [ ] Typed handle table: files, events, mutexes, pseudo-handles
- [ ] Synthetic registry backed by an INI-like store
- [ ] Thread creation interception: wrapper installs TEB/GS before guest start routine
- [ ] TLS slots (`TlsAlloc`/`TlsGetValue`/`TlsSetValue`/`TlsFree`)
- [ ] SEH surface stays minimal by design: detect-and-report stubs only

## Phase 3 — Developer experience

- [ ] `perun run <dll>` / `perun inspect <dll>` / `perun trace`
- [ ] Scaffolding generator: trap on unknown import → emit ready macro file
- [ ] Declarative `win32_api!` macro for adding implementations without touching the core
- [ ] Unit tests running entirely on Linux, no Windows toolchain needed
- [ ] Embedded-API example: call one export from any Linux program in two lines

## Explicitly out of scope (for now)

- Exception unwinding emulation (`.pdata`/`.xdata` walkers, personality routines)
- Graphics/DirectX/COM apartment model
- 32-bit (WoW64-style) images
