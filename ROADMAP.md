# Roadmap

## Phase 1 — Loader and init (done)

- [x] PE32+ parser (headers, sections, data directories)
- [x] Section mapping with page-aligned protections
- [x] Base relocations (`DIR64`)
- [x] Import resolution against the shim table
- [x] Export lookup by name/ordinal
- [x] `extern "win64"` shim plumbing; IAT filled with direct pointers
- [x] Micro-stub pool for unresolved imports (absolute `jmp [rip+0]`)
- [x] Per-thread FakeTEB installed via `arch_prctl(ARCH_SET_GS)`
- [x] FLS (`FlsAlloc`/`FlsGetValue`/`FlsSetValue`/`FlsFree`) over TEB TLS slots
- [x] `DllMain(DLL_PROCESS_ATTACH)` returns TRUE on CoreADI64.dll, zero traps

## Phase 2 — The actual goal: ADI dispatcher

- [ ] Call the ADI dispatcher export (`cvu8io98wun`, RVA `0xe4b00`) with
      provisioning parameters after init
- [ ] Map the dispatcher's expected inputs (device identity, attestation
      material) onto values the runtime can supply
- [ ] Observe and decode the dispatcher's response / error path
- [ ] Grow the shim surface as the dispatcher exercises more Win32 APIs

## Phase 3 — Runtime completeness

- [ ] Full UTF-16 ↔ UTF-8 conversion layer (surrogate pairs, best-fit for
      A-suffix APIs)
- [ ] Thread creation interception: wrapper installs TEB/GS before guest
      start routine
- [ ] SEH surface stays minimal by design: detect-and-report stubs only

## Phase 4 — Developer experience

- [ ] `perun scaffold`: trap on unknown import → emit ready macro file
- [ ] Embedded-API example: call one export from any Linux program in two
      lines

## Explicitly out of scope (for now)

- Exception unwinding emulation (`.pdata`/`.xdata` walkers, personality
  routines)
- Graphics/DirectX/COM apartment model
- 32-bit (WoW64-style) images
