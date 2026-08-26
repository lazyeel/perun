# Roadmap

## Phase 1 — Loader and init (done)

- [x] PE32+ parser (headers, sections, data directories)
- [x] Section mapping with page-aligned protections
- [x] Base relocations (`DIR64`)
- [x] Import resolution against the shim table + trap-stub fallback
- [x] FakeTEB behind `GS_BASE`, FLS over inline TLS slots
- [x] Real stack bounds from pthread (MSVC `__chkstk` works)
- [x] `DllMain(DLL_PROCESS_ATTACH)` returns TRUE, zero traps

## Phase 2 — ADI dispatcher (in progress)

- [x] `perun call` export invoker (Win64 ABI, `scratch` param token)
- [x] Version query export `cvu8io98wun` returns the version struct
- [x] Dispatcher `vdfut768ig` executes full provisioning logic
- [x] Shell/path shims (`SHGetFolderPathW`, `PathAppendW`, `PathIsDirectoryW`,
      `GetFileAttributesW`) so the dispatcher resolves the `adi` directory
- [x] Confirmed the not-provisioned gate (`0xffff5016`) is in-memory and
      uniform across all commands
- [ ] Pass the in-memory provisioning gate (valid context / load-blob command)
- [ ] Reach a real ADI operation (SAP/PAT exchange)

## Phase 3 — Tooling

- [ ] `perun scaffold`: generate a shim stub from a trap report
- [ ] Structured trap log (JSON) for offline analysis
- [ ] Optional `PERUN_APPDATA` seeding from a captured provisioning blob
