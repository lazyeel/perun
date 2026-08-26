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
- [x] Located the gate global (RVA `0x19dda0`), the obfuscated pointer table
      (RVA `0x17eca0`), and the `cmp qword ptr [ctx],0` check (RVA `0x5b20f`)
- [x] Verified the gate is crypto-validated context, not a flippable scalar
      (80-value ctx[0x8] sweep + 2048-byte pointer map, all identical)
- [x] Cross-referenced with prior ADI/FairPlay research: matches
      `kADINotProvisioned` and the documented circular dependency broken by
      the `fpinit.itunes.apple.com` server handshake
- [x] Decoded the gate as a double dereference through an obfuscated pointer
      table; identified the runtime context object (HeapAlloc 0x28) and its
      object graph
- [x] Sentinel-patched all 37 error-code sites; found the one executed
      trampoline (`0x66c2d`) and the second failure exit (`0xb5b49`);
      demonstrated both are reporting stubs, not branch selectors
- [x] Confirmed CoreADI64.dll imports no network APIs — the fpinit handshake
      belongs to the caller, not this DLL
- [ ] Pass the gate: needs a real provisioning blob or the server handshake
      replicated in the caller layer
- [ ] Reach a real ADI operation (SAP/PAT exchange)

## Phase 3 — Tooling

- [ ] `perun scaffold`: generate a shim stub from a trap report
- [ ] Structured trap log (JSON) for offline analysis
- [ ] Optional `PERUN_APPDATA` seeding from a captured provisioning blob
