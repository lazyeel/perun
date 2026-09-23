// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! `perun scaffold` — turn a trap report line into a ready-to-fill shim stub.
//!
//! The trap dispatchers print one line per unresolved import:
//! `[perun] TRAP: DLL!func(0x.., ...) — no implementation ...`
//! (and `TRAP(sysv):` for Mach-O guests). This command parses such lines and
//! emits a `win32_api!` skeleton with the observed arguments baked into a
//! comment, plus the source file whose family owns the API. The pure
//! functions below (parse/render/suggest) carry the unit tests; `run` is the
//! thin CLI shell around them.

/// One parsed trap report: the unresolved import plus the guest arguments
/// the dispatcher snapshot at the call site.
pub struct TrapCall {
    pub dll: String,
    pub func: String,
    pub args: [u64; 4],
}

/// Parse a single trap-report line. Accepts both the Win64 (`TRAP:`) and the
/// SysV (`TRAP(sysv):`) shapes, with or without the `[perun]` prefix.
/// Returns `None` for anything that is not a trap line. An empty function
/// name (`DLL!` with nothing after the bang) is an ordinal import — the
/// loader has no name to dispatch on — and parses with an empty `func`.
pub fn parse_trap_line(line: &str) -> Option<TrapCall> {
    // Accept the hint form verbatim: `perun scaffold '<trap line>'` pasted
    // back whole. Strip the command prefix and one layer of quotes first.
    let line = line.trim();
    let inner = if let Some(rest) = line
        .strip_prefix("perun scaffold")
        .filter(|r| r.starts_with(char::is_whitespace))
    {
        let rest = rest.trim();
        if rest.len() >= 2
            && ((rest.starts_with('\'') && rest.ends_with('\''))
                || (rest.starts_with('"') && rest.ends_with('"')))
        {
            &rest[1..rest.len() - 1]
        } else {
            rest
        }
    } else {
        line
    };
    let line = inner;
    // Full trap line (`[perun] TRAP: DLL!func(args) — ...`) or the bare
    // `DLL!func(args)` shape the scaffold hint quotes. Either way split off
    // the label before the first paren.
    let after_marker = if let Some(i) = line.find("TRAP(sysv):") {
        &line[i + "TRAP(sysv):".len()..]
    } else if let Some(i) = line.find("TRAP:") {
        &line[i + "TRAP:".len()..]
    } else {
        line
    };
    let after_marker = after_marker.trim_start();
    let open = after_marker.find('(')?;
    let label = after_marker[..open].trim();
    let rest = &after_marker[open + 1..];
    let close = rest.find(')')?;
    let (dll, func) = label.split_once('!')?;
    let dll = dll.trim();
    let func = func.trim();
    if dll.is_empty() || dll.contains(char::is_whitespace) {
        return None;
    }
    if !func.is_empty()
        && (func.contains(char::is_whitespace) || func.contains('(') || func.contains(')'))
    {
        return None;
    }
    let parts: Vec<&str> = rest[..close].split(',').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut args = [0u64; 4];
    for (i, p) in parts.iter().enumerate() {
        args[i] = parse_num(p.trim())?;
    }
    Some(TrapCall {
        dll: dll.to_string(),
        func: func.to_string(),
        args,
    })
}

fn parse_num(s: &str) -> Option<u64> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Which `perun-shims` source file owns the API family for a DLL name.
/// KERNEL32 spreads across several files by family, so the hint names the
/// candidates; anything without an existing home gets a new module.
pub fn suggest_file(dll: &str) -> &'static str {
    // Trap labels carry the upper-cased file name with its extension
    // (`KERNEL32.DLL`); match the stem so both spellings hit.
    let stem = dll
        .to_ascii_uppercase()
        .strip_suffix(".DLL")
        .map(str::to_string)
        .unwrap_or_else(|| dll.to_ascii_uppercase());
    match stem.as_str() {
        "ADVAPI32" => "crates/perun-shims/src/process.rs (Crypt*/Reg* live there)",
        "SHELL32" | "SHLWAPI" => "crates/perun-shims/src/shell_path.rs",
        "KERNEL32" => {
            "one of memory.rs (heap/virtual), files.rs (file IO), process.rs \
             (process/thread/time), strings_env.rs (env/module), sync.rs (sync) \
             or seh_tls.rs (SEH/TLS) — pick by family"
        }
        _ => "a new module in crates/perun-shims/src/ (declare it in lib.rs)",
    }
}

fn fmt_args(args: &[u64; 4]) -> String {
    args.iter()
        .map(|a| format!("{a:#x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Render the `win32_api!` stub for a parsed trap. The stub compiles as-is
/// and returns 0 so the guest stays alive; the TODO marks what the author
/// must still do (real signature, real semantics, right file).
pub fn render_stub(call: &TrapCall) -> String {
    let observed = fmt_args(&call.args);
    let file = suggest_file(&call.dll);
    if call.func.is_empty() {
        return format!(
            "// Scaffolded from trap: {dll}!(ordinal import, {observed}) — the loader\n\
             // saw an import by ordinal, so there is no name to dispatch on.\n\
             // Recover the ordinal from `perun info` on the guest, look the name up\n\
             // in the DLL's export table, then rename the stub below.\n\
             // Suggested file: {file}.\n\
             win32_api! {{\n\
             \x20   /// TRAP-observed args: ({observed}) — replace with the real signature.\n\
             \x20   pub unsafe extern \"win64\" fn UnnamedOrdinalImport(a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {{\n\
             \x20       // TODO: implement semantics; 0 keeps the guest alive.\n\
             \x20       let _ = (a0, a1, a2, a3);\n\
             \x20       0\n\
             \x20   }}\n\
             }}",
            dll = call.dll,
            observed = observed,
            file = file,
        );
    }
    format!(
        "// Scaffolded from trap: {dll}!{func}({observed}).\n\
         // Suggested file: {file}.\n\
         win32_api! {{\n\
         \x20   /// TRAP-observed args: ({observed}) — replace with the real signature.\n\
         \x20   pub unsafe extern \"win64\" fn {func}(a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {{\n\
         \x20       // TODO: implement {func} semantics; 0 keeps the guest alive.\n\
         \x20       let _ = (a0, a1, a2, a3);\n\
         \x20       0\n\
         \x20   }}\n\
         }}",
        dll = call.dll,
        func = call.func,
        observed = observed,
        file = file,
    )
}

/// `perun scaffold "TRAP-line" [...]`: print one stub per line on stdout.
/// Exit 2 on missing operands (usage error), 1 when any line fails to parse.
pub fn run(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!(
            "usage: perun scaffold \"TRAP-line\" [...]\n       \
             example: perun scaffold \"[perun] TRAP: KERNEL32!FooBar(0x1, 0x0, 0x0, 0x0) — no implementation\""
        );
        return 2;
    }
    let mut failed = false;
    for line in args {
        match parse_trap_line(line) {
            Some(call) => println!("{}", render_stub(&call)),
            None => {
                eprintln!("error: not a trap line: {line:?}");
                failed = true;
            }
        }
    }
    if failed { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIN64_LINE: &str = "[perun] TRAP: ADVAPI32!RegOpenKeyExA(0x80000002, 0x0, 0x0, 0x0) — no implementation (unresolved import; shim missing)";

    #[test]
    fn parses_win64_trap_line() {
        let c = parse_trap_line(WIN64_LINE).expect("must parse");
        assert_eq!(c.dll, "ADVAPI32");
        assert_eq!(c.func, "RegOpenKeyExA");
        assert_eq!(c.args, [0x80000002, 0, 0, 0]);
    }

    #[test]
    fn parses_sysv_trap_line_without_prefix() {
        let c = parse_trap_line(
            "TRAP(sysv): CoreFP!_SomeSymbol(0x1, 0x2, 0x3, 0x4) — no implementation",
        )
        .expect("must parse");
        assert_eq!(c.dll, "CoreFP");
        assert_eq!(c.func, "_SomeSymbol");
        assert_eq!(c.args, [1, 2, 3, 4]);
    }

    #[test]
    fn parses_ordinal_import_with_empty_name() {
        let c = parse_trap_line("[perun] TRAP: KERNEL32!(0x0, 0x0, 0x0, 0x0) — no implementation")
            .expect("must parse");
        assert_eq!(c.dll, "KERNEL32");
        assert!(c.func.is_empty());
    }

    #[test]
    fn parses_new_trap_shape_with_scaffold_hint() {
        let line = "[perun] TRAP: KERNEL32!FooBar(0x1, 0x0, 0xdead, 0x0) — no implementation (unresolved import; shim missing); scaffold a stub with: perun scaffold 'KERNEL32!FooBar(0x1, 0x0, 0xdead, 0x0)'";
        let c = parse_trap_line(line).expect("must parse");
        assert_eq!(c.dll, "KERNEL32");
        assert_eq!(c.func, "FooBar");
        assert_eq!(c.args, [1, 0, 0xdead, 0]);
    }

    #[test]
    fn parses_full_hint_verbatim() {
        let c = parse_trap_line(
            "perun scaffold 'KERNEL32.DLL!NoSuchApi12345(0x140000000, 0x1, 0x0, 0x0)'",
        )
        .expect("must parse");
        assert_eq!(c.dll, "KERNEL32.DLL");
        assert_eq!(c.func, "NoSuchApi12345");
        assert_eq!(c.args, [0x140000000, 1, 0, 0]);
    }

    #[test]
    fn rejects_non_trap_lines() {
        for bad in [
            "",
            "[perun] calling vdfut768ig(0x0, 0x0, 0x0, 0x0)...",
            "[perun] TRAP: KERNEL32!Foo(0x1, 0x2, 0x3) — no implementation",
            "[perun] TRAP: KERNEL32!Foo(0x1, 0x2, 0x3, 0xZZ) — no implementation",
            "[perun] TRAP: KERNEL32(0x1, 0x2, 0x3, 0x4)",
            "[perun] TRAP: !Foo(0x1, 0x2, 0x3, 0x4)",
            "[perun] TRAP: KERNEL32!Foo — no implementation",
        ] {
            assert!(parse_trap_line(bad).is_none(), "must reject {bad:?}");
        }
    }

    #[test]
    fn decimal_args_parse() {
        let c = parse_trap_line("[perun] TRAP: KERNEL32!Foo(1, 2, 3, 4) — no implementation")
            .expect("must parse");
        assert_eq!(c.args, [1, 2, 3, 4]);
    }

    #[test]
    fn render_names_func_file_and_args() {
        let c = parse_trap_line(WIN64_LINE).unwrap();
        let out = render_stub(&c);
        assert!(out.contains("fn RegOpenKeyExA"), "stub names the function");
        assert!(out.contains("process.rs"), "stub hints the owning file");
        assert!(out.contains("0x80000002"), "stub keeps observed args");
        assert!(out.contains("win32_api!"), "stub uses the shim macro");
    }

    #[test]
    fn render_ordinal_asks_for_rename() {
        let c = parse_trap_line("[perun] TRAP: KERNEL32!(0x0, 0x0, 0x0, 0x0) — no implementation")
            .unwrap();
        let out = render_stub(&c);
        assert!(out.contains("UnnamedOrdinalImport"));
        assert!(out.contains("perun info"));
    }

    #[test]
    fn file_hints_cover_known_dlls() {
        assert!(suggest_file("ADVAPI32").contains("process.rs"));
        assert!(suggest_file("shlwapi").contains("shell_path.rs"));
        assert!(suggest_file("kernel32").contains("memory.rs"));
        assert!(suggest_file("KERNEL32.DLL").contains("memory.rs"));
        assert!(suggest_file("USER32").contains("new module"));
    }
}
