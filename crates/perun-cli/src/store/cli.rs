// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! CLI front for the Store lane.
//!
//! Two personas, one binary:
//! - `perun` — the native-runtime tool: `perun store …`, `perun sap …`,
//!   plus the ipatool-compatible top-level commands;
//! - `ipatool` — argv[0]-detected drop-in replacement (also built as a
//!   separate cargo bin): only the majd/ipatool grammar exists.
//!
//! The grammar is a 1:1 port of majd/ipatool v2 (cobra): positional
//! `<term>` for search, required flags with cobra's exact error strings,
//! global `--format/--verbose/--non-interactive/--keychain-passphrase`,
//! `-h/--help`, `--version`, exit code 1 on every failure.
//!
//! The SAP signer runs on the dedicated guest thread with the same stack
//! geometry as `perun sap` (the obfuscated guest requires it), so every
//! command that signs ships through `store::run_on_sap_thread`.

use std::io::Write as _;

use crate::store::account::{self, Account};
use crate::store::appstore::StoreError;
use crate::store::{appstore, bag, out, signer};

/// Which word the binary was invoked as.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Persona {
    Perun,
    Ipatool,
}

impl Persona {
    pub fn detect() -> Persona {
        let argv0 = std::env::args().next().unwrap_or_default();
        let base = argv0
            .rsplit('/')
            .next()
            .unwrap_or(&argv0)
            .trim_end_matches(".exe");
        if base.eq_ignore_ascii_case("ipatool") {
            Persona::Ipatool
        } else {
            Persona::Perun
        }
    }
    fn name(self) -> &'static str {
        match self {
            Persona::Perun => "perun",
            Persona::Ipatool => "ipatool",
        }
    }
}

// ── cobra-shaped flag parsing ────────────────────────────────────────────

/// One parsed command invocation: globals + command flags + positionals.
pub struct Invocation {
    pub format: out::Format,
    pub verbose: bool,
    pub interactive: bool,
    pub keychain_passphrase: String,
    /// Command-local flags in `-i`/`--app-id` resolved pairs.
    pub flags: Vec<(String, String)>,
    pub positional: Vec<String>,
    /// `Some(reason)` → a usage failure with cobra's message.
    pub usage_error: Option<String>,
    pub help_requested: bool,
    pub version_requested: bool,
}

impl Invocation {
    fn new() -> Invocation {
        Invocation {
            format: out::Format::Text,
            verbose: false,
            interactive: true,
            keychain_passphrase: String::new(),
            flags: Vec::new(),
            positional: Vec::new(),
            usage_error: None,
            help_requested: false,
            version_requested: false,
        }
    }

    pub fn get(&self, names: &[&str]) -> Option<&str> {
        names.iter().find_map(|n| {
            self.flags
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.as_str())
        })
    }

    pub fn has(&self, name: &str) -> bool {
        self.flags.iter().any(|(k, _)| k == name)
    }
}

/// Parse the argv of one command (after the command word). `locals` are
/// the command's own flags, both short and long forms. Boolean flags
/// never consume the next token. Unknown flags are cobra errors.
fn parse(argv: &[String], locals: &[(&str, bool)]) -> Invocation {
    let mut inv = Invocation::new();
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--" {
            inv.positional.extend(argv[i + 1..].iter().cloned());
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            let matched = match name {
                "format" => {
                    let value = match inline {
                        Some(v) => v,
                        None => {
                            i += 1;
                            match argv.get(i) {
                                Some(v) => v.clone(),
                                None => {
                                    inv.usage_error =
                                        Some("flag needs an argument: --format".into());
                                    return inv;
                                }
                            }
                        }
                    };
                    match value.as_str() {
                        "text" => inv.format = out::Format::Text,
                        "json" => inv.format = out::Format::Json,
                        other => {
                            inv.usage_error = Some(format!(
                                "invalid argument \"{other}\" for \"--format\" flag: must be 'json', 'text'"
                            ));
                            return inv;
                        }
                    }
                    true
                }
                "verbose" => {
                    inv.verbose = true;
                    true
                }
                "non-interactive" => {
                    inv.interactive = false;
                    true
                }
                "keychain-passphrase" => {
                    let value = match inline {
                        Some(v) => v,
                        None => {
                            i += 1;
                            match argv.get(i) {
                                Some(v) => v.clone(),
                                None => {
                                    inv.usage_error = Some(
                                        "flag needs an argument: --keychain-passphrase".into(),
                                    );
                                    return inv;
                                }
                            }
                        }
                    };
                    inv.keychain_passphrase = value;
                    true
                }
                "help" => {
                    inv.help_requested = true;
                    true
                }
                "version" => {
                    inv.version_requested = true;
                    true
                }
                _ => {
                    let long_form = format!("--{name}");
                    if let Some((_, takes_value)) =
                        locals.iter().find(|(n, _)| *n == long_form.as_str())
                    {
                        let value = if *takes_value {
                            match inline {
                                Some(v) => v,
                                None => {
                                    i += 1;
                                    match argv.get(i) {
                                        Some(v) => v.clone(),
                                        None => {
                                            inv.usage_error =
                                                Some(format!("flag needs an argument: --{name}"));
                                            return inv;
                                        }
                                    }
                                }
                            }
                        } else {
                            "true".into()
                        };
                        inv.flags.push((long_form, value));
                        true
                    } else {
                        inv.usage_error = Some(format!("unknown flag: --{name}"));
                        return inv;
                    }
                }
            };
            let _ = matched;
            i += 1;
            continue;
        }
        if a.len() > 1 && a.starts_with('-') {
            let short = &a[1..];
            if let Some((name, takes_value)) = locals.iter().find(|(n, _)| {
                n.trim_start_matches('-') == short.trim_start_matches('-')
                    && n.starts_with('-')
                    && !n.starts_with("--")
            }) {
                let _ = name;
                if *takes_value {
                    let value = if a.len() > 2 {
                        a[2..].to_string()
                    } else {
                        i += 1;
                        match argv.get(i) {
                            Some(v) => v.clone(),
                            None => {
                                inv.usage_error = Some(format!("flag needs an argument: {name}"));
                                return inv;
                            }
                        }
                    };
                    inv.flags.push((name.to_string(), value));
                } else {
                    inv.flags.push((name.to_string(), "true".into()));
                }
                i += 1;
                continue;
            }
            match short {
                "h" => inv.help_requested = true,
                "v" => inv.version_requested = true,
                _ => {
                    inv.usage_error = Some(format!("unknown shorthand flag: '{short}'"));
                    return inv;
                }
            }
            i += 1;
            continue;
        }
        inv.positional.push(a.to_string());
        i += 1;
    }
    inv
}

// ── platform words (majd ParsePlatform 1:1) ───────────────────────────────

/// Returns the canonical platform word, or a cobra-shaped error for an
/// unknown value. Empty input maps to `""` (the mixed iphone/ipad lookups).
pub fn parse_platform(value: &str) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        "" => Ok(String::new()),
        "iphone" | "ios" => Ok("iphone".into()),
        "ipad" | "ipados" => Ok("ipad".into()),
        "appletv" | "apple-tv" | "tvos" => Ok("appletv".into()),
        "vision" | "visionos" | "visionpro" | "xros" | "realitydevice" => Ok("visionos".into()),
        "mac" | "macos" | "osx" => Ok("macos".into()),
        other => Err(format!("invalid platform \"{other}\"")),
    }
}

/// The `metadataPlatform` for the MDM version lookup (atv9 / realityDevice).
fn platform_metadata(platform: &str) -> Option<&'static str> {
    match platform {
        "iphone" | "ipad" => Some("enterprisestore"),
        "appletv" => Some("atv9"),
        "visionos" => Some("realityDevice"),
        _ => None,
    }
}

// ── entry ─────────────────────────────────────────────────────────────────

pub fn run(args: &[String]) -> i32 {
    let args: Vec<String> = args.to_vec();
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || {
            unsafe { crate::sap::install_thread_altstack() };
            dispatch(&args)
        })
        .expect("spawn store thread")
        .join()
        .unwrap_or_else(|_| {
            eprintln!("[store] thread panicked");
            1
        })
}

fn dispatch(args: &[String]) -> i32 {
    let persona = Persona::detect();
    if args.is_empty() {
        print_root_help(persona);
        return if persona == Persona::Ipatool { 0 } else { 2 };
    }
    // Cobra accepts global flags before the command word (`ipatool --format
    // json search x`): strip the leading globals into `pre`, which each
    // command's parser sees first.
    let mut pre: Vec<String> = Vec::new();
    let mut idx = 0;
    while idx < args.len() {
        let a = args[idx].as_str();
        let skip_next = match a {
            "--format" | "--keychain-passphrase" => true,
            "--verbose" | "--non-interactive" | "-v" | "--version" | "-h" | "--help" => false,
            _ => break,
        };
        pre.push(a.to_string());
        idx += 1;
        if skip_next && idx < args.len() {
            pre.push(args[idx].clone());
            idx += 1;
        }
    }
    if idx >= args.len() {
        // only globals: --version/-h/-v handled; bare --format etc. = no command
        if pre.iter().any(|a| a == "--version" || a == "-v") {
            println!("{} version {}", persona.name(), env!("CARGO_PKG_VERSION"));
            return 0;
        }
        if pre.iter().any(|a| a == "-h" || a == "--help") {
            print_root_help(persona);
            return 0;
        }
        print_root_help(persona);
        return if persona == Persona::Ipatool { 0 } else { 2 };
    }
    let cmd = args[idx].as_str();
    let mut rest: Vec<String> = pre;
    rest.extend_from_slice(&args[idx + 1..]);
    let rest: &[String] = &rest;

    // The bare `help` command and `--help`/`-h`/`--version`/`-v` at root.
    if cmd == "help" {
        print_root_help(persona);
        return 0;
    }
    if (cmd == "--help" || cmd == "-h" || cmd == "--version" || cmd == "-v") && rest.is_empty() {
        if cmd == "--help" || cmd == "-h" {
            print_root_help(persona);
        } else {
            println!("{} version {}", persona.name(), env!("CARGO_PKG_VERSION"));
        }
        return 0;
    }
    if rest.iter().any(|a| a == "--version" || a == "-v") && !cmd_wants_positionals(cmd) {
        println!("{} version {}", persona.name(), env!("CARGO_PKG_VERSION"));
        return 0;
    }

    match cmd {
        "auth" => cmd_auth(persona, rest),
        "search" => cmd_search(persona, rest),
        "purchase" => cmd_purchase(persona, rest),
        "download" => cmd_download(persona, rest),
        "list-purchases" => cmd_list_purchases(persona, rest),
        "list-versions" => cmd_list_versions(persona, rest),
        "get-version-metadata" => cmd_get_version_metadata(persona, rest),
        "completion" => {
            if persona == Persona::Ipatool {
                // Cobra generates real shell scripts; a functional stub is
                // worse than honesty, but the command must exist.
                completion_stub(rest);
                0
            } else {
                unknown_command(persona, cmd)
            }
        }
        _ => unknown_command(persona, cmd),
    }
}

/// Cobra prints `Error: unknown command "x" for "ipatool"` and the usage
/// block, all to stderr, rc=1 in ipatool mode. In perun mode the native
/// grammar is surfaced instead.
fn unknown_command(persona: Persona, cmd: &str) -> i32 {
    match persona {
        // Cobra's SilenceErrors/SilenceUsage: the Execute() wrapper routes
        // the error through the logger — `error="unknown command ..."`,
        // rc=1 — not the raw cobra banner.
        Persona::Ipatool => {
            let out = out::Out::new(out::Format::Text, false);
            out.error(&format!("unknown command \"{cmd}\" for \"ipatool\""));
            1
        }
        Persona::Perun => {
            eprintln!("[store] unknown command: {cmd}");
            usage_perun();
            2
        }
    }
}

/// Whether a command takes positional terms (search does) — used to keep
/// `search --version` from being eaten by the root version check.
fn cmd_wants_positionals(cmd: &str) -> bool {
    cmd == "search"
}

fn usage_perun() {
    eprintln!(
        "usage: perun store auth login|info|revoke\n\
         \x20      perun store search TERM [-l LIMIT] [--platform P]\n\
         \x20      perun store purchase -b BUNDLE_ID\n\
         \x20      perun store download -i APP_ID | -b BUNDLE_ID [-o PATH] [--purchase]\n\
         \x20      perun store list-purchases [-l MAX] [-p PAGE]\n\
         \x20      perun store list-versions -i APP_ID | -b BUNDLE_ID\n\
         \x20      perun store get-version-metadata -i APP_ID | -b BUNDLE_ID --external-version-id ID"
    );
}

// ── help texts (byte-parity with the cobra blocks) ────────────────────────

const GLOBAL_FLAGS_BLOCK: &str = "\
Global Flags:
      --format format                sets output format for command; can be 'text', 'json' (default text)
      --keychain-passphrase string   passphrase for unlocking keychain
      --non-interactive              run in non-interactive session
      --verbose                      enables verbose logs";

fn print_root_help(persona: Persona) {
    if persona == Persona::Perun {
        usage_perun();
        return;
    }
    print!(
        "A cli tool for interacting with Apple's ipa files\n\n\
Usage:\n  ipatool [command]\n\n\
Available Commands:\n\
\x20 auth                 Authenticate with the App Store\n\
\x20 completion           Generate the autocompletion script for the specified shell\n\
\x20 download             Download iOS, iPadOS, tvOS, visionOS, and macOS app packages from the App Store\n\
\x20 get-version-metadata Retrieves the metadata for a specific version of an app\n\
\x20 help                 Help about any command\n\
\x20 list-purchases       List apps owned by the authenticated App Store account\n\
\x20 list-versions        List the available versions of an iOS app\n\
\x20 purchase             Obtain a license for the app from the App Store\n\
\x20 search               Search for iOS, iPadOS, tvOS, visionOS, and macOS apps available on the App Store\n\n\
Flags:\n\
\x20     --format format                sets output format for command; can be 'text', 'json' (default text)\n\
\x20 -h, --help                         help for ipatool\n\
\x20     --keychain-passphrase string   passphrase for unlocking keychain\n\
\x20     --non-interactive              run in non-interactive session\n\
\x20     --verbose                      enables verbose logs\n\
\x20 -v, --version                      version for ipatool\n\n\
Use \"ipatool [command] --help\" for more information about a command.\n"
    );
}

fn print_command_help(short: &str, usage: &str, flags: &str) {
    print!("{short}\n\nUsage:\n  ipatool {usage}\n\nFlags:\n{flags}\n\n{GLOBAL_FLAGS_BLOCK}\n");
}

fn help_search() {
    print_command_help(
        "Search for iOS, iPadOS, tvOS, visionOS, and macOS apps available on the App Store",
        "search <term> [flags]",
        "  -h, --help              help for search\n  -l, --limit int         maximum amount of search results to retrieve; visionOS supports up to 12 (default 5)\n      --platform string   Platform to search: iphone (iOS), ipad (iPadOS), appletv (tvOS), visionos, or macos",
    );
}

fn help_purchase() {
    print_command_help(
        "Obtain a license for the app from the App Store",
        "purchase [flags]",
        "  -b, --bundle-identifier string   Bundle identifier of the target app (required)\n  -h, --help                       help for purchase\n      --platform string            Platform to purchase for: iphone (iOS), ipad (iPadOS), appletv (tvOS), visionos, or macos",
    );
}

fn help_download() {
    print_command_help(
        "Download iOS, iPadOS, tvOS, visionOS, and macOS app packages from the App Store",
        "download [flags]",
        "  -i, --app-id int                   ID of the target app (required)\n  -b, --bundle-identifier string     The bundle identifier of the target app (overrides the app ID)\n      --external-version-id string   External version identifier of the target app (defaults to latest version when not specified)\n  -h, --help                         help for download\n  -o, --output string                The destination path of the downloaded app package\n      --platform string              Platform to download for: iphone (iOS), ipad (iPadOS), appletv (tvOS), visionos, or macos\n      --purchase                     Obtain a license for the app if needed",
    );
}

fn help_list_purchases() {
    print_command_help(
        "List apps owned by the authenticated App Store account",
        "list-purchases [flags]",
        "  -h, --help              help for list-purchases\n  -l, --max-results int   maximum number of apps to return per page (default 10)\n  -p, --page int          page of owned apps to return (default 1)",
    );
}

fn help_list_versions() {
    print_command_help(
        "List the available versions of an iOS app",
        "list-versions [flags]",
        "  -i, --app-id int                 ID of the target iOS app (required)\n  -b, --bundle-identifier string   The bundle identifier of the target iOS app (overrides the app ID)\n  -h, --help                       help for list-versions",
    );
}

fn help_get_version_metadata() {
    print_command_help(
        "Retrieves the metadata for a specific version of an app",
        "get-version-metadata [flags]",
        "  -i, --app-id int                   ID of the target iOS app (required)\n  -b, --bundle-identifier string     The bundle identifier of the target iOS app (overrides the app ID)\n      --external-version-id string   External version identifier of the target iOS app (required)\n  -h, --help                         help for get-version-metadata",
    );
}

fn help_auth() {
    print!(
        "Authenticate with the App Store\n\n\
Usage:\n  ipatool auth [command]\n\n\
Available Commands:\n\
\x20 info        Show current account info\n\
\x20 login       Login to the App Store\n\
\x20 revoke      Revoke your App Store credentials\n\n\
Flags:\n  -h, --help   help for auth\n\n{GLOBAL_FLAGS_BLOCK}\n\n\
Use \"ipatool auth [command] --help\" for more information about a command.\n"
    );
}

fn help_auth_login() {
    print_command_help(
        "Login to the App Store",
        "auth login [flags]",
        "      --auth-code string   2FA code for the Apple ID\n  -e, --email string       email address for the Apple ID (required)\n  -h, --help               help for login\n  -p, --password string    password for the Apple ID (required)",
    );
}

fn help_auth_info() {
    print_command_help(
        "Show current account info",
        "auth info [flags]",
        "  -h, --help   help for info",
    );
}

fn help_auth_revoke() {
    print_command_help(
        "Revoke your App Store credentials",
        "auth revoke [flags]",
        "  -h, --help   help for revoke",
    );
}

fn completion_stub(args: &[String]) {
    // The four shells cobra generates; we do not emit real completion
    // scripts (the grammar is small enough to keep in muscle memory), but
    // the command and its help exist so scripts probing for cobra
    // subcommands see the same surface.
    let shells = ["bash", "fish", "powershell", "zsh"];
    let Some(shell) = args.first() else {
        println!(
            "Generate the autocompletion script for ipatool for the specified shell.\nSee each sub-command's help for details on how to use the generated script.\n\n\
Usage:\n  ipatool completion [command]\n\n\
Available Commands:\n\
\x20 bash        Generate the autocompletion script for bash\n\
\x20 fish        Generate the autocompletion script for fish\n\
\x20 powershell  Generate the autocompletion script for powershell\n\
\x20 zsh         Generate the autocompletion script for zsh\n\n\
Flags:\n  -h, --help   help for completion\n\n{GLOBAL_FLAGS_BLOCK}\n"
        );
        return;
    };
    if shells.contains(&shell.as_str()) {
        println!(
            "# ipatool completion for {shell}: hand-written commands are stable; see `ipatool --help`"
        );
    } else {
        eprintln!("Error: unknown command \"{shell}\" for \"ipatool completion\"");
        std::process::exit(1);
    }
}

// ── shared command plumbing ───────────────────────────────────────────────

/// Everything a command handler needs: parsed invocation + output.
/// One app row for the output layer: (id, bundle, name, version, price, purchase date).
pub type AppRow<'a> = (i64, &'a str, &'a str, &'a str, f64, Option<&'a str>);

struct Ctx {
    inv: Invocation,
    out: out::Out,
    persona: Persona,
}

impl Ctx {
    /// Cobra-style usage failure: the message through the error logger,
    /// rc=1 (majd does not distinguish usage from runtime errors).
    fn usage_fail(&self, msg: &str) -> i32 {
        self.out.error(msg);
        1
    }
    fn fail(&self, e: StoreError) -> i32 {
        self.out.error(&e.to_string());
        1
    }
    fn fail_msg(&self, msg: &str) -> i32 {
        self.out.error(msg);
        1
    }
}

/// Build the ctx; on usage_error/help/version short-circuits, handle
/// them right here and return None.
fn begin(
    persona: Persona,
    args: &[String],
    locals: &[(&str, bool)],
    help: fn(),
) -> Option<Result<Ctx, i32>> {
    let inv = parse(args, locals);
    if let Some(err) = &inv.usage_error {
        // Cobra prints `Error: <msg>` + usage to stderr; majd then logs
        // the same message through the (text) logger with success=false.
        // The observable line in the captures is the logger one.
        let out = out::Out::new(inv.format, inv.verbose);
        out.error(err);
        return Some(Err(1));
    }
    if inv.help_requested {
        help();
        return Some(Err(0));
    }
    if inv.version_requested {
        println!("{} version {}", persona.name(), env!("CARGO_PKG_VERSION"));
        return Some(Err(0));
    }
    let out = out::Out::new(inv.format, inv.verbose);
    if inv.verbose {
        // Edition 2024: set_var became unsafe (mutable statics); the CLI is
        // single-threaded before any I/O threads spawn, so this is sound.
        unsafe { std::env::set_var("PERUN_STORE_HTTP_DEBUG", "1") };
    }
    Some(Ok(Ctx { out, inv, persona }))
}

/// Load the saved account (majd: keychain → we: the encrypted store; the
/// `--keychain-passphrase` maps onto our KDF passphrase).
fn require_account(ctx: &Ctx) -> Result<Account, i32> {
    match account::load(&ctx.inv.keychain_passphrase) {
        Ok(acc) => Ok(acc),
        Err(_) => {
            ctx.fail_msg(
                "failed to get account: failed to get item: The specified item could not be found in the keyring",
            );
            Err(1)
        }
    }
}

/// majd's silent relogin (token expiry): the stored password replays the
/// login without a 2FA round (session cookies hold the second factor).
/// `None` when the account carries no password (the perun persona) — the
/// caller surfaces the original error instead.
fn relogin_if_possible(ctx: &Ctx, acc: &Account) -> Option<Account> {
    if acc.password.is_empty() {
        return None;
    }
    let mac = crate::store::primary_mac();
    let guid = appstore::guid_from_mac(&mac);
    let config = bag::Bag::fetch(&guid).ok()?.sap;
    let mut sign = signer::Signer::new(&config, mac).ok()?;
    let fresh = appstore::login(&acc.email, &acc.password, "", mac, &mut sign, &config).ok()?;
    let _ = account::save(&fresh, &ctx.inv.keychain_passphrase);
    Some(fresh)
}

/// Resolve an app by -i or -b (majd Lookup semantics: bundle wins).
fn resolve_app(ctx: &Ctx, acc: &Account) -> Result<appstore::App, i32> {
    let bundle = ctx.inv.get(&["-b", "--bundle-identifier"]);
    let app_id = ctx.inv.get(&["-i", "--app-id"]);
    let platform = ctx.inv.get(&["--platform"]).unwrap_or("");
    let platform = match parse_platform(platform) {
        Ok(p) => p,
        Err(e) => return Err(ctx.usage_fail(&e)),
    };
    if let Some(b) = bundle {
        let b = b.to_string();
        return appstore::lookup(acc, &b, &platform).map_err(|e| ctx.fail(e));
    }
    if let Some(id) = app_id {
        let id: i64 = match id.parse() {
            Ok(v) => v,
            Err(_) => return Err(ctx.usage_fail(&format!("invalid argument \"{id}\" for \"-i, --app-id\" flag: strconv.ParseInt: parsing \"{id}\": invalid syntax"))),
        };
        return appstore::lookup_by_id(acc, id, &platform).map_err(|e| ctx.fail(e));
    }
    Err(ctx.usage_fail("either the app ID or the bundle identifier must be specified"))
}

/// Fresh guid (majd recomputes per operation).
fn fresh_guid() -> String {
    let mac = crate::store::primary_mac();
    appstore::guid_from_mac(&mac)
}

/// Progress bar for interactive downloads: single line, `\r` redraw.
fn print_progress(downloaded: u64, total: u64) {
    let is_tty = unsafe { libc::isatty(1) == 1 };
    if !is_tty {
        return;
    }
    let done = if total > 0 {
        downloaded as f64 / total as f64
    } else {
        0.0
    };
    let width: usize = 40;
    let filled = (done * width as f64) as usize;
    let bar: String = "█".repeat(filled) + &"·".repeat(width.saturating_sub(filled));
    let pct = (done * 100.0) as usize;
    eprint!(
        "\r\x1b[K  downloading {pct:3}% |{bar}| ({})",
        human_size(downloaded)
    );
    if total > 0 {
        eprint!(" / {}", human_size(total));
    }
    if total > 0 && downloaded >= total {
        eprintln!();
    }
}

fn human_size(b: u64) -> String {
    if b >= 1024 * 1024 {
        format!("{:.0} MB", b as f64 / (1024.0 * 1024.0))
    } else if b >= 1024 {
        format!("{:.0} kB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

fn read_line(prompt: &str) -> std::io::Result<String> {
    let mut out = std::io::stderr();
    write!(out, "{prompt}")?;
    out.flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

// ── auth ──────────────────────────────────────────────────────────────────

fn cmd_auth(persona: Persona, args: &[String]) -> i32 {
    // Globals may sit before the subcommand (`auth --format json info`).
    let mut pre: Vec<String> = Vec::new();
    let mut idx = 0;
    while idx < args.len() {
        let a = args[idx].as_str();
        let skip_next = match a {
            "--format" | "--keychain-passphrase" => true,
            "--verbose" | "--non-interactive" => false,
            _ => break,
        };
        pre.push(a.to_string());
        idx += 1;
        if skip_next && idx < args.len() {
            pre.push(args[idx].clone());
            idx += 1;
        }
    }
    let sub: &[String] = &args[idx..];
    let mut rest: Vec<String> = sub[1..].to_vec();
    rest.extend(pre);
    let args_rest: &[String] = &rest;
    if sub.is_empty() {
        if persona == Persona::Ipatool {
            help_auth();
            return 0;
        }
        eprintln!("usage: perun store auth login|info|revoke");
        return 2;
    }
    match sub[0].as_str() {
        "login" => cmd_auth_login(persona, args_rest),
        "info" => cmd_auth_info(persona, args_rest),
        "revoke" => cmd_auth_revoke(persona, args_rest),
        other => {
            if persona == Persona::Ipatool {
                // Cobra: unknown subcommand of a parent prints the
                // parent's help and exits 0.
                help_auth();
                0
            } else {
                eprintln!("[store] unknown auth subcommand: {other}");
                2
            }
        }
    }
}

fn cmd_auth_login(persona: Persona, args: &[String]) -> i32 {
    let Some(res) = begin(
        persona,
        args,
        &[
            ("-e", true),
            ("--email", true),
            ("-p", true),
            ("--password", true),
            ("-a", true),
            ("--auth-code", true),
        ],
        help_auth_login,
    ) else {
        return 1;
    };
    let ctx = match res {
        Ok(c) => c,
        Err(code) => return code,
    };
    let email = ctx.inv.get(&["-e", "--email"]).unwrap_or("").to_string();
    let password = ctx.inv.get(&["-p", "--password"]).unwrap_or("").to_string();
    let mut auth_code = ctx
        .inv
        .get(&["-a", "--auth-code"])
        .unwrap_or("")
        .to_string();

    if email.is_empty() {
        return ctx.usage_fail("required flag(s) \"email\" not set");
    }
    if password.is_empty() && !ctx.inv.interactive {
        return ctx.usage_fail(
            "password is required when not running in interactive mode; use the \"--password\" flag",
        );
    }
    let password = if password.is_empty() {
        match read_line("enter password: ") {
            Ok(v) => v,
            Err(_) => return 1,
        }
    } else {
        password
    };

    ctx.out.log(&[(
        "msg",
        out::Field::Str("preparing authentication; the first login may take a few minutes".into()),
    )]);

    // Fresh session cookies (stale hsaccnt/mz_at0 short-circuit the 2FA
    // round with a bare 5005).
    if let Err(e) = account::reset_session() {
        eprintln!("[store] session reset: {e}");
    }

    let mac = crate::store::primary_mac();
    let guid = appstore::guid_from_mac(&mac);
    ctx.out.verbose_line(&[
        ("email", out::Field::Str(email.clone())),
        ("authCodeProvided", out::Field::Bool(!auth_code.is_empty())),
        ("msg", out::Field::Str("logging in".into())),
    ]);
    let config = match bag::Bag::fetch(&guid) {
        Ok(b) => b.sap,
        Err(e) => return ctx.fail_msg(&format!("bag: {e}")),
    };
    let mut sign = match signer::Signer::new(&config, mac) {
        Ok(s) => s,
        Err(e) => return ctx.fail_msg(&format!("SAP: {e}")),
    };

    loop {
        match appstore::login(&email, &password, &auth_code, mac, &mut sign, &config) {
            Ok(mut acc) => {
                // majd always persists the password (its retry loops relogin
                // silently on token expiry); the perun persona keeps the
                // no-password-at-rest stance.
                if ctx.persona == Persona::Ipatool {
                    acc.password = password.clone();
                }
                if let Err(e) = account::save(&acc, &ctx.inv.keychain_passphrase) {
                    return ctx.fail_msg(&format!(
                        "failed to save account in keychain: failed to set item: {e}"
                    ));
                }
                ctx.out.log(&[
                    ("name", out::Field::Str(acc.name.clone())),
                    ("email", out::Field::Str(acc.email.clone())),
                    ("success", out::Field::Bool(true)),
                ]);
                return 0;
            }
            Err(StoreError::AuthCodeRequired) => {
                if !ctx.inv.interactive {
                    // majd's quirk, kept 1:1: an INF hint and rc=0.
                    ctx.out.log(&[(
                        "msg",
                        out::Field::Str(
                            "2FA code is required; run the command again and supply a code using the `--auth-code` flag"
                                .into(),
                        ),
                    )]);
                    return 0;
                }
                let code = match read_line("enter 2FA code: ") {
                    Ok(v) => v,
                    Err(_) => return 1,
                };
                if code.trim().is_empty() {
                    return ctx.fail_msg("auth code is required");
                }
                auth_code = code.trim().to_string();
            }
            Err(StoreError::InvalidAuthCode) => {
                if !ctx.inv.interactive {
                    return ctx.fail_msg("2FA code rejected or expired");
                }
                eprintln!("2FA code rejected or expired; requesting a fresh one");
                let code = match read_line("fresh 2FA code (empty to abort): ") {
                    Ok(v) => v,
                    Err(_) => return 1,
                };
                if code.trim().is_empty() {
                    return 1;
                }
                auth_code = code.trim().to_string();
            }
            Err(e) => return ctx.fail(e),
        }
    }
}

fn cmd_auth_info(persona: Persona, args: &[String]) -> i32 {
    let Some(res) = begin(persona, args, &[], help_auth_info) else {
        return 1;
    };
    let ctx = match res {
        Ok(c) => c,
        Err(code) => return code,
    };
    match account::load(&ctx.inv.keychain_passphrase) {
        Ok(acc) => {
            ctx.out.log(&[
                ("name", out::Field::Str(acc.name.clone())),
                ("email", out::Field::Str(acc.email.clone())),
                ("success", out::Field::Bool(true)),
            ]);
            0
        }
        Err(_) => {
            ctx.fail_msg(
                "failed to get account: failed to get item: The specified item could not be found in the keyring",
            );
            1
        }
    }
}

fn cmd_auth_revoke(persona: Persona, args: &[String]) -> i32 {
    let Some(res) = begin(persona, args, &[], help_auth_revoke) else {
        return 1;
    };
    let ctx = match res {
        Ok(c) => c,
        Err(code) => return code,
    };
    match account::revoke() {
        Ok(()) => {
            ctx.out.log(&[("success", out::Field::Bool(true))]);
            0
        }
        Err(e) => ctx.fail_msg(&e),
    }
}

// ── search ────────────────────────────────────────────────────────────────

fn cmd_search(persona: Persona, args: &[String]) -> i32 {
    let Some(res) = begin(
        persona,
        args,
        &[("-l", true), ("--limit", true), ("--platform", true)],
        help_search,
    ) else {
        return 1;
    };
    let ctx = match res {
        Ok(c) => c,
        Err(code) => return code,
    };
    if ctx.inv.positional.len() != 1 {
        return ctx.usage_fail(&format!(
            "accepts 1 arg(s), received {}",
            ctx.inv.positional.len()
        ));
    }
    let term = ctx.inv.positional[0].clone();
    let limit: i64 = ctx
        .inv
        .get(&["-l", "--limit"])
        .unwrap_or("5")
        .parse()
        .unwrap_or(5);
    let platform = match parse_platform(ctx.inv.get(&["--platform"]).unwrap_or("")) {
        Ok(p) => p,
        Err(e) => return ctx.usage_fail(&e),
    };

    let acc = match require_account(&ctx) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let apps = if platform == "visionos" {
        match appstore::search_visionos(&acc, &term, limit) {
            Ok(a) => a,
            Err(e) => return ctx.fail(e),
        }
    } else {
        match appstore::search(&acc, &term, limit as u32, &platform) {
            Ok(a) => a,
            Err(e) => return ctx.fail(e),
        }
    };
    let items: Vec<AppRow> = apps
        .iter()
        .map(|a| {
            (
                a.id,
                a.bundle_id.as_str(),
                a.name.as_str(),
                a.version.as_str(),
                a.price,
                None,
            )
        })
        .collect();
    let is_console = ctx.out.format == out::Format::Text;
    let apps_field = out::Field::Arr(if is_console {
        out::apps_with_date_console(&items)
    } else {
        out::apps_with_date_json(&items)
    });
    ctx.out.log(&[
        ("count", out::Field::Int(apps.len() as i64)),
        ("apps", apps_field),
    ]);
    0
}

// ── purchase ───────────────────────────────────────────────────────────────

fn cmd_purchase(persona: Persona, args: &[String]) -> i32 {
    let Some(res) = begin(
        persona,
        args,
        &[
            ("-b", true),
            ("--bundle-identifier", true),
            ("--platform", true),
        ],
        help_purchase,
    ) else {
        return 1;
    };
    let ctx = match res {
        Ok(c) => c,
        Err(code) => return code,
    };
    let bundle = match ctx.inv.get(&["-b", "--bundle-identifier"]) {
        Some(b) => b.to_string(),
        None => return ctx.usage_fail("required flag(s) \"bundle-identifier\" not set"),
    };
    let platform = match parse_platform(ctx.inv.get(&["--platform"]).unwrap_or("")) {
        Ok(p) => p,
        Err(e) => return ctx.usage_fail(&e),
    };
    let acc = match require_account(&ctx) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let app = match appstore::lookup(&acc, &bundle, &platform) {
        Ok(a) => a,
        Err(e) => return ctx.fail(e),
    };
    if app.price > 0.0 {
        return ctx.fail_msg("purchasing paid apps is not supported");
    }
    let guid = fresh_guid();
    let mut acc = acc;
    let mut last_err: Option<StoreError> = None;
    loop {
        match appstore::purchase(&acc, &app, &guid, true) {
            Ok(()) => {
                ctx.out.log(&[
                    ("alreadyOwned", out::Field::Bool(false)),
                    ("success", out::Field::Bool(true)),
                ]);
                return 0;
            }
            Err(StoreError::LicenseAlreadyExists) => {
                ctx.out.log(&[
                    ("alreadyOwned", out::Field::Bool(true)),
                    ("success", out::Field::Bool(true)),
                ]);
                return 0;
            }
            Err(e) if matches!(e, StoreError::PasswordTokenExpired) && last_err.is_none() => {
                // majd: one silent relogin round (retry.Do attempts(2)).
                match relogin_if_possible(&ctx, &acc) {
                    Some(fresh) => {
                        acc = fresh;
                        last_err = Some(e);
                        continue;
                    }
                    None => return ctx.fail(e),
                }
            }
            Err(e) => return ctx.fail(e),
        }
    }
}

// ── download ──────────────────────────────────────────────────────────────

fn cmd_download(persona: Persona, args: &[String]) -> i32 {
    let Some(res) = begin(
        persona,
        args,
        &[
            ("-i", true),
            ("--app-id", true),
            ("-b", true),
            ("--bundle-identifier", true),
            ("-o", true),
            ("--output", true),
            ("--external-version-id", true),
            ("--platform", true),
            ("--purchase", false),
        ],
        help_download,
    ) else {
        return 1;
    };
    let ctx = match res {
        Ok(c) => c,
        Err(code) => return code,
    };
    let acc = match require_account(&ctx) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let app = match resolve_app(&ctx, &acc) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let output = ctx.inv.get(&["-o", "--output"]).unwrap_or("").to_string();
    let external_version_id = ctx
        .inv
        .get(&["--external-version-id"])
        .unwrap_or("")
        .to_string();
    let platform = match parse_platform(ctx.inv.get(&["--platform"]).unwrap_or("")) {
        Ok(p) => p,
        Err(e) => return ctx.usage_fail(&e),
    };
    let acquire_license = ctx.inv.has("--purchase");

    if platform == "macos" {
        return ctx.fail_msg(
            "macOS packages (.pkg) are not supported yet; native StoreAgent decryption is a separate phase",
        );
    }

    // tvOS/visionOS need an external version id: resolve the latest via
    // the MDM platform lookup when not supplied (majd parity).
    let external_version_id =
        if external_version_id.is_empty() && (platform == "appletv" || platform == "visionos") {
            match resolve_latest_external_version_id(&acc, app.id, &platform) {
                Ok(id) => id,
                Err(e) => return ctx.fail_msg(&e),
            }
        } else {
            external_version_id
        };

    let guid = fresh_guid();
    let mut purchased = false;
    let mut progress = if ctx.inv.interactive {
        print_progress
    } else {
        |_, _| {}
    };

    // The majd retry loop: license-needed + --purchase → buy, retry once.
    let mut retried_after_purchase = false;
    loop {
        match appstore::download(
            &acc,
            &app,
            &output,
            &external_version_id,
            &guid,
            &mut progress,
        ) {
            Ok(out) => {
                ctx.out.log(&[
                    ("output", out::Field::Str(out.destination.clone())),
                    ("purchased", out::Field::Bool(purchased)),
                    ("success", out::Field::Bool(true)),
                ]);
                return 0;
            }
            Err(StoreError::LicenseRequired) if acquire_license && !retried_after_purchase => {
                match appstore::purchase(&acc, &app, &guid, true) {
                    Ok(()) | Err(StoreError::LicenseAlreadyExists) => {
                        purchased = true;
                        retried_after_purchase = true;
                        ctx.out.verbose_line(&[
                            ("success", out::Field::Bool(true)),
                            ("msg", out::Field::Str("purchase".into())),
                        ]);
                    }
                    Err(e) => return ctx.fail(e),
                }
            }
            Err(e) => return ctx.fail(e),
        }
    }
}

/// The MDM platform version lookup (uclient-api.itunes.apple.com) for
/// tvOS; visionOS goes through the apps.apple.com product page.
fn resolve_latest_external_version_id(
    acc: &Account,
    app_id: i64,
    platform: &str,
) -> Result<String, String> {
    let country =
        appstore::country_code_from_storefront(&acc.store_front).map_err(|e| e.to_string())?;
    if platform == "visionos" {
        return appstore::lookup_latest_visionos_external_version_id(app_id, country)
            .map_err(|e| e.to_string());
    }
    let metadata = platform_metadata(platform)
        .ok_or_else(|| format!("no version lookup for platform {platform}"))?;
    appstore::lookup_latest_external_version_id(app_id, country, metadata)
        .map_err(|e| e.to_string())
}

// ── list-purchases ────────────────────────────────────────────────────────

fn cmd_list_purchases(persona: Persona, args: &[String]) -> i32 {
    let Some(res) = begin(
        persona,
        args,
        &[
            ("-l", true),
            ("--max-results", true),
            ("-p", true),
            ("--page", true),
        ],
        help_list_purchases,
    ) else {
        return 1;
    };
    let ctx = match res {
        Ok(c) => c,
        Err(code) => return code,
    };
    let limit: i64 = ctx
        .inv
        .get(&["-l", "--max-results"])
        .unwrap_or("10")
        .parse()
        .unwrap_or(10);
    let page: i64 = ctx
        .inv
        .get(&["-p", "--page"])
        .unwrap_or("1")
        .parse()
        .unwrap_or(1);
    if page < 1 {
        return ctx.usage_fail("page must be greater than 0");
    }
    if limit < 1 {
        return ctx.usage_fail("max results must be greater than 0");
    }
    if limit > 100 {
        return ctx.usage_fail("max results must not exceed 100");
    }
    let acc = match require_account(&ctx) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let guid = fresh_guid();
    let config = match bag::Bag::fetch(&guid) {
        Ok(b) => b.sap,
        Err(e) => return ctx.fail_msg(&format!("bag: {e}")),
    };
    let mut sign = match signer::Signer::new(&config, crate::store::primary_mac()) {
        Ok(s) => s,
        Err(e) => return ctx.fail_msg(&format!("SAP: {e}")),
    };
    match appstore::owned_apps(&acc, &guid, &mut sign, page as u32, limit as u32) {
        Ok(out_res) => {
            let items: Vec<AppRow> = out_res
                .apps
                .iter()
                .map(|a| {
                    (
                        a.id,
                        a.bundle_id.as_str(),
                        a.name.as_str(),
                        a.version.as_str(),
                        a.price,
                        a.purchase_date.as_deref(),
                    )
                })
                .collect();
            let is_console = ctx.out.format == out::Format::Text;
            let apps_field = out::Field::Arr(if is_console {
                out::apps_with_date_console(&items)
            } else {
                out::apps_with_date_json(&items)
            });
            ctx.out.log(&[
                ("count", out::Field::Int(out_res.apps.len() as i64)),
                ("totalCount", out::Field::Int(out_res.total as i64)),
                ("page", out::Field::Int(page)),
                ("apps", apps_field),
            ]);
            0
        }
        Err(e) => ctx.fail(e),
    }
}

// ── list-versions / get-version-metadata ─────────────────────────────────

fn cmd_list_versions(persona: Persona, args: &[String]) -> i32 {
    let Some(res) = begin(
        persona,
        args,
        &[
            ("-i", true),
            ("--app-id", true),
            ("-b", true),
            ("--bundle-identifier", true),
            ("--platform", true),
        ],
        help_list_versions,
    ) else {
        return 1;
    };
    let ctx = match res {
        Ok(c) => c,
        Err(code) => return code,
    };
    let acc = match require_account(&ctx) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let app = match resolve_app(&ctx, &acc) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let guid = fresh_guid();
    match appstore::list_versions(&acc, app.id, &guid) {
        Ok(out_res) => {
            ctx.out.log(&[
                (
                    "externalVersionIdentifiers",
                    out::Field::Arr(
                        out_res
                            .external_version_identifiers
                            .iter()
                            .map(|s| out::json_str(s))
                            .collect(),
                    ),
                ),
                ("bundleID", out::Field::Str(app.bundle_id.clone())),
                ("success", out::Field::Bool(true)),
            ]);
            0
        }
        Err(e) => ctx.fail(e),
    }
}

fn cmd_get_version_metadata(persona: Persona, args: &[String]) -> i32 {
    let Some(res) = begin(
        persona,
        args,
        &[
            ("-i", true),
            ("--app-id", true),
            ("-b", true),
            ("--bundle-identifier", true),
            ("--external-version-id", true),
            ("--platform", true),
        ],
        help_get_version_metadata,
    ) else {
        return 1;
    };
    let ctx = match res {
        Ok(c) => c,
        Err(code) => return code,
    };
    let Some(vid) = ctx.inv.get(&["--external-version-id"]) else {
        return ctx.usage_fail("required flag(s) \"external-version-id\" not set");
    };
    let vid = vid.to_string();
    let acc = match require_account(&ctx) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let app = match resolve_app(&ctx, &acc) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let guid = fresh_guid();
    match appstore::get_version_metadata(&acc, app.id, &guid, &vid) {
        Ok(meta) => {
            ctx.out.log(&[
                ("externalVersionID", out::Field::Str(vid.clone())),
                (
                    "displayVersion",
                    out::Field::Str(meta.display_version.clone()),
                ),
                ("releaseDate", out::Field::Str(meta.release_date.clone())),
                ("success", out::Field::Bool(true)),
            ]);
            0
        }
        Err(e) => ctx.fail(e),
    }
}
