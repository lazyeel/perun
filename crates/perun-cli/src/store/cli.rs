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
fn parse(persona: Persona, argv: &[String], locals: &[(&str, bool)]) -> Invocation {
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
                                let bare = name.trim_start_matches('-');
                                inv.usage_error = Some(if persona == Persona::Ipatool {
                                    format!("flag needs an argument: '{bare}' in -{bare}")
                                } else {
                                    format!("flag needs an argument: {name}")
                                });
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
                    inv.usage_error =
                        Some(format!("unknown shorthand flag: '{short}' in -{short}"));
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

/// Parse `--limit` for search, per persona.
///
/// The ipatool persona is pflag: it accepts **any** integer, including 0 and
/// negatives, and only a non-numeric value is a usage error — with pflag's own
/// wording. The perun persona keeps the 1..=200 contract it documents.
pub fn parse_search_limit_for(persona: Persona, raw: &str) -> Result<i64, String> {
    match raw.parse::<i64>() {
        Ok(v) if persona == Persona::Ipatool => Ok(v),
        Ok(v) if (1..=200).contains(&v) => Ok(v),
        Ok(_) => Err("invalid --limit: expected an integer 1..=200".into()),
        Err(_) if persona == Persona::Ipatool => Err(format!(
            "invalid argument {raw:?} for \"-l, --limit\" flag: strconv.ParseInt: parsing {raw:?}: invalid syntax"
        )),
        Err(_) => Err(format!(
            "invalid --limit {raw:?}: expected an integer 1..=200"
        )),
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
    // Legacy-name nudge: only for a real human on an interactive terminal.
    // Any automation signal — a pipe on stderr, --format json, or
    // --non-interactive — keeps the output byte-identical to the reference.
    if persona == Persona::Ipatool && interactive_orchestration(args) {
        eprintln!(
            "[perun] Note: Running via legacy 'ipatool' alias. Consider switching to 'perun'."
        );
    }
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
                completion_emit(rest);
                0
            } else {
                unknown_command(persona, cmd)
            }
        }
        _ => unknown_command(persona, cmd),
    }
}

/// "Live human" heuristic for the ipatool alias notice: stderr must be a
/// TTY (pipes/CI stay clean), and the argv must not carry --format json or
/// --non-interactive (scripted invocations get byte-parity).
fn interactive_orchestration(args: &[String]) -> bool {
    let is_tty = unsafe { libc::isatty(libc::STDERR_FILENO) == 1 };
    if !is_tty {
        return false;
    }
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--non-interactive" => return false,
            "--format" => {
                // --format json silences the hint (bots); --format text does not.
                if args.get(i + 1).map(|v| v == "json").unwrap_or(false) {
                    return false;
                }
                i += 2;
                continue;
            }
            "--format=json" => return false,
            _ => {}
        }
        i += 1;
    }
    true
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
         \x20                        [--developer | --id | --description]\n\
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
    // `begin` hands over a bare callback, and every other `help_*` in this file
    // is persona-invariant, so only this one branches. Re-reading the persona is
    // safe and costs nothing: `Persona::detect` is a basename compare on argv[0]
    // in the same process that `run` already used to get here.
    if Persona::detect() == Persona::Perun {
        print!(
            "Search for iOS, iPadOS, tvOS, visionOS, and macOS apps available on the App Store\n\n\
Usage:\n  perun search <term> [flags]\n\n\
Flags:\n  -h, --help              help for search\n  \
-l, --limit int         maximum amount of search results to retrieve; visionOS supports up to 12 (default 5)\n      \
--platform string   Platform to search: iphone (iOS), ipad (iPadOS), appletv (tvOS), visionos, or macos\n  \
-t, --term string       the search term, instead of the positional argument\n\n\
Client-side scopes — perun only, the ipatool persona has none, and the three are\n\
mutually exclusive:\n      \
--developer         keep only apps whose artistName/sellerName matches\n  -dev\n      \
--description     keep only apps whose description text matches\n  -desc\n      \
--id               the term is a numeric artist id: list that developer's whole\n                      catalog through the Lookup API\n\n\
A scope probes the backend at its maximum and applies the limit after filtering,\n\
so a filter never shrinks the page you asked for. With no scope, search stays\n\
the plain Apple search across all fields.\n\n\
{GLOBAL_FLAGS_BLOCK}\n"
        );
        return;
    }
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
        "  -i, --app-id int                 ID of the target app\n  -b, --bundle-identifier string   The bundle identifier of the target app (overrides the app ID)\n  -h, --help                       help for purchase\n      --platform string            Platform to purchase for: iphone (iOS), ipad (iPadOS), appletv (tvOS), visionos, or macos",
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
    // perun superset: the flag exists only in the perun persona; ipatool
    // help must stay byte-identical to the reference.
    if Persona::detect() == Persona::Perun {
        println!(
            "      --remember-password  store the password in the encrypted account (enables unattended relogin)"
        );
    }
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

/// `ipatool completion [shell]`: cobra's surface, reproduced.
///
/// The reference prints the generated script for the named shell. Bash is
/// carried verbatim; the other three shells are listed by the help text but
/// still have no generator here, and that gap is recorded in README.
fn completion_emit(args: &[String]) {
    let help = || {
        println!(
            "Generate the autocompletion script for ipatool for the specified shell.\nSee each sub-command's help for details on how to use the generated script.\n\n\
Usage:\n  ipatool completion [command]\n\n\
Available Commands:\n\
\x20 bash        Generate the autocompletion script for bash\n\
\x20 fish        Generate the autocompletion script for fish\n\
\x20 powershell  Generate the autocompletion script for powershell\n\
\x20 zsh         Generate the autocompletion script for zsh\n\n\
Flags:\n  -h, --help   help for completion\n\n\
{GLOBAL_FLAGS_BLOCK}\n\n\
Use \"ipatool completion [command] --help\" for more information about a command.\n"
        );
    };
    // cobra answers `--help` on the parent with the parent help, rc 0.
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        help();
        return;
    }
    let script = match args[0].as_str() {
        "bash" => Some(crate::store::completion_bash::BASH),
        "zsh" => Some(crate::store::completion_zsh::ZSH),
        "fish" => Some(crate::store::completion_fish::FISH),
        "powershell" => Some(crate::store::completion_powershell::POWERSHELL),
        _ => None,
    };
    match script {
        Some(text) => print!("{text}"),
        // Cobra answers an unrecognised shell with the parent's help and rc 0,
        // it does not treat the name as an unknown command.
        None => help(),
    }
}

// ── shared command plumbing ───────────────────────────────────────────────

/// Everything a command handler needs: parsed invocation + output.
/// One app row for the output layer: (id, bundle, name, version, price, purchase date).
pub type AppRow<'a> = (
    i64,
    &'a str,
    &'a str,
    &'a str,
    f64,
    Option<&'a str>,
    Vec<&'a str>,
);

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
    let inv = parse(persona, args, locals);
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
    let mut fresh = appstore::login(&acc.email, &acc.password, "", mac, &mut sign, &config).ok()?;
    // login() returns a bare account (no password field); carry the stored
    // one over so the NEXT silent relogin is still possible — otherwise the
    // first relogin silently erases the remembered password.
    fresh.password = acc.password.clone();
    let _ = account::save(&fresh, &ctx.inv.keychain_passphrase);
    Some(fresh)
}

/// Resolve an app by -i or -b (majd Lookup semantics: bundle wins).
fn resolve_app(ctx: &Ctx, acc: &Account) -> Result<appstore::App, i32> {
    let bundle = ctx.inv.get(&["-b", "--bundle-identifier"]);
    let app_id = ctx.inv.get(&["-i", "--app-id"]);
    // perun superset: a positional term resolves like the search UX —
    // id / bundle id / free-text (first hit). Strict ipatool ignores it.
    let positional = if ctx.persona == Persona::Perun {
        ctx.inv.positional.first().map(|s| s.as_str())
    } else {
        None
    };
    let platform = ctx.inv.get(&["--platform"]).unwrap_or("");
    let platform = match parse_platform(platform) {
        Ok(p) => p,
        Err(e) => return Err(ctx.usage_fail(&e)),
    };
    if bundle.is_none()
        && app_id.is_none()
        && let Some(term) = positional.filter(|t| !t.is_empty())
    {
        // Positional term: id / bundle / free-text, one cache entry.
        let key = cache_key(acc, &platform, "t", term);
        if let Some(app) = resolve_cache_read(&key) {
            return Ok(app);
        }
        let app = resolve_positional_term(ctx, acc, term)?;
        resolve_cache_write(&key, &app);
        return Ok(app);
    }
    if let Some(b) = bundle {
        let b = b.to_string();
        let key = cache_key(acc, &platform, "b", &b);
        if let Some(app) = resolve_cache_read(&key) {
            return Ok(app);
        }
        let app = appstore::lookup(acc, &b, &platform).map_err(|e| ctx.fail(e))?;
        resolve_cache_write(&key, &app);
        return Ok(app);
    }
    if let Some(id) = app_id {
        let id: i64 = match id.parse() {
            Ok(v) => v,
            Err(_) => return Err(ctx.usage_fail(&format!("invalid argument \"{id}\" for \"-i, --app-id\" flag: strconv.ParseInt: parsing \"{id}\": invalid syntax"))),
        };
        let key = cache_key(acc, &platform, "i", &id.to_string());
        if let Some(app) = resolve_cache_read(&key) {
            return Ok(app);
        }
        let app = appstore::lookup_by_id(acc, id, &platform).map_err(|e| ctx.fail(e))?;
        resolve_cache_write(&key, &app);
        return Ok(app);
    }
    Err(ctx.usage_fail("either the app ID or the bundle identifier must be specified"))
}

// ── resolve cache ─────────────────────────────────────────────────────────
// Cross-invocation memo for app resolution. Apple's anti-fraud tracks request
// cadence per identity; a `purchase -b X && download -b X` chain resolving
// the same app twice hits itunes.apple.com/lookup twice for one workflow.
// Entries live in the state dir, keyed by (country, platform, kind, term),
// and expire quickly: storefront data is near-static but not contractual.
// A cache miss never masks an error — only successful resolves are stored.

const RESOLVE_CACHE_TTL_SECS: u64 = 3600;

fn resolve_cache_dir() -> Option<std::path::PathBuf> {
    let dir = super::state_dir().ok()?.join("resolve-cache");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn cache_key(acc: &Account, platform: &str, kind: &str, term: &str) -> String {
    let country = appstore::country_code_from_storefront(&acc.store_front).unwrap_or("xx");
    format!("{country}|{platform}|{kind}:{term}")
}

fn resolve_cache_read(key: &str) -> Option<appstore::App> {
    let path = resolve_cache_dir()?.join(format!("{}.json", sanitize_cache_name(key)));
    let text = std::fs::read_to_string(path).ok()?;
    let entry = super::json::parse(&text).ok()?;
    let ts = entry.get("ts").and_then(|v| v.as_i64()).unwrap_or(0) as u64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    if now.saturating_sub(ts) > RESOLVE_CACHE_TTL_SECS {
        return None;
    }
    let get = |k: &str| {
        entry
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    Some(appstore::App {
        id: entry.get("id").and_then(|v| v.as_i64()).unwrap_or(0),
        bundle_id: get("bundleId"),
        name: get("name"),
        version: get("version"),
        price: entry.get("price").and_then(|v| v.as_f64()).unwrap_or(0.0),
        purchase_date: None,
        developer: get("developer"),
        description: get("description"),
        platforms: vec![],
    })
}

fn resolve_cache_write(key: &str, app: &appstore::App) {
    let Some(dir) = resolve_cache_dir() else {
        return;
    };
    let json = format!(
        "{{\"id\":{},\"bundleId\":{},\"name\":{},\"version\":{},\"price\":{},\"developer\":{},\"description\":{},\"ts\":{}}}",
        app.id,
        json_quote(&app.bundle_id),
        json_quote(&app.name),
        json_quote(&app.version),
        app.price,
        json_quote(&app.developer),
        json_quote(&app.description),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    let _ = std::fs::write(dir.join(format!("{}.json", sanitize_cache_name(key))), json);
}

/// Filesystem-safe cache name: keep the common characters, map the rest.
fn sanitize_cache_name(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '@' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// perun superset: positional term → app. A bare number is an app id, a
/// value containing a dot is a bundle id, anything else is a display-name
/// search whose first hit wins (matching majd's `search` UX).
fn resolve_positional_term(ctx: &Ctx, acc: &Account, term: &str) -> Result<appstore::App, i32> {
    let platform = ctx.inv.get(&["--platform"]).unwrap_or("");
    let platform = match parse_platform(platform) {
        Ok(p) => p,
        Err(e) => return Err(ctx.usage_fail(&e)),
    };
    if term.chars().all(|c| c.is_ascii_digit()) && !term.is_empty() {
        let id: i64 = match term.parse() {
            Ok(v) => v,
            Err(_) => return Err(ctx.usage_fail("invalid app id")),
        };
        return appstore::lookup_by_id(acc, id, &platform).map_err(|e| ctx.fail(e));
    }
    if term.contains('.') {
        return appstore::lookup(acc, term, &platform).map_err(|e| ctx.fail(e));
    }
    let apps = match appstore::search(acc, term, 1, &platform) {
        Ok(a) => a,
        Err(e) => return Err(ctx.fail(e)),
    };
    apps.into_iter()
        .next()
        .ok_or_else(|| ctx.usage_fail("no results found"))
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
    read_prompt(prompt, false)
}

/// fb1ca35: prompts stay inline (stderr), passwords read masked over a raw
/// terminal. Mirrors the reference readPrompt(prompt, masked): printable
/// runes echo '*', backspace erases, Ctrl-U clears, Ctrl-C aborts, escape
/// sequences (arrows) are swallowed whole.
fn read_password(prompt: &str) -> std::io::Result<String> {
    read_prompt(prompt, true)
}

fn read_prompt(prompt: &str, masked: bool) -> std::io::Result<String> {
    use std::io::Write;
    let mut out = std::io::stderr();
    write!(out, "{prompt}")?;
    out.flush()?;
    if !masked {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }
    // Raw terminal: stdin echoes nothing; we render the mask ourselves.
    let mut term: Option<libc::termios> = None;
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut t) == 0 {
            term = Some(t);
            let mut raw = t;
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw);
        }
    }
    let restore = |saved: &Option<libc::termios>| unsafe {
        if let Some(t) = saved {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, t);
        }
    };
    let result = masked_read_line(&mut out);
    let _ = writeln!(out);
    let _ = out.flush();
    restore(&term);
    result
}

/// Byte-at-a-time masked input; call sites pass stderr for echo.
fn masked_read_line(out: &mut std::io::Stderr) -> std::io::Result<String> {
    use std::io::{Read, Write};
    let mut input = std::io::stdin();
    let mut password: Vec<char> = Vec::new();
    let mut escape = 0u8;
    let mut buf = [0u8; 1];
    loop {
        if input.read(&mut buf)? == 0 {
            return Ok(password.into_iter().collect());
        }
        let key = buf[0];
        // Swallow escape sequences (arrows etc.) like the reference.
        if escape != 0 {
            if escape == 1 && (key == b'[' || key == b'O') {
                escape = 2;
            } else if escape == 1 || (0x40..=0x7e).contains(&key) {
                escape = 0;
            }
            continue;
        }
        let mut echo: &[u8] = &[];
        let back_bsp: &[u8] = b"\x08 \x08";
        let mut clear = Vec::new();
        match key {
            b'\r' | b'\n' => return Ok(password.into_iter().collect()),
            3 => {
                return Err(std::io::Error::other("input interrupted"));
            }
            4 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF on stdin",
                ));
            }
            27 => escape = 1,
            8 | 127 => {
                if !password.is_empty() {
                    password.pop();
                    echo = back_bsp;
                }
            }
            21 => {
                for _ in 0..password.len() {
                    clear.extend_from_slice(back_bsp);
                }
                password.clear();
                out.write_all(&clear)?;
                out.flush()?;
                continue;
            }
            _ => {
                // Printable ASCII only in raw byte mode; UTF-8 passwords
                // still work when the terminal is not raw (restore path).
                if (0x20..0x7f).contains(&key) {
                    password.push(key as char);
                    echo = b"*";
                }
            }
        }
        if !echo.is_empty() {
            out.write_all(echo)?;
            out.flush()?;
        }
    }
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
    // Guard BEFORE slicing: `sub[1..]` panics on an empty `sub`, which is what a
    // bare `auth` produces. Reference behaviour is help + exit 0.
    if sub.is_empty() {
        if persona == Persona::Ipatool {
            help_auth();
            return 0;
        }
        eprintln!("usage: perun store auth login|info|revoke");
        return 2;
    }
    let mut rest: Vec<String> = sub[1..].to_vec();
    rest.extend(pre);
    let args_rest: &[String] = &rest;
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
    // perun superset: --remember-password persists the password inside the
    // encrypted account store so unattended relogin (token expiry mid-chain)
    // can replay the full login. The ipatool persona always remembers (majd
    // semantics) and has no such flag.
    let locals: &[(&str, bool)] = if persona == Persona::Ipatool {
        &[
            ("-e", true),
            ("--email", true),
            ("-p", true),
            ("--password", true),
            ("-a", true),
            ("--auth-code", true),
        ]
    } else {
        &[
            ("-e", true),
            ("--email", true),
            ("-p", true),
            ("--password", true),
            ("-a", true),
            ("--auth-code", true),
            ("--remember-password", false),
        ]
    };
    let Some(res) = begin(persona, args, locals, help_auth_login) else {
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

    let email = if email.is_empty() {
        if !ctx.inv.interactive {
            return ctx.usage_fail("required flag(s) \"email\" not set");
        }
        match read_line("enter Apple ID email: ") {
            Ok(v) if !v.is_empty() => v,
            _ => return ctx.usage_fail("required flag(s) \"email\" not set"),
        }
    } else {
        email
    };

    if password.is_empty() && !ctx.inv.interactive {
        return ctx.usage_fail(
            "password is required when not running in interactive mode; use the \"--password\" flag",
        );
    }
    let password = if password.is_empty() {
        match read_password("enter password: ") {
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
                // silently on token expiry). The perun persona defaults to
                // no-password-at-rest; --remember-password opts in.
                let remember =
                    ctx.persona == Persona::Ipatool || ctx.inv.has("--remember-password");
                if remember {
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
    // The perun grammar keeps its native `-t/--term` flag; the ipatool
    // persona is strictly positional (majd's ExactArgs(1)).
    let locals: &[(&str, bool)] = if persona == Persona::Ipatool {
        &[("-l", true), ("--limit", true), ("--platform", true)]
    } else {
        &[
            ("-l", true),
            ("--limit", true),
            ("--platform", true),
            ("-t", true),
            ("--term", true),
            // perun superset: search scopes.
            ("--developer", false),
            ("-dev", false),
            ("--id", false),
            ("--description", false),
            ("-desc", false),
        ]
    };
    let Some(res) = begin(persona, args, locals, help_search) else {
        return 1;
    };
    let ctx = match res {
        Ok(c) => c,
        Err(code) => return code,
    };
    let term = match ctx.persona {
        Persona::Ipatool => {
            if ctx.inv.positional.len() != 1 {
                return ctx.usage_fail(&format!(
                    "accepts 1 arg(s), received {}",
                    ctx.inv.positional.len()
                ));
            }
            ctx.inv.positional[0].clone()
        }
        Persona::Perun => ctx
            .inv
            .get(&["-t", "--term"])
            .map(|s| s.to_string())
            .unwrap_or_else(|| ctx.inv.positional.first().cloned().unwrap_or_default()),
    };
    let limit_raw = ctx.inv.get(&["-l", "--limit"]).unwrap_or("5");
    let limit: i64 = match parse_search_limit_for(ctx.persona, limit_raw) {
        Ok(v) => v,
        Err(e) => return ctx.usage_fail(&e),
    };
    let platform = match parse_platform(ctx.inv.get(&["--platform"]).unwrap_or("")) {
        Ok(p) => p,
        Err(e) => return ctx.usage_fail(&e),
    };

    // Search is a public, unsigned iTunes Search API call that needs only the
    // storefront, so it reads the plaintext sidecar and never opens the vault:
    // no PBKDF2 on this path. Falls back to US when the sidecar is absent.
    let acc = Account {
        store_front: account::storefront_hint(),
        ..Default::default()
    };

    // perun search scopes. The ipatool persona never has these flags; the
    // default (no scope) stays the plain Apple search.
    let dev_scope = ctx.inv.has("--developer") || ctx.inv.has("-dev");
    let id_scope = ctx.inv.has("--id");
    let desc_scope = ctx.inv.has("--description") || ctx.inv.has("-desc");
    let scopes = [dev_scope, id_scope, desc_scope]
        .iter()
        .filter(|s| **s)
        .count();
    if scopes > 1 {
        return ctx.usage_fail("--developer, --id and --description are mutually exclusive");
    }

    let apps = if id_scope {
        // Developer catalog: Lookup API by artist id, full list.
        let artist_id: i64 = match term.parse() {
            Ok(v) => v,
            Err(_) => {
                return ctx.usage_fail(
                    "--id expects a numeric artist id (from artistId in search results)",
                );
            }
        };
        match appstore::lookup_artist_apps(&acc, artist_id, &platform) {
            Ok(a) => a,
            Err(e) => return ctx.fail(e),
        }
    } else if dev_scope || desc_scope {
        // Client-side scopes: fetch the server maximum, filter, THEN slice
        // to --limit — so a filter never shrinks the requested page.
        let probe = if platform == "visionos" {
            appstore::search_visionos(&acc, &term, 12)
        } else {
            appstore::search(&acc, &term, 200, &platform)
        };
        let all = match probe {
            Ok(a) => a,
            Err(e) => return ctx.fail(e),
        };
        let needle = term.to_lowercase();
        let matched: Vec<appstore::App> = all
            .into_iter()
            .filter(|a| {
                if dev_scope {
                    a.developer.to_lowercase().contains(&needle)
                } else {
                    a.description.to_lowercase().contains(&needle)
                }
            })
            .collect();
        matched.into_iter().take(limit as usize).collect()
    } else if platform == "visionos" {
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
    // The `platforms` column is a perun-only extension. The reference ipatool
    // never emits it, and the persona is meant to be byte-identical, so the
    // ipatool side passes an empty list and the field is dropped entirely.
    let show_platforms = ctx.persona == Persona::Perun;
    let items: Vec<AppRow> = apps
        .iter()
        .map(|a| {
            let plats = if show_platforms {
                a.platforms
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<&str>>()
            } else {
                Vec::new()
            };
            (
                a.id,
                a.bundle_id.as_str(),
                a.name.as_str(),
                a.version.as_str(),
                a.price,
                None,
                plats,
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
            ("-i", true),
            ("--app-id", true),
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
    let bundle = ctx
        .inv
        .get(&["-b", "--bundle-identifier"])
        .unwrap_or("")
        .to_string();
    // 91d4294: purchase by app id, no bundle lookup required.
    let app_id = ctx.inv.get(&["-i", "--app-id"]).unwrap_or("").to_string();
    if bundle.is_empty() && app_id.is_empty() {
        return ctx.usage_fail("either the app ID or the bundle identifier must be specified");
    }
    let app_id: i64 = if app_id.is_empty() {
        0
    } else {
        match app_id.parse() {
            Ok(v) => v,
            Err(_) => {
                return ctx.usage_fail(&format!(
                    "invalid argument \"{app_id}\" for \"-i, --app-id\" flag: strconv.ParseInt: parsing \"{app_id}\": invalid syntax"
                ));
            }
        }
    };
    let platform = match parse_platform(ctx.inv.get(&["--platform"]).unwrap_or("")) {
        Ok(p) => p,
        Err(e) => return ctx.usage_fail(&e),
    };
    let acc = match require_account(&ctx) {
        Ok(a) => a,
        Err(c) => return c,
    };
    // Resolve through the shared cache: a `purchase -b X && download -b X`
    // chain must not hit itunes.apple.com/lookup twice for one workflow.
    let app = if app_id != 0 {
        // 91d4294: app-id purchase. Hydrate price via the shared anonymous
        // lookup (cached) so the paid-app guard stays meaningful; the id
        // itself is authoritative, a lookup miss does not block purchase.
        let key = cache_key(&acc, &platform, "i", &app_id.to_string());
        match resolve_cache_read(&key) {
            Some(app) => app,
            None => match appstore::lookup_by_id(&acc, app_id, &platform) {
                Ok(app) => {
                    resolve_cache_write(&key, &app);
                    app
                }
                Err(_) => appstore::App {
                    id: app_id,
                    ..appstore::App::default()
                },
            },
        }
    } else {
        let key = cache_key(&acc, &platform, "b", &bundle);
        match resolve_cache_read(&key) {
            Some(app) => app,
            None => match appstore::lookup(&acc, &bundle, &platform) {
                Ok(app) => {
                    resolve_cache_write(&key, &app);
                    app
                }
                Err(e) => return ctx.fail(e),
            },
        }
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

    // The majd retry loop (retry.Do, Attempts(3)): license-needed +
    // --purchase → buy, retry once; token expiry → one silent relogin round
    // (the stored password replays the login, session cookies carry the 2FA).
    let mut retried_after_purchase = false;
    let mut relogined_after_expiry = false;
    let mut acc = acc;
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
                    // A fresh license purchase can itself be gated on a
                    // fresh token (2034 Sign In): relogin once and retry
                    // the whole round, like the reference's outer retry.Do.
                    Err(StoreError::PasswordTokenExpired) if !relogined_after_expiry => {
                        match relogin_if_possible(&ctx, &acc) {
                            Some(fresh) => {
                                acc = fresh;
                                relogined_after_expiry = true;
                            }
                            None => {
                                return ctx.fail(StoreError::PasswordTokenExpired);
                            }
                        }
                    }
                    Err(e) => return ctx.fail(e),
                }
            }
            Err(StoreError::PasswordTokenExpired) if !relogined_after_expiry => {
                let e = StoreError::PasswordTokenExpired;
                match relogin_if_possible(&ctx, &acc) {
                    Some(fresh) => {
                        acc = fresh;
                        relogined_after_expiry = true;
                    }
                    None => return ctx.fail(e),
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
    let limit_raw = ctx.inv.get(&["-l", "--max-results"]).unwrap_or("10");
    let limit: i64 = match limit_raw.parse() {
        Ok(v) => v,
        Err(_) => {
            return ctx.usage_fail(&format!(
                "invalid --max-results {limit_raw:?}: expected an integer 1..=100"
            ));
        }
    };
    let page_raw = ctx.inv.get(&["-p", "--page"]).unwrap_or("1");
    let page: i64 = match page_raw.parse() {
        Ok(v) => v,
        Err(_) => {
            return ctx.usage_fail(&format!(
                "invalid --page {page_raw:?}: expected an integer >= 1"
            ));
        }
    };
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
                        a.platforms
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<&str>>(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_limit_accepts_range_rejects_garbage() {
        assert_eq!(parse_search_limit_for(Persona::Perun, "5"), Ok(5));
        assert_eq!(parse_search_limit_for(Persona::Perun, "1"), Ok(1));
        assert_eq!(parse_search_limit_for(Persona::Perun, "200"), Ok(200));
        // Garbage, zero, negatives, overflow: errors, never silent 5.
        assert!(parse_search_limit_for(Persona::Perun, "abc").is_err());
        assert!(parse_search_limit_for(Persona::Perun, "").is_err());
        assert!(parse_search_limit_for(Persona::Perun, "0").is_err());
        assert!(parse_search_limit_for(Persona::Perun, "-3").is_err());
        assert!(parse_search_limit_for(Persona::Perun, "201").is_err());
        assert!(parse_search_limit_for(Persona::Perun, "99999999999999999999").is_err());
    }
}
