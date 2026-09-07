// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! CLI front for the Store lane: `perun store …` plus the ipatool-
//! compatible top-level aliases (`perun auth login`, `perun search`, …).
//!
//! Flag-for-flag compatible with majd/ipatool v2.x:
//!   auth login      -e/--email -p/--password -a/--auth-code
//!   search          -t/--term -l/--limit --platform
//!   purchase        -i/--app-id -b/--bundle-identifier
//!   download        -i/-b -o/--output
//!   list-purchases  -l/--max-results -p/--page
//!   list-versions   -i/-b
//!   get-version-metadata -i/-b --external-version-id
//!
//! The SAP signer runs on the dedicated guest thread with the same stack
//! geometry as `perun sap` (the obfuscated guest requires it), so every
//! command that signs ships through `store::run_on_sap_thread`.

use std::io::Write as _;

use crate::store::account::{self, Account};
use crate::store::appstore::StoreError;
use crate::store::{appstore, bag, signer};

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
    if args.is_empty() {
        usage();
        return 2;
    }
    let cmd = args[0].as_str();
    let rest = &args[1..];
    match cmd {
        "auth" => cmd_auth(rest),
        // Debug: sign arbitrary hex twice against the bag-driven session.
        "sign" => cmd_sign_debug(rest),
        "search" => cmd_search(rest),
        "purchase" => cmd_purchase(rest),
        "download" => cmd_download(rest),
        "list-purchases" | "purchases" => cmd_list_purchases(rest),
        "list-versions" => cmd_list_versions(rest),
        "get-version-metadata" => cmd_get_version_metadata(rest),
        _ => {
            eprintln!("[store] unknown command: {cmd}");
            usage();
            2
        }
    }
}

fn usage() {
    eprintln!(
        "usage: perun store auth login|info|revoke\n\
         \x20      perun store search -t TERM [-l LIMIT] [--platform P]\n\
         \x20      perun store purchase -i APP_ID | -b BUNDLE_ID\n\
         \x20      perun store download -i APP_ID | -b BUNDLE_ID [-o PATH]\n\
         \x20      perun store list-purchases [-l MAX] [-p PAGE]\n\
         \x20      perun store list-versions -i APP_ID | -b BUNDLE_ID\n\
         \x20      perun store get-version-metadata -i APP_ID | -b BUNDLE_ID --external-version-id ID"
    );
}

// ── shared plumbing ───────────────────────────────────────────────────────

struct Flags {
    pairs: Vec<(String, String)>,
    /// Positional (non-flag) arguments — reserved for future commands.
    #[allow(dead_code)]
    free: Vec<String>,
}

impl Flags {
    fn parse(args: &[String], known: &[&str]) -> Flags {
        let mut pairs = Vec::new();
        let mut free = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            let mut hit = false;
            for name in known {
                let with_val = if a == *name {
                    true
                } else {
                    a.starts_with(name) && a.as_bytes().get(name.len()) == Some(&b'=')
                };
                if with_val {
                    let value = if a == *name {
                        i += 1;
                        args.get(i).cloned().unwrap_or_default()
                    } else {
                        a[name.len() + 1..].to_string()
                    };
                    pairs.push(((*name).to_string(), value));
                    hit = true;
                    break;
                }
            }
            if !hit {
                free.push(a.clone());
            }
            i += 1;
        }
        Flags { pairs, free }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn take(&mut self, name: &str) -> Option<String> {
        let pos = self.pairs.iter().position(|(n, _)| n == name)?;
        Some(self.pairs.remove(pos).1)
    }
}

/// Load the saved account or fail with the ipatool-shaped message.
fn require_account() -> Result<Account, i32> {
    match account::load("") {
        Ok(acc) => Ok(acc),
        Err(e) => {
            eprintln!("[store] account: {e}");
            eprintln!("run 'perun store auth login' first");
            Err(1)
        }
    }
}

/// Resolve an app by -i or -b through the saved account's storefront.
fn resolve_app(flags: &Flags, acc: &Account) -> Result<appstore::App, i32> {
    let app_id = flags.get("--app-id").or_else(|| flags.get("-i"));
    let bundle = flags.get("--bundle-identifier").or_else(|| flags.get("-b"));
    let platform = flags.get("--platform").unwrap_or("");

    if let Some(id) = app_id {
        id.parse::<i64>()
            .map_err(|_| {
                eprintln!("[store] bad app id: {id}");
                2
            })
            .and_then(|id| appstore::lookup_by_id(acc, id, platform).map_err(exit_err))
    } else if let Some(b) = bundle {
        appstore::lookup(acc, b, platform).map_err(exit_err)
    } else {
        eprintln!("[store] provide -i/--app-id or -b/--bundle-identifier");
        Err(2)
    }
}

fn exit_err(e: StoreError) -> i32 {
    eprintln!("[store] {e}");
    1
}

/// stderr is a TTY (for the progress bar). libc isatty(2), no extra deps.
fn is_tty() -> bool {
    unsafe { libc::isatty(2) == 1 }
}

/// Progress bar: single line, carriage-return redraw, human sizes.
fn print_progress(downloaded: u64, total: u64) {
    if !is_tty() {
        return;
    }
    let done = if total > 0 {
        downloaded as f64 / total as f64
    } else {
        0.0
    };
    let width = 24;
    let filled = (done * width as f64) as usize;
    let bar: String = "█".repeat(filled) + &"·".repeat(width - filled);
    eprint!(
        "\r\x1b[K  [{bar}] {:>6.1}/{:>6.1} MiB",
        downloaded as f64 / (1024.0 * 1024.0),
        if total > 0 {
            total as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        }
    );
    if total > 0 && downloaded >= total {
        eprintln!();
    }
}

fn cmd_sign_debug(args: &[String]) -> i32 {
    let hex = args.first().cloned().unwrap_or_else(|| "0102".into());
    let mac = crate::store::primary_mac();
    let guid = appstore::guid_from_mac(&mac);
    let config = match bag::Bag::fetch(&guid) {
        Ok(b) => b.sap,
        Err(e) => {
            eprintln!("[store] bag: {e}");
            return 1;
        }
    };
    let mut sign = match signer::Signer::new(&config, mac) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[store] SAP: {e}");
            return 1;
        }
    };
    let bytes: Vec<u8> = if hex == "loginbody" {
        // A login-payload-sized XML body, like the real flow signs.
        b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>appleId</key><string>smoke-test@example.com</string><key>password</key><string>wrongpassword111111</string></dict></plist>".to_vec()
    } else {
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect()
    };
    for round in 1..=3 {
        match sign.sign(&bytes) {
            Ok(sig) => println!("round {round}: {} bytes", sig.len()),
            Err(e) => {
                eprintln!("round {round}: ERR {e}");
                return 1;
            }
        }
        // Interleave a real HTTP round-trip like the login loop does.
        let res = crate::store::http::send(crate::store::http::Request::new(
            "GET",
            "https://init.itunes.apple.com/bag.xml?guid=DEBUG",
        ));
        match res {
            Ok(r) => println!("  http between: {}", r.status),
            Err(e) => println!("  http between: ERR {e}"),
        }
    }
    0
}

// ── auth ──────────────────────────────────────────────────────────────────

fn cmd_auth(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: perun store auth login|info|revoke");
        return 2;
    }
    match args[0].as_str() {
        "login" => cmd_auth_login(&args[1..]),
        "info" => cmd_auth_info(),
        "revoke" => match account::revoke() {
            Ok(()) => {
                println!("credentials revoked");
                0
            }
            Err(e) => {
                eprintln!("[store] revoke: {e}");
                1
            }
        },
        other => {
            eprintln!("[store] unknown auth subcommand: {other}");
            2
        }
    }
}

fn cmd_auth_info() -> i32 {
    match account::load("") {
        Ok(acc) => {
            println!("email: {}", acc.email);
            if !acc.name.is_empty() {
                println!("name: {}", acc.name);
            }
            println!("dsid: {}", acc.directory_services_id);
            println!("storefront: {}", acc.store_front);
            if !acc.pod.is_empty() {
                println!("pod: {}", acc.pod);
            }
            0
        }
        Err(e) => {
            eprintln!("[store] {e}");
            1
        }
    }
}

fn cmd_auth_login(args: &[String]) -> i32 {
    let mut flags = Flags::parse(
        args,
        &["-e", "--email", "-p", "--password", "-a", "--auth-code"],
    );
    // A fresh login starts from a clean cookie jar: stale session cookies
    // from a previous failed attempt short-circuit the 2FA round.
    if let Err(e) = account::reset_session() {
        eprintln!("[store] session reset: {e}");
    }
    let email = flags
        .take("-e")
        .or_else(|| flags.take("--email"))
        .unwrap_or_default();
    let password = flags
        .take("-p")
        .or_else(|| flags.take("--password"))
        .unwrap_or_default();
    let auth_code = flags
        .take("-a")
        .or_else(|| flags.take("--auth-code"))
        .unwrap_or_default();

    let email = if email.is_empty() {
        match read_line("email: ") {
            Ok(v) => v,
            Err(_) => return 1,
        }
    } else {
        email
    };
    let password = if password.is_empty() {
        match read_line("password: ") {
            Ok(v) => v,
            Err(_) => return 1,
        }
    } else {
        password
    };

    let mac = crate::store::primary_mac();
    let guid = appstore::guid_from_mac(&mac);
    println!("[store] machine guid: {guid}");

    // Bag + signer on this (SAP-configured) thread.
    let config = match bag::Bag::fetch(&guid) {
        Ok(b) => b.sap,
        Err(e) => {
            eprintln!("[store] bag: {e}");
            return 1;
        }
    };
    let mut sign = match signer::Signer::new(&config, mac) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[store] SAP: {e}");
            return 1;
        }
    };

    let mut auth_code = auth_code;
    loop {
        match appstore::login(&email, &password, &auth_code, mac, &mut sign, &config) {
            Ok(acc) => {
                match account::save(&acc, "") {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("[store] save account: {e}");
                        return 1;
                    }
                }
                println!("logged in: {}", acc.email);
                println!("name: {}", acc.name);
                println!("storefront: {}", acc.store_front);
                return 0;
            }
            Err(StoreError::AuthCodeRequired) => {
                let code = match read_line("2FA code: ") {
                    Ok(v) => v,
                    Err(_) => return 1,
                };
                if code.trim().is_empty() {
                    eprintln!("[store] auth code is required");
                    return 1;
                }
                auth_code = code.trim().to_string();
                continue;
            }
            Err(StoreError::InvalidAuthCode) => {
                // The code was rejected or expired. Request a fresh one
                // (ideally generated ahead of time on appleid.apple.com or
                // an Apple device — codes triggered by the login itself
                // are delivered unreliably) and try again.
                eprintln!("[store] 2FA code rejected or expired");
                let code = match read_line("fresh 2FA code (empty to abort): ") {
                    Ok(v) => v,
                    Err(_) => return 1,
                };
                if code.trim().is_empty() {
                    return 1;
                }
                auth_code = code.trim().to_string();
                continue;
            }
            Err(e) => return exit_err(e),
        }
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

// ── search ────────────────────────────────────────────────────────────────

fn cmd_search(args: &[String]) -> i32 {
    let mut flags = Flags::parse(args, &["-t", "--term", "-l", "--limit", "--platform"]);
    let term = flags
        .take("-t")
        .or_else(|| flags.take("--term"))
        .unwrap_or_default();
    if term.is_empty() {
        eprintln!("[store] search requires -t/--term");
        return 2;
    }
    let limit: u32 = flags
        .take("-l")
        .or_else(|| flags.take("--limit"))
        .unwrap_or_else(|| "5".into())
        .parse()
        .unwrap_or(5);
    let platform = flags.take("--platform").unwrap_or_default();

    let acc = match require_account() {
        Ok(a) => a,
        Err(c) => return c,
    };
    match appstore::search(&acc, &term, limit, &platform) {
        Ok(apps) => {
            println!("found {} app(s)", apps.len());
            for app in &apps {
                println!(
                    "{:>12}  {:<40}  {:<24}  v{}  ${:.2}",
                    app.id, app.name, app.bundle_id, app.version, app.price
                );
            }
            0
        }
        Err(e) => exit_err(e),
    }
}

// ── purchase ──────────────────────────────────────────────────────────────

fn cmd_purchase(args: &[String]) -> i32 {
    let flags = Flags::parse(
        args,
        &["-i", "--app-id", "-b", "--bundle-identifier", "--platform"],
    );
    let acc = match require_account() {
        Ok(a) => a,
        Err(c) => return c,
    };
    let app = match resolve_app(&flags, &acc) {
        Ok(a) => a,
        Err(c) => return c,
    };
    if app.price > 0.0 {
        eprintln!("[store] purchasing paid apps is not supported");
        return 1;
    }
    let mac = crate::store::primary_mac();
    let guid = appstore::guid_from_mac(&mac);
    match appstore::purchase(&acc, &app, &guid, true) {
        Ok(()) => {
            println!("purchased: {} ({})", app.name, app.id);
            0
        }
        Err(e) => exit_err(e),
    }
}

// ── download ──────────────────────────────────────────────────────────────

fn cmd_download(args: &[String]) -> i32 {
    let flags = Flags::parse(
        args,
        &[
            "-i",
            "--app-id",
            "-b",
            "--bundle-identifier",
            "-o",
            "--output",
            "--platform",
        ],
    );
    let acc = match require_account() {
        Ok(a) => a,
        Err(c) => return c,
    };
    let app = match resolve_app(&flags, &acc) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let output = flags
        .get("--output")
        .or_else(|| flags.get("-o"))
        .unwrap_or("")
        .to_string();
    let mac = crate::store::primary_mac();
    let guid = appstore::guid_from_mac(&mac);
    let mut progress = print_progress;
    match appstore::download(&acc, &app, &output, "", &guid, &mut progress) {
        Ok(out) => {
            println!("saved: {}", out.destination);
            if !out.sinfs.is_empty() {
                println!("sinf files embedded: {}", out.sinfs.len());
            }
            0
        }
        Err(e) => exit_err(e),
    }
}

// ── list-purchases ────────────────────────────────────────────────────────

fn cmd_list_purchases(args: &[String]) -> i32 {
    let mut flags = Flags::parse(args, &["-l", "--max-results", "-p", "--page"]);
    let limit: u32 = flags
        .take("-l")
        .or_else(|| flags.take("--max-results"))
        .unwrap_or_else(|| "10".into())
        .parse()
        .unwrap_or(10);
    let page: u32 = flags
        .take("-p")
        .or_else(|| flags.take("--page"))
        .unwrap_or_else(|| "1".into())
        .parse()
        .unwrap_or(1);

    let acc = match require_account() {
        Ok(a) => a,
        Err(c) => return c,
    };
    let mac = crate::store::primary_mac();
    let guid = appstore::guid_from_mac(&mac);

    // The DAAP update/items bodies are SAP-signed: bag + signer.
    let config = match bag::Bag::fetch(&guid) {
        Ok(b) => b.sap,
        Err(e) => {
            eprintln!("[store] bag: {e}");
            return 1;
        }
    };
    let mut sign = match signer::Signer::new(&config, mac) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[store] SAP: {e}");
            return 1;
        }
    };
    match appstore::owned_apps(&acc, &guid, &mut sign, page, limit) {
        Ok(out) => {
            println!("total: {} (page {})", out.total, page);
            for app in &out.apps {
                println!(
                    "{:>12}  {:<40}  v{}  {}",
                    app.id,
                    app.name,
                    app.version,
                    app.purchase_date.as_deref().unwrap_or("")
                );
            }
            0
        }
        Err(e) => exit_err(e),
    }
}

// ── list-versions / get-version-metadata ─────────────────────────────────

fn cmd_list_versions(args: &[String]) -> i32 {
    let flags = Flags::parse(
        args,
        &["-i", "--app-id", "-b", "--bundle-identifier", "--platform"],
    );
    let acc = match require_account() {
        Ok(a) => a,
        Err(c) => return c,
    };
    let app = match resolve_app(&flags, &acc) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let mac = crate::store::primary_mac();
    let guid = appstore::guid_from_mac(&mac);
    match appstore::list_versions(&acc, app.id, &guid) {
        Ok(out) => {
            println!(
                "latest external version id: {}",
                out.latest_external_version_id
            );
            println!("version identifiers:");
            for id in &out.external_version_identifiers {
                println!("  {id}");
            }
            0
        }
        Err(e) => exit_err(e),
    }
}

fn cmd_get_version_metadata(args: &[String]) -> i32 {
    let flags = Flags::parse(
        args,
        &[
            "-i",
            "--app-id",
            "-b",
            "--bundle-identifier",
            "--external-version-id",
            "--platform",
        ],
    );
    let version_id = match flags.get("--external-version-id") {
        Some(v) => v.to_string(),
        None => {
            eprintln!("[store] --external-version-id is required");
            return 2;
        }
    };
    let acc = match require_account() {
        Ok(a) => a,
        Err(c) => return c,
    };
    let app = match resolve_app(&flags, &acc) {
        Ok(a) => a,
        Err(c) => return c,
    };
    let mac = crate::store::primary_mac();
    let guid = appstore::guid_from_mac(&mac);
    match appstore::get_version_metadata(&acc, app.id, &guid, &version_id) {
        Ok(meta) => {
            println!("version: {}", meta.display_version);
            println!("release date: {}", meta.release_date);
            0
        }
        Err(e) => exit_err(e),
    }
}
