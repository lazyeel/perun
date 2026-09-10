// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Output layer with byte-parity to majd/ipatool's zerolog rendering.
//!
//! Two exact formats, selected by `--format`:
//! - `text`: the zerolog `ConsoleWriter` shape — `10:24AM LEVEL key=value …`
//!   (INF/DBG to stdout, ERR to stderr, keys sorted, strings quoted only
//!   when they contain a space or `=`).
//! - `json`: zerolog JSON — `{"level":"info",<fields>,"time":"RFC3339"}`.
//!
//! Field values go through [`Field`], which reproduces zerolog's console
//! vs JSON asymmetry (e.g. `apps` renders before `count` in console mode
//! but after it in JSON, because that is what the reference binary does).

use std::io::Write;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    #[default]
    Text,
    Json,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Debug,
    Info,
    Error,
}

impl Level {
    fn console(self) -> &'static str {
        match self {
            Level::Debug => "DBG",
            Level::Info => "INF",
            Level::Error => "ERR",
        }
    }
    fn json(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Error => "error",
        }
    }
}

/// A structured value: rendered differently per format, like zerolog's
/// `Object`/`Array` marshaling does in console vs JSON mode.
pub enum Field {
    Str(String),
    Int(i64),
    Bool(bool),
    /// A JSON array of objects, already serialized in field order.
    Arr(Vec<String>),
}

impl Field {
    fn text(&self) -> String {
        match self {
            Field::Str(s) => quote_text(s),
            Field::Int(i) => i.to_string(),
            Field::Bool(b) => b.to_string(),
            Field::Arr(items) => {
                let mut out = String::from("[");
                out.push_str(&items.join(","));
                out.push(']');
                out
            }
        }
    }
    fn json(&self) -> String {
        match self {
            Field::Str(s) => json_str(s),
            Field::Int(i) => i.to_string(),
            Field::Bool(b) => b.to_string(),
            Field::Arr(items) => {
                let mut out = String::from("[");
                out.push_str(&items.join(","));
                out.push(']');
                out
            }
        }
    }
}

/// Console strings are bare unless they need quoting; zerolog quotes when
/// the value contains a space or an unprintable/structural character.
fn quote_text(s: &str) -> String {
    let needs = s
        .chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '=' || !c.is_ascii_graphic() && c != ' ');
    if needs || s.is_empty() {
        let mut out = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\r' => out.push_str("\\r"),
                _ => out.push(c),
            }
        }
        out.push('"');
        out
    } else {
        s.to_string()
    }
}

/// zerolog floats: `0` for zero, no trailing `.0`.
fn fmt_float(f: f64) -> String {
    if f == 0.0 {
        "0".into()
    } else if f == f.trunc() && f.abs() < 1e15 {
        format!("{}", f as i64)
    } else {
        let mut s = format!("{f}");
        if s.ends_with(".0") {
            s.truncate(s.len() - 2);
        }
        s
    }
}

pub fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub struct Out {
    pub format: Format,
    pub verbose: bool,
    /// Zero suppresses the trailing "time" field (for deterministic tests).
    pub with_time: bool,
}

impl Out {
    pub fn new(format: Format, verbose: bool) -> Out {
        Out {
            format,
            verbose,
            with_time: true,
        }
    }

    /// `Log()` — INFO.
    pub fn log(&self, fields: &[(&str, Field)]) {
        self.send(Level::Info, fields);
    }

    /// `Verbose()` — DEBUG, dropped unless `--verbose`.
    pub fn verbose_line(&self, fields: &[(&str, Field)]) {
        if self.verbose {
            self.send(Level::Debug, fields);
        }
    }

    /// `Error()` — always emitted; adds `success=false` like the
    /// reference's `Execute()` does for every command error.
    pub fn error(&self, message: &str) {
        self.send(
            Level::Error,
            &[
                ("error", Field::Str(message.to_string())),
                ("success", Field::Bool(false)),
            ],
        );
    }

    fn send(&self, level: Level, fields: &[(&str, Field)]) {
        match self.format {
            Format::Json => {
                let time = humantime_json_now();
                let mut line = String::from("{\"level\":");
                line.push_str(&json_str(level.json()));
                for (name, value) in fields {
                    line.push(',');
                    line.push_str(&json_str(name));
                    line.push(':');
                    line.push_str(&value.json());
                }
                if self.with_time {
                    line.push_str(",\"time\":");
                    line.push_str(&json_str(&time));
                }
                line.push('}');
                // JSON mode: everything to stdout, like zerolog.SyncWriter.
                let mut out = std::io::stdout();
                let _ = writeln!(out, "{line}");
                let _ = out.flush();
            }
            Format::Text => {
                let time = console_time_now();
                // Console mode: zerolog sorts keys, then the level/time
                // prefix. `success` rides in the field list like any other.
                let mut sorted: Vec<&(&str, Field)> = fields.iter().collect();
                sorted.sort_by(|a, b| a.0.cmp(b.0));
                let mut line = format!("{time} {} ", level.console());
                for (i, (name, value)) in sorted.iter().enumerate() {
                    if i > 0 {
                        line.push(' ');
                    }
                    line.push_str(name);
                    line.push('=');
                    line.push_str(&value.text());
                }
                let bytes = line.into_bytes();
                let mut sink: Box<dyn std::io::Write> = if level == Level::Error {
                    Box::new(std::io::stderr())
                } else {
                    Box::new(std::io::stdout())
                };
                let _ = sink.write_all(&bytes);
                let _ = sink.write_all(b"\n");
                let _ = sink.flush();
            }
        }
    }
}

/// RFC3339 for JSON: `2026-09-10T10:24:49Z` (UTC).
fn humantime_json_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d, h, mi, s) = civil_from_unix(now);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Console prefix `10:24AM` (the container runs UTC, matching the
/// reference captures).
pub fn console_time_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (_, _, _, h, mi, _) = civil_from_unix(now);
    let ampm = if h < 12 { "AM" } else { "PM" };
    let h12 = match h % 12 {
        0 => 12,
        h => h,
    };
    format!("{h12:02}:{mi:02}{ampm}")
}

fn civil_from_unix(t: u64) -> (i64, u64, u64, u64, u64, u64) {
    let days = t / 86_400;
    let secs = t % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    (y, m, d, secs / 3600, (secs % 3600) / 60, secs % 60)
}

/// Howard Hinnant's civil-from-days.
fn civil_from_days(z: i64) -> (i64, u64, u64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A field helper for the `apps` array used by search/list-purchases:
/// one app object serialized once, in the zerolog field order.
pub fn app_field_json(id: i64, bundle: &str, name: &str, version: &str, price: f64) -> String {
    format!(
        "{{\"id\":{},\"bundleID\":{},\"name\":{},\"version\":{},\"price\":{}}}",
        id,
        json_str(bundle),
        json_str(name),
        json_str(version),
        fmt_float(price)
    )
}

/// Console mode marshals the same object with its own key order
/// (zerolog console sorts the inner object keys): bundleID,id,name,price,version.
pub fn app_field_console(id: i64, bundle: &str, name: &str, version: &str, price: f64) -> String {
    format!(
        "{{\"bundleID\":{},\"id\":{},\"name\":{},\"price\":{},\"version\":{}}}",
        json_str(bundle),
        id,
        json_str(name),
        fmt_float(price),
        json_str(version)
    )
}

/// `apps` with an optional extra key per item (purchaseDate).
pub type AppRow<'a> = (i64, &'a str, &'a str, &'a str, f64, Option<&'a str>);

pub fn apps_with_date_json(items: &[AppRow]) -> Vec<String> {
    items
        .iter()
        .map(|(id, b, n, v, p, date)| {
            let mut s = app_field_json(*id, b, n, v, *p);
            if let Some(d) = date {
                s.truncate(s.len() - 1);
                s.push_str(&format!(",\"purchaseDate\":{}}}", json_str(d)));
            }
            s
        })
        .collect()
}

pub fn apps_with_date_console(items: &[AppRow]) -> Vec<String> {
    // Console mode sorts every key alphabetically: purchaseDate lands
    // between price and version.
    items
        .iter()
        .map(|(id, b, n, v, p, date)| match date {
            Some(d) => format!(
                "{{\"bundleID\":{},\"id\":{},\"name\":{},\"price\":{},\"purchaseDate\":{},\"version\":{}}}",
                json_str(b),
                id,
                json_str(n),
                fmt_float(*p),
                json_str(d),
                json_str(v)
            ),
            None => app_field_console(*id, b, n, v, *p),
        })
        .collect()
}
