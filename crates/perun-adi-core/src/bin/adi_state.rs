// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! adi_state: exercise the PERUNST v1 container and the Apple `adi.pb` codec.
//!
//! ```text
//! adi_state seal --identity <id.bin> --state <out.bin> --session <u32|0x..> \
//!                --cpim <276> --ptm <487> --tk <16> [--spim <347>] [--at <unix>]
//! adi_state open --identity <id.bin> --state <state.bin> [--summary]
//! adi_state apple-inspect --state <adi.pb>
//! adi_state apple-roundtrip --state <adi.pb> --out <copy.pb>
//! ```
//!
//! Exit codes: 0 success, 1 rejected/mismatch, 2 usage, 3 i/o.
//!
//! This is a harness tool, not the product API: it exists so that the
//! container can be exercised across processes and against real captures.

use std::process::ExitCode;

use perun_adi_core::cpim::CpimLayout;
use perun_adi_core::identity::Identity;
use perun_adi_core::state::{self, AppleState, ProvisioningRecord, CPIM_LEN, PTM_LEN, TK_LEN};

const USAGE: &str = "\
usage:
  adi_state seal --identity <id.bin> --state <out.bin> --session <u32|0x..> \
                 --cpim <276> --ptm <487> --tk <16> [--spim <347>] [--at <unix>]
  adi_state open --identity <id.bin> --state <state.bin> [--summary]
  adi_state apple-inspect --state <adi.pb>
  adi_state apple-roundtrip --state <adi.pb> --out <copy.pb>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("adi_state: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let Some(command) = args.first() else {
        eprintln!("{USAGE}");
        return Err("missing command".into());
    };
    match command.as_str() {
        "seal" => seal(&args[1..]),
        "open" => open(&args[1..]),
        "apple-inspect" => apple_inspect(&args[1..]),
        "apple-roundtrip" => apple_roundtrip(&args[1..]),
        "-h" | "--help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other}\n\n{USAGE}")),
    }
}
fn seal(args: &[String]) -> Result<(), String> {
    let mut opts = Options::parse(args);
    let identity = opts.identity()?;
    let state_path = opts.take("--state")?;

    // Hybrid form: --capture reads a native case directory's
    // cpim/spim/ptm/tk, so a native oracle artifact can be sealed without
    // copy-pasting four files through the shell.
    let capture = opts.take_optional("--capture");
    let (session, cpim, ptm, tk, spim, provisioned_at) = if let Some(dir) = capture {
        let session = parse_u32(&opts.take("--session")?)?;
        let cpim = read_len(&format!("{dir}/cpim.bin"), CPIM_LEN)?;
        let ptm = read_len(&format!("{dir}/ptm.bin"), PTM_LEN)?;
        let tk = read_len(&format!("{dir}/tk.bin"), TK_LEN)?;
        let spim_path = format!("{dir}/spim.bin");
        let spim = if std::path::Path::new(&spim_path).exists() {
            Some(read_len(&spim_path, 347)?)
        } else {
            None
        };
        let at = if opts.has("--at") {
            parse_u64(&opts.take("--at")?)?
        } else if let Some(at) = read_provisioned_at(&dir)? {
            at
        } else {
            now()?
        };
        (session, cpim, ptm, tk, spim, at)
    } else {
        let session = parse_u32(&opts.take("--session")?)?;
        let cpim = opts.bytes("--cpim", CPIM_LEN)?;
        let ptm = opts.bytes("--ptm", PTM_LEN)?;
        let tk = opts.bytes("--tk", TK_LEN)?;
        let spim = if opts.has("--spim") {
            Some(opts.bytes("--spim", 347)?)
        } else {
            None
        };
        let at = if opts.has("--at") {
            parse_u64(&opts.take("--at")?)?
        } else {
            now()?
        };
        (session, cpim, ptm, tk, spim, at)
    };
    opts.reject_rest()?;

    let record = ProvisioningRecord {
        identity: *identity.bound(),
        session,
        provisioned_at,
        cpim: cpim.try_into().expect("length checked"),
        ptm: ptm.try_into().expect("length checked"),
        tk: tk.try_into().expect("length checked"),
        spim,
    };
    state::store(state_path, &record).map_err(|error| error.to_string())
}

fn open(args: &[String]) -> Result<(), String> {
    let mut opts = Options::parse(args);
    let identity = opts.identity()?;
    let state_path = opts.take("--state")?;
    let capture = opts.take_optional("--capture");
    let summary = opts.toggle("--summary")?;
    opts.reject_rest()?;

    let record = state::load(state_path, &identity).map_err(|error| error.to_string())?;
    if let Some(dir) = capture {
        std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
        std::fs::write(format!("{dir}/cpim.bin"), record.cpim)
            .map_err(|error| error.to_string())?;
        std::fs::write(format!("{dir}/ptm.bin"), record.ptm).map_err(|error| error.to_string())?;
        std::fs::write(format!("{dir}/tk.bin"), record.tk).map_err(|error| error.to_string())?;
        if let Some(spim) = &record.spim {
            std::fs::write(format!("{dir}/spim.bin"), spim).map_err(|error| error.to_string())?;
        }
        std::fs::write(format!("{dir}/session.bin"), record.session.to_le_bytes())
            .map_err(|error| error.to_string())?;
        let seconds = i64::try_from(record.provisioned_at)
            .map_err(|_| "provisioned_at does not fit the native timespec".to_string())?;
        let mut provisioned_at = Vec::with_capacity(16);
        provisioned_at.extend_from_slice(&seconds.to_le_bytes());
        provisioned_at.extend_from_slice(&0i64.to_le_bytes());
        std::fs::write(format!("{dir}/provisioned-at.bin"), provisioned_at)
            .map_err(|error| error.to_string())?;
    }
    if summary {
        println!(
            "identity={} session={:#010x} provisioned_at={} cpim={} ptm={} tk={} spim={}",
            hex(&record.identity),
            record.session,
            record.provisioned_at,
            record.cpim.len(),
            record.ptm.len(),
            record.tk.len(),
            record.spim.as_ref().map_or(0, Vec::len),
        );
    } else {
        println!("{}", hex(&record.identity));
        println!("{:#010x}", record.session);
        println!("{}", record.provisioned_at);
        println!("{}", hex(&record.cpim));
        println!("{}", hex(&record.ptm));
        println!("{}", hex(&record.tk));
        println!(
            "{}",
            record.spim.as_ref().map_or(String::new(), |spim| hex(spim))
        );
    }
    Ok(())
}

fn apple_inspect(args: &[String]) -> Result<(), String> {
    let mut opts = Options::parse(args);
    let state_path = opts.take("--state")?;
    opts.reject_rest()?;

    let bytes = std::fs::read(&state_path).map_err(|error| error.to_string())?;
    let state = AppleState::parse(&bytes).map_err(|error| error.to_string())?;
    println!("bytes={}", bytes.len());
    println!("version={}", state.version());
    println!("native_supported={}", state.is_native_supported());
    println!("blob_len={}", state.blob().len());
    println!("tail_len={}", state.tail().len());
    if let Ok(cpim) = CpimLayout::parse(state.blob()) {
        println!("blob_is_cpim=true");
        println!("cpim_version={}", cpim.version);
        println!("cpim_session={}", hex(&cpim.session));
        println!("cpim_body_a_digest={}", hex(&cpim.body_a_digest));
        println!("cpim_body_b_len={}", cpim.body_b.len());
        println!("cpim_body_b_version={:#x}", cpim.body_b_version);
    }
    Ok(())
}

fn apple_roundtrip(args: &[String]) -> Result<(), String> {
    let mut opts = Options::parse(args);
    let state_path = opts.take("--state")?;
    let out_path = opts.take("--out")?;
    opts.reject_rest()?;

    let bytes = std::fs::read(&state_path).map_err(|error| error.to_string())?;
    let state = AppleState::parse(&bytes).map_err(|error| error.to_string())?;
    let encoded = state.encode();
    if encoded != bytes {
        return Err("the Apple codec is not byte-exact".into());
    }
    std::fs::write(&out_path, &encoded).map_err(|error| error.to_string())?;
    println!("round-trip={} bytes", encoded.len());
    Ok(())
}

fn now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

fn read_provisioned_at(dir: &str) -> Result<Option<u64>, String> {
    let path = format!("{dir}/provisioned-at.bin");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{path}: {error}")),
    };
    if bytes.len() != 16 {
        return Err(format!("{path}: expected a 16-byte native timespec"));
    }
    let seconds = i64::from_le_bytes(bytes[..8].try_into().expect("length checked"));
    let nanoseconds = i64::from_le_bytes(bytes[8..].try_into().expect("length checked"));
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(format!("{path}: invalid native timespec"));
    }
    Ok(Some(seconds as u64))
}

fn read_len(path: &str, len: usize) -> Result<Vec<u8>, String> {
    let value = std::fs::read(path).map_err(|error| format!("{path}: {error}"))?;
    if value.len() != len {
        return Err(format!("{path}: expected {len} bytes, got {}", value.len()));
    }
    Ok(value)
}

struct Options {
    values: Vec<String>,
}

impl Options {
    fn parse(args: &[String]) -> Self {
        Self {
            values: args.to_vec(),
        }
    }

    fn has(&self, key: &str) -> bool {
        self.values.iter().any(|value| value == key)
    }

    fn take(&mut self, key: &str) -> Result<String, String> {
        let index = self
            .values
            .iter()
            .position(|value| value == key)
            .ok_or_else(|| format!("missing {key}"))?;
        if index + 1 >= self.values.len() {
            return Err(format!("{key} needs a value"));
        }
        let value = self.values.remove(index + 1);
        self.values.remove(index);
        Ok(value)
    }

    fn toggle(&mut self, key: &str) -> Result<bool, String> {
        if !self.has(key) {
            return Ok(false);
        }
        let index = self
            .values
            .iter()
            .position(|value| value == key)
            .ok_or_else(|| format!("missing {key}"))?;
        let mut enabled = true;
        if let Some(next) = self.values.get(index + 1) {
            match next.as_str() {
                "1" | "yes" | "true" => {
                    self.values.remove(index + 1);
                }
                "0" | "no" | "false" => {
                    self.values.remove(index + 1);
                    enabled = false;
                }
                _ => {}
            }
        }
        self.values.remove(index);
        Ok(enabled)
    }

    fn bytes(&mut self, key: &str, len: usize) -> Result<Vec<u8>, String> {
        let value = std::fs::read(self.take(key)?).map_err(|error| error.to_string())?;
        if value.len() != len {
            return Err(format!("{key} must be {len} bytes, got {}", value.len()));
        }
        Ok(value)
    }

    fn take_optional(&mut self, key: &str) -> Option<String> {
        self.take(key).ok()
    }

    fn identity(&mut self) -> Result<Identity, String> {
        let path = self.take("--identity")?;
        Identity::read(path).map_err(|error| error.to_string())
    }

    fn reject_rest(&self) -> Result<(), String> {
        if self.values.is_empty() {
            Ok(())
        } else {
            Err(format!("unexpected arguments: {}", self.values.join(" ")))
        }
    }
}

fn parse_u32(text: &str) -> Result<u32, String> {
    let text = text.trim();
    let parsed = if let Some(hex) = text.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
    } else {
        text.parse()
    };
    parsed.map_err(|error| format!("invalid u32 {text:?}: {error}"))
}

fn parse_u64(text: &str) -> Result<u64, String> {
    text.trim()
        .parse()
        .map_err(|error| format!("invalid u64 {text:?}: {error}"))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
