// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Cross-process checks for the `adi_state` harness binary.
//!
//! The library tests exercise the container in one address space; these
//! run the built binary twice, so the sealed file is the only channel
//! between the writer and the reader.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use perun_adi_core::identity::Identity;

const BIN: &str = env!("CARGO_BIN_EXE_adi_state");

fn pattern<const N: usize>(seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(seed);
    }
    out
}

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "perun-adi-state-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn write_identity(path: &Path, bytes: [u8; 16]) {
    Identity::from_bytes(bytes).write(path).unwrap();
}

#[test]
fn seal_in_one_process_opens_in_another() {
    let dir = temp_dir();
    let mut identity_bytes = [0u8; 16];
    identity_bytes[..8].copy_from_slice(&pattern::<8>(0x11));
    identity_bytes[8..].copy_from_slice(&pattern::<8>(0x22));

    let identity = dir.join("id.bin");
    let state = dir.join("state.bin");
    let cpim = dir.join("cpim.bin");
    let ptm = dir.join("ptm.bin");
    let tk = dir.join("tk.bin");
    let spim = dir.join("spim.bin");
    write_identity(&identity, identity_bytes);
    fs::write(&cpim, pattern::<276>(0x33)).unwrap();
    fs::write(&ptm, pattern::<487>(0x44)).unwrap();
    fs::write(&tk, pattern::<16>(0x55)).unwrap();
    fs::write(&spim, pattern::<347>(0x66)).unwrap();

    let sealed = run(&[
        "seal",
        "--identity",
        identity.to_str().unwrap(),
        "--state",
        state.to_str().unwrap(),
        "--session",
        "0x210168c6",
        "--cpim",
        cpim.to_str().unwrap(),
        "--ptm",
        ptm.to_str().unwrap(),
        "--tk",
        tk.to_str().unwrap(),
        "--spim",
        spim.to_str().unwrap(),
        "--at",
        "1763000000",
    ]);
    assert!(
        sealed.status.success(),
        "seal failed: {}",
        String::from_utf8_lossy(&sealed.stderr)
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&state).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the state file must be private");
    }

    let opened = run(&[
        "open",
        "--identity",
        identity.to_str().unwrap(),
        "--state",
        state.to_str().unwrap(),
        "--summary",
    ]);
    assert!(
        opened.status.success(),
        "open failed: {}",
        String::from_utf8_lossy(&opened.stderr)
    );
    let summary = String::from_utf8_lossy(&opened.stdout);
    assert!(summary.contains("session=0x210168c6"), "{summary}");
    assert!(summary.contains("cpim=276"), "{summary}");
    assert!(summary.contains("ptm=487"), "{summary}");
    assert!(summary.contains("tk=16"), "{summary}");
    assert!(summary.contains("spim=347"), "{summary}");

    let mut wrong_first = identity_bytes;
    wrong_first[0] ^= 0x01;
    let wrong_first_path = dir.join("id-first.bin");
    write_identity(&wrong_first_path, wrong_first);
    let rejected = run(&[
        "open",
        "--identity",
        wrong_first_path.to_str().unwrap(),
        "--state",
        state.to_str().unwrap(),
        "--summary",
    ]);
    assert!(!rejected.status.success(), "a wrong first half must fail");
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("different identity"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );

    let mut other_last = identity_bytes;
    other_last[8..].fill(0xa5);
    let last_path = dir.join("id-last.bin");
    write_identity(&last_path, other_last);
    let accepted = run(&[
        "open",
        "--identity",
        last_path.to_str().unwrap(),
        "--state",
        state.to_str().unwrap(),
        "--summary",
    ]);
    assert!(
        accepted.status.success(),
        "the last eight identity bytes are not bound: {}",
        String::from_utf8_lossy(&accepted.stderr)
    );

    fs::remove_dir_all(dir).unwrap();
}
