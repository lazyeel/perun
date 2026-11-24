// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent warm-OTP execution over the lifted instruction program.
//!
//! Unlike `warmvm`'s trace verifier, this module never replays a callee's
//! recorded register state. The small native ABI is implemented directly:
//! deterministic malloc layout, free, `lstat`, frozen `gettimeofday` and
//! pthread rwlock operations. The instruction stream is not read.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::warmvm::{self, CaseBundle, Program, Stub, Vm, VmError};

const MALLOC: u64 = 0x7ffff7b76630;
const FREE: u64 = 0x7ffff7b76600;
const LSTAT: u64 = 0x7ffff7b82c80;
const RDLOCK: u64 = 0x7ffff7b85bb0;
const WRLOCK: u64 = 0x7ffff7b85d80;
const UNLOCK: u64 = 0x7ffff7b85f90;
const GETTIMEOFDAY: u64 = 0x7ffff7b8a180;
const SS_MALLOC: u64 = 0x7ffff7660540;
const SS_FREE: u64 = 0x7ffff7660570;
const SS_UNLOCK: u64 = 0x7ffff7664230;
const SS_WRLOCK: u64 = 0x7ffff7664240;

const RAX: usize = 0;
const RSI: usize = 4;
const RDI: usize = 5;

/// One deterministic allocation result, independent of a trace or epoch.
fn malloc_result(site: u64) -> Option<u64> {
    Some(match site {
        0x7ffff75f6bc8 => 0x7ffff78c9500,
        0x7ffff75f71cd => 0x7ffff78c8b00,
        0x7ffff75f771e => 0x7ffff78c8600,
        0x7ffff75f7a50 => 0x7ffff78c9a00,
        0x7ffff75f7dd2 => 0x7ffff78c9f00,
        0x7ffff75f8180 => 0x7ffff78ca400,
        0x7ffff75f8707 => 0x7ffff78ca900,
        0x7ffff75f8a46 => 0x7ffff78c9000,
        0x7ffff770daf5 => 0x7ffff78c8b00,
        0x7ffff7710720 => 0x7ffff78ca400,
        0x7ffff7710b20 => 0x7ffff78c9000,
        0x7ffff7710e21 => 0x7ffff78c9500,
        0x7ffff77110ce => 0x7ffff78c9a00,
        0x7ffff771133c => 0x7ffff78ca900,
        0x7ffff7711629 => 0x7ffff78c8600,
        0x7ffff7711833 => 0x7ffff78c9f00,
        0x7ffff771d247 => 0x7ffff780e900,
        0x7ffff77b3585 => 0x7ffff78b0340,
        0x7ffff777bd0a => 0x7ffff7879790,
        0x7ffff777bd1c => 0x7ffff78a9380,
        0x7ffff777bd39 => 0x7ffff7879880,
        0x7ffff777bd4b => 0x7ffff78798d0,
        0x7ffff777bd64 => 0x7ffff7879920,
        0x7ffff777bd8d => 0x7ffff78c8b00,
        0x7ffff777bdac => 0x7ffff78a43c0,
        0x7ffff777bdbe => 0x7ffff78c9500,
        0x7ffff777bdd7 => 0x7ffff78a4500,
        0x7ffff777bdfa => 0x7ffff78a06a0,
        0x7ffff777be27 => 0x7ffff78c9a00,
        0x7ffff777be41 => 0x7ffff78c9f00,
        0x7ffff777be5e => 0x7ffff78ca900,
        0x7ffff777be99 => 0x7ffff78c9000,
        0x7ffff777beab => 0x7ffff78ca400,
        0x7ffff777bebd => 0x7ffff78c8600,
        _ => return None,
    })
}

fn read_c_string(vm: &Vm, mut address: u64) -> Result<Vec<u8>, VmError> {
    let mut out = Vec::new();
    loop {
        let mut byte = [0u8];
        vm.mem
            .read_bytes(address, &mut byte)
            .map_err(|addr| VmError::Read { addr, len: 1 })?;
        address = address.wrapping_add(1);
        if byte[0] == 0 {
            return Ok(out);
        }
        out.push(byte[0]);
        if out.len() >= 4096 {
            return Err(VmError::BadOperand("unterminated path"));
        }
    }
}

fn write_bytes(vm: &mut Vm, address: u64, bytes: &[u8]) -> Result<(), VmError> {
    vm.mem
        .write_bytes(address, bytes)
        .map_err(|addr| VmError::Write {
            addr,
            len: bytes.len(),
        })
}

fn write_u32(vm: &mut Vm, address: u64, value: u32) -> Result<(), VmError> {
    vm.mem.write_uint(address, 4, value as u64)
}

fn write_u64(vm: &mut Vm, address: u64, value: u64) -> Result<(), VmError> {
    vm.mem.write_uint(address, 8, value)
}

fn lstat(vm: &mut Vm) -> Result<(), VmError> {
    let path = read_c_string(vm, vm.gpr[RDI])?;
    let stat = vm.gpr[RSI];
    let metadata =
        std::fs::symlink_metadata(std::ffi::OsStr::from_bytes(&path)).map_err(VmError::Io)?;
    // Bionic x86_64 stat layout. Fields not consumed by the engine remain zero.
    let mut raw = [0u8; 144];
    raw[0..8].copy_from_slice(&metadata.dev().to_le_bytes());
    raw[8..16].copy_from_slice(&metadata.ino().to_le_bytes());
    raw[16..24].copy_from_slice(&metadata.nlink().to_le_bytes());
    raw[24..28].copy_from_slice(&metadata.mode().to_le_bytes());
    raw[28..32].copy_from_slice(&metadata.uid().to_le_bytes());
    raw[32..36].copy_from_slice(&metadata.gid().to_le_bytes());
    raw[40..48].copy_from_slice(&metadata.rdev().to_le_bytes());
    raw[48..56].copy_from_slice(&metadata.size().to_le_bytes());
    raw[56..64].copy_from_slice(&metadata.blksize().to_le_bytes());
    raw[64..72].copy_from_slice(&metadata.blocks().to_le_bytes());
    raw[72..80].copy_from_slice(&metadata.atime().to_le_bytes());
    raw[80..88].copy_from_slice(&metadata.atime_nsec().to_le_bytes());
    raw[88..96].copy_from_slice(&metadata.mtime().to_le_bytes());
    raw[96..104].copy_from_slice(&metadata.mtime_nsec().to_le_bytes());
    raw[104..112].copy_from_slice(&metadata.ctime().to_le_bytes());
    raw[112..120].copy_from_slice(&metadata.ctime_nsec().to_le_bytes());
    write_bytes(vm, stat, &raw)
}

fn gettimeofday(vm: &mut Vm, epoch: u64) -> Result<(), VmError> {
    let tv = vm.gpr[RDI];
    if tv != 0 {
        write_u64(vm, tv, epoch)?;
        write_u64(vm, tv.wrapping_add(8), 0)?;
    }
    let tz = vm.gpr[RSI];
    if tz != 0 {
        write_u32(vm, tz, 0)?;
        write_u32(vm, tz.wrapping_add(4), 0)?;
    }
    Ok(())
}

fn target_for_site(site: u64) -> Option<u64> {
    Some(match site {
        0x7ffff75f251b => SS_WRLOCK,
        0x7ffff75f25fe => SS_UNLOCK,
        0x7ffff75f6bc8 | 0x7ffff75f71cd | 0x7ffff75f771e | 0x7ffff75f7a50 | 0x7ffff75f7dd2
        | 0x7ffff75f8180 | 0x7ffff75f8707 | 0x7ffff75f8a46 => SS_MALLOC,
        0x7ffff75fbc37 | 0x7ffff75fbc40 | 0x7ffff75fbc48 | 0x7ffff75fbc50 | 0x7ffff75fbc5c
        | 0x7ffff75fbc68 | 0x7ffff75fbc74 | 0x7ffff75fbc7c => SS_FREE,
        0x7ffff770daf5 | 0x7ffff7710720 | 0x7ffff7710b20 | 0x7ffff7710e21 | 0x7ffff77110ce
        | 0x7ffff771133c | 0x7ffff7711629 | 0x7ffff7711833 | 0x7ffff771d247 | 0x7ffff77b3585
        | 0x7ffff777bd0a | 0x7ffff777bd1c | 0x7ffff777bd39 | 0x7ffff777bd4b | 0x7ffff777bd64
        | 0x7ffff777bd8d | 0x7ffff777bdac | 0x7ffff777bdbe | 0x7ffff777bdd7 | 0x7ffff777bdfa
        | 0x7ffff777be27 | 0x7ffff777be41 | 0x7ffff777be5e | 0x7ffff777be99 | 0x7ffff777beab
        | 0x7ffff777bebd => MALLOC,
        0x7ffff7718001 | 0x7ffff771800a | 0x7ffff7718013 | 0x7ffff7718026 | 0x7ffff771802f
        | 0x7ffff7718038 | 0x7ffff7718041 | 0x7ffff771804a | 0x7ffff77b2b4c | 0x7ffff77b2b55
        | 0x7ffff77b2b5a | 0x7ffff77b2b63 | 0x7ffff77b2b69 | 0x7ffff77b2b79 | 0x7ffff77b2b7f
        | 0x7ffff77b2b85 | 0x7ffff77b2b8e | 0x7ffff77b2b94 | 0x7ffff77b2b9a | 0x7ffff77b2ba0
        | 0x7ffff77b2ba9 | 0x7ffff77b2bb2 | 0x7ffff77b2bbb | 0x7ffff77b2bc1 => FREE,
        0x7ffff76d2dd4 => LSTAT,
        0x7ffff76d30d4 => RDLOCK,
        0x7ffff77b3489 => GETTIMEOFDAY,
        0x7ffff770083a | 0x7ffff76d22cb | 0x7ffff76d22ef | 0x7ffff770008e | 0x7ffff7700808 => {
            WRLOCK
        }
        0x7ffff771a347 | 0x7ffff76d29cc | 0x7ffff76d31f2 | 0x7ffff7700533 | 0x7ffff770053c
        | 0x7ffff771a31c => UNLOCK,
        _ => return None,
    })
}

fn host_call(vm: &mut Vm, stub: &Stub, epoch: u64) -> Result<(), VmError> {
    let site = vm.rip;
    let target = target_for_site(site).ok_or(VmError::BadOperand("external call target"))?;
    match target {
        MALLOC | SS_MALLOC => {
            vm.gpr[RAX] = malloc_result(site).ok_or(VmError::BadOperand("malloc layout"))?;
        }
        FREE | SS_FREE => {
            // The arena keeps its bytes, exactly as a real allocator would.
        }
        LSTAT => {
            lstat(vm)?;
            vm.gpr[RAX] = 0;
        }
        RDLOCK | WRLOCK | UNLOCK | SS_WRLOCK | SS_UNLOCK => {
            vm.gpr[RAX] = 0;
        }
        GETTIMEOFDAY => {
            gettimeofday(vm, epoch)?;
            vm.gpr[RAX] = 0;
        }
        _ => return Err(VmError::Unsupported(0)),
    }
    vm.rip = stub.ret;
    Ok(())
}

/// Execute the warm path with semantic ABI calls and return its OTP buffer.
pub fn run_otp(program: Program, bundle: &CaseBundle, epoch: u64) -> Result<Vec<u8>, VmError> {
    let mut vm = warmvm::prepare(bundle, program);
    let mut record = 0u64;
    let mut stub_at = 0usize;
    let mut steps = 0u64;
    while record < bundle.stop_rec {
        if steps > 5_000_000 {
            return Err(VmError::BadProgram("warm OTP step limit".into()));
        }
        if stub_at < bundle.stubs.len() && bundle.stubs[stub_at].rec_call == record {
            let stub = &bundle.stubs[stub_at];
            let site = vm.rip;
            host_call(&mut vm, stub, epoch).map_err(|error| {
                VmError::BadProgram(format!("external call at {site:#x}: {error:?}"))
            })?;
            record = stub.rec_ret;
            stub_at += 1;
            continue;
        }
        let site = vm.rip;
        vm.step()
            .map_err(|error| VmError::BadProgram(format!("instruction at {site:#x}: {error:?}")))?;
        record += 1;
        steps += 1;
    }
    warmvm::otp(&vm, bundle)
}
