// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Account state + the on-disk session store.
//!
//! File format v3 (byte-compatible with the C++ ipatool fork): a binary
//! blob `[0x03][u32 salt_len][salt][IV][GCM tag][ciphertext]`, where the
//! key is PBKDF2-SHA256(machine_id + "nice_token_is_nice" + passphrase,
//! salt, 100000, 32). The plaintext is the session JSON (email, tokens,
//! storefront, pod, cookies-only auth). The password itself is stored
//! only when the user passes `--remember-password` — otherwise the file
//! holds session tokens alone and re-login asks for it again.

use std::path::PathBuf;

use super::state_dir;

/// The persisted account/session.
#[derive(Clone, Debug, Default)]
pub struct Account {
    pub email: String,
    pub name: String,
    pub directory_services_id: String,
    pub password_token: String,
    pub store_front: String,
    pub pod: String,
    /// Optional; present only with `--remember-password`.
    pub password: String,
}

impl Account {
    pub fn to_json(&self) -> String {
        // Hand-rolled JSON writer: fixed field set, no escaping surprises
        // beyond the basics. Storefront/pod/email are Apple-controlled
        // ASCII in practice; escape anyway.
        format!(
            "{{\"email\":{},\"name\":{},\"directoryServicesIdentifier\":{},\"passwordToken\":{},\"storeFront\":{},\"pod\":{},\"password\":{}}}",
            json_str(&self.email),
            json_str(&self.name),
            json_str(&self.directory_services_id),
            json_str(&self.password_token),
            json_str(&self.store_front),
            json_str(&self.pod),
            json_str(&self.password),
        )
    }

    pub fn from_json(text: &str) -> Result<Account, String> {
        let value = super::json::parse(text)?;
        let get = |key: &str| -> String {
            value
                .get(key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        Ok(Account {
            email: get("email"),
            name: get("name"),
            directory_services_id: get("directoryServicesIdentifier"),
            password_token: get("passwordToken"),
            store_front: get("storeFront"),
            pod: get("pod"),
            password: get("password"),
        })
    }
}

fn json_str(s: &str) -> String {
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

// ── file format v3 ────────────────────────────────────────────────────────

const FORMAT_V3: u8 = 0x03;
const SALT_LEN: usize = 16;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const PBKDF2_ROUNDS: u32 = 100_000;

pub fn account_file() -> Result<PathBuf, String> {
    Ok(state_dir()?.join("account"))
}

/// Machine binding: the machine MAC as lowercase colon hex (same source
/// as the `guid` used for Store requests). Pinned on first use, so the
/// file stays decryptable across NIC and namespace changes.
pub fn machine_id() -> String {
    super::primary_mac_hex()
}

/// Derive the file key: PBKDF2-SHA256(machine + pepper + passphrase, salt).
fn derive_key(machine: &str, passphrase: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let material = format!("{machine}nice_token_is_nice{passphrase}");
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac_sha256(material.as_bytes(), salt, PBKDF2_ROUNDS, &mut key);
    key
}

/// Encrypt the account JSON into the v3 blob.
pub fn encrypt(plaintext: &str, machine: &str, passphrase: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    fill_random(&mut salt);
    fill_random(&mut iv);
    let key = derive_key(machine, passphrase, &salt);
    let (ciphertext, tag) = aes_gcm_encrypt(&key, &iv, plaintext.as_bytes())?;

    let mut out = Vec::with_capacity(1 + 4 + SALT_LEN + IV_LEN + TAG_LEN + ciphertext.len());
    out.push(FORMAT_V3);
    out.extend_from_slice(&(SALT_LEN as u32).to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a v3 blob back into the account JSON.
pub fn decrypt(blob: &[u8], machine: &str, passphrase: &str) -> Result<String, String> {
    if blob.first() == Some(&b'{') {
        return Err("account file is unencrypted — please run 'auth login' again".into());
    }
    if blob.first() != Some(&FORMAT_V3) {
        return Err("account file format is unsupported — please run 'auth login' again".into());
    }
    let mut pos = 1;
    if blob.len() < pos + 4 + SALT_LEN + IV_LEN + TAG_LEN {
        return Err("account file is too short or corrupted".into());
    }
    let salt_len = u32::from_be_bytes(blob[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if salt_len != SALT_LEN || blob.len() < pos + salt_len + IV_LEN + TAG_LEN {
        return Err("account file is corrupted".into());
    }
    let salt = &blob[pos..pos + salt_len];
    pos += salt_len;
    let iv: [u8; 12] = blob[pos..pos + IV_LEN].try_into().map_err(|_| "bad iv")?;
    pos += IV_LEN;
    let tag: [u8; 16] = blob[pos..pos + TAG_LEN].try_into().map_err(|_| "bad tag")?;
    pos += TAG_LEN;
    let ciphertext = &blob[pos..];
    let key = derive_key(machine, passphrase, salt);
    aes_gcm_decrypt(&key, &iv, ciphertext, &tag)
}

pub fn save(account: &Account, passphrase: &str) -> Result<(), String> {
    let machine = machine_id();
    let blob = encrypt(&account.to_json(), &machine, passphrase)?;
    let path = account_file()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create state dir: {e}"))?;
    }
    std::fs::write(&path, blob).map_err(|e| format!("write account: {e}"))
}

pub fn load(passphrase: &str) -> Result<Account, String> {
    let path = account_file()?;
    let blob = std::fs::read(&path).map_err(|_| "not logged in — run 'auth login'".to_string())?;
    let machine = machine_id();
    let json = decrypt(&blob, &machine, passphrase)?;
    Account::from_json(&json)
}

/// Drop the cookie jar only (a fresh login wants a clean session; stale
/// `hsaccnt`/`mz_at0` cookies from a previous failed attempt make Apple
/// answer 5005 without even prompting for the 2FA code).
pub fn reset_session() -> Result<(), String> {
    let jar = super::http::cookie_jar_path()?;
    let _ = std::fs::remove_file(&jar);
    Ok(())
}

pub fn revoke() -> Result<(), String> {
    let path = account_file()?;
    let _ = std::fs::remove_file(&path);
    // Cookies too: they carry the mz_at0 session.
    let jar = super::http::cookie_jar_path()?;
    let _ = std::fs::remove_file(&jar);
    Ok(())
}

// ── crypto primitives (pure-Rust, no external crates) ─────────────────────

/// AES-256-GCM encrypt, returning `(ciphertext, tag)` with empty plaintext
/// AAD. GHASH and AES-CTR implemented over the AES-NI-free path; the
/// Store lane is not performance-critical (one blob per login).
fn aes_gcm_encrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), String> {
    let rounds = aes_key_schedule(key);
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(iv);
    counter[12..].copy_from_slice(&1u32.to_be_bytes()); // J0

    // E_K(J0) for the tag.
    let tag_base = aes_encrypt_block(&rounds, &counter);

    // CTR keystream from J0+1 (GCM encrypts data starting at counter 2
    // when the IV is 96 bits: J0 = IV||1, first data block = J0+1).
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut ctr = counter;
    let mut block_idx = 2u32;
    for chunk in plaintext.chunks(16) {
        ctr[12..].copy_from_slice(&block_idx.to_be_bytes());
        let stream = aes_encrypt_block(&rounds, &ctr);
        for (i, b) in chunk.iter().enumerate() {
            ciphertext.push(b ^ stream[i]);
        }
        block_idx = block_idx.wrapping_add(1);
    }

    let tag = ghash_tag(&rounds, &tag_base, &ciphertext, &[]);
    Ok((ciphertext, tag))
}

fn aes_gcm_decrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<String, String> {
    let rounds = aes_key_schedule(key);
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(iv);
    counter[12..].copy_from_slice(&1u32.to_be_bytes());
    let tag_base = aes_encrypt_block(&rounds, &counter);

    let expected = ghash_tag(&rounds, &tag_base, ciphertext, &[]);
    // Constant-time-ish compare (both are public-length).
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected[i] ^ tag[i];
    }
    if diff != 0 {
        return Err("account file: wrong passphrase or corrupted (GCM tag mismatch)".into());
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut ctr = counter;
    let mut block_idx = 2u32;
    for chunk in ciphertext.chunks(16) {
        ctr[12..].copy_from_slice(&block_idx.to_be_bytes());
        let stream = aes_encrypt_block(&rounds, &ctr);
        for (i, b) in chunk.iter().enumerate() {
            plaintext.push(b ^ stream[i]);
        }
        block_idx = block_idx.wrapping_add(1);
    }
    String::from_utf8(plaintext).map_err(|e| format!("account JSON utf8: {e}"))
}

/// GHASH over (AAD, ciphertext) then XOR with E_K(J0). GF(2^128) with the
/// GCM reduction polynomial, bits reflected (the standard formulation).
fn ghash_tag(
    rounds: &[[u8; 16]; 15],
    tag_base: &[u8; 16],
    ciphertext: &[u8],
    aad: &[u8],
) -> [u8; 16] {
    let h = aes_encrypt_block(rounds, &[0u8; 16]);
    let mut x = [0u8; 16];
    let mut absorb = |data: &[u8]| {
        let mut offset = 0;
        while offset < data.len() {
            let mut block = [0u8; 16];
            let take = (data.len() - offset).min(16);
            block[..take].copy_from_slice(&data[offset..offset + take]);
            for i in 0..16 {
                x[i] ^= block[i];
            }
            x = gf_mul(x, h);
            offset += 16;
        }
    };
    absorb(aad);
    absorb(ciphertext);
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    for i in 0..16 {
        x[i] ^= len_block[i];
    }
    x = gf_mul(x, h);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = x[i] ^ tag_base[i];
    }
    tag
}

/// GF(2^128) multiply per GCM (SS = 0xE1000... reflected bits: MSB-first
/// algorithm from NIST SP 800-38D).
fn gf_mul(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = y;
    for i in 0..128 {
        let bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        if bit == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        let lsb = v[15] & 1;
        // right shift v by 1
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;
        if lsb == 1 {
            v[0] ^= 0xE1;
        }
    }
    z
}

// ── AES-256 block cipher (encrypt-only is all GCM needs) ──────────────────

fn aes_key_schedule(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut words = [0u32; 60];
    for (i, w) in words.iter_mut().take(8).enumerate() {
        *w = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    let rcon: [u32; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
    for i in 8..60 {
        let mut temp = words[i - 1];
        if i % 8 == 0 {
            temp = temp.rotate_left(8);
            temp = sub_word(temp);
            temp ^= rcon[i / 8 - 1] << 24;
        } else if i % 8 == 4 {
            temp = sub_word(temp);
        }
        words[i] = words[i - 8] ^ temp;
    }
    let mut rounds = [[0u8; 16]; 15];
    for (r, rk) in rounds.iter_mut().enumerate() {
        for c in 0..4 {
            let w = words[4 * r + c];
            rk[4 * c..4 * c + 4].copy_from_slice(&w.to_be_bytes());
        }
    }
    rounds
}

/// SubWord for the key schedule: apply the S-box to each of the four bytes.
fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

fn aes_encrypt_block(rounds: &[[u8; 16]; 15], block: &[u8; 16]) -> [u8; 16] {
    let mut state = *block;
    xor_round(&mut state, &rounds[0]);
    for rk in rounds.iter().take(14).skip(1) {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        xor_round(&mut state, rk);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    xor_round(&mut state, &rounds[14]);
    state
}

fn xor_round(state: &mut [u8; 16], key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= key[i];
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    // State is column-major: state[4*c + r].
    for r in 1..4 {
        let row: Vec<u8> = (0..4).map(|c| state[4 * c + r]).collect();
        for c in 0..4 {
            state[4 * c + r] = row[(c + r) % 4];
        }
    }
}

fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let col = [
            state[4 * c],
            state[4 * c + 1],
            state[4 * c + 2],
            state[4 * c + 3],
        ];
        state[4 * c] = gf2_mul(2, col[0]) ^ gf2_mul(3, col[1]) ^ col[2] ^ col[3];
        state[4 * c + 1] = col[0] ^ gf2_mul(2, col[1]) ^ gf2_mul(3, col[2]) ^ col[3];
        state[4 * c + 2] = col[0] ^ col[1] ^ gf2_mul(2, col[2]) ^ gf2_mul(3, col[3]);
        state[4 * c + 3] = gf2_mul(3, col[0]) ^ col[1] ^ col[2] ^ gf2_mul(2, col[3]);
    }
}

fn gf2_mul(m: u8, v: u8) -> u8 {
    let mut m = m;
    let mut v = v;
    let mut out = 0u8;
    while m != 0 {
        if m & 1 != 0 {
            out ^= v;
        }
        let hi = v & 0x80;
        v <<= 1;
        if hi != 0 {
            v ^= 0x1B;
        }
        m >>= 1;
    }
    out
}

/// S-box generated at compile time? No — static table, standard Rijndael.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// ── randomness ────────────────────────────────────────────────────────────

/// Fill from the OS CSPRNG (getrandom via /dev/urandom).
fn fill_random(buf: &mut [u8]) {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(buf);
    }
}

// ── PBKDF2-HMAC-SHA256 ────────────────────────────────────────────────────

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8; 32]) {
    let mut mac = HmacSha256::new(password);
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u = mac.finalize();
    let mut t = u;
    for _ in 1..rounds {
        let mut mac = HmacSha256::new(password);
        mac.update(&u);
        u = mac.finalize();
        for i in 0..32 {
            t[i] ^= u[i];
        }
    }
    *out = t;
}

/// Minimal HMAC-SHA256.
struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    fn new(key: &[u8]) -> HmacSha256 {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        let mut outer = Sha256::new();
        outer.update(&opad);
        HmacSha256 { inner, outer }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(mut self) -> [u8; 32] {
        let inner_digest = self.inner.finalize();
        self.outer.update(&inner_digest);
        self.outer.finalize()
    }
}

/// SHA-256 (same core as the fetcher's; duplicated here to keep the store
/// module self-contained — the fetcher's is private).
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize()
    }

    pub fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        let mut offset = 0;
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            offset = take;
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            self.compress(&block);
            offset += 64;
        }
        if offset < data.len() {
            self.buffer[..data.len() - offset].copy_from_slice(&data[offset..]);
            self.buffered = data.len() - offset;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        // Padding without going through update() (which would corrupt the
        // length counter): append 0x80, zeros to 56 mod 64, then the
        // big-endian bit length. Compress each full block as it fills.
        let bits = self.length * 8;
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            // Zero-fill to the block edge, compress, start a fresh block.
            for b in self.buffer[self.buffered..].iter_mut() {
                *b = 0;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }
        for b in self.buffer[self.buffered..56].iter_mut() {
            *b = 0;
        }
        self.buffer[56..].copy_from_slice(&bits.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let s = &mut self.state;
        s[0] = s[0].wrapping_add(a);
        s[1] = s[1].wrapping_add(b);
        s[2] = s[2].wrapping_add(c);
        s[3] = s[3].wrapping_add(d);
        s[4] = s[4].wrapping_add(e);
        s[5] = s[5].wrapping_add(f);
        s[6] = s[6].wrapping_add(g);
        s[7] = s[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_json_roundtrip() {
        let acc = Account {
            email: "a@b.c".into(),
            name: "Test User".into(),
            directory_services_id: "123".into(),
            password_token: "tok".into(),
            store_front: "143441-1,17".into(),
            pod: "25".into(),
            password: String::new(),
        };
        let json = acc.to_json();
        let back = Account::from_json(&json).unwrap();
        assert_eq!(back.email, "a@b.c");
        assert_eq!(back.store_front, "143441-1,17");
        assert_eq!(back.pod, "25");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let machine = "020000000001";
        let pt = "{\"email\":\"a@b.c\"}";
        let blob = encrypt(pt, machine, "pass").unwrap();
        assert_eq!(blob[0], 0x03);
        let back = decrypt(&blob, machine, "pass").unwrap();
        assert_eq!(back, pt);
        assert!(decrypt(&blob, machine, "wrong").is_err());
        assert!(decrypt(&blob, "othermachine", "pass").is_err());
    }

    #[test]
    fn sha256_vectors() {
        let h = Sha256::digest(b"");
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let h = Sha256::digest(b"abc");
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_rfc4231() {
        // RFC 4231 test case 2 (HMAC-SHA256).
        let mut mac = HmacSha256::new(b"Jefe");
        mac.update(b"what do ya know for sure?");
        let out = mac.finalize();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "3f56014b6e18a15b7bc1b6af490dcb12b953915427618b6635e5a88560364d29"
        );
    }

    #[test]
    fn pbkdf2_rfc_vectors() {
        let mut key = [0u8; 32];
        pbkdf2_hmac_sha256(b"password", b"salt", 1, &mut key);
        assert_eq!(
            hex(&key),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        pbkdf2_hmac_sha256(b"password", b"salt", 2, &mut key);
        assert_eq!(
            hex(&key),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
        pbkdf2_hmac_sha256(b"password", b"salt", 4096, &mut key);
        assert_eq!(
            hex(&key),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    #[test]
    fn sha256_block_boundaries() {
        // Block-edge lengths exercise the buffered path and the two-block
        // finalization in finalize().
        let cases: [(usize, u8, &str); 6] = [
            (
                200,
                b'a',
                "c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5",
            ),
            (
                63,
                b'x',
                "75220b47218278e656f2013bb8f0c455a25eaf01e86c64924e9d48d89776d6f2",
            ),
            (
                64,
                b'x',
                "7ce100971f64e7001e8fe5a51973ecdfe1ced42befe7ee8d5fd6219506b5393c",
            ),
            (
                65,
                b'x',
                "9537c5fdf120482f7d58d25e9ed583f52c02b4e304ea814db1633ad565aed7e9",
            ),
            (
                119,
                b'q',
                "c8bc8a6e9626586bb888ad131d44ed2bd37fc608e902904ade3c566c4208e6ca",
            ),
            (
                120,
                b'q',
                "77a2d49d72a11e41678c51f8f0cb67f5cb570f30370c3aeffe266a0d1ee43209",
            ),
        ];
        let cases = &cases[..6];
        for (len, byte, expect) in cases {
            let data = vec![*byte; *len];
            let h = Sha256::digest(&data);
            assert_eq!(hex(&h), *expect, "length {len}");
        }
    }

    fn hex(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn gcm_nist_case4_with_data() {
        // NIST GCM test case 4 (AES-256, 60-byte plaintext, empty AAD).
        let key: [u8; 32] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08,
        ];
        let iv: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let pt: &[u8] = &[
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let (ct, tag) = aes_gcm_encrypt(&key, &iv, pt).unwrap();
        assert_eq!(
            hex(&ct),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        );
        assert_eq!(hex(&tag), "eb9f796c8d356fc31a8433884b696f4f");
        // Decrypt returns a String (the store payload is JSON); for the
        // binary NIST vector the tamper check below proves the full GCM
        // path end to end instead.
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(aes_gcm_decrypt(&key, &iv, &ct, &bad).is_err());
    }

    #[test]
    fn gcm_partial_block() {
        // 13-byte plaintext: exercises the incomplete-final-chunk XOR path.
        let key: [u8; 32] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08,
        ];
        let iv: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let pt: &[u8] = &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
        ];
        let (ct, tag) = aes_gcm_encrypt(&key, &iv, pt).unwrap();
        assert_eq!(hex(&ct), "e0dd4d374f92e474b81b4077f6");
        assert_eq!(hex(&tag), "27d409a1ea5c0a1488fa97f289cf80d3");
        // Round-trip through the String-returning decrypt only when the
        // plaintext is valid UTF-8; this NIST vector is not, so the tag
        // check above plus the tamper test in case 4 carry the proof.
    }

    #[test]
    fn aes_block_fips197() {
        // FIPS-197 C.3: AES-256 single block.
        let key: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let rounds = aes_key_schedule(&key);
        let ct = aes_encrypt_block(&rounds, &pt);
        assert_eq!(hex(&ct), "8ea2b7ca516745bfeafc49904b496089");
    }

    #[test]
    fn account_roundtrip_unicode_and_json_edge() {
        let acc = Account {
            email: "üser@пример.рф".into(),
            name: "Ω Test 😀".into(),
            directory_services_id: "1234567890".into(),
            password_token: "tok\"to\"quote".into(),
            store_front: "143469-17,29".into(),
            pod: "25".into(),
            password: String::new(),
        };
        let json = acc.to_json();
        let back = Account::from_json(&json).unwrap();
        assert_eq!(back.email, acc.email);
        assert_eq!(back.name, acc.name);
        assert_eq!(back.password_token, acc.password_token);
        assert_eq!(back.store_front, acc.store_front);
        // from_json rejects garbage.
        assert!(Account::from_json("not json").is_err());
    }

    #[test]
    fn gcm_nist_vector() {
        // NIST GCM test case 3 (AES-256): zero key, zero IV, empty PT.
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let (ct, tag) = aes_gcm_encrypt(&key, &iv, b"").unwrap();
        assert!(ct.is_empty());
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "530f8afbc74536b9a963b4f1c4cb738b");
        // Round-trip with AAD-free decrypt path.
        let pt = aes_gcm_decrypt(&key, &iv, &ct, &tag).unwrap();
        assert_eq!(pt, "");
    }
}
