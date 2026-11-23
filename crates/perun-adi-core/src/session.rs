// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Entropy-side primitives of the Android `ProvisioningStart` KDF.
//!
//! This module owns only the independently measured ChaCha/`arc4random` and
//! four-word MT key construction boundaries. It is **not** a complete
//! `session16` generator: MT initialization, twisting, and the final byte loop
//! live on separate tracks. No Apple image, Bionic state, capture or native
//! subprocess is used.

/// Bytes in the native `getentropy` draw.
pub const ENTROPY_LEN: usize = 40;

/// `arc4random` exposes at most 984 bytes after reinitialization.
pub const ARC4_WORDS_MAX: usize = (16 * 64 - 40) / 4;

/// Errors in the measured `arc4random` boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arc4Error {
    /// The caller requested more words than the first reinitialized buffer has.
    TooManyWords { count: usize },
}

impl std::fmt::Display for Arc4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyWords { count } => {
                write!(
                    f,
                    "requested {count} arc4random words, maximum {ARC4_WORDS_MAX}"
                )
            }
        }
    }
}

impl std::error::Error for Arc4Error {}

/// The measured initializer seed and the four-word MT key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MtSeedKey {
    /// Seed for the native initial recurrence.
    pub seed: u32,
    /// Key in native `[out4, out2, out3, out1]` order.
    pub key: [u32; 4],
}

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// Exact ChaCha20 block function (RFC 8439). An 8-byte `nonce` uses the
/// native `arc4random` layout (64-bit IV plus a 64-bit counter); a 12-byte
/// `nonce` uses the RFC 96-bit nonce layout.
pub fn chacha20_block(key: &[u8; 32], nonce: &[u8], counter: u64) -> [u8; 64] {
    let mut initial = [0u32; 16];
    for (i, chunk) in b"expand 32-byte k".as_chunks::<4>().0.iter().enumerate() {
        initial[i] = u32::from_le_bytes(*chunk);
    }
    for (i, chunk) in key.as_chunks::<4>().0.iter().enumerate() {
        initial[4 + i] = u32::from_le_bytes(*chunk);
    }
    initial[12] = counter as u32;
    match nonce.len() {
        8 => {
            initial[13] = (counter >> 32) as u32;
            for (i, chunk) in nonce.as_chunks::<4>().0.iter().enumerate() {
                initial[14 + i] = u32::from_le_bytes(*chunk);
            }
        }
        12 => {
            for (i, chunk) in nonce.as_chunks::<4>().0.iter().enumerate() {
                initial[13 + i] = u32::from_le_bytes(*chunk);
            }
        }
        _ => panic!("nonce must be 8 or 12 bytes"),
    }

    let mut state = initial;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for (i, (value, original)) in state.iter().zip(initial).enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&value.wrapping_add(original).to_le_bytes());
    }
    out
}

/// Return the first `count` little-endian `u32` outputs of Bionic
/// `arc4random`, starting at offset 40 of its first reinitialized buffer.
///
/// `count` must not exceed [`ARC4_WORDS_MAX`]. This is the exact
/// `getentropy -> ChaCha20 -> rekey -> output` path measured on Android, not a
/// platform random-number API.
pub fn arc4random_words(draw: &[u8; ENTROPY_LEN], count: usize) -> Result<Vec<u32>, Arc4Error> {
    if count > ARC4_WORDS_MAX {
        return Err(Arc4Error::TooManyWords { count });
    }
    let mut out = Vec::with_capacity(count);
    let mut counter = 0u64;
    while out.len() < count {
        let block = chacha20_block(
            &draw[..32].try_into().expect("32-byte key"),
            &draw[32..],
            counter,
        );
        let offset = if counter == 0 { 40 } else { 0 };
        for word in block[offset..].as_chunks::<4>().0.iter() {
            if out.len() == count {
                break;
            }
            out.push(u32::from_le_bytes(*word));
        }
        counter += 1;
    }
    Ok(out)
}

#[inline]
fn seed_mask(value: u32) -> u32 {
    value
        .wrapping_sub(value.wrapping_mul(2) & 0x79cdc552)
        .wrapping_add(0x3ce6e2a9)
}

#[inline]
fn key_mask(value: u32) -> u32 {
    value
        .wrapping_sub(value.wrapping_mul(2) & 0xc34d0ed8)
        .wrapping_add(0x61a6876c)
}

/// Construct the measured MT seed and key from the 40-byte entropy draw.
///
/// The native order is `out0` for the seed and `[out4, out2, out3, out1]` for
/// the key. The output positions and both masks are validated against native
/// sequential and `0xA5` captures.
pub fn mt_seed_and_key(draw: &[u8; ENTROPY_LEN]) -> MtSeedKey {
    let words = arc4random_words(draw, 5).expect("five arc4random words");
    MtSeedKey {
        seed: seed_mask(words[0]),
        key: [
            key_mask(words[4]),
            key_mask(words[2]),
            key_mask(words[3]),
            key_mask(words[1]),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(text: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, chunk) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let digit = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("invalid hex"),
            };
            out[i] = (digit(chunk[0]) << 4) | digit(chunk[1]);
        }
        out
    }

    fn words_bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn chacha_matches_rfc8439_block_vector() {
        let key = core::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let block = chacha20_block(&key, &nonce, 1);
        let expected = concat!(
            "10f1e7e4d13b5915500fdd1fa32071c4",
            "c7d1f4c733c068030422aa9ac3d46c4e",
            "d2826446079faa0914c2d705d98b02a2",
            "b5129cd1de164eb9cbd083e8a2503c4e"
        );
        let mut expected_bytes = [0u8; 64];
        for (i, chunk) in expected.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let digit = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("invalid hex"),
            };
            expected_bytes[i] = (digit(chunk[0]) << 4) | digit(chunk[1]);
        }
        assert_eq!(block, expected_bytes);
    }

    #[test]
    fn arc4_and_mt_key_match_native_hash_only_vectors() {
        let cases = [
            (
                bytes::Bytes40::Sequential,
                "dd3006f2819b7aeb3b8744314f8a618143c1918d29c22ad3c9382f0f34d611ae",
                "6e222e156e7762ff9475d9ba1c456e8370e9abb5549d71123bd45532ac50779e",
                "bd70aade2fe467f0fdbada1a77cda01c0343334e0e8a8feb83f7275567289bc7",
            ),
            (
                bytes::Bytes40::A5,
                "f77232e930d0ff7163bde5a36c6a45ffac7d3b942d01d68a50b9c338ed355f72",
                "6898e70b508220afd31ec9450a48c233e25ae24b4b3dabd75df340e2c222d603",
                "da6a0669c156097ee14ef6c07281d1620a86ec40966baa76339d6bc798baab3e",
            ),
        ];
        for (kind, outputs_hash, seed_key_hash, stream_hash) in cases {
            let draw = match kind {
                bytes::Bytes40::Sequential => core::array::from_fn(|i| i as u8),
                bytes::Bytes40::A5 => [0xA5; ENTROPY_LEN],
            };
            let words = arc4random_words(&draw, 5).expect("five words");
            assert_eq!(
                crate::sha256::digest(&words_bytes(&words)),
                hex32(outputs_hash)
            );
            let MtSeedKey { seed, key } = mt_seed_and_key(&draw);
            let mut seed_key = seed.to_le_bytes().to_vec();
            seed_key.extend(words_bytes(&key));
            assert_eq!(crate::sha256::digest(&seed_key), hex32(seed_key_hash));
            let stream = arc4random_words(&draw, ARC4_WORDS_MAX).expect("complete buffer");
            assert_eq!(stream.len(), ARC4_WORDS_MAX);
            assert_eq!(
                crate::sha256::digest(&words_bytes(&stream)),
                hex32(stream_hash)
            );
        }
    }

    #[test]
    fn arc4_rejects_words_beyond_the_first_buffer() {
        assert!(matches!(
            arc4random_words(&[0u8; ENTROPY_LEN], ARC4_WORDS_MAX + 1),
            Err(Arc4Error::TooManyWords { .. })
        ));
        assert_eq!(arc4random_words(&[0u8; ENTROPY_LEN], 0).unwrap().len(), 0);
    }

    mod bytes {
        pub enum Bytes40 {
            Sequential,
            A5,
        }
    }
}
