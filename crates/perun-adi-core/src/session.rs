// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Independent Android `ProvisioningStart` entropy and `session16` KDF.
//!
//! The measured ChaCha/`arc4random`, MT initialization, two twist families,
//! tempering and nonzero-byte output loop are implemented with plain Rust
//! arithmetic. No Apple image, Bionic state, capture or native subprocess is
//! used by this module.

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

const MT_WORDS: usize = 624;
const K: u32 = 0x3ce6e2a9;

fn init_genrand(seed: u32) -> [u32; MT_WORDS] {
    let mut mt = [0u32; MT_WORDS];
    mt[0] = seed;
    for i in 1..MT_WORDS {
        let previous = mt[i - 1];
        let rax = 0x6d3532u32.wrapping_add(i as u32 - 1);
        let mixed = ((previous >> 30)
            .wrapping_sub((previous >> 29) & 2)
            .wrapping_add(K))
            ^ previous;
        let product = 1812433253u32.wrapping_mul(mixed);
        let a = rax.wrapping_add(product);
        let b = a.wrapping_add(0xff92cacf);
        let d = a.wrapping_mul(2).wrapping_add(0xff25959e) & 0x79cdc552;
        mt[i] = b.wrapping_sub(d).wrapping_add(K);
    }
    mt
}

fn init_mt(MtSeedKey { seed, key }: MtSeedKey) -> [u32; MT_WORDS] {
    let mut mt = init_genrand(seed);
    let mut buffer = key;
    let mut i = 1usize;
    for k in 0..MT_WORDS {
        let previous = mt[i - 1];
        let j = k % 4;
        let x = ((previous >> 30)
            .wrapping_sub((previous >> 29) & 2)
            .wrapping_add(K))
            ^ previous;
        let mut c = 1664525u32.wrapping_mul(x);
        let d = 0x32cc1au32.wrapping_mul(x) & 0x79cdc552;
        c = c.wrapping_sub(d).wrapping_add(K) ^ mt[i];
        let rax = 0x12bd5cddu32.wrapping_add(j as u32);
        let s = 0x61a6876c ^ buffer[j];
        let y = s.wrapping_add(rax).wrapping_add(0xed42a323).wrapping_add(c);
        let c2 = y.wrapping_mul(2) & 0x79cdc552;
        mt[i] = y.wrapping_sub(c2).wrapping_add(K);
        buffer[(k + 1) % 4] ^= if (k + 1) % 4 == 0 {
            0xf7803080
        } else {
            0xf7803081
        };
        i += 1;
        if i >= MT_WORDS {
            mt[0] = mt[MT_WORDS - 1];
            i = 1;
        }
    }
    for _ in 0..MT_WORDS - 1 {
        let previous = mt[i - 1];
        let x = ((previous >> 30)
            .wrapping_sub((previous >> 29) & 2)
            .wrapping_add(K))
            ^ previous;
        let mut c = 1566083941u32.wrapping_mul(x);
        let d = 0xbab116cau32.wrapping_mul(x) & 0x79cdc552;
        c = c.wrapping_sub(d).wrapping_add(K) ^ mt[i];
        c = c.wrapping_sub(i as u32);
        let d2 = c.wrapping_mul(2) & 0x79cdc552;
        mt[i] = c.wrapping_sub(d2).wrapping_add(K);
        i += 1;
        if i >= MT_WORDS {
            mt[0] = mt[MT_WORDS - 1];
            i = 1;
        }
    }
    mt[0] = 0xbce6e2a9;
    mt
}

fn hidden_twist(mt: &mut [u32; MT_WORDS]) {
    for i in 0..MT_WORDS {
        let next = mt[(i + 1) % MT_WORDS];
        let y = (mt[i] & 0x80000000) | (next & 0x7ffffffe);
        let a = (y >> 1) ^ 0x1e737154;
        let a = a
            .wrapping_sub(a.wrapping_mul(2) & 0x79cdc552)
            .wrapping_add(K);
        let matrix = if (!next) & 1 == 0 {
            0x5bb8223a
        } else {
            0xc2b092e5
        };
        mt[i] = mt[(i + 397) % MT_WORDS] ^ matrix ^ a ^ 0x675ec093;
    }
}

fn a65_twist(mt: &mut [u32; MT_WORDS]) {
    let final_upper = mt[MT_WORDS - 1] & 0x80000000;
    for i in 0..227 {
        let next = mt[i + 1];
        let upper = mt[i] & 0x80000000;
        let mut y = (next & 0x7ffffffe)
            .wrapping_sub(next.wrapping_mul(2) & 0x4e32c364)
            .wrapping_add(0x271961b3);
        y |= upper;
        y ^= 0x1bff831b;
        let mut shifted = (y.wrapping_mul(2) & 0x92be2b44).wrapping_neg();
        shifted = y.wrapping_add(shifted).wrapping_add(0x495f15a3);
        let mut value = mt[i + 397];
        shifted >>= 1;
        value ^= if (!next) & 1 == 0 {
            0x4e79914b
        } else {
            0xd7712194
        };
        mt[i] = value ^ shifted ^ 0x6ad61b9a;
    }
    for i in 227..MT_WORDS - 1 {
        let upper = mt[i] & 0x80000000;
        let next = mt[i + 1];
        let parity = (!next) & 1;
        let left = (next & 0x7ffffffe) ^ 0x83191951;
        let mut y = ((next.wrapping_mul(2) & 0x7ffff7f0) ^ 0x79cdc550)
            .wrapping_add(left)
            .wrapping_add(0x40000407);
        let mut mask = upper.wrapping_mul(0x5c4d6d95) | 0x56fbde02;
        mask = mask.wrapping_mul(0x9e7d75bd).wrapping_add(0x089c2e86);
        y |= mask;
        let correction = (y.wrapping_mul(2) & 0xb85648e6).wrapping_neg();
        y = y.wrapping_add(correction).wrapping_add(0x5c2b2473);
        let mut value = mt[(i + 397) % MT_WORDS];
        value ^= if parity == 0 { 0x4e79914b } else { 0xd7712194 };
        mt[i] = value ^ (y >> 1) ^ 0x606c0372;
    }

    let first = mt[0];
    let mut y = (first & 0x7ffffffe) ^ 0xc81d1176;
    let other = (first.wrapping_mul(2) & 0xe9f7e7bc) ^ 0x69c5c510;
    let mut value = y.wrapping_add(other).wrapping_add(0x0b040c22);
    y = y.wrapping_add(other);
    value |= final_upper;
    let correction = y.wrapping_mul(2).wrapping_add(0x16081844) & 0xdf8dcc44;
    value = value.wrapping_sub(correction).wrapping_add(0x6fc6e622);
    let mut last = mt[396];
    value >>= 1;
    last ^= if (!first) & 1 == 0 {
        0x4e79914b
    } else {
        0xd7712194
    };
    mt[MT_WORDS - 1] = last ^ value ^ 0x799ae25a;
}

fn temper(value: u32) -> u32 {
    let first = (value >> 11) ^ value;
    let shifted = (first << 7) ^ 0x70bf3a80;
    let mut second = shifted & 0x9d2c5680;
    let correction = shifted.wrapping_mul(2) & 0x22502c00;
    second = second.wrapping_sub(correction).wrapping_add(0x13bb3738);
    second ^= first ^ 0x4371b1a1;

    let shifted = (second << 15) ^ 0xfc760000;
    let correction = shifted.wrapping_mul(2) & 0x16010000;
    let reduced = shifted.wrapping_sub(correction);
    let mut third = shifted
        .wrapping_add(correction.wrapping_neg())
        .wrapping_add(0x0b00ca57)
        & 0xefc60000;
    let correction = reduced.wrapping_mul(2).wrapping_add(0x160194ae) & 0x93840000;
    third = third.wrapping_sub(correction).wrapping_add(0xd9ca0bb8) ^ second;
    (third >> 18) ^ third ^ 0xe46af5c7
}

fn next_output(mt: &mut [u32; MT_WORDS], index: &mut usize) -> u32 {
    a65_twist(mt);
    if *index >= MT_WORDS {
        *index = 0;
    }
    let output = temper(mt[*index]) ^ 0x6ae8e6c8;
    *index += 1;
    output
}

fn output_byte(value: u32, shift: u32) -> u8 {
    let shifted = (value ^ 0x3063cfe3) >> shift;
    (shifted
        .wrapping_sub((shifted & 0x56).wrapping_mul(2))
        .wrapping_add(0x56) as u8)
        ^ 0x34
}

/// Generate the sixteen-byte CPIM session field from the controlled 40-byte
/// entropy draw.
///
/// The native producer first advances through a 120-byte nonzero-byte field.
/// That predecessor determines whether the session starts at twist 31, 32 or a
/// rarer later boundary; it is therefore computed here rather than replaced by
/// a per-input constant. During both loops a zero transformed byte is written
/// but does not advance the destination. The session returns immediately after
/// the final nonzero byte at destination zero.
pub fn session16_from_entropy(draw: [u8; ENTROPY_LEN]) -> [u8; 16] {
    let mut mt = init_mt(mt_seed_and_key(&draw));
    for _ in 0..32 {
        hidden_twist(&mut mt);
    }

    let mut index = 32usize;
    let mut remaining = 120usize;
    while remaining != 0 {
        let value = next_output(&mut mt, &mut index);
        for shift in [0, 8, 16, 24] {
            if output_byte(value, shift) != 0 {
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
        }
    }

    let mut out = [0u8; 16];
    let mut position = 15usize;
    loop {
        let value = next_output(&mut mt, &mut index);
        for shift in [0, 8, 16, 24] {
            let byte = output_byte(value, shift);
            out[position] = byte;
            if byte != 0 {
                if position == 0 {
                    return out;
                }
                position -= 1;
            }
        }
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
    fn session16_matches_native_hash_only_vectors() {
        let cases = [
            (
                core::array::from_fn(|i| i as u8),
                "ff8aad4a31ebe681f281cb41312ca2800e9c0bc61f1663d4b353e96d6304634f",
            ),
            (
                core::array::from_fn(|i| 39 - i as u8),
                "f97598545f34acabf5ccf0f3f7be36e3cd445d1fb89c7d0316988764a9560e71",
            ),
            (
                [0x01; ENTROPY_LEN],
                "bbae0c231caba4f8ed8a415b2664428382f2a70de012b18b25d4c6afdb9c5195",
            ),
            (
                [0x11; ENTROPY_LEN],
                "6f9ac132753bb4ce1934195dd71d8901f677d7c56d02891617904177a5239afd",
            ),
            (
                [0x22; ENTROPY_LEN],
                "b874cd15e0ad6059acb9182852b7e89e40c9905b3928afe2bc3006635ec93a30",
            ),
            (
                [0x33; ENTROPY_LEN],
                "96736b81f5407a285885f662fea65ae6f8ea48924cbf2397ed760a39ca6a58a3",
            ),
            (
                [0x44; ENTROPY_LEN],
                "52d6ed32800c0929927c0bdd40fe55f45c07ae9f8615da8619858004f18df5df",
            ),
            (
                [0x55; ENTROPY_LEN],
                "58461bd85e6348c57f19fa7346dadd209bc2f5d75c70b74eee20481276664fee",
            ),
            (
                [0x7f; ENTROPY_LEN],
                "7b62233f96e7a35f4f67dc541cdf905708c8773a1217f72e64d7a85360d9a3ee",
            ),
            (
                [0x80; ENTROPY_LEN],
                "22ef45d673d11ddb67617a974825eb878ffcfefcac9dd51473e2d269caafb771",
            ),
            (
                [0xa5; ENTROPY_LEN],
                "9ffbee092b8bc145c0ed66df390bb14c4d0a281bfb2372032c3a14f147619fca",
            ),
            (
                [0xff; ENTROPY_LEN],
                "8cfbb8f26b4ab381f035ef5d87cc8a44e8e66b4c4c1cb2fc6770f9254a6004f8",
            ),
        ];
        for (draw, expected) in cases {
            let session = session16_from_entropy(draw);
            assert!(session.iter().all(|byte| *byte != 0));
            assert_eq!(crate::sha256::digest(&session), hex32(expected));
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
