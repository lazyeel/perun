// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Windows machine identity after Blackwood-4NT: seven MD5 hashes over host
//! properties, truncated to 32 bits each. Pure functions plus best-effort
//! Linux collectors with documented fallbacks. MD5 below is a clean-room
//! RFC 1321 implementation (no copied code); the test vectors pin it.

/// Raw host properties feeding the fingerprint. Byte-exact encodings matter:
/// `*_ascii` are raw bytes, `*_wide` are UTF-16LE bytes, `vol4` is exactly
/// the first 4 bytes of the UTF-16LE volume serial.
pub struct MachineInputs {
    pub mac: Vec<u8>,
    pub vol4: Vec<u8>,
    pub product_id_ascii: Vec<u8>,
    pub cpu_ascii: Vec<u8>,
    pub bios_ascii: Vec<u8>,
    pub machine_wide: Vec<u8>,
    pub hwguid_wide: Vec<u8>,
}

/// Best-effort Linux collectors. No Windows hive here, so the registry-backed
/// fields fall back in documented order: ProductId <- `/etc/machine-id`,
/// BIOS <- DMI `bios_version` <- kernel release, machine name <- gethostname
/// via `/proc/sys/kernel/hostname`. Absent sysfs entries yield empty vecs
/// (upstream hashes zeros in the same situation under WOW64).
pub fn collect_linux() -> MachineInputs {
    MachineInputs {
        mac: first_mac(),
        vol4: vec![0; 4],
        product_id_ascii: std::fs::read("/etc/machine-id")
            .map(|b| trim_nl(b))
            .unwrap_or_default(),
        cpu_ascii: cpu_model(),
        bios_ascii: std::fs::read("/sys/class/dmi/id/bios_version")
            .map(|b| trim_nl(b))
            .unwrap_or_else(|_| {
                std::fs::read("/proc/sys/kernel/osrelease")
                    .map(|b| trim_nl(b))
                    .unwrap_or_default()
            }),
        machine_wide: wide(&hostname()),
        hwguid_wide: vec![],
    }
}

/// Modern `X-Mme-Device-Id`: `EEEEEEEE.VVVVVVVV....` (upper hex, dot-joined).
pub fn modern_id(m: &MachineInputs) -> String {
    [
        h32(&m.mac, true),
        h32(&m.vol4, true),
        h32(&m.product_id_ascii, true),
        h32(&m.cpu_ascii, true),
        h32(&m.bios_ascii, true),
        h32(&m.machine_wide, true),
        h32(&m.hwguid_wide, true),
    ]
    .join(".")
}

/// Legacy variant: `md5(mac)+md5(vol)+md5(biosW)+md5(cpuW)+md5(productW)`,
/// lower hex, concatenated. The `cache-control`/`Ethernet` pre-hashes from
/// the recipe only document the salt context, never the output.
pub fn legacy_id(m: &MachineInputs) -> String {
    [
        h32(&m.mac, false),
        h32(&m.vol4, false),
        h32(&wide_from_ascii(&m.bios_ascii), false),
        h32(&wide_from_ascii(&m.cpu_ascii), false),
        h32(&wide_from_ascii(&m.product_id_ascii), false),
    ]
    .concat()
}

fn h32(data: &[u8], upper: bool) -> String {
    // First 32 bits as hex: big-endian reading of the digest head, matching
    // the reference `hexdigest()[:8]` construction the pins were computed with.
    let d = md5(data);
    let v = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    if upper {
        format!("{v:08X}")
    } else {
        format!("{v:08x}")
    }
}

fn wide(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn wide_from_ascii(b: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(b)
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

fn trim_nl(mut b: Vec<u8>) -> Vec<u8> {
    while b.last().is_some_and(|&c| c == b'\n' || c == b'\r') {
        b.pop();
    }
    b
}

fn first_mac() -> Vec<u8> {
    let nets = std::fs::read_dir("/sys/class/net").ok();
    let mut fallback = vec![];
    for entry in nets.into_iter().flatten().flatten() {
        let mut p = entry.path();
        p.push("address");
        let raw = std::fs::read_to_string(&p).unwrap_or_default();
        let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() < 12 {
            continue;
        }
        let mut mac = vec![];
        for i in (0..12).step_by(2) {
            mac.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0));
        }
        if mac.iter().all(|&b| b == 0) {
            if fallback.is_empty() {
                fallback = mac;
            }
            continue;
        }
        return mac;
    }
    fallback
}

fn cpu_model() -> Vec<u8> {
    std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find_map(|l| {
            l.strip_prefix("model name")
                .and_then(|r| r.split_once(':').map(|(_, v)| v.trim().as_bytes().to_vec()))
        })
        .unwrap_or_default()
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

// ---- Clean-room MD5 (RFC 1321) ----

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

fn md5(msg: &[u8]) -> [u8; 16] {
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_le_bytes());
    for chunk in data.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..16 => ((b & c) | ((!b) & d), i),
                16..32 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..48 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g])).rotate_left(S[i]),
            );
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, w) in [a0, b0, c0, d0].iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> MachineInputs {
        MachineInputs {
            mac: vec![0x8e, 0x76, 0xa0, 0x3f, 0x85, 0x0a],
            vol4: vec![0x41, 0x00, 0x42, 0x00],
            product_id_ascii: b"TEST-PRODUCT-ID".to_vec(),
            cpu_ascii: b"AMD EPYC 7742".to_vec(),
            bios_ascii: b"rel-1.17.0".to_vec(),
            machine_wide: "TESTHOST"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect(),
            hwguid_wide: "{12345678-1234-1234-1234-123456789ABC}"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect(),
        }
    }

    #[test]
    fn md5_rfc_vectors() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
    }

    #[test]
    fn modern_pinned_vector() {
        assert_eq!(
            modern_id(&fixture()),
            "7221801F.8027CA4E.2697BBD5.35F7A7CC.5A639844.51646F60.65C519AA"
        );
    }

    #[test]
    fn legacy_pinned_vector() {
        assert_eq!(
            legacy_id(&fixture()),
            "7221801f8027ca4e361304a9618395e8ea69a6c7"
        );
    }

    #[test]
    fn shapes_hold() {
        let m = modern_id(&fixture());
        let parts: Vec<&str> = m.split('.').collect();
        assert_eq!(parts.len(), 7);
        assert!(parts.iter().all(|p| {
            p.len() == 8
                && p.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
        }));
        assert_eq!(legacy_id(&fixture()).len(), 40);
    }

    #[test]
    fn collect_linux_smoke() {
        let m = collect_linux();
        assert_eq!(m.mac.len(), 6);
        assert!(!m.cpu_ascii.is_empty());
        assert!(!modern_id(&m).is_empty());
    }
}
