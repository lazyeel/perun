// Anatomy driver: parse a CPIM blob through the crate's own
// CpimLayout and print the measured fields, with the body-A /
// digest split the campaign needs. Usage:
//   cargo run -p perun-adi-core --example cpim_anatomy -- <blob.bin>
use perun_adi_core::cpim::CpimLayout;

fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: cpim_anatomy <blob.bin>");
    let blob = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    println!("blob: {path} ({} bytes)", blob.len());
    let c = CpimLayout::parse(&blob).unwrap_or_else(|e| panic!("parse: {e}"));
    println!("version        : {}", c.version);
    println!("session (16B)  : {}", c.session.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("body_a  ({}B)  : {}", c.body_a.len(), c.body_a.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("digest  ({}B)  : {}", c.body_a_digest.len(), c.body_a_digest.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("body_b  ({}B)  : {}", c.body_b.len(), c.body_b.iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("body_b_version : {:#x}", c.body_b_version);
    // round-trip proof through the crate itself
    let rt = c.to_bytes();
    assert_eq!(rt, blob, "round-trip mismatch");
    println!("round-trip     : byte-exact through CpimLayout::to_bytes");
    // entropy windows
    println!("entropy body_a : {:.4} bits/byte (max 8.0)", shannon(&c.body_a));
    println!("entropy digest : {:.4} bits/byte", shannon(&c.body_a_digest));
    println!("entropy body_b : {:.4} bits/byte", shannon(&c.body_b));
    println!("entropy spim?? : (see the python side for the input file)");
    // byte-class census of body A: any structure at all?
    let zero = c.body_a.iter().filter(|&&b| b == 0).count();
    let ff = c.body_a.iter().filter(|&&b| b == 0xff).count();
    let ascii = c.body_a.iter().filter(|&&b| (0x20..0x7f).contains(&b)).count();
    println!("body_a census  : zeros={zero} 0xff={ff} ascii={ascii}");
    // leading-byte crypto markers
    println!("body_a[0..8]   : {}", c.body_a.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>());
    println!("digest[0..8]   : {}", c.body_a_digest.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>());
}
