//! Golden-output test: a fixed, generated input must compress to exactly the same bytes on
//! every platform. This is what backs the promise that an archive made on one architecture
//! (x86, x64, arm, arm64; Linux, Windows, macOS, Android) decompresses on any other. CI runs it
//! on all of them. If you change the model on purpose, run
//! `cargo test --test golden -- --nocapture` and update the hashes.

use dlbcore::{compress_payload, crypto, decompress_payload, Options};

fn corpus() -> Vec<u8> {
    let words = [
        "alpha", "beta", "gamma", "delta", "context", "mixing", "archive", "stream", "table",
        "value", "block", "thread", "model", "update", "result", "index",
    ];
    let mut x = 0x1234_5678u32;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    let mut v = Vec::new();
    // text
    while v.len() < 60_000 {
        let r = next();
        v.extend_from_slice(words[(r >> 8) as usize % words.len()].as_bytes());
        v.push(if r % 9 == 0 { b'\n' } else { b' ' });
    }
    // fixed-size records with a counter and noise
    for i in 0..4000u32 {
        v.extend_from_slice(&i.to_le_bytes());
        v.extend_from_slice(&(i.wrapping_mul(2654435761) >> 20).to_le_bytes());
        v.push((next() >> 24) as u8);
        v.extend_from_slice(&[0xE8, (i & 0xFF) as u8, 0, 0, 0]);
    }
    // incompressible tail
    for _ in 0..8000 {
        v.push((next() >> 16) as u8);
    }
    v
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// (level, expected size, expected SHA-256 of the whole .dlb output)
const GOLDEN: &[(u32, usize, &str)] = &[
    (1, 32829, "987af58cfc7cf24a497336054997969246293967e1b1dcaa5434a5f11ef064ad"),
    (5, 30235, "67467290e665bed3fa8b32b03b902ed91f9ada64c445e21788b0c4e39970a85f"),
    (10, 29112, "50749c969482b0ce271f78353a6ffc42bba070799fc05a25659d9b8b930dadab"),
];

#[test]
fn output_is_identical_on_every_platform() {
    let data = corpus();
    let mut bad = Vec::new();
    for &(level, size, hash) in GOLDEN {
        let blob = compress_payload(&data, &[], &Options::new(level), &mut |_| true).unwrap();
        let h = hex(&crypto::sha256(&blob));
        println!("    ({}, {}, \"{}\"),", level, blob.len(), h);
        assert_eq!(decompress_payload(&blob, 1, &mut |_| true).unwrap(), data);
        if blob.len() != size || h != hash {
            bad.push(level);
        }
    }
    assert!(bad.is_empty(), "bitstream changed at levels {:?}", bad);
}
