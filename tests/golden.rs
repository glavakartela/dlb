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
    (1, 30618, "dcf46b3ef04529e891847c816e8dcf6bada13c1950efaddfb8e3231f8e1bb2f0"),
    (5, 29149, "1d79c184c68023049132f5ee85b5dcde5e7d7398915c524478fcf3daaf2800e1"),
    (10, 28826, "ad115ddeaa5b60a5289f7dbfa2d17c0c1ac77768c2b1dd63c9aba98ed72fe157"),
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

/// Writes the corpus to the file named by DLB_DUMP (used once to build the model-v0 fixture).
#[test]
#[ignore]
fn dump_corpus() {
    if let Ok(p) = std::env::var("DLB_DUMP") {
        std::fs::write(p, corpus()).unwrap();
    }
}

/// Archives written by model v0 (releases up to 0.15) must stay readable forever.
#[test]
fn model_v0_archives_still_decode() {
    let blob = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/model-v0.dlb")).unwrap();
    assert_eq!(blob[4], 0, "fixture must be a model-v0 archive");
    let payload = decompress_payload(&blob, 1, &mut |_| true).unwrap();
    let data = corpus();
    assert!(payload.ends_with(&data), "decoded payload differs from the original file");
}
