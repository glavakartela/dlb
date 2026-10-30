//! Mutation fuzzing of every reader: whatever bytes an archive contains, reading it must end
//! (no hang) without panicking or aborting. Results may be errors, or even a different valid
//! archive; that is fine.
//!
//! `cargo test --release --test fuzz` runs 150 cases (40 on other CPU architectures, where CI may
//! emulate them); for a long run set
//! `DLB_FUZZ_ITERS=50000` (and `DLB_FUZZ_SEED` to vary the sequence).

use dlbcore::stream::{self, CompressJob};
use dlbcore::{archive, crypto, Options};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dlb-fuzz-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

struct Seed {
    name: &'static str,
    /// plain `.dlb` bytes
    bytes: Vec<u8>,
    /// sealed with this password after mutation (cheap PBKDF2 settings keep the test fast)
    password: Option<&'static str>,
}

const SALT: [u8; 16] = [7; 16];
const NONCE: [u8; 12] = [9; 12];

fn seal_cheap(blob: &[u8], pw: &str) -> Vec<u8> {
    crypto::seal_with(blob, pw, 1000, SALT, NONCE)
}

fn corpus(root: &Path) -> Vec<Seed> {
    let src = root.join("src/proj");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::create_dir_all(src.join("empty")).unwrap();
    let text: Vec<u8> = (0..300).flat_map(|i| format!("line {} of text\n", i % 31).into_bytes()).collect();
    fs::write(src.join("a.txt"), &text).unwrap();
    fs::write(src.join("sub/b.txt"), &text[..1200]).unwrap();
    fs::write(src.join("z.bin"), b"").unwrap();
    let mut x = 5u32;
    let noise: Vec<u8> = (0..900)
        .map(|_| {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            (x >> 24) as u8
        })
        .collect();
    fs::write(src.join("n.zip"), &noise).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("a.txt", src.join("ln")).unwrap();

    let mut seeds = Vec::new();
    for (name, block, pw) in [
        ("stream-plain", 1500usize, None),
        ("stream-one-block", 1 << 20, None),
        ("stream-encrypted", 1500, Some("fuzz pw")),
    ] {
        // built without a password here; the harness seals mutated copies itself
        let _ = pw;
        let out = root.join(format!("{}.dlb", name));
        let job = CompressJob {
            inputs: &[src.clone()],
            exclude: &[],
            out: &out,
            level: 1,
            threads: 1,
            block,
            password: None,
        };
        stream::compress_streaming(&job, &mut |_, _| {}, &mut |_, _, _| true).unwrap();
        seeds.push(Seed { name, bytes: fs::read(&out).unwrap(), password: pw });
    }
    // an archive from the in-memory writer, several blocks and a stored tail
    let (payload, boundaries, store_from) = archive::build_payload(&[src]).unwrap();
    let mut o = Options::new(1);
    o.threads = 2;
    o.min_block = 700;
    o.store_from = store_from;
    let blob = dlbcore::compress_payload(&payload, &boundaries, &o, &mut |_| true).unwrap();
    seeds.push(Seed { name: "memory", bytes: blob.clone(), password: None });
    seeds.push(Seed { name: "memory-encrypted", bytes: blob, password: Some("pw2") });
    seeds
}

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut d = base.to_vec();
    let rounds = 1 + rng.below(3);
    for _ in 0..rounds {
        if d.is_empty() {
            d.push(rng.next() as u8);
            continue;
        }
        // bias towards the headers: block table, entry table, envelope
        let pos = if rng.below(2) == 0 { rng.below(d.len().min(160)) } else { rng.below(d.len()) };
        match rng.below(8) {
            0 => d[pos] ^= 1 << rng.below(8),
            1 => d[pos] = rng.next() as u8,
            2 => d[pos] = if rng.below(2) == 0 { 0 } else { 0xFF },
            3 => d.truncate(pos),
            4 => {
                let n = (1 + rng.below(16)).min(d.len() - pos);
                d.drain(pos..pos + n);
            }
            5 => {
                let n = 1 + rng.below(16);
                let at = pos.min(d.len());
                for _ in 0..n {
                    d.insert(at, rng.next() as u8);
                }
            }
            6 => {
                // a 32-bit field set to an extreme value (sizes, counts, lengths)
                let v: u32 = [0, 1, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF, 0xFFFF_0000, 0x0100_0000][rng.below(7)];
                if pos + 4 <= d.len() {
                    d[pos..pos + 4].copy_from_slice(&v.to_le_bytes());
                }
            }
            _ => {
                // a 64-bit field (payload length, entry size, mtime)
                let v: u64 = [0, u64::MAX, 1 << 40, (1 << 40) + 1, 1 << 63, 0xFFFF_FFFF][rng.below(6)];
                if pos + 8 <= d.len() {
                    d[pos..pos + 8].copy_from_slice(&v.to_le_bytes());
                }
            }
        }
    }
    d
}

/// Every way the library reads an archive.
fn exercise(blob: &[u8], pw: Option<&str>, dir: &Path, id: usize) {
    let file = dir.join(format!("case-{}.dlb", id));
    fs::write(&file, blob).unwrap();
    if let Ok(src) = stream::open_source(&file, pw, &mut |_, _| true) {
        let _ = stream::list_source(&*src);
        let _ = stream::extract_archive(&*src, None, false, None, 2, &mut |_, _, _| true);
        let dest = dir.join(format!("out-{}", id));
        let _ = stream::extract_archive(&*src, Some(&dest), true, None, 2, &mut |_, _, _| true);
        let _ = stream::extract_archive(&*src, Some(&dest), true, Some(&[0, 1]), 1, &mut |_, _, _| true);
        let _ = fs::remove_dir_all(&dest);
    }
    let plain = match pw {
        Some(p) => crypto::open(blob, p).ok(),
        None => Some(blob.to_vec()),
    };
    if let Some(b) = plain {
        let _ = dlbcore::inspect(&b);
        let _ = dlbcore::list_entries(&b);
        if let Ok(payload) = dlbcore::decompress_payload(&b, 2, &mut |_| true) {
            let _ = archive::parse_payload(&payload);
        }
        let _ = dlbcore::extract_selected(&b, 1, &[0], &dir.join(format!("sel-{}", id)), true, &mut |_| true);
        let _ = fs::remove_dir_all(dir.join(format!("sel-{}", id)));
    }
    let _ = fs::remove_file(&file);
}

#[test]
fn mutated_archives_never_panic_or_hang() {
    let iters: usize = std::env::var("DLB_FUZZ_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(if cfg!(target_arch = "x86_64") { 150 } else { 40 });
    let seed: u64 = std::env::var("DLB_FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x9E37_79B9_7F4A_7C15);
    let root = tmp("run");
    let seeds = corpus(&root);
    // the unmutated seeds must read fine
    for s in &seeds {
        let f = root.join("ok.dlb");
        let bytes = match s.password {
            Some(p) => seal_cheap(&s.bytes, p),
            None => s.bytes.clone(),
        };
        fs::write(&f, &bytes).unwrap();
        let src = stream::open_source(&f, s.password, &mut |_, _| true).unwrap_or_else(|e| panic!("{}: {}", s.name, e));
        stream::extract_archive(&*src, None, false, None, 1, &mut |_, _, _| true).unwrap_or_else(|e| panic!("{}: {}", s.name, e));
    }
    let mut rng = Rng(seed);
    for i in 0..iters {
        let s = &seeds[rng.below(seeds.len())];
        let case = match s.password {
            // mostly damage the plain archive inside a valid envelope, so the readers behind
            // the HMAC get exercised; now and then damage the envelope itself
            Some(p) if rng.below(10) != 0 => seal_cheap(&mutate(&mut rng, &s.bytes), p),
            Some(p) => mutate(&mut rng, &seal_cheap(&s.bytes, p)),
            None => mutate(&mut rng, &s.bytes),
        };
        let dir = root.join("cases");
        fs::create_dir_all(&dir).unwrap();
        let (tx, rx) = mpsc::channel();
        let (pw, dir2, bytes) = (s.password, dir.clone(), case.clone());
        let handle = std::thread::spawn(move || {
            exercise(&bytes, pw, &dir2, i);
            let _ = tx.send(());
        });
        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(()) => handle.join().unwrap(),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = handle.join();
                let keep = root.join(format!("crash-{}.dlb", i));
                fs::write(&keep, &case).unwrap();
                panic!("panic on case {} (seed {}, from {}); input saved to {}", i, seed, s.name, keep.display());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let keep = root.join(format!("hang-{}.dlb", i));
                fs::write(&keep, &case).unwrap();
                panic!("hang on case {} (seed {}, from {}); input saved to {}", i, seed, s.name, keep.display());
            }
        }
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[ignore]
fn time_clean_seeds() {
    let root = tmp("time");
    let seeds = corpus(&root);
    for s in &seeds {
        let t = std::time::Instant::now();
        let bytes = match s.password {
            Some(p) => seal_cheap(&s.bytes, p),
            None => s.bytes.clone(),
        };
        exercise(&bytes, s.password, &root, 0);
        eprintln!("{}: {:?} ({} bytes)", s.name, t.elapsed(), s.bytes.len());
    }
    let _ = fs::remove_dir_all(&root);
}
