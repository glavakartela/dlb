use dlbcore::{crypto, all_cores, archive, auto_threads, compress_payload, decompress_payload, Options};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::exit;
use std::time::Instant;

const USAGE: &str = "dlb 0.4 - maximum-ratio context-mixing compressor (.dlb)

USAGE:
  dlb c [-l 1-10] [-t N] [-p PASS] [-o out.dlb] <file|dir>...
                                              compress (default level 7 ~115 MB RAM per thread;
                                              4 ~25 MB; 9 ~305 MB; 10 = ULTRA, strongest and slowest, ~600 MB+). -t N = threads
                                              (default: all cores, at most 8; 0 = all cores;
                                              level 10 defaults to 1 thread)
  dlb x [-t N] [-p PASS] <archive.dlb> [-C dir] [-f]
                                              extract (-f overwrites)
  dlb t [-p PASS] <archive.dlb>               test integrity
  dlb l [-p PASS] <archive.dlb>               list contents

-p PASS encrypts (c) or decrypts (x/t/l) with a password; -k FILE uses a key file instead of,
or together with, the password (the file's SHA-256 is mixed in; keep the file safe!); names and sizes are hidden too.
The DLB_PASSWORD environment variable works the same and keeps it out of `ps`. An encrypted
archive without a password asks for one on stdin (the input is visible).
";

/// Password (from -p or DLB_PASSWORD) and/or a key file (-k): the file's SHA-256 is appended
/// to the password, so either one alone or both together unlock the archive.
fn password_from(arg: Option<String>, keyfile: &Option<String>) -> Option<String> {
    let mut pw = arg.or_else(|| std::env::var("DLB_PASSWORD").ok()).unwrap_or_default();
    if let Some(k) = keyfile {
        let data = std::fs::read(k).unwrap_or_else(|e| fail(&format!("{}: {}", k, e)));
        for b in crypto::sha256(&data) {
            pw.push_str(&format!("{:02x}", b));
        }
    }
    if pw.is_empty() { None } else { Some(pw) }
}

fn ask_password() -> String {
    eprint!("password: ");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim_end_matches(['\r', '\n']).to_string()
}

fn fail(msg: &str) -> ! {
    eprintln!("dlb: {}", msg);
    exit(1);
}

fn progress(label: &'static str, total: usize) -> impl FnMut(usize) -> bool {
    let tty = std::io::stderr().is_terminal();
    let t0 = Instant::now();
    let mut last = 0u64;
    move |done: usize| {
        if !tty {
            return true;
        }
        let ms = t0.elapsed().as_millis() as u64;
        if ms < last + 200 && done < total {
            return true;
        }
        last = ms;
        let pct = if total == 0 { 100 } else { done * 100 / total };
        eprint!("\r{} {:3}%  {:.2} MB/s   ", label, pct, done as f64 / 1e6 / (ms.max(1) as f64 / 1e3));
        let _ = std::io::stderr().flush();
        if done >= total {
            eprintln!();
        }
        true
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print!("{}", USAGE);
        exit(2);
    }
    match args[0].as_str() {
        "c" => {
            let mut level = 7u32;
            let mut out: Option<PathBuf> = None;
            let mut threads: Option<usize> = None;
            let mut pw_arg: Option<String> = None;
            let mut keyfile: Option<String> = None;
            let mut min_block = dlbcore::DEFAULT_MIN_BLOCK;
            let mut inputs = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-l" => {
                        i += 1;
                        level = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| fail("bad -l"));
                        if !(1..=10).contains(&level) {
                            fail("level must be 1..10");
                        }
                    }
                    "-t" => {
                        i += 1;
                        let n: usize = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| fail("bad -t"));
                        threads = Some(if n == 0 { all_cores() } else { n });
                    }
                    "-p" => {
                        i += 1;
                        pw_arg = Some(args.get(i).cloned().unwrap_or_else(|| fail("missing -p value")));
                    }
                    "-k" => {
                        i += 1;
                        keyfile = Some(args.get(i).cloned().unwrap_or_else(|| fail("missing -k value")));
                    }
                    "-b" => {
                        i += 1;
                        let n: usize = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| fail("bad -b"));
                        min_block = n.max(1) << 20;
                    }
                    "-o" => {
                        i += 1;
                        out = Some(PathBuf::from(args.get(i).unwrap_or_else(|| fail("missing -o value"))));
                    }
                    a => inputs.push(PathBuf::from(a)),
                }
                i += 1;
            }
            if inputs.is_empty() {
                fail("no input files");
            }
            let out = out.unwrap_or_else(|| {
                let mut n = inputs[0].file_name().map(|s| s.to_os_string()).unwrap_or_else(|| "archive".into());
                n.push(".dlb");
                PathBuf::from(n)
            });
            let (payload, boundaries, store_from) = archive::build_payload(&inputs).unwrap_or_else(|e| fail(&e.to_string()));
            if payload.len() > dlbcore::MAX_PAYLOAD {
                fail("input is larger than the supported maximum");
            }
            let t0 = Instant::now();
            let mut pg = progress("compress", payload.len());
            let mut opts = Options::new(level);
            // ultra (10) is for maximum ratio: one stream unless -t is given
            opts.threads = threads.unwrap_or(if level >= 10 { 1 } else { auto_threads() });
            opts.min_block = min_block;
            opts.store_from = store_from;
            let blob = compress_payload(&payload, &boundaries, &opts, &mut pg).expect("not cancellable");
            let blob = match password_from(pw_arg, &keyfile) {
                Some(pw) => crypto::seal(&blob, &pw).unwrap_or_else(|e| fail(&e)),
                None => blob,
            };
            std::fs::write(&out, &blob).unwrap_or_else(|e| fail(&format!("{}: {}", out.display(), e)));
            eprintln!(
                "{} -> {} bytes  (x{:.2})  {:.1}s  => {}",
                payload.len(),
                blob.len(),
                payload.len() as f64 / blob.len().max(1) as f64,
                t0.elapsed().as_secs_f64(),
                out.display()
            );
        }
        "x" | "t" | "l" => {
            let cmd = args[0].as_str();
            let mut arc: Option<PathBuf> = None;
            let mut dir = PathBuf::from(".");
            let mut force = false;
            let mut pw_arg: Option<String> = None;
            let mut keyfile: Option<String> = None;
            let mut threads = auto_threads();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-C" => {
                        i += 1;
                        dir = PathBuf::from(args.get(i).unwrap_or_else(|| fail("missing -C value")));
                    }
                    "-f" => force = true,
                    "-p" => {
                        i += 1;
                        pw_arg = Some(args.get(i).cloned().unwrap_or_else(|| fail("missing -p value")));
                    }
                    "-k" => {
                        i += 1;
                        keyfile = Some(args.get(i).cloned().unwrap_or_else(|| fail("missing -k value")));
                    }
                    "-t" => {
                        i += 1;
                        let n: usize = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| fail("bad -t"));
                        threads = if n == 0 { all_cores() } else { n };
                    }
                    a => arc = Some(PathBuf::from(a)),
                }
                i += 1;
            }
            let arc = arc.unwrap_or_else(|| fail("no archive given"));
            let blob = std::fs::read(&arc).unwrap_or_else(|e| fail(&format!("{}: {}", arc.display(), e)));
            let blob = if crypto::is_encrypted(&blob) {
                let pw = password_from(pw_arg, &keyfile).unwrap_or_else(ask_password);
                eprintln!("decrypting...");
                crypto::open(&blob, &pw).unwrap_or_else(|e| fail(&e))
            } else {
                blob
            };
            let total = u64::from_le_bytes(blob.get(6..14).map(|s| s.try_into().unwrap()).unwrap_or([0; 8])) as usize;
            let mut pg = progress("decompress", total);
            let payload = decompress_payload(&blob, threads, &mut pg).unwrap_or_else(|e| fail(&e));
            let entries = archive::parse_payload(&payload).unwrap_or_else(|e| fail(&e));
            match cmd {
                "t" => println!("OK: {} files, {} bytes, CRC verified", entries.len(), payload.len()),
                "l" => {
                    for (e, d) in &entries {
                        match e.kind() {
                            archive::KIND_DIR => println!("{:>12}  {}/", "<dir>", e.name),
                            archive::KIND_SYMLINK => {
                                println!("{:>12}  {} -> {}", "<link>", e.name, String::from_utf8_lossy(d))
                            }
                            _ => println!("{:>12}  {}", e.size, e.name),
                        }
                    }
                }
                _ => {
                    let n = archive::extract(&entries, &dir, force).unwrap_or_else(|e| fail(&e));
                    eprintln!("extracted {} files to {}", n, dir.display());
                }
            }
        }
        _ => {
            print!("{}", USAGE);
            exit(2);
        }
    }
}
