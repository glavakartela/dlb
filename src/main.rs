use dlbcore::{archive, compress_payload, decompress_payload};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::exit;
use std::time::Instant;

const USAGE: &str = "dlb 0.1 - maximum-ratio context-mixing compressor (.dlb)

USAGE:
  dlb c [-l 1-9] [-o out.dlb] <file|dir>...   compress (default level 7 ~115 MB RAM; 4 ~25 MB; 9 ~305 MB)
  dlb x <archive.dlb> [-C dir] [-f]           extract (-f overwrites)
  dlb t <archive.dlb>                         test integrity
  dlb l <archive.dlb>                         list contents
";

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
            let mut inputs = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-l" => {
                        i += 1;
                        level = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| fail("bad -l"));
                        if !(1..=9).contains(&level) {
                            fail("level must be 1..9");
                        }
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
            let payload = archive::build_payload(&inputs).unwrap_or_else(|e| fail(&e.to_string()));
            if payload.len() > dlbcore::MAX_PAYLOAD {
                fail("input is larger than 4 GiB; split it into several archives");
            }
            let t0 = Instant::now();
            let mut pg = progress("compress", payload.len());
            let blob = compress_payload(&payload, level, &mut pg).expect("not cancellable");
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
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-C" => {
                        i += 1;
                        dir = PathBuf::from(args.get(i).unwrap_or_else(|| fail("missing -C value")));
                    }
                    "-f" => force = true,
                    a => arc = Some(PathBuf::from(a)),
                }
                i += 1;
            }
            let arc = arc.unwrap_or_else(|| fail("no archive given"));
            let blob = std::fs::read(&arc).unwrap_or_else(|e| fail(&format!("{}: {}", arc.display(), e)));
            let total = u64::from_le_bytes(blob.get(6..14).map(|s| s.try_into().unwrap()).unwrap_or([0; 8])) as usize;
            let mut pg = progress("decompress", total);
            let payload = decompress_payload(&blob, &mut pg).unwrap_or_else(|e| fail(&e));
            let entries = archive::parse_payload(&payload).unwrap_or_else(|e| fail(&e));
            match cmd {
                "t" => println!("OK: {} files, {} bytes, CRC verified", entries.len(), payload.len()),
                "l" => {
                    for (e, _) in &entries {
                        println!("{:>12}  {}", e.size, e.name);
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
