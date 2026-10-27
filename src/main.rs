use dlbcore::archive::{self, Entry};
use dlbcore::{
    all_cores, auto_threads, compress_payload, crypto, decompress_payload, glob, inspect, Options,
};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::exit;
use std::time::Instant;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage() -> String {
    format!(
        "dlb {} - maximum-ratio context-mixing compressor (.dlb)

USAGE:
  dlb c [options] <file|dir>...        compress into <first input>.dlb (or -o)
  dlb x [options] <archive> [select..] extract (everything, or only entries matching select)
  dlb t [options] <archive>            test integrity (CRC-32, and the password if any)
  dlb l [options] <archive> [select..] list contents with sizes and dates
  dlb i [options] <archive>            container info: blocks, sizes, ratio, model
  dlb cmp [options] <archive> [dir]    compare an archive with files on disk (default: .)
  dlb bench                            measure speed on this machine
  dlb completions bash|zsh|fish        print a shell completion script

OPTIONS:
  -l N        level 1-10 (default 7). RAM per thread: 4 ~25 MB, 7 ~115 MB, 9 ~305 MB,
              10 = ULTRA (strongest, slowest, ~600 MB)
  -t N        threads (default: all cores, at most 8; 0 = all cores; level 10 defaults to 1).
              Large data is split into blocks, one per thread: faster, slightly weaker ratio
  -x PATTERN  (c) leave out matching files/folders; repeatable. `node_modules`, `*.tmp`,
              `proj/**/*.log` ... (`*` stays inside a folder, `**` crosses folders)
  -o FILE     (c) output file
  -C DIR      (x) extract into DIR (default: current folder)
  -f          (x) overwrite existing files
  -p PASS     password (encrypts on c; needed on x/t/l/i/cmp). DLB_PASSWORD works too and
              keeps it out of `ps`; without either, an encrypted archive asks on stdin
  -k FILE     key file instead of / together with the password (its SHA-256 is mixed in)
  -q          quiet: no progress output
  -V          print the version

select patterns work like -x: a name matches any path component (`*.rs`), a path with `/`
matches from the start of the archive path, and naming a folder selects everything in it.
",
        VERSION
    )
}

fn fail(msg: &str) -> ! {
    eprintln!("dlb: {}", msg);
    exit(1);
}

// ------------------------------------------------------------------ arguments

#[derive(Default)]
struct Args {
    level: Option<u32>,
    threads: Option<usize>,
    min_block: Option<usize>,
    password: Option<String>,
    keyfile: Option<String>,
    out: Option<PathBuf>,
    dir: Option<PathBuf>,
    force: bool,
    quiet: bool,
    excludes: Vec<String>,
    pos: Vec<String>,
}

fn parse_args(argv: &[String]) -> Args {
    let mut a = Args::default();
    let mut i = 0;
    let mut only_pos = false;
    while i < argv.len() {
        let s = argv[i].as_str();
        let mut value = |name: &str| -> String {
            i += 1;
            argv.get(i).cloned().unwrap_or_else(|| fail(&format!("missing value for {}", name)))
        };
        if only_pos || !s.starts_with('-') || s == "-" {
            a.pos.push(s.to_string());
        } else {
            match s {
                "--" => only_pos = true,
                "-l" => {
                    let l: u32 = value("-l").parse().unwrap_or_else(|_| fail("bad -l"));
                    if !(1..=10).contains(&l) {
                        fail("level must be 1..10");
                    }
                    a.level = Some(l);
                }
                "-t" => {
                    let n: usize = value("-t").parse().unwrap_or_else(|_| fail("bad -t"));
                    a.threads = Some(if n == 0 { all_cores() } else { n });
                }
                "-b" => {
                    let n: usize = value("-b").parse().unwrap_or_else(|_| fail("bad -b"));
                    a.min_block = Some(n.max(1) << 20);
                }
                "-p" => a.password = Some(value("-p")),
                "-k" => a.keyfile = Some(value("-k")),
                "-o" => a.out = Some(PathBuf::from(value("-o"))),
                "-C" => a.dir = Some(PathBuf::from(value("-C"))),
                "-x" => a.excludes.push(value("-x")),
                "-f" => a.force = true,
                "-q" => a.quiet = true,
                "-V" | "--version" => {
                    println!("dlb {}", VERSION);
                    exit(0);
                }
                "-h" | "--help" => {
                    print!("{}", usage());
                    exit(0);
                }
                _ => fail(&format!("unknown option {} (see dlb --help)", s)),
            }
        }
        i += 1;
    }
    a
}

/// Password (-p or DLB_PASSWORD) and/or key file (-k): the file's SHA-256 is appended to the
/// password, so either one alone or both together unlock the archive.
fn password_from(a: &Args) -> Option<String> {
    let mut pw = a
        .password
        .clone()
        .or_else(|| std::env::var("DLB_PASSWORD").ok())
        .unwrap_or_default();
    if let Some(k) = &a.keyfile {
        let data = std::fs::read(k).unwrap_or_else(|e| fail(&format!("{}: {}", k, e)));
        for b in crypto::sha256(&data) {
            pw.push_str(&format!("{:02x}", b));
        }
    }
    if pw.is_empty() {
        None
    } else {
        Some(pw)
    }
}

fn ask_password() -> String {
    eprint!("password: ");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim_end_matches(['\r', '\n']).to_string()
}

// ------------------------------------------------------------------- progress

fn fmt_dur(secs: f64) -> String {
    let s = secs.max(0.0) as u64;
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s / 60) % 60)
    }
}

fn progress(label: &'static str, total: usize, quiet: bool) -> impl FnMut(usize) -> bool {
    let tty = std::io::stderr().is_terminal() && !quiet;
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
        let secs = ms.max(1) as f64 / 1e3;
        let speed = done as f64 / secs;
        let pct = if total == 0 { 100 } else { done * 100 / total };
        let eta = if done > 0 && done < total {
            format!("  ETA {}", fmt_dur((total - done) as f64 / speed))
        } else {
            String::new()
        };
        eprint!("\r{} {:3}%  {:.2} MB/s{}      ", label, pct, speed / 1e6, eta);
        let _ = std::io::stderr().flush();
        if done >= total {
            eprintln!();
        }
        true
    }
}

// --------------------------------------------------------------------- helpers

/// "YYYY-MM-DD HH:MM" (UTC) from Unix seconds.
fn fmt_time(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let sod = secs.rem_euclid(86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!("{:04}-{:02}-{:02} {:02}:{:02}", y, m, d, sod / 3600, (sod / 60) % 60)
}

fn human(n: u64) -> String {
    let u = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < u.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} B", n)
    } else {
        format!("{:.2} {}", v, u[i])
    }
}

/// Reads an archive file and removes the encryption layer if there is one.
fn load_archive(path: &PathBuf, a: &Args) -> (Vec<u8>, bool) {
    let blob = std::fs::read(path).unwrap_or_else(|e| fail(&format!("{}: {}", path.display(), e)));
    if crypto::is_encrypted(&blob) {
        let pw = password_from(a).unwrap_or_else(ask_password);
        if !a.quiet {
            eprintln!("decrypting...");
        }
        (crypto::open(&blob, &pw).unwrap_or_else(|e| fail(&e)), true)
    } else {
        (blob, false)
    }
}

/// Decompresses to the raw payload.
fn read_payload(blob: &[u8], a: &Args) -> Vec<u8> {
    let total = u64::from_le_bytes(blob.get(6..14).map(|s| s.try_into().unwrap()).unwrap_or([0; 8]));
    let mut pg = progress("decompress", total as usize, a.quiet);
    let threads = a.threads.unwrap_or_else(auto_threads);
    decompress_payload(blob, threads, &mut pg).unwrap_or_else(|e| fail(&e))
}

fn selector(pats: &[String]) -> impl Fn(&Entry) -> bool + '_ {
    move |e: &Entry| pats.is_empty() || glob::any_matches(pats, &e.name)
}

// -------------------------------------------------------------------- commands

fn cmd_compress(a: Args) {
    if a.pos.is_empty() {
        fail("no input files");
    }
    let inputs: Vec<PathBuf> = a.pos.iter().map(PathBuf::from).collect();
    let level = a.level.unwrap_or(7);
    let out = a.out.clone().unwrap_or_else(|| {
        let mut n = inputs[0]
            .file_name()
            .map(|s| s.to_os_string())
            .unwrap_or_else(|| "archive".into());
        n.push(".dlb");
        PathBuf::from(n)
    });
    let (payload, boundaries, store_from) =
        archive::build_payload_ex(&inputs, &a.excludes).unwrap_or_else(|e| fail(&e.to_string()));
    if payload.len() > dlbcore::MAX_PAYLOAD {
        fail("input is larger than the supported maximum");
    }
    let t0 = Instant::now();
    let mut pg = progress("compress", payload.len(), a.quiet);
    let mut opts = Options::new(level);
    // ultra (10) is for maximum ratio: one stream unless -t is given
    opts.threads = a.threads.unwrap_or(if level >= 10 { 1 } else { auto_threads() });
    if let Some(b) = a.min_block {
        opts.min_block = b;
    }
    opts.store_from = store_from;
    let blob = compress_payload(&payload, &boundaries, &opts, &mut pg).expect("not cancellable");
    let blob = match password_from(&a) {
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

fn cmd_archive(cmd: &str, a: Args) {
    let arc = PathBuf::from(a.pos.first().unwrap_or_else(|| fail("no archive given")));
    let (blob, encrypted) = load_archive(&arc, &a);
    let pats: Vec<String> = if cmd == "cmp" { Vec::new() } else { a.pos[1..].to_vec() };

    if cmd == "i" {
        return cmd_info(&arc, &blob, encrypted, &a);
    }
    let payload = read_payload(&blob, &a);
    let entries = archive::parse_payload(&payload).unwrap_or_else(|e| fail(&e));
    let sel = selector(&pats);
    match cmd {
        "t" => println!("OK: {} entries, {} bytes, CRC verified", entries.len(), payload.len()),
        "l" => {
            let mut files = 0u64;
            let mut total = 0u64;
            for (e, d) in entries.iter().filter(|(e, _)| sel(e)) {
                let when = if e.mtime > 0 { fmt_time(e.mtime) } else { "-".repeat(16) };
                match e.kind() {
                    archive::KIND_DIR => println!("{:>12}  {}  {}/", "<dir>", when, e.name),
                    archive::KIND_SYMLINK => println!(
                        "{:>12}  {}  {} -> {}",
                        "<link>",
                        when,
                        e.name,
                        String::from_utf8_lossy(d)
                    ),
                    _ => {
                        files += 1;
                        total += e.size;
                        println!("{:>12}  {}  {}", e.size, when, e.name);
                    }
                }
            }
            println!("{} files, {}", files, human(total));
        }
        "cmp" => {
            let dir = PathBuf::from(a.pos.get(1).map(|s| s.as_str()).unwrap_or("."));
            let diffs = archive::compare(&entries, &dir, &sel);
            if diffs.is_empty() {
                println!("identical: {} entries match {}", entries.len(), dir.display());
            } else {
                for d in &diffs {
                    println!("{}", d);
                }
                println!("{} difference(s)", diffs.len());
                exit(1);
            }
        }
        _ => {
            let dir = a.dir.clone().unwrap_or_else(|| PathBuf::from("."));
            let n = archive::extract_with(&entries, &dir, a.force, &sel).unwrap_or_else(|e| fail(&e));
            if n == 0 && !pats.is_empty() {
                fail("nothing matched the given patterns");
            }
            eprintln!("extracted {} entries to {}", n, dir.display());
        }
    }
}

fn cmd_info(arc: &PathBuf, blob: &[u8], encrypted: bool, a: &Args) {
    let info = inspect(blob).unwrap_or_else(|e| fail(&e));
    let on_disk = std::fs::metadata(arc).map(|m| m.len()).unwrap_or(blob.len() as u64);
    let comp: u64 = info.blocks.iter().map(|b| b.comp as u64).sum();
    println!("file:        {}", arc.display());
    println!(
        "format:      DLB{}{}",
        info.version,
        if encrypted { " (password protected)" } else { "" }
    );
    println!("file size:   {} ({} bytes)", human(on_disk), on_disk);
    println!(
        "payload:     {} ({} bytes), CRC-32 {:08x}",
        human(info.payload_len as u64),
        info.payload_len,
        info.crc
    );
    println!(
        "ratio:       x{:.2}  ({:.1}% of the original)",
        info.payload_len as f64 / comp.max(1) as f64,
        comp as f64 * 100.0 / info.payload_len.max(1) as f64
    );
    println!("blocks:      {} (they can be decoded in parallel)", info.blocks.len());
    if !a.quiet {
        println!("  #      raw         packed   mode");
        for (i, b) in info.blocks.iter().enumerate().take(64) {
            let mode = if b.stored {
                "stored".to_string()
            } else {
                format!("{}2^{}", if b.ultra { "ultra " } else { "" }, b.nbits)
            };
            println!("  {:<4} {:>12} {:>12}   {}", i, b.raw, b.comp, mode);
        }
        if info.blocks.len() > 64 {
            println!("  ... {} more", info.blocks.len() - 64);
        }
    }
    println!("use `dlb l` to list the contents");
}

// ----------------------------------------------------------------------- bench

fn sample_text(len: usize) -> Vec<u8> {
    const WORDS: [&str; 24] = [
        "the", "compression", "model", "context", "data", "block", "thread", "archive", "stream",
        "of", "and", "mixing", "bit", "predict", "file", "size", "value", "error", "index",
        "count", "buffer", "table", "update", "result",
    ];
    let mut x = 0x2545_F491u32;
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out.extend_from_slice(WORDS[(x >> 8) as usize % WORDS.len()].as_bytes());
        out.push(if (x >> 3) % 11 == 0 { b'\n' } else { b' ' });
    }
    out.truncate(len);
    out
}

fn cmd_bench() {
    println!("dlb {} benchmark ({} logical cores)", VERSION, all_cores());
    println!("synthetic text, single thread:");
    let data = sample_text(2 << 20);
    for level in [1u32, 4, 7] {
        let t = Instant::now();
        let blob = compress_payload(&data, &[], &Options::new(level), &mut |_| true).unwrap();
        let s = t.elapsed().as_secs_f64();
        println!(
            "  level {}: {:.2} MB/s, ratio x{:.1}",
            level,
            data.len() as f64 / 1e6 / s,
            data.len() as f64 / blob.len() as f64
        );
    }
    let cores = auto_threads();
    if cores > 1 {
        println!("parallel blocks, level 4, {} threads:", cores);
        let big = sample_text((cores * 2) << 20);
        let mut o = Options::new(4);
        o.min_block = 1 << 20;
        let t = Instant::now();
        let one = compress_payload(&big, &[], &o, &mut |_| true).unwrap();
        let t1 = t.elapsed().as_secs_f64();
        o.threads = cores;
        let t = Instant::now();
        let par = compress_payload(&big, &[], &o, &mut |_| true).unwrap();
        let tn = t.elapsed().as_secs_f64();
        println!(
            "  1 thread {:.1}s, {} threads {:.1}s: x{:.1} faster, size {:+.2}%",
            t1,
            cores,
            tn,
            t1 / tn,
            (par.len() as f64 / one.len() as f64 - 1.0) * 100.0
        );
    }
    println!("(real data is usually 2-4x slower than this synthetic text)");
}

// ----------------------------------------------------------------- completions

fn cmd_completions(shell: &str) {
    match shell {
        "bash" => print!(
            "_dlb() {{\n  local cur=${{COMP_WORDS[COMP_CWORD]}}\n  if [ $COMP_CWORD -eq 1 ]; then\n    COMPREPLY=( $(compgen -W \"c x t l i cmp bench completions\" -- \"$cur\") )\n  else\n    COMPREPLY=( $(compgen -W \"-l -t -x -o -C -f -p -k -q -V\" -- \"$cur\") $(compgen -f -- \"$cur\") )\n  fi\n}}\ncomplete -F _dlb dlb\n"
        ),
        "zsh" => print!(
            "#compdef dlb\n_arguments '1:command:(c x t l i cmp bench completions)' \\\n  '-l[level 1-10]:level:' '-t[threads]:threads:' '-x[exclude pattern]:pattern:' \\\n  '-o[output file]:file:_files' '-C[extract directory]:dir:_files -/' '-f[overwrite]' \\\n  '-p[password]:password:' '-k[key file]:file:_files' '-q[quiet]' '*:file:_files'\n"
        ),
        "fish" => print!(
            "complete -c dlb -n __fish_use_subcommand -a 'c x t l i cmp bench completions'\ncomplete -c dlb -s l -x -d 'level 1-10'\ncomplete -c dlb -s t -x -d 'threads'\ncomplete -c dlb -s x -x -d 'exclude pattern'\ncomplete -c dlb -s o -r -d 'output file'\ncomplete -c dlb -s C -r -d 'extract directory'\ncomplete -c dlb -s f -d 'overwrite'\ncomplete -c dlb -s p -x -d 'password'\ncomplete -c dlb -s k -r -d 'key file'\ncomplete -c dlb -s q -d 'quiet'\n"
        ),
        _ => fail("completions: bash, zsh or fish"),
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first().cloned() else {
        print!("{}", usage());
        exit(2);
    };
    let rest = &argv[1..];
    match cmd.as_str() {
        "c" => cmd_compress(parse_args(rest)),
        "x" | "t" | "l" | "i" | "cmp" => cmd_archive(cmd.as_str(), parse_args(rest)),
        "bench" => cmd_bench(),
        "completions" => cmd_completions(rest.first().map(|s| s.as_str()).unwrap_or("")),
        "-V" | "--version" => println!("dlb {}", VERSION),
        "-h" | "--help" | "help" => print!("{}", usage()),
        _ => {
            eprint!("{}", usage());
            exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_formatting() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00");
        assert_eq!(fmt_time(1_700_000_000), "2023-11-14 22:13");
        assert_eq!(fmt_time(951_782_400), "2000-02-29 00:00"); // leap day
    }

    #[test]
    fn argument_parsing() {
        let argv: Vec<String> = ["-l", "9", "-x", "a", "-x", "b", "-t", "3", "in1", "--", "-weird"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = parse_args(&argv);
        assert_eq!(a.level, Some(9));
        assert_eq!(a.threads, Some(3));
        assert_eq!(a.excludes, ["a", "b"]);
        assert_eq!(a.pos, ["in1", "-weird"]);
    }
}
