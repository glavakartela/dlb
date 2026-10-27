//! Solid multi-file archive payload.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

// Entry `mode` layout: bits 0-11 Unix permissions, bit 27 = x86 branch filter applied to the
// data, bits 28-31 = kind (0 file, 1 empty directory, 2 symlink; its data is the target path).
// Archives written before 0.8 only ever have kind 0 and no filter bit.

pub const KIND_SHIFT: u32 = 28;
pub const KIND_FILE: u32 = 0;
pub const KIND_DIR: u32 = 1;
pub const KIND_SYMLINK: u32 = 2;
pub const FLAG_X86: u32 = 1 << 27;

pub struct Entry {
    pub name: String,
    pub size: u64,
    pub mode: u32,
    /// modification time, seconds since the Unix epoch (0 = unknown)
    pub mtime: i64,
}

impl Entry {
    pub fn kind(&self) -> u32 {
        self.mode >> KIND_SHIFT
    }
    pub fn perms(&self) -> u32 {
        self.mode & 0o7777
    }
    pub fn x86_filtered(&self) -> bool {
        self.mode & FLAG_X86 != 0
    }
}

struct Src {
    name: String,
    path: PathBuf,
    kind: u32,
    /// already compressed media / archive: goes to the stored tail of the payload
    inc: bool,
}

/// Formats whose data is already entropy coded; modelling them again only costs time.
const INCOMPRESSIBLE_EXT: &[&str] = &[
    "zip", "7z", "rar", "gz", "tgz", "bz2", "xz", "zst", "lz4", "br", "jar", "apk", "aab", "docx",
    "xlsx", "pptx", "odt", "ods", "odp", "epub", "jpg", "jpeg", "png", "webp", "heic", "heif",
    "avif", "mp3", "aac", "m4a", "opus", "ogg", "oga", "ogv", "flac", "mp4", "m4v", "mov", "mkv",
    "webm", "avi", "woff2",
];

/// Magic-number check for already-compressed data (needs the first 16 bytes).
pub fn looks_incompressible(h: &[u8]) -> bool {
    let starts = |p: &[u8]| h.len() >= p.len() && &h[..p.len()] == p;
    starts(b"PK\x03\x04")
        || starts(b"\xFF\xD8\xFF")
        || starts(b"\x89PNG\r\n\x1a\n")
        || starts(b"GIF8")
        || (starts(b"RIFF") && h.len() >= 12 && &h[8..12] == b"WEBP")
        || starts(b"\x1f\x8b")
        || starts(b"BZh")
        || starts(b"\xFD7zXZ\x00")
        || starts(b"\x28\xB5\x2F\xFD")
        || starts(b"7z\xBC\xAF\x27\x1C")
        || starts(b"Rar!")
        || starts(b"ID3")
        || starts(b"OggS")
        || starts(b"fLaC")
        || starts(b"\x1A\x45\xDF\xA3")
        || starts(b"wOF2")
        || (h.len() >= 8 && &h[4..8] == b"ftyp")
}

fn is_incompressible_file(path: &Path, name: &str) -> bool {
    use std::io::Read;
    let Ok(md) = fs::metadata(path) else { return false };
    if md.len() < 4096 {
        return false;
    }
    if INCOMPRESSIBLE_EXT.contains(&ext_key(name).as_str()) {
        return true;
    }
    let mut h = [0u8; 16];
    match fs::File::open(path).and_then(|mut f| f.read_exact(&mut h)) {
        Ok(()) => looks_incompressible(&h),
        Err(_) => false,
    }
}

// ------------------------------------------------------------ x86 branch filter

/// True for x86 / x86-64 PE and ELF files (the only ones the filter is applied to).
pub fn is_x86_executable(b: &[u8]) -> bool {
    if b.len() < 64 {
        return false;
    }
    if &b[0..4] == b"\x7fELF" {
        let machine = u16::from_le_bytes([b[18], b[19]]);
        return b[5] == 1 && (machine == 3 || machine == 62);
    }
    if &b[0..2] == b"MZ" {
        let off = u32::from_le_bytes([b[0x3c], b[0x3d], b[0x3e], b[0x3f]]) as usize;
        if off + 6 <= b.len() && &b[off..off + 4] == b"PE\0\0" {
            let machine = u16::from_le_bytes([b[off + 4], b[off + 5]]);
            return machine == 0x014c || machine == 0x8664;
        }
    }
    false
}

/// E8/E9 (CALL/JMP rel32) filter: the low 24 bits of the operand become an absolute address,
/// which repeats far more often than relative offsets. Only operands whose top byte is 0x00 or
/// 0xFF (plausible near targets) are touched, and the top byte is never changed.
///
/// Both directions run the same scan and must take the same decisions, but a decision looks at
/// the byte 4 positions ahead, which a later conversion could overwrite. So after an E8/E9 that
/// is *not* converted, no conversion may start before that look-ahead byte has been passed
/// (`blocked`); with that rule the decoder sees exactly what the encoder saw.
fn x86_filter(data: &mut [u8], encode: bool) {
    let n = data.len();
    let mut i = 0usize;
    let mut blocked = 0usize; // conversions may only start at positions >= blocked
    while i + 5 <= n {
        let op = data[i];
        if (op == 0xE8 || op == 0xE9) && i >= blocked {
            let top = data[i + 4];
            if top == 0x00 || top == 0xFF {
                let v = u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], 0]);
                let pos = (i as u32).wrapping_add(5);
                let w = (if encode { v.wrapping_add(pos) } else { v.wrapping_sub(pos) }) & 0x00FF_FFFF;
                data[i + 1] = w as u8;
                data[i + 2] = (w >> 8) as u8;
                data[i + 3] = (w >> 16) as u8;
                i += 5;
                continue;
            }
            blocked = i + 4;
        }
        i += 1;
    }
}

pub fn x86_encode(data: &mut [u8]) {
    x86_filter(data, true)
}

pub fn x86_decode(data: &mut [u8]) {
    x86_filter(data, false)
}

fn walk(base: &str, path: &Path, out: &mut Vec<Src>, exclude: &[String]) -> io::Result<()> {
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        out.push(Src { name: base.to_string(), path: path.to_path_buf(), kind: KIND_SYMLINK, inc: false });
    } else if md.is_dir() {
        let mut kids: Vec<_> = fs::read_dir(path)?.collect::<Result<_, _>>()?;
        kids.sort_by_key(|e| e.file_name());
        if kids.is_empty() {
            out.push(Src { name: base.to_string(), path: path.to_path_buf(), kind: KIND_DIR, inc: false });
        }
        for k in kids {
            let n = format!("{}/{}", base, k.file_name().to_string_lossy());
            if crate::glob::any_matches(exclude, &n) {
                continue;
            }
            walk(&n, &k.path(), out, exclude)?;
        }
    } else if md.is_file() {
        let inc = is_incompressible_file(path, base);
        out.push(Src { name: base.to_string(), path: path.to_path_buf(), kind: KIND_FILE, inc });
    }
    // special files (sockets, devices) are skipped
    Ok(())
}

#[cfg(unix)]
fn mode_of(md: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o7777
}
#[cfg(not(unix))]
fn mode_of(_md: &fs::Metadata) -> u32 {
    0
}

fn ext_key(name: &str) -> String {
    Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Read all inputs and build the solid payload. Files are grouped by extension
/// so similar data sits together (better ratio).
/// Already-compressed files (JPEG, MP4, ZIP, ...) are placed last. Returns the payload, the
/// end offset of every entry's data (the first value is the end of the header; used to cut
/// parallel blocks) and the offset where the incompressible tail starts (`usize::MAX` if none).
pub fn build_payload(paths: &[PathBuf]) -> io::Result<(Vec<u8>, Vec<usize>, usize)> {
    build_payload_ex(paths, &[])
}

fn mtime_of(md: &fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Like [`build_payload`], skipping everything below the inputs that matches an `exclude`
/// pattern (see `glob::pattern_matches`).
pub fn build_payload_ex(
    paths: &[PathBuf],
    exclude: &[String],
) -> io::Result<(Vec<u8>, Vec<usize>, usize)> {
    let mut srcs = Vec::new();
    for p in paths {
        let base = p
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        walk(&base, p, &mut srcs, exclude)?;
    }
    srcs.sort_by(|a, b| (a.inc, ext_key(&a.name), &a.name).cmp(&(b.inc, ext_key(&b.name), &b.name)));
    let n_plain = srcs.iter().filter(|s| !s.inc).count();

    // The header size is known from the names alone, so file data is appended straight into
    // the final buffer (no second copy of the whole payload).
    for s in &srcs {
        if s.name.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
        }
    }
    let head_len: usize = 8 + srcs.iter().map(|s| 2 + s.name.len() + 20).sum::<usize>();
    let est: u64 = srcs
        .iter()
        .filter(|s| s.kind == KIND_FILE)
        .map(|s| fs::metadata(&s.path).map(|m| m.len()).unwrap_or(0))
        .sum();
    let mut buf: Vec<u8> = Vec::with_capacity(head_len + est as usize + 4096);
    buf.resize(head_len, 0);

    let mut head: Vec<u8> = Vec::with_capacity(head_len);
    head.extend_from_slice(b"DLA2");
    head.extend_from_slice(&(srcs.len() as u32).to_le_bytes());
    let mut boundaries = Vec::with_capacity(srcs.len() + 1);
    boundaries.push(head_len);
    for s in &srcs {
        let md = fs::symlink_metadata(&s.path)?;
        let mut mode = mode_of(&md) | (s.kind << KIND_SHIFT);
        let start = buf.len();
        match s.kind {
            KIND_DIR => {}
            KIND_SYMLINK => buf.extend_from_slice(
                fs::read_link(&s.path)?.to_string_lossy().replace('\\', "/").as_bytes(),
            ),
            _ => {
                use std::io::Read;
                fs::File::open(&s.path)?.read_to_end(&mut buf)?;
                if is_x86_executable(&buf[start..]) {
                    x86_encode(&mut buf[start..]);
                    mode |= FLAG_X86;
                }
            }
        }
        let size = (buf.len() - start) as u64;
        let nb = s.name.as_bytes();
        head.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        head.extend_from_slice(nb);
        head.extend_from_slice(&size.to_le_bytes());
        head.extend_from_slice(&mode.to_le_bytes());
        let mtime = if s.kind == KIND_FILE { mtime_of(&md) } else { 0 };
        head.extend_from_slice(&mtime.to_le_bytes());
        boundaries.push(buf.len());
    }
    debug_assert_eq!(head.len(), head_len);
    buf[..head_len].copy_from_slice(&head);
    let store_from = if n_plain < srcs.len() { boundaries[n_plain] } else { usize::MAX };
    Ok((buf, boundaries, store_from))
}

pub fn parse_payload(p: &[u8]) -> Result<Vec<(Entry, &[u8])>, String> {
    let bad = || "corrupt archive payload".to_string();
    if p.len() < 8 || (&p[0..4] != b"DLAR" && &p[0..4] != b"DLA2") {
        return Err("payload is not a DLB archive".into());
    }
    // DLAR (before 0.11) has no modification times
    let extra = if &p[0..4] == b"DLA2" { 8usize } else { 0 };
    let count = u32::from_le_bytes(p[4..8].try_into().unwrap()) as usize;
    let mut pos = 8usize;
    let mut metas = Vec::new();
    for _ in 0..count {
        if pos + 2 > p.len() {
            return Err(bad());
        }
        let nl = u16::from_le_bytes([p[pos], p[pos + 1]]) as usize;
        pos += 2;
        if pos + nl + 12 + extra > p.len() {
            return Err(bad());
        }
        let name = String::from_utf8_lossy(&p[pos..pos + nl]).to_string();
        pos += nl;
        let size = u64::from_le_bytes(p[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let mode = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let mtime = if extra > 0 {
            let t = i64::from_le_bytes(p[pos..pos + 8].try_into().unwrap());
            pos += 8;
            t
        } else {
            0
        };
        metas.push(Entry { name, size, mode, mtime });
    }
    let mut out = Vec::with_capacity(count);
    for m in metas {
        let end = pos.checked_add(m.size as usize).ok_or_else(bad)?;
        if end > p.len() {
            return Err(bad());
        }
        out.push((m, &p[pos..end]));
        pos = end;
    }
    Ok(out)
}

fn safe_rel(name: &str) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for part in name.split('/') {
        match Path::new(part).components().next() {
            Some(Component::Normal(c)) if Path::new(part).components().count() == 1 => {
                out.push(c)
            }
            _ => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// True if a symlink at `link_rel` (relative to the output root) pointing at `target` stays
/// inside the output root (checked lexically).
fn symlink_target_ok(link_rel: &Path, target: &str) -> bool {
    let mut depth = link_rel.components().count().saturating_sub(1) as i64;
    if target.is_empty() {
        return false;
    }
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            p => {
                // reject drive letters / absolute-looking pieces
                if p.contains(':') || p.contains('\\') {
                    return false;
                }
                depth += 1;
            }
        }
    }
    !target.starts_with('/')
}

/// Extracts files, empty directories and symlinks. Returns the number of entries created.
/// Symlinks are created last and only when they point inside `outdir`, so nothing can be
/// written through a link that came from the archive.
pub fn extract(entries: &[(Entry, &[u8])], outdir: &Path, force: bool) -> Result<usize, String> {
    extract_with(entries, outdir, force, &|_| true)
}

fn set_mtime(path: &Path, secs: i64) {
    if secs <= 0 {
        return;
    }
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64);
    let _ = fs::File::options().write(true).open(path).and_then(|f| f.set_modified(t));
}

/// Like [`extract`] but only for entries accepted by `select`.
pub fn extract_with(
    entries: &[(Entry, &[u8])],
    outdir: &Path,
    force: bool,
    select: &dyn Fn(&Entry) -> bool,
) -> Result<usize, String> {
    let mut n = 0;
    for (e, data) in entries {
        if !select(e) {
            continue;
        }
        let rel = safe_rel(&e.name).ok_or_else(|| format!("unsafe path in archive: {}", e.name))?;
        let dest = outdir.join(&rel);
        match e.kind() {
            KIND_DIR => {
                fs::create_dir_all(&dest).map_err(|x| format!("{}: {}", dest.display(), x))?;
                n += 1;
                continue;
            }
            KIND_SYMLINK => continue,
            _ => {}
        }
        if dest.exists() && !force {
            return Err(format!("{} exists (use -f to overwrite)", dest.display()));
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|x| x.to_string())?;
        }
        if e.x86_filtered() {
            let mut v = data.to_vec();
            x86_decode(&mut v);
            fs::write(&dest, &v)
        } else {
            fs::write(&dest, data)
        }
        .map_err(|x| format!("{}: {}", dest.display(), x))?;
        set_mtime(&dest, e.mtime);
        #[cfg(unix)]
        if e.perms() != 0 {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(e.perms()));
        }
        n += 1;
    }
    for (e, data) in entries {
        if e.kind() != KIND_SYMLINK || !select(e) {
            continue;
        }
        let rel = safe_rel(&e.name).ok_or_else(|| format!("unsafe path in archive: {}", e.name))?;
        let target = String::from_utf8_lossy(data).to_string();
        if !symlink_target_ok(&rel, &target) {
            return Err(format!("unsafe symlink target in archive: {} -> {}", e.name, target));
        }
        #[cfg(unix)]
        {
            let dest = outdir.join(&rel);
            if fs::symlink_metadata(&dest).is_ok() {
                if !force {
                    return Err(format!("{} exists (use -f to overwrite)", dest.display()));
                }
                let _ = fs::remove_file(&dest);
            }
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|x| x.to_string())?;
            }
            std::os::unix::fs::symlink(&target, &dest)
                .map_err(|x| format!("{}: {}", dest.display(), x))?;
            n += 1;
        }
        #[cfg(not(unix))]
        {
            let _ = target; // symlinks are only restored on Unix-like systems
        }
    }
    Ok(n)
}

/// Compares archive entries with files under `dir` (names resolve relative to it). Returns a
/// list of human-readable differences; empty means everything matches.
pub fn compare(entries: &[(Entry, &[u8])], dir: &Path, select: &dyn Fn(&Entry) -> bool) -> Vec<String> {
    let mut diffs = Vec::new();
    for (e, data) in entries {
        if !select(e) {
            continue;
        }
        let Some(rel) = safe_rel(&e.name) else {
            diffs.push(format!("{}: unsafe name", e.name));
            continue;
        };
        let p = dir.join(rel);
        match e.kind() {
            KIND_DIR => {
                if !p.is_dir() {
                    diffs.push(format!("{}: folder missing", e.name));
                }
            }
            KIND_SYMLINK => match fs::read_link(&p) {
                Ok(t) => {
                    if t.to_string_lossy().replace('\\', "/") != String::from_utf8_lossy(data) {
                        diffs.push(format!("{}: link target differs", e.name));
                    }
                }
                Err(_) => diffs.push(format!("{}: link missing", e.name)),
            },
            _ => match fs::read(&p) {
                Err(_) => diffs.push(format!("{}: missing", e.name)),
                Ok(mut disk) => {
                    // the archive holds filtered bytes for x86 executables: filter the disk
                    // copy the same way instead of decoding every entry
                    if e.x86_filtered() {
                        x86_encode(&mut disk);
                    }
                    if disk.len() as u64 != e.size {
                        diffs.push(format!("{}: size differs", e.name));
                    } else if disk != *data {
                        diffs.push(format!("{}: content differs", e.name));
                    }
                }
            },
        }
    }
    diffs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dlb_ar_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn x86_filter_is_exactly_invertible() {
        let mut x = 0x1234_5678u32;
        let orig: Vec<u8> = (0..200_000)
            .map(|i| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                // plenty of E8/E9 with plausible operands
                match (x >> 28) % 6 {
                    0 => 0xE8,
                    1 => 0xE9,
                    2 => 0x00,
                    3 => 0xFF,
                    _ => (x >> 16) as u8 ^ i as u8,
                }
            })
            .collect();
        let mut d = orig.clone();
        x86_encode(&mut d);
        assert_ne!(d, orig);
        x86_decode(&mut d);
        assert_eq!(d, orig);
    }

    #[test]
    fn detects_x86_executables() {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[18] = 62;
        assert!(is_x86_executable(&elf));
        elf[18] = 183; // aarch64
        assert!(!is_x86_executable(&elf));
        assert!(!is_x86_executable(b"hello"));
    }

    #[test]
    fn dirs_symlinks_and_filter_roundtrip() {
        let d = tmp("rt");
        let src = d.join("proj");
        fs::create_dir_all(src.join("empty")).unwrap();
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("sub/a.txt"), b"hello hello hello").unwrap();
        // fake x86-64 ELF with calls in it
        let mut elf = vec![0u8; 4096];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[18] = 62;
        for k in 0..100 {
            elf[100 + k * 10] = 0xE8;
            elf[101 + k * 10] = (k * 3) as u8;
        }
        fs::write(src.join("prog"), &elf).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("sub/a.txt", src.join("link")).unwrap();
            std::os::unix::fs::symlink("../outside", src.join("sub/up")).unwrap();
        }
        let (payload, _b, _sf) = build_payload(&[src.clone()]).unwrap();
        let entries = parse_payload(&payload).unwrap();
        let kinds: Vec<(String, u32, bool)> =
            entries.iter().map(|(e, _)| (e.name.clone(), e.kind(), e.x86_filtered())).collect();
        assert!(kinds.contains(&("proj/empty".into(), KIND_DIR, false)));
        assert!(kinds.contains(&("proj/prog".into(), KIND_FILE, true)));
        #[cfg(unix)]
        {
            assert!(kinds.contains(&("proj/link".into(), KIND_SYMLINK, false)));
            // "../outside" from proj/sub/up stays within proj/ (depth 2 -> 1): allowed
            let out = d.join("out");
            let n = extract(&entries, &out, false).unwrap();
            assert_eq!(n, 5);
            assert!(out.join("proj/empty").is_dir());
            assert_eq!(fs::read(out.join("proj/prog")).unwrap(), elf);
            assert_eq!(fs::read_link(out.join("proj/link")).unwrap().to_str().unwrap(), "sub/a.txt");
            assert_eq!(fs::read_to_string(out.join("proj/link")).unwrap(), "hello hello hello");
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn compressed_files_go_to_the_stored_tail() {
        let d = tmp("inc");
        let src = d.join("m");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), vec![b'a'; 5000]).unwrap();
        let mut jpg = b"\xFF\xD8\xFF\xE0".to_vec();
        jpg.extend((0..6000u32).map(|i| (i * 7919 % 251) as u8));
        fs::write(src.join("b.jpg"), &jpg).unwrap(); // by extension
        fs::write(src.join("noext"), &jpg).unwrap(); // by magic only
        fs::write(src.join("z.txt"), vec![b'z'; 5000]).unwrap();
        let (payload, boundaries, sf) = build_payload(&[src.clone()]).unwrap();
        let entries = parse_payload(&payload).unwrap();
        let names: Vec<&str> = entries.iter().map(|(e, _)| e.name.as_str()).collect();
        assert_eq!(names, ["m/a.txt", "m/z.txt", "m/noext", "m/b.jpg"]);
        assert_eq!(sf, boundaries[2]);
        assert_eq!(payload.len() - sf, 2 * jpg.len());
        // no compressed files: no tail
        let (_p, _b, sf2) = build_payload(&[src.join("a.txt")]).unwrap();
        assert_eq!(sf2, usize::MAX);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn symlink_escape_is_rejected() {
        assert!(symlink_target_ok(Path::new("a/b"), "c"));
        assert!(symlink_target_ok(Path::new("a/b"), "../x"));
        assert!(!symlink_target_ok(Path::new("a/b"), "../../x"));
        assert!(!symlink_target_ok(Path::new("b"), "../x"));
        assert!(!symlink_target_ok(Path::new("b"), "/etc/passwd"));
        assert!(!symlink_target_ok(Path::new("b"), "C:/Windows"));
        assert!(!symlink_target_ok(Path::new("b"), ""));
        // a malicious archive: link "evil -> .." then file "evil/x" cannot hurt:
        let entries = vec![
            (Entry { name: "evil".into(), size: 2, mode: KIND_SYMLINK << KIND_SHIFT, mtime: 0 }, &b".."[..]),
        ];
        let d = tmp("evil");
        assert!(extract(&entries, &d, false).is_err());
        assert!(!d.join("evil").exists());
        let _ = fs::remove_dir_all(&d);
    }
}
