//! Solid multi-file archive payload.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

pub struct Entry {
    pub name: String,
    pub size: u64,
    pub mode: u32,
}

struct Src {
    name: String,
    path: PathBuf,
}

fn walk(base: &str, path: &Path, out: &mut Vec<Src>) -> io::Result<()> {
    let md = fs::symlink_metadata(path)?;
    if md.is_dir() {
        let mut kids: Vec<_> = fs::read_dir(path)?.collect::<Result<_, _>>()?;
        kids.sort_by_key(|e| e.file_name());
        for k in kids {
            let n = format!("{}/{}", base, k.file_name().to_string_lossy());
            walk(&n, &k.path(), out)?;
        }
    } else if md.is_file() {
        out.push(Src { name: base.to_string(), path: path.to_path_buf() });
    }
    // symlinks and special files are skipped
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
pub fn build_payload(paths: &[PathBuf]) -> io::Result<Vec<u8>> {
    let mut srcs = Vec::new();
    for p in paths {
        let base = p
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        walk(&base, p, &mut srcs)?;
    }
    srcs.sort_by(|a, b| (ext_key(&a.name), &a.name).cmp(&(ext_key(&b.name), &b.name)));

    let mut head: Vec<u8> = Vec::new();
    head.extend_from_slice(b"DLAR");
    head.extend_from_slice(&(srcs.len() as u32).to_le_bytes());
    let mut data: Vec<u8> = Vec::new();
    for s in &srcs {
        let md = fs::metadata(&s.path)?;
        let bytes = fs::read(&s.path)?;
        let nb = s.name.as_bytes();
        if nb.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
        }
        head.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        head.extend_from_slice(nb);
        head.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        head.extend_from_slice(&mode_of(&md).to_le_bytes());
        data.extend_from_slice(&bytes);
    }
    head.extend_from_slice(&data);
    Ok(head)
}

pub fn parse_payload(p: &[u8]) -> Result<Vec<(Entry, &[u8])>, String> {
    let bad = || "corrupt archive payload".to_string();
    if p.len() < 8 || &p[0..4] != b"DLAR" {
        return Err("payload is not a DLB archive".into());
    }
    let count = u32::from_le_bytes(p[4..8].try_into().unwrap()) as usize;
    let mut pos = 8usize;
    let mut metas = Vec::new();
    for _ in 0..count {
        if pos + 2 > p.len() {
            return Err(bad());
        }
        let nl = u16::from_le_bytes([p[pos], p[pos + 1]]) as usize;
        pos += 2;
        if pos + nl + 12 > p.len() {
            return Err(bad());
        }
        let name = String::from_utf8_lossy(&p[pos..pos + nl]).to_string();
        pos += nl;
        let size = u64::from_le_bytes(p[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let mode = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap());
        pos += 4;
        metas.push(Entry { name, size, mode });
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

pub fn extract(entries: &[(Entry, &[u8])], outdir: &Path, force: bool) -> Result<usize, String> {
    let mut n = 0;
    for (e, data) in entries {
        let rel = safe_rel(&e.name).ok_or_else(|| format!("unsafe path in archive: {}", e.name))?;
        let dest = outdir.join(rel);
        if dest.exists() && !force {
            return Err(format!("{} exists (use -f to overwrite)", dest.display()));
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|x| x.to_string())?;
        }
        fs::write(&dest, data).map_err(|x| format!("{}: {}", dest.display(), x))?;
        #[cfg(unix)]
        if e.mode != 0 {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(e.mode));
        }
        n += 1;
    }
    Ok(n)
}
