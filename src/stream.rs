//! Low-memory pipeline: archives are created and read without ever holding the whole payload.
//!
//! * Compression reads file data from disk block by block, compresses blocks on worker threads
//!   and writes them to the output in order. Memory is about `threads x (block + model tables)`.
//!   The price is a smaller ratio: blocks do not share context (see `LOW_MEM_BLOCK`).
//! * Reading uses positional reads on the archive file (`Source`). Listing decodes only the
//!   start of block 0, and extraction decodes blocks in order and writes entries as the data
//!   arrives. Encrypted archives are authenticated in one streaming pass and then decrypted on
//!   the fly (ChaCha20 allows random access).
//!
//! The produced files are ordinary `.dlb` archives: the in-memory code reads them and vice versa.

use crate::archive::{self, Entry, Plan, KIND_DIR, KIND_SYMLINK};
use crate::crc32::{self, Crc32};
use crate::{cm, crypto, level_to_nbits, ERR_NEWER, MAGIC, MAGIC_V1, MODEL_VERSION, MAX_BLOCKS, MAX_PAYLOAD, V1_HEADER, V2_ENTRY, V2_HEADER};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// Error text of an encrypted archive opened without a password.
pub const PASSWORD_REQUIRED: &str = "password required";

/// Largest block in low-memory mode. Each worker holds one block of input, up to half as much
/// compressed output and its model tables.
pub const LOW_MEM_BLOCK: usize = 64 << 20;

/// Stage reported to progress callbacks together with `(done, total)` byte counts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    /// reading input files to build the entry table (total unknown, 0)
    Scan,
    /// compressing or decompressing
    Code,
    /// authenticating / encrypting the finished file
    Finish,
}

// ------------------------------------------------------------------ sources

/// Random access to the bytes of an archive (decrypted if it was encrypted).
pub trait Source: Sync {
    fn len(&self) -> u64;
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String>;
}

fn io_err(e: io::Error) -> String {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        "truncated file".into()
    } else {
        e.to_string()
    }
}

#[cfg(unix)]
fn pread(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.read_exact_at(buf, off)
}

#[cfg(windows)]
fn pread(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0usize;
    while done < buf.len() {
        let n = f.seek_read(&mut buf[done..], off + done as u64)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        done += n;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn pread(_f: &File, _buf: &mut [u8], _off: u64) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform"))
}

pub struct FileSource {
    file: File,
    len: u64,
}

impl FileSource {
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("{}: {}", path.display(), e))?;
        let len = file.metadata().map_err(io_err)?.len();
        Ok(FileSource { file, len })
    }
}

impl Source for FileSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        if off.checked_add(buf.len() as u64).map_or(true, |e| e > self.len) {
            return Err("truncated file".into());
        }
        pread(&self.file, buf, off).map_err(io_err)
    }
}

/// Decrypts on the fly: the envelope body is ChaCha20, which can start at any block.
pub struct CryptSource {
    inner: FileSource,
    keys: crypto::Keys,
}

impl Source for CryptSource {
    fn len(&self) -> u64 {
        self.inner.len - (crypto::ENVELOPE_HEADER + crypto::ENVELOPE_TAG) as u64
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        if off.checked_add(buf.len() as u64).map_or(true, |e| e > self.len()) {
            return Err("truncated file".into());
        }
        self.inner.read_at(crypto::ENVELOPE_HEADER as u64 + off, buf)?;
        self.keys.xor_at(off, buf);
        Ok(())
    }
}

/// Opens an archive. For an encrypted one the whole file is read once to check its HMAC (wrong
/// password and tampering both give `ERR_BAD_PASSWORD`); `progress(done, total)` may cancel.
pub fn open_source(
    path: &Path,
    password: Option<&str>,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> Result<Box<dyn Source>, String> {
    let fsrc = FileSource::open(path)?;
    if fsrc.len < 4 {
        return Err("not a DLB file (bad magic)".into());
    }
    let mut magic = [0u8; 4];
    fsrc.read_at(0, &mut magic)?;
    if !crypto::is_encrypted(&magic) {
        return Ok(Box::new(fsrc));
    }
    let pw = match password {
        Some(p) if !p.is_empty() => p,
        _ => return Err(PASSWORD_REQUIRED.into()),
    };
    if fsrc.len < (crypto::ENVELOPE_HEADER + crypto::ENVELOPE_TAG) as u64 {
        return Err("truncated encrypted file".into());
    }
    let mut head = [0u8; crypto::ENVELOPE_HEADER];
    fsrc.read_at(0, &mut head)?;
    let keys = crypto::read_envelope(&head, pw)?;
    let end = fsrc.len - crypto::ENVELOPE_TAG as u64;
    let mut mac = keys.mac_stream();
    mac.update(&head);
    let mut pos = crypto::ENVELOPE_HEADER as u64;
    let mut buf = vec![0u8; 1 << 20];
    while pos < end {
        let n = ((end - pos) as usize).min(buf.len());
        fsrc.read_at(pos, &mut buf[..n])?;
        mac.update(&buf[..n]);
        pos += n as u64;
        if !progress(pos, end) {
            return Err("cancelled".into());
        }
    }
    let tag = mac.finish();
    let mut stored = [0u8; crypto::ENVELOPE_TAG];
    fsrc.read_at(end, &mut stored)?;
    if !crypto::ct_eq(&tag, &stored) {
        return Err(crypto::ERR_BAD_PASSWORD.into());
    }
    Ok(Box::new(CryptSource { inner: fsrc, keys }))
}

// ---------------------------------------------------------------- container

pub struct BlockDesc {
    pub raw: usize,
    pub comp: usize,
    pub stored: bool,
    pub nbits: u32,
    /// offset of the block's bytes in the source
    pub off: u64,
}

pub struct Container {
    pub total: u64,
    pub crc: u32,
    pub blocks: Vec<BlockDesc>,
}

/// Reads and validates the block table (`DLB1` and `DLB2`).
pub fn read_container(src: &dyn Source) -> Result<Container, String> {
    let corrupt = |m: &str| Err(format!("corrupt header: {}", m));
    let check_nbits = |n: u32| (10..=30).contains(&(n & 0x7F));
    let mut magic = [0u8; 4];
    if src.len() < 4 {
        return Err("not a DLB file (bad magic)".into());
    }
    src.read_at(0, &mut magic)?;
    if &magic == MAGIC_V1 {
        if src.len() < V1_HEADER as u64 {
            return corrupt("truncated");
        }
        let mut h = [0u8; V1_HEADER];
        src.read_at(0, &mut h)?;
        let stored = h[4] & 1 != 0;
        let nbits = h[5] as u32;
        let len = u64::from_le_bytes(h[6..14].try_into().unwrap());
        let crc = u32::from_le_bytes(h[14..18].try_into().unwrap());
        let body = src.len() - V1_HEADER as u64;
        if len > MAX_PAYLOAD as u64 {
            return corrupt("unsupported length");
        }
        if !stored && !check_nbits(nbits) {
            return corrupt("nbits");
        }
        if stored && body != len {
            return Err("corrupt stored block".into());
        }
        return Ok(Container {
            total: len,
            crc,
            blocks: vec![BlockDesc {
                raw: len as usize,
                comp: body as usize,
                stored,
                nbits,
                off: V1_HEADER as u64,
            }],
        });
    }
    if &magic != MAGIC {
        return Err("not a DLB file (bad magic)".into());
    }
    if src.len() < V2_HEADER as u64 {
        return corrupt("truncated");
    }
    let mut h = [0u8; V2_HEADER];
    src.read_at(0, &mut h)?;
    if h[4] > MODEL_VERSION {
        return Err(ERR_NEWER.into());
    }
    let total = u64::from_le_bytes(h[6..14].try_into().unwrap());
    let crc = u32::from_le_bytes(h[14..18].try_into().unwrap());
    let n = u32::from_le_bytes(h[18..22].try_into().unwrap()) as usize;
    if total > MAX_PAYLOAD as u64 {
        return corrupt("unsupported length");
    }
    if n == 0 || n > MAX_BLOCKS || src.len() < (V2_HEADER + V2_ENTRY * n) as u64 {
        return corrupt("block table");
    }
    let mut table = vec![0u8; V2_ENTRY * n];
    src.read_at(V2_HEADER as u64, &mut table)?;
    let mut pos = (V2_HEADER + V2_ENTRY * n) as u64;
    let mut raw_sum = 0u64;
    let mut blocks = Vec::with_capacity(n);
    for e in table.chunks(V2_ENTRY) {
        let raw = u32::from_le_bytes(e[0..4].try_into().unwrap()) as usize;
        let comp = u32::from_le_bytes(e[4..8].try_into().unwrap()) as usize;
        let stored = e[8] & 1 != 0;
        let nbits = e[9] as u32;
        if pos.checked_add(comp as u64).map_or(true, |end| end > src.len()) {
            return Err("truncated file".into());
        }
        if stored && comp != raw {
            return Err("corrupt stored block".into());
        }
        if !stored && !check_nbits(nbits) {
            return corrupt("nbits");
        }
        if !stored && (raw as u64) > (comp as u64 + 8) * 400_000 {
            return corrupt("length inconsistent with stream size");
        }
        raw_sum += raw as u64;
        blocks.push(BlockDesc { raw, comp, stored, nbits, off: pos });
        pos += comp as u64;
    }
    if raw_sum != total {
        return corrupt("block sizes do not add up");
    }
    Ok(Container { total, crc, blocks })
}

/// Decodes the first `n` bytes of a block.
fn decode_block(
    src: &dyn Source,
    b: &BlockDesc,
    n: usize,
    prog: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>, String> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let n = n.min(b.raw);
    if b.stored {
        let mut v = vec![0u8; n];
        src.read_at(b.off, &mut v)?;
        prog(n);
        return Ok(v);
    }
    let mut comp = vec![0u8; b.comp];
    src.read_at(b.off, &mut comp)?;
    let mut out = vec![0u8; n];
    if cm::cm_decompress(&comp, &mut out, b.nbits, prog) {
        Ok(out)
    } else {
        Err("cancelled".into())
    }
}

/// The first `want` bytes of the payload (fewer if it is shorter). Block 0 is decoded from a
/// *prefix* of its compressed bytes, so a multi-gigabyte first block is not read in full.
fn payload_prefix(src: &dyn Source, c: &Container, want: usize) -> Result<Vec<u8>, String> {
    let b0 = &c.blocks[0];
    if want <= b0.raw {
        if b0.stored {
            let mut v = vec![0u8; want];
            src.read_at(b0.off, &mut v)?;
            return Ok(v);
        }
        let mut p = (1usize << 20).min(b0.comp);
        loop {
            let mut buf = vec![0u8; p];
            src.read_at(b0.off, &mut buf)?;
            let mut st = cm::CmStream::new(&buf, b0.nbits);
            let out = st.extend_to(want, b0.raw).to_vec();
            if p >= b0.comp || st.consumed() <= p {
                return Ok(out);
            }
            p = p.saturating_mul(4).min(b0.comp);
        }
    }
    let mut out = Vec::new();
    for b in &c.blocks {
        if out.len() >= want {
            break;
        }
        out.extend_from_slice(&decode_block(src, b, b.raw, &mut |_| true)?);
    }
    Ok(out)
}

/// The entry table and the length of the header (where the first entry's data starts).
pub fn read_entries(src: &dyn Source, c: &Container) -> Result<(Vec<Entry>, usize), String> {
    let total = c.total as usize;
    let mut want = 4096usize.min(total);
    loop {
        let buf = payload_prefix(src, c, want)?;
        match archive::parse_header(&buf)? {
            archive::HeaderParse::Done(entries, hl) => {
                let end = entries.last().map_or(hl as u64, |e| e.offset + e.size);
                if end > c.total {
                    return Err("corrupt archive payload".into());
                }
                return Ok((entries, hl));
            }
            archive::HeaderParse::NeedMore(n) => {
                if buf.len() >= total || n > total {
                    return Err("corrupt archive payload".into());
                }
                want = n.max(want.saturating_mul(4)).min(total);
            }
        }
    }
}

pub struct Listing {
    pub entries: Vec<Entry>,
    /// payload length
    pub total: u64,
    pub header_len: usize,
}

/// Entry table of an already opened archive.
pub fn list_source(src: &dyn Source) -> Result<Listing, String> {
    let c = read_container(src)?;
    let (entries, header_len) = read_entries(src, &c)?;
    Ok(Listing { entries, total: c.total, header_len })
}

/// Lists an archive reading only its beginning (plus one pass for authentication when it is
/// encrypted).
pub fn list_archive(
    path: &Path,
    password: Option<&str>,
    progress: &mut dyn FnMut(u64, u64) -> bool,
) -> Result<Listing, String> {
    let src = open_source(path, password, progress)?;
    list_source(&*src)
}

// ----------------------------------------------------------------- pipeline

/// Runs `produce(i)` for `i in 0..n` on `workers` threads and hands the results to `consume` in
/// index order on the calling thread. At most `window` blocks exist at any time (being
/// produced, waiting, or being consumed), which bounds memory. `progress(done)` receives the sum of what the workers report and may cancel.
fn pipeline<T: Send>(
    n: usize,
    workers: usize,
    window: usize,
    produce: &(dyn Fn(usize, &mut dyn FnMut(usize) -> bool) -> Result<T, String> + Sync),
    consume: &mut dyn FnMut(usize, T) -> Result<(), String>,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<(), String> {
    if n == 0 {
        return Ok(());
    }
    struct St<T> {
        next: usize,
        consumed: usize,
        ready: BTreeMap<usize, Result<T, String>>,
        stop: bool,
    }
    let m = Mutex::new(St::<T> { next: 0, consumed: 0, ready: BTreeMap::new(), stop: false });
    let cv = Condvar::new();
    let stop = AtomicBool::new(false);
    let done = AtomicUsize::new(0);
    let workers = workers.clamp(1, n);
    let window = window.max(1);

    let halt = |g: &mut St<T>| {
        g.stop = true;
        stop.store(true, SeqCst);
        cv.notify_all();
    };

    let mut result: Result<(), String> = Ok(());
    std::thread::scope(|sc| {
        for _ in 0..workers {
            sc.spawn(|| loop {
                let i = {
                    let mut g = m.lock().unwrap();
                    loop {
                        if g.stop || g.next >= n {
                            break None;
                        }
                        if g.next < g.consumed + window {
                            let i = g.next;
                            g.next += 1;
                            break Some(i);
                        }
                        g = cv.wait(g).unwrap();
                    }
                };
                let Some(i) = i else { break };
                let mut last = 0usize;
                let r = produce(i, &mut |d| {
                    done.fetch_add(d.saturating_sub(last), SeqCst);
                    last = last.max(d);
                    !stop.load(SeqCst)
                });
                let mut g = m.lock().unwrap();
                if r.is_err() {
                    halt(&mut g);
                }
                g.ready.insert(i, r);
                cv.notify_all();
            });
        }

        'outer: for i in 0..n {
            let item = loop {
                let mut g = m.lock().unwrap();
                if let Some(r) = g.ready.remove(&i) {
                    break Some(r);
                }
                if g.stop {
                    break None;
                }
                let (g2, _) = cv.wait_timeout(g, Duration::from_millis(40)).unwrap();
                drop(g2);
                if !progress(done.load(SeqCst)) {
                    let mut g = m.lock().unwrap();
                    halt(&mut g);
                    result = Err("cancelled".into());
                    break None;
                }
            };
            match item {
                Some(Ok(v)) => {
                    if let Err(e) = consume(i, v) {
                        result = Err(e);
                        let mut g = m.lock().unwrap();
                        halt(&mut g);
                        break 'outer;
                    }
                    {
                        // the block is gone from memory: let a worker start the next one
                        let mut g = m.lock().unwrap();
                        g.consumed = i + 1;
                        cv.notify_all();
                    }
                    if !progress(done.load(SeqCst)) {
                        result = Err("cancelled".into());
                        let mut g = m.lock().unwrap();
                        halt(&mut g);
                        break 'outer;
                    }
                }
                Some(Err(e)) => {
                    if result.is_ok() {
                        result = Err(e);
                    }
                    let mut g = m.lock().unwrap();
                    halt(&mut g);
                    break 'outer;
                }
                None => break 'outer,
            }
        }
        let mut g = m.lock().unwrap();
        halt(&mut g);
    });
    // a worker error that was not consumed (a later block failed first) still counts
    if result.is_ok() {
        let g = m.lock().unwrap();
        for r in g.ready.values() {
            if let Err(e) = r {
                return Err(e.clone());
            }
        }
    }
    result
}

// --------------------------------------------------------------- compression

pub struct CompressJob<'a> {
    pub inputs: &'a [PathBuf],
    pub exclude: &'a [String],
    pub out: &'a Path,
    pub level: u32,
    pub threads: usize,
    /// largest block (bytes); `LOW_MEM_BLOCK` by default
    pub block: usize,
    pub password: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub struct CompressStats {
    pub payload: u64,
    pub out: u64,
    pub files: u64,
}

/// Block boundaries `(start, end, stored_only)`: plain data in blocks of at most `cap` bytes
/// (cut at file ends when one falls in the last half of the window), then the incompressible
/// tail in stored chunks.
fn block_ranges(plan: &Plan, cap: usize) -> Vec<(u64, u64, bool)> {
    let cap = cap.max(1 << 10) as u64;
    let sf = plan.store_from.min(plan.total);
    let mut v = Vec::new();
    let mut start = 0u64;
    while sf - start > cap {
        let want = start + cap;
        let lo = start + cap / 2;
        let idx = plan.boundaries.partition_point(|&b| b <= want);
        let cut = if idx > 0 && plan.boundaries[idx - 1] > lo { plan.boundaries[idx - 1] } else { want };
        v.push((start, cut, false));
        start = cut;
    }
    if sf > start || v.is_empty() {
        v.push((start, sf, false));
    }
    let chunk = cap.min(32 << 20);
    let mut s = sf;
    while s < plan.total {
        let e = (s + chunk).min(plan.total);
        v.push((s, e, true));
        s = e;
    }
    v
}

struct Blk {
    stored: bool,
    nbits: u8,
    body: Vec<u8>,
    raw: usize,
    crc: u32,
}

fn part_path(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_owned();
    s.push(".part");
    PathBuf::from(s)
}

/// Creates an archive without holding the payload in memory. The result is written to
/// `<out>.part` and renamed when complete, so a failure or cancel leaves no half file.
/// `on_plan(payload_len, entries)` is called once the entry table is known.
pub fn compress_streaming(
    job: &CompressJob,
    on_plan: &mut dyn FnMut(u64, u64),
    progress: &mut dyn FnMut(Stage, u64, u64) -> bool,
) -> Result<CompressStats, String> {
    let tmp = part_path(job.out);
    let r = compress_inner(job, &tmp, on_plan, progress);
    match r {
        Ok(s) => {
            if let Err(e) = fs::rename(&tmp, job.out) {
                let _ = fs::remove_file(&tmp);
                return Err(format!("{}: {}", job.out.display(), e));
            }
            Ok(s)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn compress_inner(
    job: &CompressJob,
    tmp: &Path,
    on_plan: &mut dyn FnMut(u64, u64),
    progress: &mut dyn FnMut(Stage, u64, u64) -> bool,
) -> Result<CompressStats, String> {
    let cap = job.block.max(1 << 10);
    let plan = archive::plan_files(job.inputs, job.exclude, (cap / 2) as u64, &mut |d| {
        progress(Stage::Scan, d, 0)
    })?;
    if plan.total > MAX_PAYLOAD as u64 {
        return Err("input is larger than the supported maximum".into());
    }
    if job.password.is_some() && plan.total > crypto::MAX_BODY {
        return Err("archive is too large to encrypt (limit 256 GiB)".into());
    }
    let nfiles = u32::from_le_bytes(plan.head[4..8].try_into().unwrap()) as u64;
    on_plan(plan.total, nfiles);

    let ranges = block_ranges(&plan, cap);
    let n = ranges.len();
    if n > MAX_BLOCKS {
        return Err("too many blocks: use a larger block size".into());
    }
    let level = job.level;

    let mut f = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(tmp)
        .map_err(|e| format!("{}: {}", tmp.display(), e))?;
    let werr = |e: io::Error| format!("{}: {}", tmp.display(), e);

    let (env_head, keys) = match job.password {
        Some(pw) => {
            let (h, k) = crypto::new_envelope(pw)?;
            (Some(h), Some(k))
        }
        None => (None, None),
    };
    let base = env_head.as_ref().map_or(0u64, |h| h.len() as u64);
    if let Some(h) = &env_head {
        f.write_all(h).map_err(werr)?;
    }
    // room for the container header and block table, filled in at the end
    let table_len = V2_HEADER + V2_ENTRY * n;
    f.write_all(&vec![0u8; table_len]).map_err(werr)?;

    let produce = |i: usize, prog: &mut dyn FnMut(usize) -> bool| -> Result<Blk, String> {
        let (a, b, stored_only) = ranges[i];
        let want = (b - a) as usize;
        let mut raw = Vec::with_capacity(want);
        plan.read_range(a, b, &mut raw)?;
        if raw.len() != want {
            return Err("file changed while compressing".into());
        }
        let crc = crc32::crc32(&raw);
        if stored_only {
            if !prog(want) {
                return Err("cancelled".into());
            }
            return Ok(Blk { stored: true, nbits: 0, body: raw, raw: want, crc });
        }
        let nb = (level_to_nbits(level, want) | if level >= 10 { cm::ULTRA_FLAG } else { 0 }) as u8;
        match cm::cm_compress(&raw, nb as u32, prog) {
            None => Err("cancelled".into()),
            Some(body) if body.len() < want => {
                Ok(Blk { stored: false, nbits: nb, body, raw: want, crc })
            }
            Some(_) => Ok(Blk { stored: true, nbits: nb, body: raw, raw: want, crc }),
        }
    };

    let mut table: Vec<u8> = Vec::with_capacity(V2_ENTRY * n);
    let mut crc_total = 0u32;
    let total = plan.total;
    {
        let mut consume = |_i: usize, b: Blk| -> Result<(), String> {
            f.write_all(&b.body).map_err(werr)?;
            table.extend_from_slice(&(b.raw as u32).to_le_bytes());
            table.extend_from_slice(&(b.body.len() as u32).to_le_bytes());
            table.push(b.stored as u8);
            table.push(b.nbits);
            crc_total = crc32::combine(crc_total, b.crc, b.raw as u64);
            Ok(())
        };
        let threads = job.threads.max(1);
        pipeline(
            n,
            threads,
            threads,
            &produce,
            &mut consume,
            &mut |d| progress(Stage::Code, d as u64, total),
        )?;
    }
    plan.verify_unchanged()?;

    let mut head = Vec::with_capacity(table_len);
    head.extend_from_slice(MAGIC);
    head.push(MODEL_VERSION);
    head.push(0);
    head.extend_from_slice(&total.to_le_bytes());
    head.extend_from_slice(&crc_total.to_le_bytes());
    head.extend_from_slice(&(n as u32).to_le_bytes());
    head.extend_from_slice(&table);
    f.seek(SeekFrom::Start(base)).map_err(werr)?;
    f.write_all(&head).map_err(werr)?;

    if let (Some(h), Some(k)) = (&env_head, &keys) {
        // encrypt in place: the keystream does not change the length
        let end = f.seek(SeekFrom::End(0)).map_err(werr)?;
        let body_len = end - base;
        let mut mac = k.mac_stream();
        mac.update(h);
        let mut buf = vec![0u8; 1 << 20];
        let mut off = 0u64;
        while off < body_len {
            let n = ((body_len - off) as usize).min(buf.len());
            f.seek(SeekFrom::Start(base + off)).map_err(werr)?;
            f.read_exact(&mut buf[..n]).map_err(werr)?;
            k.xor_at(off, &mut buf[..n]);
            f.seek(SeekFrom::Start(base + off)).map_err(werr)?;
            f.write_all(&buf[..n]).map_err(werr)?;
            mac.update(&buf[..n]);
            off += n as u64;
            if !progress(Stage::Finish, off, body_len) {
                return Err("cancelled".into());
            }
        }
        f.seek(SeekFrom::End(0)).map_err(werr)?;
        f.write_all(&mac.finish()).map_err(werr)?;
    }
    f.flush().map_err(werr)?;
    let out_len = f.metadata().map_err(werr)?.len();
    Ok(CompressStats { payload: total, out: out_len, files: nfiles })
}

// ---------------------------------------------------------------- extraction

enum Sink {
    Null,
    File(File),
    Buf(Vec<u8>),
}

struct Cur {
    sink: Sink,
    crc: Crc32,
    got: u64,
    path: PathBuf,
}

/// Writes entries as their data arrives, in payload order.
struct Extractor<'a> {
    entries: &'a [Entry],
    sel: Vec<bool>,
    dest: Option<&'a Path>,
    force: bool,
    cur: usize,
    begun: bool,
    st: Option<Cur>,
    links: Vec<(PathBuf, String)>,
    files: u64,
    bytes: u64,
}

impl<'a> Extractor<'a> {
    fn open(&mut self) -> Result<(), String> {
        let i = self.cur;
        self.begun = true;
        if !self.sel[i] {
            return Ok(());
        }
        let e = &self.entries[i];
        let kind = e.kind();
        let mut path = PathBuf::new();
        if let Some(d) = self.dest {
            let rel = archive::safe_rel(&e.name)
                .ok_or_else(|| format!("unsafe path in archive: {}", e.name))?;
            path = d.join(rel);
        }
        if kind == KIND_DIR {
            if self.dest.is_some() {
                fs::create_dir_all(&path).map_err(|x| format!("{}: {}", path.display(), x))?;
                self.files += 1;
            }
            return Ok(());
        }
        let sink = if kind == KIND_SYMLINK {
            Sink::Buf(Vec::new())
        } else if self.dest.is_none() {
            Sink::Null
        } else {
            if path.exists() && !self.force {
                return Err(format!("{} exists (use -f to overwrite)", path.display()));
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|x| x.to_string())?;
            }
            if e.x86_filtered() {
                Sink::Buf(Vec::new())
            } else {
                Sink::File(File::create(&path).map_err(|x| format!("{}: {}", path.display(), x))?)
            }
        };
        self.st = Some(Cur { sink, crc: Crc32::new(), got: 0, path });
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> Result<(), String> {
        let st = self.st.as_mut().expect("open entry");
        st.crc.update(data);
        st.got += data.len() as u64;
        match &mut st.sink {
            Sink::Null => {}
            Sink::File(f) => f
                .write_all(data)
                .map_err(|x| format!("{}: {}", st.path.display(), x))?,
            Sink::Buf(v) => v.extend_from_slice(data),
        }
        Ok(())
    }

    fn close(&mut self) -> Result<(), String> {
        let i = self.cur;
        self.begun = false;
        if !self.sel[i] {
            return Ok(());
        }
        let e = &self.entries[i];
        if e.kind() == KIND_DIR {
            return Ok(());
        }
        let st = self.st.take().ok_or_else(|| "truncated archive".to_string())?;
        if st.got != e.size {
            return Err("truncated archive".into());
        }
        if e.crc != 0 && st.crc.finish() != e.crc {
            return Err(format!("checksum mismatch for {}", e.name));
        }
        match st.sink {
            Sink::Null => {}
            Sink::File(f) => {
                drop(f);
                archive::finish_file_meta(&st.path, e);
                self.files += 1;
                self.bytes += e.size;
            }
            Sink::Buf(mut v) => {
                if e.kind() == KIND_SYMLINK {
                    if let Some(d) = self.dest {
                        let rel = archive::safe_rel(&e.name)
                            .ok_or_else(|| format!("unsafe path in archive: {}", e.name))?;
                        let target = String::from_utf8_lossy(&v).to_string();
                        if !archive::symlink_target_ok(&rel, &target) {
                            return Err(format!(
                                "unsafe symlink target in archive: {} -> {}",
                                e.name, target
                            ));
                        }
                        let _ = d;
                        self.links.push((rel, target));
                    }
                } else {
                    archive::x86_decode(&mut v);
                    fs::write(&st.path, &v).map_err(|x| format!("{}: {}", st.path.display(), x))?;
                    archive::finish_file_meta(&st.path, e);
                    self.files += 1;
                    self.bytes += e.size;
                }
            }
        }
        Ok(())
    }

    /// Payload bytes `base..base + data.len()` arrive (in order, possibly with gaps that hold
    /// only unselected entries).
    fn feed(&mut self, base: u64, data: &[u8]) -> Result<(), String> {
        let end = base + data.len() as u64;
        while self.cur < self.entries.len() {
            let (es, ee) = {
                let e = &self.entries[self.cur];
                (e.offset, e.offset + e.size)
            };
            if !self.begun {
                if es > end {
                    break;
                }
                self.open()?;
            }
            let from = base.max(es);
            let to = end.min(ee);
            if from < to && self.sel[self.cur] {
                let got = self.st.as_ref().map_or(0, |s| s.got);
                if from != es + got {
                    return Err("truncated archive".into());
                }
                self.write(&data[(from - base) as usize..(to - base) as usize])?;
            }
            if ee <= end {
                self.close()?;
                self.cur += 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// All data has been fed: closes trailing empty entries and creates the symlinks.
    fn finish(&mut self, total: u64) -> Result<u64, String> {
        self.feed(total, &[])?;
        for i in self.cur..self.entries.len() {
            if self.sel[i] {
                return Err("truncated archive".into());
            }
        }
        if let Some(d) = self.dest {
            for (rel, target) in std::mem::take(&mut self.links) {
                if archive::create_symlink(d, &rel, &target, self.force)? {
                    self.files += 1;
                }
            }
        }
        Ok(self.files)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExtractStats {
    pub files: u64,
    pub bytes: u64,
    pub payload: u64,
}

/// Extracts (`dest` = Some) or only verifies (`dest` = None) an archive. `select` lists entry
/// indices (as returned by [`list_archive`]); None means everything, and then the whole-payload
/// CRC is checked as well. Only the blocks that hold wanted data are decoded.
pub fn extract_archive(
    src: &dyn Source,
    dest: Option<&Path>,
    force: bool,
    select: Option<&[usize]>,
    threads: usize,
    progress: &mut dyn FnMut(Stage, u64, u64) -> bool,
) -> Result<ExtractStats, String> {
    let c = read_container(src)?;
    let (entries, header_len) = read_entries(src, &c)?;

    let mut sel = vec![select.is_none(); entries.len()];
    let mut ranges: Vec<(u64, u64)> = vec![(0, header_len as u64)];
    if let Some(list) = select {
        for &i in list {
            let e = entries.get(i).ok_or_else(|| "selection out of range".to_string())?;
            sel[i] = true;
            ranges.push((e.offset, e.offset + e.size));
        }
    }
    let full = select.is_none();
    let mut need = vec![0usize; c.blocks.len()];
    let mut starts = Vec::with_capacity(c.blocks.len());
    let mut start = 0u64;
    for (i, b) in c.blocks.iter().enumerate() {
        starts.push(start);
        let end = start + b.raw as u64;
        if full {
            need[i] = b.raw;
        } else {
            for &(a, e) in &ranges {
                if e > a && a < end && e > start {
                    need[i] = need[i].max((e.min(end) - start) as usize);
                }
            }
        }
        start = end;
    }
    let work: u64 = need.iter().map(|&n| n as u64).sum();

    let mut ex = Extractor {
        entries: &entries,
        sel,
        dest,
        force,
        cur: 0,
        begun: false,
        st: None,
        links: Vec::new(),
        files: 0,
        bytes: 0,
    };
    let mut crc = Crc32::new();
    let blocks = &c.blocks;
    let produce = |i: usize, prog: &mut dyn FnMut(usize) -> bool| -> Result<Vec<u8>, String> {
        decode_block(src, &blocks[i], need[i], prog)
    };
    let threads = threads.max(1);
    pipeline(
        blocks.len(),
        threads,
        threads,
        &produce,
        &mut |i, data| {
            if full {
                crc.update(&data);
            }
            ex.feed(starts[i], &data)
        },
        &mut |d| progress(Stage::Code, d as u64, work),
    )?;
    if full && crc.finish() != c.crc {
        return Err("CRC mismatch: data is corrupt".into());
    }
    let files = ex.finish(c.total)?;
    Ok(ExtractStats { files, bytes: ex.bytes, payload: c.total })
}

// ---------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    /// entries of `sample_tree`: the symlink only exists on Unix
    const ENTRIES: u64 = if cfg!(unix) { 9 } else { 8 };

    fn tmpdir(tag: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "dlb-stream-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, SeqCst)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn lcg(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            })
            .collect()
    }

    fn sample_tree(root: &Path) {
        let t = root.join("proj");
        fs::create_dir_all(t.join("src/deep")).unwrap();
        fs::create_dir_all(t.join("empty")).unwrap();
        let text: Vec<u8> = (0..5_000).flat_map(|i| format!("line {} of the log\n", i % 977).into_bytes()).collect();
        fs::write(t.join("a.txt"), &text).unwrap();
        fs::write(t.join("src/b.txt"), &text[..20_000]).unwrap();
        fs::write(t.join("src/deep/c.rs"), b"fn main() {}\n").unwrap();
        fs::write(t.join("zero.bin"), b"").unwrap();
        fs::write(t.join("noise.dat"), lcg(15_000, 7)).unwrap();
        fs::write(t.join("pic.jpg"), [&[0xFFu8, 0xD8, 0xFF, 0xE0][..], &lcg(9_000, 9)].concat()).unwrap();
        // a tiny x86-64 ELF with plenty of CALL/JMP opcodes
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[18] = 62;
        for i in 0..3_000u32 {
            elf.extend_from_slice(&[0xE8, (i & 0xFF) as u8, (i >> 8) as u8, 0, 0, 0x90]);
        }
        fs::write(t.join("prog"), &elf).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("src/b.txt", t.join("link")).unwrap();
    }

    fn same_tree(a: &Path, b: &Path) {
        let mut names = Vec::new();
        fn walk(p: &Path, base: &Path, out: &mut Vec<String>) {
            for e in fs::read_dir(p).unwrap() {
                let e = e.unwrap();
                let rel = e.path().strip_prefix(base).unwrap().to_string_lossy().to_string();
                out.push(rel);
                if e.file_type().unwrap().is_dir() {
                    walk(&e.path(), base, out);
                }
            }
        }
        walk(a, a, &mut names);
        assert!(!names.is_empty());
        for n in &names {
            let (pa, pb) = (a.join(n), b.join(n));
            let ma = fs::symlink_metadata(&pa).unwrap();
            let mb = fs::symlink_metadata(&pb).unwrap_or_else(|_| panic!("missing {}", n));
            assert_eq!(ma.is_dir(), mb.is_dir(), "{}", n);
            if ma.file_type().is_symlink() {
                assert_eq!(fs::read_link(&pa).unwrap(), fs::read_link(&pb).unwrap());
            } else if ma.is_file() {
                assert_eq!(fs::read(&pa).unwrap(), fs::read(&pb).unwrap(), "{}", n);
            }
        }
    }

    fn run_compress(inputs: &[PathBuf], out: &Path, threads: usize, block: usize, pw: Option<&str>) -> CompressStats {
        let job = CompressJob {
            inputs,
            exclude: &[],
            out,
            level: 1,
            threads,
            block,
            password: pw,
        };
        compress_streaming(&job, &mut |_, _| {}, &mut |_, _, _| true).unwrap()
    }

    fn extract_all(arc: &Path, dest: &Path, pw: Option<&str>, threads: usize) -> ExtractStats {
        let src = open_source(arc, pw, &mut |_, _| true).unwrap();
        extract_archive(&*src, Some(dest), false, None, threads, &mut |_, _, _| true).unwrap()
    }

    #[test]
    fn streaming_matches_in_memory_payload() {
        let root = tmpdir("payload");
        sample_tree(&root);
        let (payload, _, _) = archive::build_payload(&[root.join("proj")]).unwrap();
        let plan = archive::plan_files(&[root.join("proj")], &[], 1 << 30, &mut |_| true).unwrap();
        assert_eq!(plan.total as usize, payload.len());
        let mut v = Vec::new();
        plan.read_range(0, plan.total, &mut v).unwrap();
        assert!(v == payload, "virtual payload differs from build_payload");
        // arbitrary sub-ranges
        for &(a, b) in &[(0u64, 10u64), (5, 3000), (plan.total - 7, plan.total), (1000, 60_000)] {
            let mut w = Vec::new();
            plan.read_range(a, b, &mut w).unwrap();
            assert!(w[..] == payload[a as usize..b as usize]);
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn roundtrip_blocks_threads_and_password() {
        let root = tmpdir("rt");
        sample_tree(&root);
        let input = vec![root.join("proj")];
        for (threads, block, pw) in [(1usize, 16_000usize, None), (3, 12_000, None), (2, 10_000, Some("pässwörd")), (1, 1 << 24, None)] {
            let arc = root.join(format!("t{}-{}.dlb", threads, block));
            let st = run_compress(&input, &arc, threads, block, pw);
            assert!(st.out > 0 && st.files == ENTRIES, "{:?}", st);
            assert!(!part_path(&arc).exists());
            // streaming reader
            let dest = root.join(format!("out-{}-{}", threads, block));
            extract_all(&arc, &dest, pw, threads);
            same_tree(&root.join("proj"), &dest.join("proj"));
            // the in-memory reader accepts the same file
            let blob = fs::read(&arc).unwrap();
            let blob = match pw {
                Some(p) => crypto::open(&blob, p).unwrap(),
                None => blob,
            };
            let payload = crate::decompress_payload(&blob, 2, &mut |_| true).unwrap();
            let entries = archive::parse_payload(&payload).unwrap();
            assert_eq!(entries.len() as u64, ENTRIES);
            let d2 = root.join(format!("mem-{}-{}", threads, block));
            archive::extract(&entries, &d2, false).unwrap();
            same_tree(&root.join("proj"), &d2.join("proj"));
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn many_blocks_when_block_is_small() {
        let root = tmpdir("blocks");
        sample_tree(&root);
        let arc = root.join("a.dlb");
        run_compress(&[root.join("proj")], &arc, 2, 8_000, None);
        let blob = fs::read(&arc).unwrap();
        let info = crate::inspect(&blob).unwrap();
        assert!(info.blocks.len() >= 8, "{} blocks", info.blocks.len());
        assert!(info.blocks.iter().all(|b| b.raw <= 32 << 20));
        assert!(info.blocks.iter().all(|b| b.raw <= 8_000));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_password_and_tampering_are_rejected() {
        let root = tmpdir("pw");
        sample_tree(&root);
        let arc = root.join("e.dlb");
        run_compress(&[root.join("proj")], &arc, 1, 20_000, Some("right"));
        let e = open_source(&arc, Some("wrong"), &mut |_, _| true).err().unwrap();
        assert_eq!(e, crypto::ERR_BAD_PASSWORD);
        let e = open_source(&arc, None, &mut |_, _| true).err().unwrap();
        assert_eq!(e, PASSWORD_REQUIRED);
        let mut data = fs::read(&arc).unwrap();
        let mid = data.len() / 2;
        data[mid] ^= 1;
        fs::write(&arc, &data).unwrap();
        let e = open_source(&arc, Some("right"), &mut |_, _| true).err().unwrap();
        assert_eq!(e, crypto::ERR_BAD_PASSWORD);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn list_and_partial_extract_stream() {
        let root = tmpdir("part");
        sample_tree(&root);
        for pw in [None, Some("k")] {
            let arc = root.join("p.dlb");
            run_compress(&[root.join("proj")], &arc, 2, 10_000, pw);
            let l = list_archive(&arc, pw, &mut |_, _| true).unwrap();
            let names: Vec<&str> = l.entries.iter().map(|e| e.name.as_str()).collect();
            assert!(names.contains(&"proj/a.txt") && names.contains(&"proj/zero.bin"));
            let want: Vec<usize> = l
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.name == "proj/src/deep/c.rs" || e.name == "proj/zero.bin" || e.name == "proj/prog")
                .map(|(i, _)| i)
                .collect();
            assert_eq!(want.len(), 3);
            let dest = root.join("sel");
            let _ = fs::remove_dir_all(&dest);
            let src = open_source(&arc, pw, &mut |_, _| true).unwrap();
            let st = extract_archive(&*src, Some(&dest), false, Some(&want), 2, &mut |_, _, _| true).unwrap();
            assert_eq!(st.files, 3);
            assert_eq!(fs::read(dest.join("proj/src/deep/c.rs")).unwrap(), b"fn main() {}\n");
            assert_eq!(fs::read(dest.join("proj/zero.bin")).unwrap().len(), 0);
            assert_eq!(
                fs::read(dest.join("proj/prog")).unwrap(),
                fs::read(root.join("proj/prog")).unwrap()
            );
            assert!(!dest.join("proj/a.txt").exists());
            // verify only
            let st = extract_archive(&*src, None, false, None, 2, &mut |_, _, _| true).unwrap();
            assert_eq!(st.payload, l.total);
            assert!(extract_archive(&*src, None, false, Some(&[999]), 1, &mut |_, _, _| true).is_err());
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn reads_archives_made_in_memory() {
        let root = tmpdir("cross");
        sample_tree(&root);
        let (payload, boundaries, store_from) = archive::build_payload(&[root.join("proj")]).unwrap();
        let mut o = crate::Options::new(1);
        o.store_from = store_from;
        o.threads = 2;
        o.min_block = 20_000;
        let blob = crate::compress_payload(&payload, &boundaries, &o, &mut |_| true).unwrap();
        for pw in [None, Some("x")] {
            let data = match pw {
                Some(p) => crypto::seal(&blob, p).unwrap(),
                None => blob.clone(),
            };
            let arc = root.join("m.dlb");
            fs::write(&arc, &data).unwrap();
            let dest = root.join("m-out");
            let _ = fs::remove_dir_all(&dest);
            extract_all(&arc, &dest, pw, 2);
            same_tree(&root.join("proj"), &dest.join("proj"));
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_archives_fail_cleanly() {
        let root = tmpdir("bad");
        sample_tree(&root);
        let arc = root.join("c.dlb");
        run_compress(&[root.join("proj")], &arc, 1, 20_000, None);
        let good = fs::read(&arc).unwrap();
        let mut x = 12345u32;
        for k in 0..24 {
            let mut d = good.clone();
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            let pos = (x as usize >> 3) % d.len();
            if k % 3 == 0 {
                d.truncate(pos);
            } else {
                d[pos] ^= 1 << (x % 8);
            }
            let bad = root.join("bad.dlb");
            fs::write(&bad, &d).unwrap();
            let dest = root.join("bad-out");
            let _ = fs::remove_dir_all(&dest);
            if let Ok(src) = open_source(&bad, None, &mut |_, _| true) {
                let _ = extract_archive(&*src, Some(&dest), true, None, 2, &mut |_, _, _| true);
            }
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cancel_leaves_no_partial_file() {
        let root = tmpdir("cancel");
        sample_tree(&root);
        let arc = root.join("x.dlb");
        let job = CompressJob {
            inputs: &[root.join("proj")],
            exclude: &[],
            out: &arc,
            level: 1,
            threads: 1,
            block: 8_000,
            password: None,
        };
        let r = compress_streaming(&job, &mut |_, _| {}, &mut |st, _, _| st != Stage::Code);
        assert_eq!(r.err().as_deref(), Some("cancelled"));
        assert!(!arc.exists() && !part_path(&arc).exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn detects_file_changed_during_compression() {
        let root = tmpdir("changed");
        sample_tree(&root);
        let arc = root.join("x.dlb");
        let victim = root.join("proj/a.txt");
        let job = CompressJob {
            inputs: &[root.join("proj")],
            exclude: &[],
            out: &arc,
            level: 1,
            threads: 1,
            block: 1 << 20,
            password: None,
        };
        let mut touched = false;
        let r = compress_streaming(&job, &mut |_, _| {}, &mut |st, _, _| {
            if st == Stage::Code && !touched {
                touched = true;
                fs::write(&victim, b"short now").unwrap();
            }
            true
        });
        assert!(r.is_err(), "modified input must not produce an archive");
        assert!(!arc.exists());
        let _ = fs::remove_dir_all(&root);
    }
}
