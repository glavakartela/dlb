//! DLB — context-mixing compressor with its own `.dlb` container format.
//!
//! Container "DLB2" (little endian):
//! ```text
//! 0   4  magic "DLB2"
//! 4   1  flags   (reserved, 0)
//! 5   1  reserved (0)
//! 6   8  payload length
//! 14  4  CRC-32 of the whole payload
//! 18  4  block count N
//! 22  10*N block table: raw_len u32 | comp_len u32 | flags u8 (bit0 = stored) | nbits u8
//! ..     block bodies back to back
//! ```
//! Every block is an independent context-mixing stream, so blocks are compressed and
//! decompressed in parallel. Blocks are at least `min_block` bytes (32 MiB by default) and
//! are cut at file boundaries when possible, so the ratio cost of splitting is negligible
//! for large inputs (the model "cold start" costs only a few KB per block).
//!
//! The older single-stream "DLB1" container is still readable.
//!
//! The payload is a solid archive: `"DLAR"`, entry count, then per entry
//! `name_len u16 | name | size u64 | mode u32`, followed by all file data back to back.

pub mod archive;
pub mod crypto;
pub mod glob;
pub mod cm;
pub mod crc32;
pub mod ffi;
pub mod stream;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::Mutex;
use std::time::Duration;

pub const MAGIC_V1: &[u8; 4] = b"DLB1";
pub const MAGIC: &[u8; 4] = b"DLB2";
/// Release name (shown by `dlb -V` and in the app); the number is `CARGO_PKG_VERSION`.
pub const CODENAME: &str = "Turbo Button";
/// Context-mixing model used by this build, stored in byte 4 of a `DLB2` header. A future model
/// gets the next number and old archives keep decoding with the old one; a reader that does not
/// know the number refuses the archive instead of producing garbage.
pub const MODEL_VERSION: u8 = 0;
pub(crate) const ERR_NEWER: &str = "this archive was made by a newer DLB (unknown model): update the program";
const V1_HEADER: usize = 18;
const V2_HEADER: usize = 22;
const V2_ENTRY: usize = 10;
/// Match tables store 32-bit positions, so every *block* is just under 4 GiB; an archive is a
/// sequence of blocks, so on 64-bit systems it is only limited by RAM (1 TiB here).
pub const MAX_BLOCK: usize = 0xFFFF_0000;
pub const MAX_PAYLOAD: usize = if usize::BITS >= 64 { 1 << 40 } else { MAX_BLOCK };
pub const DEFAULT_MIN_BLOCK: usize = 32 << 20;
/// Size of the blocks used for the stored (incompressible) region.
const STORE_CHUNK: usize = 256 << 20;
const MAX_BLOCKS: usize = 1 << 16;

/// Map level 1..=9 to log2(table slots): 18 (1 MB) .. 26 (256 MB).
pub fn level_to_nbits(level: u32, data_len: usize) -> u32 {
    // level 10 (ultra) uses a table twice as large as level 9
    let want = 17 + level.clamp(1, 9) + (level >= 10) as u32;
    // no point in a table much bigger than the input needs
    let need = (usize::BITS - data_len.max(1).leading_zeros()) + 6;
    want.min(need.max(16))
}

#[derive(Clone, Debug)]
pub struct Options {
    /// 1..=10 (10 = ultra model: more contexts, slowest, strongest); higher uses more memory per thread (see `level_to_nbits`).
    pub level: u32,
    /// Worker threads. Each one needs its own model memory.
    pub threads: usize,
    /// Smallest block size when splitting for threads.
    pub min_block: usize,
    /// Payload offset from which data is known to be incompressible (already compressed
    /// media/archives): it is stored in its own blocks without running the model, which is
    /// much faster and costs nothing in size. `usize::MAX` = no such region.
    pub store_from: usize,
}

impl Options {
    pub fn new(level: u32) -> Self {
        Options { level, threads: 1, min_block: DEFAULT_MIN_BLOCK, store_from: usize::MAX }
    }
}

/// Number of logical CPUs.
pub fn all_cores() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Default thread count: all cores, but at most 8 (memory grows with every thread).
pub fn auto_threads() -> usize {
    all_cores().min(8)
}

/// Returns the end offset of every block. `boundaries` are sorted end offsets of files
/// inside the payload; cuts prefer them so similar data stays together.
pub fn plan_blocks(
    total: usize,
    boundaries: &[usize],
    threads: usize,
    min_block: usize,
) -> Vec<usize> {
    let threads = threads.max(1);
    let min_block = min_block.max(1);
    if total <= MAX_BLOCK && (threads == 1 || total <= 2 * min_block) {
        return vec![total];
    }
    // a block (target + slack) must always fit the 32-bit match positions
    let target = min_block.max(total.div_ceil(threads)).min(MAX_BLOCK / 5 * 4);
    let slack = target / 4;
    let mut ends = Vec::new();
    let mut start = 0usize;
    while total - start > target + slack {
        let want = start + target;
        let idx = boundaries.partition_point(|&b| b < want);
        let cut = if idx < boundaries.len() && boundaries[idx] <= want + slack {
            boundaries[idx]
        } else if idx > 0 && boundaries[idx - 1] > start && boundaries[idx - 1] + slack >= want {
            boundaries[idx - 1]
        } else {
            want
        };
        ends.push(cut);
        start = cut;
    }
    ends.push(total);
    ends
}

/// Runs `work(i, progress)` for i in 0..n on up to `threads` workers and returns the results
/// in order. `sizes[i]` is the amount of progress block `i` reports in total.
/// The calling thread reports aggregate progress through `progress`; returning false from it
/// cancels everything (result `None`).
fn run_blocks<T: Send>(
    sizes: &[usize],
    threads: usize,
    work: &(dyn Fn(usize, &mut dyn FnMut(usize) -> bool) -> Option<T> + Sync),
    progress: &mut dyn FnMut(usize) -> bool,
) -> Option<Vec<T>> {
    let n = sizes.len();
    let workers = threads.clamp(1, n.max(1));
    if workers == 1 {
        let mut out = Vec::with_capacity(n);
        let mut base = 0usize;
        for i in 0..n {
            let b = base;
            out.push(work(i, &mut |d| progress(b + d))?);
            base += sizes[i];
        }
        return Some(out);
    }

    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let alive = AtomicUsize::new(workers);
    let cancel = AtomicBool::new(false);
    let slots: Vec<Mutex<Option<T>>> = (0..n).map(|_| Mutex::new(None)).collect();

    std::thread::scope(|sc| {
        for _ in 0..workers {
            sc.spawn(|| {
                loop {
                    if cancel.load(SeqCst) {
                        break;
                    }
                    let i = next.fetch_add(1, SeqCst);
                    if i >= n {
                        break;
                    }
                    let mut last = 0usize;
                    let r = work(i, &mut |d| {
                        done.fetch_add(d - last, SeqCst);
                        last = d;
                        !cancel.load(SeqCst)
                    });
                    match r {
                        Some(v) => *slots[i].lock().unwrap() = Some(v),
                        None => {
                            cancel.store(true, SeqCst);
                            break;
                        }
                    }
                }
                alive.fetch_sub(1, SeqCst);
            });
        }
        while alive.load(SeqCst) > 0 {
            if !progress(done.load(SeqCst)) {
                cancel.store(true, SeqCst);
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    });

    if cancel.load(SeqCst) {
        return None;
    }
    progress(sizes.iter().sum());
    slots.into_iter().map(|m| m.into_inner().unwrap()).collect()
}

struct BlockOut {
    stored: bool,
    nbits: u8,
    body: Vec<u8>, // empty when stored (the raw bytes are copied from the payload)
}

/// One block of a `.dlb` file as seen by [`inspect`].
#[derive(Clone, Debug)]
pub struct BlockSummary {
    pub raw: usize,
    pub comp: usize,
    pub stored: bool,
    /// log2 of the context table slots (0 for stored blocks)
    pub nbits: u32,
    /// built with the ultra model (level 10)
    pub ultra: bool,
}

/// Container information, read from the headers only (nothing is decompressed).
#[derive(Clone, Debug)]
pub struct Info {
    /// 1 for `DLB1`, 2 for `DLB2`
    pub version: u8,
    pub payload_len: usize,
    pub crc: u32,
    pub blocks: Vec<BlockSummary>,
}

/// Parses the container headers of a plain (not encrypted) `.dlb` blob.
pub fn inspect(blob: &[u8]) -> Result<Info, String> {
    let (len, crc, blocks) = parse_blocks(blob)?;
    Ok(Info {
        version: if &blob[0..4] == MAGIC_V1 { 1 } else { 2 },
        payload_len: len,
        crc,
        blocks: blocks
            .iter()
            .map(|b| BlockSummary {
                raw: b.raw,
                comp: if b.stored { b.raw } else { b.body.len() },
                stored: b.stored,
                nbits: if b.stored { 0 } else { b.nbits & 0x7F },
                ultra: !b.stored && b.nbits & cm::ULTRA_FLAG != 0,
            })
            .collect(),
    })
}

/// Compresses `payload`. `boundaries` are file end offsets inside it (may be empty).
/// `progress` receives bytes of payload processed and returns false to cancel.
pub fn compress_payload(
    payload: &[u8],
    boundaries: &[usize],
    opts: &Options,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Option<Vec<u8>> {
    let sf = opts.store_from.min(payload.len());
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut stored_only: Vec<bool> = Vec::new();
    if sf > 0 || payload.is_empty() {
        let mut s = 0usize;
        for e in plan_blocks(sf, boundaries, opts.threads, opts.min_block) {
            ranges.push((s, e));
            stored_only.push(false);
            s = e;
        }
    }
    let mut s = sf;
    while s < payload.len() {
        let e = (s + STORE_CHUNK).min(payload.len());
        ranges.push((s, e));
        stored_only.push(true);
        s = e;
    }
    let sizes: Vec<usize> = ranges.iter().map(|&(a, b)| b - a).collect();
    let level = opts.level;

    let work = |i: usize, prog: &mut dyn FnMut(usize) -> bool| -> Option<BlockOut> {
        let (a, b) = ranges[i];
        if stored_only[i] {
            if !prog(b - a) {
                return None;
            }
            return Some(BlockOut { stored: true, nbits: 0, body: Vec::new() });
        }
        let data = &payload[a..b];
        let nbits = level_to_nbits(level, data.len());
        let nb = (nbits | if level >= 10 { cm::ULTRA_FLAG } else { 0 }) as u8;
        let body = cm::cm_compress(data, nb as u32, prog)?;
        Some(if body.len() >= data.len() {
            BlockOut { stored: true, nbits: nb, body: Vec::new() }
        } else {
            BlockOut { stored: false, nbits: nb, body }
        })
    };
    let blocks = run_blocks(&sizes, opts.threads, &work, progress)?;

    let body_total: usize = blocks
        .iter()
        .zip(&sizes)
        .map(|(b, &raw)| if b.stored { raw } else { b.body.len() })
        .sum();
    let mut out = Vec::with_capacity(V2_HEADER + V2_ENTRY * blocks.len() + body_total);
    out.extend_from_slice(MAGIC);
    out.push(MODEL_VERSION);
    out.push(0);
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&crc32::crc32(payload).to_le_bytes());
    out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
    for (b, &raw) in blocks.iter().zip(&sizes) {
        let comp = if b.stored { raw } else { b.body.len() };
        out.extend_from_slice(&(raw as u32).to_le_bytes());
        out.extend_from_slice(&(comp as u32).to_le_bytes());
        out.push(b.stored as u8);
        out.push(b.nbits);
    }
    for (b, &(a, e)) in blocks.iter().zip(&ranges) {
        if b.stored {
            out.extend_from_slice(&payload[a..e]);
        } else {
            out.extend_from_slice(&b.body);
        }
    }
    Some(out)
}

struct BlockInfo<'a> {
    raw: usize,
    stored: bool,
    nbits: u32,
    body: &'a [u8],
}

fn parse_blocks(blob: &[u8]) -> Result<(usize, u32, Vec<BlockInfo<'_>>), String> {
    if blob.len() < 4 {
        return Err("not a DLB file (bad magic)".into());
    }
    let corrupt = |m: &str| Err(format!("corrupt header: {}", m));
    let check_nbits = |n: u32| (10..=30).contains(&(n & 0x7F));

    if &blob[0..4] == MAGIC_V1 {
        if blob.len() < V1_HEADER {
            return corrupt("truncated");
        }
        let stored = blob[4] & 1 != 0;
        let nbits = blob[5] as u32;
        let len = u64::from_le_bytes(blob[6..14].try_into().unwrap());
        let crc = u32::from_le_bytes(blob[14..18].try_into().unwrap());
        let body = &blob[V1_HEADER..];
        if len > MAX_PAYLOAD as u64 {
            return corrupt("unsupported length");
        }
        if !stored && !check_nbits(nbits) {
            return corrupt("nbits");
        }
        if stored && body.len() as u64 != len {
            return Err("corrupt stored block".into());
        }
        return Ok((
            len as usize,
            crc,
            vec![BlockInfo { raw: len as usize, stored, nbits, body }],
        ));
    }
    if &blob[0..4] != MAGIC {
        return Err("not a DLB file (bad magic)".into());
    }
    if blob.len() < V2_HEADER {
        return corrupt("truncated");
    }
    if blob[4] > MODEL_VERSION {
        return Err(ERR_NEWER.into());
    }
    let total = u64::from_le_bytes(blob[6..14].try_into().unwrap());
    let crc = u32::from_le_bytes(blob[14..18].try_into().unwrap());
    let n = u32::from_le_bytes(blob[18..22].try_into().unwrap()) as usize;
    if total > MAX_PAYLOAD as u64 {
        return corrupt("unsupported length");
    }
    if n == 0 || n > MAX_BLOCKS || blob.len() < V2_HEADER + V2_ENTRY * n {
        return corrupt("block table");
    }
    let mut pos = V2_HEADER + V2_ENTRY * n;
    let mut raw_sum = 0usize;
    let mut blocks = Vec::with_capacity(n);
    for k in 0..n {
        let e = &blob[V2_HEADER + V2_ENTRY * k..V2_HEADER + V2_ENTRY * (k + 1)];
        let raw = u32::from_le_bytes(e[0..4].try_into().unwrap()) as usize;
        let comp = u32::from_le_bytes(e[4..8].try_into().unwrap()) as usize;
        let stored = e[8] & 1 != 0;
        let nbits = e[9] as u32;
        if pos.checked_add(comp).map_or(true, |end| end > blob.len()) {
            return Err("truncated file".into());
        }
        if stored && comp != raw {
            return Err("corrupt stored block".into());
        }
        if !stored && !check_nbits(nbits) {
            return corrupt("nbits");
        }
        // a CM stream cannot shrink data more than ~400000:1; reject absurd lengths early
        if !stored && (raw as u64) > (comp as u64 + 8) * 400_000 {
            return corrupt("length inconsistent with stream size");
        }
        raw_sum += raw;
        blocks.push(BlockInfo { raw, stored, nbits, body: &blob[pos..pos + comp] });
        pos += comp;
    }
    if raw_sum as u64 != total {
        return corrupt("block sizes do not add up");
    }
    Ok((total as usize, crc, blocks))
}

/// Entry table of a plain `.dlb` blob, read by decoding only the start of the first block, so
/// listing an archive takes a moment even when its data is gigabytes. Returns the entries, the
/// payload length and the header length (where the first entry's data starts).
pub fn list_entries(blob: &[u8]) -> Result<(Vec<archive::Entry>, usize, usize), String> {
    let (total, _crc, blocks) = parse_blocks(blob)?;
    let b0 = blocks.first().ok_or_else(|| "corrupt header: no blocks".to_string())?;
    let mut stream = if b0.stored { None } else { Some(cm::CmStream::new(b0.body, b0.nbits)) };
    let mut want = 4096usize;
    loop {
        let buf: &[u8] = match stream.as_mut() {
            Some(s) => s.extend_to(want, b0.raw),
            None => b0.body,
        };
        match archive::parse_header(buf)? {
            archive::HeaderParse::Done(entries, hl) => {
                let end = entries.last().map_or(hl as u64, |e| e.offset + e.size);
                if end > total as u64 {
                    return Err("corrupt archive payload".into());
                }
                return Ok((entries, total, hl));
            }
            archive::HeaderParse::NeedMore(n) => {
                if buf.len() >= b0.raw || n > b0.raw {
                    // the entry table spans several blocks: decode everything instead
                    let payload = decompress_payload(blob, auto_threads(), &mut |_| true)?;
                    let (entries, hl) = match archive::parse_header(&payload)? {
                        archive::HeaderParse::Done(e, h) => (e, h),
                        archive::HeaderParse::NeedMore(_) => {
                            return Err("corrupt archive payload".into())
                        }
                    };
                    return Ok((entries, total, hl));
                }
                want = n.max(want.saturating_mul(2)).min(b0.raw);
            }
        }
    }
}

/// Decodes only what is needed to read the given payload byte ranges: blocks that contain none
/// of them are skipped and the others are decoded up to the last needed byte. The result has
/// the full payload size; bytes that were not needed are zero. The whole-payload CRC cannot be
/// checked here (entries carry their own CRC-32 for that).
pub fn decompress_ranges(
    blob: &[u8],
    threads: usize,
    ranges: &[(usize, usize)],
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>, String> {
    let (total, _crc, blocks) = parse_blocks(blob)?;
    let mut need = vec![0usize; blocks.len()];
    let mut start = 0usize;
    for (i, b) in blocks.iter().enumerate() {
        let end = start + b.raw;
        for &(a, e) in ranges {
            if e > a && a < end && e > start {
                need[i] = need[i].max(e.min(end) - start);
            }
        }
        start = end;
    }
    let mut out = vec![0u8; total];
    {
        let mut slots: Vec<Mutex<&mut [u8]>> = Vec::with_capacity(blocks.len());
        let mut rest: &mut [u8] = &mut out;
        for b in &blocks {
            let (head, tail) = rest.split_at_mut(b.raw);
            slots.push(Mutex::new(head));
            rest = tail;
        }
        let work = |i: usize, prog: &mut dyn FnMut(usize) -> bool| -> Option<()> {
            let n = need[i];
            if n == 0 {
                return Some(());
            }
            let b = &blocks[i];
            let mut dst = slots[i].lock().unwrap();
            if b.stored {
                dst[..n].copy_from_slice(&b.body[..n]);
                prog(n);
                Some(())
            } else if cm::cm_decompress(b.body, &mut dst[..n], b.nbits, prog) {
                Some(())
            } else {
                None
            }
        };
        run_blocks(&need, threads, &work, progress).ok_or_else(|| "cancelled".to_string())?;
    }
    Ok(out)
}

/// Extracts only the entries whose index is in `select` (indices into [`list_entries`]).
/// Decodes just the data those entries need. Every extracted file is checked against its own
/// CRC-32 (archives written before 0.12 have none).
pub fn extract_selected(
    blob: &[u8],
    threads: usize,
    select: &[usize],
    dest: &std::path::Path,
    force: bool,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<usize, String> {
    let (entries, _total, header_len) = list_entries(blob)?;
    let mut ranges = vec![(0usize, header_len)];
    let mut names = std::collections::HashSet::new();
    for &i in select {
        let e = entries.get(i).ok_or_else(|| "selection out of range".to_string())?;
        ranges.push((e.offset as usize, (e.offset + e.size) as usize));
        names.insert(e.name.clone());
    }
    let payload = decompress_ranges(blob, threads, &ranges, progress)?;
    let all = archive::parse_payload(&payload)?;
    archive::extract_with(&all, dest, force, &|e| names.contains(&e.name))
}

/// Decompresses a `.dlb` blob (DLB1 or DLB2) using up to `threads` workers.
pub fn decompress_payload(
    blob: &[u8],
    threads: usize,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>, String> {
    let (total, crc, blocks) = parse_blocks(blob)?;
    let mut out = vec![0u8; total];
    {
        // hand every block its own disjoint slice of the output
        let mut slots: Vec<Mutex<&mut [u8]>> = Vec::with_capacity(blocks.len());
        let mut rest: &mut [u8] = &mut out;
        for b in &blocks {
            let (head, tail) = rest.split_at_mut(b.raw);
            slots.push(Mutex::new(head));
            rest = tail;
        }
        let sizes: Vec<usize> = blocks.iter().map(|b| b.raw).collect();
        let work = |i: usize, prog: &mut dyn FnMut(usize) -> bool| -> Option<()> {
            let b = &blocks[i];
            let mut dst = slots[i].lock().unwrap();
            if b.stored {
                dst.copy_from_slice(b.body);
                prog(b.raw);
                Some(())
            } else if cm::cm_decompress(b.body, &mut dst, b.nbits, prog) {
                Some(())
            } else {
                None
            }
        };
        run_blocks(&sizes, threads, &work, progress).ok_or_else(|| "cancelled".to_string())?;
    }
    if crc32::crc32(&out) != crc {
        return Err("CRC mismatch: data is corrupt".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(n: usize) -> Vec<u8> {
        let mut x = 1u32;
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            v.extend_from_slice(format!("line {} value={}\n", x >> 20, x % 97).as_bytes());
        }
        v.truncate(n);
        v
    }

    fn rt(data: &[u8], threads: usize, min_block: usize) -> (usize, usize) {
        let opts = Options { level: 3, threads, min_block, store_from: usize::MAX };
        let c = compress_payload(data, &[], &opts, &mut |_| true).unwrap();
        let blocks = u32::from_le_bytes(c[18..22].try_into().unwrap()) as usize;
        for dt in [1, 3] {
            let d = decompress_payload(&c, dt, &mut |_| true).unwrap();
            assert_eq!(d, data);
        }
        (c.len(), blocks)
    }

    #[test]
    fn unknown_model_version_is_rejected_cleanly() {
        let data = text(5000);
        let mut blob = compress_payload(&data, &[], &Options::new(1), &mut |_| true).unwrap();
        assert_eq!(blob[4], MODEL_VERSION);
        assert_eq!(decompress_payload(&blob, 1, &mut |_| true).unwrap(), data);
        blob[4] = MODEL_VERSION + 1;
        let e = decompress_payload(&blob, 1, &mut |_| true).unwrap_err();
        assert_eq!(e, ERR_NEWER);
        assert_eq!(inspect(&blob).err().as_deref(), Some(ERR_NEWER));
    }

    #[test]
    fn roundtrip_small() {
        rt(b"", 1, DEFAULT_MIN_BLOCK);
        rt(b"a", 4, DEFAULT_MIN_BLOCK);
        rt(b"hello hello hello hello hello world", 1, DEFAULT_MIN_BLOCK);
    }

    /// Poor man's fuzzing: damaged or random input must produce an error (or, for harmless
    /// changes, a result), never a panic, hang or huge allocation.
    #[test]
    fn corrupt_input_never_panics() {
        let mut x = 0xDEAD_BEEFu32;
        let mut rnd = |m: usize| -> usize {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as usize % m
        };
        let data: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8 ^ (i / 97) as u8).collect();
        let opts = Options { level: 3, threads: 2, min_block: 8_000, store_from: usize::MAX };
        let blob = compress_payload(&data, &[], &opts, &mut |_| true).unwrap();
        for round in 0..300 {
            let mut b = blob.clone();
            match round % 4 {
                0 => {
                    for _ in 0..1 + rnd(4) {
                        let i = rnd(b.len());
                        b[i] ^= 1 << rnd(8);
                    }
                }
                1 => b.truncate(rnd(b.len())),
                2 => {
                    let i = rnd(40.min(b.len()));
                    b[i] = rnd(256) as u8; // header / block table damage
                }
                _ => b = (0..rnd(200)).map(|_| rnd(256) as u8).collect(),
            }
            let _ = decompress_payload(&b, 2, &mut |_| true);
            let _ = archive::parse_payload(&b);
            let _ = crypto::open(&b, "pw");
        }
    }

    #[test]
    fn incompressible_tail_is_stored_without_modelling() {
        let mut x = 99u32;
        let mut payload: Vec<u8> = (0..40_000u32).map(|i| (i % 13) as u8).collect();
        let sf = payload.len();
        payload.extend((0..60_000).map(|_| {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            (x >> 24) as u8
        }));
        for threads in [1usize, 3] {
            let opts = Options { level: 3, threads, min_block: 10_000, store_from: sf };
            let blob = compress_payload(&payload, &[], &opts, &mut |_| true).unwrap();
            let (_, _, blocks) = parse_blocks(&blob).unwrap();
            assert!(blocks.last().unwrap().stored);
            assert!(!blocks[0].stored);
            assert_eq!(decompress_payload(&blob, threads, &mut |_| true).unwrap(), payload);
            // store_from beyond the end / at 0 behave
            for sf in [0usize, payload.len(), usize::MAX] {
                let o = Options { store_from: sf, ..opts.clone() };
                let b = compress_payload(&payload, &[], &o, &mut |_| true).unwrap();
                assert_eq!(decompress_payload(&b, 2, &mut |_| true).unwrap(), payload);
            }
        }
    }

    #[test]
    fn list_and_partial_extract() {
        let d = std::env::temp_dir().join(format!("dlb_part_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("in/sub")).unwrap();
        for i in 0..40 {
            let body: String = (0..300).map(|k| format!("file {} line {}\n", i, k % 7)).collect();
            std::fs::write(d.join(format!("in/f{:02}.txt", i)), body).unwrap();
        }
        std::fs::write(d.join("in/sub/z.bin"), vec![7u8; 5000]).unwrap();
        let (payload, bounds, sf) = archive::build_payload(&[d.join("in")]).unwrap();
        // several blocks, so that partial decoding has something to skip
        let opts = Options { level: 3, threads: 2, min_block: 40_000, store_from: sf };
        let blob = compress_payload(&payload, &bounds, &opts, &mut |_| true).unwrap();
        let (entries, total, hl) = list_entries(&blob).unwrap();
        assert_eq!(total, payload.len());
        assert_eq!(entries.len(), 41);
        assert_eq!(entries[0].offset as usize, hl);
        let pick: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.name.ends_with("f03.txt") || e.name.ends_with("z.bin"))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(pick.len(), 2);
        let out = d.join("out");
        let n = extract_selected(&blob, 2, &pick, &out, false, &mut |_| true).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            std::fs::read(out.join("in/f03.txt")).unwrap(),
            std::fs::read(d.join("in/f03.txt")).unwrap()
        );
        assert!(!out.join("in/f04.txt").exists());
        // a damaged byte inside a selected entry is caught by its own CRC
        let mut bad = payload.clone();
        let e = &entries[pick[0]];
        bad[e.offset as usize + 5] ^= 0x55;
        let blob2 = compress_payload(&bad, &bounds, &opts, &mut |_| true).unwrap();
        let err = extract_selected(&blob2, 1, &pick[..1], &d.join("out2"), false, &mut |_| true);
        assert!(err.unwrap_err().contains("checksum"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn roundtrip_ultra_level() {
        let mut data = Vec::new();
        for i in 0..3000u32 {
            data.extend_from_slice(format!("line {} value={} status=ok\n", i, i * 7 % 101).as_bytes());
        }
        rt(&data, 10, DEFAULT_MIN_BLOCK);
        rt(&data, 10, 20_000); // several ultra blocks
    }

    #[test]
    fn roundtrip_pseudo_random_and_repetitive() {
        let mut x = 12345u32;
        let rnd: Vec<u8> = (0..20000)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            })
            .collect();
        let (c, _) = rt(&rnd, 1, DEFAULT_MIN_BLOCK);
        assert!(c <= rnd.len() + V2_HEADER + V2_ENTRY); // stored fallback
        let rep = vec![b'x'; 100_000];
        assert!(rt(&rep, 1, DEFAULT_MIN_BLOCK).0 < 200);
    }

    #[test]
    fn parallel_blocks_roundtrip() {
        let data = text(700_000);
        let (single, nb1) = rt(&data, 1, 50_000);
        let (multi, nb4) = rt(&data, 4, 50_000);
        assert_eq!(nb1, 1);
        assert!(nb4 >= 4, "expected at least 4 blocks, got {}", nb4);
        // splitting costs only a little on this data
        assert!(multi < single + single / 5, "single {} multi {}", single, multi);
    }

    #[test]
    fn mixed_stored_and_compressed_blocks() {
        let mut x = 99u32;
        let mut data: Vec<u8> = (0..120_000)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            })
            .collect();
        data.extend(text(120_000));
        let (_, nb) = rt(&data, 4, 30_000);
        assert!(nb >= 4);
    }

    #[test]
    fn huge_inputs_are_split_into_valid_blocks() {
        // no allocation: only the plan is checked
        for threads in [1usize, 2, 16] {
            let total = 10usize << 30; // 10 GiB (64-bit only)
            if usize::BITS < 64 {
                return;
            }
            let ends = plan_blocks(total, &[], threads, DEFAULT_MIN_BLOCK);
            let mut prev = 0usize;
            for &e in &ends {
                assert!(e - prev <= MAX_BLOCK, "block too large with {} threads", threads);
                assert!(e > prev);
                prev = e;
            }
            assert_eq!(prev, total);
            assert!(ends.len() >= 3);
        }
    }

    #[test]
    fn plan_blocks_respects_boundaries() {
        let ends = plan_blocks(1000, &[100, 300, 520, 700, 900, 1000], 4, 100);
        assert_eq!(ends, vec![300, 520, 770, 1000]);
        assert_eq!(plan_blocks(1000, &[], 1, 100), vec![1000]);
        assert_eq!(plan_blocks(150, &[], 8, 100), vec![150]); // too small to split
        assert_eq!(plan_blocks(0, &[], 8, 100), vec![0]);
        // every plan is strictly increasing and ends at total
        for threads in 2..9 {
            let e = plan_blocks(10_000_003, &[], threads, 1000);
            assert_eq!(*e.last().unwrap(), 10_000_003);
            assert!(e.windows(2).all(|w| w[0] < w[1]));
        }
    }

    #[test]
    fn detects_corruption() {
        let opts = Options::new(2);
        let mut c = compress_payload(&vec![7u8; 5000], &[], &opts, &mut |_| true).unwrap();
        c[V2_HEADER + V2_ENTRY] ^= 0x55; // first byte of the first block body
        let r = decompress_payload(&c, 1, &mut |_| true);
        assert!(r.is_err() || r.unwrap() != vec![7u8; 5000]);
        // garbage and truncation
        assert!(decompress_payload(b"nope", 1, &mut |_| true).is_err());
        let ok = compress_payload(b"abcabcabc", &[], &opts, &mut |_| true).unwrap();
        assert!(decompress_payload(&ok[..ok.len() - 5], 1, &mut |_| true).is_err());
    }

    #[test]
    fn cancel_stops_work() {
        let data = text(600_000);
        for threads in [1, 3] {
            let opts = Options { level: 3, threads, min_block: 50_000, store_from: usize::MAX };
            let mut calls = 0;
            let r = compress_payload(&data, &[], &opts, &mut |_| {
                calls += 1;
                calls < 2
            });
            assert!(r.is_none(), "threads={}", threads);
        }
    }
}
