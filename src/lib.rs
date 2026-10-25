//! DLB — context-mixing compressor with its own `.dlb` container format.
//!
//! Container layout (little endian):
//! ```text
//! 0   4  magic "DLB1"
//! 4   1  flags   (bit0 = stored / not compressed)
//! 5   1  nbits   (log2 of context table slots; decoder needs the same value)
//! 6   8  payload length
//! 14  4  CRC-32 of payload
//! 18  .. compressed (or stored) payload
//! ```
//! The payload is a solid archive: `"DLAR"`, entry count, then per entry
//! `name_len u16 | name | size u64 | mode u32`, followed by all file data back to back.

pub mod archive;
pub mod cm;
pub mod crc32;
pub mod ffi;

pub const MAGIC: &[u8; 4] = b"DLB1";
pub const HEADER_LEN: usize = 18;
/// Match tables store 32-bit positions, so one archive is limited to just under 4 GiB.
pub const MAX_PAYLOAD: usize = 0xFFFF_0000;

/// Map level 1..=9 to log2(table slots): 18 (1 MB) .. 26 (256 MB).
pub fn level_to_nbits(level: u32, data_len: usize) -> u32 {
    let want = 17 + level.clamp(1, 9);
    // no point in a table much bigger than the input needs
    let need = (usize::BITS - data_len.max(1).leading_zeros()) + 6;
    want.min(need.max(16))
}

pub fn compress_payload(
    payload: &[u8],
    level: u32,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Option<Vec<u8>> {
    let nbits = level_to_nbits(level, payload.len());
    let body = cm::cm_compress(payload, nbits, progress)?;
    let (flags, body): (u8, &[u8]) = if body.len() >= payload.len() {
        (1, payload)
    } else {
        (0, &body)
    };
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(MAGIC);
    out.push(flags);
    out.push(nbits as u8);
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&crc32::crc32(payload).to_le_bytes());
    out.extend_from_slice(body);
    Some(out)
}

pub fn decompress_payload(
    blob: &[u8],
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>, String> {
    if blob.len() < HEADER_LEN || &blob[0..4] != MAGIC {
        return Err("not a DLB file (bad magic)".into());
    }
    let flags = blob[4];
    let nbits = blob[5] as u32;
    if !(10..=30).contains(&nbits) {
        return Err(format!("corrupt header: nbits={}", nbits));
    }
    let len = u64::from_le_bytes(blob[6..14].try_into().unwrap());
    let crc = u32::from_le_bytes(blob[14..18].try_into().unwrap());
    if len > (1u64 << 40) {
        return Err("corrupt header: absurd length".into());
    }
    let len = len as usize;
    let body = &blob[HEADER_LEN..];
    // a CM stream cannot shrink data more than ~400000:1; reject absurd lengths early
    if flags & 1 == 0 && (len as u64) > (body.len() as u64 + 8) * 400_000 {
        return Err("corrupt header: length inconsistent with stream size".into());
    }
    let out = if flags & 1 != 0 {
        if body.len() != len {
            return Err("corrupt stored block".into());
        }
        body.to_vec()
    } else {
        cm::cm_decompress(body, len, nbits, progress).ok_or_else(|| "cancelled".to_string())?
    };
    if crc32::crc32(&out) != crc {
        return Err("CRC mismatch: data is corrupt".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(data: &[u8]) -> usize {
        let c = compress_payload(data, 3, &mut |_| true).unwrap();
        let d = decompress_payload(&c, &mut |_| true).unwrap();
        assert_eq!(d, data);
        c.len()
    }

    #[test]
    fn roundtrip_small() {
        rt(b"");
        rt(b"a");
        rt(b"hello hello hello hello hello world");
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
        let c = rt(&rnd);
        assert!(c <= rnd.len() + HEADER_LEN); // stored fallback
        let rep = vec![b'x'; 100_000];
        assert!(rt(&rep) < 200);
    }

    #[test]
    fn detects_corruption() {
        let mut c = compress_payload(&vec![7u8; 5000], 2, &mut |_| true).unwrap();
        let n = c.len();
        c[n / 2 + 1] ^= 0x55;
        let r = decompress_payload(&c, &mut |_| true);
        assert!(r.is_err() || r.unwrap() != vec![7u8; 5000]);
    }
}
