//! CRC-32 (IEEE 802.3), table driven, no dependencies.

use std::sync::OnceLock;

fn table() -> &'static [u32; 256] {
    static T: OnceLock<[u32; 256]> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u32; 256];
        for i in 0..256u32 {
            let mut c = i;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            t[i as usize] = c;
        }
        t
    })
}

/// Incremental CRC-32 for data that arrives in pieces.
#[derive(Clone)]
pub struct Crc32 {
    c: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    pub fn new() -> Self {
        Crc32 { c: 0xFFFF_FFFF }
    }
    pub fn update(&mut self, data: &[u8]) {
        let t = table();
        let mut c = self.c;
        for &b in data {
            c = t[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
        }
        self.c = c;
    }
    pub fn finish(&self) -> u32 {
        self.c ^ 0xFFFF_FFFF
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.finish()
}

fn gf2_times(mat: &[u32; 32], mut v: u32) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while v != 0 {
        if v & 1 != 0 {
            sum ^= mat[i];
        }
        v >>= 1;
        i += 1;
    }
    sum
}

fn gf2_square(sq: &mut [u32; 32], mat: &[u32; 32]) {
    for n in 0..32 {
        sq[n] = gf2_times(mat, mat[n]);
    }
}

/// CRC of `A ++ B` from `crc(A)`, `crc(B)` and `len(B)` (zlib's crc32_combine). Lets blocks be
/// checksummed independently, in any order, and merged afterwards.
pub fn combine(mut crc1: u32, crc2: u32, mut len2: u64) -> u32 {
    if len2 == 0 {
        return crc1;
    }
    let mut even = [0u32; 32];
    let mut odd = [0u32; 32];
    odd[0] = 0xEDB8_8320;
    let mut row = 1u32;
    for n in 1..32 {
        odd[n] = row;
        row <<= 1;
    }
    gf2_square(&mut even, &odd);
    gf2_square(&mut odd, &even);
    loop {
        gf2_square(&mut even, &odd);
        if len2 & 1 != 0 {
            crc1 = gf2_times(&even, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
        gf2_square(&mut odd, &even);
        if len2 & 1 != 0 {
            crc1 = gf2_times(&odd, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
    }
    crc1 ^ crc2
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn combine_matches_concatenation() {
        let a: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        let b: Vec<u8> = (0..777u32).map(|i| (i * 13 + 1) as u8).collect();
        let mut ab = a.clone();
        ab.extend_from_slice(&b);
        assert_eq!(combine(crc32(&a), crc32(&b), b.len() as u64), crc32(&ab));
        assert_eq!(combine(0, crc32(&b), b.len() as u64), crc32(&b));
        assert_eq!(combine(crc32(&a), 0, 0), crc32(&a));
        let mut inc = Crc32::new();
        inc.update(&a);
        inc.update(&b);
        assert_eq!(inc.finish(), crc32(&ab));
    }
}
