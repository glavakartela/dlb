//! Password protection for `.dlb` files, implemented from scratch (no dependencies).
//!
//! Envelope (little endian), wrapped around a complete `DLB2` blob so file names and sizes
//! are hidden too:
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 4 | magic `DLBE` |
//! | 4 | 1 | version (1) |
//! | 5 | 4 | PBKDF2 iterations |
//! | 9 | 16 | salt |
//! | 25 | 12 | nonce |
//! | 37 | n | ciphertext (ChaCha20) |
//! | 37+n | 32 | HMAC-SHA256 tag over everything before it |
//!
//! Keys: PBKDF2-HMAC-SHA256(password, salt, iterations) -> 64 bytes; the first 32 are the
//! ChaCha20 key, the last 32 the HMAC key (encrypt-then-MAC). A wrong password and a damaged
//! file are indistinguishable by design: both fail the tag check.
//!
//! This is a careful implementation checked against the RFC test vectors, but it has not been
//! audited by third parties.

pub const MAGIC_ENC: &[u8; 4] = b"DLBE";
pub const ERR_BAD_PASSWORD: &str = "wrong password or damaged archive";
const VERSION: u8 = 1;
const HEADER: usize = 37;
const TAG: usize = 32;
pub const DEFAULT_ITERATIONS: u32 = 300_000;
const MAX_ITERATIONS: u32 = 20_000_000;

pub fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == MAGIC_ENC
}

// ---------------------------------------------------------------- SHA-256

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone)]
struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    blen: usize,
    total: u64,
}

impl Sha256 {
    fn new() -> Self {
        Sha256 {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0; 64],
            blen: 0,
            total: 0,
        }
    }

    fn block(h: &mut [u32; 8], b: &[u8]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b_, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b_) ^ (a & c) ^ (b_ & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b_;
            b_ = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b_, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.blen > 0 {
            let take = (64 - self.blen).min(data.len());
            self.buf[self.blen..self.blen + take].copy_from_slice(&data[..take]);
            self.blen += take;
            data = &data[take..];
            if self.blen == 64 {
                let b = self.buf;
                Self::block(&mut self.h, &b);
                self.blen = 0;
            }
        }
        while data.len() >= 64 {
            Self::block(&mut self.h, &data[..64]);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.blen = data.len();
        }
    }

    fn finish(mut self) -> [u8; 32] {
        let bits = self.total * 8;
        let mut pad = vec![0x80u8];
        let rem = (self.blen + 1) % 64;
        let zeros = if rem <= 56 { 56 - rem } else { 120 - rem };
        pad.extend(std::iter::repeat(0u8).take(zeros));
        pad.extend_from_slice(&bits.to_be_bytes());
        let total = self.total;
        self.update(&pad);
        self.total = total;
        debug_assert_eq!(self.blen, 0);
        let mut out = [0u8; 32];
        for (i, v) in self.h.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(data);
    s.finish()
}

// ------------------------------------------------------------ HMAC / PBKDF2

/// HMAC-SHA256 with precomputed pads so PBKDF2 does not redo them every iteration.
#[derive(Clone)]
struct Hmac {
    inner: Sha256,
    outer: Sha256,
}

impl Hmac {
    fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&sha256(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ip = [0x36u8; 64];
        let mut op = [0x5cu8; 64];
        for i in 0..64 {
            ip[i] ^= k[i];
            op[i] ^= k[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ip);
        let mut outer = Sha256::new();
        outer.update(&op);
        Hmac { inner, outer }
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut i = self.inner.clone();
        for p in parts {
            i.update(p);
        }
        let ih = i.finish();
        let mut o = self.outer.clone();
        o.update(&ih);
        o.finish()
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    Hmac::new(key).mac(&[data])
}

pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let prf = Hmac::new(password);
    for (bi, chunk) in out.chunks_mut(32).enumerate() {
        let idx = (bi as u32 + 1).to_be_bytes();
        let mut u = prf.mac(&[salt, &idx]);
        let mut t = u;
        for _ in 1..iterations {
            u = prf.mac(&[&u]);
            for k in 0..32 {
                t[k] ^= u[k];
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

// ----------------------------------------------------------------- ChaCha20

fn chacha_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    s[4..12].copy_from_slice(key);
    s[12] = counter;
    s[13..16].copy_from_slice(nonce);
    let mut x = s;
    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            x[$a] = x[$a].wrapping_add(x[$b]);
            x[$d] = (x[$d] ^ x[$a]).rotate_left(16);
            x[$c] = x[$c].wrapping_add(x[$d]);
            x[$b] = (x[$b] ^ x[$c]).rotate_left(12);
            x[$a] = x[$a].wrapping_add(x[$b]);
            x[$d] = (x[$d] ^ x[$a]).rotate_left(8);
            x[$c] = x[$c].wrapping_add(x[$d]);
            x[$b] = (x[$b] ^ x[$c]).rotate_left(7);
        };
    }
    for _ in 0..10 {
        qr!(0, 4, 8, 12);
        qr!(1, 5, 9, 13);
        qr!(2, 6, 10, 14);
        qr!(3, 7, 11, 15);
        qr!(0, 5, 10, 15);
        qr!(1, 6, 11, 12);
        qr!(2, 7, 8, 13);
        qr!(3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&x[i].wrapping_add(s[i]).to_le_bytes());
    }
    out
}

fn words<const N: usize>(b: &[u8]) -> [u32; N] {
    let mut w = [0u32; N];
    for i in 0..N {
        w[i] = u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
    }
    w
}

/// XORs the ChaCha20 keystream (starting at block `counter`) into `data`.
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let k = words::<8>(key);
    let n = words::<3>(nonce);
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let ks = chacha_block(&k, ctr, &n);
        for (d, s) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= s;
        }
        ctr = ctr.wrapping_add(1);
    }
}

// -------------------------------------------------------------- randomness

#[cfg(unix)]
pub fn random_bytes(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|e| format!("no system random source: {}", e))
}

#[cfg(windows)]
pub fn random_bytes(buf: &mut [u8]) -> Result<(), String> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(alg: *mut core::ffi::c_void, buf: *mut u8, len: u32, flags: u32) -> i32;
    }
    // BCRYPT_USE_SYSTEM_PREFERRED_RNG = 2
    let st = unsafe { BCryptGenRandom(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32, 2) };
    if st == 0 {
        Ok(())
    } else {
        Err("no system random source".into())
    }
}

#[cfg(not(any(unix, windows)))]
pub fn random_bytes(_buf: &mut [u8]) -> Result<(), String> {
    Err("no system random source on this platform".into())
}

// -------------------------------------------------------------- envelope

fn derive(password: &str, salt: &[u8], iterations: u32) -> ([u8; 32], [u8; 32]) {
    let mut keys = [0u8; 64];
    pbkdf2_sha256(password.as_bytes(), salt, iterations, &mut keys);
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&keys[..32]);
    mac.copy_from_slice(&keys[32..]);
    (enc, mac)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

pub fn seal_with(
    blob: &[u8],
    password: &str,
    iterations: u32,
    salt: [u8; 16],
    nonce: [u8; 12],
) -> Vec<u8> {
    let (ek, mk) = derive(password, &salt, iterations);
    let mut out = Vec::with_capacity(HEADER + blob.len() + TAG);
    out.extend_from_slice(MAGIC_ENC);
    out.push(VERSION);
    out.extend_from_slice(&iterations.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(blob);
    chacha20_xor(&ek, &nonce, 1, &mut out[HEADER..]);
    let tag = hmac_sha256(&mk, &out);
    out.extend_from_slice(&tag);
    out
}

/// Encrypts a finished `.dlb` blob with a password.
pub fn seal(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if password.is_empty() {
        return Err("empty password".into());
    }
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    random_bytes(&mut salt)?;
    random_bytes(&mut nonce)?;
    Ok(seal_with(blob, password, DEFAULT_ITERATIONS, salt, nonce))
}

/// Decrypts an envelope produced by `seal`. Returns `ERR_BAD_PASSWORD` for a wrong password
/// or any modification of the file.
pub fn open(data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if !is_encrypted(data) {
        return Err("not an encrypted DLB file".into());
    }
    if data.len() < HEADER + TAG {
        return Err("truncated encrypted file".into());
    }
    if data[4] != VERSION {
        return Err("unsupported encryption version".into());
    }
    let iterations = u32::from_le_bytes(data[5..9].try_into().unwrap());
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err("corrupt encryption header".into());
    }
    let salt = &data[9..25];
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[25..37]);
    let (ek, mk) = derive(password, salt, iterations);
    let body_end = data.len() - TAG;
    let tag = hmac_sha256(&mk, &data[..body_end]);
    if !ct_eq(&tag, &data[body_end..]) {
        return Err(ERR_BAD_PASSWORD.into());
    }
    let mut out = data[HEADER..body_end].to_vec();
    chacha20_xor(&ek, &nonce, 1, &mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // multi-block, incremental == one-shot
        let big: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let mut s = Sha256::new();
        for c in big.chunks(37) {
            s.update(c);
        }
        assert_eq!(s.finish(), sha256(&big));
    }

    #[test]
    fn hmac_rfc4231() {
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // test case 6: key longer than the block size
        let key = [0xaau8; 131];
        assert_eq!(
            hex(&hmac_sha256(&key, b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn pbkdf2_vectors() {
        let mut o = [0u8; 32];
        pbkdf2_sha256(b"password", b"salt", 1, &mut o);
        assert_eq!(hex(&o), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
        pbkdf2_sha256(b"password", b"salt", 2, &mut o);
        assert_eq!(hex(&o), "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
        pbkdf2_sha256(b"password", b"salt", 4096, &mut o);
        assert_eq!(hex(&o), "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
        // output longer than one block
        let mut o64 = [0u8; 64];
        pbkdf2_sha256(b"password", b"salt", 1, &mut o64);
        assert_eq!(hex(&o64[..32]), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    }

    #[test]
    fn chacha20_rfc8439() {
        let mut key = [0u8; 32];
        for (i, k) in key.iter_mut().enumerate() {
            *k = i as u8;
        }
        // 2.3.2 block function
        let n = words::<3>(&[0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0]);
        let blk = chacha_block(&words::<8>(&key), 1, &n);
        assert_eq!(hex(&blk[..16]), "10f1e7e4d13b5915500fdd1fa32071c4");
        // 2.4.2 encryption
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut msg = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        chacha20_xor(&key, &nonce, 1, &mut msg);
        assert_eq!(hex(&msg[..16]), "6e2e359a2568f98041ba0728dd0d6981");
        chacha20_xor(&key, &nonce, 1, &mut msg);
        assert!(msg.starts_with(b"Ladies and Gentlemen"));
    }

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        let blob: Vec<u8> = (0..5000u32).map(|i| (i * 31 % 251) as u8).collect();
        let s = seal_with(&blob, "correct horse", 1000, [7; 16], [9; 12]);
        assert!(is_encrypted(&s));
        assert_ne!(&s[HEADER..HEADER + 64], &blob[..64]);
        assert_eq!(open(&s, "correct horse").unwrap(), blob);
        assert_eq!(open(&s, "wrong").unwrap_err(), ERR_BAD_PASSWORD);
        let mut t = s.clone();
        t[HEADER + 100] ^= 1;
        assert_eq!(open(&t, "correct horse").unwrap_err(), ERR_BAD_PASSWORD);
        let mut t = s.clone();
        let n = t.len();
        t[n - 1] ^= 1;
        assert_eq!(open(&t, "correct horse").unwrap_err(), ERR_BAD_PASSWORD);
        assert!(open(&s[..20], "x").is_err());
        // empty blob, random seal
        let e = seal(b"", "pw").unwrap();
        assert_eq!(open(&e, "pw").unwrap(), Vec::<u8>::new());
        assert_ne!(seal(b"x", "pw").unwrap(), seal(b"x", "pw").unwrap());
    }
}
