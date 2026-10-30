//! DLB context-mixing core.
//!
//! A bitwise predictor in the PAQ/lpaq family:
//!   * 12 hashed contexts (orders 0-6, 8, two word contexts, two sparse contexts)
//!     sharing one big table of 32-bit slots (8-bit check | 6-bit count | 18-bit probability),
//!   * two long-range match models (min length 20 and 6),
//!   * three first-layer mixers selected by different contexts + a second-layer mixer,
//!   * two APM/SSE stages,
//!   * 32-bit carry-less binary arithmetic coder with 16-bit probabilities.
//!
//! Everything is integer arithmetic, so output is bit-identical on every platform
//! (x86, x64, arm, arm64; Linux, Windows, Android).

const NCTX_BASE: usize = 12;
const NCTX_MAX: usize = 18; // "ultra" model adds 6 contexts
const NM: usize = 2;
const NIN_MAX: usize = NCTX_MAX * 2 + NM * 2 + 1;
const NSEL_BASE: usize = 3;
const NSEL_MAX: usize = 4; // "ultra" model adds a 4th mixer selector

/// Bit 7 of the stored `nbits` byte marks the ultra model.
pub const ULTRA_FLAG: u32 = 0x80;

const LR1: i32 = 4;
const LR2: i32 = 2;

#[inline]
fn squash(d: i32) -> i32 {
    const T: [i32; 33] = [
        1, 2, 3, 6, 10, 16, 27, 45, 73, 120, 194, 310, 488, 747, 1101, 1546, 2047, 2549, 2994,
        3348, 3607, 3785, 3901, 3975, 4022, 4050, 4068, 4079, 4085, 4089, 4092, 4093, 4094,
    ];
    if d > 2047 {
        return 4095;
    }
    if d < -2047 {
        return 0;
    }
    let w = d & 127;
    let i = ((d >> 7) + 16) as usize;
    (T[i] * (128 - w) + T[i + 1] * w + 64) >> 7
}

fn build_stretch() -> Vec<i16> {
    let mut st = vec![0i16; 4096];
    let mut pi = 0usize;
    for x in -2047..=2047i32 {
        let v = squash(x) as usize;
        for i in pi..=v {
            st[i] = x as i16;
        }
        pi = v + 1;
    }
    for i in pi..4096 {
        st[i] = 2047;
    }
    st
}

fn build_rt() -> Vec<i32> {
    // reciprocal table: 65536 / (n + 1.5)
    (0..1024).map(|n| (65536.0 / (n as f64 + 1.5)) as i32).collect()
}

#[inline]
fn hc(i: u32, v: u32) -> u32 {
    let mut h = v.wrapping_mul(0x9E37_79B1) ^ i.wrapping_mul(0x85EB_CA77);
    h ^= h >> 15;
    h = h.wrapping_mul(0x2C1B_3C6D);
    h ^= h >> 12;
    h
}

#[inline]
fn lb(len: usize) -> usize {
    if len < 16 {
        len
    } else if len < 32 {
        16 + (len - 16) / 4
    } else if len < 64 {
        20 + (len - 32) / 8
    } else if len < 512 {
        24 + (len - 64) / 64
    } else {
        31
    }
}

struct Apm {
    t: Vec<u16>,
    idx: usize,
}

impl Apm {
    fn new(n: usize) -> Self {
        let mut t = vec![0u16; n * 33];
        for i in 0..n {
            for j in 0..33 {
                t[i * 33 + j] = (squash((j as i32 - 16) * 128) * 16) as u16;
            }
        }
        Apm { t, idx: 0 }
    }
    #[inline]
    fn pp(&mut self, st: i32, cx: usize) -> u32 {
        let s = st + 2048;
        let lo = (s >> 7) as usize;
        let w = (s & 127) as u32;
        self.idx = lo + cx * 33;
        (self.t[self.idx] as u32 * (128 - w) + self.t[self.idx + 1] as u32 * w) >> 7
    }
    #[inline]
    fn update(&mut self, y: u32) {
        let g = ((y << 16) + (y << 7)) as i32 - (y as i32) * 2;
        for k in [self.idx, self.idx + 1] {
            let v = self.t[k] as i32;
            self.t[k] = (v + ((g - v) >> 7)) as u16;
        }
    }
}

struct MatchModel {
    minlen: usize,
    ht: Vec<u32>,
    hbits: u32,
    ptr: usize,
    len: usize,
    pb: u32,
    sm: Vec<u32>,
    smi: usize,
    exp: u32,
    active: bool,
}

impl MatchModel {
    fn new(minlen: usize, hbits: u32) -> Self {
        MatchModel {
            minlen,
            ht: vec![0u32; 1usize << hbits],
            hbits,
            ptr: 0,
            len: 0,
            pb: 0,
            sm: vec![1u32 << 31; 64],
            smi: 0,
            exp: 0,
            active: false,
        }
    }

    fn update_byte(&mut self, hist: &[u8]) {
        let pos = hist.len();
        if self.len > 0 && hist[self.ptr] == hist[pos - 1] {
            self.len = (self.len + 1).min(65535);
            self.ptr += 1;
        } else {
            self.len = 0;
        }
        if pos >= self.minlen {
            let mut h: u32 = 0;
            for &b in &hist[pos - self.minlen..] {
                h = h.wrapping_mul(0x2F0B_4A27).wrapping_add(b as u32 + 1);
            }
            let h = (h.wrapping_mul(0x9E37_79B1) >> (32 - self.hbits)) as usize;
            if self.len == 0 {
                let cand = self.ht[h] as usize;
                if cand > 0 {
                    let mut l = 0usize;
                    while l < 400 && l < cand && hist[cand - 1 - l] == hist[pos - 1 - l] {
                        l += 1;
                    }
                    if l >= self.minlen {
                        self.len = l;
                        self.ptr = cand;
                    }
                }
            }
            self.ht[h] = pos as u32;
        }
        if self.len > 0 {
            self.pb = hist[self.ptr] as u32;
        }
    }

    #[inline]
    fn predict(&mut self, c0: u32, bitpos: u32, stretch: &[i16], x: &mut [i32]) {
        if self.len > 0 && ((self.pb | 256) >> (8 - bitpos)) == c0 {
            let e = (self.pb >> (7 - bitpos)) & 1;
            self.exp = e;
            self.active = true;
            self.smi = lb(self.len) * 2 + e as usize;
            let p12 = (self.sm[self.smi] >> 20) as usize;
            x[0] = stretch[p12] as i32;
            let m = (self.len.min(32) * 64) as i32;
            x[1] = if e == 1 { m } else { -m };
        } else {
            self.active = false;
            x[0] = 0;
            x[1] = 0;
        }
    }

    #[inline]
    fn update_bit(&mut self, y: u32, rt: &[i32]) {
        if self.active {
            sm_update(&mut self.sm[self.smi], y, 255, rt);
            if y != self.exp {
                self.len = 0;
            }
        }
    }

    #[inline]
    fn level(&self) -> usize {
        if self.active {
            1 + (lb(self.len) / 5).min(6)
        } else {
            0
        }
    }
}

/// 22-bit probability + 10-bit count adaptive state.
#[inline]
fn sm_update(e: &mut u32, y: u32, limit: u32, rt: &[i32]) {
    let n = *e & 1023;
    let p = (*e >> 10) as i64;
    let target: i64 = if y == 1 { (1 << 22) - 1 } else { 0 };
    let np = p + (((target - p) * rt[n as usize] as i64) >> 16);
    let nn = if n < limit { n + 1 } else { n };
    *e = ((np as u32) << 10) | nn;
}

pub struct Predictor {
    nbits: u32,
    nctx: usize,
    nin: usize,
    nsel: usize,
    ultra: bool,
    t: Vec<u32>,
    stretch: Vec<i16>,
    rt: Vec<i32>,
    conf: [i32; 64],
    c0: u32,
    c4: u32,
    c8: u32,
    bitpos: u32,
    word: u32,
    pword: u32,
    ctxh: [u32; NCTX_MAX],
    idx: [usize; NCTX_MAX],
    base: [usize; NCTX_MAX],
    chk: [u32; NCTX_MAX],
    x: [i32; NIN_MAX],
    mm: [MatchModel; NM],
    w1: Vec<Vec<i32>>,
    sel: [usize; NSEL_MAX],
    p1: [i32; NSEL_MAX],
    st1: [i32; NSEL_MAX],
    w2: Vec<i32>,
    sel2: usize,
    pm: i32,
    a1: Apm,
    a2: Apm,
    pr: u32,
}

impl Predictor {
    /// `nbits_byte`: log2 of table slots, with `ULTRA_FLAG` for the ultra model.
    pub fn new(nbits_byte: u32) -> Self {
        let ultra = nbits_byte & ULTRA_FLAG != 0;
        let nbits = nbits_byte & 0x7F;
        let nctx = if ultra { NCTX_MAX } else { NCTX_BASE };
        let nsel = if ultra { NSEL_MAX } else { NSEL_BASE };
        let nin = nctx * 2 + NM * 2 + 1;
        let hbits = (nbits.saturating_sub(2)).clamp(16, 22);
        let mut conf = [0i32; 64];
        for (n, c) in conf.iter_mut().enumerate() {
            *c = ((n as i32) * 32).min(256);
        }
        let mut w1 = vec![
            vec![10000i32; 256 * nin],
            vec![10000i32; 256 * nin],
            vec![10000i32; 64 * nin],
        ];
        if ultra {
            w1.push(vec![10000i32; 256 * nin]);
        }
        let mut p = Predictor {
            nbits,
            nctx,
            nin,
            nsel,
            ultra,
            t: vec![0u32; 1usize << nbits],
            stretch: build_stretch(),
            rt: build_rt(),
            conf,
            c0: 1,
            c4: 0,
            c8: 0,
            bitpos: 0,
            word: 0,
            pword: 0,
            ctxh: [0; NCTX_MAX],
            idx: [0; NCTX_MAX],
            base: [0; NCTX_MAX],
            chk: [0; NCTX_MAX],
            x: [0; NIN_MAX],
            mm: [MatchModel::new(20, hbits), MatchModel::new(6, hbits)],
            w1,
            sel: [0; NSEL_MAX],
            p1: [2048; NSEL_MAX],
            st1: [0; NSEL_MAX],
            w2: vec![65536 / nsel as i32; 256 * nsel],
            sel2: 0,
            pm: 2048,
            a1: Apm::new(256),
            a2: Apm::new(65536),
            pr: 32768,
        };
        p.byte_update_contexts();
        if ultra {
            p.ultra_contexts(&[]);
        }
        p.predict();
        p
    }

    #[inline]
    pub fn p(&self) -> u32 {
        self.pr
    }

    fn byte_update_contexts(&mut self) {
        let c4 = self.c4;
        let c8 = self.c8;
        self.ctxh[0] = hc(0, 0);
        self.ctxh[1] = hc(1, c4 & 0xFF);
        self.ctxh[2] = hc(2, c4 & 0xFFFF);
        self.ctxh[3] = hc(3, c4 & 0xFF_FFFF);
        self.ctxh[4] = hc(4, c4);
        self.ctxh[5] = hc(5, c4 ^ (c8 & 0xFF).wrapping_mul(0x3D4D_51CB));
        self.ctxh[6] = hc(6, c4 ^ (c8 & 0xFFFF).wrapping_mul(0x3D4D_51CB));
        self.ctxh[7] = hc(7, self.word ^ (c4 & 0xFF).wrapping_mul(0x9E37));
        self.ctxh[8] = hc(8, self.word ^ self.pword.wrapping_mul(0x2545_F491));
        self.ctxh[9] = hc(9, (c4 >> 8) & 0xFFFF);
        self.ctxh[10] = hc(10, c4 & 0x00FF_00FF);
        self.ctxh[11] = hc(11, c4 ^ c8.wrapping_mul(0x2545_F491));
    }

    /// Extra long / structured contexts of the ultra model (need the raw history).
    fn ultra_contexts(&mut self, hist: &[u8]) {
        fn tail(hist: &[u8], n: usize) -> u32 {
            let s = hist.len().saturating_sub(n);
            let mut h: u32 = 0;
            for &b in &hist[s..] {
                h = h.wrapping_mul(0x2F0B_4A27).wrapping_add(b as u32 + 1);
            }
            h
        }
        let at = |k: usize| -> u32 {
            if hist.len() >= k { hist[hist.len() - k] as u32 } else { 0 }
        };
        self.ctxh[12] = hc(12, tail(hist, 10));
        self.ctxh[13] = hc(13, tail(hist, 12));
        self.ctxh[14] = hc(14, tail(hist, 16));
        self.ctxh[15] = hc(15, tail(hist, 24));
        self.ctxh[16] = hc(16, at(1) | (at(4) << 8) | (at(8) << 16));
        self.ctxh[17] = hc(17, self.word ^ (self.c4 & 0xFFFF).wrapping_mul(0x9E37_79B1));
    }

    fn predict(&mut self) {
        let c0 = self.c0;
        if self.bitpos == 0 || self.bitpos == 4 {
            // one 64-byte cache line (16 slots) per context per nibble
            let cm = if self.bitpos == 4 { c0.wrapping_mul(0x9E37_79B1) } else { 0 };
            let shift = 32 - (self.nbits - 4);
            for i in 0..self.nctx {
                let mut k = (self.ctxh[i] ^ cm).wrapping_mul(0x85EB_CA6B);
                k ^= k >> 16;
                self.base[i] = ((k >> shift) as usize) << 4;
                self.chk[i] = k & 0xFF;
            }
        }
        let nib = if self.bitpos < 4 {
            c0 as usize
        } else {
            ((c0 & ((1 << (self.bitpos - 4)) - 1)) | (1 << (self.bitpos - 4))) as usize
        };
        for i in 0..self.nctx {
            let idx = self.base[i] + nib;
            let chk = self.chk[i];
            let mut s = self.t[idx];
            if (s >> 24) != chk {
                s = (chk << 24) | (1 << 17);
                self.t[idx] = s;
            }
            self.idx[i] = idx;
            let n = ((s >> 18) & 63) as usize;
            let p12 = ((s & 0x3FFFF) >> 6) as i32;
            self.x[2 * i] = self.stretch[p12 as usize] as i32;
            self.x[2 * i + 1] = if n == 0 { 0 } else { ((p12 - 2048) * self.conf[n]) >> 8 };
        }
        let base = self.nctx * 2;
        for m in 0..NM {
            let mut tmp = [0i32; 2];
            self.mm[m].predict(c0, self.bitpos, &self.stretch, &mut tmp);
            self.x[base + m * 2] = tmp[0];
            self.x[base + m * 2 + 1] = tmp[1];
        }
        let nin = self.nin;
        self.x[nin - 1] = 256;

        let q = self.mm[0].level().max(self.mm[1].level());
        self.sel[0] = c0 as usize;
        self.sel[1] = (self.c4 & 0xFF) as usize;
        self.sel[2] = q * 8 + self.bitpos as usize;
        if self.ultra {
            self.sel[3] = ((self.c4 >> 8) & 0xFF) as usize;
        }
        let nsel = self.nsel;

        let mut dot2: i64 = 0;
        self.sel2 = c0 as usize;
        for k in 0..nsel {
            let w = &self.w1[k][self.sel[k] * nin..self.sel[k] * nin + nin];
            let mut dot: i64 = 0;
            for i in 0..nin {
                dot += w[i] as i64 * self.x[i] as i64;
            }
            let st = ((dot >> 16) as i32).clamp(-2047, 2047);
            self.st1[k] = st;
            self.p1[k] = squash(st);
            dot2 += self.w2[self.sel2 * nsel + k] as i64 * st as i64;
        }
        let st2 = ((dot2 >> 16) as i32).clamp(-2047, 2047);
        self.pm = squash(st2);

        let a1 = self.a1.pp(st2, c0 as usize);
        let a2 = self.a2.pp(st2, (c0 | ((self.c4 & 0xFF) << 8)) as usize);
        let p = ((self.pm as u32) * 16 + a1 + 2 * a2) >> 2;
        self.pr = p.clamp(1, 65535);
    }

    pub fn update(&mut self, y: u32) {
        // counters
        for i in 0..self.nctx {
            let s = self.t[self.idx[i]];
            let n = (s >> 18) & 63;
            let p = (s & 0x3FFFF) as i32;
            let target: i32 = if y == 1 { 0x3FFFF } else { 0 };
            let delta = (((target - p) >> 3) * self.rt[n as usize]) >> 13;
            let np = (p + delta) as u32;
            let nn = if n < 10 { n + 1 } else { n };
            self.t[self.idx[i]] = (s & 0xFF00_0000) | (nn << 18) | (np & 0x3FFFF);
        }
        for m in 0..NM {
            self.mm[m].update_bit(y, &self.rt);
        }
        // mixers
        let ybit = (y << 12) as i32;
        let (nin, nsel) = (self.nin, self.nsel);
        for k in 0..nsel {
            let err = (ybit - self.p1[k]) * LR1;
            let off = self.sel[k] * nin;
            let w = &mut self.w1[k][off..off + nin];
            for i in 0..nin {
                w[i] += (self.x[i] * err + 0x2000) >> 14;
            }
        }
        let err2 = (ybit - self.pm) * LR2;
        for k in 0..nsel {
            let wi = self.sel2 * nsel + k;
            self.w2[wi] += (self.st1[k] * err2 + 0x2000) >> 14;
        }
        self.a1.update(y);
        self.a2.update(y);

        self.c0 = (self.c0 << 1) | y;
        self.bitpos += 1;
        if self.bitpos == 8 {
            let c = (self.c0 & 0xFF) as u8;
            self.c8 = (self.c8 << 8) | (self.c4 >> 24);
            self.c4 = (self.c4 << 8) | c as u32;
            self.c0 = 1;
            self.bitpos = 0;
            let is_word = c.is_ascii_alphabetic() || c >= 128;
            if is_word {
                let l = c.to_ascii_lowercase() as u32;
                self.word = (self.word.wrapping_add(l + 1)).wrapping_mul(0x3D4D_51CB);
            } else if self.word != 0 {
                self.pword = self.word;
                self.word = 0;
            }
            // The caller must now store the byte and call `end_byte` with the
            // history (including this byte); that finishes the update and predicts.
            return;
        }
        self.predict();
    }

    /// Completes a byte: `hist` is everything coded so far, ending with the byte
    /// just finished. The caller owns the history, so no copy is kept here.
    pub fn end_byte(&mut self, hist: &[u8]) {
        for m in 0..NM {
            self.mm[m].update_byte(hist);
        }
        self.byte_update_contexts();
        if self.ultra {
            self.ultra_contexts(hist);
        }
        self.predict();
    }
}

pub struct Encoder {
    x1: u32,
    x2: u32,
    out: Vec<u8>,
}

impl Encoder {
    pub fn new(cap: usize) -> Self {
        Encoder { x1: 0, x2: 0xFFFF_FFFF, out: Vec::with_capacity(cap) }
    }
    #[inline]
    pub fn encode(&mut self, y: u32, p: u32) {
        let range = self.x2 - self.x1;
        let xmid = self.x1 + ((range as u64 * p as u64) >> 16) as u32;
        if y == 1 {
            self.x2 = xmid;
        } else {
            self.x1 = xmid + 1;
        }
        while (self.x1 ^ self.x2) & 0xFF00_0000 == 0 {
            self.out.push((self.x2 >> 24) as u8);
            self.x1 <<= 8;
            self.x2 = (self.x2 << 8) | 255;
        }
    }
    pub fn finish(mut self) -> Vec<u8> {
        let x = self.x1;
        self.out.extend_from_slice(&x.to_be_bytes());
        self.out
    }
}

pub struct Decoder<'a> {
    x1: u32,
    x2: u32,
    x: u32,
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        let mut d = Decoder { x1: 0, x2: 0xFFFF_FFFF, x: 0, data, pos: 0 };
        for _ in 0..4 {
            d.x = (d.x << 8) | d.next() as u32;
        }
        d
    }
    #[inline]
    fn next(&mut self) -> u8 {
        let b = if self.pos < self.data.len() { self.data[self.pos] } else { 0 };
        self.pos += 1;
        b
    }
    #[inline]
    pub fn decode(&mut self, p: u32) -> u32 {
        let range = self.x2 - self.x1;
        let xmid = self.x1 + ((range as u64 * p as u64) >> 16) as u32;
        let y = if self.x <= xmid {
            self.x2 = xmid;
            1
        } else {
            self.x1 = xmid + 1;
            0
        };
        while (self.x1 ^ self.x2) & 0xFF00_0000 == 0 {
            self.x1 <<= 8;
            self.x2 = (self.x2 << 8) | 255;
            self.x = (self.x << 8) | self.next() as u32;
        }
        y
    }
}

pub fn cm_compress(
    data: &[u8],
    nbits: u32,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Option<Vec<u8>> {
    let mut pred = Predictor::new(nbits);
    let mut enc = Encoder::new(data.len() / 2 + 16);
    for i in 0..data.len() {
        let b = data[i];
        for j in (0..8).rev() {
            let y = ((b >> j) & 1) as u32;
            enc.encode(y, pred.p());
            pred.update(y);
        }
        pred.end_byte(&data[..=i]);
        if i & 0xFFFF == 0 && !progress(i) {
            return None;
        }
    }
    progress(data.len());
    Some(enc.finish())
}

/// Incremental decoder: yields the payload from the start, on demand. Used to read an
/// archive's entry table without decoding the data behind it.
pub struct CmStream<'a> {
    pred: Predictor,
    dec: Decoder<'a>,
    out: Vec<u8>,
}

impl<'a> CmStream<'a> {
    pub fn new(comp: &'a [u8], nbits_byte: u32) -> Self {
        CmStream { pred: Predictor::new(nbits_byte), dec: Decoder::new(comp), out: Vec::new() }
    }

    /// Compressed bytes the decoder has read so far (it reads zeros past the end of its input,
    /// so a value above the input length means the output may be wrong).
    pub fn consumed(&self) -> usize {
        self.dec.pos
    }

    /// Decodes until at least `n` bytes are available (or `max` bytes in total).
    pub fn extend_to(&mut self, n: usize, max: usize) -> &[u8] {
        let n = n.min(max);
        while self.out.len() < n {
            let mut c = 0u32;
            for _ in 0..8 {
                let y = self.dec.decode(self.pred.p());
                self.pred.update(y);
                c = (c << 1) | y;
            }
            self.out.push(c as u8);
            self.pred.end_byte(&self.out);
        }
        &self.out
    }
}

/// Why a block could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// the progress callback asked to stop
    Cancelled,
    /// the arithmetic decoder ran past the end of its input: the stream is damaged (or the
    /// header lies about the length). A valid stream is consumed exactly, never beyond.
    Corrupt,
}

pub const ERR_CORRUPT_STREAM: &str = "corrupt data: compressed stream ends too early";

impl DecodeError {
    pub fn message(self) -> String {
        match self {
            DecodeError::Cancelled => "cancelled".into(),
            DecodeError::Corrupt => ERR_CORRUPT_STREAM.into(),
        }
    }
}

/// Decodes exactly `out.len()` bytes into `out`. Stops early with `Corrupt` as soon as the
/// decoder has read past its input, so a damaged block (or one whose declared length is far too
/// big) fails in moments instead of decoding garbage for minutes.
pub fn cm_decompress(
    comp: &[u8],
    out: &mut [u8],
    nbits: u32,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<(), DecodeError> {
    let len = out.len();
    let mut pred = Predictor::new(nbits);
    let mut dec = Decoder::new(comp);
    for i in 0..len {
        let mut c = 0u32;
        for _ in 0..8 {
            let y = dec.decode(pred.p());
            pred.update(y);
            c = (c << 1) | y;
        }
        out[i] = c as u8;
        pred.end_byte(&out[..=i]);
        if i & 0xFFF == 0 {
            if dec.pos > comp.len() + 8 {
                return Err(DecodeError::Corrupt);
            }
            if i & 0xFFFF == 0 && !progress(i) {
                return Err(DecodeError::Cancelled);
            }
        }
    }
    progress(len);
    Ok(())
}
