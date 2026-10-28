//! C ABI used by the Flutter app (dart:ffi). Work runs on a background thread;
//! the UI polls `dlb_job_poll` and may call `dlb_job_cancel`.

use crate::stream::{self, Stage};
use crate::{archive, auto_threads, compress_payload, crypto, Options, MAX_PAYLOAD};
use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Message of a failed extract job when the archive is encrypted and no password was given.
pub const PASSWORD_REQUIRED: &str = stream::PASSWORD_REQUIRED;

pub const STATE_RUNNING: u32 = 0;
pub const STATE_DONE: u32 = 1;
pub const STATE_ERROR: u32 = 2;
pub const STATE_CANCELLED: u32 = 3;

pub const PHASE_READING: u32 = 0; // collecting / reading input files
pub const PHASE_CODING: u32 = 1; // compressing or decompressing
pub const PHASE_WRITING: u32 = 2;

pub struct Job {
    state: AtomicU32,
    phase: AtomicU32,
    done: AtomicU64,
    total: AtomicU64,
    in_bytes: AtomicU64,
    out_bytes: AtomicU64,
    files: AtomicU64,
    cancel: AtomicBool,
    msg: Mutex<String>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

#[repr(C)]
pub struct JobStatus {
    pub state: u32,
    pub phase: u32,
    pub done: u64,
    pub total: u64,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub files: u64,
}

impl Job {
    fn new() -> Arc<Job> {
        Arc::new(Job {
            state: AtomicU32::new(STATE_RUNNING),
            phase: AtomicU32::new(PHASE_READING),
            done: AtomicU64::new(0),
            total: AtomicU64::new(0),
            in_bytes: AtomicU64::new(0),
            out_bytes: AtomicU64::new(0),
            files: AtomicU64::new(0),
            cancel: AtomicBool::new(false),
            msg: Mutex::new(String::new()),
            thread: Mutex::new(None),
        })
    }
    fn finish(&self, state: u32, msg: String) {
        *self.msg.lock().unwrap() = msg;
        self.state.store(state, SeqCst);
    }
    fn fail(&self, msg: String) {
        if msg == "cancelled" {
            self.finish(STATE_CANCELLED, msg);
        } else {
            self.finish(STATE_ERROR, msg);
        }
    }
}

fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok().map(|s| s.to_string())
}

fn spawn(job: &Arc<Job>, f: impl FnOnce(&Job) + Send + 'static) -> *const Job {
    let j = job.clone();
    let h = std::thread::spawn(move || f(&j));
    *job.thread.lock().unwrap() = Some(h);
    Arc::into_raw(job.clone())
}

/// Start compressing `n` paths (files or folders) into `out_path`.
/// `threads` = 0 picks a default (all cores, at most 8; one in low-memory mode). `password` may
/// be NULL. `flags` bit 0 = low-memory mode: files are read from disk block by block and the
/// output is written as it is produced, so RAM stays small for any input size (slightly weaker
/// ratio, see `stream`).
///
/// # Safety
/// `paths` must point to `n` valid NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn dlb_compress_start(
    paths: *const *const c_char,
    n: usize,
    out_path: *const c_char,
    level: u32,
    threads: u32,
    password: *const c_char,
    flags: u32,
) -> *const Job {
    // NULL or empty = no encryption
    let password = cstr(password).filter(|p| !p.is_empty());
    let mut inputs = Vec::new();
    for i in 0..n {
        match cstr(*paths.add(i)) {
            Some(s) => inputs.push(PathBuf::from(s)),
            None => return std::ptr::null(),
        }
    }
    let out = match cstr(out_path) {
        Some(s) => PathBuf::from(s),
        None => return std::ptr::null(),
    };
    let low_mem = flags & 1 != 0;
    let job = Job::new();
    spawn(&job, move |job| {
        if low_mem {
            let spec = stream::CompressJob {
                inputs: &inputs,
                exclude: &[],
                out: &out,
                level,
                threads: if threads == 0 { 1 } else { threads as usize },
                block: stream::LOW_MEM_BLOCK,
                password: password.as_deref(),
            };
            let r = stream::compress_streaming(
                &spec,
                &mut |total, files| {
                    job.total.store(total, SeqCst);
                    job.in_bytes.store(total, SeqCst);
                    job.files.store(files, SeqCst);
                },
                &mut |stage, done, total| {
                    match stage {
                        Stage::Scan => job.phase.store(PHASE_READING, SeqCst),
                        Stage::Code => {
                            job.phase.store(PHASE_CODING, SeqCst);
                            job.total.store(total, SeqCst);
                            job.done.store(done, SeqCst);
                        }
                        Stage::Finish => job.phase.store(PHASE_WRITING, SeqCst),
                    }
                    !job.cancel.load(SeqCst)
                },
            );
            return match r {
                Ok(st) => {
                    job.out_bytes.store(st.out, SeqCst);
                    job.finish(STATE_DONE, out.display().to_string())
                }
                Err(e) => job.fail(e),
            };
        }
        let (payload, boundaries, store_from) = match archive::build_payload(&inputs) {
            Ok(p) => p,
            Err(e) => return job.fail(e.to_string()),
        };
        if job.cancel.load(SeqCst) {
            return job.fail("cancelled".into());
        }
        if payload.len() > MAX_PAYLOAD {
            return job.fail("input is larger than the supported maximum".into());
        }
        job.in_bytes.store(payload.len() as u64, SeqCst);
        job.total.store(payload.len() as u64, SeqCst);
        job.files.store(
            u32::from_le_bytes(payload[4..8].try_into().unwrap()) as u64,
            SeqCst,
        );
        job.phase.store(PHASE_CODING, SeqCst);
        let mut opts = Options::new(level);
        opts.store_from = store_from;
        opts.threads = if threads == 0 { auto_threads() } else { threads as usize };
        let blob = compress_payload(&payload, &boundaries, &opts, &mut |d| {
            job.done.store(d as u64, SeqCst);
            !job.cancel.load(SeqCst)
        });
        let blob = match blob {
            Some(b) => b,
            None => return job.fail("cancelled".into()),
        };
        let blob = match &password {
            Some(pw) => match crypto::seal(&blob, pw) {
                Ok(b) => b,
                Err(e) => return job.fail(e),
            },
            None => blob,
        };
        job.phase.store(PHASE_WRITING, SeqCst);
        job.out_bytes.store(blob.len() as u64, SeqCst);
        match std::fs::write(&out, &blob) {
            Ok(()) => job.finish(STATE_DONE, out.display().to_string()),
            Err(e) => job.fail(format!("{}: {}", out.display(), e)),
        }
    })
}

/// Extract (or only verify, when `dest` is NULL) a `.dlb` archive.
///
/// # Safety
/// Pointers must be valid NUL-terminated UTF-8 strings (`dest` may be NULL).
#[no_mangle]
pub unsafe extern "C" fn dlb_extract_start(
    archive_path: *const c_char,
    dest: *const c_char,
    force: u8,
    password: *const c_char,
    select: *const c_char,
) -> *const Job {
    let password = cstr(password);
    // comma separated entry indices (from dlb_list_start); NULL or empty = everything
    let select: Option<Vec<usize>> = cstr(select).filter(|s| !s.trim().is_empty()).map(|s| {
        s.split(',').filter_map(|t| t.trim().parse().ok()).collect()
    });
    let arc = match cstr(archive_path) {
        Some(s) => PathBuf::from(s),
        None => return std::ptr::null(),
    };
    let dest = cstr(dest).map(PathBuf::from);
    let job = Job::new();
    spawn(&job, move |job| {
        job.in_bytes.store(std::fs::metadata(&arc).map_or(0, |m| m.len()), SeqCst);
        // an encrypted archive is authenticated first (one pass over the file)
        let src = match stream::open_source(&arc, password.as_deref(), &mut |done, total| {
            job.total.store(total, SeqCst);
            job.done.store(done, SeqCst);
            !job.cancel.load(SeqCst)
        }) {
            Ok(s) => s,
            Err(e) => return job.fail(e),
        };
        job.done.store(0, SeqCst);
        job.total.store(0, SeqCst);
        let r = stream::extract_archive(
            &*src,
            dest.as_deref(),
            force != 0,
            select.as_deref(),
            auto_threads(),
            &mut |stage, done, total| {
                if stage == Stage::Code {
                    job.phase.store(PHASE_CODING, SeqCst);
                    job.total.store(total, SeqCst);
                    job.done.store(done, SeqCst);
                }
                !job.cancel.load(SeqCst)
            },
        );
        match r {
            Ok(st) => {
                job.files.store(st.files, SeqCst);
                job.out_bytes.store(st.bytes, SeqCst);
                match &dest {
                    Some(d) => job.finish(STATE_DONE, d.display().to_string()),
                    None => job.finish(STATE_DONE, "verified".into()),
                }
            }
            Err(e) => job.fail(e),
        }
    })
}

/// Reads the entry table of an archive (fast: only the start of the data is decoded). On
/// success the job message holds one line per entry: `kind<TAB>size<TAB>mtime<TAB>name`
/// (kind 0 = file, 1 = empty folder, 2 = link; line number = entry index for
/// `dlb_extract_start`'s `select`). `files` = entry count, `out_bytes` = total file bytes.
///
/// # Safety
/// Pointers must be valid NUL-terminated UTF-8 strings (`password` may be NULL).
#[no_mangle]
pub unsafe extern "C" fn dlb_list_start(
    archive_path: *const c_char,
    password: *const c_char,
) -> *const Job {
    let arc = match cstr(archive_path) {
        Some(s) => PathBuf::from(s),
        None => return std::ptr::null(),
    };
    let password = cstr(password);
    let job = Job::new();
    spawn(&job, move |job| {
        job.in_bytes.store(std::fs::metadata(&arc).map_or(0, |m| m.len()), SeqCst);
        job.phase.store(PHASE_CODING, SeqCst);
        let lst = match stream::list_archive(&arc, password.as_deref(), &mut |done, total| {
            job.total.store(total, SeqCst);
            job.done.store(done, SeqCst);
            !job.cancel.load(SeqCst)
        }) {
            Ok(l) => l,
            Err(e) => return job.fail(e),
        };
        let mut text = String::with_capacity(lst.entries.len() * 64);
        let mut bytes = 0u64;
        for e in &lst.entries {
            if e.kind() == archive::KIND_FILE {
                bytes += e.size;
            }
            let name = e.name.replace(['\t', '\n', '\r'], " ");
            text.push_str(&format!("{}\t{}\t{}\t{}\n", e.kind(), e.size, e.mtime, name));
        }
        job.total.store(lst.total, SeqCst);
        job.out_bytes.store(bytes, SeqCst);
        job.files.store(lst.entries.len() as u64, SeqCst);
        job.finish(STATE_DONE, text);
    })
}

/// # Safety
/// `job` must come from a `dlb_*_start` call and not yet be freed; `out` must be valid.
#[no_mangle]
pub unsafe extern "C" fn dlb_job_poll(job: *const Job, out: *mut JobStatus) {
    let j = &*job;
    *out = JobStatus {
        state: j.state.load(SeqCst),
        phase: j.phase.load(SeqCst),
        done: j.done.load(SeqCst),
        total: j.total.load(SeqCst),
        in_bytes: j.in_bytes.load(SeqCst),
        out_bytes: j.out_bytes.load(SeqCst),
        files: j.files.load(SeqCst),
    };
}

/// Result path / verified note, or the error text. Free with `dlb_string_free`.
///
/// # Safety
/// `job` must be a live job.
#[no_mangle]
pub unsafe extern "C" fn dlb_job_message(job: *const Job) -> *mut c_char {
    let m = (*job).msg.lock().unwrap().replace('\0', " ");
    CString::new(m).unwrap().into_raw()
}

/// # Safety
/// `job` must be a live job.
#[no_mangle]
pub unsafe extern "C" fn dlb_job_cancel(job: *const Job) {
    (*job).cancel.store(true, SeqCst);
}

/// Cancels if still running, waits for the thread and releases the job.
///
/// # Safety
/// `job` must be a live job; it must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn dlb_job_free(job: *const Job) {
    let arc = Arc::from_raw(job);
    arc.cancel.store(true, SeqCst);
    let handle = arc.thread.lock().unwrap().take();
    if let Some(h) = handle {
        let _ = h.join();
    }
}

/// # Safety
/// `s` must come from `dlb_job_message` (or be NULL).
#[no_mangle]
pub unsafe extern "C" fn dlb_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Looks at the first bytes of a file: 0 = unreadable or not a DLB file, 1 = plain archive,
/// 2 = password protected.
///
/// # Safety
/// `path` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn dlb_probe(path: *const c_char) -> u32 {
    use std::io::Read;
    let Some(p) = cstr(path) else { return 0 };
    let mut head = [0u8; 4];
    match std::fs::File::open(p).and_then(|mut f| f.read_exact(&mut head)) {
        Ok(()) if &head == crate::MAGIC || &head == crate::MAGIC_V1 => 1,
        Ok(()) if &head == crypto::MAGIC_ENC => 2,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn dlb_version() -> u32 {
    4
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn wait(job: *const Job) -> JobStatus {
        let mut st = JobStatus { state: 0, phase: 0, done: 0, total: 0, in_bytes: 0, out_bytes: 0, files: 0 };
        loop {
            unsafe { dlb_job_poll(job, &mut st) };
            if st.state != STATE_RUNNING {
                return st;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn msg_of_job(job: *const Job) -> String {
        let m = unsafe { dlb_job_message(job) };
        let s = unsafe { CStr::from_ptr(m) }.to_str().unwrap().to_string();
        unsafe { dlb_string_free(m) };
        s
    }

    #[test]
    fn ffi_roundtrip_and_cancel() {
        let dir = std::env::temp_dir().join(format!("dlb_ffi_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("in/sub")).unwrap();
        let text: String = (0..4000).map(|i| format!("line {} of the test file\n", i % 97)).collect();
        std::fs::write(dir.join("in/a.txt"), &text).unwrap();
        std::fs::write(dir.join("in/sub/b.txt"), &text[..5000]).unwrap();

        let input = CString::new(dir.join("in").to_str().unwrap()).unwrap();
        let out = CString::new(dir.join("t.dlb").to_str().unwrap()).unwrap();
        let ptrs = [input.as_ptr()];
        let job = unsafe { dlb_compress_start(ptrs.as_ptr(), 1, out.as_ptr(), 3, 0, std::ptr::null(), 0) };
        assert!(!job.is_null());
        let st = wait(job);
        assert_eq!(st.state, STATE_DONE);
        assert_eq!(st.files, 2);
        assert!(st.out_bytes < st.in_bytes / 5);
        unsafe { dlb_job_free(job) };

        let dest = CString::new(dir.join("out").to_str().unwrap()).unwrap();
        let job = unsafe { dlb_extract_start(out.as_ptr(), dest.as_ptr(), 0, std::ptr::null(), std::ptr::null()) };
        assert_eq!(wait(job).state, STATE_DONE);
        unsafe { dlb_job_free(job) };
        assert_eq!(std::fs::read_to_string(dir.join("out/in/a.txt")).unwrap(), text);

        // verify-only
        let job = unsafe { dlb_extract_start(out.as_ptr(), std::ptr::null(), 0, std::ptr::null(), std::ptr::null()) };
        assert_eq!(wait(job).state, STATE_DONE);
        let m = unsafe { dlb_job_message(job) };
        assert_eq!(unsafe { CStr::from_ptr(m) }.to_str().unwrap(), "verified");
        unsafe { dlb_string_free(m) };
        unsafe { dlb_job_free(job) };

        // list + selective extract through the job API
        let job = unsafe { dlb_list_start(out.as_ptr(), std::ptr::null()) };
        assert_eq!(wait(job).state, STATE_DONE);
        let listing = msg_of_job(job);
        unsafe { dlb_job_free(job) };
        let lines: Vec<&str> = listing.lines().collect();
        assert_eq!(lines.len(), 2);
        let want = lines.iter().position(|l| l.ends_with("sub/b.txt")).unwrap();
        let sel = CString::new(want.to_string()).unwrap();
        let dest2 = CString::new(dir.join("part").to_str().unwrap()).unwrap();
        let job = unsafe {
            dlb_extract_start(out.as_ptr(), dest2.as_ptr(), 0, std::ptr::null(), sel.as_ptr())
        };
        assert_eq!(wait(job).state, STATE_DONE);
        unsafe { dlb_job_free(job) };
        assert!(dir.join("part/in/sub/b.txt").exists());
        assert!(!dir.join("part/in/a.txt").exists());

        // password protected archive
        let enc = CString::new(dir.join("enc.dlb").to_str().unwrap()).unwrap();
        let pw = CString::new("s3cret pass").unwrap();
        let bad = CString::new("nope").unwrap();
        let job = unsafe { dlb_compress_start(ptrs.as_ptr(), 1, enc.as_ptr(), 3, 0, pw.as_ptr(), 0) };
        assert_eq!(wait(job).state, STATE_DONE);
        unsafe { dlb_job_free(job) };
        assert_eq!(unsafe { dlb_probe(enc.as_ptr()) }, 2);
        assert_eq!(unsafe { dlb_probe(out.as_ptr()) }, 1);
        let raw = std::fs::read(dir.join("enc.dlb")).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"a.txt"), "names must be hidden");
        let msg_of = |job| {
            let m = unsafe { dlb_job_message(job) };
            let s = unsafe { CStr::from_ptr(m) }.to_str().unwrap().to_string();
            unsafe { dlb_string_free(m) };
            s
        };
        let job = unsafe { dlb_extract_start(enc.as_ptr(), std::ptr::null(), 0, std::ptr::null(), std::ptr::null()) };
        assert_eq!(wait(job).state, STATE_ERROR);
        assert_eq!(msg_of(job), PASSWORD_REQUIRED);
        unsafe { dlb_job_free(job) };
        let job = unsafe { dlb_extract_start(enc.as_ptr(), std::ptr::null(), 0, bad.as_ptr(), std::ptr::null()) };
        assert_eq!(wait(job).state, STATE_ERROR);
        assert_eq!(msg_of(job), crypto::ERR_BAD_PASSWORD);
        unsafe { dlb_job_free(job) };
        let job = unsafe { dlb_extract_start(enc.as_ptr(), std::ptr::null(), 0, pw.as_ptr(), std::ptr::null()) };
        assert_eq!(wait(job).state, STATE_DONE);
        unsafe { dlb_job_free(job) };

        // cancel a big job right away
        let big: Vec<u8> = (0..8_000_000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
        std::fs::write(dir.join("big.bin"), &big).unwrap();
        let bigp = CString::new(dir.join("big.bin").to_str().unwrap()).unwrap();
        let out2 = CString::new(dir.join("big.dlb").to_str().unwrap()).unwrap();
        let ptrs = [bigp.as_ptr()];
        let job = unsafe { dlb_compress_start(ptrs.as_ptr(), 1, out2.as_ptr(), 7, 1, std::ptr::null(), 0) };
        std::thread::sleep(Duration::from_millis(300));
        unsafe { dlb_job_cancel(job) };
        assert_eq!(wait(job).state, STATE_CANCELLED);
        unsafe { dlb_job_free(job) };
        assert!(!dir.join("big.dlb").exists());

        // error path
        let missing = CString::new("/nonexistent/zzz").unwrap();
        let ptrs = [missing.as_ptr()];
        let job = unsafe { dlb_compress_start(ptrs.as_ptr(), 1, out2.as_ptr(), 3, 0, std::ptr::null(), 0) };
        assert_eq!(wait(job).state, STATE_ERROR);
        unsafe { dlb_job_free(job) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ffi_low_memory_mode() {
        let dir = std::env::temp_dir().join(format!("dlb_ffi_lm_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("in/sub")).unwrap();
        let text: String = (0..3000).map(|i| format!("row {} of the low memory test\n", i % 89)).collect();
        std::fs::write(dir.join("in/a.txt"), &text).unwrap();
        std::fs::write(dir.join("in/sub/b.txt"), &text[..4000]).unwrap();
        let input = CString::new(dir.join("in").to_str().unwrap()).unwrap();
        let ptrs = [input.as_ptr()];
        for pw in [None, Some("pw one")] {
            let out = CString::new(dir.join("lm.dlb").to_str().unwrap()).unwrap();
            let cpw = pw.map(|p| CString::new(p).unwrap());
            let pp = cpw.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
            let job = unsafe { dlb_compress_start(ptrs.as_ptr(), 1, out.as_ptr(), 3, 0, pp, 1) };
            let st = wait(job);
            assert_eq!(st.state, STATE_DONE, "{}", msg_of_job(job));
            assert_eq!(st.files, 2);
            assert!(st.out_bytes > 0 && st.out_bytes < st.in_bytes);
            unsafe { dlb_job_free(job) };
            assert_eq!(unsafe { dlb_probe(out.as_ptr()) }, if pw.is_some() { 2 } else { 1 });

            let job = unsafe { dlb_list_start(out.as_ptr(), pp) };
            assert_eq!(wait(job).state, STATE_DONE);
            let listing = msg_of_job(job);
            unsafe { dlb_job_free(job) };
            assert_eq!(listing.lines().count(), 2);

            let dest = CString::new(dir.join("lm-out").to_str().unwrap()).unwrap();
            let _ = std::fs::remove_dir_all(dir.join("lm-out"));
            let job = unsafe { dlb_extract_start(out.as_ptr(), dest.as_ptr(), 0, pp, std::ptr::null()) };
            assert_eq!(wait(job).state, STATE_DONE);
            unsafe { dlb_job_free(job) };
            assert_eq!(std::fs::read_to_string(dir.join("lm-out/in/a.txt")).unwrap(), text);
            assert_eq!(std::fs::read_to_string(dir.join("lm-out/in/sub/b.txt")).unwrap(), &text[..4000]);
        }
        assert!(!dir.join("lm.dlb.part").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
