//! C ABI used by the Flutter app (dart:ffi). Work runs on a background thread;
//! the UI polls `dlb_job_poll` and may call `dlb_job_cancel`.

use crate::{archive, auto_threads, compress_payload, decompress_payload, Options, MAX_PAYLOAD};
use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

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
/// `threads` = 0 picks a default (all cores, at most 8).
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
) -> *const Job {
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
    let job = Job::new();
    spawn(&job, move |job| {
        let (payload, boundaries) = match archive::build_payload(&inputs) {
            Ok(p) => p,
            Err(e) => return job.fail(e.to_string()),
        };
        if job.cancel.load(SeqCst) {
            return job.fail("cancelled".into());
        }
        if payload.len() > MAX_PAYLOAD {
            return job.fail("input is larger than 4 GiB".into());
        }
        job.in_bytes.store(payload.len() as u64, SeqCst);
        job.total.store(payload.len() as u64, SeqCst);
        job.files.store(
            u32::from_le_bytes(payload[4..8].try_into().unwrap()) as u64,
            SeqCst,
        );
        job.phase.store(PHASE_CODING, SeqCst);
        let mut opts = Options::new(level);
        opts.threads = if threads == 0 { auto_threads() } else { threads as usize };
        let blob = compress_payload(&payload, &boundaries, &opts, &mut |d| {
            job.done.store(d as u64, SeqCst);
            !job.cancel.load(SeqCst)
        });
        let blob = match blob {
            Some(b) => b,
            None => return job.fail("cancelled".into()),
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
) -> *const Job {
    let arc = match cstr(archive_path) {
        Some(s) => PathBuf::from(s),
        None => return std::ptr::null(),
    };
    let dest = cstr(dest).map(PathBuf::from);
    let job = Job::new();
    spawn(&job, move |job| {
        let blob = match std::fs::read(&arc) {
            Ok(b) => b,
            Err(e) => return job.fail(format!("{}: {}", arc.display(), e)),
        };
        let total = blob
            .get(6..14)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
            .unwrap_or(0);
        job.total.store(total, SeqCst);
        job.in_bytes.store(blob.len() as u64, SeqCst);
        job.phase.store(PHASE_CODING, SeqCst);
        let payload = match decompress_payload(&blob, auto_threads(), &mut |d| {
            job.done.store(d as u64, SeqCst);
            !job.cancel.load(SeqCst)
        }) {
            Ok(p) => p,
            Err(e) => return job.fail(e),
        };
        job.out_bytes.store(payload.len() as u64, SeqCst);
        let entries = match archive::parse_payload(&payload) {
            Ok(e) => e,
            Err(e) => return job.fail(e),
        };
        job.files.store(entries.len() as u64, SeqCst);
        if let Some(d) = dest {
            job.phase.store(PHASE_WRITING, SeqCst);
            if let Err(e) = archive::extract(&entries, &d, force != 0) {
                return job.fail(e);
            }
            job.finish(STATE_DONE, d.display().to_string());
        } else {
            job.finish(STATE_DONE, "verified".into());
        }
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

#[no_mangle]
pub extern "C" fn dlb_version() -> u32 {
    1
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
        let job = unsafe { dlb_compress_start(ptrs.as_ptr(), 1, out.as_ptr(), 3, 0) };
        assert!(!job.is_null());
        let st = wait(job);
        assert_eq!(st.state, STATE_DONE);
        assert_eq!(st.files, 2);
        assert!(st.out_bytes < st.in_bytes / 5);
        unsafe { dlb_job_free(job) };

        let dest = CString::new(dir.join("out").to_str().unwrap()).unwrap();
        let job = unsafe { dlb_extract_start(out.as_ptr(), dest.as_ptr(), 0) };
        assert_eq!(wait(job).state, STATE_DONE);
        unsafe { dlb_job_free(job) };
        assert_eq!(std::fs::read_to_string(dir.join("out/in/a.txt")).unwrap(), text);

        // verify-only
        let job = unsafe { dlb_extract_start(out.as_ptr(), std::ptr::null(), 0) };
        assert_eq!(wait(job).state, STATE_DONE);
        let m = unsafe { dlb_job_message(job) };
        assert_eq!(unsafe { CStr::from_ptr(m) }.to_str().unwrap(), "verified");
        unsafe { dlb_string_free(m) };
        unsafe { dlb_job_free(job) };

        // cancel a big job right away
        let big: Vec<u8> = (0..8_000_000u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8).collect();
        std::fs::write(dir.join("big.bin"), &big).unwrap();
        let bigp = CString::new(dir.join("big.bin").to_str().unwrap()).unwrap();
        let out2 = CString::new(dir.join("big.dlb").to_str().unwrap()).unwrap();
        let ptrs = [bigp.as_ptr()];
        let job = unsafe { dlb_compress_start(ptrs.as_ptr(), 1, out2.as_ptr(), 7, 1) };
        std::thread::sleep(Duration::from_millis(300));
        unsafe { dlb_job_cancel(job) };
        assert_eq!(wait(job).state, STATE_CANCELLED);
        unsafe { dlb_job_free(job) };
        assert!(!dir.join("big.dlb").exists());

        // error path
        let missing = CString::new("/nonexistent/zzz").unwrap();
        let ptrs = [missing.as_ptr()];
        let job = unsafe { dlb_compress_start(ptrs.as_ptr(), 1, out2.as_ptr(), 3, 0) };
        assert_eq!(wait(job).state, STATE_ERROR);
        unsafe { dlb_job_free(job) };
        let _ = std::fs::remove_dir_all(&dir);
    }
}
