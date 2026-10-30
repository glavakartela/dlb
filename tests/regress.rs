//! Archives found by fuzzing that once crashed or hung a reader. Every file in `tests/data`
//! must be rejected (or read) without a panic and within a few seconds.

use dlbcore::stream;
use std::fs;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn fuzz_findings_stay_fixed() {
    let dir = format!("{}/tests/data", env!("CARGO_MANIFEST_DIR"));
    let tmp = std::env::temp_dir().join(format!("dlb-regress-{}", std::process::id()));
    let mut n = 0;
    for e in fs::read_dir(&dir).unwrap() {
        let path = e.unwrap().path();
        if path.extension().and_then(|x| x.to_str()) != Some("dlb") {
            continue;
        }
        n += 1;
        let (tx, rx) = mpsc::channel();
        let (p2, t2) = (path.clone(), tmp.clone());
        let h = std::thread::spawn(move || {
            if let Ok(src) = stream::open_source(&p2, None, &mut |_, _| true) {
                let _ = stream::list_source(&*src);
                let _ = stream::extract_archive(&*src, None, false, None, 2, &mut |_, _, _| true);
                let _ = stream::extract_archive(&*src, Some(&t2), true, None, 2, &mut |_, _, _| true);
            }
            let _ = tx.send(());
        });
        match rx.recv_timeout(Duration::from_secs(20)) {
            Ok(()) => h.join().unwrap(),
            Err(_) => panic!("{} hangs or panics", path.display()),
        }
    }
    let _ = fs::remove_dir_all(&tmp);
    assert!(n >= 1, "no regression files found in {}", dir);
}
