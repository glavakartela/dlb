//! The release number and name live in a few files; this keeps them from drifting apart.

use std::fs;

fn read(p: &str) -> String {
    fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), p)).unwrap_or_else(|e| panic!("{}: {}", p, e))
}

#[test]
fn version_and_codename_agree_everywhere() {
    let v = env!("CARGO_PKG_VERSION");
    let pubspec = read("app/dlb_app/pubspec.yaml");
    let line = pubspec.lines().find(|l| l.starts_with("version:")).expect("pubspec version");
    assert!(
        line.trim_start_matches("version:").trim().starts_with(&format!("{}+", v)),
        "pubspec has `{}`, Cargo has {}",
        line,
        v
    );
    let dart = read("app/dlb_app/lib/version.dart");
    assert!(dart.contains(&format!("kVersion = '{}'", v)), "lib/version.dart version");
    assert!(
        dart.contains(&format!("kCodename = '{}'", dlbcore::CODENAME)),
        "lib/version.dart codename"
    );
    let changelog = read("CHANGELOG.md");
    assert!(
        changelog.contains(&format!("## {} \"{}\"", v, dlbcore::CODENAME)),
        "CHANGELOG.md must start a section `## {} \"{}\"`",
        v,
        dlbcore::CODENAME
    );
}
