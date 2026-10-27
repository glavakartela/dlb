//! Tiny glob matcher for `--exclude` and selective extraction.
//!
//! `*` matches any run of characters except `/`, `**` matches anything including `/`,
//! `?` matches one character except `/`. Everything else is literal (case sensitive).

pub fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    m(&p, &t)
}

fn m(p: &[char], t: &[char]) -> bool {
    let Some(&c) = p.first() else { return t.is_empty() };
    if c == '*' {
        if p.get(1) == Some(&'*') {
            let mut rest = &p[2..];
            while rest.first() == Some(&'*') {
                rest = &rest[1..];
            }
            return (0..=t.len()).any(|i| m(rest, &t[i..]));
        }
        let rest = &p[1..];
        for i in 0..=t.len() {
            if m(rest, &t[i..]) {
                return true;
            }
            if i < t.len() && t[i] == '/' {
                break;
            }
        }
        return false;
    }
    let Some(&x) = t.first() else { return false };
    if c == '?' {
        return x != '/' && m(&p[1..], &t[1..]);
    }
    c == x && m(&p[1..], &t[1..])
}

/// Does `pat` select the archive path `name` (like `proj/src/main.rs`)?
///
/// * a pattern without `/` matches if it matches any single path component
///   (`node_modules`, `*.tmp`),
/// * a pattern with `/` matches the whole path or any leading part of it, so naming a folder
///   selects everything inside it (`proj/src`, `proj/**/*.log`).
pub fn pattern_matches(pat: &str, name: &str) -> bool {
    let pat = pat.trim_start_matches("./").trim_end_matches('/');
    if pat.is_empty() {
        return false;
    }
    let comps: Vec<&str> = name.split('/').collect();
    if !pat.contains('/') {
        return comps.iter().any(|c| glob_match(pat, c));
    }
    (1..=comps.len()).any(|k| glob_match(pat, &comps[..k].join("/")))
}

pub fn any_matches(pats: &[String], name: &str) -> bool {
    pats.iter().any(|p| pattern_matches(p, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob_match("*.txt", "a.txt"));
        assert!(!glob_match("*.txt", "dir/a.txt"));
        assert!(glob_match("**/*.txt", "dir/sub/a.txt"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "a/c"));
        assert!(glob_match("**", "x/y/z"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "a"));
    }

    #[test]
    fn patterns() {
        assert!(pattern_matches("node_modules", "proj/node_modules/x/y.js"));
        assert!(pattern_matches("*.tmp", "proj/a/b.tmp"));
        assert!(!pattern_matches("*.tmp", "proj/a/b.txt"));
        assert!(pattern_matches("proj/src", "proj/src/main.rs"));
        assert!(pattern_matches("proj/src/", "proj/src/main.rs"));
        assert!(!pattern_matches("proj/src", "proj/srcx/main.rs"));
        assert!(pattern_matches("proj/**/*.log", "proj/a/b/c.log"));
        assert!(!pattern_matches("", "a"));
        assert!(any_matches(&["a".into(), "b".into()], "x/b"));
    }
}
