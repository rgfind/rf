//! Shared in-process engine: the `ignore` walker + `grep` searcher that both
//! `content` and `find` build on. This is the cutover the whole project aimed
//! at — file classification and match provenance are read here natively, once,
//! instead of being reconstructed from a shell pipe in each verb.

use crate::query::QueryMode;
use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use grep_searcher::sinks::Bytes;
use grep_searcher::{BinaryDetection, Encoding, SearcherBuilder};
use ignore::{DirEntry, WalkBuilder};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const MAX_EVIDENCE_TEXT_BYTES: usize = 512;
pub const MAX_EVIDENCE_MATCHES: usize = 16;

/// One filter configuration. `use_ignore`/`skip_hidden` drive the walker;
/// `binary_as_text`/`query`/`encoding` drive the searcher.
pub struct SearchCfg {
    pub use_ignore: bool,
    pub skip_hidden: bool,
    pub binary_as_text: bool,
    pub query: QueryMode,
    pub encoding: Option<&'static str>,
}

/// One bounded occurrence in the same decoded byte stream that rf searched.
pub struct Occurrence {
    pub line: u64,
    pub column_byte: usize,
    pub text: String,
    pub text_lossy: bool,
    pub text_truncated: bool,
}

/// Paths that the engine could not read in this invocation, and whether it
/// read any file. A skipped path is recorded, never dropped without a trace:
/// the caller reports it as `PARTIAL_RESULT`, or as `IO_FAILURE` when no file
/// was read.
#[derive(Default)]
pub struct Skips {
    /// Walked-form path -> errno name.
    pub unreadable: BTreeMap<String, String>,
    pub read_ok: bool,
}

thread_local! {
    static SKIPS: RefCell<Skips> = RefCell::new(Skips::default());
}

/// Take the record and reset it.
pub fn take_skips() -> Skips {
    SKIPS.with(|skips| skips.take())
}

fn record_skip(path: &Path, error: &std::io::Error) {
    if path.components().any(|c| c.as_os_str() == ".git") {
        return;
    }
    SKIPS.with(|skips| {
        skips.borrow_mut().unreadable.insert(
            norm(&path.to_string_lossy()),
            crate::paths::errno_name(error),
        );
    });
}

fn record_read() {
    SKIPS.with(|skips| skips.borrow_mut().read_ok = true);
}

fn error_path(error: &ignore::Error) -> Option<&Path> {
    match error {
        ignore::Error::WithPath { path, .. } => Some(path),
        ignore::Error::WithDepth { err, .. } | ignore::Error::WithLineNumber { err, .. } => {
            error_path(err)
        }
        _ => None,
    }
}

fn record_walk_error(error: &ignore::Error) {
    if let (Some(path), Some(io)) = (error_path(error), error.io_error()) {
        record_skip(path, io);
    }
}

/// Strip a leading `./`. Used for the display form when the root is ".".
pub fn norm(p: &str) -> String {
    p.strip_prefix("./").unwrap_or(p).to_string()
}

/// Path relative to the search root, so sets from the walker line up with paths
/// git/ast-grep report (which are already root-relative).
pub fn rel(root: &str, full: &str) -> String {
    let full = full.strip_prefix("./").unwrap_or(full);
    let root = root.strip_suffix('/').unwrap_or(root);
    if root == "." || root.is_empty() {
        return full.to_string();
    }
    match full.strip_prefix(root) {
        Some(rest) => rest.trim_start_matches('/').to_string(),
        None => full.to_string(),
    }
}

/// A content search must never treat `.git` plumbing as content.
fn has_git_component(entry: &DirEntry) -> bool {
    entry.path().components().any(|c| c.as_os_str() == ".git")
}

fn is_file(entry: &DirEntry) -> bool {
    entry.file_type().map(|t| t.is_file()).unwrap_or(false)
}

fn walk(root: &str, use_ignore: bool, skip_hidden: bool) -> ignore::Walk {
    let mut wb = WalkBuilder::new(root);
    wb.hidden(skip_hidden)
        .git_ignore(use_ignore)
        .git_global(use_ignore)
        .git_exclude(use_ignore)
        .ignore(use_ignore)
        .parents(use_ignore);
    wb.build()
}

/// Files under `root` containing `pattern` under one filter configuration.
/// Paths keep the walked form (root prefix, `./` stripped); callers relativize.
pub fn content_matches(
    root: &str,
    pattern: &str,
    cfg: &SearchCfg,
) -> Result<BTreeSet<String>, String> {
    let matcher = RegexMatcherBuilder::new()
        .fixed_strings(cfg.query.fixed_strings)
        .word(cfg.query.word)
        .case_insensitive(cfg.query.case_insensitive)
        .build(pattern)
        .map_err(|e| e.to_string())?;

    let mut sb = SearcherBuilder::new();
    sb.binary_detection(if cfg.binary_as_text {
        BinaryDetection::none()
    } else {
        BinaryDetection::quit(b'\x00')
    });
    if let Some(label) = cfg.encoding {
        let enc = Encoding::new(label).map_err(|e| format!("bad encoding {label}: {e}"))?;
        sb.encoding(Some(enc));
    }
    let mut searcher = sb.build();

    let mut out = BTreeSet::new();
    for dent in walk(root, cfg.use_ignore, cfg.skip_hidden) {
        let dent = match dent {
            Ok(d) => d,
            Err(e) => {
                record_walk_error(&e);
                continue;
            }
        };
        if has_git_component(&dent) || !is_file(&dent) {
            continue;
        }
        let mut hit = false;
        // Bytes sink, not UTF8: with binary_as_text the searcher reads binary
        // files (e.g. .pyc), where the matching line routinely holds non-UTF-8
        // bytes. The UTF8 sink errors on decode and the match is lost; the
        // Bytes sink takes the raw line, so a binary match is never dropped.
        match searcher.search_path(
            &matcher,
            dent.path(),
            Bytes(|_lnum, _line| {
                hit = true;
                Ok(false) // first match is enough
            }),
        ) {
            Ok(()) => record_read(),
            Err(e) => record_skip(dent.path(), &e),
        }
        if hit {
            out.insert(norm(&dent.path().to_string_lossy()));
        }
    }
    Ok(out)
}

/// Search an already validated, caller-selected file set. The keys are the
/// stable display paths and the values are the canonical filesystem paths.
/// This intentionally does not construct a walker: every content layer and
/// encoding probe operates only on the supplied selection.
pub fn content_matches_selected(
    root: &str,
    pattern: &str,
    cfg: &SearchCfg,
    files: &BTreeMap<String, PathBuf>,
) -> Result<BTreeSet<String>, String> {
    let matcher = RegexMatcherBuilder::new()
        .fixed_strings(cfg.query.fixed_strings)
        .word(cfg.query.word)
        .case_insensitive(cfg.query.case_insensitive)
        .build(pattern)
        .map_err(|e| e.to_string())?;

    let mut sb = SearcherBuilder::new();
    sb.binary_detection(if cfg.binary_as_text {
        BinaryDetection::none()
    } else {
        BinaryDetection::quit(b'\x00')
    });
    if let Some(label) = cfg.encoding {
        let enc = Encoding::new(label).map_err(|e| format!("bad encoding {label}: {e}"))?;
        sb.encoding(Some(enc));
    }
    let mut searcher = sb.build();
    let mut out = BTreeSet::new();
    let selected_by_path: BTreeMap<PathBuf, String> = files
        .iter()
        .map(|(display, file)| (file.clone(), display.clone()))
        .collect();
    // The walker supplies the same ignore and hidden classification as normal
    // content search. It never opens or searches a non-selected file.
    for dent in walk(root, cfg.use_ignore, cfg.skip_hidden) {
        let dent = match dent {
            Ok(d) => d,
            Err(_) => continue,
        };
        if has_git_component(&dent) || !is_file(&dent) {
            continue;
        }
        let canonical = match std::fs::canonicalize(dent.path()) {
            Ok(path) => path,
            Err(_) => continue,
        };
        let Some(display) = selected_by_path.get(&canonical) else {
            continue;
        };
        let mut hit = false;
        match searcher.search_path(
            &matcher,
            dent.path(),
            Bytes(|_lnum, _line| {
                hit = true;
                Ok(false)
            }),
        ) {
            Ok(()) => record_read(),
            Err(e) => record_skip(dent.path(), &e),
        }
        if hit {
            out.insert(display.clone());
        }
    }
    Ok(out)
}

fn cap_text(text: String) -> (String, bool) {
    if text.len() <= MAX_EVIDENCE_TEXT_BYTES {
        return (text, false);
    }
    let end = text
        .char_indices()
        .take_while(|(offset, character)| *offset + character.len_utf8() <= MAX_EVIDENCE_TEXT_BYTES)
        .map(|(offset, character)| offset + character.len_utf8())
        .last()
        .unwrap_or(0);
    (text[..end].to_string(), true)
}

/// Collect up to `cap` non-overlapping primary-pattern occurrences from one
/// already-selected file. The default file-level path never calls this helper,
/// so it retains the existing first-match early exit and does not allocate line
/// text unless evidence was requested.
pub fn occurrences(
    file: &str,
    pattern: &str,
    cfg: &SearchCfg,
    cap: usize,
) -> Result<Vec<Occurrence>, String> {
    let matcher = RegexMatcherBuilder::new()
        .fixed_strings(cfg.query.fixed_strings)
        .word(cfg.query.word)
        .case_insensitive(cfg.query.case_insensitive)
        .build(pattern)
        .map_err(|e| e.to_string())?;
    let mut builder = SearcherBuilder::new();
    builder.binary_detection(if cfg.binary_as_text {
        BinaryDetection::none()
    } else {
        BinaryDetection::quit(b'\x00')
    });
    if let Some(label) = cfg.encoding {
        builder.encoding(Some(Encoding::new(label).map_err(|e| e.to_string())?));
    }
    let mut searcher = builder.build();
    let mut found = Vec::new();
    searcher
        .search_path(
            &matcher,
            file,
            Bytes(|line_number, bytes| {
                let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
                let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
                let lossy = std::str::from_utf8(bytes).is_err();
                let decoded = String::from_utf8_lossy(bytes).into_owned();
                let (text, text_truncated) = cap_text(decoded);
                let _ = matcher.find_iter(bytes, |matched| {
                    found.push(Occurrence {
                        line: line_number,
                        column_byte: matched.start() + 1,
                        text: text.clone(),
                        text_lossy: lossy,
                        text_truncated,
                    });
                    found.len() < cap
                });
                Ok(found.len() < cap)
            }),
        )
        .map_err(|e| e.to_string())?;
    Ok(found)
}

/// The `matches` value of one row. A file that matched and that rf cannot
/// read again for its occurrences gives null, never an empty list: an empty
/// list would say "zero occurrences". `report` is the name of the file in the
/// reply; it goes into `unread`, and the caller reports those names with
/// `evidence_unread_warning`.
pub fn evidence_value(
    read: &str,
    report: &str,
    pattern: &str,
    cfg: &SearchCfg,
    cap: usize,
    unread: &mut Vec<String>,
) -> serde_json::Value {
    match occurrences(read, pattern, cfg, cap) {
        Ok(found) => serde_json::Value::Array(found.into_iter().map(occurrence_json).collect()),
        Err(_) => {
            unread.push(report.to_string());
            serde_json::Value::Null
        }
    }
}

/// The `PARTIAL_RESULT` warning for rows whose `matches` is null because the
/// occurrence read failed. None when each read succeeded.
pub fn evidence_unread_warning(unread: Vec<String>) -> Option<serde_json::Value> {
    if unread.is_empty() {
        return None;
    }
    Some(crate::envelope::warn(
        "PARTIAL_RESULT",
        format!(
            "{} matched file(s) could not be read for occurrences; matches is null for them",
            unread.len()
        ),
        unread,
    ))
}

/// Files under `root` whose extension is `ext` (no dot) — the fd stage. The
/// walker's `use_ignore`/`skip_hidden` reproduce fd's default and its -I/-H/-u.
pub fn name_matches(
    root: &str,
    ext: &str,
    use_ignore: bool,
    skip_hidden: bool,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for dent in walk(root, use_ignore, skip_hidden) {
        let dent = match dent {
            Ok(d) => d,
            Err(e) => {
                record_walk_error(&e);
                continue;
            }
        };
        if has_git_component(&dent) || !is_file(&dent) {
            continue;
        }
        if dent.path().extension().and_then(|e| e.to_str()) == Some(ext) {
            out.insert(norm(&dent.path().to_string_lossy()));
        }
    }
    out
}

/// One occurrence as JSON. All five keys are in every occurrence.
pub fn occurrence_json(value: Occurrence) -> serde_json::Value {
    serde_json::json!({
        "line": value.line,
        "column_byte": value.column_byte,
        "text": value.text,
        "text_lossy": value.text_lossy,
        "text_truncated": value.text_truncated,
    })
}

/// `meta.evidence`. It is in every reply; `match_cap` is null when the
/// request did not ask for occurrences.
pub fn evidence_meta(requested: bool, match_cap: usize) -> serde_json::Value {
    serde_json::json!({
        "requested": requested,
        "match_cap": requested.then_some(match_cap),
        "text_bytes_cap": MAX_EVIDENCE_TEXT_BYTES,
        "response_bytes_cap": crate::pagination::MAX_EVIDENCE_RESPONSE_BYTES,
    })
}

#[cfg(test)]
mod evidence_tests {
    use super::{evidence_unread_warning, evidence_value, SearchCfg};
    use crate::query::QueryMode;

    fn cfg() -> SearchCfg {
        SearchCfg {
            use_ignore: false,
            skip_hidden: false,
            binary_as_text: true,
            query: QueryMode::default(),
            encoding: None,
        }
    }

    #[test]
    fn a_failed_occurrence_read_is_null_and_named_not_an_empty_list() {
        let dir = std::env::temp_dir().join(format!("rf-evidence-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let present = dir.join("present.txt");
        std::fs::write(&present, "needle here\n").unwrap();
        let gone = dir.join("gone.txt");

        let mut unread = Vec::new();
        let read = evidence_value(
            &present.to_string_lossy(),
            "present.txt",
            "needle",
            &cfg(),
            5,
            &mut unread,
        );
        assert_eq!(read.as_array().map(Vec::len), Some(1));
        assert!(unread.is_empty());
        assert!(evidence_unread_warning(Vec::new()).is_none());

        // The file matched in the first pass and is gone at the second read.
        let failed = evidence_value(
            &gone.to_string_lossy(),
            "gone.txt",
            "needle",
            &cfg(),
            5,
            &mut unread,
        );
        assert!(failed.is_null(), "{failed}");
        assert_eq!(unread, ["gone.txt"]);
        let warning = evidence_unread_warning(unread).expect("a warning");
        assert_eq!(warning["code"], "PARTIAL_RESULT");
        assert_eq!(warning["details"]["files"][0], "gone.txt");
        let _ = std::fs::remove_dir_all(dir);
    }
}
