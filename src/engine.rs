//! Shared in-process engine: the `ignore` walker + `grep` searcher that both
//! `content` and `find` build on. This is the cutover the whole project aimed
//! at — file classification and match provenance are read here natively, once,
//! instead of being reconstructed from a shell pipe in each verb.

use grep_regex::RegexMatcherBuilder;
use grep_searcher::sinks::Bytes;
use grep_searcher::{BinaryDetection, Encoding, SearcherBuilder};
use ignore::{DirEntry, WalkBuilder};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// One filter configuration. `use_ignore`/`skip_hidden` drive the walker;
/// `binary_as_text`/`case_insensitive`/`encoding` drive the searcher.
pub struct SearchCfg {
    pub use_ignore: bool,
    pub skip_hidden: bool,
    pub binary_as_text: bool,
    pub case_insensitive: bool,
    pub encoding: Option<&'static str>,
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
    crate::fault::maybe_fault("engine");
    let matcher = RegexMatcherBuilder::new()
        .case_insensitive(cfg.case_insensitive)
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
            Err(_) => continue,
        };
        if has_git_component(&dent) || !is_file(&dent) {
            continue;
        }
        let mut hit = false;
        // Bytes sink, not UTF8: with binary_as_text the searcher reads binary
        // files (e.g. .pyc), where the matching line routinely holds non-UTF-8
        // bytes. The UTF8 sink errors on decode and the match is lost; the
        // Bytes sink takes the raw line, so a binary match is never dropped.
        let _ = searcher.search_path(
            &matcher,
            dent.path(),
            Bytes(|_lnum, _line| {
                hit = true;
                Ok(false) // first match is enough
            }),
        );
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
    crate::fault::maybe_fault("engine");
    let matcher = RegexMatcherBuilder::new()
        .case_insensitive(cfg.case_insensitive)
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
        let _ = searcher.search_path(
            &matcher,
            dent.path(),
            Bytes(|_lnum, _line| {
                hit = true;
                Ok(false)
            }),
        );
        if hit {
            out.insert(display.clone());
        }
    }
    Ok(out)
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
            Err(_) => continue,
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
