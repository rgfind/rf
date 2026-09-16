//! The `find` verb — staged cross-source discovery, each match attributed to
//! the one stage that hid it. Four independent sources:
//!
//!   1. fd name filters   -> `ignore`-walker classifications (in-process)
//!   2. rg binary skip     -> `grep` binary-detection read   (in-process)
//!   3. git history        -> `git` plumbing                 (subprocess)
//!   4. ast-grep structural-> `ast-grep run --json`          (subprocess)
//!
//! Sources 1 and 2 are the fd|rg pipe, read natively in-process via the shared
//! engine. Sources 3 and 4 are genuinely external tools with no Rust binding;
//! shelling out to them is not pipe-reconstruction, it is reading a different
//! oracle. Each source contributes nothing (not a crash) when unavailable, so
//! totality holds.

use crate::engine::{content_matches, name_matches, rel, SearchCfg};
use crate::envelope::{envelope, err, warn};
use crate::query::QueryMode;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const HISTORY_BUDGET: Duration = Duration::from_secs(2);

/// -uu -a config: the content the pipe surfaces if nothing filters it (no
/// ignore, hidden shown, binary read as text). content_all uses this; the
/// per-file attribution then explains why the plain default missed each file.
fn cfg_all_text(query: QueryMode) -> SearchCfg {
    SearchCfg {
        use_ignore: false,
        skip_hidden: false,
        binary_as_text: true,
        query,
        encoding: None,
    }
}

/// ripgrep's own default: honor ignore + hidden, quit on NUL.
fn cfg_default(query: QueryMode) -> SearchCfg {
    SearchCfg {
        use_ignore: true,
        skip_hidden: true,
        binary_as_text: false,
        query,
        encoding: None,
    }
}

enum History {
    Available {
        matches: BTreeSet<String>,
        served: usize,
    },
    GitAbsent,
    GitUnusable,
    GitTimedOut,
    NotWorkTree,
    Partial {
        matches: BTreeSet<String>,
        served: usize,
        failed: usize,
    },
    Error,
}

impl History {
    fn actual_mode(&self) -> &'static str {
        match self {
            Self::Available { .. } => "available",
            Self::GitAbsent => "git-absent",
            Self::GitUnusable => "git-unusable",
            Self::GitTimedOut => "git-timed-out",
            Self::NotWorkTree => "not-work-tree",
            Self::Partial { .. } => "partial",
            Self::Error => "history-error",
        }
    }

    fn matches(&self) -> BTreeSet<String> {
        match self {
            Self::Available { matches, .. } | Self::Partial { matches, .. } => matches.clone(),
            Self::GitAbsent
            | Self::GitUnusable
            | Self::GitTimedOut
            | Self::NotWorkTree
            | Self::Error => BTreeSet::new(),
        }
    }

    fn counts(&self) -> (usize, usize) {
        match self {
            Self::Available { served, .. } => (*served, 0),
            Self::Partial { served, failed, .. } => (*served, *failed),
            Self::GitAbsent
            | Self::GitUnusable
            | Self::GitTimedOut
            | Self::NotWorkTree
            | Self::Error => (0, 0),
        }
    }
}

/// Git plumbing: files matching *.ext that held `pattern` in any committed
/// tree. An unavailable or incomplete history is a typed outcome, never an
/// indistinguishable empty result.
fn git_ever_matched_with(
    git: &Path,
    pattern: &str,
    root: &str,
    ext: &str,
    query: QueryMode,
    explicit_case_sensitive: bool,
) -> History {
    let mut out = BTreeSet::new();
    let probe = Command::new(git)
        .args(["-C", root, "rev-parse", "--is-inside-work-tree"])
        .output();
    let probe = match probe {
        Ok(out) => out,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return History::GitAbsent,
        Err(_) => return History::Error,
    };
    if !probe.status.success() || String::from_utf8_lossy(&probe.stdout).trim() != "true" {
        return History::NotWorkTree;
    }
    let revs_out = match Command::new(git)
        .args(["-C", root, "rev-list", "--all"])
        .output()
    {
        Ok(out) if out.status.success() => out,
        _ => return History::Error,
    };
    let revs: Vec<String> = String::from_utf8_lossy(&revs_out.stdout)
        .split_whitespace()
        .map(String::from)
        .collect();
    let glob = format!("*.{ext}");
    let started = Instant::now();
    let mut served = 0;
    let mut failed = 0;
    for rev in &revs {
        if started.elapsed() >= HISTORY_BUDGET {
            failed += revs.len().saturating_sub(served + failed);
            break;
        }
        let mut args = vec!["-C".into(), root.into(), "grep".into()];
        args.extend(query.git_grep_args(explicit_case_sensitive));
        args.extend([
            "-l".into(),
            "-e".into(),
            pattern.into(),
            rev.clone(),
            "--".into(),
            glob.clone(),
        ]);
        let g = match Command::new(git).args(&args).output() {
            Ok(out) => out,
            Err(_) => {
                failed += 1;
                continue;
            }
        };
        // `git grep` exits 1 when it successfully scanned a revision but found
        // no match. Other nonzero exits mean that revision was not served.
        if !g.status.success() && g.status.code() != Some(1) {
            failed += 1;
            continue;
        }
        served += 1;
        for ln in String::from_utf8_lossy(&g.stdout).lines() {
            // "<rev>:<path>"
            if let Some((_, path)) = ln.split_once(':') {
                out.insert(path.to_string());
            }
        }
    }
    if failed == 0 {
        History::Available {
            matches: out,
            served,
        }
    } else if served == 0 && !revs.is_empty() {
        History::Error
    } else {
        History::Partial {
            matches: out,
            served,
            failed,
        }
    }
}

fn git_ever_matched(
    pattern: &str,
    root: &str,
    ext: &str,
    query: QueryMode,
    explicit_case_sensitive: bool,
) -> History {
    git_ever_matched_with(
        Path::new("git"),
        pattern,
        root,
        ext,
        query,
        explicit_case_sensitive,
    )
}

fn history_meta(history: &History) -> Value {
    let (served, failed) = history.counts();
    json!({
        "requested_mode": "all-revisions",
        "actual_mode": history.actual_mode(),
        "budget_ms": HISTORY_BUDGET.as_millis(),
        "served_revisions": served,
        "failed_revisions": failed,
    })
}

fn history_probe_command(root: &str) -> String {
    crate::command::shell(
        "git",
        &[
            "-C".into(),
            root.into(),
            "rev-parse".into(),
            "--is-inside-work-tree".into(),
        ],
    )
}

/// Short hash of the most recent commit that changed `pattern`'s count in
/// `path` — the scrub commit. Volatile; used only in a warning, never in `data`.
fn git_scrub_commits(
    pattern: &str,
    root: &str,
    ext: &str,
    query: QueryMode,
) -> BTreeMap<String, String> {
    if query.word {
        return BTreeMap::new();
    }
    let glob = format!("*.{ext}");
    let out = Command::new("git")
        .args({
            let mut args = vec!["-C".into(), root.into(), "log".into()];
            if query.case_insensitive {
                args.push("-i".into());
            }
            args.extend([
                "--all".into(),
                "--format=%h".into(),
                "--name-only".into(),
                "-S".into(),
                pattern.into(),
                "--".into(),
                glob,
            ]);
            args
        })
        .output();
    let mut result = BTreeMap::new();
    let Ok(out) = out else {
        return result;
    };
    let mut commit = String::new();
    for line in String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| !line.is_empty())
    {
        if line.len() == 7 && line.bytes().all(|b| b.is_ascii_hexdigit()) {
            commit = line.into();
        } else if !commit.is_empty() {
            result.entry(line.into()).or_insert_with(|| commit.clone());
        }
    }
    result
}

enum Structural {
    Used(BTreeSet<String>),
    Missing,
    Unusable,
    TimedOut,
}

/// Files whose SYNTAX matches the structural pattern. Execution has its own
/// deadline and capture cap, separate from the `--version` health probe.
fn ast_files(structural: &str, lang: &str, root: &str) -> Structural {
    let health = crate::external_tools::probe("ast-grep");
    match health["status"].as_str().unwrap_or("missing") {
        "missing" => return Structural::Missing,
        "unusable" => return Structural::Unusable,
        "timed_out" => return Structural::TimedOut,
        _ => {}
    }
    let path =
        crate::external_tools::resolved_path("ast-grep").expect("available ast-grep has a path");
    let out = crate::external_tools::run_bounded(
        &path,
        &[
            "run",
            "--pattern",
            structural,
            "--lang",
            lang,
            "--json",
            ".",
        ],
        Some(root),
        crate::external_tools::STRUCTURAL_TIMEOUT,
        crate::external_tools::STRUCTURAL_OUTPUT_BYTES,
    );
    if out.state == crate::external_tools::RunState::TimedOut {
        return Structural::TimedOut;
    }
    if !out.success || out.output_truncated {
        return Structural::Unusable;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let hits: Value = serde_json::from_str(if text.trim().is_empty() { "[]" } else { &text })
        .unwrap_or(Value::Array(vec![]));
    let mut files = BTreeSet::new();
    if let Some(arr) = hits.as_array() {
        for m in arr {
            if let Some(f) = m.get("file").and_then(|v| v.as_str()) {
                files.insert(f.strip_prefix("./").unwrap_or(f).to_string());
            }
        }
    }
    Structural::Used(files)
}

/// Does the file at root/rel_path contain `needle` as a literal byte substring?
/// The in-process equivalent of `rg -F -uu -a` restricted to the ast hits: a
/// file where this is false but ast matched is surfaced only structurally.
fn file_contains_literal(root: &str, rel_path: &str, needle: &str) -> bool {
    let full = if root == "." || root.is_empty() {
        rel_path.to_string()
    } else {
        format!("{}/{}", root.trim_end_matches('/'), rel_path)
    };
    match std::fs::read(&full) {
        Ok(bytes) => bytes
            .windows(needle.len().max(1))
            .any(|w| w == needle.as_bytes()),
        Err(_) => false,
    }
}

// The parameters mirror the `find` CLI grammar one-to-one; a params struct is
// the deliberate refactor to make when the verb next gains fields.
#[allow(clippy::too_many_arguments)]
pub fn run(
    pattern: &str,
    path: &str,
    name: &str,
    structural: Option<&str>,
    lang: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
    query: QueryMode,
    explicit_case_sensitive: bool,
) -> (Value, i32) {
    // Guard the port keeps stable across the contract: --structural needs --lang.
    if structural.is_some() && lang.is_none() {
        let mut meta = Map::new();
        meta.insert("verb".into(), Value::from("find"));
        return (
            envelope(
                false,
                vec![],
                meta,
                vec![],
                vec![],
                vec![err(
                    "USAGE",
                    "--structural requires --lang (ast-grep needs a language)",
                )],
            ),
            1,
        );
    }
    crate::fault::maybe_fault("find");
    let ext = name;
    let root = path;
    let relset = |s: BTreeSet<String>| -> BTreeSet<String> {
        s.into_iter().map(|f| rel(root, &f)).collect()
    };

    // --- source 1: fd name-filter stages (in-process walker) ---
    let fd_default = relset(name_matches(root, ext, true, true));
    let fd_hidden = relset(name_matches(root, ext, true, false));
    let fd_ignore = relset(name_matches(root, ext, false, true));
    let fd_all = relset(name_matches(root, ext, false, false));
    let dropped_hidden: BTreeSet<_> = fd_hidden.difference(&fd_default).cloned().collect();
    let dropped_ignore: BTreeSet<_> = fd_ignore.difference(&fd_default).cloned().collect();

    // --- source 1+2: the content the pipe reads (in-process searcher) ---
    let content_all = match content_matches(root, pattern, &cfg_all_text(query)) {
        Ok(s) => relset(s),
        Err(e) => {
            let mut meta = Map::new();
            meta.insert("verb".into(), Value::from("find"));
            return (
                envelope(
                    false,
                    vec![],
                    meta,
                    vec![],
                    vec![],
                    vec![err("BAD_PATTERN", e)],
                ),
                1,
            );
        }
    };
    let rg_default = match content_matches(root, pattern, &cfg_default(query)) {
        Ok(s) => relset(s),
        Err(e) => {
            let mut meta = Map::new();
            meta.insert("verb".into(), Value::from("find"));
            return (
                envelope(
                    false,
                    vec![],
                    meta,
                    vec![],
                    vec![],
                    vec![err("BAD_PATTERN", e)],
                ),
                1,
            );
        }
    };
    let pipe_found: BTreeSet<_> = fd_default.intersection(&rg_default).cloned().collect();

    // --- source 3: Git history coverage ---
    // Probe at use time. A doctor result from an earlier command is advisory;
    // this result reports the executable state that this invocation observed.
    let git_health = crate::external_tools::probe("git");
    let history = match git_health["status"].as_str().unwrap_or("missing") {
        "available" => git_ever_matched(pattern, root, ext, query, explicit_case_sensitive),
        "missing" => History::GitAbsent,
        "unusable" => History::GitUnusable,
        "timed_out" => History::GitTimedOut,
        _ => History::Error,
    };
    if matches!(&history, History::Error) {
        let mut meta = Map::new();
        meta.insert("verb".into(), Value::from("find"));
        meta.insert("history".into(), history_meta(&history));
        return (
            envelope(
                false,
                vec![],
                meta,
                vec![],
                vec![history_probe_command(root)],
                vec![err(
                    "HISTORY_ERROR",
                    "Git history could not be scanned; no partial result was returned",
                )],
            ),
            3,
        );
    }
    let mut history_warnings: Vec<Value> = Vec::new();
    let mut history_commands: Vec<String> = Vec::new();
    match &history {
        History::GitAbsent => {
            history_warnings.push(warn(
                "GIT_ABSENT",
                "Git is unavailable; history coverage was not provided",
                vec![],
            ));
            history_commands.push(crate::command::shell("git", &["--version".into()]));
        }
        History::GitUnusable | History::GitTimedOut => {
            history_warnings.push(warn(
                "EXTERNAL_TOOL_MISSING",
                format!(
                    "Git is {}; history coverage was not provided",
                    git_health["status"].as_str().unwrap_or("unusable")
                ),
                vec![],
            ));
            history_commands.push(crate::command::shell("git", &["--version".into()]));
        }
        History::NotWorkTree => {
            history_warnings.push(warn(
                "GIT_NOT_WORK_TREE",
                "path is not a Git work tree; history coverage was not provided",
                vec![],
            ));
            history_commands.push(history_probe_command(root));
        }
        History::Partial { served, failed, .. } => {
            history_warnings.push(warn(
                "GIT_HISTORY_PARTIAL",
                format!("Git history served {served} revision(s); {failed} revision(s) failed"),
                vec![],
            ));
            history_commands.push(history_probe_command(root));
        }
        History::Available { .. } | History::Error => {}
    }

    // --- per-file stage attribution over the content the pipe surfaced ---
    let mut data: Vec<Value> = Vec::new();
    let mut stage_counts: BTreeMap<String, i64> = BTreeMap::new();
    let bump = |m: &mut BTreeMap<String, i64>, s: &str| {
        *m.entry(s.to_string()).or_insert(0) += 1;
    };
    let row = |file: &str, stage: &str, fix: Option<String>| -> Value {
        let mut r = Map::new();
        r.insert("file".into(), Value::from(file.to_string()));
        r.insert("stage".into(), Value::from(stage.to_string()));
        r.insert("fix".into(), fix.map(Value::from).unwrap_or(Value::Null));
        Value::from(r)
    };

    for f in &content_all {
        let (stage, fix): (&str, Option<String>) = if fd_default.contains(f) {
            if rg_default.contains(f) {
                ("found", None)
            } else {
                (
                    "rg_binary",
                    Some("add rg -a (fd passed it; rg suppressed a binary file)".into()),
                )
            }
        } else if fd_all.contains(f) {
            if dropped_hidden.contains(f) {
                (
                    "fd_hidden",
                    Some("add fd -H (hidden dotfile matches the name filter)".into()),
                )
            } else if dropped_ignore.contains(f) {
                (
                    "fd_ignore",
                    Some("add fd -I (gitignored file matches the name filter)".into()),
                )
            } else {
                ("fd_filter", Some("peel fd filters (fd -u)".into()))
            }
        } else {
            (
                "fd_name",
                Some(format!(
                    "widen name filter (the content match is outside *.{ext})"
                )),
            )
        };
        data.push(row(f, stage, fix));
        bump(&mut stage_counts, stage);
    }

    // --- source 3: Git history matches (scrubbed from the tree) ---
    let ever = history.matches();
    let git_deleted: Vec<String> = ever.difference(&content_all).cloned().collect(); // BTreeSet -> sorted
    let scrub_commits = git_scrub_commits(pattern, root, ext, query);
    for f in &git_deleted {
        data.push(row(
            f,
            "git_deleted",
            Some("recover the file from Git history".into()),
        ));
        bump(&mut stage_counts, "git_deleted");
    }

    // --- source 4: ast-grep structural (a construct with no literal form) ---
    let mut ast_only: Vec<String> = Vec::new();
    let mut structural_fallback = if structural.is_some() {
        None
    } else {
        Some("not-requested")
    };
    if let Some(sp) = structural {
        let lg = lang.unwrap_or("");
        match ast_files(sp, lg, root) {
            Structural::Used(ast_hits) => {
                // ast_only = files ast matched but a literal search for the pattern
                // text does NOT — surfaced only structurally.
                ast_only = ast_hits
                    .into_iter()
                    .filter(|f| !file_contains_literal(root, f, sp))
                    .collect(); // came from a BTreeSet -> already sorted
                for f in &ast_only {
                    data.push(row(
                        f,
                        "ast_structural",
                        Some(
                            "literal search finds 0; use the structural correction command".into(),
                        ),
                    ));
                    bump(&mut stage_counts, "ast_structural");
                }
            }
            Structural::Missing => structural_fallback = Some("tool-missing"),
            Structural::Unusable => structural_fallback = Some("tool-unusable"),
            Structural::TimedOut => structural_fallback = Some("tool-timed-out"),
        }
    }

    // --- headline: one line an agent can branch on ---
    let missed: Vec<&Value> = data.iter().filter(|d| d["stage"] != "found").collect();
    let tree_missed: Vec<&&Value> = missed
        .iter()
        .filter(|d| d["stage"] != "git_deleted" && d["stage"] != "ast_structural")
        .collect();
    let mut hist = String::new();
    if !git_deleted.is_empty() {
        hist.push_str(&format!(" (+{} in git history only)", git_deleted.len()));
    }
    if !ast_only.is_empty() {
        hist.push_str(&format!(
            " (+{} structural-only via ast-grep)",
            ast_only.len()
        ));
    }
    let headline = if fd_default.is_empty() {
        format!("FD_EMPTY: name filter matched no files; nothing reached rg{hist}")
    } else if pipe_found.is_empty() && !content_all.is_empty() {
        format!(
            "PIPE_EMPTY: fd found files but pipe surfaced no matches; see stage attribution{hist}"
        )
    } else if !tree_missed.is_empty() || !git_deleted.is_empty() || !ast_only.is_empty() {
        format!(
            "PARTIAL: pipe surfaced {}/{} in the tree; {} hidden by stage filters{hist}",
            pipe_found.len(),
            content_all.len(),
            tree_missed.len()
        )
    } else {
        "COMPLETE: pipe surfaced all matches".to_string()
    };

    // --- warnings: one per miss, carrying the paste-ready fix ---
    let mut warnings: Vec<Value> = history_warnings;
    if query.word && !git_deleted.is_empty() {
        warnings.push(warn(
            "GIT_SCRUB_WORD_UNAVAILABLE",
            "whole-word mode omits scrub-commit evidence because Git pickaxe is not whole-word",
            git_deleted.clone(),
        ));
    }
    if let Some(reason) = structural_fallback.filter(|reason| *reason != "not-requested") {
        warnings.push(warn(
            "EXTERNAL_TOOL_MISSING",
            format!("--structural source skipped: {reason}"),
            vec![],
        ));
    }
    for d in &missed {
        let stage = d["stage"].as_str().unwrap_or("");
        let file = d["file"].as_str().unwrap_or("").to_string();
        let mut msg = d["fix"].as_str().unwrap_or("").to_string();
        if stage == "git_deleted" {
            let sc = scrub_commits
                .get(&file)
                .cloned()
                .unwrap_or_else(|| "unknown".into());
            msg.push_str(&format!(" (scrubbed in {sc})"));
        }
        warnings.push(warn(&stage.to_uppercase(), msg, vec![file]));
    }

    // --- commands: correction recipes, one per distinct miss kind ---
    let mut commands: Vec<String> = history_commands;
    let has = |s: &str| missed.iter().any(|d| d["stage"] == s);
    if has("fd_hidden") || has("fd_ignore") || has("fd_filter") {
        let mut rg = query.rg_args(explicit_case_sensitive);
        rg.push("-a".into());
        commands.push(crate::command::pipe_fd_to_rg_with_mode(
            ext,
            pattern,
            root,
            &["-u"],
            &rg,
        ));
    }
    if has("fd_name") {
        let mut args = query.rg_args(explicit_case_sensitive);
        args.extend([
            "-uu".into(),
            "-e".into(),
            pattern.into(),
            "--".into(),
            root.into(),
        ]);
        commands.push(crate::command::shell("rg", &args));
    }
    if has("rg_binary") {
        let mut rg = query.rg_args(explicit_case_sensitive);
        rg.push("-a".into());
        commands.push(crate::command::pipe_fd_to_rg_with_mode(
            ext,
            pattern,
            root,
            &[],
            &rg,
        ));
    }
    if !git_deleted.is_empty() && !query.word {
        let mut args = vec!["log".into()];
        if query.case_insensitive {
            args.push("-i".into());
        }
        args.extend([
            "-S".into(),
            pattern.into(),
            "--oneline".into(),
            "--all".into(),
            "--".into(),
        ]);
        commands.push(crate::command::shell("git", &args));
    }
    if !ast_only.is_empty() {
        let sp = structural.unwrap_or("");
        let lg = lang.unwrap_or("");
        commands.push(crate::command::shell(
            "ast-grep",
            &[
                "run".into(),
                "-p".into(),
                sp.into(),
                "-l".into(),
                lg.into(),
                "--".into(),
                root.into(),
            ],
        ));
    }
    if structural_fallback.is_some_and(|reason| reason != "not-requested") {
        commands.push(crate::command::shell(
            "rf",
            &["doctor".into(), root.into(), "--json".into()],
        ));
    }

    // --- meta ---
    let mut meta = Map::new();
    meta.insert("verb".into(), Value::from("find"));
    meta.insert("pattern".into(), Value::from(pattern));
    meta.insert("name_filter".into(), Value::from(format!("*.{ext}")));
    meta.insert("path".into(), Value::from(root));
    meta.insert("query".into(), query.metadata());
    meta.insert("headline".into(), Value::from(headline));
    meta.insert("fd_default_files".into(), Value::from(fd_default.len()));
    meta.insert("pipe_matched".into(), Value::from(pipe_found.len()));
    meta.insert("content_total".into(), Value::from(content_all.len()));
    meta.insert("history_matches".into(), Value::from(git_deleted.len()));
    meta.insert("history".into(), history_meta(&history));
    let history_source = match &history {
        History::Available { .. } => {
            json!({"requested":true,"actual":"used","fallback_reason":null})
        }
        History::Partial { .. } => {
            json!({"requested":true,"actual":"used","fallback_reason":"history-partial"})
        }
        History::GitAbsent => {
            json!({"requested":true,"actual":"skipped","fallback_reason":"tool-missing"})
        }
        History::GitUnusable => {
            json!({"requested":true,"actual":"skipped","fallback_reason":"tool-unusable"})
        }
        History::GitTimedOut => {
            json!({"requested":true,"actual":"skipped","fallback_reason":"tool-timed-out"})
        }
        History::NotWorkTree => {
            json!({"requested":true,"actual":"skipped","fallback_reason":"not-work-tree"})
        }
        History::Error => {
            json!({"requested":true,"actual":"skipped","fallback_reason":"history-failed"})
        }
    };
    let structural_source = match structural_fallback {
        None => json!({"requested":true,"actual":"used","fallback_reason":null}),
        Some(reason) => {
            json!({"requested":structural.is_some(),"actual":"skipped","fallback_reason":reason})
        }
    };
    meta.insert(
        "sources".into(),
        json!({"history":history_source,"structural":structural_source}),
    );
    meta.insert("structural_matches".into(), Value::from(ast_only.len()));
    let counts: Map<String, Value> = stage_counts
        .into_iter()
        .map(|(k, v)| (k, Value::from(v)))
        .collect();
    meta.insert("hidden_by_stage".into(), Value::from(counts));

    let mut page_query = json!({
        "verb": "find", "pattern": pattern, "path": path, "name": name,
        "structural": structural, "lang": lang,
    });
    if let Some(mode) = query.pagination_value() {
        page_query
            .as_object_mut()
            .unwrap()
            .insert("query".into(), mode);
    }
    match crate::pagination::page(data, &page_query, limit, cursor) {
        Ok(page) => {
            let has_more = page.next_cursor.is_some();
            meta.insert(
                "pagination".into(),
                json!({
                    "limit": limit,
                    "returned": page.data.len(),
                    "total": page.total,
                    "truncated": has_more,
                    "has_more": has_more,
                    "cursor": page.next_cursor,
                    "snapshot_hash": page.snapshot_hash,
                }),
            );
            (
                envelope(true, page.data, meta, warnings, commands, vec![]),
                0,
            )
        }
        Err(error) => {
            let mut failure_meta = Map::new();
            failure_meta.insert("verb".into(), Value::from("find"));
            let (code, message, exit, restart) =
                match error {
                    crate::pagination::Error::InvalidCursor => (
                        "INVALID_INPUT",
                        "cursor is malformed or does not match this query",
                        1,
                        vec![],
                    ),
                    crate::pagination::Error::Conflict => {
                        let mut args = vec!["find".into(), "--name".into(), name.into()];
                        if let (Some(structural), Some(lang)) = (structural, lang) {
                            args.extend([
                                "--structural".into(),
                                structural.into(),
                                "--lang".into(),
                                lang.into(),
                            ]);
                        }
                        args.extend(query.rg_args(explicit_case_sensitive).into_iter().map(
                            |arg| match arg.as_str() {
                                "-F" => "--fixed-strings".into(),
                                "-w" => "--word".into(),
                                "-i" => "--ignore-case".into(),
                                "-s" => "--case-sensitive".into(),
                                _ => arg,
                            },
                        ));
                        args.extend([
                            "--limit".into(),
                            limit.to_string(),
                            pattern.into(),
                            "--".into(),
                            path.into(),
                        ]);
                        (
                            "CONFLICT",
                            "the result snapshot changed; restart the query",
                            5,
                            vec![crate::command::shell("rf", &args)],
                        )
                    }
                };
            (
                envelope(
                    false,
                    vec![],
                    failure_meta,
                    vec![],
                    restart,
                    vec![err(code, message)],
                ),
                exit,
            )
        }
    }
}

#[cfg(test)]
mod history_tests {
    use super::{git_ever_matched_with, History};
    use crate::query::QueryMode;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fake_git(label: &str, script: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("rf-history-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("git");
        fs::write(&path, script).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    #[test]
    fn history_outcomes_are_distinct_and_coverage_is_counted() {
        let absent = git_ever_matched_with(
            std::path::Path::new("/rf-no-such-git"),
            "needle",
            ".",
            "config",
            QueryMode::default(),
            false,
        );
        assert!(matches!(absent, History::GitAbsent));

        let not_work_tree = fake_git("not-work-tree", "#!/bin/sh\nexit 128\n");
        let state = git_ever_matched_with(
            &not_work_tree,
            "needle",
            ".",
            "config",
            QueryMode::default(),
            false,
        );
        assert!(matches!(state, History::NotWorkTree));

        let partial = fake_git(
            "partial",
            "#!/bin/sh\ncase \"$*\" in\n  *rev-parse*) printf 'true\\n' ;;\n  *rev-list*) printf 'good\\nbad\\n' ;;\n  *grep*good*) printf 'good:old.config\\n' ;;\n  *grep*) exit 2 ;;\nesac\n",
        );
        let state = git_ever_matched_with(
            &partial,
            "needle",
            ".",
            "config",
            QueryMode::default(),
            false,
        );
        match state {
            History::Partial {
                matches,
                served,
                failed,
            } => {
                assert_eq!(matches.into_iter().collect::<Vec<_>>(), vec!["old.config"]);
                assert_eq!((served, failed), (1, 1));
            }
            _ => panic!("expected partial history"),
        }

        let error = fake_git(
            "error",
            "#!/bin/sh\ncase \"$*\" in *rev-parse*) printf 'true\\n' ;; *rev-list*) exit 2 ;; esac\n",
        );
        let state =
            git_ever_matched_with(&error, "needle", ".", "config", QueryMode::default(), false);
        assert!(matches!(state, History::Error));
    }
}
