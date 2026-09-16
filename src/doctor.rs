//! The `doctor` verb — environment diagnosis. In the in-process port there is
//! no rg/fd subprocess to probe; instead we report the linked engine and, most
//! importantly, the active ignore mode for the target path. That is the
//! context-flip finding: .gitignore rules only apply inside a git work tree, so
//! the same query gives different answers in a scratch dir vs a real repo.

use crate::envelope::{envelope, warn, TOOL_VERSION};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

pub(crate) struct GitContext {
    pub(crate) in_repo: bool,
    pub(crate) ignore_mode: &'static str,
    pub(crate) root: PathBuf,
}

/// Walk up from `path` looking for a `.git` entry (dir or file, to cover
/// worktrees/submodules). Mirrors `git rev-parse --is-inside-work-tree`.
pub(crate) fn git_context(path: &str) -> GitContext {
    let start = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
    let mut cur: Option<&Path> = Some(start.as_path());
    while let Some(dir) = cur {
        if dir.join(".git").exists() {
            return GitContext {
                in_repo: true,
                ignore_mode: "gitignore-ACTIVE (walker skips ignored+hidden)",
                root: dir.to_path_buf(),
            };
        }
        cur = dir.parent();
    }
    GitContext {
        in_repo: false,
        ignore_mode: "gitignore-INACTIVE (not a git repo; ignore files not applied)",
        root: start,
    }
}

pub fn run(path: &str) -> (Value, i32) {
    crate::fault::maybe_fault("doctor");
    let context = git_context(path);
    let in_repo = context.in_repo;
    let ignore_mode = context.ignore_mode;

    let mut d = Map::new();
    d.insert("rf_version".into(), Value::from(TOOL_VERSION));
    d.insert(
        "engine".into(),
        Value::from("in-process: ignore + grep crates (ripgrep/fd guts)"),
    );
    d.insert("path".into(), Value::from(path));
    d.insert("git_repo".into(), Value::from(in_repo));
    d.insert("ignore_mode".into(), Value::from(ignore_mode));

    let git = crate::external_tools::probe("git");
    let ast_grep = crate::external_tools::probe("ast-grep");
    let mut external_tools = Map::new();
    external_tools.insert("git".into(), git.clone());
    external_tools.insert("ast-grep".into(), ast_grep.clone());
    d.insert("external_tools".into(), Value::from(external_tools));

    let degraded: Vec<(&str, Value)> = [("git", git), ("ast-grep", ast_grep)]
        .into_iter()
        .filter(|(_, health)| health["status"] != "available")
        .collect();

    let mut rec = Map::new();
    rec.insert("is_destructive".into(), Value::from(false));
    if degraded.is_empty() {
        rec.insert("command".into(), Value::Null);
        rec.insert(
            "rationale".into(),
            Value::from("all external tools available"),
        );
        rec.insert("affected".into(), Value::Array(vec![]));
        rec.insert("alternatives".into(), Value::Array(vec![]));
        rec.insert("references".into(), Value::Array(vec![]));
    } else {
        let affected = degraded
            .iter()
            .map(|(tool, health)| {
                let mode = if *tool == "git" {
                    "find history"
                } else {
                    "find --structural"
                };
                serde_json::json!({"verb":"find","mode":mode,"status":health["status"]})
            })
            .collect();
        rec.insert("command".into(), Value::Null);
        rec.insert("rationale".into(), Value::from("an optional external search source is degraded; use the documented install method or continue with in-process search"));
        rec.insert("affected".into(), Value::Array(affected));
        rec.insert("alternatives".into(), Value::Array(vec![serde_json::json!({"command":"rf content '<pattern>' <path> --json","purpose":"run the in-process forensic content search"})]));
        rec.insert(
            "references".into(),
            Value::Array(
                degraded
                    .iter()
                    .map(|(tool, _)| {
                        let url = if *tool == "git" {
                            "https://git-scm.com/downloads"
                        } else {
                            "https://ast-grep.github.io/guide/quick-start.html"
                        };
                        serde_json::json!({"url":url,"purpose":format!("install or repair {tool}")})
                    })
                    .collect(),
            ),
        );
    }
    d.insert("recommended_action".into(), Value::from(rec));

    let mut warnings = vec![warn(
        "IGNORE_MODE",
        format!(
            "ignore behavior here: {ignore_mode}. Results differ from a real repo if this flips."
        ),
        vec![],
    )];
    for (tool, health) in &degraded {
        warnings.push(warn(
            "EXTERNAL_TOOL_MISSING",
            format!(
                "{tool} is {}; dependent find mode is unavailable",
                health["status"].as_str().unwrap_or("unknown")
            ),
            vec![],
        ));
    }

    let mut meta = Map::new();
    meta.insert("verb".into(), Value::from("doctor"));
    let commands = if degraded.is_empty() {
        vec![]
    } else {
        vec!["rf content '<pattern>' <path> --json".into()]
    };
    (
        envelope(true, vec![Value::from(d)], meta, warnings, commands, vec![]),
        0,
    )
}
