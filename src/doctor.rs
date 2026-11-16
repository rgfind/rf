//! The `doctor` verb — environment diagnosis. In the in-process port there is
//! no rg/fd subprocess to probe; instead we report the linked engine and, most
//! importantly, the active ignore mode for the target path. That is the
//! context-flip finding: .gitignore rules only apply inside a git work tree, so
//! the same query gives different answers in a scratch dir vs a real repo.

use crate::envelope::{envelope, err, warn, TOOL_VERSION};
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

fn install_url(tool: &str) -> &'static str {
    if tool == "git" {
        "https://git-scm.com/downloads"
    } else {
        "https://ast-grep.github.io/guide/quick-start.html"
    }
}

/// The health state of one tool record: `missing` is a fallback (the find
/// source is skipped), a tool that is present and cannot run is unhealthy.
fn state(health: &Value) -> &'static str {
    match health["status"].as_str() {
        Some("available") => "healthy",
        Some("missing") => "degraded",
        _ => "unhealthy",
    }
}

pub fn run(path: &str) -> (Value, i32) {
    crate::fault::maybe_fault("doctor");
    if let Err(failure) = crate::paths::must_exist("doctor", "path", path) {
        return failure;
    }
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

    // Sorted by component name; the error order below depends on it.
    let mut tools: Vec<(&str, Value)> = Vec::new();
    for tool in ["ast-grep", "git"] {
        let mut health = crate::external_tools::probe(tool);
        let tool_state = state(&health);
        health["state"] = Value::from(tool_state);
        tools.push((tool, health));
    }
    let mut external_tools = Map::new();
    for (tool, health) in &tools {
        external_tools.insert((*tool).into(), health.clone());
    }
    d.insert("external_tools".into(), Value::from(external_tools));

    let with_state = |wanted: &str| -> Vec<&(&str, Value)> {
        tools.iter().filter(|(_, h)| h["state"] == wanted).collect()
    };
    let unhealthy = with_state("unhealthy");
    let degraded = with_state("degraded");
    let overall = if !unhealthy.is_empty() {
        "unhealthy"
    } else if !degraded.is_empty() {
        "degraded"
    } else {
        "healthy"
    };
    d.insert("overall".into(), Value::from(overall));
    let faulty: Vec<&(&str, Value)> = unhealthy.iter().chain(degraded.iter()).copied().collect();

    let mut rec = Map::new();
    rec.insert("is_destructive".into(), Value::from(false));
    rec.insert("command".into(), Value::Null);
    if faulty.is_empty() {
        rec.insert(
            "rationale".into(),
            Value::from("all external tools available"),
        );
        rec.insert("affected".into(), Value::Array(vec![]));
        rec.insert("alternatives".into(), Value::Array(vec![]));
        rec.insert("references".into(), Value::Array(vec![]));
    } else {
        let affected = faulty
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
        rec.insert("rationale".into(), Value::from("an optional external search source is degraded; use the documented install method or continue with in-process search"));
        rec.insert("affected".into(), Value::Array(affected));
        rec.insert("alternatives".into(), Value::Array(vec![serde_json::json!({"command":"rf content '<pattern>' <path> --json","purpose":"run the in-process forensic content search"})]));
        rec.insert(
            "references".into(),
            Value::Array(
                faulty
                    .iter()
                    .map(|(tool, _)| {
                        serde_json::json!({"url":install_url(tool),"purpose":format!("install or repair {tool}")})
                    })
                    .collect(),
            ),
        );
    }
    d.insert("recommended_action".into(), Value::from(rec));

    let warnings = vec![warn(
        "IGNORE_MODE",
        format!(
            "ignore behavior here: {ignore_mode}. Results differ from a real repo if this flips."
        ),
        vec![],
    )];

    // One error per faulty tool: the unhealthy group, then the degraded
    // group, each in component-name order.
    let errors: Vec<Value> = faulty
        .iter()
        .map(|(tool, health)| {
            let status = health["status"].as_str().unwrap_or("unknown");
            let (code, verb_phrase) = if health["state"] == "unhealthy" {
                ("COMPONENT_UNHEALTHY", "Repair or reinstall")
            } else {
                ("COMPONENT_DEGRADED", "Install")
            };
            let source = if *tool == "git" {
                "find history"
            } else {
                "find --structural"
            };
            let mut error = err(code, format!("{tool} is {status}; {source} cannot run"));
            error["remediation"] =
                Value::from(format!("{verb_phrase} {tool}: {}", install_url(tool)));
            error["details"] = serde_json::json!({"component": tool, "status": status});
            error
        })
        .collect();

    let mut meta = Map::new();
    meta.insert("verb".into(), Value::from("doctor"));
    let (ok, exit, commands) = if errors.is_empty() {
        (true, 0, vec![])
    } else {
        (
            false,
            6,
            vec!["rf content '<pattern>' <path> --json".into()],
        )
    };
    (
        envelope(ok, Value::from(d), meta, warnings, commands, errors),
        exit,
    )
}
