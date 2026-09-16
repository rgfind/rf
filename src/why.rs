//! The `why` verb — one-file forensic classification.

use crate::content::{classify_target, validate_single_target, Class, TargetError};
use crate::doctor::git_context;
use crate::engine::SearchCfg;
use crate::envelope::{envelope, err, err_with, warn};
use crate::query::QueryMode;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn display_root(root: &Path) -> String {
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|path| std::fs::canonicalize(path).ok());
    let relative = cwd
        .as_deref()
        .and_then(|cwd| pathdiff::diff_paths(root, cwd));
    match relative {
        Some(path) if path.as_os_str().is_empty() => ".".into(),
        Some(path) => slash(&path),
        None => slash(root),
    }
}

fn target_failure(target: &str, root: Option<&str>, error: TargetError) -> (Value, i32) {
    let remediation = match error {
        TargetError::Missing => format!("no such file: {target}; pass one existing regular file"),
        TargetError::Directory => {
            format!("{target} is a directory; use 'rf content <pattern> <dir>' to search a tree")
        }
        TargetError::NotRegular => format!("{target} is not a regular file"),
        TargetError::Unreadable => format!("{target} is not readable"),
        TargetError::InsideGit => {
            format!("{target} is inside .git; rf does not search repository internals")
        }
        TargetError::OutsideRoot => format!("{target} is outside --root {}", root.unwrap_or(".")),
    };
    let mut meta = Map::new();
    meta.insert("verb".into(), Value::from("why"));
    (
        envelope(
            false,
            vec![],
            meta,
            vec![],
            vec![],
            vec![err_with(
                "INVALID_TARGET",
                "target cannot be searched",
                target,
                remediation,
            )],
        ),
        1,
    )
}

fn evidence_cfg(class: Option<Class>, query: QueryMode) -> SearchCfg {
    let class = class.unwrap_or(Class::Default);
    let (use_ignore, skip_hidden, binary_as_text, encoding) = match class {
        Class::Default => (true, true, false, None),
        Class::VcsIgnore => (false, true, false, None),
        Class::Hidden => (false, false, false, None),
        Class::Binary => (false, false, true, None),
        Class::Case => (false, false, true, None),
        Class::EncodingUtf16 => (false, false, true, Some("utf-16")),
    };
    let query = if class == Class::Case {
        QueryMode {
            case_insensitive: true,
            ..query
        }
    } else {
        query
    };
    SearchCfg {
        use_ignore,
        skip_hidden,
        binary_as_text,
        query,
        encoding,
    }
}

fn occurrence_value(value: crate::engine::Occurrence) -> Value {
    let mut occurrence = Map::new();
    occurrence.insert("line".into(), Value::from(value.line));
    occurrence.insert("column_byte".into(), Value::from(value.column_byte));
    occurrence.insert("text".into(), Value::from(value.text));
    if value.text_lossy {
        occurrence.insert("text_lossy".into(), Value::from(true));
    }
    if value.text_truncated {
        occurrence.insert("text_truncated".into(), Value::from(true));
    }
    Value::from(occurrence)
}

fn bad_root(target: &str, root: &str) -> (Value, i32) {
    let mut meta = Map::new();
    meta.insert("verb".into(), Value::from("why"));
    (
        envelope(
            false,
            vec![],
            meta,
            vec![],
            vec![],
            vec![err_with(
                "INVALID_TARGET",
                "root cannot be used for target validation",
                target,
                format!("--root {root} does not exist or is not a directory"),
            )],
        ),
        1,
    )
}

fn resolve_root(target: &str, root_arg: Option<&str>) -> Result<(PathBuf, PathBuf), (Value, i32)> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let target_path = Path::new(target);
    let target_candidate = if target_path.is_absolute() {
        target_path.to_path_buf()
    } else {
        cwd.join(target_path)
    };

    if let Some(root_arg) = root_arg {
        let root = match std::fs::canonicalize(root_arg) {
            Ok(root) if root.is_dir() => root,
            _ => return Err(bad_root(target, root_arg)),
        };
        return Ok((root, target_candidate));
    }

    let canonical_target = match std::fs::canonicalize(&target_candidate) {
        Ok(path) => path,
        Err(_) => return Err(target_failure(target, None, TargetError::Missing)),
    };
    let context = git_context(&slash(&canonical_target));
    let root = if context.in_repo {
        context.root
    } else {
        canonical_target
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf()
    };
    Ok((root, canonical_target))
}

pub fn run(
    pattern: &str,
    target: &str,
    root_arg: Option<&str>,
    query: QueryMode,
    explicit_case_sensitive: bool,
    evidence: bool,
    max_matches: Option<usize>,
) -> (Value, i32) {
    crate::fault::maybe_fault("why");
    if max_matches.is_some() && !evidence {
        let mut meta = Map::new();
        meta.insert("verb".into(), Value::from("why"));
        return (
            envelope(
                false,
                vec![],
                meta,
                vec![],
                vec![],
                vec![err("INVALID_INPUT", "--max-matches requires --matches")],
            ),
            1,
        );
    }
    let (root, target_candidate) = match resolve_root(target, root_arg) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let (relative, canonical) = match validate_single_target(&root, &target_candidate) {
        Ok(value) => value,
        Err(error) => return target_failure(target, root_arg, error),
    };
    let file = slash(&relative);
    let root_display = display_root(&root);
    let class = match classify_target(pattern, &root, &canonical, query) {
        Ok(class) => class,
        Err(message) => {
            let mut meta = Map::new();
            meta.insert("verb".into(), Value::from("why"));
            return (
                envelope(
                    false,
                    vec![],
                    meta,
                    vec![],
                    vec![],
                    vec![err("BAD_PATTERN", message)],
                ),
                1,
            );
        }
    };

    let matched = class.is_some();
    let hidden = matches!(class, Some(value) if value != Class::Default);
    let mut row = Map::new();
    row.insert("file".into(), Value::from(file.clone()));
    row.insert("pattern".into(), Value::from(pattern));
    row.insert("matched".into(), Value::from(matched));
    row.insert("hidden_from_default".into(), Value::from(hidden));
    row.insert(
        "surfaced_by".into(),
        class
            .map(|value| Value::from(value.name()))
            .unwrap_or(Value::Null),
    );
    if evidence {
        let matches = crate::engine::occurrences(
            &canonical.to_string_lossy(),
            pattern,
            &evidence_cfg(class, query),
            max_matches
                .unwrap_or(crate::engine::MAX_EVIDENCE_MATCHES)
                .min(crate::engine::MAX_EVIDENCE_MATCHES),
        )
        .unwrap_or_default()
        .into_iter()
        .map(occurrence_value)
        .collect();
        row.insert("matches".into(), Value::Array(matches));
    }

    let mut warnings = Vec::new();
    let mut commands = Vec::new();
    if let Some(class) = class {
        if class == Class::VcsIgnore {
            match crate::provenance::resolve(&root, &canonical) {
                Ok(source) => {
                    row.insert("ignore_source".into(), source);
                }
                Err(reason) => warnings.push(warn(
                    "IGNORE_SOURCE_UNRESOLVED",
                    format!("ignore provenance could not be reconstructed: {reason}"),
                    vec![file.clone()],
                )),
            }
        }
        if let Some((code, hint, flags)) = class.hiding_filter() {
            row.insert(
                "hiding_filter".into(),
                serde_json::json!({"code": code, "layer": class.name(), "rg_flags": flags}),
            );
            warnings.push(warn(
                code,
                format!("match hidden from a default tree search; {hint}"),
                vec![file.clone()],
            ));
            let mut args = query.rg_args(explicit_case_sensitive);
            args.extend(flags.split_whitespace().map(String::from));
            args.extend([
                "-e".into(),
                pattern.into(),
                "--".into(),
                root_display.clone(),
            ]);
            commands.push(crate::command::shell("rg", &args));
        }
    }

    let context = git_context(&slash(&canonical));
    let mut meta = Map::new();
    meta.insert("verb".into(), Value::from("why"));
    meta.insert("pattern".into(), Value::from(pattern));
    meta.insert("file".into(), Value::from(file));
    meta.insert("root".into(), Value::from(root_display));
    meta.insert("query".into(), query.metadata());
    meta.insert("git_repo".into(), Value::from(context.in_repo));
    meta.insert("ignore_mode".into(), Value::from(context.ignore_mode));
    meta.insert("matched".into(), Value::from(matched));
    meta.insert(
        "surfaced_by".into(),
        class
            .map(|value| Value::from(value.name()))
            .unwrap_or(Value::Null),
    );
    if evidence {
        meta.insert(
            "evidence".into(),
            serde_json::json!({
                "requested": true,
            "match_cap": max_matches.unwrap_or(crate::engine::MAX_EVIDENCE_MATCHES).min(crate::engine::MAX_EVIDENCE_MATCHES),
                "text_bytes_cap": crate::engine::MAX_EVIDENCE_TEXT_BYTES,
                "response_bytes_cap": crate::pagination::MAX_EVIDENCE_RESPONSE_BYTES,
            }),
        );
    }
    (
        envelope(
            true,
            vec![Value::from(row)],
            meta,
            warnings,
            commands,
            vec![],
        ),
        0,
    )
}
