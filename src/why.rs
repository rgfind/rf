//! The `why` verb — one-file forensic classification.

use crate::content::{classify_target, validate_single_target, Class, TargetError};
use crate::doctor::git_context;
use crate::engine::SearchCfg;
use crate::envelope::{envelope, err, warn};
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

fn invalid(arg: &str, message: String, remediation: &str) -> (Value, i32) {
    let mut error = err("INVALID_INPUT", message);
    let object = error.as_object_mut().expect("error is an object");
    object.insert("arg".into(), Value::from(arg));
    object.insert("remediation".into(), Value::from(remediation));
    let mut meta = Map::new();
    meta.insert("verb".into(), Value::from("why"));
    (
        envelope(false, Value::Null, meta, vec![], vec![], vec![error]),
        1,
    )
}

fn target_failure(target: &str, root: Option<&str>, error: TargetError) -> (Value, i32) {
    let fix = "Name one regular file under --root.";
    match error {
        TargetError::Missing => crate::paths::not_found("why", "file", target),
        TargetError::Unreadable(number) => crate::paths::io_failure(
            "why",
            Path::new(target),
            &crate::paths::errno_name(&std::io::Error::from_raw_os_error(number)),
            &[],
        ),
        TargetError::Directory => invalid(
            "file",
            format!("{target} is a directory"),
            "Name one regular file; `rf content <pattern> <dir>` searches a tree.",
        ),
        TargetError::NotRegular => invalid("file", format!("{target} is not a regular file"), fix),
        TargetError::InsideGit => invalid(
            "file",
            format!("{target} is inside .git; rf does not search repository internals"),
            fix,
        ),
        TargetError::OutsideRoot => invalid(
            "file",
            format!("{target} is outside --root {}", root.unwrap_or(".")),
            fix,
        ),
    }
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

fn resolve_root(target: &str, root_arg: Option<&str>) -> Result<(PathBuf, PathBuf), (Value, i32)> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let target_path = Path::new(target);
    let target_candidate = if target_path.is_absolute() {
        target_path.to_path_buf()
    } else {
        cwd.join(target_path)
    };

    if let Some(root_arg) = root_arg {
        crate::paths::must_exist("why", "--root", root_arg)?;
        let root = match std::fs::canonicalize(root_arg) {
            Ok(root) if root.is_dir() => root,
            _ => {
                return Err(invalid(
                    "--root",
                    format!("--root {root_arg} is not a directory"),
                    "Give --root a directory.",
                ))
            }
        };
        return Ok((root, target_candidate));
    }

    let canonical_target = match std::fs::canonicalize(&target_candidate) {
        Ok(path) => path,
        Err(error) => return Err(target_failure(target, None, TargetError::from_io(&error))),
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
    if max_matches.is_some() && !evidence {
        let mut meta = Map::new();
        meta.insert("verb".into(), Value::from("why"));
        return (
            envelope(
                false,
                Value::Null,
                meta,
                vec![],
                vec![],
                vec![err("MISSING_REQUIRED", "--max-matches requires --matches")],
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
                    Value::Null,
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
    let match_cap = max_matches
        .unwrap_or(crate::engine::MAX_EVIDENCE_MATCHES)
        .min(crate::engine::MAX_EVIDENCE_MATCHES);
    // Every key is in every reply; a key with no value is null.
    let matches = if evidence {
        Value::Array(
            crate::engine::occurrences(
                &canonical.to_string_lossy(),
                pattern,
                &evidence_cfg(class, query),
                match_cap,
            )
            .unwrap_or_default()
            .into_iter()
            .map(crate::engine::occurrence_json)
            .collect(),
        )
    } else {
        Value::Null
    };
    row.insert("matches".into(), matches);
    row.insert("ignore_source".into(), Value::Null);
    row.insert("hiding_filter".into(), Value::Null);

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
    meta.insert(
        "evidence".into(),
        crate::engine::evidence_meta(evidence, match_cap),
    );
    (
        envelope(true, Value::from(row), meta, warnings, commands, vec![]),
        0,
    )
}
