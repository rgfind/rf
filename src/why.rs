//! The `why` verb — one-file forensic classification.

use crate::content::{classify_target, validate_single_target, Class, TargetError};
use crate::doctor::git_context;
use crate::envelope::{envelope, err, err_with, warn};
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

pub fn run(pattern: &str, target: &str, root_arg: Option<&str>) -> (Value, i32) {
    crate::fault::maybe_fault("why");
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
    let class = match classify_target(pattern, &root, &canonical) {
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

    let mut warnings = Vec::new();
    let mut commands = Vec::new();
    if let Some(class) = class {
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
            let mut args: Vec<String> = flags.split_whitespace().map(String::from).collect();
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
    meta.insert("git_repo".into(), Value::from(context.in_repo));
    meta.insert("ignore_mode".into(), Value::from(context.ignore_mode));
    meta.insert("matched".into(), Value::from(matched));
    meta.insert(
        "surfaced_by".into(),
        class
            .map(|value| Value::from(value.name()))
            .unwrap_or(Value::Null),
    );
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
