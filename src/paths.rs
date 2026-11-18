//! Path faults. A path that does not exist is the caller's error
//! (`NOT_FOUND`, exit 1). A path that exists and cannot be read is the
//! environment's (`IO_FAILURE`, exit 3).

use crate::envelope::{envelope, err};
use serde_json::{json, Map, Value};
use std::io;
use std::path::Path;

/// The errno name of an OS error, for `details.os_error`.
pub fn errno_name(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(1) => "EPERM".into(),
        Some(2) => "ENOENT".into(),
        Some(5) => "EIO".into(),
        Some(13) => "EACCES".into(),
        Some(20) => "ENOTDIR".into(),
        Some(21) => "EISDIR".into(),
        Some(24) => "EMFILE".into(),
        Some(28) => "ENOSPC".into(),
        Some(30) => "EROFS".into(),
        Some(62) | Some(40) => "ELOOP".into(),
        Some(63) | Some(36) => "ENAMETOOLONG".into(),
        Some(number) => format!("errno {number}"),
        None => match error.kind() {
            io::ErrorKind::PermissionDenied => "EACCES".into(),
            io::ErrorKind::NotFound => "ENOENT".into(),
            kind => format!("{kind:?}"),
        },
    }
}

fn absolute(path: &Path) -> String {
    std::path::absolute(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

fn failure(verb: &str, error: Value, exit: i32) -> (Value, i32) {
    let mut meta = Map::new();
    meta.insert("verb".into(), Value::from(verb));
    (
        envelope(false, Value::Null, meta, vec![], vec![], vec![error]),
        exit,
    )
}

/// `NOT_FOUND` for the path that `arg` supplied.
pub fn not_found(verb: &str, arg: &str, path: &str) -> (Value, i32) {
    let mut error = err("NOT_FOUND", format!("no such file or directory: {path}"));
    let object = error.as_object_mut().expect("error is an object");
    object.insert("arg".into(), Value::from(arg));
    object.insert(
        "remediation".into(),
        Value::from(if arg.starts_with('-') {
            format!("Give {arg} a path that exists.")
        } else {
            format!("Give <{arg}> a path that exists.")
        }),
    );
    failure(verb, error, 1)
}

/// `IO_FAILURE` for a read of `file` that the OS refused. `others` lists
/// more paths with the same outcome.
pub fn io_failure(verb: &str, file: &Path, os_error: &str, others: &[String]) -> (Value, i32) {
    let file = absolute(file);
    let mut error = err("IO_FAILURE", format!("cannot read {file}: {os_error}"));
    let mut details = json!({"op": "read", "file": file, "os_error": os_error});
    if !others.is_empty() {
        details["files"] = json!(others);
    }
    error
        .as_object_mut()
        .expect("error is an object")
        .insert("details".into(), details);
    failure(verb, error, 3)
}

/// Stage 7 for a path that the verb reads: it must exist.
pub fn must_exist(verb: &str, arg: &str, path: &str) -> Result<(), (Value, i32)> {
    match std::fs::metadata(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(not_found(verb, arg, path)),
        Err(error) => Err(io_failure(verb, Path::new(path), &errno_name(&error), &[])),
    }
}

/// Close a walk. No file read and one or more paths refused: `IO_FAILURE`.
/// Some files read and some paths refused: a `PARTIAL_RESULT` warning.
/// `display` maps a walked path to the form that the verb reports.
pub fn settle(
    verb: &str,
    display: impl Fn(&crate::rawpath::RawPath) -> String,
) -> Result<Option<Value>, (Value, i32)> {
    let skips = crate::engine::take_skips();
    let Some((first, os_error)) = skips.unreadable.iter().next() else {
        return Ok(None);
    };
    if !skips.read_ok {
        let others: Vec<String> = skips
            .unreadable
            .keys()
            .skip(1)
            .map(|p| absolute(&p.to_path_buf()))
            .collect();
        return Err(io_failure(verb, &first.to_path_buf(), os_error, &others));
    }
    let files: Vec<String> = skips.unreadable.keys().map(display).collect();
    Ok(Some(crate::envelope::warn(
        "PARTIAL_RESULT",
        format!(
            "{} path(s) could not be read; the result does not cover them",
            files.len()
        ),
        files,
    )))
}
