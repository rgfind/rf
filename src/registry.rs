//! The one code registry and the exit dictionary. Every `errors[].code` and
//! `warnings[].code` that rf can emit has one entry here. `capabilities`
//! publishes the table, `err()` reads the default remediation from it, and
//! `emit` checks the process status against it.

use serde_json::{json, Map, Value};

/// How a caller reproduces a code.
pub enum Repro {
    /// A bare call is enough.
    Example(&'static str),
    /// The code needs a prepared state.
    Fixture {
        precondition: &'static str,
        fixture: &'static str,
    },
}

pub struct Code {
    pub name: &'static str,
    pub errors: bool,
    pub warnings: bool,
    /// The exit of a call whose first error has this code. None for a code
    /// that appears only in `warnings`.
    pub exit: Option<i32>,
    pub summary: &'static str,
    /// Default `remediation` for an error that sets none of its own.
    pub remediation: Option<&'static str>,
    pub repro: Repro,
    /// Verbs that emit the code.
    pub sites: &'static [&'static str],
    /// Shape of `details` on the entry.
    pub details: &'static str,
}

const fn error(
    name: &'static str,
    exit: i32,
    summary: &'static str,
    remediation: &'static str,
    repro: Repro,
    sites: &'static [&'static str],
    details: &'static str,
) -> Code {
    Code {
        name,
        errors: true,
        warnings: false,
        exit: Some(exit),
        summary,
        remediation: Some(remediation),
        repro,
        sites,
        details,
    }
}

const fn warning(
    name: &'static str,
    summary: &'static str,
    fixture: &'static str,
    sites: &'static [&'static str],
    details: &'static str,
) -> Code {
    Code {
        name,
        errors: false,
        warnings: true,
        exit: None,
        summary,
        remediation: None,
        repro: Repro::Fixture {
            precondition: summary,
            fixture,
        },
        sites,
        details,
    }
}

const ALL: &[&str] = &["*"];
const FILES: &str = "details.files[]";
const NONE: &str = "null";

pub const CODES: &[Code] = &[
    error(
        "UNKNOWN_FLAG",
        1,
        "flag not recognized",
        "Run `rf --help` for the declared flags.",
        Repro::Example("rf --json content --bogus x"),
        ALL,
        NONE,
    ),
    error(
        "UNKNOWN_COMMAND",
        1,
        "command not recognized",
        "Run `rf --help` for the declared commands.",
        Repro::Example("rf --json bogus"),
        ALL,
        NONE,
    ),
    error(
        "INVALID_INPUT",
        1,
        "a supplied value failed validation: type, range, enum, pattern, empty value, flag conflict, surplus positional, or malformed cursor",
        "Correct the value named in `arg`; `rf capabilities --json` declares each flag domain.",
        Repro::Example("rf --json content --limit=0 x"),
        ALL,
        "null, or {bytes_hex} for undecodable argv",
    ),
    error(
        "MISSING_REQUIRED",
        1,
        "a required positional, flag, flag value, or companion flag is absent",
        "Add the item named in `arg`.",
        Repro::Example("rf --json content"),
        ALL,
        NONE,
    ),
    error(
        "INVALID_SELECTION",
        1,
        "selected-input bytes or paths failed validation",
        "Send only readable regular files under the root, each one time; do not send paths inside .git.",
        Repro::Example("printf 'no-such-file\\0' | rf --json content --paths-stdin x ."),
        &["content"],
        NONE,
    ),
    error(
        "NOT_FOUND",
        1,
        "a path that the caller named does not exist",
        "Correct the path named in `arg`.",
        Repro::Example("rf --json why x no-such-file"),
        &["content", "doctor", "find", "why"],
        NONE,
    ),
    error(
        "IO_FAILURE",
        3,
        "a path that the caller named exists and rf cannot read it",
        "Read details.os_error, then correct the permissions or the type of details.file.",
        Repro::Fixture {
            precondition: "a file that exists and has no read permission",
            fixture: "chmod 000 a file, then run why or content on it",
        },
        &["content", "find", "why"],
        "{op, file, os_error}; files[] also, when more than one path failed",
    ),
    error(
        "DEPENDENCY_MISSING",
        3,
        "a program that the call needs is not on the search path",
        "Install ast-grep (https://ast-grep.github.io/guide/quick-start.html) and put it on PATH, or remove --structural.",
        Repro::Fixture {
            precondition: "ast-grep is not on PATH",
            fixture: "run find --structural with a PATH that has no ast-grep",
        },
        &["find"],
        "{program, child_exit, child_signal}",
    ),
    error(
        "BAD_PATTERN",
        1,
        "the search pattern failed to compile",
        "Correct the regex, or add --fixed-strings to search for the literal text.",
        Repro::Example("rf --json content '('"),
        &["content", "find", "why"],
        NONE,
    ),
    error(
        "CONFLICT",
        5,
        "a cursor snapshot no longer matches the current result set",
        "Restart the query without --cursor.",
        Repro::Fixture {
            precondition: "a cursor from an earlier page, and a result set that changed after that page",
            fixture: "read meta.pagination.cursor from a --limit 1 page, add a file that matches, then send the cursor",
        },
        &["content", "find"],
        NONE,
    ),
    error(
        "HISTORY_ERROR",
        3,
        "Git history could not be scanned; no partial result was returned",
        "Run `rf doctor --json` and read data.external_tools.git.",
        Repro::Fixture {
            precondition: "git runs and the history scan fails",
            fixture: "run find in a work tree with a damaged object store",
        },
        &["find"],
        NONE,
    ),
    error(
        "CONFORMANCE_FAIL",
        1,
        "one or more conformance cases have verdict fail",
        "Read data.cases; each failed row names its case_id.",
        Repro::Fixture {
            precondition: "a build with a contract defect",
            fixture: "none in a correct build; the self-check of a defective build gives it",
        },
        &["conformance"],
        NONE,
    ),
    error(
        "COMPONENT_UNHEALTHY",
        6,
        "doctor found an external tool that is present and cannot run",
        "Repair or reinstall the tool that details.component names.",
        Repro::Fixture {
            precondition: "git or ast-grep is on PATH and its --version call fails or exceeds the probe limit",
            fixture: "put a script named ast-grep that exits 1 first on PATH, then run doctor",
        },
        &["doctor"],
        "{component, status}",
    ),
    error(
        "COMPONENT_DEGRADED",
        6,
        "doctor found an optional external tool absent; the dependent find source cannot run",
        "Install the tool that details.component names.",
        Repro::Fixture {
            precondition: "git or ast-grep is not on PATH",
            fixture: "run doctor with a PATH that has no git or no ast-grep",
        },
        &["doctor"],
        "{component, status}",
    ),
    error(
        "INTERNAL",
        7,
        "defect in rf caught by the totality wrapper",
        "This is a defect in rf, not in the call. Do not retry. Report it at https://github.com/rgfind/rf/issues with the command.",
        Repro::Fixture {
            precondition: "an injected fault",
            fixture: "test build only (cargo feature fault-injection): RF_FAULT=<diagnosis stage> rf --json content x",
        },
        ALL,
        NONE,
    ),
    warning(
        "IGNORE_VCS",
        "a VCS-ignore rule hides a match from a default search",
        "put a match in a file that .gitignore names, then run content",
        &["content", "why"],
        FILES,
    ),
    warning(
        "HIDDEN_SKIPPED",
        "a hidden path hides a match from a default search",
        "put a match in a dot-file, then run content",
        &["content", "why"],
        FILES,
    ),
    warning(
        "BINARY_SKIPPED",
        "binary detection hides a match from a default search",
        "put a match after a NUL byte in a file, then run content",
        &["content", "why"],
        FILES,
    ),
    warning(
        "CASE_SENSITIVE",
        "a search without case finds a match that the default search does not",
        "search a lower-case pattern where the file holds the upper-case text",
        &["content", "why"],
        FILES,
    ),
    warning(
        "ENCODING_MISS",
        "UTF-16 decoding finds a match that the default search does not",
        "put a match in a UTF-16 file with a byte-order mark, then run content",
        &["content", "why"],
        FILES,
    ),
    warning(
        "FD_NAME",
        "the name filter excludes a file whose content matches",
        "run find --name rs where the match is in a .txt file",
        &["find"],
        FILES,
    ),
    warning(
        "FD_HIDDEN",
        "a hidden path excludes a file whose content matches",
        "run find where the match is in a dot-file with the named extension",
        &["find"],
        FILES,
    ),
    warning(
        "FD_IGNORE",
        "an ignore rule excludes a file whose content matches",
        "run find where the match is in a file that .gitignore names",
        &["find"],
        FILES,
    ),
    warning(
        "RG_BINARY",
        "binary detection excludes a file whose content matches",
        "run find where the match follows a NUL byte",
        &["find"],
        FILES,
    ),
    warning(
        "GIT_DELETED",
        "the match exists only in Git history",
        "commit a file that matches, delete it, commit, then run find",
        &["find"],
        FILES,
    ),
    warning(
        "GIT_ABSENT",
        "git is not available, so history was not searched",
        "run find with a PATH that has no git",
        &["find"],
        FILES,
    ),
    warning(
        "GIT_NOT_WORK_TREE",
        "the root is not a Git work tree, so history was not searched",
        "run find in a directory outside every Git repository",
        &["find"],
        FILES,
    ),
    warning(
        "GIT_HISTORY_PARTIAL",
        "the history scan budget ended before all revisions were read",
        "run find in a repository whose history scan takes more than 2000 ms",
        &["find"],
        NONE,
    ),
    warning(
        "AST_STRUCTURAL",
        "the match comes only from the structural stage",
        "run find --structural with a pattern that has no fixed literal form",
        &["find"],
        FILES,
    ),
    warning(
        "STRUCTURAL_UNAVAILABLE",
        "ast-grep is present and failed or exceeded its time limit, so the structural stage did not run",
        "put a script named ast-grep that exits 1 first on PATH, then run find --structural",
        &["find"],
        NONE,
    ),
    warning(
        "PARTIAL_RESULT",
        "one or more paths under the root could not be read; the result covers the other paths",
        "chmod 000 one file in a tree that has other readable files, then run content",
        &["content", "find"],
        FILES,
    ),
    warning(
        "IGNORE_MODE",
        "doctor reports the active ignore mode for the path",
        "run doctor on a directory outside every Git repository",
        &["doctor"],
        NONE,
    ),
    warning(
        "IGNORE_SOURCE_UNRESOLVED",
        "the ignore rule that hides the file could not be identified",
        "run why on a file hidden by an ignore rule that rf cannot trace to one source line",
        &["why"],
        FILES,
    ),
    warning(
        "EXTERNAL_TOOL_MISSING",
        "git is present and cannot run, so history was not searched",
        "put a script named git that exits 1 first on PATH, then run find",
        &["find"],
        NONE,
    ),
    warning(
        "GIT_SCRUB_WORD_UNAVAILABLE",
        "whole-word mode omits Git pickaxe evidence",
        "run find --word in a repository with a history-only match",
        &["find"],
        FILES,
    ),
];

pub fn lookup(code: &str) -> Option<&'static Code> {
    CODES.iter().find(|c| c.name == code)
}

/// The exit dictionary: (code, meaning, retryable).
pub const EXITS: &[(i32, &str, Option<bool>)] = &[
    (0, "success", None),
    (1, "user-input-error", Some(false)),
    (2, "safety-block", Some(false)),
    (3, "tool-environment-error", None),
    (4, "transient-failure", Some(true)),
    (5, "conflict", Some(false)),
    (6, "findings-present", Some(false)),
    (7, "internal-error", Some(false)),
    (129, "ended-by-sighup", None),
    (130, "ended-by-sigint", None),
    (141, "reader-closed-pipe", None),
    (143, "ended-by-sigterm", None),
];

pub const INTERNAL_EXIT: i32 = 7;

pub fn exit_codes_json() -> Value {
    let mut map = Map::new();
    for (code, meaning, retryable) in EXITS {
        map.insert(
            code.to_string(),
            json!({"meaning": meaning, "retryable": retryable}),
        );
    }
    Value::from(map)
}

pub fn error_codes_json() -> Value {
    let mut map = Map::new();
    for code in CODES {
        let mut appears = Vec::new();
        if code.errors {
            appears.push("errors");
        }
        if code.warnings {
            appears.push("warnings");
        }
        let mut entry = Map::new();
        entry.insert("appears_in".into(), json!(appears));
        entry.insert("exit".into(), json!(code.exit));
        entry.insert("summary".into(), json!(code.summary));
        match &code.repro {
            Repro::Example(call) => {
                entry.insert("example_invocation".into(), json!(call));
            }
            Repro::Fixture {
                precondition,
                fixture,
            } => {
                entry.insert("precondition".into(), json!(precondition));
                entry.insert("fixture".into(), json!(fixture));
            }
        }
        entry.insert("sites".into(), json!(code.sites));
        entry.insert("details".into(), json!(code.details));
        map.insert(code.name.into(), Value::from(entry));
    }
    Value::from(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_well_formed() {
        let exits: Vec<i32> = EXITS.iter().map(|e| e.0).collect();
        for (i, code) in CODES.iter().enumerate() {
            assert!(
                CODES[..i].iter().all(|c| c.name != code.name),
                "{} is registered twice",
                code.name
            );
            assert!(code.errors || code.warnings, "{}", code.name);
            assert_eq!(code.errors, code.exit.is_some(), "{}", code.name);
            assert_eq!(code.errors, code.remediation.is_some(), "{}", code.name);
            if let Some(exit) = code.exit {
                assert!(exits.contains(&exit), "{} exit {exit}", code.name);
            }
        }
        assert_eq!(lookup("INTERNAL").and_then(|c| c.exit), Some(INTERNAL_EXIT));
    }
}
