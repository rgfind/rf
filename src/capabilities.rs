//! The `capabilities` verb — the machine contract, emitted as data. Layer-1
//! introspection: an agent reads this once and knows every verb, flag, exit
//! code, and warning code without trial and error.

use crate::envelope::{envelope, CONTRACT_VERSION, TOOL_VERSION};
use serde_json::{json, Map, Value};

pub fn build() -> Value {
    #[allow(unused_mut)]
    let mut v = json!({
        "contract_version": CONTRACT_VERSION,
        "tool_version": TOOL_VERSION,
        "release_scope": {"workflow_guides": ["robot-docs guide"], "workflow_guides_status": "released in contract version 2"},
        "engine": "in-process (ignore + grep crates); no subprocess",
        "verbs": {
            "robot-docs": {"summary": "agent workflow documents", "aliases": [], "flags": [], "subcommands": {"guide": {"flags": [{"name":"--compact", "arity":0, "type":"bool"}], "output_schema": {"data[]": {"id":"string", "goal":"string", "inputs":"array[string]", "command":"safe shell command", "expected_branch":"string", "version_range":"string"}}}}},
            "robot-docs guide": {"summary": "emit agent workflow recipes", "aliases": [], "flags": [{"name":"--compact", "arity":0, "type":"bool"}], "output_schema": {"data[]": {"id":"string", "goal":"string", "inputs":"array[string]", "command":"safe shell command", "expected_branch":"string", "version_range":"string"}}},
            "capabilities": {"summary": "emit this machine contract", "aliases": [], "flags": []},
            "content": {
                "summary": "content search; attributes each match to the filter that would hide it",
                "aliases": [],
                "args": [
                    {"name": "pattern", "arity": 1, "type": "string"},
                    {"name": "path", "arity": 1, "type": "path", "default": "."}
                ],
                "flags": [
                    {"name": "--paths-stdin", "arity": 0, "type": "bool", "conflicts_with": "--paths-envelope", "input": "stdin NUL-delimited UTF-8 paths; relative paths resolve under path"},
                    {"name": "--paths-envelope", "arity": 0, "type": "bool", "conflicts_with": "--paths-stdin", "input": "stdin rf JSON envelope; each data[] row must contain file:string"},
                    {"name": "--limit", "arity": 1, "type": "int", "default": 100, "range": "1..=1000"},
                    {"name": "--cursor", "arity": 1, "type": "string", "domain": "opaque cursor from meta.pagination.cursor"}
                ],
                "selected_input": {"validation": "reject empty, malformed UTF-8/JSON, duplicate, out-of-root, missing, non-file, .git, and unreadable paths", "error_code": "INVALID_SELECTION", "classification": "selected files are classified by content layers; they are never marked recovered"},
                "output_schema": {"data[]": {"file": "string", "selection": "selected when a selected-input mode is used", "surfaced_by": "enum[default,vcs_ignore,hidden,binary,case,encoding_utf16]"}, "meta.selection": {"mode": "enum[root-walk,stdin-nul,rf-envelope]", "selected_files": "int when selected input is used"}, "meta.pagination": {"limit": "int", "returned": "int", "total": "int", "truncated": "bool", "has_more": "bool", "cursor": "string|null", "snapshot_hash": "sha256"}}
            },
            "find": {
                "summary": "staged fd|rg pipe (in-process) + typed Git history coverage + ast-grep structural; attributes each miss to fd_name/fd_hidden/fd_ignore/rg_binary/git_deleted/ast_structural",
                "aliases": [],
                "args": [
                    {"name": "pattern", "arity": 1, "type": "string"},
                    {"name": "path", "arity": 1, "type": "path", "default": "."}
                ],
                "flags": [
                    {"name": "--name", "arity": 1, "type": "string", "required": true, "value_pattern": "non-empty file extension without dot or path separator"},
                    {"name": "--structural", "arity": 1, "type": "string", "domain": "ast-grep pattern; a construct with no fixed literal form"},
                    {"name": "--lang", "arity": 1, "type": "string", "domain": "ast-grep language id; required with --structural"},
                    {"name": "--limit", "arity": 1, "type": "int", "default": 100, "range": "1..=1000"},
                    {"name": "--cursor", "arity": 1, "type": "string", "domain": "opaque cursor from meta.pagination.cursor"}
                ],
                "output_schema": {"data[]": {"file": "string", "stage": "enum[found,fd_name,fd_hidden,fd_ignore,fd_filter,rg_binary,git_deleted,ast_structural]", "fix": "string|null"}, "meta.pagination": {"limit": "int", "returned": "int", "total": "int", "truncated": "bool", "has_more": "bool", "cursor": "string|null", "snapshot_hash": "sha256"}, "meta.history": {"requested_mode": "all-revisions", "actual_mode": "enum[available,git-absent,not-work-tree,partial,history-error]", "budget_ms": 2000, "served_revisions": "int", "failed_revisions": "int"}}
            },
            "doctor": {
                "summary": "environment DIAGNOSE: engine build, regex features, and the active ignore mode for a path",
                "aliases": [],
                "args": [{"name": "path", "arity": 1, "type": "path", "default": "."}],
                "flags": []
            },
            "why": {
                "summary": "per-file verdict: whether one readable regular file matches and which normal tree-search filter hid it",
                "aliases": [],
                "args": [
                    {"name": "pattern", "arity": 1, "type": "string"},
                    {"name": "file", "arity": 1, "type": "path"}
                ],
                "flags": [
                    {"name": "--root", "arity": 1, "type": "path", "required": false, "input": "directory that supplies target validation and ignore context"}
                ],
                "output_schema": {
                    "data[]": {"file": "root-relative target path", "pattern": "string", "matched": "bool", "hidden_from_default": "bool", "surfaced_by": "enum[default,vcs_ignore,hidden,binary,case,encoding_utf16]|null", "hiding_filter": "{code,layer,rg_flags}|absent"},
                    "meta": {"file": "root-relative target path", "root": "path relative to process working directory", "git_repo": "bool", "ignore_mode": "string", "matched": "bool", "surfaced_by": "string|null"},
                    "commands": "empty unless a hidden filter is corrected; emitted command reproduces the root-scoped tree search and can include sibling matches"
                }
            },
            "conformance": {
                "summary": "run the release self-check profile against this binary and emit the verdict set (probeability rule P-f)",
                "aliases": [],
                "flags": [],
                "profile": "release-self-check",
                "not_applicable": {
                    "S-01": "release-build-fault-trigger-unavailable",
                    "S-02": "release-build-fault-trigger-unavailable",
                    "X-02": "release-build-fault-trigger-unavailable"
                },
                "output_schema": {"data[0]": {"profile": "string", "counts": {"pass": "int", "fail": "int", "not_applicable": "int"}, "cases": "array[{case_id,verdict,reason,request_id,target}]"}}
            }
        },
        "global_flags": [
            {"name": "--json", "aliases": [], "arity": 0, "type": "bool", "positions": "before or after a verb", "summary": "machine envelope"},
            {"name": "--no-color", "aliases": [], "arity": 0, "type": "bool", "positions": "before or after a verb", "summary": "disable terminal decoration"},
            {"name": "--human", "aliases": [], "arity": 0, "type": "bool", "positions": "before or after a verb", "summary": "force the human render even when stdout is not a terminal; --json wins if both are given"},
            {"name": "--help", "aliases": ["-h"], "arity": 0, "type": "bool", "summary": "usage text; exit 0"},
            {"name": "--version", "aliases": ["-V"], "arity": 0, "type": "bool", "summary": "version string; exit 0"}
        ],
        "exit_codes": {
            "0": {"meaning": "success (includes empty results: data:[]); a self-check with no failures", "retryable": false},
            "1": {"meaning": "user-input-error (bad flags / missing args), or a failing conformance self-check", "retryable": false},
            "3": {"meaning": "tool-environment-error", "retryable": false},
            "5": {"meaning": "conflict: a paged result snapshot changed; restart the query", "retryable": true},
            "6": {"meaning": "internal defect caught by the totality wrapper", "retryable": false}
        },
        "error_codes": {
            "USAGE": "invalid arguments: unknown verb/flag, missing flag value, or --structural without --lang",
            "UNKNOWN_FLAG": "an unrecognized global or verb-local flag",
            "UNKNOWN_COMMAND": "an unrecognized command path",
            "INVALID_INPUT": "a supplied value failed parser validation",
            "INVALID_SELECTION": "selected-input bytes or paths failed validation",
            "INVALID_TARGET": "why target or root failed validation",
            "MISSING_ARGUMENT": "a required positional or flag value is absent",
            "BAD_PATTERN": "the search regex failed to compile",
            "CONFLICT": "a cursor snapshot no longer matches the current result set",
            "HISTORY_ERROR": "Git history could not be scanned; no partial result was returned",
            "INTERNAL": "internal fault caught by the totality wrapper",
            "CONFORMANCE_FAIL": "one or more conformance cases returned verdict:fail"
        },
        "warning_codes": [
            "IGNORE_VCS", "HIDDEN_SKIPPED", "BINARY_SKIPPED", "CASE_SENSITIVE",
            "ENCODING_MISS", "FD_NAME", "FD_HIDDEN", "FD_IGNORE", "RG_BINARY",
            "GIT_DELETED", "GIT_ABSENT", "GIT_NOT_WORK_TREE", "GIT_HISTORY_PARTIAL",
            "AST_STRUCTURAL", "STRUCTURAL_UNAVAILABLE", "IGNORE_MODE"
        ],
        "diagnosis_order": [
            "bootstrap_mode", "global_flag", "command_path", "command_flag",
            "value_validation", "required_argument", "semantic_resolution", "execution"
        ],
        "value_domains": [
            {"command": "find", "flag": "--name", "accepted": "config", "rejected": ".config", "error_code": "INVALID_INPUT"}
        ],
        "verification_fixtures": {
            "envelope_and_parser_errors": "tests/conformance.rs::error_envelopes_and_global_json_are_total",
            "content_find_warnings_paging_and_conflicts": "tests/conformance.rs::conformance",
            "history_outcomes": "find::history_tests::history_outcomes_are_distinct_and_coverage_is_counted",
            "totality_exit_6": "tests/conformance.rs::fault_seam_proves_totality",
            "release_self_check_failure": "src/conformance.rs::run"
        },
        "env_vars": ["SOURCE_DATE_EPOCH", "NO_COLOR"]
    });
    // The release contract lists only the two stable vars above; a fault-injection
    // build additionally reads RF_FAULT, so it discloses that here. This is the one
    // contract difference between the two builds — the release pin stays canonical.
    #[cfg(feature = "fault-injection")]
    if let Some(a) = v.get_mut("env_vars").and_then(Value::as_array_mut) {
        a.push(Value::from("RF_FAULT"));
    }
    // The parser-derived surface, published as an independent second source. The
    // conformance verb (X-01) reconciles it against the hand-kept `verbs` above.
    if let Some(o) = v.as_object_mut() {
        o.insert("parser_manifest".into(), crate::manifest::build());
    }
    v
}

pub fn run() -> (Value, i32) {
    let mut meta = Map::new();
    meta.insert("verb".into(), Value::from("capabilities"));
    (
        envelope(true, vec![build()], meta, vec![], vec![], vec![]),
        0,
    )
}
