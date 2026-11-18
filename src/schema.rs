//! The output schema of each verb, as JSON Schema. `capabilities` publishes
//! these under `verbs.<verb>.output_schema`.
//!
//! Each schema covers `data` and `meta` of a reply that carries data. Every
//! declared key is in `required`: a key with no value is null, never absent.
//! A failed request with `data: null` carries only the base `meta` keys.

use serde_json::{json, Map, Value};

/// An object schema. Every property is required and no other key is allowed.
fn obj(properties: Value) -> Value {
    let required: Vec<Value> = properties
        .as_object()
        .map(|p| p.keys().cloned().map(Value::from).collect())
        .unwrap_or_default();
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": false,
    })
}

/// The same schema, with null as one more permitted value.
fn nullable(mut schema: Value) -> Value {
    let kinds = match schema["type"].take() {
        Value::String(kind) => vec![Value::from(kind), Value::from("null")],
        Value::Array(mut kinds) => {
            kinds.push(Value::from("null"));
            kinds
        }
        _ => vec![Value::from("null")],
    };
    schema["type"] = Value::from(kinds);
    if let Some(values) = schema.get_mut("enum").and_then(Value::as_array_mut) {
        values.push(Value::Null);
    }
    schema
}

fn string() -> Value {
    json!({"type": "string"})
}

/// `file_bytes_hex`: the exact bytes of a file name that is not UTF-8, as
/// lowercase hex; null when `file` is the exact name.
fn file_bytes_hex() -> Value {
    nullable(json!({"type": "string", "pattern": "^([0-9a-f]{2})+$"}))
}

fn boolean() -> Value {
    json!({"type": "boolean"})
}

/// A count or size: an integer from 0.
fn count() -> Value {
    json!({"type": "integer", "minimum": 0})
}

/// A 1-based position: a line or a byte column.
fn position() -> Value {
    json!({"type": "integer", "minimum": 1})
}

fn one_of(values: &[&str]) -> Value {
    json!({"type": "string", "enum": values})
}

fn array(items: Value) -> Value {
    json!({"type": "array", "items": items})
}

/// The envelope part that the verb owns: `data`, and `meta` with the base
/// keys that every reply has plus the verb's own keys.
fn reply(data: Value, verb_meta: Value) -> Value {
    let mut meta: Map<String, Value> = [
        ("request_id", string()),
        ("ts_iso", string()),
        ("contract_version", string()),
        ("elapsed_ms", count()),
        ("data_hash", string()),
        ("verb", string()),
    ]
    .into_iter()
    .map(|(key, schema)| (key.to_string(), schema))
    .collect();
    if let Value::Object(extra) = verb_meta {
        meta.extend(extra);
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "description": "data and meta of a reply that carries data; every key is always present, and a key with no value is null",
        "type": "object",
        "required": ["data", "meta"],
        "properties": {"data": data, "meta": obj(Value::from(meta))},
    })
}

/// A list payload: `items` and the count of all rows.
fn list(row: Value) -> Value {
    obj(json!({"items": array(row), "total": count()}))
}

const LAYERS: [&str; 6] = [
    "default",
    "vcs_ignore",
    "hidden",
    "binary",
    "case",
    "encoding_utf16",
];

/// Occurrences, or null when the request did not ask for them or the row
/// has no text to show.
fn matches() -> Value {
    let occurrence = obj(json!({
        "line": position(),
        "column_byte": position(),
        "text": string(),
        "text_lossy": boolean(),
        "text_truncated": boolean(),
    }));
    let mut schema = nullable(array(occurrence));
    schema["maxItems"] = json!(crate::engine::MAX_EVIDENCE_MATCHES);
    schema
}

fn query() -> Value {
    obj(json!({
        "syntax": one_of(&["regex", "fixed"]),
        "word": boolean(),
        "case": one_of(&["sensitive", "insensitive"]),
    }))
}

fn evidence() -> Value {
    obj(json!({
        "requested": boolean(),
        "match_cap": nullable(json!({"type": "integer", "minimum": 0, "maximum": crate::engine::MAX_EVIDENCE_MATCHES})),
        "text_bytes_cap": count(),
        "response_bytes_cap": count(),
    }))
}

fn pagination() -> Value {
    obj(json!({
        "limit": count(),
        "returned": count(),
        "total": count(),
        "truncated": boolean(),
        "has_more": boolean(),
        "cursor": nullable(string()),
        "snapshot_hash": string(),
    }))
}

pub fn content() -> Value {
    reply(
        list(obj(json!({
            "file": string(),
            "file_bytes_hex": file_bytes_hex(),
            "selection": nullable(one_of(&["selected"])),
            "surfaced_by": one_of(&LAYERS),
            "matches": matches(),
        }))),
        json!({
            "pattern": string(),
            "path": string(),
            "query": query(),
            "selection": obj(json!({
                "mode": one_of(&["root-walk", "stdin-nul", "rf-envelope"]),
                "selected_files": nullable(count()),
            })),
            "matched_files": count(),
            "default_matched_files": count(),
            "hidden_by_filters": count(),
            "evidence": evidence(),
            "pagination": pagination(),
        }),
    )
}

pub fn find() -> Value {
    let source = |reasons: &[&str]| {
        obj(json!({
            "requested": boolean(),
            "actual": one_of(&["used", "skipped"]),
            "fallback_reason": nullable(one_of(reasons)),
        }))
    };
    reply(
        list(obj(json!({
            "file": string(),
            "file_bytes_hex": file_bytes_hex(),
            "stage": one_of(&["found", "fd_name", "fd_hidden", "fd_ignore", "fd_filter", "rg_binary", "git_deleted", "ast_structural"]),
            "fix": nullable(string()),
            "matches": matches(),
            "matches_unavailable_reason": nullable(one_of(&["history-only", "structural-only"])),
        }))),
        json!({
            "pattern": string(),
            "name_filter": string(),
            "path": string(),
            "query": query(),
            "headline": string(),
            "fd_default_files": count(),
            "pipe_matched": count(),
            "content_total": count(),
            "history_matches": count(),
            "structural_matches": count(),
            "hidden_by_stage": {"type": "object", "additionalProperties": count()},
            "history": obj(json!({
                "requested_mode": one_of(&["all-revisions"]),
                "actual_mode": one_of(&["available", "git-absent", "git-unusable", "git-timed-out", "not-work-tree", "partial", "history-error"]),
                "budget_ms": count(),
                "served_revisions": count(),
                "failed_revisions": count(),
            })),
            "sources": obj(json!({
                "history": source(&["tool-missing", "tool-unusable", "tool-timed-out", "not-work-tree", "history-partial", "history-failed"]),
                "structural": source(&["not-requested", "tool-missing", "tool-unusable", "tool-timed-out"]),
            })),
            "evidence": evidence(),
            "pagination": pagination(),
        }),
    )
}

pub fn why() -> Value {
    let mut schema = reply(
        obj(json!({
            "file": string(),
            "file_bytes_hex": file_bytes_hex(),
            "pattern": string(),
            "matched": boolean(),
            "hidden_from_default": boolean(),
            "surfaced_by": nullable(one_of(&LAYERS)),
            "matches": matches(),
            "hiding_filter": nullable(obj(json!({
                "code": string(),
                "layer": string(),
                "rg_flags": string(),
            }))),
            "ignore_source": nullable(obj(json!({
                "source_file": string(),
                "class": one_of(&["gitignore", "git_exclude", "git_global", "dot_ignore"]),
                "pattern": string(),
                "line": nullable(position()),
            }))),
        })),
        json!({
            "pattern": string(),
            "file": string(),
            "root": string(),
            "query": query(),
            "git_repo": boolean(),
            "ignore_mode": string(),
            "matched": boolean(),
            "surfaced_by": nullable(one_of(&LAYERS)),
            "evidence": evidence(),
        }),
    );
    schema["required"] = json!(["data", "meta", "commands"]);
    schema["properties"]["commands"] = json!({
        "type": "array",
        "items": {"type": "string"},
        "description": "empty unless a hidden filter is corrected; the command reproduces the root-scoped tree search and can include sibling matches",
    });
    schema
}

pub fn doctor() -> Value {
    let tool = || {
        obj(json!({
            "status": one_of(&["available", "missing", "timed_out", "unusable"]),
            "state": one_of(&["healthy", "degraded", "unhealthy"]),
            "path": nullable(string()),
            "version": nullable(string()),
            "probe_error": nullable(string()),
        }))
    };
    reply(
        obj(json!({
            "rf_version": string(),
            "engine": string(),
            "path": string(),
            "git_repo": boolean(),
            "ignore_mode": string(),
            "overall": one_of(&["healthy", "degraded", "unhealthy"]),
            "external_tools": obj(json!({"ast-grep": tool(), "git": tool()})),
            "recommended_action": obj(json!({
                "command": nullable(string()),
                "rationale": string(),
                "is_destructive": boolean(),
                "affected": array(obj(json!({"verb": string(), "mode": string(), "status": string()}))),
                "alternatives": array(obj(json!({"command": string(), "purpose": string()}))),
                "references": array(obj(json!({"url": string(), "purpose": string()}))),
            })),
        })),
        json!({}),
    )
}

/// `help` mirrors `--help`, which runs before verb dispatch, so `meta.verb`
/// is null.
pub fn help() -> Value {
    reply(
        obj(json!({"usage": string(), "capabilities_command": string()})),
        json!({"verb": nullable(string())}),
    )
}

/// The top level of the contract. Each key is typed; the inner shape is
/// pinned by the golden file, not repeated here.
pub fn capabilities() -> Value {
    let object = || json!({"type": "object"});
    reply(
        obj(json!({
            "contract_policy": object(),
            "contract_version": string(),
            "diagnosis_order": array(string()),
            "engine": string(),
            "env_vars": object(),
            "envelope_meta": object(),
            "error_codes": object(),
            "exit_codes": object(),
            "global_flags": array(object()),
            "limits": object(),
            "parser_manifest": object(),
            "release_scope": object(),
            "schema_versions": object(),
            "tool_version": string(),
            "verb_dependencies": object(),
            "verbs": object(),
            "verification_fixtures": object(),
        })),
        json!({}),
    )
}

pub fn guide() -> Value {
    reply(
        list(obj(json!({
            "id": string(),
            "goal": string(),
            "inputs": array(string()),
            "command": string(),
            "expected_branch": string(),
            "version_range": string(),
        }))),
        json!({"format": one_of(&["index", "guide"])}),
    )
}

pub fn conformance() -> Value {
    reply(
        obj(json!({
            "profile": string(),
            "counts": obj(json!({"pass": count(), "fail": count(), "not_applicable": count()})),
            "cases": array(obj(json!({
                "case_id": string(),
                "verdict": one_of(&["pass", "fail", "not_applicable"]),
                "reason": nullable(string()),
                "request_id": string(),
                "target": {"type": "object", "additionalProperties": {"type": "string"}},
            }))),
        })),
        json!({"profile": string(), "headline": string()}),
    )
}
