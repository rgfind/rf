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
        "contract_policy": {
            "policy_version": 2,
            "url": "https://github.com/rgfind/rf/blob/main/CONTRACT.md#contract-version-2",
            "supported_contract_versions": [CONTRACT_VERSION],
            "release_record": "release-records/0.0.8.md",
            "release_classification": "additive-pending-release-verification"
        },
        "schema_versions": {
            "envelope": 2, "capabilities": 2, "content": 2, "find": 2,
            "why": 2, "doctor": 2, "robot-docs": 2, "conformance": 2
        },
        "release_scope": {"workflow_guides": ["robot-docs guide"], "workflow_guides_status": "released in contract version 0.1"},
        "engine": "in-process (ignore + grep crates); no subprocess",
        "verbs": {
            "robot-docs": {"description": "agent workflow documents", "aliases": [], "flags": [], "subcommands": {"guide": {"description": "emit agent workflow recipes", "flags": [], "output_schema": {"data.items[]": {"id":"string", "goal":"string", "inputs":"array[string]", "command":"safe shell command", "expected_branch":"string", "version_range":"string"}}}}},
            "robot-docs guide": {"description": "emit agent workflow recipes", "aliases": [], "flags": [], "output_schema": {"data.items[]": {"id":"string", "goal":"string", "inputs":"array[string]", "command":"safe shell command", "expected_branch":"string", "version_range":"string"}}},
            "capabilities": {"description": "emit this machine contract", "aliases": [], "flags": []},
            "help": {"description": "show help for rf or for one verb; same bytes as --help at that node", "aliases": [], "flags": []},
            "content": {
                "description": "content search; attributes each match to the filter that would hide it",
                "aliases": [],
                "flags": [],
                "selected_input": {"validation": "reject empty, malformed UTF-8/JSON, duplicate, out-of-root, missing, non-file, .git, and unreadable paths", "error_code": "INVALID_SELECTION", "classification": "selected files are classified by content layers; they are never marked recovered"},
                "output_schema": {"data.items[]": {"file": "string", "selection": "selected when a selected-input mode is used", "surfaced_by": "enum[default,vcs_ignore,hidden,binary,case,encoding_utf16]", "matches": "opt-in occurrence[]: {line:positive-int,column_byte:positive-int,text:string,text_lossy?:true,text_truncated?:true}"}, "meta.query": {"syntax":"enum[regex,fixed]", "word":"bool", "case":"enum[sensitive,insensitive]"}, "meta.selection": {"mode": "enum[root-walk,stdin-nul,rf-envelope]", "selected_files": "int when selected input is used"}, "meta.evidence": {"requested":"true when --matches", "match_cap":"int<=16", "text_bytes_cap":512, "response_bytes_cap":32768}, "meta.pagination": {"limit": "int", "returned": "int", "total": "int", "truncated": "bool", "has_more": "bool", "cursor": "string|null", "snapshot_hash": "sha256"}}
            },
            "find": {
                "description": "staged fd|rg pipe (in-process) + typed Git history coverage + ast-grep structural; attributes each miss to fd_name/fd_hidden/fd_ignore/rg_binary/git_deleted/ast_structural",
                "aliases": [],
                "flags": [],
                "output_schema": {"data.items[]": {"file": "string", "stage": "enum[found,fd_name,fd_hidden,fd_ignore,fd_filter,rg_binary,git_deleted,ast_structural]", "fix": "string|null", "matches": "opt-in occurrence[] or null for history-only/structural-only", "matches_unavailable_reason":"history-only|structural-only when matches is null"}, "meta.query": {"syntax":"enum[regex,fixed]", "word":"bool", "case":"enum[sensitive,insensitive]", "stages":"tree: Rust regex; history grep: Git BRE; pickaxe: literal; structural: ast-grep"}, "meta.evidence": {"requested":"true when --matches", "match_cap":"int<=16", "text_bytes_cap":512, "response_bytes_cap":32768}, "meta.pagination": {"limit": "int", "returned": "int", "total": "int", "truncated": "bool", "has_more": "bool", "cursor": "string|null", "snapshot_hash": "sha256"}, "meta.history": {"requested_mode": "all-revisions", "actual_mode": "enum[available,git-absent,git-unusable,git-timed-out,not-work-tree,partial,history-error]", "budget_ms": 2000, "served_revisions": "int", "failed_revisions": "int"}, "meta.sources": {"history": {"requested":"bool", "actual":"enum[used,skipped]", "fallback_reason":"null|enum[tool-missing,tool-unusable,tool-timed-out,not-work-tree,history-partial,history-failed]"}, "structural": {"requested":"bool", "actual":"enum[used,skipped]", "fallback_reason":"null|enum[not-requested,tool-missing,tool-unusable,tool-timed-out]"}}}
            },
            "doctor": {
                "description": "environment DIAGNOSE: engine build, regex features, and the active ignore mode for a path",
                "aliases": [],
                "flags": [],
                "output_schema": {"data": {"overall": "enum[healthy,degraded,unhealthy]", "external_tools": {"git":"{status,state,path,version,probe_error}", "ast-grep":"{status,state,path,version,probe_error}"}, "recommended_action": {"command":"string|null", "rationale":"string", "is_destructive":"false", "affected":"array[{verb,mode,status}]", "alternatives":"array[{command,purpose}]", "references":"array[{url,purpose}]"}}}
            },
            "why": {
                "description": "per-file verdict: whether one readable regular file matches and which normal tree-search filter hid it",
                "aliases": [],
                "flags": [],
                "output_schema": {
                    "data": {"file": "root-relative target path", "pattern": "string", "matched": "bool", "hidden_from_default": "bool", "surfaced_by": "enum[default,vcs_ignore,hidden,binary,case,encoding_utf16]|null", "matches": "opt-in occurrence[]: {line:positive-int,column_byte:positive-int,text:string,text_lossy?:true,text_truncated?:true}", "hiding_filter": "{code,layer,rg_flags}|absent", "ignore_source": "optional {source_file:string,class:enum[gitignore,git_exclude,git_global,dot_ignore],pattern:string,line?:positive-int}; only vcs_ignore"},
                    "meta": {"file": "root-relative target path", "root": "path relative to process working directory", "query": {"syntax":"enum[regex,fixed]", "word":"bool", "case":"enum[sensitive,insensitive]"}, "evidence": {"requested":"true when --matches", "match_cap":"int<=16", "text_bytes_cap":512, "response_bytes_cap":32768}, "git_repo": "bool", "ignore_mode": "string", "matched": "bool", "surfaced_by": "string|null"},
                    "commands": "empty unless a hidden filter is corrected; emitted command reproduces the root-scoped tree search and can include sibling matches"
                }
            },
            "conformance": {
                "description": "run the release self-check profile against this binary and emit the verdict set (probeability rule P-f)",
                "aliases": [],
                "flags": [],
                "profile": "release-self-check",
                "not_applicable": {
                    "S-01": "release-build-fault-trigger-unavailable",
                    "S-02": "release-build-fault-trigger-unavailable",
                    "X-02": "release-build-fault-trigger-unavailable"
                },
                "output_schema": {"data": {"profile": "string", "counts": {"pass": "int", "fail": "int", "not_applicable": "int"}, "cases": "array[{case_id,verdict,reason,request_id,target}]"}}
            }
        },
        "global_flags": crate::flags::global_flags_json(),
        "exit_codes": crate::registry::exit_codes_json(),
        "error_codes": crate::registry::error_codes_json(),
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
            "totality_exit_7": "tests/conformance.rs::fault_seam_proves_totality",
            "release_self_check_failure": "src/conformance.rs::run"
        },
        "env_vars": {
            "SOURCE_DATE_EPOCH": {"description": "fixed clock for reproducible output: sets meta.ts_iso and makes meta.elapsed_ms 0", "industry_standard": true},
            "NO_COLOR": {"description": "suppress terminal decoration; rf output has none, so this has no effect", "industry_standard": true}
        }
    });
    if let Some(object) = v.as_object_mut() {
        object.insert("verb_dependencies".into(), json!({
            "git": [{"verb":"find","mode":"history","behavior":"degrades with typed use-time provenance"}],
            "ast-grep": [{"verb":"find","mode":"structural","behavior":"degrades with typed use-time provenance"}]
        }));
        object.insert("limits".into(), json!({
            "pagination": {"default_limit": 100, "max_limit": 1000},
            "evidence": {"max_occurrences_per_row": 16, "text_bytes": 512, "response_data_bytes": 32768},
            "external_tool_probe": {"timeout_ms": 2000, "captured_output_bytes": 8192, "probe_error_bytes": 512},
            "structural_search": {"timeout_ms": 5000, "captured_output_bytes": 65536}
        }));
        object.insert("envelope_meta".into(), json!({
            "ts_iso": {"format": "RFC 3339 UTC with Z", "precision": "seconds"},
            "data_hash": {"algorithm": "sha256", "format": "sha256:<64 hex>", "covers": "data", "canonicalization": "compact JSON, keys sorted, separators (',', ':')"},
            "request_id": {"format": "req_<16 hex>", "unique_per_invocation": true}
        }));
    }
    // The release contract lists only the two stable vars above; a fault-injection
    // build additionally reads RF_FAULT, so it discloses that here. This is the one
    // contract difference between the two builds — the release pin stays canonical.
    #[cfg(feature = "fault-injection")]
    if let Some(vars) = v.get_mut("env_vars").and_then(Value::as_object_mut) {
        vars.insert(
            "RF_FAULT".into(),
            json!({"description": "fault trigger: names one diagnosis stage that then panics; present only in a build with the fault-injection cargo feature", "test_only": true}),
        );
    }
    // Flag and positional declarations come from the one table that the argv
    // validator reads, so declared and checked behavior cannot drift.
    if let Some(verbs) = v.get_mut("verbs").and_then(Value::as_object_mut) {
        for node in &crate::flags::NODES {
            let flags = crate::flags::flags_json(node.path);
            let args = crate::flags::args_json(node.path);
            // The exits that the verb's own logic returns. Exit 3 and exit 7
            // can come from any verb, so each list implies them.
            let exits: &[i32] = match node.path.join(" ").as_str() {
                "robot-docs" => &[1],
                "content" => &[0, 1, 5],
                "find" => &[0, 1, 3, 5],
                "doctor" => &[0, 1, 6],
                _ => &[0, 1],
            };
            if let Some(flat) = verbs.get_mut(&node.path.join(" ")) {
                flat["flags"] = flags.clone();
                flat["args"] = args.clone();
                flat["mutates"] = json!(false);
                flat["json"] = json!(true);
                flat["exit_codes"] = json!(exits);
            }
            let mut entry = verbs.get_mut(node.path[0]);
            for name in &node.path[1..] {
                entry = entry.and_then(|e| e["subcommands"].get_mut(*name));
            }
            if let Some(entry) = entry {
                entry["flags"] = flags;
                entry["args"] = args;
                entry["mutates"] = json!(false);
                entry["json"] = json!(true);
                entry["exit_codes"] = json!(exits);
            }
        }
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
    (envelope(true, build(), meta, vec![], vec![], vec![]), 0)
}
