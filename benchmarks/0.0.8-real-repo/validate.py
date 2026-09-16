#!/usr/bin/env python3
"""Validate the committed rf 0.0.8 K-record without third-party packages."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RECORD = ROOT / "k-record.json"
SCHEMA = ROOT / "k-record.schema.json"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TOP_LEVEL = {
    "schema_version", "benchmark_id", "rf_release", "corpus", "ground_truth",
    "reset_rule", "arms", "model", "prompts", "tasks", "run_ids", "scores",
    "perf_rule", "measurements", "selected_A", "selected_limits",
    "artifact_checksums", "scope",
}
SCHEMA_REQUIRED = [
    "schema_version", "benchmark_id", "rf_release", "corpus", "ground_truth",
    "reset_rule", "arms", "model", "prompts", "tasks", "run_ids", "scores",
    "perf_rule", "measurements", "selected_A", "selected_limits",
    "artifact_checksums", "scope",
]


def fail(message: str) -> None:
    print(f"K-record validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse {path.name}: {error}")


def require_map(value: object, name: str) -> dict:
    if not isinstance(value, dict):
        fail(f"{name} must be an object")
    return value


def require_list(value: object, name: str) -> list:
    if not isinstance(value, list) or not value:
        fail(f"{name} must be a non-empty array")
    return value


def require_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{name} must be a non-empty string")
    return value


def require_fields(value: object, name: str, fields: set[str]) -> dict:
    mapping = require_map(value, name)
    missing = fields - set(mapping)
    if missing:
        fail(f"{name} is missing {', '.join(sorted(missing))}")
    return mapping


def check_digest(value: object, name: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        fail(f"{name} must be sha256: followed by 64 lowercase hex digits")


def check_checksum_map(value: object, name: str) -> None:
    mapping = require_map(value, name)
    if not mapping:
        fail(f"{name} must not be empty")
    for path, digest in mapping.items():
        require_string(path, f"{name} key")
        if Path(path).is_absolute() or "\\" in path or path.startswith("../"):
            fail(f"{name} contains a non-portable relative path: {path}")
        check_digest(digest, f"{name}[{path}]")


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    schema = require_map(load(SCHEMA), "schema")
    if schema.get("required") != SCHEMA_REQUIRED:
        fail("schema required fields differ from validator required fields")
    record = require_map(load(RECORD), "record")
    if set(record) != TOP_LEVEL:
        fail("record top-level fields must exactly match the documented shape")
    if record["schema_version"] != 1:
        fail("schema_version must be 1")
    require_string(record["benchmark_id"], "benchmark_id")

    release = require_fields(record["rf_release"], "rf_release", {"version", "binary_sha256", "crate_sha256", "source_revision"})
    require_string(release["version"], "rf_release.version")
    require_string(release["source_revision"], "rf_release.source_revision")
    check_digest(release["binary_sha256"], "rf_release.binary_sha256")
    check_digest(release["crate_sha256"], "rf_release.crate_sha256")

    corpus = require_fields(record["corpus"], "corpus", {"repo", "revision", "disk_states"})
    require_string(corpus["repo"], "corpus.repo")
    require_string(corpus["revision"], "corpus.revision")
    states = require_map(corpus["disk_states"], "corpus.disk_states")
    if set(states) != {"pristine", "built"}:
        fail("corpus.disk_states must contain exactly pristine and built")
    for state_name, state in states.items():
        state = require_fields(state, f"corpus.disk_states.{state_name}", {"description", "file_checksums"})
        require_string(state["description"], f"{state_name}.description")
        check_checksum_map(state["file_checksums"], f"{state_name}.file_checksums")

    ground_truth = require_fields(record["ground_truth"], "ground_truth", {"tool", "version", "command_template", "tasks"})
    for key in ("tool", "version", "command_template"):
        require_string(ground_truth[key], f"ground_truth.{key}")
    ground_tasks = require_list(ground_truth["tasks"], "ground_truth.tasks")
    tasks = require_list(record["tasks"], "tasks")
    task_ids = set()
    for task in tasks:
        task = require_fields(task, "tasks[]", {"task_id", "class"})
        task_id = require_string(task["task_id"], "tasks[].task_id")
        require_string(task["class"], "tasks[].class")
        if task_id in task_ids:
            fail(f"duplicate task id: {task_id}")
        task_ids.add(task_id)
    ground_ids = set()
    for task in ground_tasks:
        task = require_fields(task, "ground_truth.tasks[]", {"task_id", "command", "stdout_sha256", "matches"})
        task_id = require_string(task["task_id"], "ground_truth.tasks[].task_id")
        check_digest(task["stdout_sha256"], f"ground_truth.tasks[{task_id}].stdout_sha256")
        require_list(task["matches"], f"ground_truth.tasks[{task_id}].matches")
        ground_ids.add(task_id)
    if ground_ids != task_ids:
        fail("ground-truth task ids must exactly match task ids")

    require_string(record["reset_rule"], "reset_rule")
    arms = require_list(record["arms"], "arms")
    arm_names = set()
    git_access = set()
    for arm in arms:
        arm = require_fields(arm, "arms[]", {"name", "tool_allowlist", "shell_policy"})
        name = require_string(arm["name"], "arms[].name")
        if name not in {"rf", "raw"}:
            fail("arm name must be rf or raw")
        arm_names.add(name)
        allowlist = require_list(arm["tool_allowlist"], f"arms[{name}].tool_allowlist")
        if not all(isinstance(tool, str) and tool for tool in allowlist):
            fail(f"arms[{name}].tool_allowlist must contain strings")
        git_access.add("git" in allowlist)
        require_string(arm["shell_policy"], f"arms[{name}].shell_policy")
    if arm_names != {"rf", "raw"}:
        fail("arms must contain exactly rf and raw")
    if any(task["class"] == "history-deleted" for task in tasks) and git_access != {True}:
        fail("history tasks require equal Git access in both arms")

    model = require_fields(record["model"], "model", {"name", "effort", "harness_version"})
    for key in model:
        require_string(model[key], f"model.{key}")
    prompts = require_list(record["prompts"], "prompts")
    prompt_ids = set()
    for prompt in prompts:
        prompt = require_fields(prompt, "prompts[]", {"task_id", "text"})
        prompt_ids.add(require_string(prompt["task_id"], "prompts[].task_id"))
        require_string(prompt["text"], "prompts[].text")
    if prompt_ids != task_ids:
        fail("prompt task ids must exactly match task ids")

    run_ids = require_list(record["run_ids"], "run_ids")
    score_ids = set()
    for run in run_ids:
        run = require_fields(run, "run_ids[]", {"task_id", "arm", "run_id"})
        if run["task_id"] not in task_ids or run["arm"] not in arm_names:
            fail("run_ids contains an unknown task or arm")
        require_string(run["run_id"], "run_ids[].run_id")
        score_ids.add((run["task_id"], run["arm"]))
    expected_pairs = {(task_id, arm) for task_id in task_ids for arm in arm_names}
    if score_ids != expected_pairs:
        fail("run_ids must contain one task/arm pair for every task and arm")
    scores = require_list(record["scores"], "scores")
    seen_scores = set()
    for score in scores:
        score = require_fields(score, "scores[]", {"task_id", "arm", "correct", "turns", "failed_calls", "wall_ms", "reason"})
        pair = (score["task_id"], score["arm"])
        if pair not in expected_pairs or pair in seen_scores:
            fail("scores must contain exactly one valid task/arm pair")
        seen_scores.add(pair)
        if not isinstance(score["correct"], bool) or any(not isinstance(score[key], int) or score[key] < 0 for key in ("turns", "failed_calls", "wall_ms")):
            fail("scores have invalid scalar values")
        require_string(score["reason"], "scores[].reason")
    if seen_scores != expected_pairs:
        fail("scores must contain all task/arm pairs")

    perf = require_fields(record["perf_rule"], "perf_rule", {"corpus", "commands", "warmups", "runs", "statistic", "host", "max_regression_pct"})
    if not isinstance(perf["warmups"], int) or not isinstance(perf["runs"], int) or perf["warmups"] < 0 or perf["runs"] < 1:
        fail("perf_rule warmups/runs are invalid")
    require_list(perf["commands"], "perf_rule.commands")
    for key in ("corpus", "statistic", "host"):
        require_string(perf[key], f"perf_rule.{key}")
    if not isinstance(perf["max_regression_pct"], (int, float)) or perf["max_regression_pct"] < 0:
        fail("perf_rule.max_regression_pct is invalid")
    for measurement in require_list(record["measurements"], "measurements"):
        measurement = require_fields(measurement, "measurements[]", {"command_id", "wall_ms", "median_ms"})
        require_string(measurement["command_id"], "measurements[].command_id")
        if not isinstance(measurement["wall_ms"], list) or len(measurement["wall_ms"]) != perf["runs"]:
            fail("measurement wall_ms length must equal perf_rule.runs")
        if any(not isinstance(value, (int, float)) or value < 0 for value in measurement["wall_ms"]):
            fail("measurement wall_ms values are invalid")
        if not isinstance(measurement["median_ms"], (int, float)) or measurement["median_ms"] < 0:
            fail("measurement median_ms is invalid")

    selected = require_fields(record["selected_A"], "selected_A", {"evidence_schema", "max_matches_default", "per_match_text_cap", "per_response_cap", "decision_rule"})
    require_map(selected["evidence_schema"], "selected_A.evidence_schema")
    if not isinstance(selected["max_matches_default"], int) or not 1 <= selected["max_matches_default"] <= 1000:
        fail("selected_A.max_matches_default must be in 1..=1000")
    for key in ("per_match_text_cap", "per_response_cap"):
        if not isinstance(selected[key], int) or selected[key] < 1:
            fail(f"selected_A.{key} must be a positive integer")
    require_string(selected["decision_rule"], "selected_A.decision_rule")
    limits = require_fields(record["selected_limits"], "selected_limits", {"input", "external_tools", "structural_search"})
    for name, values in limits.items():
        values = require_map(values, f"selected_limits.{name}")
        if not values or any(not isinstance(value, int) or value < 1 for value in values.values()):
            fail(f"selected_limits.{name} must contain positive integer limits")

    for path, expected in require_map(record["artifact_checksums"], "artifact_checksums").items():
        check_digest(expected, f"artifact_checksums[{path}]")
        target = ROOT / path
        if not target.is_file() or target.parent != ROOT:
            fail(f"artifact checksum path must name a file in this directory: {path}")
        if sha256(target) != expected:
            fail(f"artifact checksum mismatch: {path}")
    scope = require_fields(record["scope"], "scope", {"evidence_for", "not_evidence_for"})
    for key in scope:
        require_string(scope[key], f"scope.{key}")

    canonical = json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if RECORD.read_text(encoding="utf-8") != canonical:
        fail("k-record.json is not canonical sorted-key, two-space JSON with one trailing newline")
    print(f"K-record valid: {sha256(RECORD)}")


if __name__ == "__main__":
    main()
