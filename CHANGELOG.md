# Changelog

## Unreleased

- `find`: the scrub `git log` now has a time limit of 2000 ms and an output
  cap of 1 MiB. Past either one, rf gives `GIT_SCRUB_UNAVAILABLE`, as for a
  failed log. Before, the log had no limit: `-S` diffs every commit on every
  branch, so `find` could block for minutes on a large history. Capabilities
  `limits` has the new key `scrub_log`. Additive; contract stays `0.1`.

## 0.1.1 — defect fixes after 0.1.0

Contract version stays `0.1`. All changes are additive or defect fixes. The
classification is in `release-records/0.1.1.md`.

- `find` reads Git history paths NUL-delimited (`git grep -z`,
  `git log -z`). A history path that Git quotes (a non-ASCII byte, a control
  character, a quote, a backslash) is reported with its real name. Before,
  rf reported the quoted form: `café.rs` came out as `"caf\303\251.rs"`.
- `find` reads a scrub hash of any length. Before, a hash longer than 7
  characters gave "scrubbed in unknown" in `GIT_DELETED`.
- `find`: when the scrub `git log` cannot start or exits non-zero, rf gives
  the new warning `GIT_SCRUB_UNAVAILABLE`. It names the history-only matches.
  Before, `GIT_DELETED` said "scrubbed in unknown" with no cause. The log
  now runs only when there is a history-only match.
- `--matches`: a matched file that cannot be read for its occurrences has
  `matches: null` and a `PARTIAL_RESULT` warning that names it (`content`,
  `find`, `why`). Before, it had an empty list. `PARTIAL_RESULT` is now
  registered for `why`.
- `find --structural`: ast-grep output that is not a JSON list gives
  `STRUCTURAL_UNAVAILABLE` (`tool-unusable`). Before, rf read it as zero
  files. Empty output and `[]` still mean zero files.
- Selected-path mode (`--paths-stdin`, `--paths-envelope`) records a walk or
  canonicalize error that can hide a selected file. The result has a
  `PARTIAL_RESULT` warning, or `IO_FAILURE` (exit 3) when no file was read,
  as in normal mode. Before, the error was dropped.
- A declared value flag with undecodable bytes in its value
  (`--cursor=<bytes>`, `--json=<bytes>`) gives `INVALID_INPUT` with `arg` set
  to the flag name and `details.bytes_hex`. Before, it gave `UNKNOWN_FLAG`.
  Both exit 1.

## 0.1.0 — make-cli 0.1 contract

- **Breaking: contract version `0.1`.** rf now follows the make-cli 0.1.0
  contract. Contract version `2` ends, and no old spelling stays as an alias.
  The full compatibility statement is in `release-records/0.1.0.md`.
  - Version scheme: `contract_version` is a `major.minor` string. Before `1.0`
    a minor bump may break.
  - Envelope: `data` is an object. Rows are in `data.items`; the capabilities
    contract is `data`, not `data[0]`. A failed request can keep its result.
    Errors gain `arg` and `details`. Warnings are `code`, `message`, `details`
    (`msg` and `files` are removed; files are in `details.files`). Every
    declared key is always present.
  - Exits: an internal defect is exit 7, not 6. Exit 6 means findings present:
    `doctor` with a faulty external tool, `conformance` with a failed case. An
    unreadable named path is exit 3 (`why` gave 1, `content` gave 0). Signal and closed-pipe exits are declared.
  - Flags: `--human` is removed. Human output is the default, also to a pipe.
    `--json` is the only machine selector. The `help` verb is new.
  - Codes: errors and warnings are in one registry, `error_codes`.
    `INVALID_TARGET` is now `NOT_FOUND`, `INVALID_INPUT` or `IO_FAILURE`.
    `CONFORMANCE_FAIL` is now `CASE_FAILED`. `MISSING_ARGUMENT` is now
    `MISSING_REQUIRED`. `USAGE` is removed.
  - Capabilities: output schemas are JSON Schema. `value_domains` and
    `warning_codes` are removed. `robot-docs guide` is a subcommand entry.
  - Cursors from older builds return `CONFLICT` with a restart command.

- Set the crate `homepage` to <https://rgfind.dev/>, so the crates.io listing
  links to the documentation site.
- The README now links the documentation site — quickstart, JSON contract, and
  agent guide at rgfind.dev. Packaging and docs only; no behavior change.

## 0.0.8 — agent contract governance and bounded match evidence

- Added opt-in match evidence to `content`, `find`, and `why`. `--matches`
  returns per-occurrence `line`, `column_byte`, and `text`; `--max-matches`
  bounds the count and requires `--matches`. Truncated evidence is marked with
  `text_lossy` and `text_truncated`. Default output and default cursor identity
  are unchanged.
- Added external-tool health to `doctor`. It probes `git` and `ast-grep`,
  reports typed availability with `references` ({url, purpose}) and safe
  commands, and emits the new `EXTERNAL_TOOL_MISSING` warning (nineteen codes).
- `find` results now carry `meta.sources` with structural and history
  provenance ({requested, actual, fallback_reason}). `matches` is `null` with
  `matches_unavailable_reason` for history-only or structural-only results.
- Added the agent-contract governance surface. `CONTRACT.md` documents the
  contract; `capabilities` gains `contract_policy` (supported contract
  versions, release classification, release record), per-verb
  `schema_versions`, and `verb_dependencies`.

## 0.0.7 — ignore provenance and query modes

- Added `ignore_source` to `rf why` results for a file hidden by an active
  ignore rule. It gives the source file, source class, rule pattern, and an
  unambiguous line number when available.
- Added `--fixed-strings`, `--word`, `--ignore-case`, and `--case-sensitive`
  to `content`, `find`, and `why`. Successful results now state the active
  query mode in `meta.query`.
- `find --word` reports `GIT_SCRUB_WORD_UNAVAILABLE` when Git pickaxe evidence
  cannot preserve whole-word semantics.

## 0.0.6 — why per-file forensic verdict

- Added `rf why <pattern> <file> [--root <dir>]` for one-file match verdicts and
  normal search-filter attribution.
- Added `INVALID_TARGET` for missing, unreadable, non-file, out-of-root, and
  repository-internal why targets.

## 0.0.5 — contract version 2

This release changes the machine contract.

- The JSON envelope has seven top-level keys. Failed requests use `data: null`.
- Exit code 5 means a paged result snapshot changed. Restart with the emitted command.
- `content` and `find` return at most 100 rows by default and 1000 rows at most.
- `find` reports Git history coverage and does not hide unavailable history as an empty result.
- `rf robot-docs guide` emits ready-to-run agent workflow recipes. Capabilities lists all released commands.
