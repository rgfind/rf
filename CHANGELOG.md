# Changelog

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
