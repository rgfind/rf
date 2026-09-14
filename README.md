# rf

**Search results that agents can inspect, explain, and safely continue from.**

A naive `rg pattern` silently skips gitignored, hidden, and binary files. On a
working tree it can miss most of the matches and still exit 0, so the caller
thinks the search succeeded. The blind spot multiplies the moment `rg` is chained
with `fd`, Git history, or structural search in an ad-hoc pipeline: no stage can
say what the pipeline as a whole failed to search. `rf` (**r**ipgrep + **f**d)
owns those stages, finds the hidden matches, and names the filter that hid each.

**Status: early development.** The command surface and the JSON envelope below
work today; expect breaking changes before 1.0.

## Install

```sh
cargo install rf
```

## Who it's for

`rf` is for when a *program* acts on a search result unattended — an agent, a
script, a test. For interactive work at a terminal, plain `rg` and `fd` are fine;
if a search comes up short you add `-uu` and look again. A program cannot look
again. It needs the result to say what it searched, what it hid, and whether it is
safe to build on — in a stable, typed shape. That is what `rf` provides and a
shell pipe cannot.

## The control surface

Every `rf` command returns **one** envelope of a known shape. Run
`rf capabilities --json` to read the live contract before you act. The envelope is
what makes a result something an agent can *inspect, explain, and safely continue
from*:

- **inspect** — `rf capabilities` declares the verbs, flags, exit codes, and
  warning codes of the running binary. Every response is the same seven-key
  envelope (`ok`, `data`, `meta`, `warnings`, `errors`, `commands`,
  `tool_version`). An empty result is `ok: true` with `data: []`, never an error.
- **explain** — every recovered file is attributed to the filter or stage that
  hid it, and every miss carries a typed warning code plus the paste-ready `rg`
  command that surfaces it.
- **safely continue from** — outcomes carry typed exit codes (`0` success, `1`
  input error, `3` environment error, `5` snapshot changed, `6` internal), not one
  overloaded status. `content` and `find` page at 100 rows with an opaque cursor,
  and a prior result's file list can feed the next command via `--paths-envelope`.
  A page whose snapshot changed underneath it returns exit `5` and a safe restart
  command instead of silently skewed rows.

None of these is reproducible by adding flags to `rg`.

## Proof: recovery with provenance

The recovery case is the contract made visible. A repo with the search term in
three places — a tracked file, a hidden file, and a gitignored file:

```
config.py          timeout = 30
.env.local         timeout = 5      # hidden
cache/build.py     timeout = 999    # gitignored
```

Plain ripgrep finds one of the three. `rf` finds all three and names the filter
that hid each:

<!-- BEGIN GENERATED:readme-example -->
```
$ rf content timeout .
content 'timeout' in .: 3 file(s), 1 by default, 2 hidden by filters
  default      config.py
  hidden       .env.local
  vcs_ignore   cache/build.py
  ! IGNORE_VCS: 1 match(es) hidden by default; add -u (ignore .gitignore/.ignore rules)
  ! HIDDEN_SKIPPED: 1 match(es) hidden by default; add -uu (also search hidden/dotfiles)
  $ 'rg' '-u' '-e' 'timeout' '--' '.'
  $ 'rg' '-uu' '-e' 'timeout' '--' '.'
```
<!-- END GENERATED:readme-example -->

Piped or with `--json`, the same result is one structured envelope:

```json
{
  "ok": true,
  "data": [
    { "file": "config.py",      "surfaced_by": "default" },
    { "file": ".env.local",     "surfaced_by": "hidden" },
    { "file": "cache/build.py", "surfaced_by": "vcs_ignore" }
  ],
  "meta": { "matched_files": 3, "default_matched_files": 1, "hidden_by_filters": 2 }
}
```

The `warnings` array (elided above) carries one entry per miss, each with a
warning code and the paste-ready `rg` command that surfaces it. The recovery is
not the product — it is the evidence that the contract holds.

## Per-file verdict: `why`

Use `rf why <pattern> <file>` when you already know the one file that a normal
tree search appears to have missed. It reads that file, returns one verdict row,
and names the filter that hid it. Its correction command repeats the tree search
from the root, so it can include sibling matches; `data[].file` is the target.

`doctor` answers a different question. `rf doctor <path>` reports the ambient
ignore regime and does not read a search target. `rf why` reads one named file
with one pattern and returns that file's verdict.

<!-- BEGIN GENERATED:why-example -->
```
$ rf why timeout cache/build.py --human
why 'timeout' cache/build.py: MATCH - hidden by vcs_ignore
  ! IGNORE_VCS: match hidden from a default tree search; add -u (ignore .gitignore/.ignore rules)
  $ 'rg' '-u' '-e' 'timeout' '--' '.'
```
<!-- END GENERATED:why-example -->

## The pipeline case: `find`

`rf find` is where the control surface pays off. It runs staged discovery across
independent sources and attributes every miss to the one stage that hid it —
something no `fd | rg` pipe can do, because the pipe erases fd's exit code and
conflates ripgrep's "no files" with "no match."

- **`rf find <pattern> <path> --name <ext>`** — the fd name filters (`fd_name`,
  `fd_hidden`, `fd_ignore`) and ripgrep's binary skip (`rg_binary`) run
  in-process; git history (`git_deleted`) recovers matches scrubbed from the tree;
  with `--structural PAT --lang LANG`, ast-grep (`ast_structural`) finds matches
  with no fixed literal form. `find` reports Git history coverage in
  `meta.history`, so an unavailable history is a distinct, typed outcome — not an
  empty result that looks like success.

The other verbs share the same envelope:

- **`rf content <pattern> <path>`** — content search that peels ripgrep's default
  filters as layers (vcs-ignore, hidden, binary, case) plus a utf-16 encoding
  probe, attributing every recovered file to the filter that hid it.
- **`rf doctor <path>`** — reports the linked engine and whether `.gitignore` is
  active for the path. (`.gitignore` applies only inside a git work tree, so the
  same search can answer differently in a scratch dir and a real repo.)
- **`rf why <pattern> <file> [--root <dir>]`** — returns one file's match
  verdict and the normal tree-search filter that hid it, if any.
- **`rf capabilities`** — the machine contract as JSON.
- **`rf conformance`** — runs the release self-check on this binary.
- **`rf robot-docs guide`** — ready-to-run agent workflow recipes (goal, command,
  expected branch, version range); `--compact` emits a terse form.

## How it works

`rf` links the [`ignore`](https://crates.io/crates/ignore) walker and the
[`grep`](https://crates.io/crates/grep) searcher — ripgrep's and fd's own crates
— directly, rather than shelling out to the `rg` and `fd` binaries. Each file's
membership in a filter is read natively as the walk runs, so a match keeps its
stage provenance instead of losing it when a shell pipe erases fd's exit code and
conflates ripgrep's "no files" with "no match." Git history and ast-grep are
external oracles with no Rust binding, so `rf` runs them as subprocesses; each
contributes nothing (rather than failing) when its tool is absent.

`rf` is the first worked example of a broader method: give an agent-first contract
to a venerable, human-first CLI whose failures are silent and load-bearing. The
search cluster (ripgrep + fd) is that first example — a demonstration on one
clean-tool cluster, not a proof that the method generalizes.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
