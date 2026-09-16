# Releasing rf

crates.io is **write-once**: once a version is published, its README, metadata,
and code can never be changed for that version. So the documentation and the
code must agree **at the exact moment of publishing** — not before, not after.

Under plumb 0.0.3 the publish is done by **CI**, not by hand. The release
command runs Plumbline locally. It verifies everything and pushes the tag. A
tag-triggered workflow then does the real `cargo publish`. You never run
`cargo publish` yourself.

The guard is [`plumbline`](https://github.com/rgfind/plumbline), an installed
CLI invoked as `plumb` (not an in-repo tool). Pin it to the exact version the
workflows use — never float to git HEAD (a floating install is what reddened
the 0.0.7 tag). It reads `plumbline.json` at the repo root:

```sh
cargo install plumbline@0.0.3 --locked
```

## The stop sign

```sh
plumb preflight
```

Preflight is the release stop sign. It refuses to pass unless everything that
ships is in lock step. It holds four classes of gate:

**Contract and package integrity**

1. **Worktree clean and committed.** `cargo publish` packages the working tree,
   so any uncommitted change could ship un-reviewed. The tree must be clean.
2. **The fixture matches the binary.** It rebuilds `rf`, runs
   `rf capabilities --json`, and confirms the committed contract fixture is
   identical (contract-equivalent) to that fresh output.
3. **The docs match the fixture.** Every registered contract fact still equals
   its fixture field, and every generated block on a doc surface has a known id.
4. **Packaged files stay within the allowlist.** Every file `cargo package`
   would ship is a source file, an allowlisted doc, or cargo's own metadata — so
   no guard tool, cargo config, test fixture, or CI file leaks into the archive.
5. **The README example matches the binary.** It renders the recovery example
   from a real run of the freshly built binary and confirms the committed block
   in `README.md` is byte-identical.

**Declared code gates** (`verification.ci`) — `cargo fmt --check`,
`cargo clippy --all-targets --locked -D warnings`, `cargo test --locked`.

**Publish dry run** (`verification.release`) — `cargo publish --dry-run --locked`.

**CI proof** — a green GitHub Actions run of `ci.yml` (the workflow named in
`verification.github_actions.workflow_path`) for the exact release commit,
proven through the GitHub API. This is why the commit must be pushed and its
CI must be green **before** you release.

## Release

Run one command from a clean, current `main` branch:

```sh
./scripts/release 0.0.8 "bounded match evidence"
```

The command updates `Cargo.toml` and `CHANGELOG.md`, captures the contract
fixture, runs the local release checks, commits and pushes the preparation,
waits for CI proof, then runs `plumb release --yes`. Plumbline creates and
pushes the annotated tag. The tag starts `release.yml`, which publishes to
crates.io and creates the GitHub release.

Check the planned action without changing files or remote state:

```sh
./scripts/release --dry-run 0.0.8 "bounded match evidence"
```

The command does not read or print the registry token. GitHub Actions uses the
repository secret during the publish step.

## What the stop sign does not cover

- **Interpretive prose** (the explanatory text around the generated tables) is
  human-reviewed, not machine-checked. Read it when the contract changes. This
  includes the hand-written `--json` envelope beside the README recovery example:
  gate 5 regenerates the human render, but the JSON snippet next to it stays
  hand-kept, so re-read it when the `content` output shape changes.
