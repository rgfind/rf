//! Best-effort reconstruction of the ignore rule that hid one file.
//!
//! The `ignore` walker does not expose the winning glob. This module uses its
//! public gitignore matcher for each source independently. The search verdict
//! remains the walker differential in `content`; this is evidence only.

use ignore::gitignore::{Gitignore, GitignoreBuilder, Glob};
use ignore::Match;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct Rule {
    source_file: PathBuf,
    class: &'static str,
    pattern: String,
}

fn parent_chain(target: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut current = target.parent();
    while let Some(dir) = current {
        out.push(dir.to_path_buf());
        current = dir.parent();
    }
    out
}

fn git_root(chain: &[PathBuf]) -> Option<PathBuf> {
    chain
        .iter()
        .find(|dir| {
            let dot_git = dir.join(".git");
            dot_git.is_dir() || dot_git.is_file()
        })
        .cloned()
}

fn match_rule(matcher: &Gitignore, target: &Path) -> Result<Option<Rule>, ()> {
    match matcher.matched_path_or_any_parents(target, false) {
        Match::Ignore(glob) => Ok(Some(rule_from_glob(glob)?)),
        Match::Whitelist(_) => Err(()),
        Match::None => Ok(None),
    }
}

/// Global excludes are constructed with the process directory as their base,
/// while a query root can be elsewhere. `matched` has no under-root assertion;
/// check the target and its parents explicitly to retain directory-rule
/// behavior without changing the process directory.
fn match_global_rule(matcher: &Gitignore, target: &Path) -> Result<Option<Rule>, ()> {
    let mut candidate = Some(target);
    while let Some(path) = candidate {
        match matcher.matched(path, path != target) {
            Match::Ignore(glob) => return Ok(Some(rule_from_glob(glob)?)),
            Match::Whitelist(_) => return Err(()),
            Match::None => candidate = path.parent(),
        }
    }
    Ok(None)
}

fn rule_from_glob(glob: &Glob) -> Result<Rule, ()> {
    Ok(Rule {
        source_file: glob.from().ok_or(())?.to_path_buf(),
        // Filled by the source caller. A glob itself does not carry this.
        class: "",
        pattern: glob.original().to_string(),
    })
}

fn source_rule(source: &Path, class: &'static str, target: &Path) -> Result<Option<Rule>, ()> {
    source_rule_at(
        source,
        source.parent().unwrap_or(Path::new("/")),
        class,
        target,
    )
}

fn source_rule_at(
    source: &Path,
    base: &Path,
    class: &'static str,
    target: &Path,
) -> Result<Option<Rule>, ()> {
    if !source.is_file() {
        return Ok(None);
    }
    let mut builder = GitignoreBuilder::new(base);
    if builder.add(source).is_some() {
        return Err(());
    }
    let matcher = builder.build().map_err(|_| ())?;
    match_rule(&matcher, target).map(|rule| {
        rule.map(|mut rule| {
            rule.class = class;
            rule
        })
    })
}

fn linked_exclude(root: &Path) -> Result<PathBuf, ()> {
    let dot_git = root.join(".git");
    if dot_git.is_dir() {
        return Ok(dot_git.join("info/exclude"));
    }
    let text = std::fs::read_to_string(&dot_git).map_err(|_| ())?;
    let gitdir = text.strip_prefix("gitdir: ").ok_or(())?.trim();
    if gitdir.is_empty() {
        return Err(());
    }
    let gitdir = PathBuf::from(gitdir);
    let gitdir = if gitdir.is_absolute() {
        gitdir
    } else {
        root.join(gitdir)
    };
    let common = std::fs::read_to_string(gitdir.join("commondir")).map_err(|_| ())?;
    let common = common.trim();
    if common.is_empty() {
        return Err(());
    }
    let common = PathBuf::from(common);
    let common = if common.is_absolute() {
        common
    } else {
        gitdir.join(common)
    };
    Ok(common.join("info/exclude"))
}

// This mirrors ignore's parser handling that affects `Glob::original()`.
fn preprocessed_lines(source: &Path) -> Result<Vec<(u64, String)>, ()> {
    let bytes = std::fs::read(source).map_err(|_| ())?;
    let text = String::from_utf8(bytes).map_err(|_| ())?;
    Ok(text
        .lines()
        .enumerate()
        .map(|(index, raw)| {
            let raw = if index == 0 {
                raw.strip_prefix('\u{feff}').unwrap_or(raw)
            } else {
                raw
            };
            let line = if raw.ends_with("\\ ") {
                raw.to_string()
            } else {
                raw.trim_end().to_string()
            };
            ((index + 1) as u64, line)
        })
        .collect())
}

fn source_path(root: &Path, source: &Path) -> String {
    let normalized = std::fs::canonicalize(source).unwrap_or_else(|_| source.to_path_buf());
    normalized
        .strip_prefix(root)
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| normalized.to_string_lossy().replace('\\', "/"))
}

fn as_json(root: &Path, rule: Rule) -> Value {
    let mut value = Map::new();
    value.insert(
        "source_file".into(),
        Value::from(source_path(root, &rule.source_file)),
    );
    value.insert("class".into(), Value::from(rule.class));
    value.insert("pattern".into(), Value::from(rule.pattern.clone()));
    if let Ok(lines) = preprocessed_lines(&rule.source_file) {
        let matches: Vec<u64> = lines
            .into_iter()
            .filter_map(|(line, text)| (text == rule.pattern).then_some(line))
            .collect();
        if matches.len() == 1 {
            value.insert("line".into(), Value::from(matches[0]));
        }
    }
    Value::from(value)
}

/// Return a source object, or a stable unresolved reason. This function is
/// called only after the authoritative differential says `vcs_ignore`.
pub fn resolve(root: &Path, target: &Path) -> Result<Value, &'static str> {
    let chain = parent_chain(target);
    let git_root = git_root(&chain);
    let git_index = git_root
        .as_ref()
        .and_then(|boundary| chain.iter().position(|dir| dir == boundary));

    // Precedence is directory-first, not source-class-first: the deepest
    // directory wins and `.ignore` only outranks `.gitignore` at that same
    // directory. Each file gets its own matcher, preserving anchored rules.
    for (index, dir) in chain.iter().enumerate() {
        if let Some(rule) = source_rule(&dir.join(".ignore"), "dot_ignore", target)
            .map_err(|_| "could not read or parse a .ignore source")?
        {
            return Ok(as_json(root, rule));
        }
        if git_index.is_some_and(|last| index <= last) {
            if let Some(rule) = source_rule(&dir.join(".gitignore"), "gitignore", target)
                .map_err(|_| "could not read or parse a .gitignore source")?
            {
                return Ok(as_json(root, rule));
            }
        }
    }

    let Some(git_root) = git_root else {
        return Err("no active Git boundary could reproduce the ignore decision");
    };

    let exclude =
        linked_exclude(&git_root).map_err(|_| "Git exclude metadata is missing or invalid")?;
    if let Some(rule) = source_rule_at(&exclude, &git_root, "git_exclude", target)
        .map_err(|_| "could not read or parse the Git exclude source")?
    {
        return Ok(as_json(root, rule));
    }

    let (global, error) = Gitignore::global();
    if error.is_some() {
        return Err("could not load the global Git ignore source");
    }
    if let Some(mut rule) = match_global_rule(&global, target)
        .map_err(|_| "global Git ignore whitelist contradicted the verdict")?
    {
        rule.class = "git_global";
        return Ok(as_json(root, rule));
    }
    Err("no enabled ignore source reproduced the walker decision")
}
