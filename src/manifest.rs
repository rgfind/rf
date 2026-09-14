//! Parser-derived surface manifest (probeability rule X-01).
//!
//! This is intentionally independent from `capabilities`: it walks clap's live
//! registry and records every accepted command path, flag spelling, alias, and
//! positional. Consumers may use its names for parser-derived suggestions; the
//! conformance verb compares it with the hand-written public contract.

use clap::{Arg, ArgAction, Command, CommandFactory};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

fn arity(arg: &Arg) -> i64 {
    matches!(arg.get_action(), ArgAction::Set | ArgAction::Append) as i64
}

fn spellings(arg: &Arg) -> Vec<String> {
    let mut names = BTreeSet::new();
    if let Some(long) = arg.get_long() {
        names.insert(format!("--{long}"));
    }
    for alias in arg.get_all_aliases().unwrap_or_default() {
        names.insert(format!("--{alias}"));
    }
    if let Some(short) = arg.get_short() {
        names.insert(format!("-{short}"));
    }
    for alias in arg.get_all_short_aliases().unwrap_or_default() {
        names.insert(format!("-{alias}"));
    }
    names.into_iter().collect()
}

fn flag(arg: &Arg) -> Value {
    let names = spellings(arg);
    let mut m = Map::new();
    m.insert(
        "name".into(),
        Value::from(names.first().cloned().unwrap_or_default()),
    );
    m.insert(
        "aliases".into(),
        Value::from(
            names
                .into_iter()
                .skip(1)
                .map(Value::from)
                .collect::<Vec<_>>(),
        ),
    );
    m.insert("arity".into(), Value::from(arity(arg)));
    Value::from(m)
}

fn walk(command: &Command, parent: &[String], commands: &mut Map<String, Value>) {
    let mut path = parent.to_vec();
    path.push(command.get_name().to_string());
    let path_name = path.join(" ");
    let mut flags = Vec::new();
    let mut positionals = Vec::new();
    for arg in command.get_arguments() {
        if arg.is_positional() {
            positionals.push(arg.get_id().as_str().to_string());
        } else if !arg.is_global_set() && !matches!(arg.get_id().as_str(), "help" | "version") {
            flags.push(flag(arg));
        }
    }
    flags.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    positionals.sort();
    let mut aliases: Vec<String> = command.get_all_aliases().map(String::from).collect();
    aliases.sort();
    let mut entry = Map::new();
    entry.insert("path".into(), Value::from(path.clone()));
    entry.insert("aliases".into(), Value::from(aliases));
    entry.insert("flags".into(), Value::from(flags));
    entry.insert(
        "positionals".into(),
        Value::from(positionals.into_iter().map(Value::from).collect::<Vec<_>>()),
    );
    commands.insert(path_name, Value::from(entry));
    for sub in command.get_subcommands() {
        walk(sub, &path, commands);
    }
}

/// All parser-accepted public names. This is the only name source for future
/// typo correction and recipe validation; it never duplicates a hand list.
#[allow(dead_code)]
pub fn public_names() -> BTreeSet<String> {
    let manifest = build();
    let mut names = BTreeSet::new();
    for flag in manifest["global_flags"].as_array().into_iter().flatten() {
        for name in
            std::iter::once(&flag["name"]).chain(flag["aliases"].as_array().into_iter().flatten())
        {
            if let Some(name) = name.as_str() {
                names.insert(name.to_string());
            }
        }
    }
    for (path, command) in manifest["commands"].as_object().into_iter().flatten() {
        names.insert(path.clone());
        for alias in command["aliases"].as_array().into_iter().flatten() {
            if let Some(alias) = alias.as_str() {
                names.insert(alias.to_string());
            }
        }
        for flag in command["flags"].as_array().into_iter().flatten() {
            for name in std::iter::once(&flag["name"])
                .chain(flag["aliases"].as_array().into_iter().flatten())
            {
                if let Some(name) = name.as_str() {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

/// The unique public ASCII name at edit distance one. Ties and distant tokens
/// deliberately yield no suggestion.
pub fn correction(token: &str) -> Option<String> {
    fn distance_one(a: &str, b: &str) -> bool {
        if !a.is_ascii() || !b.is_ascii() || a == b || a.len().abs_diff(b.len()) > 1 {
            return false;
        }
        let (mut i, mut j, mut edits) = (0, 0, 0);
        let aa = a.as_bytes();
        let bb = b.as_bytes();
        while i < aa.len() && j < bb.len() {
            if aa[i] == bb[j] {
                i += 1;
                j += 1;
                continue;
            }
            edits += 1;
            if edits > 1 {
                return false;
            }
            if aa.len() > bb.len() {
                i += 1;
            } else if bb.len() > aa.len() {
                j += 1;
            } else {
                i += 1;
                j += 1;
            }
        }
        edits + (aa.len() - i) + (bb.len() - j) == 1
    }
    let matches: Vec<_> = public_names()
        .into_iter()
        .filter(|name| distance_one(token, name))
        .collect();
    (matches.len() == 1).then(|| matches[0].clone())
}

#[cfg(test)]
mod tests {
    use super::correction;
    #[test]
    fn correction_requires_one_public_near_match() {
        assert_eq!(correction("capabilitie").as_deref(), Some("capabilities"));
        assert_eq!(correction("not-even-close"), None);
    }
}

/// Build the manifest by walking clap's full command tree. Global and automatic
/// flags are declared once at the root; all command entries use full paths.
pub fn build() -> Value {
    let mut cmd = crate::Cli::command();
    // clap adds its automatic help/version arguments during build.
    cmd.build();
    let mut global_flags: Vec<Value> = cmd
        .get_arguments()
        .filter(|arg| !arg.is_positional())
        .map(flag)
        .collect();
    // clap synthesizes help/version on each subcommand, not at the root. They
    // are nevertheless global grammar, so derive their spellings from the
    // live subcommand registry and publish them once.
    for sub in cmd.get_subcommands() {
        for arg in sub
            .get_arguments()
            .filter(|arg| matches!(arg.get_id().as_str(), "help" | "version"))
        {
            let candidate = flag(arg);
            if !global_flags
                .iter()
                .any(|existing| existing["name"] == candidate["name"])
            {
                global_flags.push(candidate);
            }
        }
    }
    global_flags.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let mut commands = Map::new();
    for sub in cmd.get_subcommands() {
        walk(sub, &[], &mut commands);
    }
    let mut root = Map::new();
    root.insert("source".into(), Value::from("clap command registry"));
    root.insert("global_flags".into(), Value::from(global_flags));
    root.insert("commands".into(), Value::from(commands));
    Value::from(root)
}
