//! Parser-derived surface manifest (probeability rule X-01).
//!
//! This is intentionally independent from `capabilities`: it walks clap's live
//! registry and records every accepted command path, flag spelling, alias, and
//! positional. The conformance verb compares it with the public contract, and a unit
//! test compares it with the flag table.

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
