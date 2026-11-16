//! rf — an agent-first forensic search envelope that fuses ripgrep and fd.
//!
//! In-process design: the `ignore` walker and `grep` searcher (ripgrep's and
//! fd's own crates) run linked in-process, so every match keeps its full stage
//! provenance natively instead of being reconstructed from a shell pipe. Every
//! verb emits the universal machine-first envelope; see `capabilities`.

mod capabilities;
mod command;
mod conformance;
mod content;
mod doctor;
mod engine;
mod envelope;
mod external_tools;
mod fault;
mod find;
mod flags;
mod guide;
mod manifest;
mod pagination;
mod paths;
mod provenance;
mod query;
mod registry;
mod why;

use clap::{Parser, Subcommand};
use envelope::{envelope, err, CONTRACT_VERSION, TOOL_VERSION};
use serde_json::{json, Map, Value};
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "rf",
    version,
    about = "agent-first forensic search over ripgrep + fd",
    disable_help_subcommand = true,
    after_help = "Machine contract: rf capabilities --json\nAutomation: read the JSON envelope before you use a follow-up command.\nExit: 0 success; 1 input error; 3 environment error; 5 snapshot conflict; 6 findings; 7 internal error.\nWorkflow guides: rf robot-docs guide emits agent workflow recipes."
)]
struct Cli {
    /// Emit the machine-readable envelope. Accepted before or after a verb.
    #[arg(long, global = true)]
    json: bool,
    /// Disable terminal decoration. rf currently emits no ANSI decoration, but
    /// the accepted global flag is part of the stable parser contract.
    #[arg(long = "no-color", global = true)]
    no_color: bool,
    #[command(subcommand)]
    verb: Verb,
}

fn extension(value: &str) -> Result<String, String> {
    if value.is_empty() || value.contains('.') || value.contains('/') || value.contains('\\') {
        Err("file extension must be non-empty and contain no dot or path separator".into())
    } else {
        Ok(value.into())
    }
}

fn max_matches(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "--max-matches must be an integer in 1..=1000".to_string())?;
    if (1..=1000).contains(&parsed) {
        Ok(parsed)
    } else {
        Err("--max-matches must be in 1..=1000".into())
    }
}

#[derive(Subcommand)]
enum Verb {
    /// Task workflows for agents.
    #[command(name = "robot-docs")]
    RobotDocs {
        #[command(subcommand)]
        command: RobotDocs,
    },
    /// Emit the machine contract.
    Capabilities {},
    /// Content search with per-filter attribution.
    Content {
        pattern: String,
        #[arg(default_value = ".")]
        path: String,
        /// Read a NUL-delimited selected file list from stdin.
        #[arg(long, conflicts_with = "paths_envelope")]
        paths_stdin: bool,
        /// Read selected files from the data.items[].file fields of an rf JSON envelope on stdin.
        #[arg(long, conflicts_with = "paths_stdin")]
        paths_envelope: bool,
        #[arg(long, default_value_t = pagination::DEFAULT_LIMIT, value_parser = pagination::limit)]
        limit: usize,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        fixed_strings: bool,
        #[arg(long)]
        word: bool,
        #[arg(long, conflicts_with = "case_sensitive")]
        ignore_case: bool,
        #[arg(long, conflicts_with = "ignore_case")]
        case_sensitive: bool,
        /// Include bounded primary-pattern occurrences in each result row.
        #[arg(long)]
        matches: bool,
        /// Maximum occurrences per result file; requires --matches.
        #[arg(long, value_parser = max_matches)]
        max_matches: Option<usize>,
    },
    /// Staged cross-source discovery (port in progress).
    Find {
        pattern: String,
        #[arg(default_value = ".")]
        path: String,
        #[arg(long)]
        #[arg(value_parser = extension)]
        name: String,
        #[arg(long)]
        structural: Option<String>,
        #[arg(long)]
        lang: Option<String>,
        #[arg(long, default_value_t = pagination::DEFAULT_LIMIT, value_parser = pagination::limit)]
        limit: usize,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        fixed_strings: bool,
        #[arg(long)]
        word: bool,
        #[arg(long, conflicts_with = "case_sensitive")]
        ignore_case: bool,
        #[arg(long, conflicts_with = "ignore_case")]
        case_sensitive: bool,
        #[arg(long)]
        matches: bool,
        #[arg(long, value_parser = max_matches)]
        max_matches: Option<usize>,
    },
    /// Diagnose the environment and active ignore mode.
    Doctor {
        #[arg(default_value = ".")]
        path: String,
    },
    /// Explain whether one file matches and which normal search filter hid it.
    Why {
        pattern: String,
        file: String,
        /// Root directory for target validation and ignore context.
        #[arg(long)]
        root: Option<String>,
        #[arg(long)]
        fixed_strings: bool,
        #[arg(long)]
        word: bool,
        #[arg(long, conflicts_with = "case_sensitive")]
        ignore_case: bool,
        #[arg(long, conflicts_with = "ignore_case")]
        case_sensitive: bool,
        #[arg(long)]
        matches: bool,
        #[arg(long, value_parser = max_matches)]
        max_matches: Option<usize>,
    },
    /// Run the release self-check profile against this binary.
    Conformance {},
    /// Show help for rf or for one verb.
    Help {
        /// Verb path, for example `content` or `robot-docs guide`.
        verb_path: Vec<String>,
    },
}

#[derive(Subcommand)]
enum RobotDocs {
    Guide {
        #[arg(long)]
        compact: bool,
    },
}

/// Lexical mode scan over raw argv. It decodes nothing and stops at `--`.
/// A malformed selector (`--json=false`) still selects machine rendering; the
/// parser then refuses it.
fn bootstrap_json(args: &[OsString]) -> bool {
    args.iter()
        .take_while(|a| a.as_os_str() != OsStr::new("--"))
        .any(|a| {
            let bytes = a.as_encoded_bytes();
            bytes == b"--json" || bytes.starts_with(b"--json=")
        })
}

/// Text form of one raw token: each undecodable byte becomes `\xNN`.
fn escaped(token: &OsStr) -> String {
    let mut out = String::new();
    for chunk in token.as_encoded_bytes().utf8_chunks() {
        out.push_str(chunk.valid());
        for byte in chunk.invalid() {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    out
}

fn hex(token: &OsStr) -> String {
    token
        .as_encoded_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The verbs whose next positional is also a command name.
const GROUPS: [&str; 2] = ["robot-docs", "help"];

/// Classify the first undecodable token by its position.
fn undecodable(args: &[OsString]) -> Option<Value> {
    let mut after_dashes = false;
    let mut command_slots = 1;
    for token in args {
        let bytes = token.as_encoded_bytes();
        if !after_dashes && bytes == b"--" {
            after_dashes = true;
            continue;
        }
        let is_flag = !after_dashes && bytes.starts_with(b"-") && bytes.len() > 1;
        let Some(text) = token.to_str() else {
            let shown = escaped(token);
            let (code, what) = if is_flag {
                ("UNKNOWN_FLAG", "unknown flag")
            } else if command_slots > 0 && !after_dashes {
                ("UNKNOWN_COMMAND", "unknown command")
            } else {
                ("INVALID_INPUT", "argument is not valid UTF-8:")
            };
            let mut problem = err(code, format!("{what} \"{shown}\""));
            let object = problem.as_object_mut().unwrap();
            object.insert("arg".into(), Value::from(shown));
            object.insert("details".into(), json!({"bytes_hex": hex(token)}));
            return Some(problem);
        };
        if !is_flag && command_slots > 0 {
            command_slots -= 1;
            if GROUPS.contains(&text) {
                command_slots += 1;
            }
        }
    }
    None
}

fn is_bare(args: &[OsString]) -> bool {
    args.iter().all(|a| {
        let bytes = a.as_encoded_bytes();
        bytes == b"--json" || bytes == b"--no-color"
    })
}

/// The help text of one node of the verb path. The root is the empty path.
fn help_text(path: &[String]) -> String {
    let argv = std::iter::once("rf")
        .chain(path.iter().map(String::as_str))
        .chain(std::iter::once("--help"));
    match <Cli as clap::CommandFactory>::command().try_get_matches_from(argv) {
        Err(e) => e.render().to_string(),
        Ok(_) => String::new(),
    }
}

fn usage_text() -> String {
    help_text(&[])
}

fn internal(message: &str, json: bool, started: Instant) -> ! {
    let mut meta = Map::new();
    meta.insert("verb".into(), Value::Null);
    let env = envelope(
        false,
        Value::Null,
        meta,
        vec![],
        vec![],
        vec![err("INTERNAL", message)],
    );
    emit(env, registry::INTERNAL_EXIT, json, started)
}

/// Write to stdout and stderr with checked writes, then exit. A closed stdout
/// reader ends the process with 141 and no panic text.
fn finish(stdout: &str, stderr: &str, code: i32) -> ! {
    let mut out = std::io::stdout().lock();
    let wrote = out.write_all(stdout.as_bytes()).and_then(|()| out.flush());
    if let Err(e) = wrote {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(141);
        }
    }
    if !stderr.is_empty() {
        let _ = std::io::stderr().write_all(stderr.as_bytes());
    }
    std::process::exit(code);
}

/// A successful help surface: human text, or an envelope under `--json`.
fn surface(text: &str, data: Value, json: bool, started: Instant) -> ! {
    if json {
        let mut meta = Map::new();
        meta.insert("verb".into(), Value::Null);
        emit(
            envelope(true, data, meta, vec![], vec![], vec![]),
            0,
            true,
            started,
        );
    }
    let mut text = text.to_string();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    finish(&text, "", 0)
}

fn refuse(problem: Value, json: bool, started: Instant) -> ! {
    let mut meta = Map::new();
    meta.insert("verb".into(), Value::Null);
    let env = envelope(false, Value::Null, meta, vec![], vec![], vec![problem]);
    emit(env, 1, json, started)
}

fn dispatch(v: &Verb) -> (Value, i32) {
    match v {
        Verb::RobotDocs {
            command: RobotDocs::Guide { compact },
        } => guide::run(*compact),
        Verb::Capabilities { .. } => capabilities::run(),
        Verb::Content {
            pattern,
            path,
            paths_stdin,
            paths_envelope,
            limit,
            cursor,
            fixed_strings,
            word,
            ignore_case,
            case_sensitive,
            matches,
            max_matches,
            ..
        } => {
            let selection = if *paths_stdin {
                Some(content::SelectionMode::NulStdin)
            } else if *paths_envelope {
                Some(content::SelectionMode::Envelope)
            } else {
                None
            };
            content::run(
                pattern,
                path,
                *limit,
                cursor.as_deref(),
                selection,
                query::QueryMode::new(*fixed_strings, *word, *ignore_case),
                *case_sensitive,
                *matches,
                *max_matches,
            )
        }
        Verb::Find {
            pattern,
            path,
            name,
            structural,
            lang,
            limit,
            cursor,
            fixed_strings,
            word,
            ignore_case,
            case_sensitive,
            matches,
            max_matches,
        } => find::run(
            pattern,
            path,
            name,
            structural.as_deref(),
            lang.as_deref(),
            *limit,
            cursor.as_deref(),
            query::QueryMode::new(*fixed_strings, *word, *ignore_case),
            *case_sensitive,
            *matches,
            *max_matches,
        ),
        Verb::Doctor { path, .. } => doctor::run(path),
        Verb::Why {
            pattern,
            file,
            root,
            fixed_strings,
            word,
            ignore_case,
            case_sensitive,
            matches,
            max_matches,
        } => why::run(
            pattern,
            file,
            root.as_deref(),
            query::QueryMode::new(*fixed_strings, *word, *ignore_case),
            *case_sensitive,
            *matches,
            *max_matches,
        ),
        Verb::Conformance { .. } => conformance::run(),
        Verb::Help { .. } => unreachable!("the validator answers help before the parser"),
    }
}

/// Minimal human rendering. It is the default; `--json` selects the envelope.
fn render_human(env: &Value) -> String {
    let meta = &env["meta"];
    let verb = meta["verb"].as_str().unwrap_or("");
    let mut out: Vec<String> = Vec::new();
    match verb {
        "content" => {
            out.push(format!(
                "content '{}' in {} [{}]: {} file(s), {} by default, {} hidden by filters",
                meta["pattern"].as_str().unwrap_or(""),
                meta["path"].as_str().unwrap_or(""),
                meta["query"]["syntax"].as_str().unwrap_or("regex"),
                meta["matched_files"],
                meta["default_matched_files"],
                meta["hidden_by_filters"]
            ));
            for d in env["data"]["items"].as_array().unwrap_or(&vec![]) {
                out.push(format!(
                    "  {:<12} {}",
                    d["surfaced_by"].as_str().unwrap_or(""),
                    d["file"].as_str().unwrap_or("")
                ));
            }
        }
        "find" => {
            out.push(format!(
                "find '{}' in {} [{}]: {} tree match(es), {} history-only",
                meta["pattern"].as_str().unwrap_or(""),
                meta["path"].as_str().unwrap_or(""),
                meta["query"]["syntax"].as_str().unwrap_or("regex"),
                meta["content_total"],
                meta["history_matches"]
            ));
            for d in env["data"]["items"].as_array().unwrap_or(&vec![]) {
                out.push(format!(
                    "  {:<14} {}",
                    d["stage"].as_str().unwrap_or(""),
                    d["file"].as_str().unwrap_or("")
                ));
            }
        }
        "doctor" => {
            let d = &env["data"];
            out.push(format!("rf: {}", d["rf_version"].as_str().unwrap_or("")));
            out.push(format!("engine: {}", d["engine"].as_str().unwrap_or("")));
            out.push(format!(
                "ignore_mode: {}",
                d["ignore_mode"].as_str().unwrap_or("")
            ));
            if let Some(tools) = d["external_tools"].as_object() {
                for (tool, health) in tools {
                    out.push(format!(
                        "{tool}: {} ({})",
                        health["state"].as_str().unwrap_or(""),
                        health["status"].as_str().unwrap_or("")
                    ));
                }
            }
            out.push(format!("overall: {}", d["overall"].as_str().unwrap_or("")));
        }
        "why" => {
            let d = &env["data"];
            let pattern = d["pattern"].as_str().unwrap_or("");
            let file = d["file"].as_str().unwrap_or("");
            if d["matched"].as_bool().unwrap_or(false) {
                let suffix = d["surfaced_by"]
                    .as_str()
                    .filter(|class| *class != "default")
                    .map(|class| format!(" - hidden by {class}"))
                    .unwrap_or_default();
                let query = &meta["query"];
                out.push(format!(
                    "why '{pattern}' {file} [{} {} {}]: MATCH{suffix}",
                    query["syntax"].as_str().unwrap_or("regex"),
                    if query["word"].as_bool().unwrap_or(false) {
                        "word"
                    } else {
                        "any"
                    },
                    query["case"].as_str().unwrap_or("sensitive")
                ));
                if let Some(source) = d.get("ignore_source") {
                    out.push(format!(
                        "  ignore rule: {}:{} ({})",
                        source["source_file"].as_str().unwrap_or(""),
                        source["line"]
                            .as_u64()
                            .map(|line| line.to_string())
                            .unwrap_or_else(|| "unknown line".into()),
                        source["pattern"].as_str().unwrap_or("")
                    ));
                }
            } else {
                out.push(format!(
                    "why '{pattern}' {file}: NO MATCH (pattern absent under all filters)"
                ));
            }
        }
        "conformance" => {
            let d = &env["data"];
            out.push(format!(
                "conformance [{}]: {}",
                d["profile"].as_str().unwrap_or(""),
                meta["headline"].as_str().unwrap_or("")
            ));
            for c in d["cases"].as_array().unwrap_or(&vec![]) {
                let v = c["verdict"].as_str().unwrap_or("");
                if v == "pass" {
                    continue;
                }
                out.push(format!(
                    "  {:<15} {} {}",
                    c["case_id"].as_str().unwrap_or(""),
                    v,
                    c["reason"].as_str().unwrap_or("")
                ));
            }
        }
        _ => return serde_json::to_string_pretty(env).unwrap_or_default(),
    }
    for w in env["warnings"].as_array().unwrap_or(&vec![]) {
        out.push(format!(
            "  ! {}: {}",
            w["code"].as_str().unwrap_or(""),
            w["message"].as_str().unwrap_or("")
        ));
    }
    for c in env["commands"].as_array().unwrap_or(&vec![]) {
        out.push(format!("  $ {}", c.as_str().unwrap_or("")));
    }
    out.join("\n")
}

/// The did-you-mean lines for stderr. Empty when the hint is null.
fn hint_lines(env: &Value) -> String {
    let Some(hint) = env["errors"][0]["did_you_mean"].as_str() else {
        return String::new();
    };
    let mut out = format!("  did you mean: {hint}\n");
    if let Some(command) = env["commands"][0].as_str() {
        out.push_str(&format!("  corrected:    {command}\n"));
    }
    out
}

fn emit(mut env: Value, code: i32, json: bool, started: Instant) -> ! {
    if let Some(meta) = env.get_mut("meta").and_then(Value::as_object_mut) {
        // A fixed source epoch is the explicit reproducible-output mode. It
        // freezes the timing field too, so fixtures can compare complete JSON.
        let elapsed = if std::env::var_os("SOURCE_DATE_EPOCH").is_some() {
            0
        } else {
            started.elapsed().as_millis() as u64
        };
        meta.insert("elapsed_ms".into(), Value::from(elapsed));
    }
    if !env["ok"].as_bool().unwrap_or(false) {
        // One code has one exit. A mismatch is a defect in the caller.
        debug_assert_eq!(
            env["errors"][0]["code"]
                .as_str()
                .and_then(registry::lookup)
                .and_then(|c| c.exit),
            Some(code),
            "exit does not match the registry for {}",
            env["errors"][0]["code"]
        );
        if let Some(errors) = env.get_mut("errors").and_then(Value::as_array_mut) {
            for error in errors {
                if let Some(object) = error.as_object_mut() {
                    object.insert("exit_code".into(), Value::from(code));
                }
            }
        }
    }
    let mut stdout = String::new();
    let mut stderr = String::new();
    if json {
        stdout.push_str(&serde_json::to_string_pretty(&env).unwrap_or_default());
        stdout.push('\n');
        if let Some(message) = env["errors"][0]["message"].as_str() {
            stderr.push_str(&format!("error: {message}\n"));
        }
        stderr.push_str(&hint_lines(&env));
    } else {
        // A refusal with no payload is stderr text only in human rendering.
        if !env["data"].is_null() || env["ok"].as_bool().unwrap_or(false) {
            stdout.push_str(&render_human(&env));
            stdout.push('\n');
        }
        for e in env["errors"].as_array().unwrap_or(&vec![]) {
            stderr.push_str(&format!(
                "error: {}: {}\n",
                e["code"].as_str().unwrap_or(""),
                e["message"].as_str().unwrap_or("")
            ));
        }
        stderr.push_str(&hint_lines(&env));
    }
    finish(&stdout, &stderr, code)
}

fn main() {
    let started = Instant::now();
    let raw: Vec<OsString> = std::env::args_os().skip(1).collect();
    let json = bootstrap_json(&raw);
    if let Some(problem) = undecodable(&raw) {
        refuse(problem, json, started);
    }
    let selector_end = raw
        .iter()
        .position(|a| a.as_os_str() == OsStr::new("--"))
        .unwrap_or(raw.len());
    if raw[..selector_end]
        .iter()
        .any(|a| a.as_encoded_bytes().starts_with(b"--json="))
    {
        let mut problem = err("INVALID_INPUT", "--json takes no value");
        problem
            .as_object_mut()
            .unwrap()
            .insert("arg".into(), Value::from("--json"));
        refuse(problem, json, started);
    }
    if is_bare(&raw) {
        let usage = usage_text();
        surface(
            &usage,
            json!({"usage": usage, "default_action": null}),
            json,
            started,
        );
    }
    let tokens: Vec<String> = raw
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    // The validator checks argv in the fixed diagnosis order. Clap then only
    // builds the typed struct from argv that is already valid.
    let argv = match flags::validate(&tokens) {
        flags::Outcome::Run(argv) => argv,
        flags::Outcome::Help(path) => {
            let usage = help_text(&path);
            surface(
                &usage,
                json!({"usage": usage, "capabilities_command": "rf capabilities --json"}),
                json,
                started,
            );
        }
        flags::Outcome::Version => surface(
            TOOL_VERSION,
            json!({"contract_version": CONTRACT_VERSION, "build": null}),
            json,
            started,
        ),
        flags::Outcome::Refuse { error, command } => {
            let mut meta = Map::new();
            meta.insert("verb".into(), Value::Null);
            let commands = command.into_iter().collect();
            let env = envelope(false, Value::Null, meta, vec![], commands, vec![error]);
            emit(env, 1, json, started);
        }
    };
    let cli = match Cli::try_parse_from(std::iter::once("rf".to_string()).chain(argv)) {
        Ok(c) => c,
        Err(_) => internal(
            "the parser refused argv that the validator accepted",
            json,
            started,
        ),
    };

    // Totality: no backend panic reaches the user as an unmediated crash.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(&cli.verb)));
    match result {
        Ok((env, code)) => emit(env, code, json, started),
        Err(_) => internal("internal error (panic caught)", json, started),
    }
}
