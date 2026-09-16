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
mod guide;
mod manifest;
mod pagination;
mod provenance;
mod query;
mod why;

use clap::{Parser, Subcommand};
use envelope::{envelope, err};
use serde_json::{Map, Value};
use std::io::IsTerminal;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "rf",
    version,
    about = "agent-first forensic search over ripgrep + fd",
    disable_help_subcommand = true,
    after_help = "Machine contract: rf capabilities --json\nAutomation: read the JSON envelope before you use a follow-up command.\nExit: 0 success; 1 input error; 3 environment error; 5 snapshot conflict; 6 internal error.\nWorkflow guides: rf robot-docs guide emits agent workflow recipes."
)]
struct Cli {
    /// Emit the machine-readable envelope. Accepted before or after a verb.
    #[arg(long, global = true)]
    json: bool,
    /// Disable terminal decoration. rf currently emits no ANSI decoration, but
    /// the accepted global flag is part of the stable parser contract.
    #[arg(long = "no-color", global = true)]
    no_color: bool,
    /// Force the human-readable render even when stdout is not a terminal (the
    /// mirror of --json). Use it to save or page the human output. --json wins
    /// if both are given.
    #[arg(long, global = true)]
    human: bool,
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
        /// Read selected files from the data[].file fields of an rf JSON envelope on stdin.
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
}

#[derive(Subcommand)]
enum RobotDocs {
    Guide {
        #[arg(long)]
        compact: bool,
    },
}

fn bootstrap_json() -> bool {
    // This scan is deliberately lexical and stops at `--`: a later `--json` or
    // `--human` is data, not a global option. It decides the render mode before
    // clap can reject malformed argv. Precedence: --json (machine) wins over
    // --human (human); with neither, a real terminal gets the human render.
    let (mut json, mut human) = (false, false);
    for a in std::env::args().skip(1).take_while(|a| a != "--") {
        match a.as_str() {
            "--json" => json = true,
            "--human" => human = true,
            _ => {}
        }
    }
    if json {
        true
    } else if human {
        false
    } else {
        !std::io::stdout().is_terminal()
    }
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
    }
}

/// Minimal human rendering for a TTY; JSON is the machine default.
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
            for d in env["data"].as_array().unwrap_or(&vec![]) {
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
            for d in env["data"].as_array().unwrap_or(&vec![]) {
                out.push(format!(
                    "  {:<14} {}",
                    d["stage"].as_str().unwrap_or(""),
                    d["file"].as_str().unwrap_or("")
                ));
            }
        }
        "doctor" => {
            let d = &env["data"][0];
            out.push(format!("rf: {}", d["rf_version"].as_str().unwrap_or("")));
            out.push(format!("engine: {}", d["engine"].as_str().unwrap_or("")));
            out.push(format!(
                "ignore_mode: {}",
                d["ignore_mode"].as_str().unwrap_or("")
            ));
        }
        "why" => {
            let d = &env["data"][0];
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
            let d = &env["data"][0];
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
            w["msg"].as_str().unwrap_or("")
        ));
    }
    for c in env["commands"].as_array().unwrap_or(&vec![]) {
        out.push(format!("  $ {}", c.as_str().unwrap_or("")));
    }
    out.join("\n")
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
        if let Some(errors) = env.get_mut("errors").and_then(Value::as_array_mut) {
            for error in errors {
                if let Some(object) = error.as_object_mut() {
                    object.insert("exit_code".into(), Value::from(code));
                }
            }
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&env).unwrap_or_default());
        if let Some(message) = env["errors"][0]["message"].as_str() {
            eprintln!("error: {message}");
        }
    } else {
        println!("{}", render_human(&env));
        for e in env["errors"].as_array().unwrap_or(&vec![]) {
            eprintln!(
                "error: {}: {}",
                e["code"].as_str().unwrap_or(""),
                e["message"].as_str().unwrap_or("")
            );
        }
    }
    std::process::exit(code);
}

fn main() {
    let started = Instant::now();
    let json = bootstrap_json();
    // Parse. clap exits 0 on --help/--version; remap its bad-args exit to the
    // the user-input-error code (1) with an envelope.
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            use clap::error::ErrorKind;
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                e.print().ok();
                std::process::exit(0);
            }
            let mut meta = Map::new();
            meta.insert("verb".into(), Value::Null);
            let code = match e.kind() {
                ErrorKind::UnknownArgument => "UNKNOWN_FLAG",
                ErrorKind::InvalidSubcommand => "UNKNOWN_COMMAND",
                ErrorKind::InvalidValue | ErrorKind::ValueValidation => "INVALID_INPUT",
                ErrorKind::MissingRequiredArgument => "MISSING_ARGUMENT",
                _ => "USAGE",
            };
            let rendered = e.to_string();
            let token = rendered
                .split('`')
                .nth(1)
                .or_else(|| rendered.split('\'').nth(1));
            let suggestion = if std::env::args().skip(1).any(|arg| arg == "--") {
                None
            } else {
                token.and_then(manifest::correction)
            };
            let mut problem = err(code, "invalid arguments; see --help");
            if let Some(suggestion) = suggestion {
                problem
                    .as_object_mut()
                    .unwrap()
                    .insert("did_you_mean".into(), Value::from(suggestion.clone()));
                let command = crate::command::shell("rf", &[suggestion]);
                let env = envelope(false, vec![], meta, vec![], vec![command], vec![problem]);
                emit(env, 1, json, started);
            }
            let env = envelope(false, vec![], meta, vec![], vec![], vec![problem]);
            emit(env, 1, json, started);
        }
    };

    // Totality: no backend panic reaches the user as an unmediated crash.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(&cli.verb)));
    match result {
        Ok((env, code)) => emit(env, code, json || cli.json, started),
        Err(_) => {
            let mut meta = Map::new();
            meta.insert("verb".into(), Value::Null);
            let env = envelope(
                false,
                vec![],
                meta,
                vec![],
                vec![],
                vec![err("INTERNAL", "internal error (panic caught)")],
            );
            emit(env, 6, json || cli.json, started);
        }
    }
}
