//! The one flag table, and the argv validator that reads it.
//!
//! Two readers use this table. `validate` checks raw tokens in the fixed
//! diagnosis order before clap sees them. `capabilities` publishes the same
//! entries, so the declared surface and the checked surface cannot drift.

use crate::envelope::err;
use regex::Regex;
use serde_json::{json, Map, Value};

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Str,
    Int,
    Path,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Str => "string",
            Kind::Int => "int",
            Kind::Path => "path",
        }
    }
}

pub struct Flag {
    pub name: &'static str,
    pub alias: Option<&'static str>,
    /// `None` is arity 0.
    pub value: Option<Kind>,
    pub choices: &'static [&'static str],
    pub pattern: Option<&'static str>,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub default: Option<i64>,
    pub must_exist: bool,
    pub allow_empty: bool,
    pub required: bool,
    pub conflicts_with: &'static [&'static str],
    pub requires: &'static [&'static str],
    pub description: &'static str,
}

const F: Flag = Flag {
    name: "",
    alias: None,
    value: None,
    choices: &[],
    pattern: None,
    min: None,
    max: None,
    default: None,
    must_exist: false,
    allow_empty: false,
    required: false,
    conflicts_with: &[],
    requires: &[],
    description: "",
};

pub struct Pos {
    pub name: &'static str,
    pub kind: Kind,
    pub required: bool,
    pub default: Option<&'static str>,
    pub repeatable: bool,
    /// The verb reads this path: absent is `NOT_FOUND`, unreadable is
    /// `IO_FAILURE`. The verb makes the check, after the argv stages.
    pub must_exist: bool,
}

pub struct Node {
    pub path: &'static [&'static str],
    pub flags: &'static [Flag],
    pub args: &'static [Pos],
    pub subs: &'static [&'static str],
}

/// ast-grep language ids that rf accepts. Canonical names only.
pub const LANGS: &[&str] = &[
    "bash",
    "c",
    "cpp",
    "csharp",
    "css",
    "elixir",
    "go",
    "haskell",
    "hcl",
    "html",
    "java",
    "javascript",
    "json",
    "kotlin",
    "lua",
    "nix",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "solidity",
    "swift",
    "tsx",
    "typescript",
    "yaml",
];

const LIMIT: Flag = Flag {
    name: "--limit",
    value: Some(Kind::Int),
    min: Some(1),
    max: Some(1000),
    default: Some(100),
    description: "maximum result rows in one page",
    ..F
};
const CURSOR: Flag = Flag {
    name: "--cursor",
    value: Some(Kind::Str),
    pattern: Some("^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    description: "opaque cursor from meta.pagination.cursor",
    ..F
};
const FIXED: Flag = Flag {
    name: "--fixed-strings",
    description: "read the pattern as a literal string",
    ..F
};
const WORD: Flag = Flag {
    name: "--word",
    description: "match whole words only",
    ..F
};
const IGNORE_CASE: Flag = Flag {
    name: "--ignore-case",
    conflicts_with: &["--case-sensitive"],
    description: "match without case",
    ..F
};
const CASE_SENSITIVE: Flag = Flag {
    name: "--case-sensitive",
    conflicts_with: &["--ignore-case"],
    description: "match with case; no case-recovery layer",
    ..F
};
const MATCHES: Flag = Flag {
    name: "--matches",
    description: "opt-in occurrence evidence in each result row",
    ..F
};
const MAX_MATCHES: Flag = Flag {
    name: "--max-matches",
    value: Some(Kind::Int),
    min: Some(1),
    max: Some(1000),
    default: Some(16),
    requires: &["--matches"],
    description: "maximum occurrences per result file; values above 16 are capped at 16",
    ..F
};

const PATTERN: Pos = Pos {
    name: "pattern",
    kind: Kind::Str,
    required: true,
    default: None,
    repeatable: false,
    must_exist: false,
};
const PATH: Pos = Pos {
    name: "path",
    kind: Kind::Path,
    required: false,
    default: Some("."),
    repeatable: false,
    must_exist: true,
};

pub static GLOBALS: [Flag; 4] = [
    Flag {
        name: "--json",
        description: "machine envelope",
        ..F
    },
    Flag {
        name: "--no-color",
        description: "disable terminal decoration",
        ..F
    },
    Flag {
        name: "--help",
        alias: Some("-h"),
        description: "usage text; exit 0",
        ..F
    },
    Flag {
        name: "--version",
        alias: Some("-V"),
        description: "version string; exit 0",
        ..F
    },
];

pub static NODES: [Node; 9] = [
    Node {
        path: &["robot-docs"],
        flags: &[],
        args: &[],
        subs: &["guide"],
    },
    Node {
        path: &["robot-docs", "guide"],
        flags: &[Flag {
            name: "--compact",
            description: "emit short recipes",
            ..F
        }],
        args: &[],
        subs: &[],
    },
    Node {
        path: &["capabilities"],
        flags: &[],
        args: &[],
        subs: &[],
    },
    Node {
        path: &["help"],
        flags: &[],
        args: &[Pos {
            name: "verb_path",
            kind: Kind::Str,
            required: false,
            default: None,
            repeatable: true,
            must_exist: false,
        }],
        subs: &[],
    },
    Node {
        path: &["content"],
        flags: &[
            Flag {
                name: "--paths-stdin",
                conflicts_with: &["--paths-envelope"],
                description: "stdin NUL-delimited UTF-8 paths; relative paths resolve under path",
                ..F
            },
            Flag {
                name: "--paths-envelope",
                conflicts_with: &["--paths-stdin"],
                description:
                    "stdin rf JSON envelope; each data.items[] row must contain file:string",
                ..F
            },
            LIMIT,
            CURSOR,
            FIXED,
            WORD,
            IGNORE_CASE,
            CASE_SENSITIVE,
            MATCHES,
            MAX_MATCHES,
        ],
        args: &[PATTERN, PATH],
        subs: &[],
    },
    Node {
        path: &["find"],
        flags: &[
            Flag {
                name: "--name",
                value: Some(Kind::Str),
                required: true,
                pattern: Some(r"^[^-./\\\s][^./\\\s]*$"),
                description: "file extension without dot or path separator",
                ..F
            },
            Flag {
                name: "--structural",
                value: Some(Kind::Str),
                requires: &["--lang"],
                description: "ast-grep pattern; a construct with no fixed literal form",
                ..F
            },
            Flag {
                name: "--lang",
                value: Some(Kind::Str),
                choices: LANGS,
                requires: &["--structural"],
                description: "ast-grep language id",
                ..F
            },
            LIMIT,
            CURSOR,
            FIXED,
            WORD,
            IGNORE_CASE,
            CASE_SENSITIVE,
            MATCHES,
            MAX_MATCHES,
        ],
        args: &[PATTERN, PATH],
        subs: &[],
    },
    Node {
        path: &["doctor"],
        flags: &[],
        args: &[PATH],
        subs: &[],
    },
    Node {
        path: &["why"],
        flags: &[
            Flag {
                name: "--root",
                value: Some(Kind::Path),
                must_exist: true,
                description: "directory that supplies target validation and ignore context",
                ..F
            },
            FIXED,
            WORD,
            IGNORE_CASE,
            CASE_SENSITIVE,
            MATCHES,
            MAX_MATCHES,
        ],
        args: &[
            PATTERN,
            Pos {
                name: "file",
                kind: Kind::Path,
                required: true,
                default: None,
                repeatable: false,
                must_exist: true,
            },
        ],
        subs: &[],
    },
    Node {
        path: &["conformance"],
        flags: &[],
        args: &[],
        subs: &[],
    },
];

pub fn node(path: &[&str]) -> Option<&'static Node> {
    NODES.iter().find(|n| n.path == path)
}

fn children(path: &[&str]) -> Vec<&'static str> {
    NODES
        .iter()
        .filter(|n| n.path.len() == path.len() + 1 && n.path[..path.len()] == *path)
        .map(|n| n.path[path.len()])
        .collect()
}

fn flag_json(f: &Flag, global: bool) -> Value {
    let mut m = Map::new();
    m.insert("name".into(), Value::from(f.name));
    if let Some(alias) = f.alias {
        m.insert("aliases".into(), json!([alias]));
    }
    match f.value {
        None => {
            m.insert("arity".into(), Value::from(0));
            m.insert("default".into(), Value::from(false));
        }
        Some(kind) => {
            m.insert("arity".into(), Value::from(1));
            m.insert("value_type".into(), Value::from(kind.name()));
            if kind == Kind::Path {
                m.insert("must_exist".into(), Value::from(f.must_exist));
            }
            if !f.choices.is_empty() {
                m.insert("enum".into(), json!(f.choices));
            }
            if let Some(pattern) = f.pattern {
                m.insert("value_pattern".into(), Value::from(pattern));
            }
            if let Some(min) = f.min {
                m.insert("minimum".into(), Value::from(min));
            }
            if let Some(max) = f.max {
                m.insert("maximum".into(), Value::from(max));
            }
            if let Some(default) = f.default {
                m.insert("default".into(), Value::from(default));
            }
            m.insert("allow_empty".into(), Value::from(f.allow_empty));
            m.insert("required".into(), Value::from(f.required));
        }
    }
    if !f.conflicts_with.is_empty() {
        m.insert("conflicts_with".into(), json!(f.conflicts_with));
    }
    if !f.requires.is_empty() {
        m.insert("requires".into(), json!(f.requires));
    }
    if global {
        m.insert("position".into(), Value::from("anywhere"));
    }
    m.insert("description".into(), Value::from(f.description));
    Value::from(m)
}

/// The `flags` list of one verb path, as `capabilities` publishes it.
pub fn flags_json(path: &[&str]) -> Value {
    Value::from(
        node(path)
            .map(|n| {
                n.flags
                    .iter()
                    .map(|f| flag_json(f, false))
                    .collect::<Vec<Value>>()
            })
            .unwrap_or_default(),
    )
}

/// The `args` list of one verb path, as `capabilities` publishes it.
pub fn args_json(path: &[&str]) -> Value {
    let args = node(path).map(|n| n.args).unwrap_or(&[]);
    Value::from(
        args.iter()
            .map(|a| {
                let mut m = Map::new();
                m.insert("name".into(), Value::from(a.name));
                m.insert("required".into(), Value::from(a.required));
                m.insert("type".into(), Value::from(a.kind.name()));
                if let Some(default) = a.default {
                    m.insert("default".into(), Value::from(default));
                }
                if a.repeatable {
                    m.insert("repeatable".into(), Value::from(true));
                }
                if a.kind == Kind::Path {
                    m.insert("must_exist".into(), Value::from(a.must_exist));
                }
                Value::from(m)
            })
            .collect::<Vec<_>>(),
    )
}

pub fn global_flags_json() -> Value {
    Value::from(
        GLOBALS
            .iter()
            .map(|f| flag_json(f, true))
            .collect::<Vec<_>>(),
    )
}

/// Optimal string alignment distance of at most one: one insert, delete,
/// substitution, or swap of two adjacent characters.
fn near(a: &str, b: &str) -> bool {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a == b || a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let (ra, rb) = (&a[prefix..], &b[prefix..]);
    match (ra.len(), rb.len()) {
        (x, y) if x == y => {
            ra[1..] == rb[1..] || (x >= 2 && ra[0] == rb[1] && ra[1] == rb[0] && ra[2..] == rb[2..])
        }
        (x, y) if x > y => ra[1..] == *rb,
        _ => *ra == rb[1..],
    }
}

/// The one declared name within the edit limit, or none.
fn suggest<'a>(token: &str, names: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let mut hits: Vec<&str> = names.into_iter().filter(|n| near(token, n)).collect();
    hits.sort_unstable();
    hits.dedup();
    (hits.len() == 1).then(|| hits[0])
}

pub enum Outcome {
    /// Canonical argv for clap: every value is attached, positionals follow `--`.
    Run(Vec<String>),
    Help(Vec<String>),
    Version,
    Refuse {
        error: Value,
        command: Option<String>,
    },
}

struct Fault {
    stage: u8,
    order: usize,
    error: Value,
    corrected: Option<Vec<String>>,
}

struct Seen {
    flag: &'static Flag,
    written: String,
    value: Option<String>,
    index: usize,
}

fn problem(code: &str, message: String, arg: &str, remediation: String) -> Value {
    let mut error = err(code, message);
    let object = error.as_object_mut().expect("error is an object");
    object.insert("arg".into(), Value::from(arg));
    object.insert("remediation".into(), Value::from(remediation));
    error
}

fn with_hint(mut error: Value, hint: Option<&str>) -> Value {
    if let Some(hint) = hint {
        let object = error.as_object_mut().expect("error is an object");
        object.insert("did_you_mean".into(), Value::from(hint));
        object.insert(
            "remediation".into(),
            Value::from(format!("Use {hint}; the corrected command is in commands.")),
        );
    }
    error
}

fn replaced(tokens: &[String], index: usize, with: String) -> Vec<String> {
    let mut out = tokens.to_vec();
    out[index] = with;
    out
}

fn flag_shaped(token: &str) -> bool {
    token.len() > 1 && token.starts_with('-')
}

fn signed_number(token: &str) -> bool {
    let digits = token.strip_prefix(['-', '+']).unwrap_or(token);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

fn unknown_flag(
    tokens: &[String],
    index: usize,
    name: &str,
    inline: Option<&str>,
    local: &[Flag],
    stage: u8,
) -> Fault {
    let names: Vec<&str> = local
        .iter()
        .chain(GLOBALS.iter())
        .flat_map(|f| std::iter::once(f.name).chain(f.alias))
        .collect();
    let hint = suggest(name, names.iter().copied());
    let starts: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| n.starts_with(name) && name.len() > 2)
        .collect();
    let remediation = if starts.is_empty() {
        "Run `rf capabilities --json` for the declared flags.".to_string()
    } else {
        format!(
            "Names match exactly. Declared flags that start with {name}: {}.",
            starts.join(", ")
        )
    };
    let error = problem(
        "UNKNOWN_FLAG",
        format!("unknown flag \"{name}\""),
        name,
        remediation,
    );
    Fault {
        stage,
        order: index,
        error: with_hint(error, hint),
        corrected: hint.map(|h| {
            let token = match inline {
                Some(value) => format!("{h}={value}"),
                None => h.to_string(),
            };
            replaced(tokens, index, token)
        }),
    }
}

fn unknown_command(tokens: &[String], index: usize, parent: &[&str]) -> Fault {
    let token = tokens[index].as_str();
    let names = children(parent);
    let hint = suggest(token, names.iter().copied());
    let starts: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| n.starts_with(token))
        .collect();
    let remediation = if starts.is_empty() {
        format!("Declared commands here: {}.", names.join(", "))
    } else {
        format!(
            "Names match exactly. Declared commands that start with {token}: {}.",
            starts.join(", ")
        )
    };
    let error = problem(
        "UNKNOWN_COMMAND",
        format!("unknown command \"{token}\""),
        token,
        remediation,
    );
    Fault {
        stage: 3,
        order: index,
        error: with_hint(error, hint),
        corrected: hint.map(|h| replaced(tokens, index, h.to_string())),
    }
}

/// Stage 5 checks on one flag value.
fn check_value(tokens: &[String], seen: &Seen) -> Option<Fault> {
    let flag = seen.flag;
    let kind = flag.value?;
    let value = seen.value.as_deref()?;
    let name = seen.written.as_str();
    let fault = |message: String, remediation: String, hint: Option<&str>| {
        let error = problem("INVALID_INPUT", message, name, remediation);
        Fault {
            stage: 5,
            order: seen.index,
            error: with_hint(error, hint),
            corrected: hint.map(|h| {
                if tokens[seen.index].contains('=') {
                    replaced(tokens, seen.index, format!("{name}={h}"))
                } else {
                    replaced(tokens, seen.index + 1, h.to_string())
                }
            }),
        }
    };
    if value.is_empty() && !flag.allow_empty {
        return Some(fault(
            format!("{name} needs a non-empty value"),
            format!("Give {name} a value, or remove the flag."),
            None,
        ));
    }
    if kind == Kind::Int {
        let (min, max) = (flag.min.unwrap_or(i64::MIN), flag.max.unwrap_or(i64::MAX));
        let parsed = signed_number(value)
            .then(|| value.parse::<i64>().ok())
            .flatten();
        if !parsed.is_some_and(|n| (min..=max).contains(&n)) {
            return Some(fault(
                format!("{name} must be a base-10 integer from {min} to {max} (got: \"{value}\")"),
                format!("Use {name}=<integer from {min} to {max}>."),
                None,
            ));
        }
    }
    if !flag.choices.is_empty() && !flag.choices.contains(&value) {
        return Some(fault(
            format!(
                "{name} must be one of: {} (got: \"{value}\")",
                flag.choices.join(", ")
            ),
            format!("Use one declared value for {name}."),
            suggest(value, flag.choices.iter().copied()),
        ));
    }
    if let Some(pattern) = flag.pattern {
        let matches = Regex::new(pattern).is_ok_and(|re| re.is_match(value));
        if !matches {
            return Some(fault(
                format!("{name} value must match {pattern} (got: \"{value}\")"),
                format!("{}: {}.", name, flag.description),
                None,
            ));
        }
    }
    None
}

/// Check argv in the fixed diagnosis order. `tokens` excludes the program name.
pub fn validate(tokens: &[String]) -> Outcome {
    let split = tokens
        .iter()
        .position(|t| t == "--")
        .unwrap_or(tokens.len());
    let mut faults: Vec<Fault> = Vec::new();
    let mut path: Vec<&'static str> = Vec::new();
    let mut expecting_command = true;
    let mut help_verb = false;
    let mut positionals: Vec<(usize, &str)> = Vec::new();
    let mut seen: Vec<Seen> = Vec::new();
    let mut globals: Vec<&'static str> = Vec::new();
    let mut lost = false;

    let mut i = 0;
    while i < split {
        let token = tokens[i].as_str();
        if flag_shaped(token) {
            let (name, inline) = match token.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (token, None),
            };
            let local: &[Flag] = if expecting_command {
                &[]
            } else {
                node(&path).map(|n| n.flags).unwrap_or(&[])
            };
            if let Some(flag) = local.iter().find(|f| f.name == name) {
                if seen.iter().any(|s| s.flag.name == flag.name) {
                    faults.push(Fault {
                        stage: 5,
                        order: i,
                        error: problem(
                            "INVALID_INPUT",
                            format!("{name} is given more than once"),
                            name,
                            format!("Give {name} one time."),
                        ),
                        corrected: None,
                    });
                }
                let at = i;
                let mut value = None;
                if flag.value.is_none() {
                    if inline.is_some() {
                        faults.push(Fault {
                            stage: 5,
                            order: i,
                            error: problem(
                                "INVALID_INPUT",
                                format!("{name} takes no value"),
                                name,
                                format!("Use {name} with no value."),
                            ),
                            corrected: Some(replaced(tokens, i, name.to_string())),
                        });
                    }
                } else if let Some(inline) = inline {
                    value = Some(inline.to_string());
                } else {
                    let next = tokens[..split].get(i + 1).map(String::as_str);
                    let numeric = flag.value == Some(Kind::Int);
                    match next {
                        Some(next) if !flag_shaped(next) || (numeric && signed_number(next)) => {
                            value = Some(next.to_string());
                            i += 1;
                        }
                        _ => faults.push(Fault {
                            stage: 5,
                            order: i,
                            error: problem(
                                "MISSING_REQUIRED",
                                format!("{name} needs a value"),
                                name,
                                format!("Use {name}=<value>."),
                            ),
                            corrected: None,
                        }),
                    }
                }
                seen.push(Seen {
                    flag,
                    written: name.to_string(),
                    value,
                    index: at,
                });
            } else if let Some(global) = GLOBALS
                .iter()
                .find(|f| f.name == name || f.alias == Some(name))
            {
                if inline.is_some() {
                    faults.push(Fault {
                        stage: 1,
                        order: i,
                        error: problem(
                            "INVALID_INPUT",
                            format!("{name} takes no value"),
                            name,
                            format!("Use {name} with no value."),
                        ),
                        corrected: Some(replaced(tokens, i, name.to_string())),
                    });
                }
                globals.push(global.name);
            } else {
                let stage = if path.is_empty() { 2 } else { 4 };
                faults.push(unknown_flag(tokens, i, name, inline, local, stage));
            }
        } else if expecting_command {
            if children(&path).contains(&token) {
                let name = children(&path)
                    .into_iter()
                    .find(|c| *c == token)
                    .expect("checked above");
                path.push(name);
                help_verb = path == ["help"];
                expecting_command = node(&path).is_some_and(|n| !n.subs.is_empty());
            } else {
                faults.push(unknown_command(tokens, i, &path));
                lost = true;
                break;
            }
        } else {
            positionals.push((i, token));
        }
        i += 1;
    }
    if !lost {
        positionals.extend(
            tokens
                .iter()
                .enumerate()
                .skip(split + 1)
                .map(|(index, token)| (index, token.as_str())),
        );
    }

    let wants_help = globals.contains(&"--help") || help_verb;
    let wants_version = globals.contains(&"--version");
    let mut help_path: Vec<&'static str> = if help_verb { Vec::new() } else { path.clone() };

    if !lost && help_verb {
        for (index, token) in &positionals {
            match children(&help_path).into_iter().find(|c| c == token) {
                Some(name) => help_path.push(name),
                None => {
                    faults.push(unknown_command(tokens, *index, &help_path));
                    break;
                }
            }
        }
    } else if !lost && !wants_help && !wants_version {
        if expecting_command {
            let message = if path.is_empty() {
                "a command is required".to_string()
            } else {
                format!("{} needs a subcommand", path.join(" "))
            };
            faults.push(Fault {
                stage: 6,
                order: usize::MAX,
                error: problem(
                    "MISSING_REQUIRED",
                    message,
                    "command",
                    format!("Declared commands here: {}.", children(&path).join(", ")),
                ),
                corrected: None,
            });
        } else if let Some(node) = node(&path) {
            for item in &seen {
                faults.extend(check_value(tokens, item));
            }
            for (position, item) in seen.iter().enumerate() {
                let earlier = seen[..position]
                    .iter()
                    .find(|other| item.flag.conflicts_with.contains(&other.flag.name));
                if let Some(other) = earlier {
                    faults.push(Fault {
                        stage: 5,
                        order: item.index,
                        error: problem(
                            "INVALID_INPUT",
                            format!(
                                "{} and {} cannot be used together",
                                other.written, item.written
                            ),
                            &item.written,
                            format!("Use {} or {}, not both.", other.written, item.written),
                        ),
                        corrected: None,
                    });
                }
            }
            let repeatable = node.args.last().is_some_and(|a| a.repeatable);
            if positionals.len() > node.args.len() && !repeatable {
                let (index, token) = positionals[node.args.len()];
                faults.push(Fault {
                    stage: 5,
                    order: index,
                    error: problem(
                        "INVALID_INPUT",
                        format!(
                            "unexpected argument \"{token}\": {} takes at most {} positional argument(s)",
                            path.join(" "),
                            node.args.len()
                        ),
                        token,
                        "Remove the surplus argument, or give it to a flag as --flag=value."
                            .to_string(),
                    ),
                    corrected: None,
                });
            }
            for item in &seen {
                for companion in item.flag.requires {
                    if seen.iter().any(|other| other.flag.name == *companion) {
                        continue;
                    }
                    let takes_value = node
                        .flags
                        .iter()
                        .find(|f| f.name == *companion)
                        .is_some_and(|f| f.value.is_some());
                    let corrected = (!takes_value).then(|| {
                        let mut out = tokens.to_vec();
                        out.insert(item.index, companion.to_string());
                        out
                    });
                    let add = if takes_value {
                        format!("{companion}=<value>")
                    } else {
                        companion.to_string()
                    };
                    faults.push(Fault {
                        stage: 6,
                        order: item.index,
                        error: problem(
                            "MISSING_REQUIRED",
                            format!("{} requires {companion}", item.written),
                            &item.written,
                            format!("Add {add} to the command."),
                        ),
                        corrected,
                    });
                }
            }
            for flag in node.flags.iter().filter(|f| f.required) {
                if !seen.iter().any(|s| s.flag.name == flag.name) {
                    faults.push(Fault {
                        stage: 6,
                        order: usize::MAX - 1,
                        error: problem(
                            "MISSING_REQUIRED",
                            format!("{} requires {}", path.join(" "), flag.name),
                            flag.name,
                            format!("Add {}=<value>: {}.", flag.name, flag.description),
                        ),
                        corrected: None,
                    });
                }
            }
            for (position, arg) in node.args.iter().enumerate() {
                if arg.required && positionals.len() <= position {
                    faults.push(Fault {
                        stage: 6,
                        order: usize::MAX,
                        error: problem(
                            "MISSING_REQUIRED",
                            format!("{} requires <{}>", path.join(" "), arg.name),
                            arg.name,
                            format!("Add the <{}> argument.", arg.name),
                        ),
                        corrected: None,
                    });
                    break;
                }
            }
        }
    }

    // A help or version request answers before value checks, not before a
    // name that the parser does not know.
    faults.retain(|f| f.stage < 5 || !(wants_help || wants_version));
    faults.sort_by_key(|f| (f.stage, f.order));
    if let Some(first) = faults.into_iter().next() {
        return Outcome::Refuse {
            error: first.error,
            command: first
                .corrected
                .map(|args| crate::command::shell("rf", &args)),
        };
    }
    if wants_help {
        return Outcome::Help(help_path.iter().map(|s| s.to_string()).collect());
    }
    if wants_version {
        return Outcome::Version;
    }

    let mut argv: Vec<String> = Vec::new();
    for global in ["--json", "--no-color"] {
        if globals.contains(&global) {
            argv.push(global.to_string());
        }
    }
    argv.extend(path.iter().map(|s| s.to_string()));
    for item in &seen {
        argv.push(match &item.value {
            Some(value) => format!("{}={value}", item.flag.name),
            None => item.flag.name.to_string(),
        });
    }
    argv.push("--".into());
    argv.extend(positionals.iter().map(|(_, token)| token.to_string()));
    Outcome::Run(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(args: &[&str]) -> (String, String, Value) {
        let tokens: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        match validate(&tokens) {
            Outcome::Refuse { error, .. } => (
                error["code"].as_str().unwrap().to_string(),
                error["arg"].as_str().unwrap_or("").to_string(),
                error["did_you_mean"].clone(),
            ),
            _ => panic!("expected a refusal for {args:?}"),
        }
    }

    #[test]
    fn near_counts_one_edit_and_one_swap() {
        assert!(near("rsut", "rust"));
        assert!(near("--jsno", "--json"));
        assert!(near("contnt", "content"));
        assert!(near("contentt", "content"));
        assert!(near("cantent", "content"));
        assert!(!near("content", "content"));
        assert!(!near("--js", "--json"));
        assert!(!near("tsur", "rust"));
    }

    #[test]
    fn earlier_stage_wins() {
        assert_eq!(refusal(&["--bogus", "badverb"]).0, "UNKNOWN_FLAG");
        assert_eq!(
            refusal(&["content", "--limit", "--bogus", "x"]).0,
            "UNKNOWN_FLAG"
        );
        let (code, arg, _) = refusal(&["find", "--name=-rs"]);
        assert_eq!((code.as_str(), arg.as_str()), ("INVALID_INPUT", "--name"));
        let (code, arg, _) = refusal(&["content", "--limit", "--word", "x"]);
        assert_eq!(
            (code.as_str(), arg.as_str()),
            ("MISSING_REQUIRED", "--limit")
        );
    }

    #[test]
    fn hints_name_one_candidate_or_none() {
        assert_eq!(refusal(&["fnd"]).2, "find");
        assert_eq!(refusal(&["content", "--wrod", "x"]).2, "--word");
        assert_eq!(refusal(&["content", "--lim", "5", "x"]).2, Value::Null);
        let (code, _, hint) = refusal(&[
            "find",
            "x",
            "--name",
            "rs",
            "--structural",
            "f",
            "--lang",
            "rsut",
        ]);
        assert_eq!(
            (code.as_str(), hint),
            ("INVALID_INPUT", Value::from("rust"))
        );
    }

    #[test]
    fn valid_argv_becomes_canonical() {
        let tokens: Vec<String> = ["content", "--limit", "5", "x", "--json", "--", "-p"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        match validate(&tokens) {
            Outcome::Run(argv) => {
                assert_eq!(argv, ["--json", "content", "--limit=5", "--", "x", "-p"])
            }
            _ => panic!("expected a run"),
        }
    }

    #[test]
    fn table_matches_the_clap_registry() {
        let manifest = crate::manifest::build();
        let commands = manifest["commands"].as_object().unwrap();
        assert_eq!(commands.len(), NODES.len());
        for node in &NODES {
            let entry = &commands[&node.path.join(" ")];
            let mut declared: Vec<(String, i64)> = node
                .flags
                .iter()
                .map(|f| (f.name.to_string(), f.value.is_some() as i64))
                .collect();
            declared.sort();
            let parsed: Vec<(String, i64)> = entry["flags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| {
                    (
                        f["name"].as_str().unwrap().to_string(),
                        f["arity"].as_i64().unwrap(),
                    )
                })
                .collect();
            assert_eq!(declared, parsed, "flags of {:?}", node.path);
            assert_eq!(
                entry["positionals"].as_array().unwrap().len(),
                node.args.len(),
                "positionals of {:?}",
                node.path
            );
        }
    }
}
