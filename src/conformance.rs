//! The `conformance` verb: the make-cli case set, run against this binary.
//!
//! The verb spawns this executable on argv that it generates from the
//! declared surface: the flag table (`flags::NODES`, `flags::GLOBALS`), the
//! published capabilities, and the code registry. No case instance is listed
//! by hand. Each instance gets one verdict: pass, fail, or not-applicable
//! with a reason from the closed set.
//!
//! The verb never spawns `rf conformance` with argv that the validator
//! accepts, because that child would run this sweep again without end.

use crate::capabilities;
use crate::envelope::{envelope, err};
use crate::flags::{self, Flag, Kind, Node};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const PROFILE: &str = if crate::fault::SEAM_PRESENT {
    "full-ci"
} else {
    "release-self-check"
};

/// The pinned verdict map of this build's profile (case X-04).
#[cfg(not(feature = "fault-injection"))]
const PIN: &str = include_str!("../tests/golden/conformance.verdicts.json");
#[cfg(feature = "fault-injection")]
const PIN: &str = include_str!("../tests/golden/conformance.verdicts.full-ci.json");

const UNAVAILABLE: &str = "release-build-fault-trigger-unavailable";
const NO_LADDER: &str = "no-name-on-ladder";
const REASONS: [&str; 4] = [
    UNAVAILABLE,
    "release-build-fault-trigger-disabled",
    "parser-manifest-not-published",
    NO_LADDER,
];

const SEVEN: [&str; 7] = [
    "ok",
    "tool_version",
    "data",
    "meta",
    "warnings",
    "commands",
    "errors",
];
const EIGHT: [&str; 8] = [
    "code",
    "message",
    "arg",
    "path",
    "remediation",
    "did_you_mean",
    "details",
    "exit_code",
];
const THREE: [&str; 3] = ["code", "message", "details"];

static NULL: Value = Value::Null;

type Verdict = Result<(), String>;

/// The case labels that this build records not-applicable, with the reason.
pub fn not_applicable_json() -> Value {
    let mut map = Map::new();
    if !crate::fault::SEAM_PRESENT {
        for label in ["S-01", "S-02", "X-02"] {
            map.insert(label.into(), Value::from(UNAVAILABLE));
        }
    }
    for number in 1..=11 {
        map.insert(format!("L-{number:02}"), Value::from(NO_LADDER));
    }
    Value::from(map)
}

/// One observed call of the rf binary.
struct Probe {
    exit: i32,
    doc: Option<Value>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Probe {
    fn doc(&self) -> &Value {
        self.doc.as_ref().unwrap_or(&NULL)
    }

    fn error(&self) -> &Value {
        &self.doc()["errors"][0]
    }

    fn code(&self) -> &str {
        self.error()["code"].as_str().unwrap_or("")
    }

    fn rid(&self) -> Option<String> {
        self.doc()["meta"]["request_id"].as_str().map(String::from)
    }

    fn seven(&self) -> bool {
        exact_keys(self.doc(), &SEVEN)
    }

    fn observed(&self) -> String {
        format!(
            "exit {}, ok {}, code {}",
            self.exit,
            self.doc()["ok"],
            self.error()["code"]
        )
    }

    /// The reply is a refusal with this exit and this first error code.
    fn refused(&self, exit: i32, code: &str) -> Verdict {
        if self.exit == exit && self.doc()["ok"] == false && self.code() == code {
            Ok(())
        } else {
            Err(format!("want exit {exit} {code}; got {}", self.observed()))
        }
    }

    /// The reply is a success envelope.
    fn succeeded(&self) -> Verdict {
        if self.exit == 0 && self.doc()["ok"] == true {
            Ok(())
        } else {
            Err(format!("want exit 0 ok true; got {}", self.observed()))
        }
    }
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)))
}

fn check(condition: bool, reason: impl FnOnce() -> String) -> Verdict {
    if condition {
        Ok(())
    } else {
        Err(reason())
    }
}

#[derive(Default)]
struct Call<'a> {
    args: Vec<OsString>,
    env: Vec<(&'a str, String)>,
    fault: Option<&'a str>,
    closed_stdout: bool,
}

fn call<'a>(args: &[String]) -> Call<'a> {
    Call {
        args: args.iter().map(OsString::from).collect(),
        ..Call::default()
    }
}

fn spawn(exe: &Path, call: &Call) -> Probe {
    let failed = || Probe {
        exit: -1,
        doc: None,
        stdout: vec![],
        stderr: vec![],
    };
    let mut cmd = Command::new(exe);
    cmd.args(&call.args)
        .env("NO_COLOR", "1")
        .env_remove("RF_FAULT")
        .stdin(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in &call.env {
        cmd.env(key, value);
    }
    if let Some(stage) = call.fault {
        cmd.env("RF_FAULT", stage);
    }
    if call.closed_stdout {
        // The read end closes before the child starts, so the first write
        // of the child meets a closed pipe.
        let Ok((reader, writer)) = std::io::pipe() else {
            return failed();
        };
        drop(reader);
        cmd.stdout(writer);
    } else {
        cmd.stdout(Stdio::piped());
    }
    match cmd.output() {
        Ok(output) => Probe {
            exit: output.status.code().unwrap_or(-1),
            doc: serde_json::from_slice(&output.stdout).ok(),
            stdout: output.stdout,
            stderr: output.stderr,
        },
        Err(_) => failed(),
    }
}

/// The composite instance id: the label, then the sorted `key=value`
/// segments, joined by `::`.
fn cid(label: &str, target: &[(&str, &str)]) -> String {
    let mut segments: Vec<String> = target.iter().map(|(k, v)| format!("{k}={v}")).collect();
    segments.sort();
    let mut id = String::from(label);
    for segment in segments {
        id.push_str("::");
        id.push_str(&segment);
    }
    id
}

/// A stable id for a case that has no single probe call.
fn synth_id(case_id: &str) -> String {
    let hex: String = Sha256::digest(case_id.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("req_{}", &hex[..16])
}

/// The files and directories that the probes read.
struct Fixtures {
    root: PathBuf,
    empty: String,
    file: String,
    locked: String,
    noread: String,
    nopath: String,
    missing: String,
    /// False when the process can read a mode 000 path (it runs as root).
    unreadable: bool,
}

impl Fixtures {
    fn create() -> Fixtures {
        let root = std::env::temp_dir().join(format!("rf-conformance-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let text = |name: &str| root.join(name).to_string_lossy().into_owned();
        let fixtures = Fixtures {
            empty: text("empty"),
            file: text("f.txt"),
            locked: text("locked.txt"),
            noread: text("noread"),
            nopath: text("nopath"),
            missing: text("missing"),
            unreadable: false,
            root,
        };
        for dir in [&fixtures.empty, &fixtures.noread, &fixtures.nopath] {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(&fixtures.file, "conformance fixture\n");
        let _ = std::fs::write(&fixtures.locked, "conformance fixture\n");
        let _ = std::fs::write(
            Path::new(&fixtures.noread).join("inner.txt"),
            "conformance fixture\n",
        );
        fixtures.set_modes(0o000, 0o000);
        let unreadable = std::fs::File::open(&fixtures.locked).is_err()
            && std::fs::read_dir(&fixtures.noread).is_err();
        Fixtures {
            unreadable,
            ..fixtures
        }
    }

    #[cfg(unix)]
    fn set_modes(&self, file: u32, dir: u32) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.locked, std::fs::Permissions::from_mode(file));
        let _ = std::fs::set_permissions(&self.noread, std::fs::Permissions::from_mode(dir));
    }

    #[cfg(not(unix))]
    fn set_modes(&self, _file: u32, _dir: u32) {}

    fn remove(&self) {
        self.set_modes(0o644, 0o755);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// How to build the argv of one verb. The default is the plain valid call.
#[derive(Default, Clone, Copy)]
struct Shape<'a> {
    /// A required flag to leave out, because the probe gives it another way.
    skip: Option<&'a str>,
    /// The value of each free-text positional.
    pattern: Option<&'a str>,
    /// One positional, by name, that gets this value.
    replace: Option<(&'a str, &'a str)>,
    /// Put `--` before the positionals.
    dashes: bool,
}

fn verb_key(node: &Node) -> String {
    node.path.join(".")
}

fn runnable() -> impl Iterator<Item = &'static Node> {
    flags::NODES.iter().filter(|n| n.subs.is_empty())
}

fn is_conformance(node: &Node) -> bool {
    node.path == ["conformance"]
}

/// A verb whose first positional is free text.
fn free_text(node: &Node) -> bool {
    node.args
        .first()
        .is_some_and(|a| a.kind == Kind::Str && !a.repeatable)
}

fn strings(tokens: &[&str]) -> Vec<String> {
    tokens.iter().map(|t| t.to_string()).collect()
}

fn joined(mut head: Vec<String>, tail: &[&str]) -> Vec<String> {
    head.extend(tail.iter().map(|t| t.to_string()));
    head
}

/// Each string that is one delete, one substitution, or one insert from
/// `name`. The first `keep` characters stay as they are.
fn edits(name: &str, keep: usize, alphabet: &BTreeSet<char>) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut out = Vec::new();
    let build = |parts: &[&[char]]| parts.iter().flat_map(|p| p.iter()).collect::<String>();
    for i in keep..chars.len() {
        out.push(build(&[&chars[..i], &chars[i + 1..]]));
    }
    for i in keep..chars.len() {
        for c in alphabet {
            out.push(build(&[&chars[..i], &[*c], &chars[i + 1..]]));
        }
    }
    for i in keep..=chars.len() {
        for c in alphabet {
            out.push(build(&[&chars[..i], &[*c], &chars[i..]]));
        }
    }
    out
}

fn near_names<'a>(token: &str, names: &[&'a str]) -> Vec<&'a str> {
    let mut hits: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| flags::near(token, n))
        .collect();
    hits.sort_unstable();
    hits.dedup();
    hits
}

/// A token one delete from `name` that is near no other name of `names`.
fn typo(name: &str, keep: usize, names: &[&str]) -> Option<String> {
    edits(name, keep, &BTreeSet::new())
        .into_iter()
        .find(|t| t.len() > keep && !names.contains(&t.as_str()) && near_names(t, names) == [name])
}

/// The longest proper prefix of `name` that is no declared name. `keep` is
/// the number of leading characters that are not part of the name.
fn prefix(name: &str, keep: usize, names: &[&str]) -> Option<String> {
    (keep + 1..name.len())
        .rev()
        .map(|end| name[..end].to_string())
        .find(|p| !names.contains(&p.as_str()))
}

/// For each pair of names, one undeclared token within the edit limit of
/// the two.
fn ambiguous(names: &[&str], keep: usize) -> BTreeMap<(String, String), String> {
    let alphabet: BTreeSet<char> = names.iter().flat_map(|n| n.chars().skip(keep)).collect();
    let mut out = BTreeMap::new();
    for name in names {
        for token in edits(name, keep, &alphabet) {
            if token.len() <= keep || names.contains(&token.as_str()) {
                continue;
            }
            let hits = near_names(&token, names);
            if hits.len() >= 2 {
                out.entry((hits[0].to_string(), hits[1].to_string()))
                    .or_insert(token);
            }
        }
    }
    out
}

/// Each declared spelling with the arity that its source enforces.
fn flag_arities(v: &Value) -> BTreeMap<String, i64> {
    v.get("flags")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .flat_map(|e| {
                    let arity = e.get("arity").and_then(Value::as_i64).unwrap_or(0);
                    std::iter::once(&e["name"])
                        .chain(e["aliases"].as_array().into_iter().flatten())
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .map(move |name| (name, arity))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The positional names of one node. The declared surface lists objects
/// under `args`; the parser manifest lists strings under `positionals`.
fn positional_names(v: &Value) -> BTreeSet<String> {
    let from_args = v.get("args").and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(|e| e.get("name").and_then(Value::as_str).map(String::from))
            .collect::<BTreeSet<String>>()
    });
    let from_pos = v.get("positionals").and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(|e| e.as_str().map(String::from))
            .collect::<BTreeSet<String>>()
    });
    from_args.or(from_pos).unwrap_or_default()
}

fn alias_names(v: &Value) -> BTreeSet<String> {
    v["aliases"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(String::from)
        .collect()
}

/// Put each node of the declared verb tree in `out`, keyed by its full path
/// (`robot-docs guide`).
fn flatten(prefix: &str, verbs: &Map<String, Value>, out: &mut Map<String, Value>) {
    for (name, entry) in verbs {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix} {name}")
        };
        if let Some(subs) = entry.get("subcommands").and_then(Value::as_object) {
            flatten(&path, subs, out);
        }
        out.insert(path, entry.clone());
    }
}

fn two_way<T: Ord + std::fmt::Debug>(what: &str, declared: &T, parsed: &T) -> Option<String> {
    (declared != parsed).then(|| format!("{what}: declared {declared:?}, parser {parsed:?}"))
}

/// The two-way difference between the declared surface and the parser
/// manifest, for each node. The root node is `rf`. An empty list is agreement.
fn surface_diff(
    hand: &Map<String, Value>,
    derived: &Map<String, Value>,
    hand_globals: &Value,
    derived_globals: &Value,
) -> BTreeMap<String, Vec<String>> {
    let mut flat = Map::new();
    flatten("", hand, &mut flat);
    let children = |keys: &mut dyn Iterator<Item = &String>, parent: &str| -> BTreeSet<String> {
        keys.filter_map(|k| {
            let rest = if parent.is_empty() {
                k.as_str()
            } else {
                k.strip_prefix(parent)?.strip_prefix(' ')?
            };
            (!rest.contains(' ')).then(|| rest.to_string())
        })
        .collect()
    };
    let globals = |list: &Value| {
        flag_arities(&Value::Object(
            [("flags".to_string(), list.clone())].into_iter().collect(),
        ))
    };
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let root: Vec<String> = [
        two_way(
            "verbs",
            &children(&mut flat.keys(), ""),
            &children(&mut derived.keys(), ""),
        ),
        two_way(
            "global flags",
            &globals(hand_globals),
            &globals(derived_globals),
        ),
    ]
    .into_iter()
    .flatten()
    .collect();
    out.insert("rf".into(), root);
    let nodes: BTreeSet<&String> = flat.keys().chain(derived.keys()).collect();
    for node in nodes {
        let faults: Vec<String> = match (flat.get(node), derived.get(node)) {
            (Some(declared), Some(parsed)) => [
                two_way("flags", &flag_arities(declared), &flag_arities(parsed)),
                two_way(
                    "positionals",
                    &positional_names(declared),
                    &positional_names(parsed),
                ),
                two_way("aliases", &alias_names(declared), &alias_names(parsed)),
                two_way(
                    "subcommands",
                    &children(&mut flat.keys(), node),
                    &children(&mut derived.keys(), node),
                ),
            ]
            .into_iter()
            .flatten()
            .collect(),
            (Some(_), None) => vec!["declared and not in the parser".into()],
            _ => vec!["in the parser and not declared".into()],
        };
        out.insert(node.replace(' ', "."), faults);
    }
    out
}

/// The X-07 rules on one declared schema.
fn schema_faults(schema: &Value, at: &str, faults: &mut Vec<String>) {
    if let Some(properties) = schema["properties"].as_object() {
        let required: BTreeSet<&str> = schema["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for (key, property) in properties {
            let here = format!("{at}.{key}");
            if !required.contains(key.as_str()) {
                faults.push(format!("{here}: declared and not required"));
            }
            if matches!(key.as_str(), "line" | "col" | "column_byte") && property["minimum"] != 1 {
                faults.push(format!("{here}: minimum is not 1"));
            }
            if matches!(key.as_str(), "index" | "offset") && property["minimum"] != 0 {
                faults.push(format!("{here}: minimum is not 0"));
            }
            schema_faults(property, &here, faults);
        }
    }
    for key in ["items", "additionalProperties"] {
        if schema[key].is_object() {
            schema_faults(&schema[key], &format!("{at}[]"), faults);
        }
    }
}

struct Sweep {
    exe: PathBuf,
    fx: Fixtures,
    caps: Value,
    rows: Vec<Value>,
    exits: BTreeSet<i32>,
    codes: BTreeSet<String>,
    warnings: BTreeSet<String>,
    /// Machine calls that wrote zero bytes on stdout (S-03).
    silent: usize,
    /// Machine calls whose exit and document do not agree (S-04).
    unpaired: usize,
    /// Labels with rows that this host cannot make.
    absent: BTreeSet<&'static str>,
}

impl Sweep {
    fn observe(&mut self, p: &Probe) {
        self.exits.insert(p.exit);
        let doc = p.doc();
        for error in doc["errors"].as_array().into_iter().flatten() {
            if let Some(code) = error["code"].as_str() {
                self.codes.insert(code.into());
            }
        }
        for warning in doc["warnings"].as_array().into_iter().flatten() {
            if let Some(code) = warning["code"].as_str() {
                self.warnings.insert(code.into());
            }
        }
        if p.stdout.is_empty() {
            self.silent += 1;
        }
        let ok = doc["ok"].as_bool();
        let paired = match ok {
            Some(true) => p.exit == 0,
            Some(false) => p.exit != 0 && p.error()["exit_code"] == p.exit,
            None => false,
        };
        if !paired {
            self.unpaired += 1;
        }
    }

    /// A machine call with full control of argv and environment.
    fn machine_call(&mut self, call: &Call) -> Probe {
        let p = spawn(&self.exe, call);
        if !call.closed_stdout {
            self.observe(&p);
        }
        p
    }

    /// A machine call: the selector goes first.
    fn machine(&mut self, args: &[String]) -> Probe {
        let mut argv = vec!["--json".to_string()];
        argv.extend_from_slice(args);
        self.machine_call(&call(&argv))
    }

    /// A human call: argv as written, no selector.
    fn human(&self, args: &[String]) -> Probe {
        spawn(&self.exe, &call(args))
    }

    fn push(&mut self, id: String, target: &[(&str, &str)], verdict: &str, reason: Value) {
        let mut row = Map::new();
        row.insert("request_id".into(), Value::from(synth_id(&id)));
        row.insert("case_id".into(), Value::from(id));
        row.insert("verdict".into(), Value::from(verdict));
        row.insert("reason".into(), reason);
        let mut object = Map::new();
        for (key, value) in target {
            object.insert((*key).into(), Value::from(*value));
        }
        row.insert("target".into(), Value::from(object));
        self.rows.push(Value::from(row));
    }

    fn row(&mut self, label: &str, target: &[(&str, &str)], verdict: Verdict, rid: Option<String>) {
        let (name, reason) = match verdict {
            Ok(()) => ("pass", Value::Null),
            Err(reason) => ("fail", Value::from(reason)),
        };
        self.push(cid(label, target), target, name, reason);
        if let (Some(rid), Some(row)) = (rid, self.rows.last_mut()) {
            row["request_id"] = Value::from(rid);
        }
    }

    fn not_applicable(&mut self, label: &str, target: &[(&str, &str)], reason: &str) {
        self.push(
            cid(label, target),
            target,
            "not_applicable",
            Value::from(reason),
        );
    }

    fn sample(&self, flag: &Flag) -> String {
        match flag.value {
            Some(Kind::Int) => "5".into(),
            Some(Kind::Path) => self.fx.empty.clone(),
            _ => flag.choices.first().copied().unwrap_or("conf").to_string(),
        }
    }

    /// `--flag=value` for a flag with a value, the bare name for a switch.
    fn written(&self, flag: &Flag) -> String {
        if flag.value.is_some() {
            format!("{}={}", flag.name, self.sample(flag))
        } else {
            flag.name.to_string()
        }
    }

    /// The flags that `flag` requires, each with a sample value.
    fn companions(&self, node: &Node, flag: &Flag) -> Vec<String> {
        flag.requires
            .iter()
            .filter_map(|name| node.flags.iter().find(|f| f.name == *name))
            .map(|f| self.written(f))
            .collect()
    }

    /// Valid argv of one verb: the path, each required flag, each positional.
    fn argv(&self, node: &Node, shape: Shape) -> Vec<String> {
        let mut out: Vec<String> = node.path.iter().map(|s| s.to_string()).collect();
        for flag in node.flags.iter().filter(|f| f.required) {
            if shape.skip != Some(flag.name) {
                out.push(self.written(flag));
            }
        }
        if shape.dashes {
            out.push("--".into());
        }
        for arg in node.args.iter().filter(|a| !a.repeatable) {
            let value = match shape.replace {
                Some((name, value)) if name == arg.name => value,
                _ => match arg.kind {
                    Kind::Path if arg.default.is_some() => self.fx.empty.as_str(),
                    Kind::Path => self.fx.file.as_str(),
                    _ => shape.pattern.unwrap_or("conf"),
                },
            };
            out.push(value.to_string());
        }
        out
    }

    fn base(&self, node: &Node) -> Vec<String> {
        self.argv(node, Shape::default())
    }

    /// A call of the verb that the validator refuses: it is safe for every
    /// verb, `conformance` included.
    fn refused_argv(&self, node: &Node) -> Vec<String> {
        joined(self.base(node), &["--zzqq"])
    }

    // --- group 1: argv boundaries --------------------------------------

    fn command_cases(&mut self) {
        let groups: Vec<Vec<&'static str>> = std::iter::once(Vec::new())
            .chain(
                flags::NODES
                    .iter()
                    .filter(|n| !n.subs.is_empty())
                    .map(|n| n.path.to_vec()),
            )
            .collect();
        for group in groups {
            let names: Vec<&str> = flags::NODES
                .iter()
                .filter(|n| n.path.len() == group.len() + 1 && n.path[..group.len()] == group[..])
                .map(|n| n.path[group.len()])
                .collect();
            let node_key = if group.is_empty() {
                "rf".to_string()
            } else {
                group.join(".")
            };
            let at = |token: &str| joined(strings(&group), &[token]);

            let p = self.machine(&at("zzqq"));
            self.row(
                "B-01",
                &[("node", &node_key)],
                p.refused(1, "UNKNOWN_COMMAND"),
                p.rid(),
            );

            for name in &names {
                let key = joined(strings(&group), &[name]).join(".");
                if let Some(token) = typo(name, 0, &names) {
                    let p = self.machine(&at(&token));
                    let verdict = p.refused(1, "UNKNOWN_COMMAND").and_then(|()| {
                        check(p.error()["did_you_mean"] == *name, || {
                            format!("did_you_mean is {}", p.error()["did_you_mean"])
                        })
                    });
                    self.row("B-02", &[("verb", &key)], verdict, p.rid());
                }
                if let Some(token) = prefix(name, 0, &names) {
                    let p = self.machine(&at(&token));
                    self.row(
                        "B-17",
                        &[("verb", &key)],
                        p.refused(1, "UNKNOWN_COMMAND"),
                        p.rid(),
                    );
                }
            }

            for ((first, second), token) in ambiguous(&names, 0) {
                let (a, b) = (
                    joined(strings(&group), &[&first]).join("."),
                    joined(strings(&group), &[&second]).join("."),
                );
                let verdict = self.ambiguous_verdict(&at(&token), "UNKNOWN_COMMAND");
                self.row("B-28", &[("verb", &a), ("peer", &b)], verdict, None);
            }
        }

        let p = self.machine(&strings(&["--zzqq", "zzqq"]));
        self.row("B-05", &[], p.refused(1, "UNKNOWN_FLAG"), p.rid());
    }

    /// B-28: the machine reply has a null hint, and the human reply has no
    /// corrected command line.
    fn ambiguous_verdict(&mut self, argv: &[String], code: &str) -> Verdict {
        let p = self.machine(argv);
        p.refused(1, code)?;
        check(p.error()["did_you_mean"].is_null(), || {
            format!("did_you_mean is {}", p.error()["did_you_mean"])
        })?;
        let human = self.human(argv);
        check(
            !String::from_utf8_lossy(&human.stderr).contains("corrected:"),
            || "stderr has a corrected line".into(),
        )
    }

    fn flag_name_cases(&mut self) {
        let global_names: Vec<&str> = flags::GLOBALS
            .iter()
            .flat_map(|f| std::iter::once(f.name).chain(f.alias))
            .collect();

        // Global flags, at the root node.
        for flag in flags::GLOBALS.iter().filter(|f| f.name.len() >= 6) {
            if let Some(token) = prefix(flag.name, 2, &global_names) {
                let p = self.machine(&strings(&[&token, "capabilities"]));
                self.row(
                    "B-16",
                    &[("node", "rf"), ("flag", flag.name)],
                    p.refused(1, "UNKNOWN_FLAG"),
                    p.rid(),
                );
            }
        }
        let long: Vec<&str> = global_names
            .iter()
            .copied()
            .filter(|n| n.starts_with("--"))
            .collect();
        let short: Vec<&str> = global_names
            .iter()
            .copied()
            .filter(|n| !n.starts_with("--"))
            .collect();
        for (names, keep) in [(long, 2), (short, 1)] {
            for ((first, second), token) in ambiguous(&names, keep) {
                let verdict =
                    self.ambiguous_verdict(&strings(&[&token, "capabilities"]), "UNKNOWN_FLAG");
                self.row(
                    "B-28",
                    &[("node", "rf"), ("flag", &first), ("peer", &second)],
                    verdict,
                    None,
                );
            }
        }

        for node in runnable() {
            let verb = verb_key(node);
            let base = self.base(node);

            let p = self.machine(&joined(base.clone(), &["--zzqq"]));
            self.row(
                "B-03",
                &[("verb", &verb)],
                p.refused(1, "UNKNOWN_FLAG"),
                p.rid(),
            );

            let mut before = vec!["--zzqq".to_string()];
            before.extend(base.clone());
            let p = self.machine(&before);
            self.row(
                "B-04",
                &[("verb", &verb)],
                p.refused(1, "UNKNOWN_FLAG"),
                p.rid(),
            );

            if let Some(arg) = node.args.iter().find(|a| a.must_exist) {
                let shape = Shape {
                    replace: Some((arg.name, &self.fx.missing)),
                    ..Shape::default()
                };
                let p = self.machine(&joined(self.argv(node, shape), &["--zzqq"]));
                self.row(
                    "B-06",
                    &[("verb", &verb)],
                    p.refused(1, "UNKNOWN_FLAG"),
                    p.rid(),
                );
            }

            let mut names: Vec<&str> = node.flags.iter().map(|f| f.name).collect();
            names.extend(long_globals());
            for flag in node.flags.iter().filter(|f| f.name.len() >= 6) {
                if let Some(token) = prefix(flag.name, 2, &names) {
                    let p = self.machine(&joined(base.clone(), &[&token]));
                    self.row(
                        "B-16",
                        &[("verb", &verb), ("flag", flag.name)],
                        p.refused(1, "UNKNOWN_FLAG"),
                        p.rid(),
                    );
                }
            }
            for ((first, second), token) in ambiguous(&names, 2) {
                let local = |name: &str| node.flags.iter().any(|f| f.name == name);
                if !local(&first) && !local(&second) {
                    continue;
                }
                let verdict =
                    self.ambiguous_verdict(&joined(base.clone(), &[&token]), "UNKNOWN_FLAG");
                self.row(
                    "B-28",
                    &[("verb", &verb), ("flag", &first), ("peer", &second)],
                    verdict,
                    None,
                );
            }

            let last_repeats = node.args.last().is_some_and(|a| a.repeatable);
            if !last_repeats {
                let p = self.machine(&joined(base.clone(), &["surplus"]));
                let verdict = p.refused(1, "INVALID_INPUT").and_then(|()| {
                    check(p.error()["arg"] == "surplus", || {
                        format!("arg is {}", p.error()["arg"])
                    })
                });
                self.row("B-19", &[("verb", &verb)], verdict, p.rid());
            }
        }
    }

    fn flag_value_cases(&mut self) {
        for node in runnable() {
            let verb = verb_key(node);
            for flag in node.flags {
                let target = [("verb", verb.as_str()), ("flag", flag.name)];
                let shape = Shape {
                    skip: Some(flag.name),
                    ..Shape::default()
                };
                let base = self.argv(node, shape);
                let with = |tail: &[&str]| joined(base.clone(), tail);
                let arg_is_flag = |p: &Probe| {
                    check(p.error()["arg"] == flag.name, || {
                        format!("arg is {}", p.error()["arg"])
                    })
                };

                if flag.value.is_some() {
                    let p = self.machine(&with(&[flag.name]));
                    let verdict = p
                        .refused(1, "MISSING_REQUIRED")
                        .and_then(|()| arg_is_flag(&p));
                    self.row("B-07", &target, verdict, p.rid());

                    let other = node
                        .flags
                        .iter()
                        .find(|f| f.value.is_none() && f.name != flag.name)
                        .map(|f| f.name)
                        .unwrap_or("--no-color");
                    let p = self.machine(&with(&[flag.name, other]));
                    self.row("B-08", &target, p.refused(1, "MISSING_REQUIRED"), p.rid());

                    let p = self.machine(&with(&[flag.name, "--zzqq"]));
                    self.row("B-09", &target, p.refused(1, "UNKNOWN_FLAG"), p.rid());

                    if !flag.allow_empty {
                        let attached = format!("{}=", flag.name);
                        let p = self.machine(&with(&[&attached]));
                        let q = self.machine(&with(&[flag.name, ""]));
                        let verdict = p
                            .refused(1, "INVALID_INPUT")
                            .and_then(|()| q.refused(1, "INVALID_INPUT"));
                        self.row("B-10", &target, verdict, p.rid());
                    }

                    // The selector is the token after the flag, not the first.
                    let p = self.machine_call(&call(&with(&[flag.name, "--json"])));
                    self.row("M-05", &target, p.refused(1, "MISSING_REQUIRED"), p.rid());
                }

                if flag.pattern.is_some() {
                    let attached = format!("{}=-x", flag.name);
                    let p = self.machine(&with(&[&attached]));
                    self.row("B-11", &target, p.refused(1, "INVALID_INPUT"), p.rid());
                }

                if let Some((choice, token)) = flag.choices.iter().find_map(|choice| {
                    let token = format!("{choice}x");
                    (near_names(&token, flag.choices) == [*choice]).then_some((*choice, token))
                }) {
                    let mut argv = with(&[&format!("{}={token}", flag.name)]);
                    argv.extend(self.companions(node, flag));
                    let p = self.machine(&argv);
                    let verdict = p.refused(1, "INVALID_INPUT").and_then(|()| {
                        check(p.error()["did_you_mean"] == choice, || {
                            format!("did_you_mean is {}", p.error()["did_you_mean"])
                        })
                    });
                    self.row("B-12", &target, verdict, p.rid());
                }

                if flag.value == Some(Kind::Int) {
                    let companions = self.companions(node, flag);
                    let mut verdict = Ok(());
                    let mut rid = None;
                    for (value, accepted) in [
                        ("0x10", false),
                        ("1e2", false),
                        ("1_000", false),
                        ("010", true),
                    ] {
                        let mut argv = with(&[&format!("{}={value}", flag.name)]);
                        argv.extend(companions.clone());
                        let p = self.machine(&argv);
                        let one = if accepted {
                            p.succeeded()
                        } else {
                            p.refused(1, "INVALID_INPUT")
                        };
                        verdict = verdict.and(one.map_err(|e| format!("{value}: {e}")));
                        rid = p.rid();
                    }
                    self.row("B-18", &target, verdict, rid);
                }

                for peer in flag.conflicts_with.iter().filter(|p| flag.name < **p) {
                    let p = self.machine(&with(&[flag.name, peer]));
                    let q = self.machine(&with(&[peer, flag.name]));
                    let names_both = |p: &Probe| {
                        let message = p.error()["message"].as_str().unwrap_or("");
                        check(
                            message.contains(flag.name) && message.contains(peer),
                            || format!("message does not name the two flags: {message}"),
                        )
                    };
                    let verdict = p
                        .refused(1, "INVALID_INPUT")
                        .and_then(|()| names_both(&p))
                        .and_then(|()| q.refused(1, "INVALID_INPUT"))
                        .and_then(|()| names_both(&q));
                    self.row(
                        "B-20",
                        &[("verb", &verb), ("flag", flag.name), ("peer", peer)],
                        verdict,
                        p.rid(),
                    );
                }

                if !flag.requires.is_empty() {
                    let p = self.machine(&with(&[&self.written(flag)]));
                    let verdict = p
                        .refused(1, "MISSING_REQUIRED")
                        .and_then(|()| arg_is_flag(&p))
                        .and_then(|()| {
                            let message = p.error()["message"].as_str().unwrap_or("");
                            check(flag.requires.iter().any(|c| message.contains(c)), || {
                                format!("message names no companion: {message}")
                            })
                        });
                    self.row("B-27", &target, verdict, p.rid());
                }
            }
        }
    }

    fn path_cases(&mut self) {
        for node in runnable() {
            let verb = verb_key(node);
            for arg in node.args.iter().filter(|a| a.must_exist) {
                let target = [("verb", verb.as_str()), ("arg", arg.name)];
                let with = |value: &str| {
                    self.argv(
                        node,
                        Shape {
                            replace: Some((arg.name, value)),
                            ..Shape::default()
                        },
                    )
                };
                let missing = with(&self.fx.missing);
                let unreadable = with(if arg.default.is_some() {
                    &self.fx.noread
                } else {
                    &self.fx.locked
                });
                self.path_rows(&target, arg.name, &missing, &unreadable);
            }
            for flag in node.flags.iter().filter(|f| f.must_exist) {
                let target = [("verb", verb.as_str()), ("flag", flag.name)];
                let with =
                    |value: &str| joined(self.base(node), &[&format!("{}={value}", flag.name)]);
                // A file that the verb reads must be in the unreadable root.
                let inner = Path::new(&self.fx.noread).join("inner.txt");
                let inner = inner.to_string_lossy();
                let mut unreadable = with(&self.fx.noread);
                if let Some(arg) = node
                    .args
                    .iter()
                    .find(|a| a.must_exist && a.default.is_none())
                {
                    let shape = Shape {
                        replace: Some((arg.name, &inner)),
                        ..Shape::default()
                    };
                    unreadable = joined(
                        self.argv(node, shape),
                        &[&format!("{}={}", flag.name, self.fx.noread)],
                    );
                }
                let missing = with(&self.fx.missing);
                self.path_rows(&target, flag.name, &missing, &unreadable);
            }
        }
    }

    fn path_rows(
        &mut self,
        target: &[(&str, &str)],
        name: &str,
        missing: &[String],
        unreadable: &[String],
    ) {
        let p = self.machine(missing);
        let verdict = p.refused(1, "NOT_FOUND").and_then(|()| {
            check(p.error()["arg"] == name, || {
                format!("arg is {}", p.error()["arg"])
            })
        });
        self.row("B-23", target, verdict, p.rid());

        if !self.fx.unreadable {
            self.absent.insert("B-24");
            return;
        }
        let p = self.machine(unreadable);
        let verdict = p.refused(3, "IO_FAILURE").and_then(|()| {
            let details = &p.error()["details"];
            check(
                ["op", "file", "os_error"]
                    .iter()
                    .all(|k| details[*k].is_string()),
                || format!("details is {details}"),
            )
        });
        self.row("B-24", target, verdict, p.rid());
    }

    fn data_cases(&mut self) {
        for node in runnable().filter(|n| free_text(n)) {
            let verb = verb_key(node);
            let target = [("verb", verb.as_str())];
            let as_data = |token| Shape {
                pattern: Some(token),
                dashes: true,
                ..Shape::default()
            };

            let p = self.machine(&self.argv(node, as_data("--json")));
            self.row("B-13", &target, p.succeeded(), p.rid());

            let p = self.human(&self.argv(node, as_data("--json")));
            let verdict = check(
                p.exit == 0 && p.doc.is_none() && !p.stdout.is_empty(),
                || format!("exit {}, stdout is JSON: {}", p.exit, p.doc.is_some()),
            );
            self.row("M-04", &target, verdict, None);

            let p = self.machine(&self.argv(node, as_data("--help")));
            let verdict = p.succeeded().and_then(|()| {
                check(p.doc()["data"].get("usage").is_none(), || {
                    "the reply is the help surface".into()
                })
            });
            self.row("H-04", &target, verdict, p.rid());
        }
    }

    #[cfg(unix)]
    fn byte_cases(&mut self) {
        use std::os::unix::ffi::OsStringExt;
        let bad = || OsString::from_vec(vec![0xff]);

        let p = self.machine_call(&Call {
            args: vec![OsString::from("--json"), bad()],
            ..Call::default()
        });
        let verdict = p.refused(1, "UNKNOWN_COMMAND").and_then(|()| {
            check(p.error()["details"]["bytes_hex"] == "ff", || {
                format!("details is {}", p.error()["details"])
            })
        });
        self.row("B-14", &[], verdict, p.rid());

        let p = self.machine_call(&Call {
            args: vec![bad(), OsString::from("--json")],
            ..Call::default()
        });
        let verdict = check(p.seven() && p.doc()["ok"] == false && p.exit == 1, || {
            format!("no failure envelope: {}", p.observed())
        });
        self.row("M-08", &[], verdict, p.rid());
    }

    #[cfg(not(unix))]
    fn byte_cases(&mut self) {
        self.absent.insert("B-14");
        self.absent.insert("M-08");
    }

    fn fixture_cases(&mut self) {
        let empty_path = vec![("PATH", self.fx.nopath.clone())];

        // B-29: one instance for each verb and each rendering.
        for node in runnable() {
            let verb = verb_key(node);
            let argv = if is_conformance(node) {
                self.refused_argv(node)
            } else {
                self.base(node)
            };
            let mut machine = vec!["--json".to_string()];
            machine.extend(argv.clone());
            let shapes: &[(&str, &Vec<String>)] = if is_conformance(node) {
                // The human refusal writes nothing on stdout.
                &[("envelope", &machine)]
            } else {
                &[("envelope", &machine), ("human", &argv)]
            };
            for (shape, argv) in shapes {
                let p = spawn(
                    &self.exe,
                    &Call {
                        closed_stdout: true,
                        ..call(argv)
                    },
                );
                let verdict = check(p.exit == 141 && !contains(&p.stderr, "panicked"), || {
                    format!("exit {}", p.exit)
                });
                self.row("B-29", &[("verb", &verb), ("shape", shape)], verdict, None);
            }
        }

        // B-32 and B-36 fold over the registry: the verbs of each code's sites.
        for site in sites("COMPONENT_DEGRADED") {
            let Some(node) = runnable().find(|n| verb_key(n) == site) else {
                continue;
            };
            let mut argv = vec!["--json".to_string()];
            argv.extend(self.base(node));
            let p = self.machine_call(&Call {
                env: empty_path.clone(),
                ..call(&argv)
            });
            let verdict = p.refused(6, "COMPONENT_DEGRADED").and_then(|()| {
                check(
                    p.doc()["data"]["overall"] == "degraded"
                        && !p.doc()["warnings"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .any(|w| w["code"] == "DEGRADED_TIER"),
                    || format!("data.overall is {}", p.doc()["data"]["overall"]),
                )
            });
            self.row("B-32", &[("verb", &site)], verdict, p.rid());
        }
        for site in sites("DEPENDENCY_MISSING") {
            let Some(node) = runnable().find(|n| verb_key(n) == site) else {
                continue;
            };
            // The flags of the verb that start another program: each flag
            // that needs a companion and carries free text.
            for flag in node.flags.iter().filter(|f| {
                !f.requires.is_empty() && f.value == Some(Kind::Str) && f.choices.is_empty()
            }) {
                let mut argv = vec!["--json".to_string()];
                argv.extend(self.base(node));
                argv.push(self.written(flag));
                argv.extend(self.companions(node, flag));
                let p = self.machine_call(&Call {
                    env: empty_path.clone(),
                    ..call(&argv)
                });
                let verdict = p.refused(3, "DEPENDENCY_MISSING").and_then(|()| {
                    check(
                        p.error()["details"]["program"].is_string()
                            && !p.error()["remediation"].is_null(),
                        || format!("details is {}", p.error()["details"]),
                    )
                });
                self.row(
                    "B-36",
                    &[("verb", &site), ("flag", flag.name)],
                    verdict,
                    p.rid(),
                );
            }
        }
    }

    // --- group 2: rendering ---------------------------------------------

    fn rendering_cases(&mut self) {
        for node in runnable() {
            let verb = verb_key(node);
            let refused = self.refused_argv(node);

            let p = self.machine(&refused);
            let mut verdict = check(
                p.seven()
                    && p.doc()["errors"]
                        .as_array()
                        .is_some_and(|a| !a.is_empty() && a.iter().all(|e| exact_keys(e, &EIGHT))),
                || format!("failure envelope keys are wrong: {}", p.observed()),
            );
            if !is_conformance(node) {
                let q = self.machine(&self.base(node));
                verdict = verdict.and(check(
                    q.seven()
                        && q.doc()["warnings"]
                            .as_array()
                            .is_some_and(|a| a.iter().all(|w| exact_keys(w, &THREE)))
                        && q.doc()["errors"]
                            .as_array()
                            .is_some_and(|a| a.iter().all(|e| exact_keys(e, &EIGHT))),
                    || format!("envelope keys are wrong: {}", q.observed()),
                ));
            }
            self.row(
                "M-01",
                &[("verb", &verb), ("shape", "envelope")],
                verdict,
                p.rid(),
            );

            let p = self.human(&refused);
            let mut verdict = check(
                p.stdout.is_empty() && !p.stderr.is_empty() && p.exit != 0,
                || {
                    format!(
                        "human refusal: exit {}, {} stdout byte(s)",
                        p.exit,
                        p.stdout.len()
                    )
                },
            );
            if !is_conformance(node) {
                let q = self.human(&self.base(node));
                verdict = verdict.and(check(q.doc.is_none() && !q.stdout.is_empty(), || {
                    "human stdout is JSON or empty".into()
                }));
            }
            self.row("M-02", &[("verb", &verb)], verdict, None);
        }

        for spelling in ["--json=false", "--json=1", "--json="] {
            let p = self.machine_call(&call(&strings(&[spelling, "capabilities"])));
            let verdict = p
                .refused(1, "INVALID_INPUT")
                .and(check(p.seven(), || "no envelope".into()));
            self.row("M-03", &[("flag", spelling)], verdict, p.rid());
        }
    }

    // --- group 3: totality ----------------------------------------------

    fn totality_cases(&mut self) {
        let Some(find) = runnable().find(|n| n.flags.iter().any(|f| f.required)) else {
            return;
        };
        let happy = self.base(find);
        let mut machine = vec!["--json".to_string()];
        machine.extend(happy);
        for stage in crate::fault::STAGES {
            let target = [("stage", stage)];
            if !crate::fault::SEAM_PRESENT {
                self.not_applicable("S-01", &target, UNAVAILABLE);
                self.not_applicable("X-02", &target, UNAVAILABLE);
                continue;
            }
            let p = self.machine_call(&Call {
                fault: Some(stage),
                ..call(&machine)
            });
            let total = p
                .refused(crate::registry::INTERNAL_EXIT, "INTERNAL")
                .and(check(p.seven(), || "no envelope".into()))
                .and(check(!p.stderr.is_empty(), || "stderr is empty".into()));
            self.row("S-01", &target, total, p.rid());

            let quiet = self.machine_call(&call(&machine));
            let fires = check(
                p.exit == crate::registry::INTERNAL_EXIT && quiet.exit == 0,
                || format!("exit {} with the fault, {} without", p.exit, quiet.exit),
            );
            self.row("X-02", &target, fires, p.rid());
        }

        let target = [("stage", crate::fault::STAGES[0])];
        if crate::fault::SEAM_PRESENT {
            let p = self.machine_call(&Call {
                fault: Some(crate::fault::STAGES[0]),
                ..call(&strings(&["--json", "capabilities"]))
            });
            let verdict = p
                .refused(crate::registry::INTERNAL_EXIT, "INTERNAL")
                .and(check(p.seven(), || "no envelope".into()));
            self.row("S-02", &target, verdict, p.rid());
        } else {
            self.not_applicable("S-02", &target, UNAVAILABLE);
            // X-03: the seam is compiled out, no test-only variable is
            // declared, and a set trigger changes nothing.
            let declared = self.caps["env_vars"]
                .as_object()
                .is_some_and(|vars| vars.values().any(|v| v["test_only"] == true));
            let p = self.machine_call(&Call {
                fault: Some(crate::fault::STAGES[0]),
                ..call(&strings(&["--json", "capabilities"]))
            });
            let verdict =
                check(!declared, || "a test-only variable is declared".into()).and(p.succeeded());
            self.row("X-03", &[], verdict, p.rid());
        }
    }

    // --- group 4: help surfaces -----------------------------------------

    fn help_cases(&mut self) {
        let text = |p: &Probe| String::from_utf8_lossy(&p.stdout).into_owned();
        let quiet = |p: &Probe| {
            check(
                p.exit == 0 && !p.stdout.is_empty() && p.doc.is_none() && p.stderr.is_empty(),
                || format!("exit {}, {} stderr byte(s)", p.exit, p.stderr.len()),
            )
        };

        let bare = self.human(&[]);
        self.row("H-01", &[], quiet(&bare), None);
        let help = self.human(&strings(&["--help"]));
        self.row("H-02", &[("flag", "--help")], quiet(&help), None);
        let version = self.human(&strings(&["--version"]));
        self.row("H-02", &[("flag", "--version")], quiet(&version), None);

        for (surface, argv, floor) in [
            ("bare", vec![], ["usage", "default_action"]),
            ("help", vec!["--help"], ["usage", "capabilities_command"]),
            ("version", vec!["--version"], ["contract_version", "build"]),
        ] {
            let p = self.machine(&strings(&argv));
            let verdict = p.succeeded().and_then(|()| {
                check(
                    p.seven() && floor.iter().all(|k| p.doc()["data"].get(*k).is_some()),
                    || format!("data is {}", p.doc()["data"]),
                )
            });
            self.row("H-03", &[("surface", surface)], verdict, p.rid());
        }

        let paths: Vec<Vec<&str>> = std::iter::once(Vec::new())
            .chain(flags::NODES.iter().map(|n| n.path.to_vec()))
            .collect();
        for path in paths {
            let node_key = if path.is_empty() {
                "rf".to_string()
            } else {
                path.join(".")
            };
            let want = self.human(&joined(strings(&path), &["--help"]));
            let mut verdict = quiet(&want);
            let mut spellings = vec![joined(strings(&path), &["-h"])];
            let mut by_verb = vec!["help".to_string()];
            by_verb.extend(strings(&path));
            spellings.push(by_verb);
            for argv in spellings {
                let got = self.human(&argv);
                verdict = verdict.and(check(got.exit == 0 && got.stdout == want.stdout, || {
                    format!("`{}` differs from --help", argv.join(" "))
                }));
            }
            self.row("H-05", &[("node", &node_key)], verdict, None);
        }

        let short = self.human(&strings(&["-V"]));
        let declared = self.caps["tool_version"].as_str().unwrap_or("");
        let one_line = |p: &Probe| text(p).trim_end_matches('\n') == declared;
        self.row(
            "H-06",
            &[],
            check(one_line(&version) && one_line(&short), || {
                format!("--version prints {:?}", text(&version))
            }),
            None,
        );

        let broken = vec![
            ("PATH", self.fx.nopath.clone()),
            ("HOME", self.fx.missing.clone()),
            ("XDG_CONFIG_HOME", self.fx.missing.clone()),
        ];
        let mut verdict = Ok(());
        for (flag, want) in [("--help", &help), ("--version", &version)] {
            let got = spawn(
                &self.exe,
                &Call {
                    env: broken.clone(),
                    ..call(&strings(&[flag]))
                },
            );
            verdict = verdict.and(check(got.exit == 0 && got.stdout == want.stdout, || {
                format!("{flag} differs in a broken environment")
            }));
        }
        self.row("H-07", &[], verdict, None);
    }

    // --- group 5: the contract as a whole -------------------------------

    fn contract_cases(&mut self) {
        let caps = self.caps.clone();

        match (
            caps["verbs"].as_object(),
            caps["parser_manifest"]["commands"].as_object(),
        ) {
            (Some(hand), Some(derived)) => {
                let diff = surface_diff(
                    hand,
                    derived,
                    &caps["global_flags"],
                    &caps["parser_manifest"]["global_flags"],
                );
                for (node, faults) in diff {
                    let verdict = check(faults.is_empty(), || faults.join("; "));
                    self.row("X-01", &[("node", &node)], verdict, None);
                }
            }
            _ => self.not_applicable("X-01", &[], "parser-manifest-not-published"),
        }

        // X-06: each observed code is declared, and each declared code says
        // how to reproduce it.
        let declared_exits: BTreeSet<i32> = crate::registry::EXITS
            .iter()
            .map(|(code, _, _)| *code)
            .collect();
        let mut faults: Vec<String> = Vec::new();
        for exit in self.exits.difference(&declared_exits) {
            faults.push(format!("exit {exit} is not declared"));
        }
        for code in self.codes.iter().chain(&self.warnings) {
            if caps["error_codes"].get(code).is_none() {
                faults.push(format!("{code} is not declared"));
            }
        }
        for (code, entry) in caps["error_codes"].as_object().into_iter().flatten() {
            let reproduced = ["example_invocation", "fixture", "precondition"]
                .iter()
                .any(|key| entry[*key].is_string());
            if !reproduced {
                faults.push(format!("{code} has no reproduction and no precondition"));
            }
        }
        self.row(
            "X-06",
            &[],
            check(faults.is_empty(), || faults.join("; ")),
            None,
        );

        // X-07 and X-08 fold over each declared verb node.
        let mut flat = Map::new();
        if let Some(verbs) = caps["verbs"].as_object() {
            flatten("", verbs, &mut flat);
        }
        let group_names: Vec<&str> = flat
            .iter()
            .filter(|(_, entry)| entry.get("subcommands").is_some())
            .filter_map(|(path, _)| path.rsplit(' ').next())
            .collect();
        for (path, entry) in &flat {
            let verb = path.replace(' ', ".");
            if entry["output_schema"].is_object() {
                let mut faults = Vec::new();
                schema_faults(&entry["output_schema"], "$", &mut faults);
                self.row(
                    "X-07",
                    &[("verb", &verb)],
                    check(faults.is_empty(), || faults.join("; ")),
                    None,
                );
            }
            if !group_names.is_empty() {
                let name = path.rsplit(' ').next().unwrap_or("");
                let words: Vec<&str> = name.split('-').collect();
                let clash = group_names.iter().find(|group| {
                    **group != name
                        && (words.first() == Some(*group) || words.last() == Some(*group))
                });
                self.row(
                    "X-08",
                    &[("verb", &verb)],
                    check(clash.is_none(), || {
                        format!(
                            "{name} has the group name {} at one end",
                            clash.unwrap_or(&"")
                        )
                    }),
                    None,
                );
            }
        }

        // The deprecation ladder. rf declares no name on it.
        let ladder = [
            "\"deprecated\"",
            "\"removed\"",
            "\"default_changes_in\"",
            "\"default_changed_in\"",
            "\"exit_code_changes\"",
        ];
        let text = caps.to_string();
        let on_ladder = ladder.iter().any(|key| text.contains(key));
        for number in 1..=11 {
            let label = format!("L-{number:02}");
            if on_ladder {
                self.row(
                    &label,
                    &[],
                    Err("a ladder entry is declared and this case has no generator".into()),
                    None,
                );
            } else {
                self.not_applicable(&label, &[], NO_LADDER);
            }
        }
        let deprecated = self.warnings.contains("DEPRECATED");
        self.row(
            "L-12",
            &[],
            check(!deprecated, || "a call gave a DEPRECATED warning".into()),
            None,
        );

        self.row(
            "S-03",
            &[],
            check(self.silent == 0, || {
                format!("{} machine call(s) wrote zero bytes on stdout", self.silent)
            }),
            None,
        );
        self.row(
            "S-04",
            &[],
            check(self.unpaired == 0, || {
                format!(
                    "{} machine call(s) have an exit that does not match the document",
                    self.unpaired
                )
            }),
            None,
        );
    }

    /// X-05, on the rows of this sweep. The exit and the error list are
    /// derived from the same rows, in `run`.
    fn self_check(&mut self) {
        let mut faults: Vec<String> = Vec::new();
        let mut seen = BTreeSet::new();
        for row in &self.rows {
            let id = row["case_id"].as_str().unwrap_or("");
            let floor = ["case_id", "verdict", "reason", "request_id", "target"];
            if !exact_keys(row, &floor) || !row["target"].is_object() {
                faults.push(format!("{id}: row floor"));
            }
            let label = id.split("::").next().unwrap_or("");
            let pairs: Vec<(&str, &str)> = row["target"]
                .as_object()
                .into_iter()
                .flatten()
                .filter_map(|(k, v)| Some((k.as_str(), v.as_str()?)))
                .collect();
            if cid(label, &pairs) != id {
                faults.push(format!("{id}: target does not give the case id"));
            }
            if !seen.insert(id) {
                faults.push(format!("{id}: more than one row"));
            }
            let reason = row["reason"].as_str();
            match row["verdict"].as_str() {
                Some("not_applicable") if reason.is_some_and(|r| REASONS.contains(&r)) => {}
                Some("pass") if reason.is_none() => {}
                Some("fail") => {}
                _ => faults.push(format!("{id}: verdict and reason do not agree")),
            }
        }
        if PROFILE.is_empty() || self.caps["verbs"]["conformance"]["profile"] != PROFILE {
            faults.push("the profile is not named".into());
        }
        self.row(
            "X-05",
            &[],
            check(faults.is_empty(), || faults.join("; ")),
            None,
        );
    }

    /// X-04: the verdict map, less this row, equals the pin of the profile.
    fn pin_check(&mut self) {
        let project = |rows: &[Value]| -> BTreeMap<String, (String, Value)> {
            rows.iter()
                .filter_map(|row| {
                    let id = row["case_id"].as_str()?;
                    let label = id.split("::").next().unwrap_or("");
                    (label != "X-04" && !self.absent.contains(label)).then(|| {
                        (
                            id.to_string(),
                            (
                                row["verdict"].as_str().unwrap_or("").to_string(),
                                row["reason"].clone(),
                            ),
                        )
                    })
                })
                .collect()
        };
        let pin: Value = serde_json::from_str(PIN).unwrap_or(Value::Null);
        let want = project(pin["cases"].as_array().map(Vec::as_slice).unwrap_or(&[]));
        let got = project(&self.rows);
        let mut faults: Vec<String> = Vec::new();
        for (id, (verdict, _)) in &got {
            match want.get(id) {
                None => faults.push(format!("{id}: not in the pin")),
                Some((pinned, _)) if pinned != verdict => {
                    faults.push(format!("{id}: {pinned} in the pin, {verdict} now"))
                }
                Some((_, reason)) if *reason != got[id].1 => {
                    faults.push(format!("{id}: the reason changed"))
                }
                _ => {}
            }
        }
        for id in want.keys().filter(|id| !got.contains_key(*id)) {
            faults.push(format!("{id}: in the pin, not in the sweep"));
        }
        let verdict = check(pin["profile"] == PROFILE, || {
            "the pin is for a different profile".into()
        })
        .and(check(faults.is_empty(), || {
            let shown: Vec<&str> = faults.iter().take(8).map(String::as_str).collect();
            format!("{} difference(s): {}", faults.len(), shown.join("; "))
        }));
        self.row("X-04", &[("profile", PROFILE)], verdict, None);
    }

    fn sort(&mut self) {
        self.rows
            .sort_by(|a, b| a["case_id"].as_str().cmp(&b["case_id"].as_str()));
    }
}

fn long_globals() -> impl Iterator<Item = &'static str> {
    flags::GLOBALS.iter().map(|f| f.name)
}

fn contains(bytes: &[u8], text: &str) -> bool {
    String::from_utf8_lossy(bytes).contains(text)
}

/// The verbs that the registry names as the sites of one code.
fn sites(code: &str) -> Vec<String> {
    crate::registry::lookup(code)
        .map(|entry| entry.sites.iter().map(|s| s.replace(' ', ".")).collect())
        .unwrap_or_default()
}

pub fn run() -> (Value, i32) {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rf"));
    let mut sweep = Sweep {
        exe,
        fx: Fixtures::create(),
        caps: capabilities::build(),
        rows: vec![],
        exits: BTreeSet::new(),
        codes: BTreeSet::new(),
        warnings: BTreeSet::new(),
        silent: 0,
        unpaired: 0,
        absent: BTreeSet::new(),
    };
    sweep.command_cases();
    sweep.flag_name_cases();
    sweep.flag_value_cases();
    sweep.path_cases();
    sweep.data_cases();
    sweep.byte_cases();
    sweep.fixture_cases();
    sweep.rendering_cases();
    sweep.totality_cases();
    sweep.help_cases();
    sweep.contract_cases();
    sweep.fx.remove();
    sweep.sort();
    sweep.self_check();
    sweep.sort();
    sweep.pin_check();
    sweep.sort();

    let count = |verdict: &str| {
        sweep
            .rows
            .iter()
            .filter(|row| row["verdict"] == verdict)
            .count()
    };
    let (pass, fail, na) = (count("pass"), count("fail"), count("not_applicable"));
    // One error for each failed case. The rows are in case id order.
    let errors: Vec<Value> = sweep
        .rows
        .iter()
        .filter(|row| row["verdict"] == "fail")
        .map(|row| {
            let id = row["case_id"].as_str().unwrap_or("");
            let mut error = err(
                "CASE_FAILED",
                format!("{id}: {}", row["reason"].as_str().unwrap_or("")),
            );
            error["details"] = serde_json::json!({"case_id": id});
            error
        })
        .collect();

    let mut counts = Map::new();
    counts.insert("pass".into(), Value::from(pass));
    counts.insert("fail".into(), Value::from(fail));
    counts.insert("not_applicable".into(), Value::from(na));
    let mut payload = Map::new();
    payload.insert("profile".into(), Value::from(PROFILE));
    payload.insert("counts".into(), Value::from(counts));
    payload.insert("cases".into(), Value::from(sweep.rows));

    let mut meta = Map::new();
    meta.insert("verb".into(), Value::from("conformance"));
    meta.insert("profile".into(), Value::from(PROFILE));
    meta.insert(
        "headline".into(),
        Value::from(format!("{pass} pass, {fail} fail, {na} n/a")),
    );
    let ok = errors.is_empty();
    (
        envelope(ok, Value::from(payload), meta, vec![], vec![], errors),
        if ok { 0 } else { 6 },
    )
}

#[cfg(test)]
mod reconciliation_tests {
    use super::*;

    fn agree(diff: &BTreeMap<String, Vec<String>>) -> bool {
        diff.values().all(Vec::is_empty)
    }

    #[test]
    fn x01_rejects_one_sided_command_drift() {
        let caps = capabilities::build();
        let hand = caps["verbs"].as_object().unwrap().clone();
        let manifest = caps["parser_manifest"].clone();
        let derived = manifest["commands"].as_object().unwrap().clone();
        let globals = caps["global_flags"].clone();
        let derived_globals = manifest["global_flags"].clone();
        let diff = surface_diff(&hand, &derived, &globals, &derived_globals);
        assert!(agree(&diff), "{diff:?}");
        assert!(diff.contains_key("rf") && diff.contains_key("robot-docs.guide"));

        let mut parser_only = derived.clone();
        parser_only.insert("parser-only".into(), Value::Object(Map::new()));
        let diff = surface_diff(&hand, &parser_only, &globals, &derived_globals);
        assert!(!diff["rf"].is_empty() && !diff["parser-only"].is_empty());

        let mut capabilities_only = hand.clone();
        capabilities_only.insert("capabilities-only".into(), Value::Object(Map::new()));
        let diff = surface_diff(&capabilities_only, &derived, &globals, &derived_globals);
        assert!(!diff["rf"].is_empty() && !diff["capabilities-only"].is_empty());
    }

    #[test]
    fn x01_rejects_alias_and_arity_drift() {
        let caps = capabilities::build();
        let hand = caps["verbs"].as_object().unwrap().clone();
        let manifest = caps["parser_manifest"].clone();
        let globals = caps["global_flags"].clone();
        let derived_globals = manifest["global_flags"].clone();
        let mut derived = manifest["commands"].as_object().unwrap().clone();
        derived["content"]["aliases"] = serde_json::json!(["grep"]);
        derived["find"]["flags"][0]["arity"] = serde_json::json!(7);
        let diff = surface_diff(&hand, &derived, &globals, &derived_globals);
        assert!(!diff["content"].is_empty() && !diff["find"].is_empty());
        assert!(diff["doctor"].is_empty());
    }

    #[test]
    fn manifest_and_flag_table_agree_on_global_names() {
        let manifest = crate::manifest::build();
        let mut parsed: Vec<String> = Vec::new();
        for flag in manifest["global_flags"].as_array().unwrap() {
            parsed.push(flag["name"].as_str().unwrap().to_string());
            for alias in flag["aliases"].as_array().unwrap() {
                parsed.push(alias.as_str().unwrap().to_string());
            }
        }
        parsed.sort();
        let mut declared: Vec<String> = crate::flags::GLOBALS
            .iter()
            .flat_map(|f| std::iter::once(f.name).chain(f.alias))
            .map(String::from)
            .collect();
        declared.sort();
        assert_eq!(parsed, declared);
    }

    #[test]
    fn the_typo_and_prefix_generators_give_undeclared_tokens() {
        let names = ["content", "conformance", "find", "why"];
        assert_eq!(typo("find", 0, &names).as_deref(), Some("ind"));
        assert_eq!(prefix("why", 0, &names).as_deref(), Some("wh"));
        assert_eq!(
            prefix("--word", 2, &["--word", "--wor"]).as_deref(),
            Some("--wo")
        );
        let pairs = ambiguous(&["-h", "-V"], 1);
        assert!(pairs.contains_key(&("-V".to_string(), "-h".to_string())));
        assert!(ambiguous(&names, 0).is_empty());
    }
}
