//! Conformance harness for the `rf` binary — the executable contract that
//! travels with the production artifact. Asserts the contract properties on the
//! Rust binary itself. `cargo test` builds `rf` and points CARGO_BIN_EXE_rf at it.
//!
//! It builds its own self-contained corpus in a temp dir (git-init'd so
//! .gitignore rules are active), so it depends on no external fixtures.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_rf");
const TOKEN: &str = "MAGIC_TOKEN_XYZ";
const KEYS: [&str; 7] = [
    "ok",
    "tool_version",
    "data",
    "meta",
    "warnings",
    "commands",
    "errors",
];
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn unique_temp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "rf-{label}-{}-{nanos}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

/// A self-cleaning corpus that exercises every content layer once.
struct Corpus {
    path: PathBuf,
}

impl Corpus {
    fn new() -> Corpus {
        let path = unique_temp("conf");
        std::fs::create_dir_all(path.join("src")).unwrap();

        let w = |rel: &str, bytes: &[u8]| std::fs::write(path.join(rel), bytes).unwrap();
        w("src/app.py", format!("print('{TOKEN}')\n").as_bytes()); // default
        w("secrets.env", format!("KEY={TOKEN}\n").as_bytes()); // vcs_ignore
        w(".gitignore", b"*.env\n");
        w(".hidden.txt", format!("{TOKEN}\n").as_bytes()); // hidden
        w("blob.dat", format!("pre\0{TOKEN}\n").as_bytes()); // binary (NUL before match)
                                                             // binary trap #2: NUL (so quit-on-NUL layers abort) THEN a match line
                                                             // whose bytes are not valid UTF-8 (0xda continuation byte before the
                                                             // token, then 0x80 after) — the real .pyc string-table shape. Only the
                                                             // binary layer reaches it, and only a byte-oriented sink reports it: the
                                                             // UTF8 sink errors on decode and silently drops the match.
        let mut blob = vec![b'h', b'e', b'a', b'd', 0x00, 0xda];
        blob.extend_from_slice(TOKEN.as_bytes());
        blob.extend_from_slice(&[0x80, b'\n']);
        w("blob_bin.dat", &blob); // binary (non-UTF-8 match line)
        w("lower.txt", TOKEN.to_lowercase().as_bytes()); // case
                                                         // encoding: UTF-16LE, no BOM. rg's UTF-8 assumption + NUL binary-detection
                                                         // miss it entirely; only the forced-decoder probe surfaces it.
        let utf16le: Vec<u8> = format!("setting = {TOKEN}\n")
            .chars()
            .flat_map(|c| (c as u16).to_le_bytes())
            .collect();
        w("config_utf16.txt", &utf16le); // encoding_utf16
        w("decoy.txt", b"nothing to see\n"); // true negative

        // require_git defaults true: .gitignore only applies inside a work tree.
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&path)
            .status()
            .expect("git init");
        Corpus { path }
    }
}

impl Drop for Corpus {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A self-cleaning corpus that plants one trap for every `find` stage. Task is
/// "find TOKEN in *.config". Needs two commits (for the git-history scrub) so it
/// builds its own git identity to stay CI-portable.
struct FindCorpus {
    path: PathBuf,
}

impl FindCorpus {
    fn new() -> FindCorpus {
        let path = unique_temp("find");
        std::fs::create_dir_all(path.join("src")).unwrap();
        std::fs::create_dir_all(path.join("gen")).unwrap();

        let w = |rel: &str, bytes: &[u8]| std::fs::write(path.join(rel), bytes).unwrap();
        w("src/app.config", format!("[db]\nKEY={TOKEN}\n").as_bytes()); // found
        w("settings.conf", format!("KEY={TOKEN}\n").as_bytes()); // fd_name (ext .conf)
        w(".hidden.config", format!("{TOKEN}\n").as_bytes()); // fd_hidden
        w("gen/build.config", format!("{TOKEN}\n").as_bytes()); // fd_ignore
        w(".gitignore", b"gen/\n");
        w("bin.config", format!("head\0{TOKEN}\n").as_bytes()); // rg_binary (NUL)
        w("empty.config", b"[db]\nOTHER=1\n"); // true negative
        w("history.config", format!("[db]\nKEY={TOKEN}\n").as_bytes()); // -> git_deleted
                                                                        // db.connect($$$): a node with no fixed literal form; carries NO TOKEN so
                                                                        // it stays orthogonal to the config/TOKEN task.
        w(
            "conn.py",
            b"import db\n\n\ndef get():\n    return db.connect(dsn, timeout=30)\n",
        ); // ast_structural
        w(
            "other.py",
            b"import db\n\n\ndef ping():\n    return db.ping()\n",
        ); // ast true negative

        let git = |args: &[&str]| {
            Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@t"])
                .args(args)
                .current_dir(&path)
                .output()
                .expect("git");
        };
        git(&["init", "-q"]);
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "seed (history.config has the token)"]);
        // scrub the token from history.config: it now lives only in commit 1.
        w("history.config", b"[db]\n# rotated out\n");
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "rotate token out of history.config"]);
        FindCorpus { path }
    }
}

impl Drop for FindCorpus {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Run rf; return (exit_code, parsed_json_stdout, raw_stdout).
fn rf(args: &[&str], cwd: Option<&Path>, env: &[(&str, &str)]) -> (i32, Value, String) {
    let mut c = Command::new(BIN);
    c.args(args);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().expect("spawn rf");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let json = serde_json::from_str(&stdout).unwrap_or(Value::Null);
    (out.status.code().unwrap_or(-1), json, stdout)
}

/// The error contract has a second required channel: structured output remains
/// on stdout while the first error message is mirrored to stderr.
fn rf_with_stderr(
    args: &[&str],
    cwd: Option<&Path>,
    env: &[(&str, &str)],
) -> (i32, Value, String, String) {
    let mut c = Command::new(BIN);
    c.args(args);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().expect("spawn rf");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let json = serde_json::from_str(&stdout).expect("machine output parses");
    (out.status.code().unwrap_or(-1), json, stdout, stderr)
}

#[cfg(unix)]
fn executable(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
#[test]
fn external_tool_health_and_find_provenance_are_bounded_and_typed() {
    let root = unique_temp("external-tools");
    let bin = root.join("bin");
    std::fs::create_dir(&bin).unwrap();

    let (_, missing, _) = rf(
        &["doctor", ".", "--json"],
        None,
        &[("PATH", "/no/such/path")],
    );
    for tool in ["git", "ast-grep"] {
        assert_eq!(missing["data"]["external_tools"][tool]["status"], "missing");
        assert!(missing["data"]["external_tools"][tool]["path"].is_null());
        assert!(missing["data"]["external_tools"][tool]["version"].is_null());
    }

    for tool in ["git", "ast-grep"] {
        executable(
            &bin.join(tool),
            "#!/bin/sh\ni=0; while [ \"$i\" -lt 9000 ]; do printf x; i=$((i + 1)); done\nexit 1\n",
        );
    }
    let fake_path = bin.to_string_lossy().into_owned();
    let (_, flooded, _) = rf(&["doctor", ".", "--json"], None, &[("PATH", &fake_path)]);
    for tool in ["git", "ast-grep"] {
        let health = &flooded["data"]["external_tools"][tool];
        assert_eq!(health["status"], "unusable");
        assert!(health["probe_error"].as_str().unwrap_or("").len() <= 540);
    }

    for tool in ["git", "ast-grep"] {
        executable(&bin.join(tool), "#!/bin/sh\n/bin/sleep 3\n");
    }
    let (_, timed, _) = rf(&["doctor", ".", "--json"], None, &[("PATH", &fake_path)]);
    for tool in ["git", "ast-grep"] {
        assert_eq!(timed["data"]["external_tools"][tool]["status"], "timed_out");
    }

    executable(
        &bin.join("git"),
        "#!/bin/sh\nprintf 'git version test\\n'\n",
    );
    executable(&bin.join("ast-grep"), "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'ast-grep test\\n'; exit 0; fi\n/bin/sleep 6\n");
    let corpus = Corpus::new();
    let (code, structural, _) = rf(
        &[
            "find",
            TOKEN,
            ".",
            "--name",
            "py",
            "--structural",
            "x",
            "--lang",
            "python",
            "--json",
        ],
        Some(&corpus.path),
        &[("PATH", &fake_path)],
    );
    assert_eq!(code, 0);
    assert_eq!(
        structural["meta"]["sources"]["structural"]["requested"],
        true
    );
    assert_eq!(
        structural["meta"]["sources"]["structural"]["actual"],
        "skipped"
    );
    assert_eq!(
        structural["meta"]["sources"]["structural"]["fallback_reason"],
        "tool-timed-out"
    );
    assert!(structural["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning["code"] == "STRUCTURAL_UNAVAILABLE"));
    assert!(structural["commands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|command| command.as_str().unwrap_or("").contains("'rf' 'doctor'")));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn match_evidence_flags_are_uniform_and_preserve_default_rows() {
    let corpus = Corpus::new();
    let cwd = Some(corpus.path.as_path());
    let calls: [Vec<&str>; 3] = [
        vec![
            "content",
            TOKEN,
            ".",
            "--matches",
            "--max-matches=2",
            "--json",
        ],
        vec![
            "find",
            TOKEN,
            ".",
            "--name",
            "txt",
            "--matches",
            "--max-matches",
            "2",
            "--json",
        ],
        vec![
            "why",
            TOKEN,
            "src/app.py",
            "--matches",
            "--max-matches",
            "2",
            "--json",
        ],
    ];
    for args in calls {
        let (code, response, _) = rf(&args, cwd, &[]);
        assert_eq!(code, 0, "{response}");
        // content and find return a list in data.items; why returns one
        // verdict object as data.
        let rows = match response["data"]["items"].as_array() {
            Some(items) => items.clone(),
            None => vec![response["data"].clone()],
        };
        assert!(!rows.is_empty());
        assert!(rows.iter().all(|row| row["matches"].is_array()));
    }
    let (_, default, _) = rf(&["content", TOKEN, ".", "--json"], cwd, &[]);
    assert!(default["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row.get("matches").is_some_and(Value::is_null)));
    for args in [
        vec!["content", TOKEN, ".", "--max-matches", "2", "--json"],
        vec![
            "find",
            TOKEN,
            ".",
            "--name",
            "txt",
            "--max-matches",
            "2",
            "--json",
        ],
        vec!["why", TOKEN, "src/app.py", "--max-matches", "2", "--json"],
    ] {
        let (code, response, _) = rf(&args, cwd, &[]);
        assert_eq!(code, 1);
        assert_eq!(response["errors"][0]["code"], "MISSING_REQUIRED");
        assert_eq!(response["errors"][0]["arg"], "--max-matches");
    }
}

#[test]
fn match_evidence_is_text_and_response_bounded_with_a_resume_cursor() {
    let root = unique_temp("evidence-bounds");
    let suffix = "x".repeat(700);
    for number in 0..20 {
        let mut contents = String::new();
        for _ in 0..16 {
            contents.push_str(&format!("{TOKEN} {suffix}\n"));
        }
        std::fs::write(root.join(format!("{number:02}.txt")), contents).unwrap();
    }
    let root_text = root.to_string_lossy().into_owned();
    let args = [
        "content",
        TOKEN,
        &root_text,
        "--matches",
        "--limit",
        "100",
        "--json",
    ];
    let (code, first, raw) = rf(&args, None, &[]);
    assert_eq!(code, 0, "{first}");
    assert!(raw.len() < 64 * 1024, "response was {} bytes", raw.len());
    assert_eq!(first["meta"]["evidence"]["match_cap"], 16);
    assert_eq!(first["meta"]["evidence"]["text_bytes_cap"], 512);
    assert!(first["meta"]["pagination"]["has_more"].as_bool().unwrap());
    for row in first["data"]["items"].as_array().unwrap() {
        assert_eq!(row["matches"].as_array().unwrap().len(), 16);
        assert!(row["matches"][0]["text"].as_str().unwrap().len() <= 512);
        assert_eq!(row["matches"][0]["text_truncated"], true);
    }
    let cursor = first["meta"]["pagination"]["cursor"].as_str().unwrap();
    let next_args = [
        "content",
        TOKEN,
        &root_text,
        "--matches",
        "--limit",
        "100",
        "--cursor",
        cursor,
        "--json",
    ];
    let (next_code, next, _) = rf(&next_args, None, &[]);
    assert_eq!(next_code, 0, "{next}");
    let first_files: BTreeSet<_> = first["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["file"].as_str().unwrap())
        .collect();
    let next_files: BTreeSet<_> = next["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["file"].as_str().unwrap())
        .collect();
    assert!(first_files.is_disjoint(&next_files));
    let _ = std::fs::remove_dir_all(root);
}

fn rf_with_input(args: &[&str], cwd: Option<&Path>, input: &[u8]) -> (i32, Value, String) {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(BIN)
        .args(args)
        .current_dir(cwd.unwrap_or_else(|| Path::new(".")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn rf");
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().expect("wait rf");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let json = serde_json::from_str(&stdout).expect("machine output parses");
    (out.status.code().unwrap_or(-1), json, stdout)
}

#[test]
fn error_envelopes_and_global_json_are_total() {
    let corpus = Corpus::new();
    let cwd = Some(corpus.path.as_path());
    let error_keys = [
        "code",
        "message",
        "path",
        "remediation",
        "did_you_mean",
        "exit_code",
    ];

    for args in [
        vec!["--json", "content", "(", "."],
        vec!["content", "(", ".", "--json"],
        vec!["--json", "content"],
    ] {
        let (code, env, _stdout, stderr) = rf_with_stderr(&args, cwd, &[]);
        assert_eq!(code, 1, "{args:?}");
        assert_eq!(env["ok"], Value::from(false));
        assert!(env["data"].is_null());
        assert!(KEYS.iter().all(|key| env.get(*key).is_some()));
        assert!(error_keys
            .iter()
            .all(|key| env["errors"][0].get(*key).is_some()));
        assert_eq!(env["errors"][0]["exit_code"], Value::from(1));
        assert!(!stderr.trim().is_empty());
    }

    // A global flag is valid in both parser positions. A flag after `--` is
    // literal pattern data and cannot select JSON mode by bootstrap accident.
    for args in [
        vec!["--json", "content", TOKEN, "."],
        vec!["content", TOKEN, ".", "--json"],
        vec!["--json", "content", "--", "--json"],
    ] {
        let (code, env, _stdout, _stderr) = rf_with_stderr(&args, cwd, &[]);
        assert_eq!(code, 0, "{args:?}");
        assert_eq!(env["ok"], Value::from(true));
    }

    // Stage-order probes: parser global flags beat a bad verb, verb resolution
    // beats later local syntax, and `--` prevents flag recognition.
    for (args, want) in [
        (vec!["--json", "--bogus", "badverb"], "UNKNOWN_FLAG"),
        (vec!["--json", "badverb", "--bogus"], "UNKNOWN_COMMAND"),
        (vec!["--json", "content", "--bogus"], "UNKNOWN_FLAG"),
    ] {
        let (code, env, _stdout, _stderr) = rf_with_stderr(&args, cwd, &[]);
        assert_eq!(code, 1, "{args:?}");
        assert_eq!(env["errors"][0]["code"], Value::from(want));
    }
}

#[test]
fn typo_correction_is_public_unique_and_stops_at_double_dash() {
    let (_, near, _, _) = rf_with_stderr(&["--json", "capabilitie"], None, &[]);
    assert_eq!(near["errors"][0]["did_you_mean"], "capabilities");
    assert_eq!(near["commands"][0], "'rf' '--json' 'capabilities'");
    let (_, far, _, _) = rf_with_stderr(&["--json", "not-even-close"], None, &[]);
    assert!(far["errors"][0]["did_you_mean"].is_null());
    let (_, literal, _, _) = rf_with_stderr(&["--json", "content", "--", "--jsno"], None, &[]);
    assert!(literal["errors"][0]["did_you_mean"].is_null());
}

#[test]
fn workflow_guide_is_declared_and_uses_typed_recipes() {
    let (_, guide, _, _) = rf_with_stderr(&["robot-docs", "guide", "--json"], None, &[]);
    let recipes = guide["data"]["items"].as_array().unwrap();
    assert!(!recipes.is_empty());
    assert!(recipes.iter().all(|recipe| [
        "id",
        "goal",
        "inputs",
        "command",
        "expected_branch",
        "version_range"
    ]
    .iter()
    .all(|key| recipe.get(*key).is_some())));
    let (_, caps, _, _) = rf_with_stderr(&["capabilities", "--json"], None, &[]);
    assert!(caps["data"]["verbs"]["robot-docs"].is_object());
    // One declaration for the node: nested, with no flat duplicate.
    assert!(caps["data"]["verbs"].get("robot-docs guide").is_none());
    let node = &caps["data"]["verbs"]["robot-docs"]["subcommands"]["guide"];
    assert_eq!(node["exit_codes"], serde_json::json!([0, 1]));
    assert!(node["output_schema"].is_object());
}

#[test]
fn content_selected_input_validates_and_classifies_only_selected_files() {
    let corpus = Corpus::new();
    let cwd = Some(corpus.path.as_path());
    let input = b"src/app.py\0.hidden.txt\0config_utf16.txt\0";
    let (code, selected, _) = rf_with_input(
        &["content", TOKEN, ".", "--paths-stdin", "--json"],
        cwd,
        input,
    );
    assert_eq!(code, 0);
    assert_eq!(selected["meta"]["selection"]["mode"], "stdin-nul");
    assert_eq!(selected["meta"]["selection"]["selected_files"], 3);
    let found = selected["data"]["items"].as_array().unwrap();
    assert_eq!(found.len(), 3);
    assert!(found.iter().all(|row| row["selection"] == "selected"));
    assert_eq!(
        found
            .iter()
            .find(|row| row["file"] == ".hidden.txt")
            .unwrap()["surfaced_by"],
        "hidden"
    );
    assert_eq!(
        found
            .iter()
            .find(|row| row["file"] == "config_utf16.txt")
            .unwrap()["surfaced_by"],
        "encoding_utf16"
    );

    let (_, full, raw) = rf(&["content", TOKEN, ".", "--json"], cwd, &[]);
    let (envelope_code, from_envelope, _) = rf_with_input(
        &["content", TOKEN, ".", "--paths-envelope", "--json"],
        cwd,
        raw.as_bytes(),
    );
    assert_eq!(envelope_code, 0);
    assert_eq!(from_envelope["meta"]["selection"]["mode"], "rf-envelope");
    assert_eq!(
        from_envelope["meta"]["matched_files"],
        full["meta"]["matched_files"]
    );

    for input in [
        b"src/app.py\0src/app.py\0".as_slice(),
        b"../outside\0".as_slice(),
        b".git/HEAD\0".as_slice(),
        b"src/app.py\0\0".as_slice(),
        b"\xff\0".as_slice(),
    ] {
        let (bad_code, bad, _) = rf_with_input(
            &["content", TOKEN, ".", "--paths-stdin", "--json"],
            cwd,
            input,
        );
        assert_eq!(bad_code, 1);
        assert_eq!(bad["errors"][0]["code"], "INVALID_SELECTION");
    }
    let (both_code, both, _) = rf_with_input(
        &[
            "content",
            TOKEN,
            ".",
            "--paths-stdin",
            "--paths-envelope",
            "--json",
        ],
        cwd,
        b"src/app.py\0",
    );
    assert_eq!(both_code, 1);
    assert_eq!(both["errors"][0]["code"], "INVALID_INPUT");
}

#[test]
fn why_reports_one_target_verdict_and_validates_inputs() {
    let corpus = Corpus::new();
    let cwd = Some(corpus.path.as_path());
    for (file, class) in [
        ("src/app.py", "default"),
        ("secrets.env", "vcs_ignore"),
        (".hidden.txt", "hidden"),
        ("blob.dat", "binary"),
        ("lower.txt", "case"),
        ("config_utf16.txt", "encoding_utf16"),
    ] {
        let pattern = TOKEN;
        let (code, env, _) = rf(&["why", pattern, file, "--json"], cwd, &[]);
        assert_eq!(code, 0, "{file}");
        assert!(env["data"].is_object());
        assert_eq!(env["data"]["file"], file);
        assert_eq!(env["data"]["surfaced_by"], class);
        assert_eq!(env["meta"]["file"], file);
        assert_eq!(env["meta"]["root"], ".");
        if class == "default" {
            assert!(env["commands"].as_array().unwrap().is_empty());
        } else {
            let command = env["commands"][0].as_str().unwrap();
            let output = Command::new("/bin/sh")
                .args(["-c", command])
                .current_dir(corpus.path.as_path())
                .output()
                .unwrap();
            assert!(output.status.success(), "{command}");
            assert!(String::from_utf8_lossy(&output.stdout).contains(file));
        }
    }

    let absolute = corpus.path.join("secrets.env");
    let (code, abs, _) = rf(
        &["why", TOKEN, absolute.to_str().unwrap(), "--json"],
        cwd,
        &[],
    );
    assert_eq!(code, 0);
    assert_eq!(abs["data"]["file"], "secrets.env");
    let (code, absent, _) = rf(&["why", "ABSENT", "src/app.py", "--json"], cwd, &[]);
    assert_eq!(code, 0);
    assert_eq!(absent["data"]["matched"], false);
    assert!(absent["data"]["surfaced_by"].is_null());
    for (args, want) in [
        (vec!["why", "x", ".", "--json"], "INVALID_INPUT"),
        (vec!["why", "x", "missing", "--json"], "NOT_FOUND"),
        (vec!["why", "x", ".git/HEAD", "--json"], "INVALID_INPUT"),
        (vec!["why", "[", "missing", "--json"], "NOT_FOUND"),
    ] {
        let (code, env, _) = rf(&args, cwd, &[]);
        assert_eq!(code, 1, "{args:?}");
        assert_eq!(env["errors"][0]["code"], want, "{args:?}");
        assert_eq!(env["errors"][0]["arg"], "file", "{args:?}");
    }
    let (code, bad_pattern, _) = rf(&["why", "[", "src/app.py", "--json"], cwd, &[]);
    assert_eq!(code, 1);
    assert_eq!(bad_pattern["errors"][0]["code"], "BAD_PATTERN");
}

#[test]
fn query_modes_keep_results_commands_and_cursors_honest() {
    let corpus = Corpus::new();
    let cwd = Some(corpus.path.as_path());
    std::fs::write(
        corpus.path.join("literal.txt"),
        b"A.B\npreMAGIC_TOKEN_XYZpost\n",
    )
    .unwrap();
    std::fs::write(corpus.path.join("regex-only.txt"), b"AxB\n").unwrap();

    let (_, regex, _) = rf(&["why", "A.B", "regex-only.txt", "--json"], cwd, &[]);
    let (_, fixed, _) = rf(
        &["why", "A.B", "regex-only.txt", "--fixed-strings", "--json"],
        cwd,
        &[],
    );
    assert_eq!(regex["data"]["matched"], true);
    assert_eq!(fixed["data"]["matched"], false);
    assert_eq!(fixed["meta"]["query"]["syntax"], "fixed");

    let (_, word, _) = rf(&["why", TOKEN, "literal.txt", "--word", "--json"], cwd, &[]);
    assert_eq!(word["data"]["matched"], false);

    let (_, insensitive, _) = rf(
        &[
            "why",
            &TOKEN.to_lowercase(),
            "lower.txt",
            "--ignore-case",
            "--json",
        ],
        cwd,
        &[],
    );
    assert_eq!(insensitive["data"]["surfaced_by"], "default");
    assert_eq!(insensitive["meta"]["query"]["case"], "insensitive");

    let (_, utf16, _) = rf(
        &[
            "why",
            &TOKEN.to_lowercase(),
            "config_utf16.txt",
            "--ignore-case",
            "--json",
        ],
        cwd,
        &[],
    );
    assert_eq!(utf16["data"]["surfaced_by"], "encoding_utf16");

    let (_, explicit, _) = rf(
        &[
            "content",
            TOKEN,
            ".",
            "--case-sensitive",
            "--limit",
            "1",
            "--json",
        ],
        cwd,
        &[],
    );
    let (_, plain, _) = rf(&["content", TOKEN, ".", "--limit", "1", "--json"], cwd, &[]);
    assert_eq!(
        explicit["meta"]["pagination"]["cursor"],
        plain["meta"]["pagination"]["cursor"]
    );
    assert!(explicit["commands"]
        .as_array()
        .unwrap()
        .iter()
        .all(|command| command.as_str().unwrap_or("").contains("'-s'")
            || !command.as_str().unwrap_or("").contains("'rg'")));

    let cursor = plain["meta"]["pagination"]["cursor"].as_str().unwrap();
    let (code, mismatch, _) = rf(
        &[
            "content",
            TOKEN,
            ".",
            "--ignore-case",
            "--cursor",
            cursor,
            "--json",
        ],
        cwd,
        &[],
    );
    assert_eq!(code, 1);
    assert_eq!(mismatch["errors"][0]["code"], "INVALID_INPUT");
    let (code, conflict, _) = rf(
        &[
            "content",
            TOKEN,
            ".",
            "--ignore-case",
            "--case-sensitive",
            "--json",
        ],
        cwd,
        &[],
    );
    assert_eq!(code, 1);
    assert_eq!(conflict["errors"][0]["code"], "INVALID_INPUT");
}

#[test]
fn why_reports_ignore_source_and_parent_chain_evidence() {
    let corpus = Corpus::new();
    let cwd = Some(corpus.path.as_path());
    let (_, root_rule, _) = rf(&["why", TOKEN, "secrets.env", "--json"], cwd, &[]);
    assert_eq!(root_rule["data"]["ignore_source"]["class"], "gitignore");
    assert_eq!(
        root_rule["data"]["ignore_source"]["source_file"],
        ".gitignore"
    );
    assert_eq!(root_rule["data"]["ignore_source"]["line"], 1);

    std::fs::write(corpus.path.join(".ignore"), b"*.env\n").unwrap();
    let (_, dot_rule, _) = rf(&["why", TOKEN, "secrets.env", "--json"], cwd, &[]);
    assert_eq!(dot_rule["data"]["ignore_source"]["class"], "dot_ignore");

    std::fs::remove_file(corpus.path.join(".ignore")).unwrap();
    std::fs::create_dir(corpus.path.join("nested")).unwrap();
    std::fs::write(corpus.path.join("nested/child.env"), TOKEN).unwrap();
    let nested = corpus.path.join("nested");
    let (_, ancestor, _) = rf(
        &[
            "why",
            TOKEN,
            "nested/child.env",
            "--root",
            nested.to_str().unwrap(),
            "--json",
        ],
        cwd,
        &[],
    );
    assert_eq!(ancestor["data"]["ignore_source"]["class"], "gitignore");
    assert!(ancestor["data"]["ignore_source"]["source_file"]
        .as_str()
        .unwrap()
        .starts_with('/'));

    std::fs::create_dir_all(corpus.path.join("anchored/build")).unwrap();
    std::fs::write(corpus.path.join("anchored/build/item.txt"), TOKEN).unwrap();
    std::fs::write(corpus.path.join("anchored/.gitignore"), b"/build/\n").unwrap();
    let (_, anchored, _) = rf(
        &["why", TOKEN, "anchored/build/item.txt", "--json"],
        cwd,
        &[],
    );
    assert_eq!(
        anchored["data"]["ignore_source"]["source_file"],
        "anchored/.gitignore"
    );
    assert_eq!(anchored["data"]["ignore_source"]["pattern"], "/build/");

    std::fs::write(corpus.path.join(".git/info/exclude"), b"*.excluded\n").unwrap();
    std::fs::write(corpus.path.join("secret.excluded"), TOKEN).unwrap();
    let (_, exclude, _) = rf(&["why", TOKEN, "secret.excluded", "--json"], cwd, &[]);
    assert_eq!(exclude["data"]["ignore_source"]["class"], "git_exclude");

    std::fs::write(corpus.path.join("duplicate.dup"), TOKEN).unwrap();
    std::fs::write(corpus.path.join(".gitignore"), b"*.env\n*.dup\n*.dup\n").unwrap();
    let (_, duplicate, _) = rf(&["why", TOKEN, "duplicate.dup", "--json"], cwd, &[]);
    assert_eq!(duplicate["data"]["ignore_source"]["class"], "gitignore");
    assert_eq!(
        duplicate["data"]["ignore_source"].get("line"),
        Some(&Value::Null)
    );
}

#[test]
fn find_word_mode_omits_non_whole_word_scrub_evidence() {
    let corpus = FindCorpus::new();
    let cwd = Some(corpus.path.as_path());
    let (code, env, _) = rf(
        &["find", TOKEN, ".", "--name", "config", "--word", "--json"],
        cwd,
        &[],
    );
    assert_eq!(code, 0);
    assert!(env["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning["code"] == "GIT_SCRUB_WORD_UNAVAILABLE"));
    assert!(env["commands"]
        .as_array()
        .unwrap()
        .iter()
        .all(|command| !command.as_str().unwrap_or("").contains("'-S'")));
}

#[test]
fn conformance() {
    let corpus = Corpus::new();
    let cd = Some(corpus.path.as_path());
    let mut results: Vec<(String, bool, String)> = Vec::new();
    let mut check = |name: &str, cond: bool, detail: String| {
        results.push((name.to_string(), cond, detail));
    };

    // --- envelope shape: all seven keys + contract_version on every verb ---
    let verbs: [&[&str]; 4] = [
        &["capabilities", "--json"],
        &["content", TOKEN, ".", "--json"],
        &["find", TOKEN, ".", "--name", "config", "--json"],
        &["doctor", ".", "--json"],
    ];
    for v in verbs {
        let (_, e, _) = rf(v, cd, &[]);
        let keys_ok = e.is_object()
            && KEYS.iter().all(|k| e.get(*k).is_some())
            && e.as_object().unwrap().len() == KEYS.len();
        check(
            &format!("envelope keys: {}", v[0]),
            keys_ok,
            format!(
                "{:?}",
                e.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>())
            ),
        );
        check(
            &format!("meta.contract_version: {}", v[0]),
            e["meta"]["contract_version"] == "0.1",
            String::new(),
        );
    }

    // --- exit-code dictionary ---
    check(
        "exit 0 on empty result",
        rf(&["content", "NOPE_NONE", ".", "--json"], cd, &[]).0 == 0,
        String::new(),
    );
    check(
        "exit 1 on usage error (missing arg)",
        rf(&["content"], cd, &[]).0 == 1,
        String::new(),
    );
    check(
        "exit 1 on bad regex",
        rf(&["content", "(", ".", "--json"], cd, &[]).0 == 1,
        String::new(),
    );
    check(
        "exit 1 on --structural without --lang",
        rf(
            &[
                "find",
                TOKEN,
                ".",
                "--name",
                "config",
                "--structural",
                "x($$$)",
                "--json",
            ],
            cd,
            &[],
        )
        .0 == 1,
        String::new(),
    );

    // --- forensic correctness: 5 planted, 1 by default, each layer attributed ---
    let (code, e, _) = rf(&["content", TOKEN, ".", "--json"], cd, &[]);
    check("content: exit 0", code == 0, String::new());
    check(
        "content: 7 matched",
        e["meta"]["matched_files"] == 7,
        format!("{}", e["meta"]),
    );
    check(
        "content: 1 by default",
        e["meta"]["default_matched_files"] == 1,
        format!("{}", e["meta"]),
    );
    let by_file: BTreeMap<String, String> = e["data"]["items"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|d| {
            (
                d["file"].as_str().unwrap_or("").to_string(),
                d["surfaced_by"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    for (file, layer) in [
        ("src/app.py", "default"),
        ("secrets.env", "vcs_ignore"),
        (".hidden.txt", "hidden"),
        ("blob.dat", "binary"),
        ("blob_bin.dat", "binary"),
        ("lower.txt", "case"),
        ("config_utf16.txt", "encoding_utf16"),
    ] {
        check(
            &format!("content: {file} attributed to {layer}"),
            by_file.get(file).map(|s| s.as_str()) == Some(layer),
            format!("{:?}", by_file.get(file)),
        );
    }
    // true negative must not be surfaced at all
    check(
        "content: true negative not flagged",
        !by_file.contains_key("decoy.txt"),
        String::new(),
    );
    // each non-default layer + the encoding probe emits a warning + correction
    let (_, e2, _) = rf(&["content", TOKEN, ".", "--json"], cd, &[]);
    check(
        "content: 5 filter warnings",
        e2["warnings"].as_array().map(|a| a.len()) == Some(5),
        format!("{}", e2["warnings"]),
    );
    check(
        "content: 5 correction commands",
        e2["commands"].as_array().map(|a| a.len()) == Some(5),
        format!("{}", e2["commands"]),
    );

    // --- paging: pages are sorted, snapshot-bound, and never duplicate rows ---
    let (code, first, _) = rf(&["content", TOKEN, ".", "--limit", "2", "--json"], cd, &[]);
    check(
        "paging: first page succeeds",
        code == 0 && first["data"]["items"].as_array().map(|a| a.len()) == Some(2),
        format!("{}", first),
    );
    check(
        "paging: first page reports truncation",
        first["meta"]["pagination"]["has_more"] == true
            && first["meta"]["pagination"]["truncated"] == true,
        format!("{}", first["meta"]["pagination"]),
    );
    let snapshot = first["meta"]["pagination"]["snapshot_hash"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let mut cursor = first["meta"]["pagination"]["cursor"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let mut paged = first["data"]["items"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    while !cursor.is_empty() {
        let args = [
            "content", TOKEN, ".", "--limit", "2", "--cursor", &cursor, "--json",
        ];
        let (next_code, next, _) = rf(&args, cd, &[]);
        check(
            "paging: later page succeeds",
            next_code == 0,
            format!("{}", next),
        );
        check(
            "paging: snapshot stays stable",
            next["meta"]["pagination"]["snapshot_hash"] == snapshot,
            format!("{}", next["meta"]["pagination"]),
        );
        paged.extend(
            next["data"]["items"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        );
        cursor = next["meta"]["pagination"]["cursor"]
            .as_str()
            .unwrap_or("")
            .to_string();
    }
    let mut unique = paged
        .iter()
        .map(|row| row["file"].as_str().unwrap_or("").to_string())
        .collect::<Vec<_>>();
    unique.sort();
    unique.dedup();
    check(
        "paging: all later pages are complete and unique",
        paged.len() == 7 && unique.len() == 7,
        format!("rows={}", paged.len()),
    );
    check(
        "paging: page data hash differs from snapshot hash",
        first["meta"]["data_hash"] != snapshot,
        format!("{}", first["meta"]),
    );

    let first_cursor = first["meta"]["pagination"]["cursor"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let (mismatch_code, mismatch, _) = rf(
        &[
            "content",
            "DIFFERENT_QUERY",
            ".",
            "--cursor",
            &first_cursor,
            "--json",
        ],
        cd,
        &[],
    );
    check(
        "paging: query-mismatched cursor is invalid input",
        mismatch_code == 1 && mismatch["errors"][0]["code"] == "INVALID_INPUT",
        format!("{}", mismatch),
    );
    let (bad_code, bad, _) = rf(
        &["content", TOKEN, ".", "--cursor", "not-a-cursor", "--json"],
        cd,
        &[],
    );
    check(
        "paging: malformed cursor is invalid input",
        bad_code == 1 && bad["errors"][0]["code"] == "INVALID_INPUT",
        format!("{}", bad),
    );
    std::fs::write(corpus.path.join("changed.txt"), format!("{TOKEN}\n")).unwrap();
    let (conflict_code, conflict, _) = rf(
        &["content", TOKEN, ".", "--cursor", &first_cursor, "--json"],
        cd,
        &[],
    );
    check(
        "paging: changed snapshot returns conflict and restart",
        conflict_code == 5
            && conflict["errors"][0]["code"] == "CONFLICT"
            && conflict["commands"].as_array().map(|a| a.len()) == Some(1),
        format!("{}", conflict),
    );
    check(
        "paging: invalid limit is rejected",
        rf(&["content", TOKEN, ".", "--limit", "0", "--json"], cd, &[]).1["errors"][0]["code"]
            == "INVALID_INPUT",
        String::new(),
    );

    // --- determinism: identical stdout under a pinned epoch, except
    // meta.request_id, which is unique per invocation by contract ---
    let strip_request_id = |mut value: Value| {
        let had_id = value["meta"]["request_id"].is_string();
        if let Some(meta) = value["meta"].as_object_mut() {
            meta.remove("request_id");
        }
        (had_id, value)
    };
    let a = rf(
        &["content", TOKEN, ".", "--json"],
        cd,
        &[("SOURCE_DATE_EPOCH", "0")],
    )
    .1;
    let b = rf(
        &["content", TOKEN, ".", "--json"],
        cd,
        &[("SOURCE_DATE_EPOCH", "0")],
    )
    .1;
    check(
        "content: request_id is unique per invocation",
        a["meta"]["request_id"].is_string() && a["meta"]["request_id"] != b["meta"]["request_id"],
        format!("{} {}", a["meta"]["request_id"], b["meta"]["request_id"]),
    );
    let (a_had_id, a) = strip_request_id(a);
    let (b_had_id, b) = strip_request_id(b);
    check(
        "content: deterministic (identical apart from request_id)",
        a_had_id && b_had_id && a == b,
        String::new(),
    );
    check(
        "content: ts honors SOURCE_DATE_EPOCH",
        rf(
            &["content", TOKEN, ".", "--json"],
            cd,
            &[("SOURCE_DATE_EPOCH", "0")],
        )
        .1["meta"]["ts_iso"]
            == "1970-01-01T00:00:00Z",
        String::new(),
    );

    // --- doctor: git repo -> ignore mode ACTIVE ---
    let (_, e, _) = rf(&["doctor", ".", "--json"], cd, &[]);
    check(
        "doctor: repo -> ignore ACTIVE",
        e["data"]["ignore_mode"]
            .as_str()
            .unwrap_or("")
            .contains("ACTIVE"),
        format!("{}", e["data"]["ignore_mode"]),
    );

    // --- capabilities: advertises the verbs and the exit-code dictionary ---
    let (_, e, _) = rf(&["capabilities", "--json"], cd, &[]);
    let caps = &e["data"];
    check(
        "capabilities: all verbs advertised",
        ["capabilities", "content", "find", "doctor"]
            .iter()
            .all(|v| caps["verbs"].get(*v).is_some()),
        String::new(),
    );
    check(
        "capabilities: exit codes 0/1/3 documented",
        ["0", "1", "3"]
            .iter()
            .all(|c| caps["exit_codes"].get(*c).is_some()),
        String::new(),
    );
    check(
        "capabilities: engine is in-process",
        caps["engine"].as_str().unwrap_or("").contains("in-process"),
        String::new(),
    );
    check(
        "capabilities: conformance verb advertised (P-f discovery)",
        caps["verbs"].get("conformance").is_some(),
        String::new(),
    );
    check(
        "capabilities: error codes registered (X-06)",
        ["MISSING_REQUIRED", "BAD_PATTERN", "INTERNAL"]
            .iter()
            .all(|c| caps["error_codes"].get(*c).is_some()),
        String::new(),
    );

    // --- conformance: the in-situ self-check meets the P-f schema floor ---
    let (code, e, _) = rf(&["conformance", "--json"], cd, &[]);
    let d = &e["data"];
    check(
        "conformance: exit 0 with no failures",
        code == 0 && e["ok"] == true,
        format!("code={code}"),
    );
    check(
        "conformance: profile is the profile of this build",
        d["profile"]
            == if cfg!(feature = "fault-injection") {
                "full-ci"
            } else {
                "release-self-check"
            },
        String::new(),
    );
    check(
        "conformance: counts + cases present",
        d["counts"].get("pass").is_some()
            && d["counts"].get("fail").is_some()
            && d["counts"].get("not_applicable").is_some()
            && d["cases"].is_array(),
        String::new(),
    );
    let cases = d["cases"].as_array().cloned().unwrap_or_default();
    check(
        "conformance: every case has the five floor keys",
        cases.iter().all(|c| {
            ["case_id", "verdict", "reason", "request_id", "target"]
                .iter()
                .all(|k| c.get(*k).is_some())
        }),
        String::new(),
    );
    check(
        "conformance: cases sorted by case_id",
        cases.windows(2).all(|w| {
            w[0]["case_id"].as_str().unwrap_or("") <= w[1]["case_id"].as_str().unwrap_or("")
        }),
        String::new(),
    );
    check(
        "conformance: no case failed",
        d["counts"]["fail"].as_i64() == Some(0),
        format!("{}", d["counts"]["fail"]),
    );
    check(
        "conformance: not-applicable reasons are non-null",
        cases
            .iter()
            .filter(|c| c["verdict"] == "not_applicable")
            .all(|c| c["reason"].is_string()),
        String::new(),
    );

    // --- find: four independent sources, each miss attributed to one stage ---
    let fc = FindCorpus::new();
    let fd = Some(fc.path.as_path());
    let ast_available = Command::new("ast-grep")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    // Without ast-grep a structural request is DEPENDENCY_MISSING, so the
    // structural source is requested only where the program is present.
    let mut find_args = vec!["find", TOKEN, ".", "--name", "config"];
    if ast_available {
        find_args.extend(["--structural", "db.connect($$$)", "--lang", "python"]);
    }
    find_args.push("--json");
    let (code, e, _) = rf(&find_args, fd, &[]);
    check("find: exit 0", code == 0, format!("code={code}"));
    let stage: BTreeMap<String, String> = e["data"]["items"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|d| {
            (
                d["file"].as_str().unwrap_or("").to_string(),
                d["stage"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    for (file, want) in [
        ("src/app.config", "found"),
        ("settings.conf", "fd_name"),
        (".hidden.config", "fd_hidden"),
        ("gen/build.config", "fd_ignore"),
        ("bin.config", "rg_binary"),
        ("history.config", "git_deleted"),
    ] {
        check(
            &format!("find: {file} -> {want}"),
            stage.get(file).map(|s| s.as_str()) == Some(want),
            format!("{:?}", stage.get(file)),
        );
    }
    // true negatives: correct name but no token, and the ast decoy, stay unflagged
    check(
        "find: empty.config not flagged",
        !stage.contains_key("empty.config"),
        String::new(),
    );
    check(
        "find: other.py not flagged (ast decoy)",
        !stage.contains_key("other.py"),
        String::new(),
    );
    // pipe accounting mirrors the reference corpus
    check(
        "find: fd_default_files == 4",
        e["meta"]["fd_default_files"] == 4,
        format!("{}", e["meta"]),
    );
    check(
        "find: pipe_matched == 1",
        e["meta"]["pipe_matched"] == 1,
        format!("{}", e["meta"]),
    );
    check(
        "find: content_total == 5",
        e["meta"]["content_total"] == 5,
        format!("{}", e["meta"]),
    );
    check(
        "find: history_matches == 1",
        e["meta"]["history_matches"] == 1,
        format!("{}", e["meta"]),
    );
    check(
        "find: headline is PARTIAL",
        e["meta"]["headline"]
            .as_str()
            .unwrap_or("")
            .starts_with("PARTIAL"),
        format!("{}", e["meta"]["headline"]),
    );
    // The paging calls take the same source set as the call above, so they
    // also run where ast-grep is absent.
    let mut page_args = find_args.clone();
    page_args.pop();
    page_args.extend(["--limit", "2", "--json"]);
    let (find_page_code, find_page, _) = rf(&page_args, fd, &[]);
    let find_cursor = find_page["meta"]["pagination"]["cursor"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let mut next_args = find_args.clone();
    next_args.pop();
    next_args.extend(["--limit", "2", "--cursor", &find_cursor, "--json"]);
    let (find_next_code, find_next, _) = rf(&next_args, fd, &[]);
    let first_files: BTreeSet<String> = find_page["data"]["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["file"].as_str().map(String::from))
        .collect();
    let next_files: BTreeSet<String> = find_next["data"]["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["file"].as_str().map(String::from))
        .collect();
    check(
        "find paging: page continuation has no duplicate rows",
        find_page_code == 0
            && find_next_code == 0
            && !first_files.is_empty()
            && !next_files.is_empty()
            && first_files.is_disjoint(&next_files),
        format!("first={first_files:?}, next={next_files:?}"),
    );
    check(
        "find paging: scanned totals stay complete",
        find_page["meta"]["content_total"] == e["meta"]["content_total"]
            && find_page["meta"]["hidden_by_stage"] == e["meta"]["hidden_by_stage"],
        format!("{}", find_page["meta"]),
    );
    let plain = unique_temp("history-state");
    std::fs::write(plain.join("only.config"), format!("{TOKEN}\n")).unwrap();
    let plain_s = plain.to_string_lossy().into_owned();
    let (not_tree_code, not_tree, _) = rf(
        &["find", TOKEN, &plain_s, "--name", "config", "--json"],
        None,
        &[],
    );
    check(
        "find: non-work-tree history is explicit",
        not_tree_code == 0
            && not_tree["meta"]["history"]["actual_mode"] == "not-work-tree"
            && not_tree["warnings"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|w| w["code"] == "GIT_NOT_WORK_TREE"),
        format!("{}", not_tree),
    );
    let (absent_code, absent, _) = rf(
        &["find", TOKEN, &plain_s, "--name", "config", "--json"],
        None,
        &[("PATH", "/rf-no-git-bin")],
    );
    check(
        "find: absent Git history is explicit",
        absent_code == 0
            && absent["meta"]["history"]["actual_mode"] == "git-absent"
            && absent["warnings"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|w| w["code"] == "GIT_ABSENT"),
        format!("{}", absent),
    );
    std::fs::remove_dir_all(plain).unwrap();

    // structural source is conditional on ast-grep; both branches must be total
    if ast_available {
        check(
            "find: conn.py -> ast_structural",
            stage.get("conn.py").map(|s| s.as_str()) == Some("ast_structural"),
            format!("{:?}", stage.get("conn.py")),
        );
        check(
            "find: structural_matches == 1",
            e["meta"]["structural_matches"] == 1,
            format!("{}", e["meta"]),
        );
    }
    let (code, no_ast, _) = rf(
        &[
            "find",
            TOKEN,
            ".",
            "--name",
            "config",
            "--structural",
            "db.connect($$$)",
            "--lang",
            "python",
            "--json",
        ],
        fd,
        &[("PATH", "/rf-no-ast-grep-bin")],
    );
    let entry = &no_ast["errors"][0];
    check(
        "find: absent ast-grep is DEPENDENCY_MISSING (exit 3)",
        code == 3
            && no_ast["ok"] == false
            && no_ast["data"].is_null()
            && entry["code"] == "DEPENDENCY_MISSING"
            && entry["details"]["program"] == "ast-grep"
            && entry["details"]["child_exit"].is_null()
            && entry["details"]["child_signal"].is_null()
            && entry["remediation"].is_string(),
        format!("code={code} {no_ast}"),
    );

    // --- report (visible with `cargo test -- --nocapture`) ---
    let mut fails = Vec::new();
    for (name, cond, detail) in &results {
        println!(
            "  {}  {name}{}",
            if *cond { "PASS" } else { "FAIL" },
            if !cond && !detail.is_empty() {
                format!("   [{detail}]")
            } else {
                String::new()
            }
        );
        if !cond {
            fails.push(name.clone());
        }
    }
    println!("\n{}/{} passed", results.len() - fails.len(), results.len());
    assert!(fails.is_empty(), "conformance failures: {fails:?}");
}

// --- P-e: golden verdict pins ---------------------------------------------
//
// The `conformance` test above asserts *structure* (floor keys, sorting, no
// fail). These two pins assert *instance -> verdict*: the exact machine contract
// and the exact case->verdict map. They catch silent drift a structural check
// cannot — a verb quietly added/removed, an exit or error code renamed, a case
// flipping pass<->fail<->n/a, or an n/a reason string changing.
//
// The goldens are generated from real binary output, never hand-written. When a
// change to either surface is intentional, re-pin (commands below) and commit
// the new golden as part of that change.

#[cfg(not(feature = "fault-injection"))]
const CAPS_GOLDEN: &str = include_str!("golden/capabilities.data.json");
#[cfg(not(feature = "fault-injection"))]
const VERDICTS_GOLDEN: &str = include_str!("golden/conformance.verdicts.json");
#[cfg(feature = "fault-injection")]
const VERDICTS_GOLDEN: &str = include_str!("golden/conformance.verdicts.full-ci.json");

/// tool_version tracks CARGO_PKG_VERSION and bumps every release; the pin guards
/// the *contract*, so normalize it out. contract_version stays real — it is the
/// gate that must move deliberately.
#[cfg(not(feature = "fault-injection"))]
fn normalize_caps(mut d: Value) -> Value {
    if let Some(o) = d.as_object_mut() {
        o.insert("tool_version".into(), Value::from("PINNED"));
    }
    d
}

// Pinned against the release contract. A fault-injection build discloses RF_FAULT
// in env_vars and flips several conformance verdicts, so its output is a different
// (also-honest) contract; the pins guard the canonical release build only.
#[cfg(not(feature = "fault-injection"))]
#[test]
fn golden_capabilities_contract() {
    let want: Value = serde_json::from_str(CAPS_GOLDEN).expect("golden parses");
    let (_, e, _) = rf(
        &["capabilities", "--json"],
        None,
        &[("SOURCE_DATE_EPOCH", "0")],
    );
    let got = normalize_caps(e["data"].clone());
    assert!(
        got == want,
        "capabilities contract drifted from the golden pin.\n\
         If this change is intentional, re-pin:\n  \
         SOURCE_DATE_EPOCH=0 cargo run -q -- capabilities --json \\\n    \
         | python3 -c \"import sys,json; d=json.load(sys.stdin)['data']; d['tool_version']='PINNED'; \
print(json.dumps(d,indent=2,sort_keys=True))\" > tests/golden/capabilities.data.json\n\n\
         observed (normalized):\n{}",
        serde_json::to_string_pretty(&got).unwrap_or_default()
    );
}

#[test]
fn golden_conformance_verdicts() {
    let want: Value = serde_json::from_str(VERDICTS_GOLDEN).expect("golden parses");
    let (_, e, _) = rf(
        &["conformance", "--json"],
        None,
        &[("SOURCE_DATE_EPOCH", "0")],
    );
    let p = &e["data"];
    // Project to the pinned shape: request_id is per-host (embeds argv[0]) and
    // target is derivable from case_id, so neither is pinned; verdict + reason are.
    let cases: Vec<Value> = p["cases"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|c| {
            let mut m = serde_json::Map::new();
            m.insert("case_id".into(), c["case_id"].clone());
            m.insert("verdict".into(), c["verdict"].clone());
            m.insert("reason".into(), c["reason"].clone());
            Value::from(m)
        })
        .collect();
    let mut got = serde_json::Map::new();
    got.insert("profile".into(), p["profile"].clone());
    got.insert("counts".into(), p["counts"].clone());
    got.insert("cases".into(), Value::from(cases));
    let got = Value::from(got);
    assert!(
        got == want,
        "conformance verdict set drifted from the golden pin.\n\
         If this change is intentional, re-pin:\n  \
         SOURCE_DATE_EPOCH=0 cargo run -q -- conformance --json \\\n    \
         | python3 -c \"import sys,json; p=json.load(sys.stdin)['data']; \
print(json.dumps({{'profile':p['profile'],'counts':p['counts'],\
'cases':[{{'case_id':c['case_id'],'verdict':c['verdict'],'reason':c['reason']}} for c in p['cases']]}},\
indent=2,sort_keys=True))\" > tests/golden/conformance.verdicts.json\n\n\
         observed:\n{}",
        serde_json::to_string_pretty(&got).unwrap_or_default()
    );
}

// --- P-d: the per-stage fault-injection seam ------------------------------
//
// Two complementary proofs, one per build. The release build proves the seam is
// truly compiled out (RF_FAULT is inert); the fault-injection build proves the
// totality wrapper converts a real per-stage panic into a total error envelope.
// Exactly one runs per `cargo test` invocation, chosen by the feature flag.

/// argv that reaches each stage's seam with otherwise-valid input.
/// The eight diagnosis stages, in the declared order.
const STAGES: [&str; 8] = [
    "bootstrap_mode",
    "global_flag",
    "command_path",
    "command_flag",
    "value_validation",
    "required_argument",
    "semantic_resolution",
    "execution",
];

/// Valid argv that goes through each diagnosis stage.
fn stage_argv(empty: &str) -> Vec<&str> {
    vec![
        "find",
        "zzq_no_such_token",
        empty,
        "--name",
        "conf",
        "--json",
    ]
}

/// Verdict of a single conformance case_id (exact match), or "<absent>".
fn verdict_of(e: &Value, case_id: &str) -> String {
    e["data"]["cases"]
        .as_array()
        .and_then(|cs| cs.iter().find(|c| c["case_id"] == case_id))
        .and_then(|c| c["verdict"].as_str())
        .unwrap_or("<absent>")
        .to_string()
}

#[cfg(not(feature = "fault-injection"))]
#[test]
fn fault_seam_absent_in_release() {
    // RF_FAULT must be inert: the seam is not compiled in, so a normal search runs.
    let empty_dir = unique_temp("fault-empty");
    let empty = empty_dir.to_string_lossy().into_owned();
    for stage in STAGES {
        let (code, e, _) = rf(&stage_argv(&empty), None, &[("RF_FAULT", stage)]);
        assert!(
            code == 0 && e["ok"] == true,
            "RF_FAULT={stage} should be inert in a release build: code={code} {e}"
        );
    }
    let _ = std::fs::remove_dir(&empty_dir);
    // And the self-check reports the totality cases not-applicable, not pass.
    let (_, e, _) = rf(&["conformance", "--json"], None, &[]);
    for stage in STAGES {
        for label in ["S-01", "X-02"] {
            let id = format!("{label}::stage={stage}");
            assert_eq!(
                verdict_of(&e, &id),
                "not_applicable",
                "{id} in release build"
            );
        }
    }
    assert_eq!(
        verdict_of(&e, "S-02::stage=bootstrap_mode"),
        "not_applicable"
    );
    assert_eq!(verdict_of(&e, "X-03"), "pass");
}

#[cfg(feature = "fault-injection")]
#[test]
fn fault_seam_proves_totality() {
    // Injecting a fault at each stage must yield a TOTAL error envelope: the
    // catch_unwind wrapper turns the panic into exit 7 + INTERNAL + seven keys,
    // never an unmediated crash (which would be exit 101 with no JSON).
    let empty_dir = unique_temp("fault-empty");
    let empty = empty_dir.to_string_lossy().into_owned();
    for stage in STAGES {
        let (code, e, _) = rf(&stage_argv(&empty), None, &[("RF_FAULT", stage)]);
        assert_eq!(
            code, 7,
            "stage {stage}: fault must exit 7 (internal), not crash"
        );
        assert_eq!(
            e["ok"],
            Value::from(false),
            "stage {stage}: ok must be false"
        );
        assert_eq!(
            e["errors"][0]["code"],
            Value::from("INTERNAL"),
            "stage {stage}"
        );
        assert!(
            e.is_object() && KEYS.iter().all(|k| e.get(*k).is_some()),
            "stage {stage}: envelope lost a key under fault",
        );
    }
    // The in-situ self-check now adjudicates the totality cases for real.
    let (code, e, _) = rf(&["conformance", "--json"], None, &[]);
    assert_eq!(
        code, 0,
        "self-check must still be all-pass under the seam build"
    );
    for stage in STAGES {
        for label in ["S-01", "X-02"] {
            let id = format!("{label}::stage={stage}");
            assert_eq!(
                verdict_of(&e, &id),
                "pass",
                "{id} should pass with the seam in"
            );
        }
    }
    assert_eq!(verdict_of(&e, "S-02::stage=bootstrap_mode"), "pass");
    // A test build gives no X-03 instance: that case is for the release artifact.
    assert_eq!(verdict_of(&e, "X-03"), "<absent>");
    assert_eq!(e["data"]["counts"]["fail"], Value::from(0));
}

/// Mode and help surfaces: JSON is selected, never automatic. The help
/// spellings are one surface, and a closed reader ends the process with 141.
#[cfg(unix)]
#[test]
fn mode_and_help_surfaces_follow_the_selector() {
    use std::ffi::OsStr;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::process::Stdio;

    let raw = |args: &[&OsStr]| {
        let out = Command::new(BIN).args(args).output().expect("spawn rf");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
        )
    };
    let text = |args: &[&str]| {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        raw(&args)
    };

    // No selector gives human text, even when stdout is a pipe.
    let (code, out) = text(&["doctor"]);
    assert!(code == 0 || code == 6, "doctor exit {code}");
    assert!(out.contains("overall: "), "{out}");
    assert!(serde_json::from_str::<Value>(&out).is_err(), "{out}");
    let (code, _, _) = rf(&["--human", "doctor", "--json"], None, &[]);
    assert_eq!(code, 1, "--human is removed");

    // Version: the bare version in human rendering, the floor keys in JSON.
    for flag in ["--version", "-V"] {
        assert_eq!(
            text(&[flag]),
            (0, format!("{}\n", env!("CARGO_PKG_VERSION")))
        );
    }
    let (code, env, _) = rf(&["--version", "--json"], None, &[]);
    assert_eq!(code, 0);
    assert_eq!(env["data"]["contract_version"], "0.1");
    assert!(env["data"]["build"].is_null());
    assert!(env["data"].as_object().unwrap().contains_key("build"));

    // Bare invocation and help.
    let (code, usage) = text(&[]);
    assert_eq!(code, 0);
    assert!(usage.contains("Usage: rf"));
    let (code, env, _) = rf(&["--json"], None, &[]);
    assert_eq!(code, 0);
    assert_eq!(env["data"]["usage"], Value::from(usage.clone()));
    assert!(env["data"]["default_action"].is_null());
    let (code, env, _) = rf(&["--help", "--json"], None, &[]);
    assert_eq!(code, 0);
    assert_eq!(
        env["data"]["capabilities_command"],
        "rf capabilities --json"
    );
    assert_eq!(env["data"]["usage"], Value::from(usage.clone()));

    // The three help spellings give the same bytes at each node.
    for node in [&[][..], &["content"][..], &["robot-docs", "guide"][..]] {
        let mut long = node.to_vec();
        long.push("--help");
        let mut short = node.to_vec();
        short.push("-h");
        let mut verb = vec!["help"];
        verb.extend_from_slice(node);
        let want = text(&long);
        assert_eq!(want.0, 0);
        assert_eq!(text(&short), want, "{node:?}");
        assert_eq!(text(&verb), want, "{node:?}");
    }
    let (code, env, _) = rf(&["help", "contnt", "--json"], None, &[]);
    assert_eq!(code, 1);
    assert_eq!(env["errors"][0]["code"], "UNKNOWN_COMMAND");
    assert_eq!(env["errors"][0]["did_you_mean"], "content");

    // A malformed selector still selects machine rendering.
    for selector in ["--json=false", "--json=1", "--json="] {
        let (code, env, _) = rf(&[selector, "doctor"], None, &[]);
        assert_eq!(code, 1, "{selector}");
        assert_eq!(env["errors"][0]["code"], "INVALID_INPUT");
        assert_eq!(env["errors"][0]["arg"], "--json");
    }

    // Undecodable argv: classified by position, bytes reported exactly.
    let bad = OsStr::from_bytes(b"\xff");
    let bad_flag = OsStr::from_bytes(b"--b\xffd");
    let json = OsStr::new("--json");
    for (args, want, hex) in [
        (vec![bad, json], "UNKNOWN_COMMAND", "ff"),
        (vec![json, bad], "UNKNOWN_COMMAND", "ff"),
        (
            vec![OsStr::new("content"), bad_flag, json],
            "UNKNOWN_FLAG",
            "2d2d62ff64",
        ),
        (
            vec![OsStr::new("content"), bad, json],
            "INVALID_INPUT",
            "ff",
        ),
    ] {
        let (code, out) = raw(&args);
        let env: Value = serde_json::from_str(&out).expect("envelope");
        assert_eq!(code, 1);
        assert_eq!(env["errors"][0]["code"], want);
        assert_eq!(env["errors"][0]["details"]["bytes_hex"], hex);
        assert!(env["errors"][0]["arg"].as_str().unwrap().contains("\\xff"));
    }
    // Bad bytes in the value of a declared flag: the flag is known.
    let bad_value = OsStr::from_bytes(b"--cursor=\xff");
    let (code, out) = raw(&[OsStr::new("content"), OsStr::new("x"), bad_value, json]);
    let env: Value = serde_json::from_str(&out).expect("envelope");
    assert_eq!(code, 1);
    assert_eq!(env["errors"][0]["code"], "INVALID_INPUT");
    assert_eq!(env["errors"][0]["arg"], "--cursor");
    assert_eq!(
        env["errors"][0]["details"]["bytes_hex"],
        "2d2d637572736f723dff"
    );
    let (code, out) = raw(&[bad]);
    assert_eq!(
        (code, out.as_str()),
        (1, ""),
        "human refusal is stderr only"
    );

    // A closed reader: exit 141 and no panic text.
    for args in [&["capabilities", "--json"][..], &["--help"][..]] {
        let mut child = Command::new(BIN)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn rf");
        drop(child.stdout.take());
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(141), "{args:?}");
        assert!(!stderr.contains("panicked"), "{stderr}");
    }
}

#[test]
fn parser_faults_follow_the_diagnosis_order() {
    let run = |args: &[&str]| {
        let (code, env, _, stderr) = rf_with_stderr(args, None, &[]);
        assert_eq!(code, 1, "{args:?}");
        assert_eq!(env["ok"], false, "{args:?}");
        (env["errors"][0].clone(), env["commands"].clone(), stderr)
    };
    let expect = |args: &[&str], code: &str, arg: &str| {
        let (error, _, _) = run(args);
        assert_eq!(error["code"], code, "{args:?}");
        assert_eq!(error["arg"], arg, "{args:?}");
        error
    };

    // A value flag never consumes a flag-shaped token, and never runs dry.
    expect(
        &["--json", "content", "x", ".", "--limit"],
        "MISSING_REQUIRED",
        "--limit",
    );
    expect(
        &["--json", "content", "--limit", "--word", "x"],
        "MISSING_REQUIRED",
        "--limit",
    );
    expect(
        &["content", "--limit", "--json", "x"],
        "MISSING_REQUIRED",
        "--limit",
    );
    expect(
        &["--json", "content", "--limit", "--bogus", "x"],
        "UNKNOWN_FLAG",
        "--bogus",
    );

    // Value hygiene.
    expect(
        &["--json", "content", "--limit=", "x"],
        "INVALID_INPUT",
        "--limit",
    );
    expect(
        &["--json", "content", "--limit", "", "x"],
        "INVALID_INPUT",
        "--limit",
    );
    expect(
        &["--json", "content", "--limit=0x10", "x"],
        "INVALID_INPUT",
        "--limit",
    );
    expect(
        &["--json", "content", "--limit", "-5", "x"],
        "INVALID_INPUT",
        "--limit",
    );
    expect(
        &["--json", "content", "--word=true", "x"],
        "INVALID_INPUT",
        "--word",
    );
    expect(
        &["--json", "content", "--cursor=-abc", "x"],
        "INVALID_INPUT",
        "--cursor",
    );
    expect(&["--json", "find", "--name=-rs"], "INVALID_INPUT", "--name");
    expect(
        &["--json", "why", "--root=", "x", "a"],
        "INVALID_INPUT",
        "--root",
    );
    let lang = expect(
        &[
            "--json",
            "find",
            "x",
            "--name",
            "rs",
            "--structural",
            "f",
            "--lang",
            "rsut",
        ],
        "INVALID_INPUT",
        "--lang",
    );
    assert_eq!(lang["did_you_mean"], "rust");

    // Surplus positional, conflicts in both orders, companions.
    expect(
        &["--json", "content", "x", ".", "extra"],
        "INVALID_INPUT",
        "extra",
    );
    expect(
        &["--json", "capabilities", "extra"],
        "INVALID_INPUT",
        "extra",
    );
    let pair = expect(
        &[
            "--json",
            "content",
            "--ignore-case",
            "--case-sensitive",
            "x",
        ],
        "INVALID_INPUT",
        "--case-sensitive",
    );
    let message = pair["message"].as_str().unwrap();
    assert!(message.contains("--ignore-case") && message.contains("--case-sensitive"));
    expect(
        &[
            "--json",
            "content",
            "--case-sensitive",
            "--ignore-case",
            "x",
        ],
        "INVALID_INPUT",
        "--ignore-case",
    );
    let (alone, commands, _) = run(&["--json", "content", "--max-matches", "5", "x"]);
    assert_eq!(alone["code"], "MISSING_REQUIRED");
    assert!(alone["message"].as_str().unwrap().contains("--matches"));
    assert_eq!(
        commands[0],
        "'rf' '--json' 'content' '--matches' '--max-matches' '5' 'x'"
    );
    expect(
        &["--json", "find", "x", "--name", "rs", "--lang", "rust"],
        "MISSING_REQUIRED",
        "--lang",
    );
    expect(
        &["--json", "find", "x", "--name", "rs", "--structural", "f"],
        "MISSING_REQUIRED",
        "--structural",
    );
    expect(&["--json", "find", "x"], "MISSING_REQUIRED", "--name");
    expect(&["--json", "content"], "MISSING_REQUIRED", "pattern");
    expect(&["--json", "robot-docs"], "MISSING_REQUIRED", "command");

    // Stage order: a bad value is reported before a missing positional, and
    // an unknown name before both.
    expect(
        &["--json", "content", "--limit=abc"],
        "INVALID_INPUT",
        "--limit",
    );
    expect(&["--json", "--bogus", "badverb"], "UNKNOWN_FLAG", "--bogus");
    expect(
        &["--json", "content", "--bogus", "--limit=abc"],
        "UNKNOWN_FLAG",
        "--bogus",
    );

    // Names match exactly; one near candidate gives a hint and a corrected line.
    let prefix = expect(
        &["--json", "content", "--lim", "5", "x"],
        "UNKNOWN_FLAG",
        "--lim",
    );
    assert!(prefix["did_you_mean"].is_null());
    assert!(prefix["remediation"].as_str().unwrap().contains("--limit"));
    let human = Command::new(BIN)
        .args(["content", "--wrod", "x"])
        .output()
        .expect("spawn rf");
    assert_eq!(human.status.code(), Some(1));
    assert!(human.stdout.is_empty(), "human mode has no envelope");
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(stderr.contains("did you mean: --word"), "{stderr}");
    assert!(
        stderr.contains("corrected:    'rf' 'content' '--word' 'x'"),
        "{stderr}"
    );
    let (verb, commands, stderr) = run(&["--json", "contnt", "x"]);
    assert_eq!(verb["code"], "UNKNOWN_COMMAND");
    assert_eq!(verb["did_you_mean"], "content");
    assert_eq!(commands[0], "'rf' '--json' 'content' 'x'");
    assert!(stderr.contains("corrected:"));
    let (far, _, stderr) = run(&["--json", "con", "x"]);
    assert!(far["did_you_mean"].is_null());
    assert!(!stderr.contains("corrected:"));

    // A value that looks like a flag passes after `--`, and a negative-looking
    // pattern is data there.
    let (code, env, _) = rf(&["--json", "content", "--", "--limit", "."], None, &[]);
    assert_eq!(code, 0);
    assert_eq!(env["meta"]["pattern"], "--limit");
}

#[test]
fn exit_dictionary_and_code_registry_are_closed() {
    let (code, env, _) = rf(&["--json", "capabilities"], None, &[]);
    assert_eq!(code, 0);
    let caps = &env["data"];

    // The exit dictionary has the conventional values.
    let exits = caps["exit_codes"].as_object().expect("exit_codes object");
    let retry = |code: &str| exits[code]["retryable"].clone();
    for code in ["0", "3", "129", "130", "141", "143"] {
        assert!(retry(code).is_null(), "exit {code} retryable");
    }
    for code in ["1", "2", "5", "6", "7"] {
        assert_eq!(retry(code), false, "exit {code} retryable");
    }
    assert_eq!(retry("4"), true);
    assert_eq!(exits["6"]["meaning"], "findings-present");
    assert_eq!(exits["7"]["meaning"], "internal-error");

    // One registry holds errors and warnings. Each entry has the fixed keys
    // and a reproduction.
    assert!(caps.get("warning_codes").is_none());
    assert!(caps.get("warning_details").is_none());
    let registry = caps["error_codes"].as_object().expect("registry object");
    for (name, entry) in registry {
        let appears = entry["appears_in"].as_array().expect("appears_in");
        assert!(!appears.is_empty(), "{name}");
        assert!(entry["summary"].is_string(), "{name}");
        let warning_only = appears.iter().all(|a| a == "warnings");
        assert_eq!(entry["exit"].is_null(), warning_only, "{name} exit");
        if let Some(exit) = entry["exit"].as_i64() {
            assert!(exits.contains_key(&exit.to_string()), "{name} exit {exit}");
        }
        assert!(
            entry["example_invocation"].is_string()
                || (entry["precondition"].is_string() && entry["fixture"].is_string()),
            "{name} has no reproduction"
        );
    }
    assert_eq!(registry["INTERNAL"]["exit"], 7);
    assert_eq!(registry["CONFLICT"]["exit"], 5);
    assert_eq!(registry["IGNORE_VCS"]["appears_in"][0], "warnings");

    // Closure: each code literal in the source is registered.
    let known = [
        "OUT_FILE",
        "RF_FAULT",
        "SOURCE_DATE_EPOCH",
        "NO_COLOR",
        "CARGO_PKG_VERSION",
    ];
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for file in std::fs::read_dir(&src).expect("src dir") {
        let path = file.expect("entry").path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if [
            "registry.rs",
            "conformance.rs",
            "capabilities.rs",
            "guide.rs",
        ]
        .contains(&name.as_str())
        {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source");
        for piece in text.split('"').skip(1).step_by(2) {
            let shaped = piece.len() >= 5
                && piece.contains('_')
                && piece.chars().all(|c| c.is_ascii_uppercase() || c == '_');
            if shaped && !known.contains(&piece) {
                assert!(
                    registry.contains_key(piece),
                    "{name}: {piece} is not registered"
                );
            }
        }
    }

    // An example invocation gives the code and the exit that its entry declares.
    for (name, entry) in registry {
        let Some(call) = entry["example_invocation"].as_str() else {
            continue;
        };
        if call.contains('|') {
            continue;
        }
        let args: Vec<&str> = call
            .split_whitespace()
            .skip(1)
            .map(|a| a.trim_matches('\''))
            .collect();
        let (code, reply, _) = rf(&args, None, &[]);
        assert_eq!(reply["errors"][0]["code"], name.as_str(), "{call}");
        assert_eq!(i64::from(code), entry["exit"].as_i64().unwrap(), "{call}");
        assert_eq!(reply["errors"][0]["exit_code"], code, "{call}");
    }

    // Env vars are an object with a description for each.
    let vars = caps["env_vars"].as_object().expect("env_vars object");
    for (name, entry) in vars {
        assert!(entry["description"].is_string(), "{name}");
    }
    assert_eq!(
        vars.contains_key("RF_FAULT"),
        cfg!(feature = "fault-injection")
    );
    if let Some(fault) = vars.get("RF_FAULT") {
        assert_eq!(fault["test_only"], true);
    }

    // Each verb declares description, mutates and its own exits.
    for (name, verb) in caps["verbs"].as_object().expect("verbs") {
        assert!(verb["description"].is_string(), "{name}");
        assert!(verb.get("summary").is_none(), "{name}");
        assert_eq!(verb["mutates"], false, "{name}");
        assert!(verb["exit_codes"].is_array(), "{name}");
    }
    assert_eq!(
        caps["verbs"]["content"]["exit_codes"],
        serde_json::json!([0, 1, 5])
    );
}

#[test]
fn stale_cursor_names_its_own_remedy() {
    let dir = unique_temp("stale-cursor");
    std::fs::write(dir.join("a.txt"), "needle\n").unwrap();
    std::fs::write(dir.join("b.txt"), "needle\n").unwrap();
    let (code, page, _) = rf(
        &["--json", "content", "--limit", "1", "needle", "."],
        Some(&dir),
        &[],
    );
    assert_eq!(code, 0);
    let cursor = page["meta"]["pagination"]["cursor"]
        .as_str()
        .expect("cursor")
        .to_string();
    std::fs::write(dir.join("c.txt"), "needle\n").unwrap();
    let (code, stale, _) = rf(
        &[
            "--json", "content", "--limit", "1", "--cursor", &cursor, "needle", ".",
        ],
        Some(&dir),
        &[],
    );
    assert_eq!(code, 5);
    assert_eq!(stale["errors"][0]["code"], "CONFLICT");
    assert_eq!(
        stale["errors"][0]["remediation"],
        "Restart the query without --cursor."
    );
}

// --- Paths, child programs and doctor health (make-cli 0.1.0 exit dictionary) ---

#[test]
fn missing_and_unreadable_paths_are_typed() {
    use std::os::unix::fs::PermissionsExt;
    let root = unique_temp("paths");
    std::fs::write(root.join("a.txt"), "hello\n").unwrap();
    std::fs::write(root.join("locked.txt"), "hello\n").unwrap();
    std::fs::create_dir(root.join("only")).unwrap();
    std::fs::write(root.join("only").join("locked.txt"), "hello\n").unwrap();
    let lock = |path: &Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    lock(&root.join("locked.txt"), 0o000);
    lock(&root.join("only").join("locked.txt"), 0o000);
    let cwd = Some(root.as_path());

    // A path that does not exist: NOT_FOUND, exit 1, and the argument is named.
    for (args, arg) in [
        (vec!["content", "hello", "absent", "--json"], "path"),
        (
            vec!["find", "hello", "absent", "--name", "txt", "--json"],
            "path",
        ),
        (vec!["doctor", "absent", "--json"], "path"),
        (vec!["why", "hello", "absent", "--json"], "file"),
        (
            vec!["why", "hello", "a.txt", "--root", "absent", "--json"],
            "--root",
        ),
    ] {
        let (code, env, _) = rf(&args, cwd, &[]);
        let entry = &env["errors"][0];
        assert_eq!(code, 1, "{args:?}");
        assert_eq!(entry["code"], "NOT_FOUND", "{args:?}");
        assert_eq!(entry["arg"], arg, "{args:?}");
        assert_eq!(entry["exit_code"], 1, "{args:?}");
        assert!(env["data"].is_null(), "{args:?}");
    }

    // A path that exists and cannot be read: IO_FAILURE, exit 3, with the
    // operation, the absolute file and the errno name.
    let absolute = std::fs::canonicalize(&root).unwrap();
    for args in [
        vec!["why", "hello", "locked.txt", "--json"],
        vec!["content", "hello", "only", "--json"],
    ] {
        let (code, env, _) = rf(&args, cwd, &[]);
        let entry = &env["errors"][0];
        assert_eq!(code, 3, "{args:?} {env}");
        assert_eq!(entry["code"], "IO_FAILURE", "{args:?}");
        assert_eq!(entry["details"]["os_error"], "EACCES", "{args:?}");
        assert!(entry["details"]["op"].is_string(), "{args:?}");
        let file = entry["details"]["file"].as_str().unwrap_or("");
        assert!(
            Path::new(file).is_absolute() && file.ends_with("locked.txt"),
            "{args:?} file={file} root={}",
            absolute.display()
        );
        assert!(entry["path"].is_null(), "path is a JSONPath, never a file");
    }

    // Some files read and some not: the result stands, with a warning that
    // names each file that was skipped.
    for args in [
        vec!["content", "hello", ".", "--json"],
        vec!["find", "hello", ".", "--name", "txt", "--json"],
    ] {
        let (code, env, _) = rf(&args, cwd, &[]);
        assert_eq!(code, 0, "{args:?} {env}");
        assert_eq!(env["ok"], true, "{args:?}");
        let partial = env["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|warning| warning["code"] == "PARTIAL_RESULT")
            .unwrap_or_else(|| panic!("no PARTIAL_RESULT: {args:?} {env}"));
        let files: Vec<&str> = partial["details"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(files, ["locked.txt", "only/locked.txt"], "{args:?}");
        assert!(
            env["data"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["file"] == "a.txt"),
            "{args:?} {env}"
        );
    }

    lock(&root.join("locked.txt"), 0o644);
    lock(&root.join("only").join("locked.txt"), 0o644);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn doctor_reports_faulty_components_with_exit_six() {
    let root = unique_temp("doctor-health");
    let bin = root.join("bin");
    std::fs::create_dir(&bin).unwrap();

    // Both tools absent: two degraded components, in component-name order.
    let (code, env, _) = rf(
        &["doctor", ".", "--json"],
        None,
        &[("PATH", "/no/such/path")],
    );
    assert_eq!(code, 6);
    assert_eq!(env["ok"], false);
    assert_eq!(env["data"]["overall"], "degraded");
    assert!(
        env["data"]["external_tools"].is_object(),
        "the report stays"
    );
    let listed = |env: &Value| -> Vec<(String, String)> {
        env["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    entry["code"].as_str().unwrap_or("").to_string(),
                    entry["details"]["component"]
                        .as_str()
                        .unwrap_or("")
                        .to_string(),
                )
            })
            .collect()
    };
    assert_eq!(
        listed(&env),
        [
            ("COMPONENT_DEGRADED".to_string(), "ast-grep".to_string()),
            ("COMPONENT_DEGRADED".to_string(), "git".to_string()),
        ]
    );
    for entry in env["errors"].as_array().unwrap() {
        assert_eq!(entry["exit_code"], 6);
        assert!(entry["remediation"].is_string());
    }

    // git present and broken, ast-grep absent: the unhealthy group goes first.
    executable(&bin.join("git"), "#!/bin/sh\nexit 1\n");
    let fake_path = bin.to_string_lossy().into_owned();
    let (code, env, _) = rf(&["doctor", ".", "--json"], None, &[("PATH", &fake_path)]);
    assert_eq!(code, 6);
    assert_eq!(env["data"]["overall"], "unhealthy");
    assert_eq!(env["data"]["external_tools"]["git"]["state"], "unhealthy");
    assert_eq!(
        env["data"]["external_tools"]["ast-grep"]["state"],
        "degraded"
    );
    assert_eq!(
        listed(&env),
        [
            ("COMPONENT_UNHEALTHY".to_string(), "git".to_string()),
            ("COMPONENT_DEGRADED".to_string(), "ast-grep".to_string()),
        ]
    );

    // Both tools answer: healthy, exit 0, no errors.
    executable(
        &bin.join("git"),
        "#!/bin/sh\nprintf 'git version test\\n'\n",
    );
    executable(
        &bin.join("ast-grep"),
        "#!/bin/sh\nprintf 'ast-grep test\\n'\n",
    );
    let (code, env, _) = rf(&["doctor", ".", "--json"], None, &[("PATH", &fake_path)]);
    assert_eq!(code, 0, "{env}");
    assert_eq!(env["ok"], true);
    assert_eq!(env["data"]["overall"], "healthy");
    assert_eq!(env["errors"], serde_json::json!([]));
    let _ = std::fs::remove_dir_all(root);
}

/// The JSON type name of a value, as JSON Schema spells it.
fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Check `value` against `schema`. This covers the JSON Schema keywords that
/// rf's output schemas use; each fault is one line in `faults`.
fn check_schema(schema: &Value, value: &Value, at: &str, faults: &mut Vec<String>) {
    let kind = json_kind(value);
    let allowed: Vec<&str> = match &schema["type"] {
        Value::String(one) => vec![one.as_str()],
        Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    if !allowed.is_empty() && !allowed.contains(&kind) {
        faults.push(format!("{at}: type {kind} is not in {allowed:?}"));
        return;
    }
    if let Some(values) = schema["enum"].as_array() {
        if !values.contains(value) {
            faults.push(format!("{at}: {value} is not in the enum"));
        }
    }
    if let (Some(minimum), Some(number)) = (schema["minimum"].as_i64(), value.as_i64()) {
        if number < minimum {
            faults.push(format!("{at}: {number} is less than {minimum}"));
        }
    }
    if let (Some(maximum), Some(number)) = (schema["maximum"].as_i64(), value.as_i64()) {
        if number > maximum {
            faults.push(format!("{at}: {number} is more than {maximum}"));
        }
    }
    if let Some(items) = value.as_array() {
        if let Some(max) = schema["maxItems"].as_u64() {
            if items.len() as u64 > max {
                faults.push(format!("{at}: more than {max} items"));
            }
        }
        if schema["items"].is_object() {
            for (index, item) in items.iter().enumerate() {
                check_schema(&schema["items"], item, &format!("{at}[{index}]"), faults);
            }
        }
    }
    if let Some(object) = value.as_object() {
        for key in schema["required"].as_array().into_iter().flatten() {
            let key = key.as_str().unwrap();
            if !object.contains_key(key) {
                faults.push(format!("{at}.{key}: absent"));
            }
        }
        for (key, child) in object {
            let here = format!("{at}.{key}");
            if let Some(property) = schema["properties"].get(key) {
                check_schema(property, child, &here, faults);
            } else if schema["additionalProperties"].is_object() {
                check_schema(&schema["additionalProperties"], child, &here, faults);
            } else if schema["additionalProperties"] == false {
                faults.push(format!("{here}: not declared"));
            }
        }
    }
}

/// The make-cli X-07 rules on a declared schema: every declared key is in
/// `required`, and a `line` or column key has minimum 1.
fn check_declaration(schema: &Value, at: &str, faults: &mut Vec<String>) {
    if let Some(properties) = schema["properties"].as_object() {
        let required: BTreeSet<&str> = schema["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for (key, property) in properties {
            let here = format!("{at}.{key}");
            // `commands` is an envelope key; the envelope schema requires it.
            if !required.contains(key.as_str()) && here != "$.commands" {
                faults.push(format!("{here}: declared and not required"));
            }
            if matches!(key.as_str(), "line" | "col" | "column_byte") && property["minimum"] != 1 {
                faults.push(format!("{here}: minimum is not 1"));
            }
            if matches!(key.as_str(), "index" | "offset") && property["minimum"] != 0 {
                faults.push(format!("{here}: minimum is not 0"));
            }
            check_declaration(property, &here, faults);
        }
    }
    for key in ["items", "additionalProperties"] {
        if schema[key].is_object() {
            check_declaration(&schema[key], &format!("{at}[]"), faults);
        }
    }
}

#[test]
fn output_matches_the_declared_schema_with_every_key_present() {
    let (_, caps, _) = rf(&["capabilities", "--json"], None, &[]);
    let verbs = &caps["data"]["verbs"];
    let schema_of = |verb: &str| -> Value {
        let schema = if verb == "robot-docs guide" {
            &verbs["robot-docs"]["subcommands"]["guide"]["output_schema"]
        } else {
            &verbs[verb]["output_schema"]
        };
        assert!(schema.is_object(), "{verb}: no output_schema");
        schema.clone()
    };

    let mut faults = Vec::new();
    for verb in [
        "content",
        "find",
        "why",
        "doctor",
        "conformance",
        "robot-docs guide",
    ] {
        check_declaration(&schema_of(verb), "$", &mut faults);
    }
    assert!(faults.is_empty(), "schema declarations: {faults:#?}");

    let corpus = Corpus::new();
    let find_corpus = FindCorpus::new();
    let tree = Some(corpus.path.as_path());
    let find_tree = Some(find_corpus.path.as_path());
    let selected = b"src/app.py\0secrets.env\0";
    let mut replies: Vec<(&str, String, Value)> = Vec::new();
    let mut run = |verb: &'static str, args: &[&str], cwd: Option<&Path>, input: Option<&[u8]>| {
        let (code, reply, raw) = match input {
            Some(bytes) => rf_with_input(args, cwd, bytes),
            None => rf(args, cwd, &[]),
        };
        assert!(reply["data"].is_object(), "{args:?}: exit {code}: {raw}");
        replies.push((verb, format!("{args:?}"), reply));
    };
    run("content", &["content", TOKEN, ".", "--json"], tree, None);
    run(
        "content",
        &["content", TOKEN, ".", "--matches", "--json"],
        tree,
        None,
    );
    run(
        "content",
        &["content", TOKEN, ".", "--paths-stdin", "--json"],
        tree,
        Some(selected),
    );
    run(
        "find",
        &["find", TOKEN, ".", "--name", "config", "--json"],
        find_tree,
        None,
    );
    run(
        "find",
        &[
            "find",
            TOKEN,
            ".",
            "--name",
            "config",
            "--matches",
            "--json",
        ],
        find_tree,
        None,
    );
    for file in [
        "src/app.py",
        "secrets.env",
        ".hidden.txt",
        "config_utf16.txt",
    ] {
        run("why", &["why", TOKEN, file, "--json"], tree, None);
        run(
            "why",
            &["why", TOKEN, file, "--matches", "--json"],
            tree,
            None,
        );
    }
    run(
        "why",
        &["why", "NO_SUCH_TOKEN", "src/app.py", "--json"],
        tree,
        None,
    );
    run("doctor", &["doctor", "--json"], tree, None);
    run("conformance", &["conformance", "--json"], None, None);
    run(
        "robot-docs guide",
        &["robot-docs", "guide", "--json"],
        None,
        None,
    );

    for (verb, argv, reply) in &replies {
        check_schema(
            &schema_of(verb),
            reply,
            &format!("{verb} {argv}"),
            &mut faults,
        );
    }
    assert!(faults.is_empty(), "replies: {faults:#?}");
}

/// A pattern that does not compile is refused by each search verb. This was
/// case R-01 of the old self-check; it is not a make-cli case.
#[test]
fn bad_pattern_is_refused_by_each_search_verb() {
    for argv in [
        vec!["content", "[", ".", "--json"],
        vec!["find", "[", ".", "--name", "rs", "--json"],
    ] {
        let (code, e, _) = rf(&argv, None, &[]);
        assert_eq!(code, 1, "{argv:?}");
        assert_eq!(e["ok"], false, "{argv:?}");
        assert_eq!(e["errors"][0]["code"], "BAD_PATTERN", "{argv:?}");
    }
}
