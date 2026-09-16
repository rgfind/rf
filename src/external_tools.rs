//! Bounded probes and execution for optional external tools.

use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const PROBE_TIMEOUT: Duration = Duration::from_millis(2_000);
pub const PROBE_OUTPUT_BYTES: usize = 8_192;
pub const PROBE_ERROR_BYTES: usize = 512;
pub const STRUCTURAL_TIMEOUT: Duration = Duration::from_millis(5_000);
pub const STRUCTURAL_OUTPUT_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunState {
    Missing,
    TimedOut,
    Completed,
}

pub struct RunOutput {
    pub state: RunState,
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub output_truncated: bool,
}

fn read_capped(
    mut input: impl Read + Send + 'static,
    cap: usize,
) -> thread::JoinHandle<(Vec<u8>, bool)> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut truncated = false;
        loop {
            match input.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let remaining = cap.saturating_sub(bytes.len());
                    let take = remaining.min(count);
                    bytes.extend_from_slice(&buffer[..take]);
                    truncated |= take < count;
                }
            }
        }
        (bytes, truncated)
    })
}

pub fn resolved_path(tool: &str) -> Option<PathBuf> {
    if tool.contains(std::path::MAIN_SEPARATOR) {
        return Path::new(tool).is_file().then(|| PathBuf::from(tool));
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(tool))
            .find(|candidate| candidate.is_file())
    })
}

/// Run `program args` with independent byte caps for stdout and stderr.
/// Children are killed at the declared deadline; their output is never streamed
/// into an rf response before it has been bounded.
pub fn run_bounded(
    program: &Path,
    args: &[&str],
    cwd: Option<&str>,
    timeout: Duration,
    cap: usize,
) -> RunOutput {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RunOutput {
                state: RunState::Missing,
                success: false,
                stdout: vec![],
                stderr: vec![],
                output_truncated: false,
            };
        }
        Err(error) => {
            return RunOutput {
                state: RunState::Completed,
                success: false,
                stdout: vec![],
                stderr: error.to_string().into_bytes(),
                output_truncated: false,
            };
        }
    };
    let stdout = read_capped(child.stdout.take().expect("piped stdout"), cap);
    let stderr = read_capped(child.stderr.take().expect("piped stderr"), cap);
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= timeout => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => break None,
        }
    };
    let (stdout, stdout_truncated) = stdout.join().unwrap_or_default();
    let (stderr, stderr_truncated) = stderr.join().unwrap_or_default();
    RunOutput {
        state: if timed_out {
            RunState::TimedOut
        } else {
            RunState::Completed
        },
        success: status.is_some_and(|status| status.success()),
        stdout,
        stderr,
        output_truncated: stdout_truncated || stderr_truncated,
    }
}

fn clipped(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.char_indices()
        .take_while(|(offset, _)| *offset < PROBE_ERROR_BYTES)
        .map(|(_, c)| c)
        .collect()
}

/// A total, machine-readable health record for one optional binary.
pub fn probe(tool: &str) -> Value {
    let Some(path) = resolved_path(tool) else {
        return json!({"status":"missing","path":null,"version":null,"probe_error":null});
    };
    let output = run_bounded(
        &path,
        &["--version"],
        None,
        PROBE_TIMEOUT,
        PROBE_OUTPUT_BYTES,
    );
    match output.state {
        RunState::Missing => {
            json!({"status":"missing","path":null,"version":null,"probe_error":null})
        }
        RunState::TimedOut => {
            json!({"status":"timed_out","path":path,"version":null,"probe_error":"version probe exceeded 2000 ms"})
        }
        RunState::Completed if output.success && !output.stdout.is_empty() => {
            let version = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            json!({"status":"available","path":path,"version":version,"probe_error":null})
        }
        RunState::Completed => {
            let mut detail = clipped(if output.stderr.is_empty() {
                &output.stdout
            } else {
                &output.stderr
            });
            if detail.is_empty() {
                detail = "version probe returned no usable version".into();
            }
            if output.output_truncated {
                detail.push_str(" (output truncated)");
            }
            json!({"status":"unusable","path":path,"version":null,"probe_error":detail})
        }
    }
}
