//! The universal machine-first envelope: the fixed 7-key contract every verb emits.
//!
//! Every verb emits the same seven keys: ok, tool_version, data, meta,
//! warnings, commands, errors. `meta` is content-addressed and honors
//! SOURCE_DATE_EPOCH, so a given input yields byte-identical output.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CONTRACT_VERSION: &str = "2";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

fn sha_hex(input: &str) -> String {
    Sha256::digest(input.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Full SHA-256 for a canonical JSON value. Paging cursors use this as an
/// opaque binding, so no query input or filesystem name appears in the cursor.
pub fn hash_value(value: &Value) -> String {
    sha_hex(&serde_json::to_string(value).unwrap_or_default())
}

/// Full SHA-256 for sorted result rows. The envelope itself publishes a short
/// form as `meta.data_hash`; snapshot paging needs the full collision-resistant
/// binding and therefore uses this public helper.
pub fn hash_data(data: &[Value]) -> String {
    sha_hex(&format!("{:?}", canonical(data)))
}

/// Canonical, sorted serialization of the data array. serde_json backs objects
/// with a BTreeMap (no preserve_order feature), so keys are already sorted; we
/// only sort the elements against each other. This is the determinism anchor.
fn canonical(data: &[Value]) -> Vec<String> {
    let mut v: Vec<String> = data
        .iter()
        .map(|d| serde_json::to_string(d).unwrap_or_default())
        .collect();
    v.sort();
    v
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    // Howard Hinnant's days->civil algorithm (proleptic Gregorian).
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn now_iso() -> String {
    let secs: i64 = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        });
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Build the full envelope value. `meta_extra` carries verb-specific fields
/// (verb, headline, counts) merged over the base content-addressed meta.
pub fn envelope(
    ok: bool,
    data: Vec<Value>,
    meta_extra: Map<String, Value>,
    warnings: Vec<Value>,
    commands: Vec<String>,
    errors: Vec<Value>,
) -> Value {
    let argv: Vec<String> = std::env::args().collect();
    let body = canonical(&data);
    let body_repr = format!("{body:?}");

    let mut meta = Map::new();
    meta.insert(
        "request_id".into(),
        Value::from(sha_hex(&format!("{} {}", argv.join(" "), body_repr))[..16].to_string()),
    );
    meta.insert("ts_iso".into(), Value::from(now_iso()));
    meta.insert("contract_version".into(), Value::from(CONTRACT_VERSION));
    // This is finalized by the top-level emitter, which owns the wall-clock
    // measurement. Keeping the key here means every envelope has the same
    // meta floor, including errors made below the dispatcher.
    meta.insert("elapsed_ms".into(), Value::from(0));
    meta.insert(
        "data_hash".into(),
        Value::from(hash_data(&data)[..12].to_string()),
    );
    for (k, v) in meta_extra {
        meta.insert(k, v);
    }

    let mut root = Map::new();
    root.insert("ok".into(), Value::from(ok));
    root.insert("tool_version".into(), Value::from(TOOL_VERSION));
    // An empty array means a successful query found nothing. A failed request
    // did not produce a result, so it is deliberately distinguishable as null.
    root.insert(
        "data".into(),
        if ok { Value::from(data) } else { Value::Null },
    );
    root.insert("meta".into(), Value::from(meta));
    root.insert("warnings".into(), Value::from(warnings));
    root.insert(
        "commands".into(),
        Value::from(commands.into_iter().map(Value::from).collect::<Vec<_>>()),
    );
    root.insert("errors".into(), Value::from(errors));
    Value::from(root)
}

/// A single common error object. `emit` fills `exit_code`, because it is the
/// top-level owner of the process status.
pub fn err(code: &str, message: impl Into<String>) -> Value {
    let mut m = Map::new();
    m.insert("code".into(), Value::from(code));
    m.insert("message".into(), Value::from(message.into()));
    m.insert("path".into(), Value::Null);
    m.insert(
        "remediation".into(),
        Value::from("Run `rf --help` for command syntax."),
    );
    m.insert("did_you_mean".into(), Value::Null);
    m.insert("exit_code".into(), Value::Null);
    Value::from(m)
}

/// Build an error with a caller-specific path and remediation. This preserves
/// the common envelope shape while allowing a command to report a precise
/// validation failure instead of generic command syntax.
pub fn err_with(
    code: &str,
    message: impl Into<String>,
    path: impl Into<String>,
    remediation: impl Into<String>,
) -> Value {
    let mut value = err(code, message);
    let object = value.as_object_mut().expect("error is an object");
    object.insert("path".into(), Value::from(path.into()));
    object.insert("remediation".into(), Value::from(remediation.into()));
    value
}

/// A single warning entry {code, msg, files}.
pub fn warn(code: &str, msg: impl Into<String>, files: Vec<String>) -> Value {
    let mut m = Map::new();
    m.insert("code".into(), Value::from(code));
    m.insert("msg".into(), Value::from(msg.into()));
    m.insert(
        "files".into(),
        Value::from(files.into_iter().map(Value::from).collect::<Vec<_>>()),
    );
    Value::from(m)
}
