//! The universal machine-first envelope: the fixed 7-key contract every verb emits.
//!
//! Every verb emits the same seven keys: ok, tool_version, data, meta,
//! warnings, commands, errors. `data` is an object or null, never a bare
//! array. `meta.ts_iso` honors SOURCE_DATE_EPOCH; `meta.request_id` is unique
//! per invocation and `meta.data_hash` covers `data` only.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CONTRACT_VERSION: &str = "0.1";
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

/// A list payload: rows in `items`, the count of all matches in `total`.
/// `total` can exceed `items.len()` when a page bound clipped the rows.
pub fn list(items: Vec<Value>, total: usize) -> Value {
    let mut m = Map::new();
    m.insert("items".into(), Value::from(items));
    m.insert("total".into(), Value::from(total));
    Value::from(m)
}

/// `sha256:<64 hex>` over the compact, key-sorted JSON of `data`. serde_json
/// backs objects with a BTreeMap (no preserve_order feature), so its compact
/// form is already the canonical one that `capabilities` declares.
pub fn data_hash(data: &Value) -> String {
    format!("sha256:{}", hash_value(data))
}

/// An id that joins one invocation to its logs. Two calls never share one,
/// even with the same argv, so it mixes the process id, the clock and a
/// per-process counter. It is not derived from argv or data.
fn request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!(
        "{}:{nanos}:{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    format!("req_{}", &sha_hex(&seed)[..16])
}

/// Build the full envelope value. `data` is the verb payload: an object, or
/// `Value::Null` when the request produced no result. A failed request may
/// still carry a payload (a report with failing parts), so `ok` does not
/// decide whether `data` is kept. `meta_extra` carries verb-specific fields
/// (verb, headline, counts) merged over the base meta.
pub fn envelope(
    ok: bool,
    data: Value,
    meta_extra: Map<String, Value>,
    warnings: Vec<Value>,
    commands: Vec<String>,
    errors: Vec<Value>,
) -> Value {
    debug_assert!(
        data.is_object() || data.is_null(),
        "envelope data must be an object or null"
    );
    let mut meta = Map::new();
    meta.insert("request_id".into(), Value::from(request_id()));
    meta.insert("ts_iso".into(), Value::from(now_iso()));
    meta.insert("contract_version".into(), Value::from(CONTRACT_VERSION));
    // This is finalized by the top-level emitter, which owns the wall-clock
    // measurement. Keeping the key here means every envelope has the same
    // meta floor, including errors made below the dispatcher.
    meta.insert("elapsed_ms".into(), Value::from(0));
    meta.insert("data_hash".into(), Value::from(data_hash(&data)));
    for (k, v) in meta_extra {
        meta.insert(k, v);
    }

    let mut root = Map::new();
    root.insert("ok".into(), Value::from(ok));
    root.insert("tool_version".into(), Value::from(TOOL_VERSION));
    root.insert("data".into(), data);
    root.insert("meta".into(), Value::from(meta));
    root.insert("warnings".into(), Value::from(warnings));
    root.insert(
        "commands".into(),
        Value::from(commands.into_iter().map(Value::from).collect::<Vec<_>>()),
    );
    root.insert("errors".into(), Value::from(errors));
    Value::from(root)
}

/// A single common error object with the fixed eight keys. A key that does not
/// apply is null, never absent. `emit` fills `exit_code`, because it is the
/// top-level owner of the process status.
pub fn err(code: &str, message: impl Into<String>) -> Value {
    let mut m = Map::new();
    m.insert("code".into(), Value::from(code));
    m.insert("message".into(), Value::from(message.into()));
    m.insert("arg".into(), Value::Null);
    m.insert("path".into(), Value::Null);
    m.insert(
        "remediation".into(),
        Value::from(
            crate::registry::lookup(code)
                .and_then(|c| c.remediation)
                .unwrap_or("Run `rf --help` for command syntax."),
        ),
    );
    m.insert("did_you_mean".into(), Value::Null);
    m.insert("details".into(), Value::Null);
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

/// A single warning entry with the fixed three keys {code, message, details}.
/// The affected files go in `details.files`; `details` is null when there are
/// none.
pub fn warn(code: &str, message: impl Into<String>, files: Vec<String>) -> Value {
    let mut m = Map::new();
    m.insert("code".into(), Value::from(code));
    m.insert("message".into(), Value::from(message.into()));
    m.insert(
        "details".into(),
        if files.is_empty() {
            Value::Null
        } else {
            serde_json::json!({ "files": files })
        },
    );
    Value::from(m)
}
