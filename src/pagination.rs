//! Snapshot-bound, deterministic paging for result rows.

use crate::envelope::{hash_data, hash_value, CONTRACT_VERSION};
use serde_json::Value;

pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 1_000;
pub const MAX_EVIDENCE_RESPONSE_BYTES: usize = 32 * 1024;

pub fn limit(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "limit must be a positive integer".to_string())?;
    if parsed == 0 || parsed > MAX_LIMIT {
        Err(format!("limit must be from 1 to {MAX_LIMIT}"))
    } else {
        Ok(parsed)
    }
}

pub struct Page {
    pub data: Vec<Value>,
    pub total: usize,
    pub snapshot_hash: String,
    pub next_cursor: Option<String>,
}

pub enum Error {
    InvalidCursor,
    Conflict,
}

fn row_key(row: &Value) -> (&str, &str) {
    let attribution = row["stage"]
        .as_str()
        .or_else(|| row["surfaced_by"].as_str())
        .unwrap_or("");
    let path = row["file"].as_str().unwrap_or("");
    (attribution, path)
}

/// Return a page that is bound to the complete sorted result set. The cursor
/// contains only hashes and a row position: `v<contract>.<query>.<snapshot>.<position>`.
pub fn page(
    mut all: Vec<Value>,
    query: &Value,
    limit: usize,
    cursor: Option<&str>,
) -> Result<Page, Error> {
    all.sort_by(|a, b| row_key(a).cmp(&row_key(b)));
    let snapshot_hash = hash_data(&all);
    let query_hash = hash_value(query);
    let start = match cursor {
        None => 0,
        Some(cursor) => {
            let fields: Vec<&str> = cursor.split('.').collect();
            let expected_version = format!("v{CONTRACT_VERSION}");
            if fields.len() != 4
                || fields[0] != expected_version
                || fields[1] != query_hash
                || fields[2].len() != 64
                || !fields[2].bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(Error::InvalidCursor);
            }
            let position = fields[3]
                .parse::<usize>()
                .map_err(|_| Error::InvalidCursor)?;
            if position > all.len() {
                return Err(Error::InvalidCursor);
            }
            if fields[2] != snapshot_hash {
                return Err(Error::Conflict);
            }
            position
        }
    };
    let end = (start + limit).min(all.len());
    let next_cursor = (end < all.len())
        .then(|| format!("v{CONTRACT_VERSION}.{query_hash}.{snapshot_hash}.{end}"));
    Ok(Page {
        data: all[start..end].to_vec(),
        total: all.len(),
        snapshot_hash,
        next_cursor,
    })
}

/// Page evidence rows inside a fixed serialized-data budget. The cursor starts
/// at the first omitted row, so a later page cannot skip or repeat a row.
pub fn page_evidence(
    mut all: Vec<Value>,
    query: &Value,
    limit: usize,
    cursor: Option<&str>,
) -> Result<Page, Error> {
    all.sort_by(|a, b| row_key(a).cmp(&row_key(b)));
    let snapshot_hash = hash_data(&all);
    let query_hash = hash_value(query);
    let start = match cursor {
        None => 0,
        Some(cursor) => {
            let fields: Vec<&str> = cursor.split('.').collect();
            let expected_version = format!("v{CONTRACT_VERSION}");
            if fields.len() != 4
                || fields[0] != expected_version
                || fields[1] != query_hash
                || fields[2].len() != 64
                || !fields[2].bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(Error::InvalidCursor);
            }
            let position = fields[3]
                .parse::<usize>()
                .map_err(|_| Error::InvalidCursor)?;
            if position > all.len() {
                return Err(Error::InvalidCursor);
            }
            if fields[2] != snapshot_hash {
                return Err(Error::Conflict);
            }
            position
        }
    };
    let hard_end = (start + limit).min(all.len());
    let mut bytes = 2usize;
    let mut end = start;
    while end < hard_end {
        let row_bytes = serde_json::to_vec(&all[end]).unwrap_or_default().len();
        let separator = usize::from(end > start);
        if end > start && bytes + separator + row_bytes > MAX_EVIDENCE_RESPONSE_BYTES {
            break;
        }
        bytes += separator + row_bytes;
        end += 1;
    }
    if end == start && start < hard_end {
        end += 1;
    }
    let next_cursor = (end < all.len())
        .then(|| format!("v{CONTRACT_VERSION}.{query_hash}.{snapshot_hash}.{end}"));
    Ok(Page {
        data: all[start..end].to_vec(),
        total: all.len(),
        snapshot_hash,
        next_cursor,
    })
}
