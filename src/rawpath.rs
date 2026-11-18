//! A discovered path, kept as its raw bytes.
//!
//! A file name on Unix is bytes, not text. rf keys every result set by these
//! bytes, so two names that differ only in bytes that are not UTF-8 stay two
//! results. Text is made only at the output edge: `display` gives the lossy
//! name for `file`, and `bytes_hex` gives the exact bytes when that name is
//! lossy.

use serde_json::Value;
use std::path::{Path, PathBuf};

/// Byte order. For valid UTF-8 this is the same order as `String`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawPath(Vec<u8>);

impl RawPath {
    pub fn from_bytes(bytes: Vec<u8>) -> RawPath {
        RawPath(bytes)
    }

    /// The bytes of `path`. Off Unix, the lossy text with `/` separators.
    pub fn from_path(path: &Path) -> RawPath {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            RawPath(path.as_os_str().as_bytes().to_vec())
        }
        #[cfg(not(unix))]
        {
            RawPath(path.to_string_lossy().replace('\\', "/").into_bytes())
        }
    }

    /// Lowercase hex, two digits per byte. None for odd length or a bad digit.
    pub fn from_hex(hex: &str) -> Option<RawPath> {
        // `from_str_radix` takes a leading `+`; only hex digits are allowed.
        if !hex.len().is_multiple_of(2) || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let digits = hex.as_bytes();
        let mut bytes = Vec::with_capacity(digits.len() / 2);
        for pair in digits.chunks(2) {
            let text = std::str::from_utf8(pair).ok()?;
            bytes.push(u8::from_str_radix(text, 16).ok()?);
        }
        Some(RawPath(bytes))
    }

    /// The path of a result row: `file_bytes_hex` when it is set, else `file`.
    pub fn from_row(row: &Value) -> RawPath {
        row["file_bytes_hex"]
            .as_str()
            .and_then(RawPath::from_hex)
            .unwrap_or_else(|| RawPath(row["file"].as_str().unwrap_or("").as_bytes().to_vec()))
    }

    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A path to open. Off Unix, the bytes are UTF-8 by construction.
    pub fn to_path_buf(&self) -> PathBuf {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            PathBuf::from(std::ffi::OsStr::from_bytes(&self.0))
        }
        #[cfg(not(unix))]
        {
            PathBuf::from(String::from_utf8_lossy(&self.0).into_owned())
        }
    }

    /// The `file` text: each byte run that is not UTF-8 becomes U+FFFD.
    pub fn display(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }

    /// The `file_bytes_hex` value: None when the name is valid UTF-8.
    pub fn bytes_hex(&self) -> Option<String> {
        std::str::from_utf8(&self.0).is_err().then(|| hex(&self.0))
    }

    /// `file_bytes_hex` as a row value.
    pub fn bytes_hex_value(&self) -> Value {
        self.bytes_hex().map(Value::from).unwrap_or(Value::Null)
    }

    /// Text for people and messages: each byte that is not UTF-8 becomes
    /// `\xNN`, the form argv errors use.
    pub fn escaped(&self) -> String {
        escaped(&self.0)
    }

    /// Strip a leading `./`: the walked form when the root is ".".
    pub fn strip_dot(self) -> RawPath {
        match self.0.strip_prefix(b"./") {
            Some(rest) => RawPath(rest.to_vec()),
            None => self,
        }
    }

    /// The path relative to the search root, so walker paths line up with
    /// the root-relative paths that Git reports.
    pub fn rel(&self, root: &str) -> RawPath {
        let full = self.0.strip_prefix(b"./").unwrap_or(&self.0);
        let root = root.strip_suffix('/').unwrap_or(root);
        if root == "." || root.is_empty() {
            return RawPath(full.to_vec());
        }
        match full.strip_prefix(root.as_bytes()) {
            Some(rest) => {
                let start = rest.iter().take_while(|byte| **byte == b'/').count();
                RawPath(rest[start..].to_vec())
            }
            None => RawPath(full.to_vec()),
        }
    }

    /// The root-relative path `self` joined under `root` again.
    pub fn under(&self, root: &str) -> RawPath {
        if root == "." || root.is_empty() {
            return self.clone();
        }
        let mut bytes = root.trim_end_matches('/').as_bytes().to_vec();
        bytes.push(b'/');
        bytes.extend_from_slice(&self.0);
        RawPath(bytes)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn escaped(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for byte in chunk.invalid() {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    out
}

/// Display names of a set, in its order.
pub fn displays<'a>(paths: impl IntoIterator<Item = &'a RawPath>) -> Vec<String> {
    paths.into_iter().map(RawPath::display).collect()
}

#[cfg(test)]
mod tests {
    use super::RawPath;

    #[test]
    fn names_that_differ_in_bytes_stay_apart_and_round_trip() {
        let a = RawPath::from_bytes(b"caf\xe9.txt".to_vec());
        let b = RawPath::from_bytes(b"caf\xea.txt".to_vec());
        assert_ne!(a, b);
        assert_eq!(a.display(), b.display());
        assert_eq!(a.bytes_hex().as_deref(), Some("636166e92e747874"));
        assert_eq!(RawPath::from_hex("636166e92e747874"), Some(a.clone()));
        assert_eq!(a.escaped(), "caf\\xe9.txt");
        let plain = RawPath::from_bytes(b"src/a.txt".to_vec());
        assert_eq!(plain.bytes_hex(), None);
        assert_eq!(RawPath::from_hex("zz"), None);
        assert_eq!(RawPath::from_hex("abc"), None);
        assert_eq!(RawPath::from_hex("+a"), None);
    }

    #[test]
    fn rel_and_under_match_the_text_forms() {
        let full = RawPath::from_bytes(b"./root/sub/a.txt".to_vec());
        assert_eq!(full.rel("root").as_bytes(), b"sub/a.txt");
        assert_eq!(full.rel("root/").as_bytes(), b"sub/a.txt");
        assert_eq!(full.rel(".").as_bytes(), b"root/sub/a.txt");
        let rel = RawPath::from_bytes(b"sub/a.txt".to_vec());
        assert_eq!(rel.under("root/").as_bytes(), b"root/sub/a.txt");
        assert_eq!(rel.under(".").as_bytes(), b"sub/a.txt");
    }
}
