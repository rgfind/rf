//! Shared query-mode contract for content-bearing commands.

use serde_json::{json, Value};

/// Effective matching semantics selected by the caller.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueryMode {
    pub fixed_strings: bool,
    pub word: bool,
    pub case_insensitive: bool,
}

impl QueryMode {
    pub fn new(fixed_strings: bool, word: bool, ignore_case: bool) -> Self {
        Self {
            fixed_strings,
            word,
            case_insensitive: ignore_case,
        }
    }

    pub fn metadata(self) -> Value {
        json!({
            "syntax": if self.fixed_strings { "fixed" } else { "regex" },
            "word": self.word,
            "case": if self.case_insensitive { "insensitive" } else { "sensitive" },
        })
    }

    /// The canonical pagination representation deliberately omits the default
    /// so old default cursors remain valid.
    pub fn pagination_value(self) -> Option<Value> {
        (!self.is_default()).then(|| self.metadata())
    }

    pub fn is_default(self) -> bool {
        !self.fixed_strings && !self.word && !self.case_insensitive
    }

    pub fn rg_args(self, explicit_case_sensitive: bool) -> Vec<String> {
        let mut args = Vec::new();
        if self.fixed_strings {
            args.push("-F".into());
        }
        if self.word {
            args.push("-w".into());
        }
        if self.case_insensitive {
            args.push("-i".into());
        } else if explicit_case_sensitive {
            args.push("-s".into());
        }
        args
    }

    pub fn git_grep_args(self, explicit_case_sensitive: bool) -> Vec<String> {
        let mut args = Vec::new();
        if self.fixed_strings {
            args.push("-F".into());
        }
        if self.word {
            args.push("-w".into());
        }
        if self.case_insensitive {
            args.push("-i".into());
        } else if explicit_case_sensitive {
            args.push("--no-ignore-case".into());
        }
        args
    }
}
