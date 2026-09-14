use crate::envelope::envelope;
use serde_json::{json, Map, Value};

pub fn run(compact: bool) -> (Value, i32) {
    let recipes = vec![
        json!({"id":"content-forensics","goal":"find filtered content matches","inputs":["pattern","path"],"command":"'rf' 'content' '<pattern>' '--' '<path>' '--json'","expected_branch":"ok:true","version_range":"2"}),
        json!({"id":"query-modes","goal":"use literal, whole-word, or case-insensitive content matching","inputs":["pattern","path","mode"],"command":"'rf' 'content' '--fixed-strings' '--ignore-case' '<pattern>' '--' '<path>' '--json'","expected_branch":"meta.query","version_range":"2"}),
        json!({"id":"ignore-provenance","goal":"identify the ignore rule that hid one matching file","inputs":["pattern","file","root"],"command":"'rf' 'why' '<pattern>' '<file>' '--root' '<root>' '--json'","expected_branch":"data[0].ignore_source when surfaced_by=vcs_ignore","version_range":"2"}),
        json!({"id":"history-forensics","goal":"find removed history matches","inputs":["pattern","path","name"],"command":"'rf' 'find' '<pattern>' '--name' '<name>' '--' '<path>' '--json'","expected_branch":"meta.history","version_range":"2"}),
    ];
    let mut meta = Map::new();
    meta.insert("verb".into(), Value::from("robot-docs guide"));
    meta.insert(
        "format".into(),
        Value::from(if compact { "index" } else { "guide" }),
    );
    (envelope(true, recipes, meta, vec![], vec![], vec![]), 0)
}
