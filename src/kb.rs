//! Knowledge-base loading and matching. The KB is embedded at compile time so
//! the tool ships as a single self-contained binary.

use crate::model::{KbEntry, KnowledgeBase};
use crate::parser::Command;

const EMBEDDED_KB: &str = include_str!("../data/knowledge.json");

/// Load the embedded knowledge base.
pub fn load() -> Result<KnowledgeBase, serde_json::Error> {
    serde_json::from_str(EMBEDDED_KB)
}

/// Does `entry` apply to `cmd` within its raw line?
///
/// Command-scoped entries (those with a `command`) require the program to
/// match and any `args_contains` / `raw_contains` refinements to hold.
pub fn command_entry_matches(entry: &KbEntry, cmd: &Command) -> bool {
    let Some(want) = &entry.command else {
        return false;
    };
    if cmd.program.to_lowercase() != want.to_lowercase() {
        return false;
    }
    if let Some(sub) = &entry.args_contains
        && !cmd.args_joined().contains(&sub.to_lowercase())
    {
        return false;
    }
    if let Some(rc) = &entry.raw_contains
        && !cmd.raw.to_lowercase().contains(&rc.to_lowercase())
    {
        return false;
    }
    true
}

/// Does a raw-only entry (no `command`) apply to this line?
pub fn raw_entry_matches(entry: &KbEntry, raw_line: &str) -> bool {
    if entry.command.is_some() {
        return false;
    }
    match &entry.raw_contains {
        Some(rc) => raw_line.to_lowercase().contains(&rc.to_lowercase()),
        None => false,
    }
}
