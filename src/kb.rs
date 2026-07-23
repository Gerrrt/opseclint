//! Knowledge-base loading and matching. Each platform's KB is embedded at
//! compile time so the tool ships as a single self-contained binary.

use clap::ValueEnum;

use crate::model::{KbEntry, KnowledgeBase};
use crate::parser::Command;

const EMBEDDED_LINUX: &str = include_str!("../data/knowledge.json");
const EMBEDDED_WINDOWS: &str = include_str!("../data/knowledge-windows.json");

/// The host platform / telemetry model an analysis targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Platform {
    /// Linux hosts with auditd / EDR syscall telemetry.
    #[value(name = "linux-auditd", alias = "linux")]
    LinuxAuditd,
    /// Windows hosts with Sysmon / Security-log telemetry.
    #[value(name = "windows-sysmon", alias = "windows")]
    WindowsSysmon,
}

impl Platform {
    /// The Sigma `logsource.product` value to filter rules by for this platform.
    pub fn sigma_product(self) -> &'static str {
        match self {
            Platform::LinuxAuditd => "linux",
            Platform::WindowsSysmon => "windows",
        }
    }
}

/// Load the embedded knowledge base for a platform.
pub fn load(platform: Platform) -> Result<KnowledgeBase, serde_json::Error> {
    let raw = match platform {
        Platform::LinuxAuditd => EMBEDDED_LINUX,
        Platform::WindowsSysmon => EMBEDDED_WINDOWS,
    };
    serde_json::from_str(raw)
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
