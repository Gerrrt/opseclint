//! Rendering: a human-readable terminal report and a machine-readable JSON
//! form for CI consumption.

use std::fmt::Write as _;

use crate::model::{Report, Severity};

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";

/// Render the report for a terminal. `color` toggles ANSI escapes.
pub fn render_human(report: &Report, color: bool) -> String {
    let c = |code: &'static str| if color { code } else { "" };
    let mut out = String::new();

    let _ = writeln!(
        out,
        "{}opseclint{} — detection-coverage report ({})",
        c(BOLD),
        c(RESET),
        report.platform
    );
    let _ = writeln!(
        out,
        "{}{} line(s) analyzed, {} finding(s){}",
        c(DIM),
        report.lines_analyzed,
        report.findings.len(),
        c(RESET)
    );
    let _ = writeln!(out);

    if report.findings.is_empty() {
        let _ = writeln!(
            out,
            "  No modeled actions matched. (Absence of a finding is not proof of stealth —",
        );
        let _ = writeln!(
            out,
            "  it only means nothing in the seed knowledge base matched this input.)",
        );
        return out;
    }

    for f in &report.findings {
        let sev = f.severity;
        let _ = writeln!(
            out,
            "  {}L{:<4}{} {}[{} {}]{}  {}",
            c(DIM),
            f.line,
            c(RESET),
            c(sev.color()),
            sev.label(),
            f.noise,
            c(RESET),
            f.description,
        );
        for t in &f.techniques {
            let _ = writeln!(
                out,
                "        {}technique{}  {} {}",
                c(DIM),
                c(RESET),
                t.id,
                t.name
            );
        }
        for tel in &f.telemetry {
            let _ = writeln!(out, "        {}telemetry{}  {}", c(DIM), c(RESET), tel);
        }
        for d in &f.detections {
            let _ = writeln!(
                out,
                "        {}detection{}  {}: {} ({} confidence)",
                c(DIM),
                c(RESET),
                d.source,
                d.rule,
                d.confidence,
            );
        }
        let _ = writeln!(out);
    }

    let sev = report.max_severity();
    let _ = writeln!(
        out,
        "{}summary{}  loudest action: {}{} ({}){}",
        c(BOLD),
        c(RESET),
        c(sev.color()),
        sev.label(),
        report.max_noise,
        c(RESET),
    );
    if !report.note.is_empty() {
        let _ = writeln!(out, "\n{}{}{}", c(DIM), report.note, c(RESET));
    }
    out
}

/// Render the report as pretty JSON.
pub fn render_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// Human-readable one-liner for a severity, used in CI gate messages.
pub fn severity_word(sev: Severity) -> &'static str {
    sev.label()
}
