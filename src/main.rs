//! opseclint — a detection-coverage analyzer for Linux/auditd and
//! Windows/Sysmon.
//!
//! Point it at a command, a script, or a playbook and it statically resolves
//! each action to the ATT&CK technique(s) it implements, the host telemetry it
//! emits, and the detections that would fire — with a detectability score.
//! It answers "what would a defender see?", to help red/purple teams and
//! detection engineers reason about coverage. It does not recommend evasions.

mod analyzer;
mod kb;
mod model;
mod parser;
mod report;
mod sarif;
mod sigma;

use std::io::{IsTerminal, Read};
use std::process::ExitCode;

use clap::Parser;

/// Detection-coverage analyzer: shell actions -> ATT&CK -> telemetry -> detections.
#[derive(Parser, Debug)]
#[command(name = "opseclint", version, about, long_about = None)]
struct Cli {
    /// Path to a script or playbook to analyze. Reads stdin if omitted and
    /// --command is not given.
    path: Option<String>,

    /// Analyze a single command string instead of a file.
    #[arg(short, long)]
    command: Option<String>,

    /// Target platform / telemetry model.
    #[arg(long, value_enum, default_value = "linux-auditd")]
    platform: kb::Platform,

    /// Emit machine-readable JSON instead of a terminal report.
    #[arg(long)]
    json: bool,

    /// Emit SARIF 2.1.0 (for GitHub code scanning / SARIF-aware tools).
    #[arg(long, conflicts_with = "json")]
    sarif: bool,

    /// Only report findings at or above this detectability score (0-100).
    #[arg(long, default_value_t = 0)]
    min: u8,

    /// CI gate: exit non-zero if any finding's detectability is >= --threshold.
    #[arg(long)]
    ci: bool,

    /// Detectability threshold used by --ci (0-100).
    #[arg(long, default_value_t = 50)]
    threshold: u8,

    /// Force-disable ANSI color (color is auto-disabled when not a TTY).
    #[arg(long)]
    no_color: bool,

    /// Enrich findings with real rules from a SigmaHQ checkout (directory of
    /// Sigma YAML). Matched by ATT&CK technique; Linux-relevant rules only.
    #[arg(long, value_name = "DIR")]
    sigma: Option<String>,
}

fn read_input(cli: &Cli) -> std::io::Result<String> {
    if let Some(cmd) = &cli.command {
        return Ok(cmd.clone());
    }
    if let Some(path) = &cli.path {
        return std::fs::read_to_string(path);
    }
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let kb = match kb::load(cli.platform) {
        Ok(kb) => kb,
        Err(e) => {
            eprintln!("opseclint: failed to load knowledge base: {e}");
            return ExitCode::from(2);
        }
    };

    let input = match read_input(&cli) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("opseclint: failed to read input: {e}");
            return ExitCode::from(2);
        }
    };

    let mut report = analyzer::analyze(&input, &kb);
    if cli.min > 0 {
        report.findings.retain(|f| f.noise >= cli.min);
    }

    if let Some(dir) = &cli.sigma {
        match sigma::SigmaIndex::load_dir(std::path::Path::new(dir), cli.platform.sigma_product()) {
            Ok(index) => {
                let enriched = sigma::enrich(&mut report, &index);
                if !cli.json && !cli.sarif {
                    eprintln!(
                        "opseclint: sigma — {} rule(s) from {} file(s); enriched {} finding(s)",
                        index.rules_indexed, index.files_scanned, enriched
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "opseclint: could not read sigma dir '{dir}': {e} (using seed references)"
                );
            }
        }
    }

    if cli.sarif {
        let source_uri = cli.path.clone().unwrap_or_else(|| {
            if cli.command.is_some() {
                "<command>"
            } else {
                "stdin"
            }
            .to_string()
        });
        println!("{}", sarif::render(&report, &source_uri));
    } else if cli.json {
        println!("{}", report::render_json(&report));
    } else {
        let color = !cli.no_color && std::io::stdout().is_terminal();
        print!("{}", report::render_human(&report, color));
    }

    if cli.ci && report.max_noise >= cli.threshold {
        if !cli.json {
            eprintln!(
                "\nopseclint: CI gate failed — loudest action {} (>= threshold {})",
                report::severity_word(report.max_severity()),
                cli.threshold
            );
        }
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}
