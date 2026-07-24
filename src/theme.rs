//! Tokyo Night terminal palette, applied consistently across all output.
//! Truecolor ANSI escapes; painting is a no-op when color is disabled
//! (`--no-color`, `NO_COLOR`, or a non-TTY).

pub const RED: &str = "\x1b[38;2;247;118;142m"; // #f7768e
pub const ORANGE: &str = "\x1b[38;2;255;158;100m"; // #ff9e64
pub const YELLOW: &str = "\x1b[38;2;224;175;104m"; // #e0af68
pub const GREEN: &str = "\x1b[38;2;158;206;106m"; // #9ece6a
pub const CYAN: &str = "\x1b[38;2;125;207;255m"; // #7dcfff
pub const BLUE: &str = "\x1b[38;2;122;162;247m"; // #7aa2f7
pub const PURPLE: &str = "\x1b[38;2;187;154;247m"; // #bb9af7
pub const FG: &str = "\x1b[38;2;192;202;245m"; // #c0caf5
pub const FG_DIM: &str = "\x1b[38;2;169;177;214m"; // #a9b1d6
pub const COMMENT: &str = "\x1b[38;2;86;95;137m"; // #565f89
pub const RULE: &str = "\x1b[38;2;65;72;104m"; // #414868
pub const BOLD: &str = "\x1b[1m";
pub const RESET: &str = "\x1b[0m";

/// Wraps text in ANSI color when enabled, else returns it plain.
pub struct Painter {
    on: bool,
}

impl Painter {
    pub fn new(on: bool) -> Self {
        Painter { on }
    }

    /// Paint `text` with `code` (and RESET). No-op when color is off.
    pub fn paint(&self, code: &str, text: &str) -> String {
        if self.on {
            format!("{code}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    /// Bold + colored.
    pub fn bold(&self, code: &str, text: &str) -> String {
        if self.on {
            format!("{BOLD}{code}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    /// A horizontal rule of `width` box-drawing dashes.
    pub fn rule(&self, width: usize) -> String {
        self.paint(RULE, &"─".repeat(width))
    }
}
