//! What a command proxy says while a dial is pending, as the UI receives
//! it (issue #223).
//!
//! Two pipes feed it and they are NOT equally trusted, which is why every
//! line carries its [`ProxyOutputSource`]. Stderr is the local process the
//! user approved. The lines on stdout before the SSH banner are whatever
//! reached the proxy's stdout: from `ossh` that is its own login prose,
//! but a proxy that only relays bytes (`nc %h %p`, `socat`) hands over the
//! REMOTE server's pre-identification lines (RFC 4253 §4.2) verbatim. So a
//! consumer may show both, but may only act on stderr (the connect card
//! offers links from stderr alone).
//!
//! Both are text some other program chose, and they reach a terminal
//! emulator (the pane marker lines), the card and the log. So every line
//! is reduced to what it visibly says ([`sanitize_proxy_line`]) at the
//! one place lines enter the channel (`ProxyStderr::heard`): no escape
//! sequence a hostile server printed before its banner can drive the
//! emulator (an OSC 52 clipboard write, a title, an OSC 8 link), and no
//! bidi override can make the card read differently from the bytes.

/// Which pipe a proxy line arrived on. See the module docs for why it
/// matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyOutputSource {
    /// The proxy process's own stderr: the local program the user
    /// approved.
    Stderr,
    /// A line on stdout before the SSH banner: the proxy's, or the remote
    /// server's when the proxy only relays bytes.
    BeforeBanner,
}

/// One line a command proxy said, already sanitized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyOutputLine {
    pub text: String,
    pub source: ProxyOutputSource,
}

impl ProxyOutputLine {
    /// Whether this line came from the local process itself, and so may
    /// be acted on (a login link offered as a button).
    pub fn is_local(&self) -> bool {
        self.source == ProxyOutputSource::Stderr
    }
}

/// `line` reduced to what it visibly says: control characters (C0 except
/// TAB, DEL, C1, and so ESC and every escape sequence introducer) and
/// invisible formatting characters (bidi overrides and isolates, zero
/// width joiners and spaces, the soft hyphen, the BOM) are dropped, and
/// trailing whitespace is trimmed. The same set the password popup strips
/// from a prompt's target (`oryxis_terminal::prompt_detect`).
pub fn sanitize_proxy_line(line: &str) -> String {
    let kept: String = line
        .chars()
        .filter(|&c| {
            (c == '\t' || !c.is_control())
                && !matches!(
                    c,
                    '\u{00AD}'
                        | '\u{061C}'
                        | '\u{180E}'
                        | '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2060}'..='\u{2064}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{FEFF}'
                )
        })
        .collect();
    kept.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_sequences_cannot_reach_the_emulator() {
        // OSC 52 (clipboard write), a title, a CSI colour and a C1 CSI.
        let hostile = "\x1b]52;c;ZXZpbA==\x07Login \x1b]0;pwned\x07\x1b[31mhere\x1b[0m \u{9b}2J";
        let clean = sanitize_proxy_line(hostile);
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\x07'));
        assert!(!clean.contains('\u{9b}'));
        assert!(clean.contains("Login"));
        assert!(clean.contains("here"));
    }

    #[test]
    fn invisible_formatting_is_dropped_and_tabs_kept() {
        assert_eq!(
            sanitize_proxy_line("visit\thttps://sso.\u{202E}elpmaxe\u{200D}/x \r"),
            "visit\thttps://sso.elpmaxe/x"
        );
    }

    #[test]
    fn only_stderr_lines_are_local() {
        let local = ProxyOutputLine { text: "a".into(), source: ProxyOutputSource::Stderr };
        let relayed = ProxyOutputLine { text: "a".into(), source: ProxyOutputSource::BeforeBanner };
        assert!(local.is_local());
        assert!(!relayed.is_local());
    }
}
