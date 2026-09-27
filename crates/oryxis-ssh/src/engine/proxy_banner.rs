//! A command proxy's stdout, up to and past the SSH banner.
//!
//! RFC 4253 §4.2 lets the server side send lines before its
//! identification string, and a command proxy IS the server side as far
//! as the client can tell. Proxies use that room: `ossh` prints "Expired
//! SSH credentials found. Will refresh..." and a browser login URL there
//! (issue #223). russh accepts such lines but only 20 of them, each under
//! 255 bytes, so a login URL alone ends the dial with "invalid SSH
//! version string". OpenSSH reads the same stream with 1024 lines of up
//! to 8192 bytes (`SSH_MAX_PRE_BANNER_LINES`, `SSH_MAX_BANNER_LEN` in
//! `ssh.h`, consumed by `kex_exchange_identification` in `kex.c`), and
//! those are the limits here.
//!
//! [`PreBannerFilter`] reads the proxy's stdout line by line until one
//! starts with `SSH-`, hands every earlier line to the proxy's
//! [`ProxyStderr`] (the connect card shows it, the dial error quotes it,
//! and on an attended dial it stops the connect clock while the proxy is
//! talking), then passes the banner and everything after it through
//! byte for byte. It works on the READ side only and only when russh
//! reads, so russh keeps writing its own identification at the same time
//! and a server that waits for the client's banner first cannot deadlock
//! against it.
//!
//! [`ProxyTransport`] is the stream russh gets: that filter over stdout,
//! stdin, and the `Child` itself, spawned `kill_on_drop`, so dropping the
//! connection (or the dial, when the user cancels it) ends the proxy.

use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout};

use super::proxy_spawn::ProxyStderr;

/// `SSH_MAX_PRE_BANNER_LINES` in OpenSSH's `ssh.h`.
pub(crate) const MAX_PRE_BANNER_LINES: usize = 1024;
/// `SSH_MAX_BANNER_LEN` in OpenSSH's `ssh.h`: the longest line, banner
/// included, before the identification is given up on.
pub(crate) const MAX_PRE_BANNER_LINE_LEN: usize = 8192;

enum FilterState {
    /// Before the banner: bytes collect here until a whole line is in.
    Scanning { buf: Vec<u8>, lines: usize },
    /// The banner and whatever arrived with it, handed out before the
    /// inner reader is read again.
    Draining { pending: Vec<u8>, pos: usize },
    /// Past the banner: a plain pass-through.
    Through,
}

/// See the module docs.
pub(crate) struct PreBannerFilter<R> {
    inner: R,
    state: FilterState,
    voice: ProxyStderr,
}

impl<R> PreBannerFilter<R> {
    pub(crate) fn new(inner: R, voice: ProxyStderr) -> Self {
        PreBannerFilter {
            inner,
            state: FilterState::Scanning {
                buf: Vec::new(),
                lines: 0,
            },
            voice,
        }
    }
}

fn line_text(line: &[u8]) -> String {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    String::from_utf8_lossy(line).into_owned()
}

fn too_much(what: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what)
}

impl<R: AsyncRead + Unpin> AsyncRead for PreBannerFilter<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                FilterState::Through => return Pin::new(&mut this.inner).poll_read(cx, out),
                FilterState::Draining { pending, pos } => {
                    let n = (pending.len() - *pos).min(out.remaining());
                    out.put_slice(&pending[*pos..*pos + n]);
                    *pos += n;
                    if *pos == pending.len() {
                        this.state = FilterState::Through;
                    }
                    return Poll::Ready(Ok(()));
                }
                FilterState::Scanning { buf, lines } => {
                    // Every whole line already in: the banner ends the
                    // scan, anything else is the proxy talking.
                    while let Some(nl) = buf.iter().position(|b| *b == b'\n') {
                        if nl > MAX_PRE_BANNER_LINE_LEN {
                            return Poll::Ready(Err(too_much(format!(
                                "the command proxy printed a line over {MAX_PRE_BANNER_LINE_LEN} bytes before the SSH banner"
                            ))));
                        }
                        if buf.starts_with(b"SSH-") {
                            let pending = std::mem::take(buf);
                            this.voice.banner_arrived();
                            this.state = FilterState::Draining { pending, pos: 0 };
                            break;
                        }
                        let text = line_text(&buf[..nl]);
                        buf.drain(..=nl);
                        *lines += 1;
                        if *lines > MAX_PRE_BANNER_LINES {
                            return Poll::Ready(Err(too_much(format!(
                                "the command proxy printed more than {MAX_PRE_BANNER_LINES} lines before the SSH banner"
                            ))));
                        }
                        if !text.trim().is_empty() {
                            tracing::info!(
                                target: "oryxis::ssh::proxy",
                                "command proxy (before the SSH banner): {}",
                                text
                            );
                            this.voice.heard(text);
                        }
                    }
                    let FilterState::Scanning { buf, .. } = &mut this.state else {
                        continue;
                    };
                    if buf.len() > MAX_PRE_BANNER_LINE_LEN {
                        return Poll::Ready(Err(too_much(format!(
                            "the command proxy printed a line over {MAX_PRE_BANNER_LINE_LEN} bytes before the SSH banner"
                        ))));
                    }
                    let mut chunk = [0u8; 4096];
                    let mut rb = ReadBuf::new(&mut chunk);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let got = rb.filled();
                    if got.is_empty() {
                        // EOF before any banner: say what was left, then
                        // report the end the way the stream ended.
                        if !buf.is_empty() {
                            let text = line_text(buf);
                            buf.clear();
                            if !text.trim().is_empty() {
                                this.voice.heard(text);
                            }
                        }
                        this.state = FilterState::Through;
                        return Poll::Ready(Ok(()));
                    }
                    buf.extend_from_slice(got);
                }
            }
        }
    }
}

/// The stream a command proxy dial hands russh. Owns the `Child`
/// (spawned `kill_on_drop`), so the proxy ends with the connection.
pub(crate) struct ProxyTransport {
    reader: PreBannerFilter<ChildStdout>,
    writer: ChildStdin,
    _child: Child,
}

impl ProxyTransport {
    pub(crate) fn new(
        stdout: ChildStdout,
        stdin: ChildStdin,
        child: Child,
        voice: ProxyStderr,
    ) -> Self {
        ProxyTransport {
            reader: PreBannerFilter::new(stdout, voice),
            writer: stdin,
            _child: child,
        }
    }
}

impl AsyncRead for ProxyTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Feed `chunks` (each written separately, so lines and the banner
    /// can arrive in pieces) and read the filtered stream to the end.
    async fn filtered(chunks: Vec<Vec<u8>>) -> (std::io::Result<Vec<u8>>, ProxyStderr) {
        let (mut tx, rx) = tokio::io::duplex(64 * 1024);
        let voice = ProxyStderr::default();
        let mut filter = PreBannerFilter::new(rx, voice.clone());
        let writer = tokio::spawn(async move {
            for chunk in chunks {
                tx.write_all(&chunk).await.unwrap();
                tx.flush().await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let mut out = Vec::new();
        let res = filter.read_to_end(&mut out).await.map(|_| out);
        let _ = writer.await;
        (res, voice)
    }

    #[tokio::test]
    async fn warnings_before_the_banner_are_heard_not_passed() {
        let (out, voice) = filtered(vec![
            b"WARN Expired SSH credentials found. Will refresh...\r\n".to_vec(),
            b"Opening a browser to log you in\n".to_vec(),
            b"SSH-2.0-OpenSSH_9.6\r\nbinary\x00after".to_vec(),
        ])
        .await;
        assert_eq!(out.unwrap(), b"SSH-2.0-OpenSSH_9.6\r\nbinary\x00after".to_vec());
        assert_eq!(
            voice.settled_tail().await,
            vec![
                "WARN Expired SSH credentials found. Will refresh...".to_string(),
                "Opening a browser to log you in".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn a_login_url_longer_than_russh_allows_is_fine() {
        let url = format!("Visit https://sso.example/login?token={}", "x".repeat(900));
        let (out, voice) = filtered(vec![
            format!("{url}\n").into_bytes(),
            b"SSH-2.0-srv\r\n".to_vec(),
        ])
        .await;
        assert_eq!(out.unwrap(), b"SSH-2.0-srv\r\n".to_vec());
        assert_eq!(voice.settled_tail().await, vec![url]);
    }

    #[tokio::test]
    async fn more_lines_than_openssh_allows_is_an_error() {
        let mut talk = Vec::new();
        for i in 0..=MAX_PRE_BANNER_LINES {
            talk.extend_from_slice(format!("line {i}\n").as_bytes());
        }
        let (out, _) = filtered(vec![talk, b"SSH-2.0-late\r\n".to_vec()]).await;
        let err = out.unwrap_err();
        assert!(err.to_string().contains("more than 1024 lines"), "{err}");
    }

    #[tokio::test]
    async fn an_endless_line_is_an_error() {
        let (out, _) = filtered(vec![vec![b'a'; MAX_PRE_BANNER_LINE_LEN + 10]]).await;
        assert!(out.unwrap_err().to_string().contains("8192 bytes"));
    }

    #[tokio::test]
    async fn a_banner_split_across_reads_is_reassembled() {
        let (out, voice) = filtered(vec![
            b"note\nSS".to_vec(),
            b"H-2.0-Op".to_vec(),
            b"enSSH_9.6\r".to_vec(),
            b"\npayload".to_vec(),
        ])
        .await;
        assert_eq!(out.unwrap(), b"SSH-2.0-OpenSSH_9.6\r\npayload".to_vec());
        assert_eq!(voice.settled_tail().await, vec!["note".to_string()]);
    }

    #[tokio::test]
    async fn bytes_after_the_banner_pass_untouched() {
        // Binary packet data that happens to contain newlines and "SSH-"
        // must not be scanned once the banner has gone by.
        let tail: Vec<u8> = b"\n\nSSH-fake\nnoise\r\n\x01\x02".to_vec();
        let mut first = b"SSH-2.0-x\r\n".to_vec();
        first.extend_from_slice(&tail);
        let (out, voice) = filtered(vec![first.clone(), b"more".to_vec()]).await;
        let mut want = first;
        want.extend_from_slice(b"more");
        assert_eq!(out.unwrap(), want);
        assert!(voice.settled_tail().await.is_empty());
    }

    #[tokio::test]
    async fn eof_before_the_banner_reports_what_was_said() {
        let (out, voice) = filtered(vec![b"ERROR: no route\nlast words".to_vec()]).await;
        assert!(out.unwrap().is_empty());
        assert_eq!(
            voice.settled_tail().await,
            vec!["ERROR: no route".to_string(), "last words".to_string()]
        );
    }

    #[tokio::test]
    async fn the_ui_hears_lines_until_the_banner_only() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let voice = ProxyStderr::for_dial(Some(tx), None, true);
        let (mut w, r) = tokio::io::duplex(1024);
        let mut filter = PreBannerFilter::new(r, voice.clone());
        w.write_all(b"login at https://sso.example/x\nSSH-2.0-s\r\n").await.unwrap();
        drop(w);
        let mut out = Vec::new();
        filter.read_to_end(&mut out).await.unwrap();
        voice.heard("after the banner".to_string());
        assert_eq!(rx.recv().await.as_deref(), Some("login at https://sso.example/x"));
        // The banner closed the UI channel: nothing more arrives.
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn an_attended_proxy_that_talks_stops_the_clock_until_the_banner() {
        use super::super::dial_clock::{DialClock, DialTimeout};
        use std::time::Duration;
        let clock = DialClock::new();
        let voice = ProxyStderr::for_dial(None, Some(clock.clone()), true);
        let started = tokio::time::Instant::now();
        let out = clock
            .run(Duration::from_secs(15), async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                voice.heard("Opening a browser".to_string());
                // A login far longer than the network budget.
                tokio::time::sleep(Duration::from_secs(120)).await;
                voice.banner_arrived();
                std::future::pending::<()>().await
            })
            .await;
        assert_eq!(out, Err(DialTimeout::Network));
        assert_eq!(started.elapsed(), Duration::from_secs(120 + 15));
    }

    #[tokio::test(start_paused = true)]
    async fn an_unattended_proxy_never_stops_the_clock() {
        use super::super::dial_clock::{DialClock, DialTimeout};
        use std::time::Duration;
        let clock = DialClock::new();
        let voice = ProxyStderr::for_dial(None, Some(clock.clone()), false);
        let started = tokio::time::Instant::now();
        let out = clock
            .run(Duration::from_secs(15), async move {
                voice.heard("Opening a browser".to_string());
                std::future::pending::<()>().await
            })
            .await;
        assert_eq!(out, Err(DialTimeout::Network));
        assert_eq!(started.elapsed(), Duration::from_secs(15));
    }

    /// Dropping the transport (a closed connection, or a dial the user
    /// cancelled) ends the proxy, even one that ignores its stdin.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dropping_the_transport_kills_the_proxy() {
        let mut child = super::super::proxy_spawn::spawn_proxy_process("exec sleep 300")
            .expect("spawn");
        let pid = child.id().expect("pid");
        let stdout = child.stdout.take().unwrap();
        let stdin = child.stdin.take().unwrap();
        let transport = ProxyTransport::new(stdout, stdin, child, ProxyStderr::default());
        drop(transport);
        // Killed and reaped (tokio's orphan reaper), or at worst a zombie.
        let gone = |pid: u32| match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => true,
            Ok(stat) => stat
                .rsplit(')')
                .next()
                .and_then(|rest| rest.split_whitespace().next())
                .is_some_and(|state| state == "Z" || state == "X"),
        };
        for _ in 0..100 {
            if gone(pid) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the proxy {pid} outlived its transport");
    }
}
