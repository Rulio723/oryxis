//! The connect timeout, counted in NETWORK time only.
//!
//! `connect_timeout` (15 s by default) exists so an unreachable host fails
//! fast instead of hanging on SYN retransmits. It was a plain
//! `tokio::time::timeout` around the whole dial, which also counted the
//! time a PERSON spent: reading a host-key fingerprint, deciding whether
//! to approve a command proxy, or finishing a browser login a command
//! proxy started (issue #223: `ossh` refreshing expired credentials). None
//! of those is the network being slow, and OpenSSH does not bound them
//! either: with no `ConnectTimeout` it waits for the banner with no
//! deadline at all (`ssh.c`, `timeout_ms = INT_MAX`).
//!
//! So the dial runs under a [`DialClock`] that stops while a [`Hold`] is
//! alive. Two kinds of hold:
//!
//! - [`HoldKind::Human`]: a prompt is waiting for the user (host key,
//!   command-proxy consent). Unbounded, like the prompt itself; closing
//!   the connect card is how the user gives up.
//! - [`HoldKind::ProxyAuth`]: a command proxy on an ATTENDED dial is
//!   talking (it printed something before the SSH banner, which is what a
//!   proxy walking someone through a login does). Paused too, but under a
//!   long ceiling ([`PROXY_AUTH_CEILING`]) so a proxy that chatters and
//!   never connects still ends in an answer. A SILENT proxy never earns
//!   this hold, so a hung one still fails at the ordinary timeout.
//!
//! The clock is carried to the code that takes holds through a task-local
//! for everything that runs inside the dial future, and explicitly (a
//! clone in the handler and the proxy observer) for what russh or the
//! stderr drain run on tasks of their own.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

/// The longest a command proxy may keep an attended dial waiting for its
/// own login once it has started talking. Ten minutes covers a browser
/// SSO round trip with a detour to a password manager, and is short
/// enough that a proxy stuck in a retry loop still ends in a message.
pub(crate) const PROXY_AUTH_CEILING: Duration = Duration::from_secs(10 * 60);

tokio::task_local! {
    static DIAL_CLOCK: DialClock;
}

/// Why the clock ended a dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialTimeout {
    /// The network budget ran out (no hold was active).
    Network,
    /// A command proxy spent the whole [`PROXY_AUTH_CEILING`] talking
    /// without ever producing the SSH banner.
    ProxyAuth,
}

/// What a [`Hold`] stands for; decides whether a ceiling applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HoldKind {
    Human,
    ProxyAuth,
}

#[derive(Default)]
struct State {
    holds: usize,
    /// When the current pause began (`holds > 0`).
    paused_since: Option<Instant>,
    /// Paused time already accounted for.
    paused_total: Duration,
    /// Live `ProxyAuth` holds and when the first of them began.
    proxy_holds: usize,
    proxy_since: Option<Instant>,
}

struct Inner {
    state: Mutex<State>,
    notify: Notify,
}

/// A dial's stoppable clock. Cheap to clone; clones share one state.
#[derive(Clone)]
pub(crate) struct DialClock {
    inner: Arc<Inner>,
}

/// Keeps the clock stopped while alive. Dropping it resumes the count.
pub(crate) struct Hold {
    clock: DialClock,
    kind: HoldKind,
}

impl Default for DialClock {
    fn default() -> Self {
        Self::new()
    }
}

impl DialClock {
    pub(crate) fn new() -> Self {
        DialClock {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                notify: Notify::new(),
            }),
        }
    }

    /// The clock of the dial the caller is running inside, if any.
    pub(crate) fn current() -> Option<DialClock> {
        DIAL_CLOCK.try_with(|c| c.clone()).ok()
    }

    /// Run `fut` with this clock as the task's current one, so code deep
    /// inside the dial can reach it through [`DialClock::current`].
    pub(crate) async fn scope<F: Future>(&self, fut: F) -> F::Output {
        DIAL_CLOCK.scope(self.clone(), fut).await
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Stop the clock until the returned guard is dropped.
    pub(crate) fn hold(&self, kind: HoldKind) -> Hold {
        {
            let now = Instant::now();
            let mut s = self.lock();
            if s.holds == 0 {
                s.paused_since = Some(now);
            }
            s.holds += 1;
            if kind == HoldKind::ProxyAuth {
                if s.proxy_holds == 0 {
                    s.proxy_since = Some(now);
                }
                s.proxy_holds += 1;
            }
        }
        self.inner.notify.notify_waiters();
        Hold {
            clock: self.clone(),
            kind,
        }
    }

    fn release(&self, kind: HoldKind) {
        {
            let now = Instant::now();
            let mut s = self.lock();
            s.holds = s.holds.saturating_sub(1);
            if s.holds == 0
                && let Some(since) = s.paused_since.take()
            {
                s.paused_total += now.saturating_duration_since(since);
            }
            if kind == HoldKind::ProxyAuth {
                s.proxy_holds = s.proxy_holds.saturating_sub(1);
                if s.proxy_holds == 0 {
                    s.proxy_since = None;
                }
            }
        }
        self.inner.notify.notify_waiters();
    }

    /// Run `fut`, failing it once `limit` of UNHELD time has passed, or
    /// once a proxy-auth hold has lasted [`PROXY_AUTH_CEILING`].
    pub(crate) async fn run<F: Future>(
        &self,
        limit: Duration,
        fut: F,
    ) -> Result<F::Output, DialTimeout> {
        self.run_with_ceiling(limit, PROXY_AUTH_CEILING, fut).await
    }

    async fn run_with_ceiling<F: Future>(
        &self,
        limit: Duration,
        ceiling: Duration,
        fut: F,
    ) -> Result<F::Output, DialTimeout> {
        let start = Instant::now();
        let fut = self.scope(fut);
        tokio::pin!(fut);
        loop {
            // Arm the wake-up BEFORE reading the state, so a hold taken
            // or released between the read and the select is not missed.
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let (deadline, ceiling_at) = {
                let s = self.lock();
                let deadline = (s.holds == 0).then(|| start + limit + s.paused_total);
                let ceiling_at = s.proxy_since.map(|since| since + ceiling);
                (deadline, ceiling_at)
            };
            let far = start + Duration::from_secs(60 * 60 * 24 * 365);
            tokio::select! {
                out = &mut fut => return Ok(out),
                _ = &mut notified => continue,
                _ = tokio::time::sleep_until(deadline.unwrap_or(far)), if deadline.is_some() => {
                    return Err(DialTimeout::Network);
                }
                _ = tokio::time::sleep_until(ceiling_at.unwrap_or(far)), if ceiling_at.is_some() => {
                    return Err(DialTimeout::ProxyAuth);
                }
            }
        }
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.clock.release(self.kind);
    }
}

/// Take a hold on the current dial's clock, if the caller is inside one.
/// Outside a dial (a test, a helper reused elsewhere) there is nothing to
/// stop and the answer is `None`.
pub(crate) fn hold_current(kind: HoldKind) -> Option<Hold> {
    DialClock::current().map(|c| c.hold(kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: Duration = Duration::from_secs(15);

    #[tokio::test(start_paused = true)]
    async fn an_unheld_dial_times_out_at_the_limit() {
        let clock = DialClock::new();
        let started = Instant::now();
        let out = clock.run(LIMIT, std::future::pending::<()>()).await;
        assert_eq!(out, Err(DialTimeout::Network));
        assert_eq!(started.elapsed(), LIMIT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_finished_dial_returns_its_output() {
        let clock = DialClock::new();
        let out = clock
            .run(LIMIT, async {
                tokio::time::sleep(Duration::from_secs(3)).await;
                7
            })
            .await;
        assert_eq!(out, Ok(7));
    }

    #[tokio::test(start_paused = true)]
    async fn a_human_hold_stops_the_count() {
        // 10 s of network, a 5 minute prompt, then 10 s more: the dial
        // has used 20 s of NETWORK time, so it times out 5 s after the
        // prompt closes, not 15 s after it started.
        let clock = DialClock::new();
        let started = Instant::now();
        let out = clock
            .run(LIMIT, async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let hold = DialClock::current().unwrap().hold(HoldKind::Human);
                tokio::time::sleep(Duration::from_secs(300)).await;
                drop(hold);
                std::future::pending::<()>().await
            })
            .await;
        assert_eq!(out, Err(DialTimeout::Network));
        assert_eq!(started.elapsed(), Duration::from_secs(10 + 300 + 5));
    }

    #[tokio::test(start_paused = true)]
    async fn a_hold_taken_from_another_task_counts() {
        // The host-key prompt is awaited on russh's session task, not
        // inside the dial future: it reaches the clock through a clone.
        let clock = DialClock::new();
        let other = clock.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let hold = other.hold(HoldKind::Human);
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(hold);
        });
        let started = Instant::now();
        let out = clock.run(LIMIT, std::future::pending::<()>()).await;
        assert_eq!(out, Err(DialTimeout::Network));
        assert_eq!(started.elapsed(), Duration::from_secs(60 + 15));
    }

    #[tokio::test(start_paused = true)]
    async fn a_proxy_auth_hold_ends_at_its_ceiling() {
        let clock = DialClock::new();
        let started = Instant::now();
        let out = clock
            .run_with_ceiling(LIMIT, Duration::from_secs(120), async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let _hold = hold_current(HoldKind::ProxyAuth);
                std::future::pending::<()>().await
            })
            .await;
        assert_eq!(out, Err(DialTimeout::ProxyAuth));
        assert_eq!(started.elapsed(), Duration::from_secs(2 + 120));
    }

    #[tokio::test(start_paused = true)]
    async fn a_proxy_that_finishes_its_login_resumes_the_network_count() {
        let clock = DialClock::new();
        let started = Instant::now();
        let out = clock
            .run(LIMIT, async {
                let hold = hold_current(HoldKind::ProxyAuth);
                tokio::time::sleep(Duration::from_secs(200)).await;
                drop(hold);
                std::future::pending::<()>().await
            })
            .await;
        assert_eq!(out, Err(DialTimeout::Network));
        assert_eq!(started.elapsed(), Duration::from_secs(200 + 15));
    }

    #[test]
    fn outside_a_dial_there_is_no_clock() {
        assert!(DialClock::current().is_none());
        assert!(hold_current(HoldKind::Human).is_none());
    }
}
