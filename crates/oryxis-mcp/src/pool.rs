//! One live SSH connection per host, kept between `ssh_execute` calls.
//!
//! A tool call used to be a full dial: TCP, key exchange, authentication,
//! one command, and an abrupt close. Every call paid the handshake and
//! every call was a fresh login on the host. Here the authenticated
//! transport outlives the command, the way the app's own F2 reuse keeps a
//! second tab off the wire, and a later call to the same host costs one
//! channel open. The host sees one session with one exec channel per
//! call, which is what `ssh -o ControlMaster` does for the same reason.
//!
//! What the pool holds is a [`MonitorConn`]: the authenticated handle and
//! nothing else, no PTY, no reader task. It is dialled through
//! [`SshEngine::connect_monitor`], the same headless path the monitor
//! dashboard uses, so host-key strictness, the TOTP autofill and the
//! command-proxy gate are the engine's, not restated here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use uuid::Uuid;

use oryxis_ssh::{ExecResult, KeyMaterial, MonitorConn, SshError};

use crate::handlers::DialPlan;

/// Bounds for a headless dial. The client on the other end of the pipe
/// has a budget of its own for the whole call, and a first call to a
/// host pays connect + auth + command out of it.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// Client keepalive on a pooled link. russh closes the session after
/// three go unanswered, which is how a link a NAT dropped silently is
/// noticed before the next call trusts it.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// The channel open on a reused connection. One round trip; a link
/// that cannot answer it in this long is treated as gone and redialled.
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// A connection nobody has used for this long is closed. Long enough
/// to span a conversation's pauses, short enough that a host does not
/// carry an idle login from a chat closed hours ago.
pub const IDLE_TTL: Duration = Duration::from_secs(300);
/// How often the sweeper looks for idle connections.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

struct Live {
    conn: Arc<MonitorConn>,
    signature: u64,
    last_used: Instant,
}

/// A slot per host id. The slot is locked while a connection for the
/// host is being chosen or dialled, so two calls arriving together dial
/// once and share the result; it is NOT held while a command runs, so
/// concurrent calls to one host multiplex channels on one connection.
type Slot = Arc<tokio::sync::Mutex<Option<Live>>>;

#[derive(Default)]
pub struct Pool {
    slots: Mutex<HashMap<Uuid, Slot>>,
}

/// A completed run, with the figures the log line reports.
pub struct PoolRun {
    pub label: String,
    pub endpoint: String,
    pub reused: bool,
    pub dial_ms: u128,
    pub exec_ms: u128,
    pub result: ExecResult,
}

/// A failed run, with the stage it failed in. Boxed on the way out:
/// the Ok side is the common one and the error carries two strings.
pub struct PoolFailure {
    pub label: String,
    pub endpoint: String,
    pub stage: &'static str,
    pub error: SshError,
}

impl PoolFailure {
    /// The prefix the tool answer carries, kept in the wording earlier
    /// releases used so a client's own pattern matching keeps working.
    pub fn stage_title(&self) -> &'static str {
        match self.stage {
            "connect" => "Connection failed",
            "auth" => "Authentication failed",
            _ => "Execution failed",
        }
    }
}

impl Pool {
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(&self, id: Uuid) -> Slot {
        let mut slots = lock_or_recover(&self.slots);
        Arc::clone(slots.entry(id).or_default())
    }

    /// Drop the connection for `id`, if any. Callers still holding a
    /// clone finish their command on it; the disconnect goes out with
    /// the last clone.
    pub fn forget(&self, id: Uuid) {
        let slot = {
            let mut slots = lock_or_recover(&self.slots);
            slots.remove(&id)
        };
        if let Some(slot) = slot {
            if let Ok(mut guard) = slot.try_lock() {
                guard.take();
            }
            // A slot mid-dial is left to the dialler: it stores the
            // fresh connection into a slot nobody can find any more,
            // and that `Arc` dies with the dial's own clone.
        }
    }

    /// Close connections idle for longer than [`IDLE_TTL`]. Slots that
    /// are busy (a dial in flight) are skipped; they are by definition
    /// not idle.
    pub fn sweep_idle(&self) {
        let now = Instant::now();
        let slots: Vec<(Uuid, Slot)> = {
            let slots = lock_or_recover(&self.slots);
            slots.iter().map(|(k, v)| (*k, Arc::clone(v))).collect()
        };
        for (id, slot) in slots {
            let Ok(mut guard) = slot.try_lock() else {
                continue;
            };
            let idle = guard
                .as_ref()
                .map(|live| now.duration_since(live.last_used) >= IDLE_TTL)
                .unwrap_or(false);
            if idle {
                tracing::info!(host_id = %id, "pool: closing idle connection");
                guard.take();
            }
        }
        // Then forget the slots left empty, so the map tracks the hosts
        // in use rather than every host ever called. Only a slot nobody
        // else holds: `slot()` clones under this same lock, so a count
        // of one here means no call is between finding the slot and
        // locking it, and removing it cannot strand a dial.
        let mut slots = lock_or_recover(&self.slots);
        slots.retain(|_, slot| {
            Arc::strong_count(slot) > 1 || slot.try_lock().map(|g| g.is_some()).unwrap_or(true)
        });
    }

    /// Close every connection and wait for the disconnects to go out,
    /// each bounded. For the process's own exit: a spawned disconnect
    /// would be cut off by `process::exit`, and the host would log a
    /// connection reset for what was a clean close.
    pub async fn shutdown(&self) {
        let slots: Vec<Slot> = {
            let mut slots = lock_or_recover(&self.slots);
            slots.drain().map(|(_, v)| v).collect()
        };
        for slot in slots {
            let live = match slot.try_lock() {
                Ok(mut guard) => guard.take(),
                Err(_) => None,
            };
            if let Some(live) = live {
                let _ = tokio::time::timeout(Duration::from_secs(1), live.conn.disconnect()).await;
            }
        }
    }

    /// Run `command` on the host `plan` describes, over the pooled
    /// connection when one is live and still matches the plan's
    /// signature, else over a fresh dial that is then pooled.
    ///
    /// A reused connection that turns out dead (closed, or silent on the
    /// channel open: the keepalive has a window in which a dead link
    /// still reads as alive) is dropped and the dial retried once. One
    /// the server answered with a REFUSAL is healthy and stays pooled;
    /// the call runs on a one-off connection instead. A command that
    /// TIMES OUT is never retried, it may have acted on the host.
    ///
    /// `cancel` is honoured at every wait: the slot, the dial and the
    /// command. A dial dropped mid-flight takes its connection with it
    /// (nothing was pooled yet); a cancelled command closes its channel
    /// and leaves the connection for the next call.
    pub async fn exec(
        &self,
        plan: DialPlan,
        command: &str,
        run_timeout: Duration,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<PoolRun, Box<PoolFailure>> {
        let (label, endpoint) = (plan.label.clone(), plan.endpoint.clone());
        let fail = move |stage: &'static str, error: SshError| {
            Box::new(PoolFailure {
                label: label.clone(),
                endpoint: endpoint.clone(),
                stage,
                error,
            })
        };
        let slot = self.slot(plan.conn_id);
        // The pooled connection that refused a channel, if one did: it
        // is skipped on the retry, and ONLY it, so a fresh connection a
        // concurrent call dialled meanwhile is used rather than
        // replaced.
        let mut refused: Option<Arc<MonitorConn>> = None;
        loop {
            let dial_started = Instant::now();
            let (conn, reused) = {
                let mut guard = tokio::select! {
                    guard = slot.lock() => guard,
                    () = cancelled(&mut cancel) => return Err(fail("connect", SshError::Cancelled)),
                };
                match guard.as_mut() {
                    Some(live)
                        if live.signature == plan.signature
                            && live.conn.is_alive()
                            && !refused
                                .as_ref()
                                .is_some_and(|r| Arc::ptr_eq(r, &live.conn)) =>
                    {
                        live.last_used = Instant::now();
                        (Arc::clone(&live.conn), true)
                    }
                    _ => {
                        // Whatever was there is stale: gone, changed
                        // under the user, or just found dead. Its
                        // disconnect goes out on the drop.
                        guard.take();
                        let conn = tokio::select! {
                            dialled = dial(&plan) => dialled?,
                            () = cancelled(&mut cancel) => {
                                return Err(fail("connect", SshError::Cancelled));
                            }
                        };
                        let conn = Arc::new(conn);
                        *guard = Some(Live {
                            conn: Arc::clone(&conn),
                            signature: plan.signature,
                            last_used: Instant::now(),
                        });
                        (conn, false)
                    }
                }
            };
            let dial_ms = if reused { 0 } else { dial_started.elapsed().as_millis() };

            let exec_started = Instant::now();
            match conn
                .exec_capture(command, None, OPEN_TIMEOUT, run_timeout, Some(cancel.clone()))
                .await
            {
                Ok(result) => {
                    return Ok(PoolRun {
                        label: plan.label,
                        endpoint: plan.endpoint,
                        reused,
                        dial_ms,
                        exec_ms: exec_started.elapsed().as_millis(),
                        result,
                    })
                }
                Err(SshError::Channel(why)) if reused && refused.is_none() => {
                    match channel_verdict(&why, conn.is_alive()) {
                        ChannelVerdict::Dead => {
                            tracing::info!(
                                host = %plan.label,
                                endpoint = %plan.endpoint,
                                error = %why,
                                "pool: pooled connection is gone, dialling fresh"
                            );
                            refused = Some(conn);
                            continue;
                        }
                        ChannelVerdict::Refused => {
                            // The server answered, so the link is
                            // healthy and stays pooled: it is busy
                            // (`MaxSessions`) or policy said no to one
                            // more channel. Evicting it would redial the
                            // host on every call past the limit, the
                            // login churn the pool exists to prevent.
                            // This call gets a connection of its own,
                            // closed as soon as it has answered.
                            tracing::info!(
                                host = %plan.label,
                                endpoint = %plan.endpoint,
                                error = %why,
                                "pool: pooled connection refused a channel, running on a one-off connection"
                            );
                            return self
                                .exec_overflow(&plan, command, run_timeout, cancel, &fail)
                                .await;
                        }
                        ChannelVerdict::Other => return Err(fail("exec", SshError::Channel(why))),
                    }
                }
                Err(e) => return Err(fail("exec", e)),
            }
        }
    }

    /// Run `command` on a connection dialled for this call alone and
    /// closed once it has answered. The pooled one refused a channel
    /// while alive, so it stays where it is for the calls that fit.
    async fn exec_overflow(
        &self,
        plan: &DialPlan,
        command: &str,
        run_timeout: Duration,
        mut cancel: watch::Receiver<bool>,
        fail: &(impl Fn(&'static str, SshError) -> Box<PoolFailure> + ?Sized),
    ) -> Result<PoolRun, Box<PoolFailure>> {
        let dial_started = Instant::now();
        let conn = tokio::select! {
            dialled = dial(plan) => dialled?,
            () = cancelled(&mut cancel) => return Err(fail("connect", SshError::Cancelled)),
        };
        let dial_ms = dial_started.elapsed().as_millis();
        let exec_started = Instant::now();
        let outcome = conn
            .exec_capture(command, None, OPEN_TIMEOUT, run_timeout, Some(cancel))
            .await;
        let exec_ms = exec_started.elapsed().as_millis();
        let _ = tokio::time::timeout(Duration::from_secs(1), conn.disconnect()).await;
        match outcome {
            Ok(result) => Ok(PoolRun {
                label: plan.label.clone(),
                endpoint: plan.endpoint.clone(),
                reused: false,
                dial_ms,
                exec_ms,
                result,
            }),
            Err(e) => Err(fail("exec", e)),
        }
    }
}

/// What a channel failure on a POOLED connection says about it.
#[derive(Debug, PartialEq, Eq)]
enum ChannelVerdict {
    /// The link is gone, or silent: closed, or the open got no answer
    /// inside [`OPEN_TIMEOUT`] (the keepalive has a window in which a
    /// NAT-dropped link still reads as alive). Redial once.
    Dead,
    /// The server answered with `SSH_MSG_CHANNEL_OPEN_FAILURE`: the link
    /// is fine and said no to one more channel.
    Refused,
    /// Anything else: the channel opened, so the command may have run.
    /// Never retried.
    Other,
}

/// Classify a `SshError::Channel` from `exec_capture_on`. The strings
/// are that function's own prefixes (`open session:` wrapping russh's
/// `ChannelOpenFailure` display, and the open timeout's message);
/// `channel_verdict_matches_the_engine_wording` pins them.
fn channel_verdict(why: &str, alive: bool) -> ChannelVerdict {
    if !alive || why.starts_with("channel open timed out") || why == "connection closed" {
        ChannelVerdict::Dead
    } else if why.starts_with("open session:") {
        if why.contains("Failed to open channel") {
            ChannelVerdict::Refused
        } else {
            // A transport error on the open (send failed, disconnect):
            // nothing reached the host.
            ChannelVerdict::Dead
        }
    } else {
        ChannelVerdict::Other
    }
}

/// Dial and authenticate `plan`. Errors carry the stage they belong to
/// through the same two prefixes the pre-pool handler answered with.
async fn dial(plan: &DialPlan) -> Result<MonitorConn, Box<PoolFailure>> {
    let key_material = plan
        .private_key
        .as_deref()
        .map(|pem| KeyMaterial::new(pem, plan.certificate.as_deref()));
    plan.engine
        .connect_monitor(&plan.auth_conn, plan.password.as_deref(), key_material, None)
        .await
        .map_err(|error| {
            Box::new(PoolFailure {
                label: plan.label.clone(),
                endpoint: plan.endpoint.clone(),
                // `connect_monitor` dials then authenticates; the engine's
                // auth failures are the `Key` / `AuthFailed` shapes and
                // everything else happened on the way to the host.
                stage: match error {
                    SshError::AuthFailed | SshError::Key(_) => "auth",
                    _ => "connect",
                },
                error,
            })
        })
}

/// Resolve once `rx` says cancelled; never resolve if the sender is
/// gone (an abandoned handle is not a cancel).
pub async fn cancelled(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

fn lock_or_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wording `exec_capture_on` produces, verbatim: russh's
    /// `ChannelOpenFailure` displays as "Failed to open channel (..)"
    /// and the engine prefixes the open with "open session:". A change
    /// on either side must come through here, or a refusal starts
    /// redialling again (or a dead link stops being noticed).
    #[test]
    fn channel_verdict_matches_the_engine_wording() {
        let refused = "open session: Failed to open channel (AdministrativelyProhibited)";
        assert_eq!(channel_verdict(refused, true), ChannelVerdict::Refused);
        // The same refusal on a link that has since closed is a dead one.
        assert_eq!(channel_verdict(refused, false), ChannelVerdict::Dead);
        assert_eq!(
            channel_verdict("channel open timed out after 10s", true),
            ChannelVerdict::Dead
        );
        assert_eq!(channel_verdict("connection closed", true), ChannelVerdict::Dead);
        assert_eq!(
            channel_verdict("open session: Disconnected", true),
            ChannelVerdict::Dead
        );
        // Past the open the command may have run: never retried.
        assert_eq!(channel_verdict("exec: Send error", true), ChannelVerdict::Other);
        assert_eq!(channel_verdict("stdin: Send error", true), ChannelVerdict::Other);
    }

    #[test]
    fn sweep_forgets_empty_slots_nobody_holds() {
        let pool = Pool::new();
        let idle = Uuid::new_v4();
        let held = Uuid::new_v4();
        drop(pool.slot(idle));
        // A call between finding its slot and locking it.
        let in_use = pool.slot(held);
        pool.sweep_idle();
        let slots = lock_or_recover(&pool.slots);
        assert!(!slots.contains_key(&idle), "an empty slot is forgotten");
        assert!(slots.contains_key(&held), "a slot a call holds is kept");
        drop(slots);
        drop(in_use);
    }
}
