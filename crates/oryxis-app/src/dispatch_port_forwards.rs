//! `Oryxis::handle_port_forwards`, match arms for the standalone port
//! forward entity: CRUD on `PortForwardRule`, and the runtime on/off
//! toggle. Every forward to one host rides a single shared PTY-less SSH
//! connection (`PfHostConn`, issue #126): the first rule dials, later
//! rules attach as channels, and the connection closes when the host's
//! last forward stops.
//!
//! Kept separate from `dispatch_ssh.rs` (terminal sessions) so the two
//! lifecycles don't tangle. Turning a rule off drops its
//! `ForwardSession`, which cancels only that rule's tunnel.

// Domain handlers return `Err(Message)` to pass an unclaimed message
// back up the chain. See the note in `dispatch_ssh.rs`.
#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use iced::futures::SinkExt;
use iced::Task;
use uuid::Uuid;

use oryxis_core::models::port_forward_rule::PortForwardRule;
use oryxis_ssh::{ForwardConn, HostKeyQuery, KbiQuery, SshEngine};

use crate::app::{SshMessage, PortForwardMessage, Message, Oryxis};

/// Items streamed out of an interactive (manual-toggle) forward dial:
/// a host-key or keyboard-interactive (2FA) question for the UI
/// modals, or the final result.
enum PfStreamMsg {
    HostKey(HostKeyQuery),
    ProxyCommand(oryxis_ssh::ProxyCommandQuery),
    Kbi(KbiQuery),
    Done(Result<ForwardConn, String>),
    NoCommonAlgo {
        category: oryxis_ssh::NegCategory,
        server_offers: Vec<String>,
    },
    /// The dial ended without a connection and without a `Done` error to
    /// surface (the legacy-algorithm dialog owns the UX). Unwinds the
    /// in-flight bookkeeping so the dialog's retry isn't blocked by the
    /// double-start guard.
    Aborted,
}

/// Runtime state of a host's shared forward connection (issue #126).
/// Every live forward to one host multiplexes its channels over a single
/// PTY-less SSH connection, the way OpenSSH stacks `-L`/`-R`/`-D` flags
/// on one invocation, instead of each rule dialing its own.
#[derive(Debug)]
pub(crate) enum PfHostConn {
    /// A dial for this host is in flight; rules toggled on meanwhile
    /// queue here and attach when `PortForwardConnReady` lands.
    Connecting { pending: Vec<Uuid> },
    /// The connection is up; further rules attach onto it immediately.
    Up(ForwardConn),
}

/// Retry bookkeeping for an `auto_start` forward that is down. `next_at` is
/// the earliest wall-clock instant to re-attempt; `attempts` is how many
/// re-attempts have been issued so far, driving the backoff. The attempt
/// count is never capped, only the interval is: an `auto_start` forward is
/// meant to stay up, so it keeps trying (cheaply) until the key/network
/// comes back, rather than giving up like the SSH-tab reconnect does.
#[derive(Debug, Clone)]
pub(crate) struct PfRetry {
    pub next_at: Instant,
    pub attempts: u32,
}

/// Backoff for the Nth retry: 15s, 30s, 60s, then a 120s ceiling. Cheap
/// enough to poll a dead endpoint indefinitely (≤ ~720 attempts/day) yet
/// snappy enough that a forward comes up seconds after its key lands.
fn pf_retry_backoff(attempts: u32) -> Duration {
    let secs = 15u64.saturating_mul(1u64 << attempts.min(3));
    Duration::from_secs(secs.min(120))
}

/// Whether a down forward rule should keep its retry entry. This mirrors
/// the gate `pf_mark_retry_pending` uses for the `Dropped` cause: an
/// `auto_start` rule always retries, and any rule retries while the user
/// has `auto_reconnect` on. Keeping the prune side in sync with the mark
/// side is what stops a manually started `auto_reconnect` forward from
/// being pruned on the first tick and never retrying again (issue #144).
fn pf_retry_still_wanted(auto_start: bool, auto_reconnect: bool) -> bool {
    auto_start || auto_reconnect
}

/// A reading of the keys an agent-backed forward could authenticate
/// with: what every reachable ssh-agent holds, plus how many keys
/// external tools have pushed into our own agent server.
///
/// Compared reading-to-reading by the retry healer. The backoff alone
/// answers "the endpoint is still down"; it cannot answer "the missing
/// key just arrived", which is exactly the issue-#101 shape: KeePassXC
/// hands its keys to an agent only when its database unlocks, so a
/// forward that started before it can sit out up to 120 s of backoff
/// after the key is already available. A change here means the cause of
/// the failure may have just disappeared, so every pending rule becomes
/// due immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PfAgentWatch {
    /// `oryxis_ssh::agent_key_census()`: the rosters of the reachable
    /// agents. Down to fingerprints rather than endpoints, because the
    /// common case is a key landing in an agent that was ALREADY
    /// running (the always-on Windows OpenSSH service), which moves no
    /// endpoint at all.
    agents: Vec<String>,
    /// `AgentRuntime::external_add_generation()`, 0 when our agent
    /// server is off. Covers the mirror case: a tool pushing a key into
    /// US, where there is no external roster to poll.
    added_keys: u64,
}

/// Whether the agent picture moved since the last reading. The FIRST
/// reading is a baseline and never a kick: with nothing to compare
/// against, "changed" would fire on an unchanged environment.
fn pf_agent_changed(prev: Option<&PfAgentWatch>, now: &PfAgentWatch) -> bool {
    prev.is_some_and(|p| p != now)
}

/// Why a forward is being queued for another attempt. The two cases have
/// different answers because one of them the user is watching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PfRetryCause {
    /// It was running and the connection died.
    Dropped,
    /// The connect attempt itself failed.
    StartFailed,
}

impl Oryxis {
    pub(crate) fn handle_port_forwards(
        &mut self,
        message: PortForwardMessage,
    ) -> Task<Message> {
        match message {
            // -- Editor panel --
            PortForwardMessage::ShowPortForwardPanel => {
                self.overlay = None;
                self.panels.port_forward_panel = true;
                self.port_forward_form.editing_id = None;
                self.port_forward_form.label.clear();
                self.port_forward_form.kind = oryxis_core::models::port_forward_rule::ForwardKind::Local;
                // Default the host to the first connection so the picker
                // isn't empty on a fresh rule.
                self.port_forward_form.host_id = self.connections.first().map(|c| c.id);
                self.port_forward_form.listen_host = "127.0.0.1".into();
                self.port_forward_form.listen_port.clear();
                self.port_forward_form.target_host.clear();
                self.port_forward_form.target_port.clear();
                self.port_forward_form.auto_start = false;
                self.port_forward_form.error = None;
            }
            PortForwardMessage::HidePortForwardPanel => {
                self.panels.port_forward_panel = false;
            }
            PortForwardMessage::PfLabelChanged(v) => self.port_forward_form.label = v,
            PortForwardMessage::PfKindChanged(k) => self.port_forward_form.kind = k,
            PortForwardMessage::PfHostChanged(id) => self.port_forward_form.host_id = Some(id),
            PortForwardMessage::PfListenHostChanged(v) => self.port_forward_form.listen_host = v,
            PortForwardMessage::PfListenPortChanged(v) => {
                self.port_forward_form.listen_port = v.chars().filter(|c| c.is_ascii_digit()).collect();
            }
            PortForwardMessage::PfTargetHostChanged(v) => self.port_forward_form.target_host = v,
            PortForwardMessage::PfTargetPortChanged(v) => {
                self.port_forward_form.target_port = v.chars().filter(|c| c.is_ascii_digit()).collect();
            }
            PortForwardMessage::PfAutoStartToggled(v) => self.port_forward_form.auto_start = v,
            PortForwardMessage::EditPortForwardRule(idx) => {
                if let Some(rule) = self.port_forward_rules.get(idx) {
                    self.panels.port_forward_panel = true;
                    self.port_forward_form.editing_id = Some(rule.id);
                    self.port_forward_form.label = rule.label.clone();
                    self.port_forward_form.kind = rule.kind;
                    self.port_forward_form.host_id = Some(rule.host_id);
                    self.port_forward_form.listen_host = rule.listen_host.clone();
                    self.port_forward_form.listen_port = rule.listen_port.to_string();
                    self.port_forward_form.target_host = rule.target_host.clone();
                    self.port_forward_form.target_port = rule.target_port.to_string();
                    self.port_forward_form.auto_start = rule.auto_start;
                    self.port_forward_form.error = None;
                }
            }
            PortForwardMessage::SavePortForwardRule => {
                if let Some(err) = self.save_port_forward_rule() {
                    self.port_forward_form.error = Some(err);
                } else {
                    self.panels.port_forward_panel = false;
                    self.port_forward_form.error = None;
                    self.load_data_from_vault();
                }
            }
            PortForwardMessage::ShowPortForwardMenu(idx) => {
                self.port_forward_context_menu = Some(idx);
                self.overlay = Some(crate::state::OverlayState {
                    content: crate::state::OverlayContent::PortForwardActions(idx),
                    x: self.mouse_position.x,
                    y: self.mouse_position.y,
                });
            }
            PortForwardMessage::RequestDeletePortForwardRule(idx) => {
                // Both affordances land here: the hover trash in the row's
                // action cluster and the Delete row inside the edit panel
                // (which keynav reaches with a plain Enter). A rule can
                // carry a jump chain, a bound address and an auto-start
                // flag, and there is no undo short of restoring a portable
                // export, so neither one should fire on a single click.
                if let Some(rule) = self.port_forward_rules.get(idx) {
                    // Name it the way its card does: the user's label plus
                    // the ports, because several rules can share a label and
                    // the ports are what makes one distinguishable.
                    let summary = crate::views::port_forwards::forward_summary(rule);
                    let name = if rule.label.trim().is_empty() {
                        summary
                    } else {
                        format!("{} \u{2014} {}", rule.label, summary)
                    };
                    self.confirm_remove(
                        name,
                        Message::PortForward(PortForwardMessage::DeletePortForwardRule(idx)),
                    );
                }
            }
            PortForwardMessage::DeletePortForwardRule(idx) => {
                if let Some(rule) = self.port_forward_rules.get(idx) {
                    let id = rule.id;
                    // Tear down a live forward before the rule disappears.
                    let session = self.active_forwards.remove(&id);
                    self.port_forward_starting.remove(&id);
                    self.port_forward_retry.remove(&id);
                    if let Some(vault) = &self.vault {
                        let _ = vault.delete_port_forward_rule(&id);
                        self.panels.port_forward_panel = false;
                        self.load_data_from_vault();
                    }
                    // Last forward of its host gone: close the shared
                    // connection too.
                    self.pf_gc_host_conns();
                    // Await `cancel()` like StopPortForward does: a deleted
                    // `-R` rule must release its server-side listener via
                    // `cancel_tcpip_forward`, because the shared connection
                    // may stay up for sibling rules and then Drop alone
                    // leaves the remote bind occupied (re-creating the rule
                    // would hit EADDRINUSE on the server).
                    if let Some(session) = session {
                        return Task::perform(
                            async move { session.cancel().await },
                            |_| {
                                Message::PortForward(
                                    PortForwardMessage::PortForwardLivenessTick,
                                )
                            },
                        );
                    }
                }
            }

            // -- Runtime on/off --
            PortForwardMessage::StartPortForward(id) => {
                return self.start_port_forward(id, false);
            }
            PortForwardMessage::StopPortForward(id) => {
                self.port_forward_starting.remove(&id);
                // The user turned it off: stop any self-healing retry so an
                // auto_start rule the user explicitly stopped never
                // resurrects on the next tick.
                self.port_forward_retry.remove(&id);
                // Await `cancel()` so a remote (`-R`) forward also releases
                // its server-side listener via `cancel_tcpip_forward`, not
                // just the local tasks that Drop would stop. Dropping the
                // last `Arc` afterwards tears the rest down.
                if let Some(session) = self.active_forwards.remove(&id) {
                    // Last forward of its host: drop the shared connection
                    // so toggling everything off really disconnects. The
                    // session keeps its own handle clone, so the awaited
                    // `cancel()` below still reaches the server.
                    self.pf_gc_host_conns();
                    return Task::perform(
                        async move { session.cancel().await },
                        |_| Message::PortForward(PortForwardMessage::PortForwardLivenessTick),
                    );
                }
            }
            PortForwardMessage::PortForwardStarted(id, res) => {
                // `remove` returns false when StopPortForward already pulled
                // this id from the in-flight set, i.e. the user toggled the
                // rule off while the connect was still running. In that case
                // honor the stop and drop the freshly-made session rather than
                // silently re-activating a forward the user turned off.
                let was_starting = self.port_forward_starting.remove(&id);
                match res {
                    Ok(session) => {
                        // Guard against a delete or stop that landed while the
                        // connect was in flight: if the rule is gone, or a stop
                        // was requested, drop the session so it doesn't linger
                        // with no UI to stop (or against the user's intent).
                        if was_starting && self.port_forward_rules.iter().any(|r| r.id == id) {
                            self.active_forwards.insert(id, session);
                            // Came up: clear any retry so a later drop starts
                            // the backoff fresh from the shortest interval.
                            self.port_forward_retry.remove(&id);
                            self.port_forward_form.error = None;
                        } else {
                            // Honor the stop/delete that raced the attach:
                            // release the rule's listener (and, for `-R`,
                            // the server-side bind) with a real cancel, and
                            // drop the shared connection when this was the
                            // host's last forward.
                            self.pf_gc_host_conns();
                            return Task::perform(
                                async move { session.cancel().await },
                                |_| {
                                    Message::PortForward(
                                        PortForwardMessage::PortForwardLivenessTick,
                                    )
                                },
                            );
                        }
                    }
                    Err(e) => {
                        // Same rule as the Ok arm: a stop or delete that
                        // landed while the attach was in flight already
                        // cleared the retry entry, and re-arming it here
                        // would resurrect a forward the user turned off.
                        if was_starting {
                            // First/foreground failure surfaces the error. An
                            // auto_start rule additionally enters the retry loop
                            // so a transient failure (SSH key not loaded yet,
                            // network down) self-heals instead of staying dead.
                            let already_retrying = self.port_forward_retry.contains_key(&id);
                            self.pf_mark_retry_pending(id, PfRetryCause::StartFailed);
                            // Stay silent on background retries: the amber
                            // "Retrying…" chip already carries the signal, and the
                            // single shared error field would otherwise clobber
                            // across rows on every tick.
                            if !already_retrying {
                                self.port_forward_form.error = Some(e);
                            }
                        }
                        // A failed attach may leave the shared connection
                        // with no forwards on it; don't let it idle.
                        self.pf_gc_host_conns();
                    }
                }
            }
            PortForwardMessage::PortForwardConnReady(host_id, res) => {
                return self.handle_port_forward_conn_ready(host_id, res);
            }
            PortForwardMessage::PortForwardConnAborted(host_id) => {
                // The dial ended without a connection and without an error
                // to surface (the legacy-algorithm dialog owns the UX).
                // Unwind the in-flight bookkeeping so the dialog's retry
                // passes the double-start guard instead of hitting a stuck
                // "starting" id, and queued siblings stop spinning.
                match self.forward_conns.remove(&host_id) {
                    Some(PfHostConn::Connecting { pending }) => {
                        for rid in &pending {
                            self.port_forward_starting.remove(rid);
                        }
                        // Remember the queue for the dialog's retry
                        // (`PortForwardHostRetry`): manual siblings have no
                        // retry-ladder entry to bring them back, so without
                        // this they would silently stay off.
                        if !pending.is_empty() {
                            self.pf_aborted_pending.insert(host_id, pending);
                        }
                    }
                    // A stray abort must not drop a live connection.
                    Some(up) => {
                        self.forward_conns.insert(host_id, up);
                    }
                    None => {}
                }
            }
            PortForwardMessage::PortForwardHostRetry(host_id, initiator) => {
                // The legacy-algorithm dialog's retry: restart the whole
                // queue that the abort unwound, initiator first so it opens
                // the dial and the siblings queue behind it (the double-start
                // guard in `start_port_forward` skips anything already back).
                let mut ids = self
                    .pf_aborted_pending
                    .remove(&host_id)
                    .unwrap_or_default();
                ids.retain(|rid| *rid != initiator);
                ids.insert(0, initiator);
                return Task::batch(ids.into_iter().map(|rid| {
                    Task::done(Message::PortForward(
                        PortForwardMessage::StartPortForward(rid),
                    ))
                }));
            }
            PortForwardMessage::PortForwardLivenessTick => {
                // Drop forwards whose underlying connection has died so the
                // per-row toggle reflects reality instead of lying "on".
                let dead: Vec<Uuid> = self
                    .active_forwards
                    .iter()
                    .filter(|(_, s)| !s.is_alive())
                    .map(|(id, _)| *id)
                    .collect();
                for id in dead {
                    self.active_forwards.remove(&id);
                    // An auto_start forward that dropped should climb back
                    // up on its own (network loss / server closed the
                    // connection); a manual one just goes off.
                    self.pf_mark_retry_pending(id, PfRetryCause::Dropped);
                    tracing::info!("port forward {id} connection dropped, toggled off");
                }
                // Shared connections whose forwards all died (they share
                // the handle, so they die together) go with them; a retry
                // then dials fresh instead of attaching to a corpse.
                self.pf_gc_host_conns();
            }
            PortForwardMessage::PortForwardRetryTick => {
                return self.handle_port_forward_retry_tick();
            }
            PortForwardMessage::PortForwardAgentCensus(agents) => {
                return self.handle_port_forward_agent_census(agents);
            }
            PortForwardMessage::PortForwardCardHovered(idx) => {
                self.hover.port_forward_card = Some(idx);
            }
            PortForwardMessage::PortForwardCardUnhovered(idx) => {
                self.hover.leave_port_forward_card(idx);
            }
            PortForwardMessage::PortForwardSearchChanged(v) => self.port_forward_search = v,
        }
        Task::none()
    }

    /// Validate the editor draft and persist it. Returns `Some(error)` on
    /// a validation failure (left in the panel), `None` on success.
    fn save_port_forward_rule(&mut self) -> Option<String> {
        let label = self.port_forward_form.label.trim();
        if label.is_empty() {
            return Some(crate::i18n::t("pf_err_required").to_string());
        }
        let Some(host_id) = self.port_forward_form.host_id else {
            return Some(crate::i18n::t("pf_err_host").to_string());
        };
        if !self.connections.iter().any(|c| c.id == host_id) {
            return Some(crate::i18n::t("pf_err_host").to_string());
        }
        let Some(listen_port) = parse_port(&self.port_forward_form.listen_port) else {
            return Some(crate::i18n::t("pf_err_port").to_string());
        };
        let (target_host, target_port) = if self.port_forward_form.kind.has_target() {
            let th = self.port_forward_form.target_host.trim();
            if th.is_empty() {
                return Some(crate::i18n::t("pf_err_required").to_string());
            }
            let Some(tp) = parse_port(&self.port_forward_form.target_port) else {
                return Some(crate::i18n::t("pf_err_port").to_string());
            };
            (th.to_string(), tp)
        } else {
            (String::new(), 0)
        };

        let mut rule = if let Some(id) = self.port_forward_form.editing_id {
            self.port_forward_rules
                .iter()
                .find(|r| r.id == id)
                .cloned()
                .unwrap_or_else(|| PortForwardRule::new("", self.port_forward_form.kind, host_id))
        } else {
            PortForwardRule::new("", self.port_forward_form.kind, host_id)
        };
        rule.label = label.to_string();
        rule.kind = self.port_forward_form.kind;
        rule.host_id = host_id;
        rule.listen_host = self.port_forward_form.listen_host.trim().to_string();
        rule.listen_port = listen_port;
        rule.target_host = target_host;
        rule.target_port = target_port;
        rule.auto_start = self.port_forward_form.auto_start;
        rule.updated_at = chrono::Utc::now();

        let vault = self.vault.as_ref()?;
        match vault.save_port_forward_rule(&rule) {
            Ok(()) => None,
            Err(e) => Some(e.to_string()),
        }
    }

    /// Bring a rule up on its host's SHARED forward connection: every
    /// forward to one host multiplexes channels over a single PTY-less
    /// SSH session (issue #126). The first rule dials; rules toggled on
    /// while that dial is in flight queue behind it; later rules attach
    /// onto the live connection with no transport or auth at all.
    ///
    /// Host-key policy splits on `boot_auto_start`: a boot/unlock auto-start
    /// runs **known-only** (strict, silent), so a host whose key isn't
    /// already trusted just fails to off instead of popping a modal storm
    /// before the window is even ready. A manual toggle, by contrast, wires
    /// the same host-key and keyboard-interactive (2FA) prompts the
    /// terminal uses, so the user can trust a new key or answer an OTP
    /// challenge on the spot; boot auto-starts stay silent and rely on the
    /// stored TOTP secret's autofill alone.
    pub(crate) fn start_port_forward(&mut self, id: Uuid, boot_auto_start: bool) -> Task<Message> {
        if self.active_forwards.contains_key(&id) || self.port_forward_starting.contains(&id) {
            return Task::none();
        }
        let Some(rule) = self.port_forward_rules.iter().find(|r| r.id == id) else {
            return Task::none();
        };
        let host_id = rule.host_id;
        let rule_label = rule.label.clone();

        match self.forward_conns.get_mut(&host_id) {
            // Already connected: attach this rule as one more channel.
            Some(PfHostConn::Up(fconn)) if fconn.is_alive() => {
                let fconn = fconn.clone();
                self.port_forward_starting.insert(id);
                return self.attach_port_forward_task(fconn, id);
            }
            // The connection died since its last forward: dial fresh below.
            Some(PfHostConn::Up(_)) => {
                self.forward_conns.remove(&host_id);
            }
            // A dial for this host is already in flight: queue behind it;
            // `PortForwardConnReady` attaches everything at once.
            Some(PfHostConn::Connecting { pending }) => {
                if !pending.contains(&id) {
                    pending.push(id);
                }
                self.port_forward_starting.insert(id);
                return Task::none();
            }
            None => {}
        }

        let Some(mut conn) = self
            .connections
            .iter()
            .find(|c| c.id == host_id)
            .cloned()
        else {
            self.port_forward_form.error = Some(crate::i18n::t("pf_err_host").to_string());
            return Task::none();
        };

        // Same working copy every connect path dials: group inheritance
        // (D4) collapses the effective proxy onto `conn.proxy` (engine
        // reads only that field) plus the inherited username / identity,
        // so a forward authenticates exactly like a tab to its host.
        self.apply_group_inheritance(&mut conn);
        let (password, private_key, certificate) = self.resolve_credentials(&conn);
        // Agent-auth pin (B3), same rule as the tab connect.
        let pinned_agent = self.pinned_agent_public(&conn);
        let totp_secret = self
            .vault
            .as_ref()
            .and_then(|v| v.get_connection_totp_secret(&conn.id).ok().flatten());
        let resolver = self.make_jump_resolver(&mut conn);
        let host_key_check = self.make_host_key_check();
        let keepalive = self.effective_keepalive(&conn);
        self.port_forward_starting.insert(id);
        // This rule opens the dial; siblings toggled on meanwhile queue
        // behind it and everything attaches on `PortForwardConnReady`.
        self.forward_conns
            .insert(host_id, PfHostConn::Connecting { pending: vec![id] });
        // A fresh dial supersedes any queue stranded by an earlier
        // legacy-algorithm abort; drop it so a later dialog retry can't
        // resurrect rules the user has since left off.
        self.pf_aborted_pending.remove(&host_id);

        if boot_auto_start {
            tracing::info!("auto-starting port forward {} ({})", rule_label, id);
            // Approvals resolved here, on the UI thread, and answered
            // from that snapshot inside the task: this dial fires at
            // boot with nobody watching, which is precisely where a
            // route pushed by a sync peer would run unattended. Same
            // reasoning as `with_strict_host_key(true)` on the line
            // below, and the same shape of answer: known-good passes,
            // everything else is refused rather than prompted for.
            let trusted_proxy_commands = self.trusted_proxy_commands();
            return Task::perform(
                async move {
                    let engine = SshEngine::new()
                        .with_host_key_check(host_key_check)
                        .with_strict_host_key(true)
                        .with_proxy_command_ask(oryxis_ssh::trusted_only_proxy_command_ask(
                            trusted_proxy_commands,
                        ))
                        .with_totp_secret(totp_secret.as_deref())
                        .with_keepalive(keepalive)
                        .with_address_family(conn.address_family)
                        .with_rekey_limit_mb(conn.rekey_limit_mb)
                        .with_pinned_agent_key(pinned_agent.as_deref())
                        .with_algorithm_overrides(
                            conn.ciphers.clone(),
                            conn.kex.clone(),
                            conn.macs.clone(),
                            conn.host_key_algorithms.clone(),
                        );
                    engine
                        .connect_forward_conn(
                            &conn,
                            password.as_deref(),
                            private_key
                                .as_deref()
                                .map(|pem| oryxis_ssh::KeyMaterial::new(pem, certificate.as_deref())),
                            resolver.as_ref(),
                        )
                        .await
                        .map_err(|e| e.to_string())
                },
                move |res| {
                    Message::PortForward(PortForwardMessage::PortForwardConnReady(host_id, res))
                },
            );
        }

        // Manual toggle: reuse the terminal's host-key ask machinery. The
        // engine sends unknown/changed keys to `hk_ask`; the bridge forwards
        // them to the shared host-key modal and waits for the user's answer
        // on `hk_resp` (driven by the existing SshHostKey* handlers).
        let (hk_ask_tx, mut hk_ask_rx) = tokio::sync::mpsc::channel::<(
            HostKeyQuery,
            tokio::sync::oneshot::Sender<bool>,
        )>(1);
        let (hk_resp_tx, mut hk_resp_rx) = tokio::sync::mpsc::channel::<bool>(1);
        self.host_key_response_tx = Some(hk_resp_tx);

        // Keyboard-interactive bridge, same shape: a 2FA server whose OTP
        // round the TOTP autofill can't answer (no stored secret, or a
        // rejected code) surfaces the shared `SshKbi*` modal instead of
        // failing with "additional authentication could not be completed"
        // (issue #126 follow-up). Single shared response slot, same
        // documented limitation as the remote-desktop launch: a manual
        // toggle is a foreground, one-at-a-time user action.
        let (kbi_ask_tx, mut kbi_ask_rx) = tokio::sync::mpsc::channel::<(
            KbiQuery,
            tokio::sync::oneshot::Sender<Option<Vec<String>>>,
        )>(1);
        let (kbi_resp_tx, mut kbi_resp_rx) =
            tokio::sync::mpsc::channel::<Option<Vec<String>>>(1);
        self.kbi_response_tx = Some(kbi_resp_tx);

        // Command-proxy approval, same bridge shape. The user toggled
        // this rule, so an unapproved line may raise the prompt (unlike
        // the boot sweep above).
        let (pc_ask_tx, mut pc_ask_rx) = tokio::sync::mpsc::channel::<(
            oryxis_ssh::ProxyCommandQuery,
            tokio::sync::oneshot::Sender<bool>,
        )>(1);
        let (pc_resp_tx, mut pc_resp_rx) = tokio::sync::mpsc::channel::<bool>(1);
        self.proxy_command_response_tx = Some(pc_resp_tx);

        // Captured for the map closure (conn moves into the producer); the
        // retry re-runs this same port-forward start.
        let pf_conn_id = conn.id;
        let stream = iced::stream::channel::<PfStreamMsg>(8, move |mut sender: iced::futures::channel::mpsc::Sender<PfStreamMsg>| async move {
            let engine = SshEngine::new()
                .with_host_key_check(host_key_check)
                .with_host_key_ask(hk_ask_tx)
                .with_proxy_command_ask(pc_ask_tx)
                .with_kbi_ask(kbi_ask_tx)
                .with_totp_secret(totp_secret.as_deref())
                .with_password_prompt_labels(
                    crate::i18n::t("auth_password_prompt_title").to_string(),
                    crate::i18n::t("password").to_string(),
                )
                // The user just toggled this rule on, so a touch may be
                // asked for (the boot sweep above never passes this).
                .with_security_key_prompts(crate::connect_methods::security_key_prompts(None))
                .with_keepalive(keepalive)
                .with_address_family(conn.address_family)
                .with_rekey_limit_mb(conn.rekey_limit_mb)
                .with_pinned_agent_key(pinned_agent.as_deref())
                .with_algorithm_overrides(
                    conn.ciphers.clone(),
                    conn.kex.clone(),
                    conn.macs.clone(),
                    conn.host_key_algorithms.clone(),
                );

            let mut sender_clone = sender.clone();
            let _bridge = tokio::spawn(async move {
                while let Some((query, resp_tx)) = hk_ask_rx.recv().await {
                    let _ = sender_clone.send(PfStreamMsg::HostKey(query)).await;
                    let accepted = hk_resp_rx.recv().await.unwrap_or(false);
                    let _ = resp_tx.send(accepted);
                }
            });

            let mut kbi_sender = sender.clone();
            let _kbi_bridge = tokio::spawn(async move {
                while let Some((query, resp_tx)) = kbi_ask_rx.recv().await {
                    let _ = kbi_sender.send(PfStreamMsg::Kbi(query)).await;
                    let answers = kbi_resp_rx.recv().await.unwrap_or(None);
                    let _ = resp_tx.send(answers);
                }
            });

            let mut pc_sender = sender.clone();
            let _pc_bridge = tokio::spawn(async move {
                while let Some((query, resp_tx)) = pc_ask_rx.recv().await {
                    let _ = pc_sender.send(PfStreamMsg::ProxyCommand(query)).await;
                    let approved = pc_resp_rx.recv().await.unwrap_or(false);
                    let _ = resp_tx.send(approved);
                }
            });

            match engine
                .connect_forward_conn(
                    &conn,
                    password.as_deref(),
                    private_key
                        .as_deref()
                        .map(|pem| oryxis_ssh::KeyMaterial::new(pem, certificate.as_deref())),
                    resolver.as_ref(),
                )
                .await
            {
                Ok(fconn) => {
                    let _ = sender.send(PfStreamMsg::Done(Ok(fconn))).await;
                }
                Err(e) => {
                    if let Some(nf) = e.negotiation_failure() {
                        let _ = sender
                            .send(PfStreamMsg::NoCommonAlgo {
                                category: nf.category,
                                server_offers: nf.server_offers,
                            })
                            .await;
                        // The dialog owns the UX from here; unwind the
                        // in-flight bookkeeping so its retry can redial.
                        let _ = sender.send(PfStreamMsg::Aborted).await;
                    } else {
                        let _ = sender.send(PfStreamMsg::Done(Err(e.to_string()))).await;
                    }
                }
            }
        });

        Task::stream(stream).map(move |m| match m {
            PfStreamMsg::HostKey(q) => Message::Ssh(SshMessage::SshHostKeyVerify(q)),
            PfStreamMsg::ProxyCommand(q) => Message::Ssh(SshMessage::SshProxyCommandVerify(
                Box::new(q),
                crate::state::ProxyConsentMode::Ask,
            )),
            PfStreamMsg::Kbi(q) => Message::Ssh(SshMessage::SshKbiPrompt(None, q)),
            PfStreamMsg::Done(r) => {
                Message::PortForward(PortForwardMessage::PortForwardConnReady(pf_conn_id, r))
            }
            PfStreamMsg::NoCommonAlgo { category, server_offers } => Message::Ssh(SshMessage::SshNoCommonAlgo {
                conn_id: pf_conn_id,
                category,
                server_offers,
                retry: Box::new(Message::PortForward(PortForwardMessage::PortForwardHostRetry(pf_conn_id, id))),
            }),
            PfStreamMsg::Aborted => {
                Message::PortForward(PortForwardMessage::PortForwardConnAborted(pf_conn_id))
            }
        })
    }

    /// Task that attaches a rule onto its host's live shared connection:
    /// binds the listener / requests the server-side bind and reports back
    /// as `PortForwardStarted`, exactly like a dedicated dial used to. A
    /// rule deleted while queued has already left `port_forward_starting`,
    /// so the silent no-op is correct.
    fn attach_port_forward_task(&self, fconn: ForwardConn, id: Uuid) -> Task<Message> {
        let Some(rule) = self.port_forward_rules.iter().find(|r| r.id == id).cloned() else {
            return Task::none();
        };
        Task::perform(
            async move {
                fconn
                    .attach(&rule)
                    .await
                    .map(Arc::new)
                    .map_err(|e| e.to_string())
            },
            move |res| Message::PortForward(PortForwardMessage::PortForwardStarted(id, res)),
        )
    }

    /// The shared dial for `host_id` settled: on success, store the live
    /// connection and attach every rule that queued while it was in
    /// flight; on failure, fan the one error out to each queued rule so
    /// all of them get the exact `PortForwardStarted(Err)` bookkeeping
    /// (error surface, retry ladder) a dedicated dial would have given.
    fn handle_port_forward_conn_ready(
        &mut self,
        host_id: Uuid,
        res: Result<ForwardConn, String>,
    ) -> Task<Message> {
        let pending = match self.forward_conns.remove(&host_id) {
            Some(PfHostConn::Connecting { pending }) => pending,
            // One dial per host at a time, so this can only be a stray
            // late completion; keep whatever state superseded it.
            Some(up @ PfHostConn::Up(_)) => {
                self.forward_conns.insert(host_id, up);
                Vec::new()
            }
            None => Vec::new(),
        };
        match res {
            Ok(fconn) => {
                // Only rules still wanted: a stop or delete during the dial
                // pulls the id from `port_forward_starting`, which is the
                // record of intent here.
                let due: Vec<Uuid> = pending
                    .into_iter()
                    .filter(|rid| self.port_forward_starting.contains(rid))
                    .collect();
                if due.is_empty() {
                    // Everyone gave up while dialing: let the fresh
                    // connection drop and close.
                    return Task::none();
                }
                let mut tasks: Vec<Task<Message>> = due
                    .iter()
                    .map(|rid| self.attach_port_forward_task(fconn.clone(), *rid))
                    .collect();
                self.forward_conns.insert(host_id, PfHostConn::Up(fconn));
                // This dial proves the route is back: pull every other
                // pending forward off its backoff too (issue #144). The
                // rules attaching above are still in
                // `port_forward_starting`, so the kick skips them.
                tasks.push(self.pf_kick_pending_retries());
                Task::batch(tasks)
            }
            Err(e) => {
                // Same still-wanted filter as the Ok arm: a rule stopped
                // mid-dial already left `port_forward_starting`, and
                // handing it a failure now would re-arm the retry ladder
                // the stop just cleared.
                Task::batch(
                    pending
                        .into_iter()
                        .filter(|rid| self.port_forward_starting.contains(rid))
                        .map(|rid| {
                            Task::done(Message::PortForward(
                                PortForwardMessage::PortForwardStarted(rid, Err(e.clone())),
                            ))
                        }),
                )
            }
        }
    }

    /// Drop the shared connection of any host that no longer has a live
    /// or starting forward: the last toggle-off must close the SSH
    /// connection, not leave it idling. `Connecting` entries are exempt,
    /// their `PortForwardConnReady` is still in flight and settles them.
    fn pf_gc_host_conns(&mut self) {
        let rules = &self.port_forward_rules;
        let active = &self.active_forwards;
        let starting = &self.port_forward_starting;
        self.forward_conns.retain(|host_id, state| match state {
            PfHostConn::Connecting { .. } => true,
            PfHostConn::Up(_) => {
                let on_this_host = |rid: &Uuid| {
                    rules.iter().any(|r| r.id == *rid && r.host_id == *host_id)
                };
                active.keys().any(&on_this_host) || starting.iter().any(on_this_host)
            }
        });
    }

    /// Start every rule marked `auto_start`. Called once after the vault is
    /// unlocked (boot or `VaultUnlock`). Returns the connect tasks to batch
    /// into the caller's task list.
    pub(crate) fn auto_start_port_forwards(&mut self) -> Vec<Task<Message>> {
        let ids: Vec<Uuid> = self
            .port_forward_rules
            .iter()
            .filter(|r| r.auto_start)
            .map(|r| r.id)
            .collect();
        ids.into_iter()
            .map(|id| self.start_port_forward(id, true))
            .collect()
    }

    /// Mark a failed/dropped rule as pending and schedule its first
    /// re-attempt. No-op for a rule that nothing opted into self-healing
    /// (per-cause gates below) or that already has a pending retry
    /// (`or_insert` so a repeated failure never resets a backoff that's
    /// already climbing).
    fn pf_mark_retry_pending(&mut self, id: Uuid, cause: PfRetryCause) {
        let is_auto = self
            .port_forward_rules
            .iter()
            .any(|r| r.id == id && r.auto_start);
        let allowed = match cause {
            // A forward that was UP and fell over is the same event as a
            // host disconnecting, so it answers to the same setting the
            // user already set for that ("Auto-reconnect on disconnect",
            // on by default). Gating this on `auto_start` was wrong:
            // auto_start says "bring it up at launch", which is a
            // different question from "keep it up", and it left a manually
            // started forward silently dead after a network blip while
            // every terminal tab climbed back on its own.
            PfRetryCause::Dropped => self.prefs.auto_reconnect || is_auto,
            // A start the user just watched fail shows its error instead
            // of looping behind their back. Only an auto_start rule, whose
            // attempt nobody is watching, retries from here.
            PfRetryCause::StartFailed => is_auto,
        };
        if !allowed {
            return;
        }
        self.port_forward_retry.entry(id).or_insert_with(|| PfRetry {
            next_at: Instant::now() + pf_retry_backoff(0),
            attempts: 0,
        });
    }

    /// One beat of the self-healing loop: re-attempt whatever is due, and
    /// ask the agents what they hold so an arriving key can shortcut the
    /// backoff. Driven by the `PortForwardRetryTick` subscription, which
    /// only mounts while `port_forward_retry` is non-empty and the vault
    /// is unlocked, so neither half ever runs on an idle app.
    fn handle_port_forward_retry_tick(&mut self) -> Task<Message> {
        if self.port_forward_retry.is_empty() {
            // Nothing pending: drop the baseline so the next retry run
            // compares against a fresh reading instead of one taken an
            // arbitrarily long time ago (agents come and go meanwhile).
            self.port_forward_agent_watch = None;
            return Task::none();
        }
        // Ask the agents what they are holding, off the update loop (a
        // dial + LIST per endpoint); the answer comes back as
        // `PortForwardAgentCensus` and can only make rules due EARLIER,
        // so the backoff pass below never waits on it.
        Task::batch([
            Task::perform(oryxis_ssh::agent_key_census(), |census| {
                Message::PortForward(PortForwardMessage::PortForwardAgentCensus(census))
            }),
            self.pf_issue_due_retries(Instant::now()),
        ])
    }

    /// Fold a fresh agent census into the watch and, when the keys moved,
    /// re-attempt every pending rule at once.
    fn handle_port_forward_agent_census(&mut self, agents: Vec<String>) -> Task<Message> {
        if self.port_forward_retry.is_empty() {
            self.port_forward_agent_watch = None;
            return Task::none();
        }
        let watch = PfAgentWatch {
            agents,
            added_keys: self
                .agent
                .runtime
                .as_ref()
                .map_or(0, |r| r.external_add_generation()),
        };
        let changed = pf_agent_changed(self.port_forward_agent_watch.as_ref(), &watch);
        self.port_forward_agent_watch = Some(watch);
        if !changed {
            return Task::none();
        }
        // A key just arrived (or left): the most likely cause of the
        // failure is gone, so nothing waits out a backoff that has
        // already climbed to the 120 s ceiling (issue #101). Every
        // pending rule is kicked, not just the agent-authenticated ones:
        // the reading only moves on a real agent event, and one extra
        // dial is cheap next to leaving a forward down for two minutes.
        tracing::info!("ssh-agent keys changed, re-attempting pending port forwards");
        self.pf_reissue_pending_now()
    }

    /// Pull every pending rule off its backoff and re-attempt it now.
    /// Shared by the two "conditions changed" signals: the agent census
    /// (a key just arrived) and a fresh connection coming up (the
    /// network is back).
    fn pf_reissue_pending_now(&mut self) -> Task<Message> {
        let now = Instant::now();
        for retry in self.port_forward_retry.values_mut() {
            retry.next_at = now;
            // New conditions, fresh ladder: a forward that fails again
            // from here starts back at the short intervals instead of
            // resuming the old ceiling.
            retry.attempts = 0;
        }
        self.pf_issue_due_retries(now)
    }

    /// A connection just dialed successfully somewhere in the app,
    /// which after a local outage is the proof that the network is
    /// back (issue #144): re-attempt every pending forward right away
    /// instead of letting each wait out a backoff that may have
    /// climbed to the 120 s ceiling. Host tabs already reconnect on
    /// their own, so riding their success is what keeps forwards
    /// symmetric with them. No-op while nothing is pending, so the
    /// connect hot path stays free.
    pub(crate) fn pf_kick_pending_retries(&mut self) -> Task<Message> {
        if self.port_forward_retry.is_empty() {
            return Task::none();
        }
        tracing::info!("a connection came up, re-attempting pending port forwards");
        self.pf_reissue_pending_now()
    }

    /// Issue a connect for every pending rule whose backoff has elapsed.
    /// Prunes entries that are no longer eligible (rule deleted, no longer
    /// wanted per `pf_retry_still_wanted`, or already up) so the
    /// subscription unmounts once nothing is pending. Shared by the
    /// heartbeat and the census kick.
    fn pf_issue_due_retries(&mut self, now: Instant) -> Task<Message> {
        let ids: Vec<Uuid> = self.port_forward_retry.keys().copied().collect();
        let auto_reconnect = self.prefs.auto_reconnect;
        let mut due = Vec::new();
        for id in ids {
            let still_wanted = self
                .port_forward_rules
                .iter()
                .any(|r| r.id == id && pf_retry_still_wanted(r.auto_start, auto_reconnect));
            if !still_wanted || self.active_forwards.contains_key(&id) {
                self.port_forward_retry.remove(&id);
                continue;
            }
            // An attempt is already in flight (or the connect just landed);
            // don't stack a second one. `start_port_forward` also guards
            // this, but skipping here keeps the backoff honest.
            if self.port_forward_starting.contains(&id) {
                continue;
            }
            if self
                .port_forward_retry
                .get(&id)
                .is_some_and(|r| r.next_at <= now)
            {
                due.push(id);
            }
        }

        let mut tasks = Vec::new();
        for id in due {
            // Advance the backoff BEFORE issuing: a failure that lands after
            // this tick keeps climbing, and a success clears the entry.
            if let Some(retry) = self.port_forward_retry.get_mut(&id) {
                retry.attempts = retry.attempts.saturating_add(1);
                retry.next_at = now + pf_retry_backoff(retry.attempts);
            }
            tracing::info!("retrying auto-start port forward {id}");
            tasks.push(self.start_port_forward(id, true));
        }
        Task::batch(tasks)
    }
}

/// Parse a 1..=65535 port from the editor's digit-filtered string.
fn parse_port(s: &str) -> Option<u16> {
    match s.trim().parse::<u16>() {
        Ok(p) if p > 0 => Some(p),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{pf_agent_changed, pf_retry_backoff, pf_retry_still_wanted, PfAgentWatch};
    use std::time::Duration;

    fn watch(agents: &[&str], added_keys: u64) -> PfAgentWatch {
        PfAgentWatch {
            agents: agents.iter().map(|s| s.to_string()).collect(),
            added_keys,
        }
    }

    #[test]
    fn first_agent_reading_is_a_baseline_not_a_kick() {
        // Nothing to compare against: an unchanged environment must not
        // read as "the keys moved" on the very first tick.
        assert!(!pf_agent_changed(None, &watch(&[], 0)));
        assert!(!pf_agent_changed(None, &watch(&["/tmp/agent.sock SHA256:aaa"], 3)));
    }

    #[test]
    fn steady_agent_picture_never_kicks() {
        let prev = watch(&["/tmp/agent.sock SHA256:aaa"], 2);
        assert!(!pf_agent_changed(
            Some(&prev),
            &watch(&["/tmp/agent.sock SHA256:aaa"], 2)
        ));
    }

    #[test]
    fn key_arriving_in_a_running_agent_kicks() {
        // The issue-#101 edge, and the one an endpoint-only watch would
        // miss: the agent (the always-on Windows OpenSSH service) was
        // there all along, KeePassXC just handed it the key.
        let before = watch(&[r"\\.\pipe\openssh-ssh-agent <empty>"], 0);
        let after = watch(&[r"\\.\pipe\openssh-ssh-agent SHA256:aaa"], 0);
        assert!(pf_agent_changed(Some(&before), &after));
        // The reverse (KeePassXC locked, keys pulled) also counts: the
        // picture moved, and one extra dial is cheap next to leaving a
        // forward down for two minutes.
        assert!(pf_agent_changed(Some(&after), &before));
    }

    #[test]
    fn whole_agent_appearing_kicks() {
        // KeePassXC in Pageant mode publishes its own pipe on launch.
        let before = watch(&[], 0);
        let after = watch(&[r"\\.\pipe\pageant.alice.abcd SHA256:aaa"], 0);
        assert!(pf_agent_changed(Some(&before), &after));
    }

    #[test]
    fn key_pushed_into_our_own_agent_kicks() {
        // Same endpoint set, but KeePassXC just ADDed a key to the
        // Oryxis agent server: the missing credential is now available.
        let before = watch(&[r"\\.\pipe\openssh-ssh-agent"], 0);
        let after = watch(&[r"\\.\pipe\openssh-ssh-agent"], 1);
        assert!(pf_agent_changed(Some(&before), &after));
    }

    #[test]
    fn backoff_climbs_then_caps_at_120s() {
        assert_eq!(pf_retry_backoff(0), Duration::from_secs(15));
        assert_eq!(pf_retry_backoff(1), Duration::from_secs(30));
        assert_eq!(pf_retry_backoff(2), Duration::from_secs(60));
        assert_eq!(pf_retry_backoff(3), Duration::from_secs(120));
        // The ceiling holds for every further attempt, and the bounded
        // shift (`attempts.min(3)`) means a huge count can't overflow.
        assert_eq!(pf_retry_backoff(4), Duration::from_secs(120));
        assert_eq!(pf_retry_backoff(50), Duration::from_secs(120));
        assert_eq!(pf_retry_backoff(u32::MAX), Duration::from_secs(120));
    }

    #[test]
    fn auto_reconnect_keeps_a_manual_forward_retrying() {
        // An auto_start forward always keeps retrying.
        assert!(pf_retry_still_wanted(true, false));
        // A manually started forward keeps retrying while auto_reconnect is
        // on. Regression for issue #144: the prune gate only checked
        // auto_start, so such a forward was dropped from the retry set on
        // the first tick (the retry subscription then unmounted) and never
        // came back after the local network dropped, unlike host sessions.
        assert!(pf_retry_still_wanted(false, true));
        // A manual forward with auto_reconnect off is not retried.
        assert!(!pf_retry_still_wanted(false, false));
    }
}
