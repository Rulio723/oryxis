//! What a launch owes the tabs it restored, beyond putting the chips
//! back (issue #229): the dial each one gets under "connect at launch",
//! and the landing on the chip that was active.
//!
//! The dial is the in-place one (`restart_pane`'s shape), never the
//! foreground `ConnectSsh` a select runs: that path pushes a NEW tab,
//! raises the progress card and takes `active_tab`, and a failed one
//! parks the card until the user answers it. Five hosts dialled that
//! way at boot with one of them down would hijack the screen and stall
//! on the first failure. In place, the pane keeps its slot and its
//! hint, focus stays where the landing put it, and a failure lands in
//! the pane the way an auto-reconnect's does.
//!
//! The dials are SEQUENTIAL, driven from the update funnel. The
//! host-key, 2FA and command-proxy answers ride single staging slots
//! (`host_key_response_tx` and its two siblings), documented in the
//! pane dial as mis-routing when several first-time dials run at once
//! and "revisit if batch first-connect becomes common". A launch is
//! that case, so one dial is in flight at a time and the slots are
//! never contended by this path.

use iced::Task;

use crate::app::{Message, Oryxis, SftpMessage, TabsMessage};

impl Oryxis {
    /// Dial the next queued restored tab, once nothing is dialling.
    ///
    /// Called after every `update` while the queue holds something.
    /// The observable it waits on is the one every completion already
    /// clears (`Pane::connecting`, cleared by `SshConnected`,
    /// `PaneConnectError` and the local spawn), plus a progress card
    /// that is still working: a card the user is looking at as FAILED
    /// waits for them, not for us. No dial arm needed a hook for this.
    ///
    /// A queued tab the user selected meanwhile (its spec already
    /// taken) or closed is skipped rather than dialled twice.
    pub(crate) fn advance_launch_dials(&mut self) -> Option<Task<Message>> {
        if self.launch_dials.is_empty() {
            return None;
        }
        // Credentials and known hosts are read from the vault at dial
        // time, so a soft lock pauses the queue rather than draining it
        // into failures.
        if self.vault_ui.state != crate::state::VaultState::Unlocked {
            return None;
        }
        let in_flight = self.connecting.as_ref().is_some_and(|c| !c.failed)
            || self
                .tabs
                .iter()
                .flat_map(|t| t.pane_grid.panes.values())
                .any(|p| p.connecting);
        if in_flight {
            return None;
        }
        // A Local host naming a curated terminal resolves it from
        // `local_terminals`, which a machine that never looked (or a
        // vault that booted locked, so the boot scan saw no hosts) does
        // not have yet. Dialling now would fail the tab for a scan that
        // had not run; the queue starts one and waits for it instead.
        if let Some(&front) = self.launch_dials.front()
            && self.local_terminals.is_none()
            && self.queued_tab_needs_terminal_list(front)
        {
            if self.local_terminals_scanning {
                return None;
            }
            // Raised HERE, not when the message lands: the funnel runs
            // after every update, and each one before the rescan is
            // handled would otherwise ask for another scan.
            self.local_terminals_scanning = true;
            return Some(Task::done(Message::Settings(
                crate::app::SettingsMessage::RescanLocalTerminals,
            )));
        }
        while let Some(id) = self.launch_dials.pop_front() {
            let dial = self.dial_dormant_in_place(id);
            // A landing that waited for the terminal scan lands now,
            // after its dial, whether or not the dial could start (a tab
            // closed meanwhile simply has nothing to select).
            let landing = (self.launch_landing_deferred == Some(id))
                .then(|| {
                    self.launch_landing_deferred = None;
                    self.tabs.iter().position(|t| t._id == id)
                })
                .flatten()
                .map(|idx| Task::done(Message::Tabs(TabsMessage::SelectTab(idx))));
            match (dial, landing) {
                (Some(dial), Some(select)) => return Some(Task::batch([dial, select])),
                (Some(dial), None) => return Some(dial),
                (None, Some(select)) => return Some(select),
                (None, None) => {}
            }
        }
        None
    }

    /// Whether the queued tab `tab_id` is a saved Local host that names a
    /// curated terminal (and so cannot resolve before the list exists).
    fn queued_tab_needs_terminal_list(&self, tab_id: uuid::Uuid) -> bool {
        let Some(crate::state::PinnedTabSpec::Host { id, .. }) = self
            .tabs
            .iter()
            .find(|t| t._id == tab_id)
            .and_then(|t| t.pending_reopen.as_ref())
        else {
            return false;
        };
        self.connections.iter().find(|c| c.id == *id).is_some_and(|c| {
            c.protocol == oryxis_core::models::connection::ConnectionProtocol::Local
                && c.local.as_ref().is_some_and(|l| {
                    l.terminal_id.is_some()
                        || l.terminal_label.as_deref().is_some_and(|s| !s.trim().is_empty())
                })
        })
    }

    /// Dial a dormant tab INTO its own pane, keeping its slot, pin and
    /// placeholder; `None` when the tab is gone, already reopened, or
    /// names something with no in-place path.
    ///
    /// The prep mirrors `restart_pane`: the origin is written BEFORE
    /// the spec is taken (a live tab's snapshot derives its spec from
    /// the origin, and a pane left at the `Ephemeral` default would
    /// drop out of the next `open_tabs` write), the in-flight flag is
    /// raised so the funnel waits and a Reconnect meanwhile is a no-op,
    /// and the dim marker says what is happening below the hint.
    pub(crate) fn dial_dormant_in_place(&mut self, tab_id: uuid::Uuid) -> Option<Task<Message>> {
        let tab_idx = self.tabs.iter().position(|t| t._id == tab_id)?;
        let spec = self.tabs[tab_idx].pending_reopen.clone()?;
        match spec {
            crate::state::PinnedTabSpec::Host { id, .. } => {
                // A host deleted since the snapshot stays a dormant
                // chip: selecting it says so, the way it always did.
                let conn_idx = self.connections.iter().position(|c| c.id == id)?;
                // A host edited into a remote desktop since the snapshot
                // has no pane to dial into: the in-place path would only
                // launch the external client, unasked, at startup. It
                // stays dormant and a select opens it the usual way.
                if self.connections[conn_idx].protocol
                    == oryxis_core::models::connection::ConnectionProtocol::RemoteDesktop
                {
                    return None;
                }
                let conn = self.connections[conn_idx].clone();
                self.tabs[tab_idx].pending_reopen = None;
                // What a fresh dial of this host would give the tab: its
                // current label (it may have been renamed since), its
                // palette, and the sidebar decision the tab path makes.
                self.tabs[tab_idx].label = conn.label.clone();
                let palette = self.resolve_terminal_palette_for_connection(&conn);
                let auto_open = conn
                    .sidebar_auto_open
                    .unwrap_or(self.prefs.sidebar_auto_open);
                if auto_open && let Some(side) = self.sidebar_auto_open_side() {
                    self.tabs[tab_idx].sidebar_open[side.idx()] = true;
                }
                let pane = self.tabs[tab_idx].active_mut();
                pane.origin = crate::state::PaneOrigin::Host(id);
                pane.connecting = true;
                pane.ended = false;
                pane.end_verdict = None;
                if let Ok(mut state) = pane.terminal.lock() {
                    state.set_palette(palette);
                    state.process(
                        format!("\r\n\x1b[2m[connecting to {}...]\x1b[0m\r\n", conn.label)
                            .as_bytes(),
                    );
                }
                let pane_id = pane.id;
                Some(self.spawn_ssh_for_pane(conn_idx, tab_idx, pane_id))
            }
            crate::state::PinnedTabSpec::LocalShell {
                program,
                args,
                label,
            } => {
                self.tabs[tab_idx].pending_reopen = None;
                let spec = crate::state::LocalShellSpec {
                    label,
                    program,
                    args,
                };
                let pane = self.tabs[tab_idx].active_mut();
                pane.origin = crate::state::PaneOrigin::Local(spec.clone());
                pane.connecting = true;
                pane.ended = false;
                pane.end_verdict = None;
                if let Ok(mut state) = pane.terminal.lock() {
                    state.process(
                        format!("\r\n\x1b[2m[connecting to {}...]\x1b[0m\r\n", spec.label)
                            .as_bytes(),
                    );
                }
                let pane_id = pane.id;
                // Spawned into the placeholder's own terminal, the same
                // answer a restart gives; it clears the in-flight flag
                // itself, since no `SshConnected` follows a local spawn.
                Some(self.respawn_local_pane(tab_idx, pane_id, &spec))
            }
            // An SFTP tab re-mounts on focus (the swap-on-focus
            // invariant) and a cloud tab spawns through a plugin into a
            // tab of its own: neither has an in-place path, so neither
            // is queued, and this is the compiler asking.
            crate::state::PinnedTabSpec::EcsExec { .. }
            | crate::state::PinnedTabSpec::KubectlExec { .. }
            | crate::state::PinnedTabSpec::Sftp { .. } => None,
        }
    }

    /// The landing on the chip that was active, taken by the ONE site
    /// that lands (boot for an open vault, the unlock otherwise), and
    /// taken there whatever else is landing, so a later unlock (a soft
    /// lock's) finds nothing left to land on.
    ///
    /// `outranked` is a launch argument with a stronger claim on where
    /// the app opens (`--connect`, a deep link, a CLI target). Then the
    /// landing does NOTHING: no select, and no dial either, because the
    /// argument runs a foreground dial of its own and a second one in
    /// flight at the same moment is exactly what the sequential queue
    /// exists to prevent (the host-key / 2FA / proxy answers ride
    /// single slots). The tab stays in `launch_dials` and dials in its
    /// turn once the foreground one settles.
    ///
    /// Otherwise the landing tab is dialled in place FIRST,
    /// synchronously, so the select finds it already reopening rather
    /// than running the foreground reopen on it (which would replace the
    /// placeholder with a second tab while the queue still named the
    /// first). Taking it out of the queue raises the pane's in-flight
    /// flag, so the returned `dial` must always be run: dropping it
    /// would leave the pane dialling forever and the funnel waiting on
    /// it with every other restored tab behind.
    pub(crate) fn take_launch_landing_task(&mut self, outranked: bool) -> LaunchLanding {
        let mut out = LaunchLanding::default();
        let Some(target) = self.launch_landing.take() else {
            return out;
        };
        if outranked {
            return out;
        }
        match target {
            crate::state::TabRef::Terminal(id) => {
                if self.launch_dials.iter().any(|q| *q == id) {
                    self.launch_dials.retain(|q| *q != id);
                    if self.local_terminals.is_none() && self.queued_tab_needs_terminal_list(id) {
                        // Its terminal list is not there yet: first in
                        // line instead, dialled by the funnel once the
                        // scan it starts has answered, and SELECTED
                        // then too. Selecting a dormant tab now would
                        // run the foreground reopen against the missing
                        // list and fail it.
                        self.launch_dials.push_front(id);
                        self.launch_landing_deferred = Some(id);
                        return out;
                    }
                    out.dial = self.dial_dormant_in_place(id);
                }
                out.select = self
                    .tabs
                    .iter()
                    .position(|t| t._id == id)
                    .map(|idx| Task::done(Message::Tabs(TabsMessage::SelectTab(idx))));
            }
            crate::state::TabRef::Sftp(id) => {
                out.select = self
                    .sftp_tabs
                    .iter()
                    .position(|t| t.id == id)
                    .map(|idx| Task::done(Message::Sftp(SftpMessage::SelectSftpTab(idx))));
            }
            // Never written by the snapshot (panels are not restored).
            crate::state::TabRef::Panel(_) => {}
        }
        out
    }

    /// A message for the boot to return so the funnel runs once and
    /// the queue starts, without waiting for whatever first event the
    /// window happens to raise.
    pub(crate) fn launch_dial_kick(&self) -> Option<Task<Message>> {
        (!self.launch_dials.is_empty()).then(|| Task::done(Message::NoOp))
    }
}

/// What [`Oryxis::take_launch_landing_task`] hands the landing site.
/// Both halves must be run; an outranked landing hands back neither.
#[derive(Default)]
pub(crate) struct LaunchLanding {
    pub dial: Option<Task<Message>>,
    pub select: Option<Task<Message>>,
}
