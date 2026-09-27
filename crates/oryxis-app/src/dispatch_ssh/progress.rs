//! The connection progress card: its step stream, the two ways out
//! of it (close it, or jump to the host editor), the retry, and the
//! pre-auth banner text that renders on it.
//!
//! Banners are unauthenticated server input, so the concat that
//! feeds the card is capped.

use super::*;

impl Oryxis {
    /// Abort the dial the progress card tracks, if it is still running.
    /// Answers whether one was aborted.
    pub(crate) fn abort_progress_dial(&mut self) -> bool {
        match self.connecting.as_mut() {
            Some(p) if !p.failed => match p.dial_task.take() {
                Some(handle) => {
                    handle.abort();
                    true
                }
                None => false,
            },
            _ => false,
        }
    }

    pub(super) fn handle_ssh_progress(&mut self, message: SshMessage) -> Task<Message> {
        match message {
            SshMessage::SshProgress(pane_id, step, log) => {
                // Scoped to the dial this card is tracking: a progress
                // event from a connect whose card was superseded by a
                // newer tab's dial must not append to that card's
                // timeline (concurrent connections).
                if self
                    .connecting
                    .as_ref()
                    .is_some_and(|p| p.pane_id == pane_id)
                    && let Some(ref mut progress) = self.connecting
                {
                    progress.step = step;
                    progress.logs.push((step, log));
                }
            }
            SshMessage::SshCloseProgress => {
                // Closing the card while the dial is still running STOPS
                // it: the task is aborted, and the transport's
                // `kill_on_drop` takes a command proxy (one parked on a
                // browser login, issue #223) down with it.
                self.abort_progress_dial();
                // Close connection progress, remove the tab
                if let Some(ref progress) = self.connecting {
                    let tab_idx = progress.tab_idx;
                    if tab_idx < self.tabs.len() {
                        self.tabs.remove(tab_idx);
                        self.adjust_last_terminal_tab_after_remove(tab_idx);
                    }
                }
                self.connecting = None;
                // A parked identity/key switch dies with its connect.
                self.pending_auth_switch = None;
                // So does a parked KBI prompt (same sweep EditFromProgress
                // does): left behind, it would render as the port-forward
                // KBI overlay on the Dashboard once `connecting` is None.
                if self.pending_kbi_prompt.is_some() {
                    self.pending_kbi_prompt = None;
                    self.pending_kbi_quick = None;
                    self.kbi_inputs.clear();
                    if let Some(ref tx) = self.kbi_response_tx {
                        let _ = tx.try_send(None);
                    }
                }
                self.active_tab = None;
                self.active_view = View::Dashboard;
            }
            SshMessage::SshEditFromProgress => {
                if let Some(ref progress) = self.connecting {
                    let origin = progress.origin;
                    let tab_idx = progress.tab_idx;
                    // A still-live connect (quick hosts offer Edit in every
                    // state, not just failure) is parked on a prompt or mid
                    // dial. Answer any pending ask so the engine isn't left
                    // hanging on its oneshot, and arm the one-shot swallow
                    // for the error that cancel provokes, else it lands
                    // inside the editor as `host_panel_error`.
                    if !progress.failed {
                        if self.pending_kbi_prompt.is_some() {
                            self.pending_kbi_prompt = None;
                            self.pending_kbi_quick = None;
                            self.kbi_inputs.clear();
                            if let Some(ref tx) = self.kbi_response_tx {
                                let _ = tx.try_send(None);
                            }
                        }
                        if self.pending_host_key.is_some() {
                            self.pending_host_key = None;
                            if let Some(ref tx) = self.host_key_response_tx {
                                let _ = tx.try_send(false);
                            }
                        }
                        // An aborted dial reports nothing, so there is no
                        // error to swallow; arming the swallow anyway would
                        // eat the NEXT connect's real error. Only a dial
                        // that cannot be aborted (Telnet / Serial carry no
                        // handle) still owes the cancel-provoked error.
                        if !self.abort_progress_dial() {
                            self.pending_edit_cancel = true;
                        }
                    }
                    self.connecting = None;
                    // The switch parked for this connect dies with it.
                    self.pending_auth_switch = None;
                    if tab_idx < self.tabs.len() {
                        self.tabs.remove(tab_idx);
                        self.adjust_last_terminal_tab_after_remove(tab_idx);
                    }
                    self.active_tab = None;
                    self.active_view = View::Dashboard;
                    return match origin {
                        crate::state::ProgressOrigin::Saved(id) => {
                            self.update(Message::Editor(EditorMessage::EditConnection(id)))
                        }
                        // Ad-hoc host: edit the TEMPORARY entry; the editor
                        // opens with Connect (without saving) as the primary
                        // action, Save as the explicit opt-in.
                        crate::state::ProgressOrigin::Quick(id) => {
                            self.update(Message::Editor(EditorMessage::EditQuickHost(id)))
                        }
                    };
                }
            }
            SshMessage::SshRetry => {
                if let Some(ref progress) = self.connecting {
                    let origin = progress.origin;
                    let tab_idx = progress.tab_idx;
                    self.connecting = None;
                    if tab_idx < self.tabs.len() {
                        self.tabs.remove(tab_idx);
                        self.adjust_last_terminal_tab_after_remove(tab_idx);
                    }
                    self.active_tab = None;
                    return match origin {
                        crate::state::ProgressOrigin::Saved(id) => {
                            self.update(Message::Ssh(SshMessage::ConnectSavedHost(id)))
                        }
                        crate::state::ProgressOrigin::Quick(id) => {
                            match self.quick_connects.get(&id).cloned() {
                                Some(entry) => self
                                    .update(Message::Ssh(SshMessage::QuickConnect(Box::new(entry)))),
                                None => Task::none(),
                            }
                        }
                    };
                }
            }
            SshMessage::SshBanner(pane_id, text) => {
                // Progress-card copy, so legal notices / MFA instructions
                // are readable while the auth prompts are up. Multiple
                // banners concatenate, but CAPPED: banners are
                // unauthenticated input, and an unbounded concat would
                // hand a hostile server a memory + per-frame-redaction
                // lever. 8 KiB shows any real notice; the terminal copy
                // below (scrollback-bounded) carries the overflow.
                const BANNER_CAP: usize = 8 * 1024;
                // A whitespace-only banner must not materialize an empty
                // card block (or an empty scrollback write below).
                if text.trim().is_empty() {
                    return Task::none();
                }
                // Card copy scoped to the dial this card tracks: a banner
                // from a connect whose card a newer tab's dial superseded
                // must not render on that connect's card.
                if self
                    .connecting
                    .as_ref()
                    .is_some_and(|p| p.pane_id == pane_id)
                    && let Some(p) = &mut self.connecting
                {
                    let slot = p.banner.get_or_insert_with(String::new);
                    if slot.len() < BANNER_CAP {
                        if !slot.is_empty() {
                            slot.push('\n');
                        }
                        slot.push_str(text.trim_end());
                        if slot.len() > BANNER_CAP {
                            let mut cut = BANNER_CAP;
                            while !slot.is_char_boundary(cut) {
                                cut -= 1;
                            }
                            slot.truncate(cut);
                            slot.push('\u{2026}');
                        }
                    }
                }
                // Terminal copy: lands in THIS pane's own tab's
                // scrollback (not the current progress card's tab, which
                // concurrent connections may have taken over), so the
                // banner is still reviewable after the card closes
                // (PuTTY prints it in the terminal). The emulator wants
                // CRLF.
                if let Some(tab_idx) = self.pane_tab_index(pane_id)
                    && let Some(tab) = self.tabs.get(tab_idx)
                    && let Ok(mut state) = tab.active().terminal.lock()
                {
                    let normalized = text.replace("\r\n", "\n").replace('\n', "\r\n");
                    state.process(normalized.as_bytes());
                }
            }
            SshMessage::SshProxyOutput(pane_id, line) => {
                // Card copy only, scoped to the dial this card tracks, and
                // capped: a proxy that prints forever must not grow it.
                const PROXY_LINES_CAP: usize = 200;
                if !line.trim().is_empty()
                    && let Some(p) = self.connecting.as_mut().filter(|p| p.pane_id == pane_id)
                    && p.proxy_output.len() < PROXY_LINES_CAP
                {
                    p.proxy_output.push(line);
                }
            }
            SshMessage::SshPaneProxyOutput(pane_id, line) => {
                // Split-pane / in-place dial: no card, so the proxy's words
                // land in the pane as dim marker lines, the way the
                // "[connecting to ...]" line does.
                if !line.trim().is_empty()
                    && let Some(pane) = self.pane_by_id_mut(pane_id)
                    && let Ok(mut state) = pane.terminal.lock()
                {
                    state.process(format!("\x1b[2m{}\x1b[0m\r\n", line.trim_end()).as_bytes());
                }
            }
            SshMessage::SshPaneBanner(pane_id, text) => {
                // Split-pane connect: no progress card, straight to the
                // pane's terminal.
                if text.trim().is_empty() {
                    return Task::none();
                }
                if let Some(pane) = self.pane_by_id_mut(pane_id)
                    && let Ok(mut state) = pane.terminal.lock()
                {
                    let normalized = text.replace("\r\n", "\n").replace('\n', "\r\n");
                    state.process(normalized.as_bytes());
                }
            }
            // The router sends only this family here, so anything
            // else is a grouping mistake, not a runtime case.
            m => return crate::dispatch::unrouted(m),
        }
        Task::none()
    }
}
