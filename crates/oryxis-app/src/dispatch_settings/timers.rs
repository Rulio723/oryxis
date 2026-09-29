//! The settings that own a clock: auto-reconnect, the vault's idle
//! auto-lock, and the connect animation.
//!
//! Their ticks live with them. `AutoReconnectTick` is the largest thing
//! here because a reconnect has to decide, per dormant tab, whether it
//! is due, allowed and not already in flight.

use super::*;

impl Oryxis {
    pub(super) fn handle_settings_timers(
        &mut self,
        message: SettingsMessage,
    ) -> Result<Task<Message>, SettingsMessage> {
        match message {
            SettingsMessage::SettingToggleAutoReconnect => {
                self.prefs.auto_reconnect = !self.prefs.auto_reconnect;
                self.persist_setting(
                    "auto_reconnect",
                    if self.prefs.auto_reconnect { "true" } else { "false" },
                );
            }
            SettingsMessage::SettingMaxReconnectChanged(val) => {
                self.prefs.max_reconnect_attempts = sanitize_uint(&val, 100);
                self.persist_setting(
                    "max_reconnect_attempts",
                    &self.prefs.max_reconnect_attempts,
                );
            }
            SettingsMessage::SettingAutoLockChanged(val) => {
                self.prefs.auto_lock_minutes = sanitize_uint(&val, 1440);
                self.persist_setting("auto_lock_minutes", &self.prefs.auto_lock_minutes);
            }
            SettingsMessage::SettingManualLockActionChanged(val) => {
                // Sibling of the lock family above: what the Lock Vault
                // button does. The pick_list only offers the three known
                // tokens, but the guard keeps a corrupted row from
                // sticking as a phantom fourth state.
                let normalized = match val.as_str() {
                    "sleep" | "lock" => val.as_str(),
                    _ => "ask",
                };
                self.prefs.manual_lock_action = normalized.into();
                self.persist_setting("manual_lock_action", normalized);
            }
            SettingsMessage::AutoLockTick => {
                // Idle check. Guarded on Unlocked so a tick racing the
                // lock is a no-op, and on a parseable non-zero threshold
                // (the subscription only mounts then, but the setting can
                // change between mount and fire).
                let minutes = self
                    .prefs.auto_lock_minutes
                    .parse::<u64>()
                    .ok()
                    .filter(|m| *m > 0);
                if let Some(minutes) = minutes
                    && self.vault_ui.state == crate::state::VaultState::Unlocked
                    // Without a master password, locking reopens
                    // immediately; auto-locking would just churn.
                    && self.vault_ui.has_user_password
                    && self.last_user_activity.elapsed().as_secs() >= minutes * 60
                {
                    tracing::info!("vault auto-lock after {minutes} min idle");
                    return Ok(Task::done(Message::Vault(VaultMessage::SoftLockVault)));
                }
            }
            SettingsMessage::ConnectAnimTick => {
                self.connect_anim_tick = self.connect_anim_tick.wrapping_add(1);
            }
            SettingsMessage::AutoReconnectTick => {
                // Liveness sweep, independent of the auto-reconnect setting.
                // A pane whose SSH writer task has died reports
                // `is_alive() == false` while its reader may still be
                // draining output: the tab looks "connected" but silently
                // swallows every keystroke (the writer's `send` errors and
                // the input sites discard it). Nothing else checks
                // `is_alive`, so without this such a pane stays a dead
                // input sink forever. Surface it as a real disconnect so the
                // UI updates and, when enabled, reconnect kicks in. Panes
                // already torn down have `session == None` and are
                // skipped, so this can't loop.
                let dead: Vec<_> = self
                    .tabs
                    .iter()
                    .flat_map(|t| t.pane_grid.panes.values())
                    .filter(|p| p.session.as_ref().is_some_and(|s| !s.is_alive()))
                    .map(|p| p.id)
                    .collect();
                if !dead.is_empty() {
                    return Ok(Task::batch(
                        dead.into_iter()
                            .map(|id| Task::done(Message::Ssh(SshMessage::SshDisconnected(id)))),
                    ));
                }
                if !self.prefs.auto_reconnect {
                    // fall through, nothing to do
                } else {
                    let max_attempts: u32 =
                        self.prefs.max_reconnect_attempts.parse().unwrap_or(5);
                    // Find the first disconnected SSH tab whose counter is under the limit.
                    // Only reconnect one per tick to avoid thrashing; next tick picks up
                    // the next candidate.
                    let candidate: Option<usize> = (0..self.tabs.len()).find(|&i| {
                        let tab = &self.tabs[i];
                        if !tab.label.ends_with(" (disconnected)") {
                            return false;
                        }
                        // Never auto-reconnect a split tab: `ReconnectTab`
                        // removes + rebuilds the whole tab, which would kill
                        // the live sibling panes. (Belt + suspenders: a
                        // multi-pane tab isn't relabeled "(disconnected)" in
                        // the first place, see `SshDisconnected`.)
                        if tab.pane_grid.panes.len() > 1 {
                            return false;
                        }
                        let base = tab.label.trim_end_matches(" (disconnected)");
                        // Quick-connect hosts resolve via the same label
                        // lookup; their counters key on the ephemeral id,
                        // which is stable for the life of the entry.
                        let Some(conn) = self.any_connection_by_label(base) else {
                            return false;
                        };
                        // Nobody started this dial, so it may not ask for a
                        // touch: a security-key host waits for a click.
                        if self.host_signs_with_token(conn) {
                            return false;
                        }
                        let attempts = self.reconnect_counters.get(&conn.id).copied().unwrap_or(0);
                        attempts < max_attempts
                    });
                    if let Some(tab_idx) = candidate {
                        let base = self.tabs[tab_idx]
                            .label
                            .trim_end_matches(" (disconnected)")
                            .to_string();
                        if let Some(cid) = self.any_connection_by_label(&base).map(|c| c.id) {
                            let entry = self.reconnect_counters.entry(cid).or_insert(0);
                            *entry += 1;
                        }
                        return Ok(Task::done(Message::Tabs(TabsMessage::ReconnectTab(tab_idx))));
                    }
                }
            }
            m => return Err(m),
        }
        Ok(Task::none())
    }
}
