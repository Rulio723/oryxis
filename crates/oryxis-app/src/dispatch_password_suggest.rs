//! Password-suggest popup: offer a stored credential at a password
//! prompt (issue #117, Termius parity).
//!
//! The detector is [`oryxis_terminal::prompt_detect`], fed off the grid
//! once per output batch. This module owns everything after that: which
//! credentials are worth offering, when a popup may open at all, the
//! keyboard contract, and the injection.
//!
//! Three rules the whole design hangs on:
//!
//! - **Nothing is ever sent without a pick.** The popup is a
//!   suggestion. Enter with nothing selected still belongs to the
//!   prompt, so a user who typed their password by hand is never
//!   interrupted.
//! - **No plaintext in app state.** Entries carry the vault row to read
//!   from, never the credential. The decrypt happens on the pick and
//!   the buffer is scrubbed after the write.
//! - **Never over a login script.** A `LoginScript` run exists to
//!   answer exactly these prompts (issue #122). Offering the user a
//!   second credential for a prompt the runner is already answering
//!   would put two secrets on one PTY.

use iced::Task;

use crate::app::{Message, Oryxis, TerminalMessage};
use crate::state::{OverlayContent, OverlayState, PasswordSource, PasswordSourceKind};

/// Gap between the caret and the popup, on whichever side it opens.
/// Shared with the layout's flip so both edges sit the same distance
/// from the text they belong to.
pub(crate) const CARET_GAP: f32 = 2.0;

/// Fold this batch's detection into the pane's remembered signature and
/// answer whether a popup should be raised.
///
/// The whole edge-trigger lives here. Grid reading is stateless, so a
/// prompt still on screen re-detects on every output batch (a bell, an
/// OSC, a keepalive); without this the popup would reopen forever, and
/// Esc would be undone by the next byte to arrive.
///
/// Call it ONLY on batches where the detection actually ran. A gated
/// batch knows nothing about the screen, and clearing the signature on
/// one would resurrect a dismissed popup as soon as the gate lifted.
pub(crate) fn observe_password_prompt(
    sig: &mut Option<(String, i64)>,
    prompt: Option<oryxis_terminal::PasswordPrompt>,
) -> bool {
    match prompt {
        Some(p) => {
            let next = (p.text, p.abs_line);
            if sig.as_ref() == Some(&next) {
                // Same prompt, still waiting. Already offered (or
                // already dismissed); either way, say nothing.
                return false;
            }
            *sig = Some(next);
            true
        }
        // The prompt is gone (answered, redrawn, or a full-screen app
        // took the pane): forget it, so the same text at the same row
        // later reads as a new prompt.
        None => {
            *sig = None;
            false
        }
    }
}

/// The credentials to offer, most likely first.
///
/// Ordinarily: the pane's own host, then the identity that host
/// authenticates with (on a host that logs in through an identity, that
/// is the account `sudo` is asking about), then every other identity
/// with a password, by label.
///
/// A prompt that names ANOTHER machine (`target`: an `ssh b` or a git
/// push run inside the session on `a`, the ordinary case inside tmux)
/// is not asking for the pane host's password, and ranking that first
/// would put it one Enter away from a host that did not earn it. Then
/// the named host's own rows lead, identities follow (the named account
/// first), and the pane's host goes last.
pub(crate) fn rank_password_sources(
    conn: Option<&oryxis_core::models::Connection>,
    target: Option<&oryxis_terminal::prompt_detect::PromptTarget>,
    connections: &[oryxis_core::models::Connection],
    identities: &[oryxis_core::models::Identity],
    with_password: &std::collections::HashSet<uuid::Uuid>,
    identities_with_password: &std::collections::HashSet<uuid::Uuid>,
) -> Vec<PasswordSource> {
    let conn_source = |c: &oryxis_core::models::Connection| PasswordSource {
        label: c.label.clone(),
        sublabel: c.username.clone().unwrap_or_default(),
        kind: PasswordSourceKind::Connection(c.id),
    };
    let ident_source = |i: &oryxis_core::models::Identity| PasswordSource {
        label: i.label.clone(),
        sublabel: i.username.clone().unwrap_or_default(),
        kind: PasswordSourceKind::Identity(i.id),
    };
    let mut out: Vec<PasswordSource> = Vec::new();

    let foreign = target.filter(|t| conn.is_none_or(|c| !names_host(c, &t.host)));
    if let Some(target) = foreign {
        let not_named_user = |user: &Option<String>| target.user.is_some() && *user != target.user;
        let mut named: Vec<&oryxis_core::models::Connection> = connections
            .iter()
            .filter(|c| names_host(c, &target.host) && with_password.contains(&c.id))
            .collect();
        named.sort_by_key(|c| (not_named_user(&c.username), c.label.to_lowercase()));
        out.extend(named.into_iter().map(conn_source));
        let mut idents: Vec<&oryxis_core::models::Identity> = identities
            .iter()
            .filter(|i| identities_with_password.contains(&i.id))
            .collect();
        idents.sort_by_key(|i| (not_named_user(&i.username), i.label.to_lowercase()));
        out.extend(idents.into_iter().map(ident_source));
        if let Some(conn) = conn
            && with_password.contains(&conn.id)
        {
            out.push(conn_source(conn));
        }
        return out;
    }

    let mut seen_identity = std::collections::HashSet::new();
    if let Some(conn) = conn {
        if with_password.contains(&conn.id) {
            out.push(conn_source(conn));
        }
        if let Some(id) = conn.identity_id
            && identities_with_password.contains(&id)
            && let Some(ident) = identities.iter().find(|i| i.id == id)
        {
            seen_identity.insert(id);
            out.push(ident_source(ident));
        }
    }
    let mut rest: Vec<&oryxis_core::models::Identity> = identities
        .iter()
        .filter(|i| identities_with_password.contains(&i.id) && !seen_identity.contains(&i.id))
        .collect();
    rest.sort_by_key(|i| i.label.to_lowercase());
    out.extend(rest.into_iter().map(ident_source));
    out
}

/// What the popup's title should name: the machine the prompt names,
/// `user@host` as printed (or just the host), WHENEVER it names one,
/// the pane's own host included. Inside tmux or screen the pane cannot
/// tell which of the multiplexer's panes printed the prompt, and a
/// hostile session in a neighbouring pane can print the pane host's own
/// prompt shape; saying whose password is being asked for, every time,
/// is what lets the user see that before picking. `None` for a prompt
/// that names no machine (`sudo`, `doas`, a bare `Password:`).
pub(crate) fn prompt_target_label(
    target: Option<&oryxis_terminal::prompt_detect::PromptTarget>,
) -> Option<String> {
    let target = target?;
    Some(match &target.user {
        Some(user) => format!("{user}@{}", target.host),
        None => target.host.clone(),
    })
}

/// Whether `host`, as a prompt printed it, is `conn`: its address or
/// the label a `ssh` alias would carry. Case-insensitive, like DNS.
fn names_host(conn: &oryxis_core::models::Connection, host: &str) -> bool {
    conn.hostname.eq_ignore_ascii_case(host) || conn.label.eq_ignore_ascii_case(host)
}

impl Oryxis {
    /// Credentials worth offering for a prompt on `pane_id`, ranked by
    /// [`rank_password_sources`]. Empty when there is nothing to offer,
    /// which is what keeps the popup from ever opening on an empty list.
    fn password_suggest_sources(
        &self,
        pane_id: uuid::Uuid,
    ) -> (Vec<PasswordSource>, Option<String>) {
        // Which rows HAVE a password is asked of the vault here, once
        // per popup, rather than read from a boot-time cache. A password
        // can be written by paths that never refresh one (a sync apply,
        // a portable import, an ssh-config import), and a stale cache
        // fails in the direction that looks like the feature is broken:
        // a host whose password you can see in the editor, never
        // offered. Both queries are existence checks (no decrypt, no
        // unlock), and once per prompt is not a hot path.
        let Some(vault) = self.vault.as_ref() else {
            return (Vec::new(), None);
        };
        let with_password = vault.list_connection_ids_with_password().unwrap_or_default();
        let identities_with_password =
            vault.list_identity_ids_with_password().unwrap_or_default();

        // The pane's host. Quick-connect hosts live in an in-memory
        // store with no vault row, so only saved hosts qualify.
        let pane = self.pane_by_id(pane_id);
        let conn = pane.and_then(|p| match &p.origin {
            crate::state::PaneOrigin::Host(id) => {
                self.connections.iter().find(|c| c.id == *id)
            }
            _ => None,
        });
        let target = pane
            .and_then(|p| p.password_prompt_sig.as_ref())
            .and_then(|(text, _)| oryxis_terminal::prompt_detect::prompt_target(text));
        let entries = rank_password_sources(
            conn,
            target.as_ref(),
            &self.connections,
            &self.identities,
            &with_password,
            &identities_with_password,
        );
        (entries, prompt_target_label(target.as_ref()))
    }

    /// The pane a password prompt may raise a popup on right now, or
    /// `None` when no popup should open at all.
    ///
    /// Everything here is a "the user is not looking at this pane"
    /// test. A background pane hitting `sudo` must not throw an overlay
    /// over the Dashboard, and the overlay slot is single: opening over
    /// a kebab menu the user is mid-click on would steal it.
    pub(crate) fn password_suggest_target(&self) -> Option<uuid::Uuid> {
        if !self.prefs.terminal_password_autofill || self.overlay.is_some() {
            return None;
        }
        // A blocking modal owns the screen and the keyboard (a host-key
        // prompt from a background reconnect, an error dialog, the
        // update dialog). Opening under one would put a popup the user
        // cannot see in front of the keys they are aiming at the modal.
        if self.any_modal_blocks_input() {
            return None;
        }
        // The soft auto-lock keeps sessions (and their output) flowing
        // with `active_view` untouched, so without this gate a prompt
        // arriving behind the lock screen would open a popup in state
        // that pops into view at unlock: the existence checks below
        // work on a SEALED vault by design.
        if self.vault_ui.state != crate::state::VaultState::Unlocked {
            return None;
        }
        // Whether the terminal is ON SCREEN is asked of the same helper
        // `view_content` decides the content area with, never of
        // `active_view`. The two stopped agreeing when tabs became the
        // outer surface: opening a host from the Dashboard pushes a tab
        // and leaves `active_view` on `Dashboard`, and the tab wins in
        // `view_content`, so the terminal the user is looking at reads
        // as "not the current view". That gate barred the popup on the
        // ordinary path (click a host, run `sudo`) while the Local
        // Shell picker, which does assign `active_view`, kept working,
        // which is why the committed `.ice` never saw it. It also
        // covers the connect screen, which `active_view` cannot.
        if !self.terminal_surface_visible() {
            return None;
        }
        let tab = self.tabs.get(self.active_tab?)?;
        if tab.files_mode {
            return None;
        }
        Some(tab.active().id)
    }

    /// Open the popup for a prompt just detected on `pane_id`.
    ///
    /// Two ways to decline, and they are not the same. Nothing to offer
    /// is a settled answer for this vault state, so the caller keeps the
    /// signature and stops asking. A missing anchor is transient (the
    /// pane has not reported a drawn rect yet), so the caller drops the
    /// signature and the next output batch tries again; without that
    /// distinction a prompt that arrived one frame too early would be
    /// silently skipped for good.
    pub(crate) fn show_password_suggest(&mut self, pane_id: uuid::Uuid) {
        let (entries, prompt_for) = self.password_suggest_sources(pane_id);
        if entries.is_empty() {
            return;
        }
        let Some((x, y, caret_top)) = self.password_suggest_anchor(pane_id) else {
            if let Some(pane) = self.pane_by_id_mut(pane_id) {
                pane.password_prompt_sig = None;
            }
            return;
        };
        self.overlay = Some(OverlayState {
            content: OverlayContent::PasswordSuggest {
                pane_id,
                entries,
                selected: None,
                caret_top,
                scroll: 0.0,
                prompt_for,
            },
            x,
            y,
        });
    }

    /// Window coordinates just under the terminal caret of `pane_id`,
    /// plus the caret's own top edge (the pivot the layout flips the
    /// popup over when it does not fit below).
    /// `None` before the pane has ever been drawn (no reported bounds),
    /// which also means the user cannot be looking at it.
    fn password_suggest_anchor(&self, pane_id: uuid::Uuid) -> Option<(f32, f32, f32)> {
        let pane = self.pane_by_id(pane_id)?;
        let bounds = pane.bounds.get();
        if bounds.width <= 0.0 || bounds.height <= 0.0 {
            return None;
        }
        let cell = pane.terminal.lock().ok()?.cursor_cell();
        let caret = oryxis_terminal::ime_caret_rect(
            bounds,
            self.terminal_font_px(),
            Some(self.terminal_font_name.as_str()),
            self.terminal_font_weight.font_weight(),
            cell,
        );
        Some((caret.x, caret.y + caret.height + CARET_GAP, caret.y))
    }

    /// Keep the keyboard selection inside the popup's viewport, and
    /// scroll ONLY when it would otherwise leave it: a list that yanks
    /// on every arrow press is unreadable (same contract as the SFTP
    /// row list). A no-op while the whole list fits, where there is no
    /// scrollable mounted at all.
    ///
    /// Rows are not uniform here (a credential with a username is two
    /// lines tall), so the offsets come from the same metrics the popup
    /// is drawn by rather than from `idx * ROW_H`.
    fn password_suggest_scroll_into_view(&mut self, idx: usize) -> Task<Message> {
        use crate::views::layout::{
            password_suggest_layout, password_suggest_row_height, password_suggest_row_top,
            password_suggest_rows_height, PASSWORD_SUGGEST_SCROLL_ID,
        };
        let window_h = self.window_size.height;
        let Some(OverlayContent::PasswordSuggest {
            entries, scroll, ..
        }) = self.overlay.as_mut().map(|o| &mut o.content)
        else {
            return Task::none();
        };
        let Some(viewport) = password_suggest_layout(entries, window_h).rows_viewport else {
            return Task::none();
        };
        let Some(row_h) = entries.get(idx).map(password_suggest_row_height) else {
            return Task::none();
        };
        let max_scroll = (password_suggest_rows_height(entries) - viewport).max(0.0);
        let row_top = password_suggest_row_top(entries, idx);
        let at = scroll.clamp(0.0, max_scroll);
        let next = if row_top < at {
            row_top
        } else if row_top + row_h > at + viewport {
            row_top + row_h - viewport
        } else {
            // Already fully visible: leave the list where the user
            // (or the previous move) put it.
            return Task::none();
        };
        let next = next.clamp(0.0, max_scroll);
        // Optimistic, because a burst of arrow presses lands before the
        // scrollable's own `on_scroll` reports back.
        *scroll = next;
        iced::widget::operation::scroll_to(
            iced::widget::Id::new(PASSWORD_SUGGEST_SCROLL_ID),
            iced::widget::scrollable::AbsoluteOffset { x: 0.0, y: next },
            iced::widget::operation::Animation::Instant,
        )
    }

    /// The open popup's pane + entries + selection, if one is up.
    fn password_suggest_state(&self) -> Option<(uuid::Uuid, &[PasswordSource], Option<usize>)> {
        match self.overlay.as_ref().map(|o| &o.content) {
            Some(OverlayContent::PasswordSuggest {
                pane_id,
                entries,
                selected,
                ..
            }) => Some((*pane_id, entries.as_slice(), *selected)),
            _ => None,
        }
    }

    /// The pane the open popup belongs to. Callers that close it on a
    /// context switch use this so they only ever clear an overlay that
    /// is theirs.
    pub(crate) fn password_suggest_pane(&self) -> Option<uuid::Uuid> {
        self.password_suggest_state().map(|(pane_id, _, _)| pane_id)
    }

    /// Close the popup if it is open, leaving any other overlay alone.
    /// Called on every context switch that makes the suggestion stale:
    /// clicking a pane, switching tabs, typing.
    pub(crate) fn dismiss_password_suggest(&mut self) {
        if self.password_suggest_pane().is_some() {
            self.overlay = None;
        }
    }

    /// Same, but only when the popup belongs to `pane_id`. For events
    /// that are about one pane (a disconnect) on a tab whose other
    /// panes are still live.
    pub(crate) fn dismiss_password_suggest_for(&mut self, pane_id: uuid::Uuid) {
        if self.password_suggest_pane() == Some(pane_id) {
            self.overlay = None;
        }
    }

    pub(crate) fn handle_password_suggest(&mut self, message: TerminalMessage) -> Task<Message> {
        match message {
            TerminalMessage::PasswordSuggestNavigate(delta) => {
                let Some((_, entries, selected)) = self.password_suggest_state() else {
                    return Task::none();
                };
                let len = entries.len();
                if len == 0 {
                    return Task::none();
                }
                // The first move engages the popup and lands on the
                // first row regardless of direction: Up as an opener
                // should reach the list, not wrap to its end.
                let next = match selected {
                    None => 0,
                    Some(cur) => {
                        let n = cur as i64 + delta as i64;
                        n.rem_euclid(len as i64) as usize
                    }
                };
                if let Some(OverlayContent::PasswordSuggest { selected, .. }) =
                    self.overlay.as_mut().map(|o| &mut o.content)
                {
                    *selected = Some(next);
                }
                return self.password_suggest_scroll_into_view(next);
            }
            TerminalMessage::PasswordSuggestScrolled(offset) => {
                if let Some(OverlayContent::PasswordSuggest { scroll, .. }) =
                    self.overlay.as_mut().map(|o| &mut o.content)
                {
                    *scroll = offset;
                }
            }
            TerminalMessage::PasswordSuggestDismiss => {
                self.dismiss_password_suggest();
            }
            TerminalMessage::PasswordSuggestPick(idx) => {
                let Some((pane_id, entries, _)) = self.password_suggest_state() else {
                    return Task::none();
                };
                let Some(kind) = entries.get(idx).map(|e| e.kind) else {
                    return Task::none();
                };
                self.overlay = None;
                let secret = match kind {
                    PasswordSourceKind::Connection(id) => self
                        .vault
                        .as_ref()
                        .and_then(|v| v.get_connection_password(&id).ok().flatten()),
                    PasswordSourceKind::Identity(id) => self
                        .vault
                        .as_ref()
                        .and_then(|v| v.get_identity_password(&id).ok().flatten()),
                };
                let Some(secret) = secret.filter(|s| !s.is_empty()) else {
                    // The row was built from an existence check; a miss
                    // here means the vault relocked or the row was
                    // deleted between show and pick.
                    self.set_toast(crate::i18n::t("no_stored_password").to_string());
                    return crate::shortcuts::toast_clear_after_secs(2);
                };
                self.send_password_to_pane(pane_id, secret);
            }
            // Routed here by the parent; anything else is a grouping
            // mistake, not a runtime case.
            m => return crate::dispatch::unrouted(m),
        }
        Task::none()
    }

    /// Type `secret` + Enter into `pane_id` through the input-capture
    /// bypass, then scrub the buffer.
    ///
    /// Shared by the popup and by the sudo-password snippet action, so
    /// there is one implementation of "hand a credential to a prompt".
    pub(crate) fn send_password_to_pane(&mut self, pane_id: uuid::Uuid, mut secret: String) {
        use zeroize::Zeroize as _;
        // Pre-size so the trailing newline can't force a realloc that
        // would strand a freed copy of the plaintext (a fresh
        // `into_bytes().push()` usually does, since a decrypted String's
        // capacity equals its length). Then scrub the source String too.
        let mut data = Vec::with_capacity(secret.len() + 1);
        data.extend_from_slice(secret.as_bytes());
        data.push(b'\n');
        secret.zeroize();
        self.write_secret_to_pane(pane_id, &data);
        crate::dispatch_login_script::zeroize_bytes(&mut data);
    }

    /// Keyboard contract of the popup, run BEFORE the modal navigation
    /// router so the arrow keys reach it (the modal router's catch-all
    /// would claim them first).
    ///
    /// Deliberately non-modal. Unengaged, it consumes only the two keys
    /// that address it (Down to engage, Esc to dismiss) and lets
    /// everything else through to the PTY, so the user can just keep
    /// typing their password. Engaged, it owns movement and Enter until
    /// the user leaves it, and any printable key both dismisses the
    /// popup AND reaches the prompt: typing is an answer, not a
    /// navigation.
    pub(crate) fn handle_password_suggest_key(
        &mut self,
        event: &iced::keyboard::Event,
    ) -> Option<Task<Message>> {
        use iced::keyboard::{key::Named, Event, Key};
        let (_, _, selected) = self.password_suggest_state()?;
        // A modal opened while the popup was up (a reconnect's host-key
        // prompt, an error dialog). Attention has moved and the
        // suggestion is stale: drop it and let the modal's own router
        // have the key it was aimed at.
        if self.any_modal_blocks_input() {
            self.dismiss_password_suggest();
            return None;
        }
        let Event::KeyPressed { key, modifiers, .. } = event else {
            return None;
        };
        // A chord belongs to the binding table, not to a popup that
        // never advertised one.
        if modifiers.control() || modifiers.alt() || modifiers.logo() {
            return None;
        }
        let msg = |m: TerminalMessage| Some(Task::done(Message::Terminal(m)));
        match key {
            Key::Named(Named::Escape) => msg(TerminalMessage::PasswordSuggestDismiss),
            Key::Named(Named::ArrowDown) => msg(TerminalMessage::PasswordSuggestNavigate(1)),
            // Up only enters the list once it is engaged. Unengaged it
            // stays with readline's history, which is what an Up press
            // at a shell prompt means everywhere else.
            Key::Named(Named::ArrowUp) if selected.is_some() => {
                msg(TerminalMessage::PasswordSuggestNavigate(-1))
            }
            Key::Named(Named::Enter) if let Some(i) = selected => {
                msg(TerminalMessage::PasswordSuggestPick(i))
            }
            // Enter with nothing selected is the user answering the
            // prompt themselves: close, and let the key through.
            Key::Named(Named::Enter) => {
                self.dismiss_password_suggest();
                None
            }
            // Typing is an answer too. Dismiss without consuming, so
            // the character still reaches the PTY.
            Key::Character(_) | Key::Named(Named::Space) => {
                self.dismiss_password_suggest();
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oryxis_terminal::PasswordPrompt;

    fn prompt(text: &str, abs_line: i64) -> Option<PasswordPrompt> {
        Some(PasswordPrompt {
            text: text.into(),
            abs_line,
        })
    }

    fn ranked_labels(
        pane_host: usize,
        prompt: &str,
        conns: &[oryxis_core::models::Connection],
        idents: &[oryxis_core::models::Identity],
    ) -> Vec<String> {
        let with: std::collections::HashSet<uuid::Uuid> = conns.iter().map(|c| c.id).collect();
        let iwith: std::collections::HashSet<uuid::Uuid> = idents.iter().map(|i| i.id).collect();
        let target = oryxis_terminal::prompt_detect::prompt_target(prompt);
        rank_password_sources(Some(&conns[pane_host]), target.as_ref(), conns, idents, &with, &iwith)
            .into_iter()
            .map(|s| s.label)
            .collect()
    }

    #[test]
    fn a_prompt_naming_another_host_does_not_lead_with_the_pane_host() {
        use oryxis_core::models::{Connection, Identity};
        let a = Connection::new("alpha", "10.0.0.1");
        let mut b = Connection::new("bravo", "10.0.0.2");
        b.username = Some("deploy".into());
        let mut ops = Identity::new("ops");
        ops.username = Some("deploy".into());
        let admin = Identity::new("admin");
        let conns = vec![a, b];
        let idents = vec![admin, ops];

        // `ssh deploy@10.0.0.2` run inside the session on alpha.
        assert_eq!(
            ranked_labels(0, "deploy@10.0.0.2's password:", &conns, &idents),
            ["bravo", "ops", "admin", "alpha"]
        );
        // A host the vault does not know: identities first, pane last.
        assert_eq!(
            ranked_labels(0, "(root@elsewhere) Password:", &conns, &idents),
            ["admin", "ops", "alpha"]
        );
        // The prompt names the pane's own host (by address or by label):
        // the ordinary ranking.
        assert_eq!(
            ranked_labels(0, "root@10.0.0.1's password:", &conns, &idents),
            ["alpha", "admin", "ops"]
        );
        assert_eq!(
            ranked_labels(0, "root@ALPHA's password:", &conns, &idents),
            ["alpha", "admin", "ops"]
        );
        // A local prompt keeps the pane's host first.
        assert_eq!(
            ranked_labels(0, "[sudo] password for wilson:", &conns, &idents),
            ["alpha", "admin", "ops"]
        );
    }

    #[test]
    fn a_prompt_that_stays_on_screen_is_offered_once() {
        // The failure this guards: grid reading is stateless, so every
        // batch after the prompt (a bell, an OSC, a keepalive) would
        // re-raise the popup on top of itself.
        let mut sig = None;
        assert!(observe_password_prompt(&mut sig, prompt("Password:", 4)));
        for _ in 0..5 {
            assert!(
                !observe_password_prompt(&mut sig, prompt("Password:", 4)),
                "the same prompt must not re-raise"
            );
        }
    }

    #[test]
    fn a_dismissal_survives_the_next_batch() {
        // Esc leaves the signature recorded; output arriving after it
        // (sudo's own bell, a keepalive) must not undo the dismissal.
        let mut sig = None;
        assert!(observe_password_prompt(&mut sig, prompt("Password:", 4)));
        // ... user pressed Esc; the popup is gone but the signature is not.
        assert!(!observe_password_prompt(&mut sig, prompt("Password:", 4)));
    }

    #[test]
    fn the_retry_after_a_wrong_password_is_a_new_prompt() {
        // `Sorry, try again.` scrolls the retry onto a new row, which
        // is exactly why the row is half of the identity.
        let mut sig = None;
        assert!(observe_password_prompt(
            &mut sig,
            prompt("[sudo] password for wilson:", 4)
        ));
        assert!(observe_password_prompt(
            &mut sig,
            prompt("[sudo] password for wilson:", 6)
        ));
    }

    #[test]
    fn answering_the_prompt_clears_the_memory() {
        // Same prompt text at the same row later (a screen that scrolled
        // back to the same offset) has to read as new again.
        let mut sig = None;
        assert!(observe_password_prompt(&mut sig, prompt("Password:", 4)));
        assert!(!observe_password_prompt(&mut sig, None));
        assert_eq!(sig, None);
        assert!(observe_password_prompt(&mut sig, prompt("Password:", 4)));
    }

    #[test]
    fn the_title_names_whatever_machine_the_prompt_names() {
        let target = |p: &str| oryxis_terminal::prompt_detect::prompt_target(p);
        // The pane's own host is named too: inside tmux the prompt may
        // come from a different session printing that host's shape.
        assert_eq!(
            prompt_target_label(target("bob@web.example's password:").as_ref()),
            Some("bob@web.example".to_string())
        );
        assert_eq!(
            prompt_target_label(target("bob@db's password:").as_ref()),
            Some("bob@db".to_string())
        );
        // A local `sudo` names nobody, and keeps the plain title.
        assert_eq!(prompt_target_label(target("[sudo] password for bob:").as_ref()), None);
    }
}
