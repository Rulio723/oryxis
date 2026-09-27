//! Menus and the odd global affordance: the burger, the sub-nav
//! overflow, a card's kebab, the view's search field, and running a
//! hotkey action by name.

use super::*;

impl Oryxis {
    pub(super) fn handle_tabs_menus(&mut self, message: TabsMessage) -> Task<Message> {
        match message {
            TabsMessage::ToggleBurgerMenu => {
                self.panels.burger_menu = !self.panels.burger_menu;
            }
            TabsMessage::ToggleSubnavOverflow => {
                self.panels.subnav_overflow = !self.panels.subnav_overflow;
            }
            TabsMessage::HideOverlayMenu => {
                self.overlay = None;
                self.card_context_menu = None;
                self.snippet_context_menu = None;
                self.keys_ui.context_menu = None;
                self.identity_context_menu = None;
                self.port_forward_context_menu = None;
                self.panels.keychain_add_menu = false;
            }
            TabsMessage::ShowCardMenu(idx) => {
                // The index is resolved to the host ID HERE, against
                // the list this click was rendered from; everything
                // downstream (the menu's items, the card's own kebab
                // highlight) keys off the id, so a re-sort under the
                // open menu can't re-aim it at another host.
                let Some(id) = self.connections.get(idx).map(|c| c.id) else {
                    return Task::none();
                };
                if self.card_context_menu == Some(id) {
                    self.card_context_menu = None;
                    self.overlay = None;
                } else {
                    self.card_context_menu = Some(id);
                    let anchor = self.keynav_take_menu_anchor();
                    self.overlay = Some(OverlayState {
                        content: OverlayContent::HostActions(id),
                        x: anchor.0,
                        y: anchor.1,
                    });
                }
            }
            TabsMessage::ShowTreeHostMenu(idx) => {
                // Same anchor contract as ShowCardMenu: the Menu key
                // parks the ringed row's rect in `keynav.menu_anchor`,
                // a right-click falls back to the cursor. No
                // `card_context_menu` here: that flag pins the
                // dashboard card's kebab, which the tree row doesn't
                // have.
                let Some(id) = self.connections.get(idx).map(|c| c.id) else {
                    return Task::none();
                };
                let anchor = self.keynav_take_menu_anchor();
                self.overlay = Some(OverlayState {
                    content: OverlayContent::TreeHostActions(id),
                    x: anchor.0,
                    y: anchor.1,
                });
            }
            TabsMessage::HideCardMenu => {
                self.card_context_menu = None;
                self.overlay = None;
            }
            TabsMessage::RunHotkeyAction(action) => {
                return self.dispatch_hotkey_action(
                    action,
                    crate::hotkeys::FamilyMatch::Plain,
                );
            }
            TabsMessage::RunHotkeyActionRepeated(action, times) => {
                // Bounded: a runaway count from a driver reporting a huge
                // magnification must not freeze the loop. The font clamp
                // makes anything past a few dozen steps a no-op anyway.
                let tasks: Vec<Task<Message>> = (0..times.min(64))
                    .map(|_| {
                        self.dispatch_hotkey_action(action, crate::hotkeys::FamilyMatch::Plain)
                    })
                    .collect();
                return Task::batch(tasks);
            }
            TabsMessage::OpenSettingsSection(section) => {
                // Switch to Settings AND select the section:
                // ChangeSettingsSection alone assumes the view is open.
                let t1 = self.update(Message::Navigation(NavigationMessage::ChangeView(View::Settings)));
                let t2 = self.update(Message::Settings(SettingsMessage::ChangeSettingsSection(section)));
                return Task::batch([t1, t2]);
            }
            TabsMessage::FocusViewSearch => {
                // Ctrl+F always returns keynav to the canonical idle
                // state (search = "zone zero", `focus == None`).
                self.keynav.focus = None;
                // Over a focused terminal pane, Ctrl+F opens the scrollback
                // find-bar (C1). `active_tab` is cleared on navigation into
                // the vault / settings / SFTP surfaces, so its presence means
                // the terminal surface is the one on screen; the hybrid Files
                // (SFTP) mode is excluded, since it has its own remote filter,
                // reached through `active_view_search_id` below.
                if let Some(tab) = self.active_tab.and_then(|i| self.tabs.get(i))
                    && !tab.files_mode
                {
                    return self.update(Message::Terminal(TerminalMessage::TerminalSearchOpen));
                }
                if let Some(id) = self.active_view_search_id() {
                    return crate::widgets::focus_input(id);
                }
            }
            // Routed here by the parent; anything else is a
            // grouping mistake, not a runtime case.
            m => return crate::dispatch::unrouted(m),
        }
        Task::none()
    }
}
