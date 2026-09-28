//! The two terminal-sidebar regions (issue #102).
//!
//! Every sidebar tab is docked to a physical side
//! (`AppPrefs::sidebar_tab_side`), so the terminal can carry a LEFT
//! and a RIGHT region at once, each with its own strip, active tab,
//! width and open flag. This module is the single authority for the
//! questions everyone else asks about a region:
//!
//! - which tabs a region offers right now (dock side + feature gates
//!   + the focused pane's transport),
//! - which tab a region shows (the remembered active tab re-resolved
//!   against those offers),
//! - whether a region is actually on screen (open AND non-empty),
//! - what happens when a tab changes sides in Settings.
//!
//! The render site, the keynav router, the tab-bar toggle buttons and
//! the SFTP width reservation all read these, so they can't drift.

use crate::app::Oryxis;
use crate::state::{SidebarSide, TerminalSidebarTab};

impl Oryxis {
    /// Whether the ACTIVE terminal tab's focused pane has a live SSH
    /// session, the transport gate shared by Files / Monitor / Tmux.
    fn active_pane_has_ssh(&self) -> bool {
        self.active_tab
            .and_then(|i| self.tabs.get(i))
            .and_then(|t| t.active().session.as_ref().and_then(|s| s.ssh()))
            .is_some()
    }

    /// Whether the ACTIVE terminal tab's focused pane is a local shell,
    /// which the Files tab serves with the local backend (issue #145).
    fn active_pane_is_local(&self) -> bool {
        self.active_tab
            .and_then(|i| self.tabs.get(i))
            .map(|t| t.active())
            .is_some_and(|p| {
                p.session.is_none()
                    && matches!(p.origin, crate::state::PaneOrigin::Local(_))
            })
    }

    /// Whether a sidebar tab can show at all under the current feature
    /// toggles, ignoring the focused pane's MOMENTARY transport. The
    /// auto-open decision runs while a session is still dialing (nothing
    /// has SSH yet), so it needs this eventual form: gating it on the
    /// live transport would refuse to open a region whose tabs appear
    /// the instant the dial lands.
    fn sidebar_tab_possible(&self, tab: TerminalSidebarTab) -> bool {
        match tab {
            TerminalSidebarTab::Chat => self.ai.enabled,
            TerminalSidebarTab::Files => self.sftp_enabled,
            TerminalSidebarTab::Monitor => self.prefs.host_monitoring,
            TerminalSidebarTab::Tmux => self.prefs.tmux_manager,
            TerminalSidebarTab::Snippets
            | TerminalSidebarTab::History
            | TerminalSidebarTab::HostConfig
            | TerminalSidebarTab::HostsTree => true,
        }
    }

    /// Whether a sidebar tab is offered at all for the active terminal
    /// tab: its feature toggles plus the focused pane's transport.
    /// Snippets / History / Host config / Hosts never gate, so a
    /// region holding any of them survives any pane. (Placement is a
    /// separate axis: a HIDDEN tab never reaches the region filters,
    /// available or not.)
    pub(crate) fn sidebar_tab_available(&self, tab: TerminalSidebarTab) -> bool {
        self.sidebar_tab_possible(tab)
            && match tab {
                // Files also serves local shells (issue #145); Monitor
                // and Tmux stay strictly transport-bound.
                TerminalSidebarTab::Files => {
                    self.active_pane_has_ssh() || self.active_pane_is_local()
                }
                TerminalSidebarTab::Monitor | TerminalSidebarTab::Tmux => {
                    self.active_pane_has_ssh()
                }
                _ => true,
            }
    }

    /// The region the ToggleSidebar hotkey drives. With ONE populated
    /// region it is simply that one (owner ask 2026-08-10: the key
    /// should follow the tabs, whichever side they live on). With tabs
    /// docked to BOTH sides it prefers the region that is OPEN, so the
    /// key can always close what is on screen (the old
    /// unconditional-right bias left an open left region
    /// keyboard-uncloseable); when neither or both are open it keeps
    /// the historical right bias, and `ToggleSidebarOther` covers the
    /// counterpart. `None` when no region has tabs: a toggle would
    /// only latch an invisible open flag.
    pub(crate) fn sidebar_toggle_target(&self) -> Option<SidebarSide> {
        let populated: Vec<SidebarSide> = SidebarSide::BOTH
            .into_iter()
            .filter(|s| self.sidebar_region_has_tabs(*s))
            .collect();
        match populated[..] {
            [] => None,
            [only] => Some(only),
            _ => {
                let open: Vec<SidebarSide> = SidebarSide::BOTH
                    .into_iter()
                    .filter(|s| self.active_sidebar_shown(*s))
                    .collect();
                match open[..] {
                    [only_open] => Some(only_open),
                    _ => Some(SidebarSide::Right),
                }
            }
        }
    }

    /// The region the ToggleSidebarOther hotkey drives: the counterpart
    /// of whatever `sidebar_toggle_target` picks right now, and only
    /// while BOTH regions have tabs (with a single populated region the
    /// primary key already reaches it, and "the other" would be empty).
    pub(crate) fn sidebar_toggle_other_target(&self) -> Option<SidebarSide> {
        if !SidebarSide::BOTH.into_iter().all(|s| self.sidebar_region_has_tabs(s)) {
            return None;
        }
        self.sidebar_toggle_target().map(SidebarSide::other)
    }

    /// Prepare a connect path's sidebar auto-open and return the region
    /// it should open. A configured default tab wins over the restored
    /// "last opened" memory; without one, that memory is left intact.
    /// The default tab's region is preferred when it can show something
    /// under the feature toggles, else this keeps the historical right
    /// bias. `None` means no region can show anything.
    pub(crate) fn sidebar_auto_open_side(&mut self) -> Option<SidebarSide> {
        let possible = |side: SidebarSide| {
            TerminalSidebarTab::ALL.into_iter().any(|t| {
                self.prefs.sidebar_tab_side(t) == Some(side) && self.sidebar_tab_possible(t)
            })
        };
        let side = self
            .prefs
            .sidebar_default_tab
            .and_then(|t| self.prefs.sidebar_tab_side(t))
            .filter(|s| possible(*s))
            .or_else(|| [SidebarSide::Right, SidebarSide::Left].into_iter().find(|s| possible(*s)));

        if let (Some(default), Some(side)) = (self.prefs.sidebar_default_tab, side)
            && self.prefs.sidebar_tab_side(default) == Some(side)
            && self.sidebar_tab_possible(default)
        {
            self.set_sidebar_region_tab(default);
        }
        side
    }

    /// The tabs a region offers right now, in strip order (hidden
    /// tabs are on no side, so they never appear).
    pub(crate) fn sidebar_region_tabs(&self, side: SidebarSide) -> Vec<TerminalSidebarTab> {
        TerminalSidebarTab::ALL
            .into_iter()
            .filter(|t| {
                self.prefs.sidebar_tab_side(*t) == Some(side) && self.sidebar_tab_available(*t)
            })
            .collect()
    }

    /// Whether a region has anything to show. A toggle button only
    /// renders (and an open region only mounts) while this holds.
    pub(crate) fn sidebar_region_has_tabs(&self, side: SidebarSide) -> bool {
        TerminalSidebarTab::ALL
            .into_iter()
            .any(|t| self.prefs.sidebar_tab_side(t) == Some(side) && self.sidebar_tab_available(t))
    }

    /// The tab a region shows: the remembered active tab when it still
    /// belongs to this region and passes its gates, else the region's
    /// first offer, else `None` (empty region, nothing renders).
    pub(crate) fn sidebar_region_tab(&self, side: SidebarSide) -> Option<TerminalSidebarTab> {
        let want = self.terminal_sidebar_tab[side.idx()];
        if self.prefs.sidebar_tab_side(want) == Some(side) && self.sidebar_tab_available(want) {
            return Some(want);
        }
        self.sidebar_region_tabs(side).into_iter().next()
    }

    /// Whether a region is on screen for the given terminal tab: open
    /// on that tab, not replaced by Files mode, and non-empty.
    pub(crate) fn sidebar_region_shown(
        &self,
        tab: &crate::state::TerminalTab,
        side: SidebarSide,
    ) -> bool {
        tab.sidebar_visible(side) && !tab.files_mode && self.sidebar_region_has_tabs(side)
    }

    /// `sidebar_region_shown` for the ACTIVE terminal tab.
    pub(crate) fn active_sidebar_shown(&self, side: SidebarSide) -> bool {
        self.active_tab
            .and_then(|i| self.tabs.get(i))
            .is_some_and(|t| self.sidebar_region_shown(t, side))
    }

    /// The regions that deserve a toggle button in the window chrome:
    /// every side whose region has at least one available tab, left
    /// first. One button per region, so with tabs docked to both
    /// sides the chrome shows two icons (issue #102).
    pub(crate) fn sidebar_toggle_sides(&self) -> Vec<SidebarSide> {
        SidebarSide::BOTH
            .into_iter()
            .filter(|s| self.sidebar_region_has_tabs(*s))
            .collect()
    }

    /// Whether a sidebar tab is actually on screen right now: its
    /// region is open on the active terminal tab and resolves to it.
    /// The "should I refresh what this tab shows" gate (History
    /// follows the focused pane, etc.). Hidden tabs are never shown.
    pub(crate) fn sidebar_tab_shown(&self, tab: TerminalSidebarTab) -> bool {
        let Some(side) = self.prefs.sidebar_tab_side(tab) else {
            return false;
        };
        self.active_sidebar_shown(side) && self.sidebar_region_tab(side) == Some(tab)
    }

    /// Make `tab` the active tab of its own region and persist that
    /// choice across launches (the region is looked up, never passed,
    /// so a caller can't desync them). A hidden tab has no region, so
    /// it is never remembered as active.
    pub(crate) fn set_sidebar_region_tab(&mut self, tab: TerminalSidebarTab) {
        if let Some(side) = self.prefs.sidebar_tab_side(tab) {
            self.terminal_sidebar_tab[side.idx()] = tab;
            self.persist_setting(side.last_tab_setting_key(), tab.code());
        }
    }

    /// A tab's placement changed in Settings. Moving to a REGION
    /// makes it active there (the user is configuring it, losing it
    /// behind another tab would read as a silent no-op), carrying the
    /// open state over from the other region when the tab was showing
    /// there so it visibly travels instead of vanishing. Hiding needs
    /// no handoff: the regions re-resolve on the next read.
    ///
    /// `came_from` is the side the tab LEFT (`None` = it was hidden),
    /// captured by the caller before writing the new placement: the
    /// remembered slots are never cleared on hide, so deciding "was it
    /// showing" from the raw slot would hand a Hidden -> region move a
    /// carry-over that pops a sidebar open out of nowhere.
    pub(crate) fn sidebar_tab_moved(
        &mut self,
        tab: TerminalSidebarTab,
        came_from: Option<SidebarSide>,
        to: crate::state::SidebarPlacement,
    ) {
        if let Some(to_side) = to.side() {
            let was_showing = came_from.is_some_and(|from| {
                from != to_side
                    && self.terminal_sidebar_tab[from.idx()] == tab
                    && self.sidebar_tab_available(tab)
            });
            self.set_sidebar_region_tab(tab);
            if was_showing
                && let Some(from) = came_from
            {
                let from_open = self
                    .active_tab
                    .and_then(|i| self.tabs.get(i))
                    .is_some_and(|t| t.sidebar_visible(from));
                if from_open {
                    // Only collapse the old region when the move
                    // emptied it; otherwise it re-resolves to its next
                    // tab and stays. Computed against the
                    // ALREADY-updated prefs.
                    let collapse_from = !self.sidebar_region_has_tabs(from);
                    if let Some(idx) = self.active_tab
                        && let Some(ttab) = self.tabs.get_mut(idx)
                    {
                        ttab.sidebar_open[to_side.idx()] = true;
                        if collapse_from {
                            ttab.sidebar_open[from.idx()] = false;
                        }
                    }
                }
            }
        }
        // Hiding Chat removes the Stop / Reset affordances from every
        // terminal tab at once, and the close-region abort gate keys on
        // Chat's side, which is now `None`, so it can never fire again:
        // without this, a running tool loop would keep executing
        // commands with no reachable stop control.
        if tab == TerminalSidebarTab::Chat && to.side().is_none() {
            self.abort_all_chat_tasks();
        }
        // A ring engaged on the moved tab points at rows that next
        // frame will re-record in another region's list (or nowhere,
        // when hiding); drop it rather than let a stale (tab, idx)
        // pair act on the wrong row.
        if self.keynav.sidebar_selected.is_some_and(|(t, _)| t == tab) {
            self.keynav.sidebar_selected = None;
        }
    }
}
