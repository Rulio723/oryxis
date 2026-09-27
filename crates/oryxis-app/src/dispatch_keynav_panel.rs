//! Keyboard router for side-panel rows (host editor and friends).
//!
//! Contract (v2, after live QA):
//!
//! - Tab / Shift+Tab walk EVERY recorded row, wrapping: input rows
//!   (text fields, combos, text editors) receive real iced focus;
//!   non-input rows (pick_lists, toggles, buttons) show the ring.
//!   This replaces the old raw `focus_next` walk, which skipped
//!   everything that isn't a text input.
//! - Up / Down move ONLY while the ring sits on a non-input row, and
//!   they hop OVER input rows (arrows are the quick jump between
//!   actionable widgets; Tab is the full walk). While an input is
//!   focused the arrows stay native: combo suggestion lists and
//!   multi-line editors keep their own navigation.
//! - Enter / Space on a ringed row activate it (toggles repeat, the
//!   selection stays). Enter on input rows is never consumed, so the
//!   fields' `.on_submit(EditorSave)` keeps saving and combos keep
//!   selecting their highlighted suggestion.
//! - Left / Right cycle picker rows while ringed; otherwise they
//!   belong to the caret.
//! - Esc clears the ring first; from an input (or with no ring) it
//!   falls through to the panel's own close behavior.
//!
//! Focus itself is unobservable in iced, so the selection index is
//! kept in sync by OUR focus dispatches (Tab). A mouse click into
//! some other field desyncs it by one hop at worst; the next Tab
//! re-establishes it.

use iced::keyboard;
use iced::Task;

use crate::app::{Message, Oryxis};
use crate::keynav::movement::index_move;
use crate::keynav::RowAction;

/// Blur every focusable (focusing a nonexistent id): moving the ring
/// onto a non-input row takes the keyboard away from whatever input
/// had focus.
fn blur_task() -> Task<Message> {
    iced::widget::operation::focus(iced::widget::Id::new("__keynav_blur__"))
}

impl Oryxis {
    /// Whether the recorded row at `idx` is an input row (Tab focuses
    /// it instead of ringing it).
    fn panel_row_is_input(&self, idx: usize) -> bool {
        self.keynav
            .panel_items
            .borrow()
            .get(idx)
            .is_some_and(|a| a.focus.is_some())
    }

    /// Whether the side-panel keyboard ring currently sits on a
    /// non-input row. While it does, no text input is focused (moving
    /// the ring onto such a row blurs everything), so an Enter belongs
    /// to the ringed row and view code must not hand any `on_submit`
    /// binding to the panel's inputs: the fork's `text_input` fires
    /// the binding on ANY Enter, focused or not (`from_key_press`
    /// gates on focus, the on_submit shortcut in front of it does
    /// not), and that phantom submit also CAPTURES the key away from
    /// this router. See `hp_submit` in `views/host_panel/mod.rs`.
    pub(crate) fn panel_ring_on_noninput(&self) -> bool {
        self.keynav
            .panel_selected
            .is_some_and(|i| !self.panel_row_is_input(i))
    }

    /// Keep the current row visible: every instrumented side panel
    /// gives its body scrollable the shared "side-panel-scroll" id
    /// (only one panel renders at a time), and the offset estimate is
    /// the row's position across the recording, the same best-effort
    /// approach the content zones use (iced exposes no row bounds).
    fn panel_nav_scroll(&self, idx: usize) -> Task<Message> {
        let len = self.keynav.panel_items.borrow().len();
        let denom = len.saturating_sub(1).max(1);
        iced::widget::operation::snap_to(
            iced::widget::Id::new("side-panel-scroll"),
            iced::widget::operation::RelativeOffset {
                x: None,
                y: Some(idx as f32 / denom as f32),
            },
            iced::widget::operation::Animation::Instant,
        )
        // snap_to stores a RELATIVE offset that scrollable keeps as a
        // fraction; any later content-height change (a picker value
        // revealing/hiding form rows) remaps the fraction to a new
        // pixel position and the panel visibly jumps without any
        // scroll input. A zero scroll_by right after materializes the
        // offset into an absolute pixel value, which height changes
        // leave alone.
        .chain(iced::widget::operation::scroll_by(
            iced::widget::Id::new("side-panel-scroll"),
            iced::widget::operation::AbsoluteOffset { x: 0.0, y: 0.0 },
            iced::widget::operation::Animation::Instant,
        ))
    }

    /// Continuation of a Tab press once iced has reported which widget is
    /// actually focused. Sync the ring index to that widget (a mouse click
    /// moved focus without touching our index), then walk to the next row.
    /// `focused == None` leaves the index as-is (nothing focused, so the
    /// ring is authoritative, e.g. it sits on a non-input row).
    pub(crate) fn panel_nav_tab_resolved(
        &mut self,
        forward: bool,
        focused: Option<iced::widget::Id>,
    ) -> Task<Message> {
        if let Some(id) = focused {
            let pos = self
                .keynav
                .panel_items
                .borrow()
                .iter()
                .position(|a| a.focus.as_ref() == Some(&id));
            if let Some(idx) = pos {
                self.keynav.panel_selected = Some(idx);
                self.keynav.panel_last_row.set(Some(idx));
            }
        }
        // Walk from the (now-synced) index. `None` means the panel recorded
        // nothing this frame; fall back to the raw focus chain.
        self.panel_nav_tab(forward).unwrap_or_else(|| {
            if forward {
                iced::widget::operation::focus_next()
            } else {
                iced::widget::operation::focus_previous()
            }
        })
    }

    /// Tab / Shift+Tab over the recorded rows. Returns `None` when
    /// the open panel recorded nothing (caller falls back to the raw
    /// focus chain).
    pub(crate) fn panel_nav_tab(&mut self, forward: bool) -> Option<Task<Message>> {
        let len = self.keynav.panel_items.borrow().len();
        if len == 0 {
            return None;
        }
        let next = index_move(len, self.keynav.panel_selected, forward)?;
        self.keynav.panel_selected = Some(next);
        self.keynav.panel_last_row.set(Some(next));
        let action: RowAction = self.keynav.panel_items.borrow().get(next)?.clone();
        let step = match action.focus {
            Some(id) => crate::widgets::focus_input(id),
            None => blur_task(),
        };
        Some(Task::batch([step, self.panel_nav_scroll(next)]))
    }

    /// Entry point for the non-Tab keys, called from
    /// `handle_keynav_key` while a side panel is open. Returns
    /// `Some(task)` when the key was consumed.
    pub(crate) fn handle_panel_nav_key(
        &mut self,
        event: &keyboard::Event,
    ) -> Option<Task<Message>> {
        let keyboard::Event::KeyPressed { key, modifiers, .. } = event else {
            return None;
        };
        if modifiers.control() || modifiers.alt() || modifiers.logo() {
            return None;
        }
        // The ring is "active" only on non-input rows; while the
        // selection points at an input row the real focus owns the
        // keys (typing, caret, combo dropdown, textarea lines).
        let ring = self
            .keynav
            .panel_selected
            .filter(|&i| !self.panel_row_is_input(i));

        let is_space = matches!(key, keyboard::Key::Named(keyboard::key::Named::Space))
            || matches!(key, keyboard::Key::Character(c) if c.as_str() == " ");
        if is_space {
            let idx = ring?;
            let action = self.keynav.panel_items.borrow().get(idx).cloned()?;
            if action.activate.is_some() {
                return self.panel_nav_activate(action);
            }
            return None;
        }
        let keyboard::Key::Named(named) = key else {
            return None;
        };
        use keyboard::key::Named;
        match named {
            Named::Enter => {
                // Input rows keep on_submit / combo selection; only a
                // ringed row consumes Enter.
                let idx = ring?;
                let action = self.keynav.panel_items.borrow().get(idx).cloned()?;
                self.panel_nav_activate(action)
            }
            Named::Escape => {
                if ring.is_some() {
                    self.keynav.panel_selected = None;
                    return Some(Task::none());
                }
                // From an input or with no ring: drop any (invisible)
                // input-row selection and let Esc close the panel.
                self.keynav.panel_selected = None;
                None
            }
            Named::ArrowUp | Named::ArrowDown => {
                // Only meaningful while ringed; hop over input rows so
                // arrows never steal a caret or a combo dropdown.
                let cur = ring?;
                if modifiers.shift() {
                    return None;
                }
                let forward = matches!(named, Named::ArrowDown);
                // Native-select behavior on the remaining ringed picker
                // rows (combo_box rows, which have no focus id in the
                // fork): Up/Down change the value in place, like a
                // focused OS select. pick_list rows no longer come
                // through here: they carry a focus id, so Tab focuses
                // them and the widget itself owns the keys.
                let cur_action = self.keynav.panel_items.borrow().get(cur).cloned();
                if let Some(a) = cur_action
                    && (a.prev.is_some() || a.next.is_some())
                {
                    let msg = if forward { a.next } else { a.prev };
                    return Some(match msg {
                        Some(msg) => self.update(msg),
                        // At a non-wrapping end (chain reorder rows):
                        // consume, nothing to change.
                        None => Task::none(),
                    });
                }
                let len = self.keynav.panel_items.borrow().len();
                let mut next = cur;
                for _ in 0..len {
                    next = index_move(len, Some(next), forward)?;
                    if !self.panel_row_is_input(next) {
                        break;
                    }
                }
                if self.panel_row_is_input(next) {
                    // Every other row is an input; stay put.
                    return Some(Task::none());
                }
                self.keynav.panel_selected = Some(next);
                self.keynav.panel_last_row.set(Some(next));
                Some(self.panel_nav_scroll(next))
            }
            Named::ArrowLeft | Named::ArrowRight => {
                let idx = ring?;
                let action = self.keynav.panel_items.borrow().get(idx).cloned()?;
                let rtl = crate::i18n::is_rtl_layout();
                let forward = matches!(named, Named::ArrowRight) != rtl;
                let msg = if forward { action.next } else { action.prev };
                match msg {
                    Some(msg) => Some(self.update(msg)),
                    // Ringed non-picker row: consume as a no-op so the
                    // key doesn't leak anywhere surprising.
                    None => Some(Task::none()),
                }
            }
            Named::Home | Named::End => {
                ring?;
                let len = self.keynav.panel_items.borrow().len();
                if len == 0 {
                    return Some(Task::none());
                }
                // First / last NON-input row.
                let mut idx = if matches!(named, Named::Home) { 0 } else { len - 1 };
                let step_forward = matches!(named, Named::Home);
                for _ in 0..len {
                    if !self.panel_row_is_input(idx) {
                        break;
                    }
                    idx = index_move(len, Some(idx), step_forward)?;
                }
                if !self.panel_row_is_input(idx) {
                    self.keynav.panel_selected = Some(idx);
                    self.keynav.panel_last_row.set(Some(idx));
                    return Some(self.panel_nav_scroll(idx));
                }
                Some(Task::none())
            }
            _ => None,
        }
    }

    /// Enter/Space on a ringed row: dispatch its action, keeping the
    /// selection so repeat toggling works. (Input rows never reach
    /// here; Tab focuses them directly.)
    fn panel_nav_activate(&mut self, action: RowAction) -> Option<Task<Message>> {
        if let Some(id) = action.focus {
            // Defensive: shouldn't happen under the v2 contract.
            self.keynav.panel_selected = None;
            return Some(crate::widgets::focus_input(id));
        }
        if let Some(msg) = action.activate {
            return Some(self.update(msg));
        }
        Some(Task::none())
    }
}
