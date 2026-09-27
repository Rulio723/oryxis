//! Multi-selection of host cards on the dashboard, and the drag that
//! carries one or more of them onto a folder (issue #230).
//!
//! Keyed by connection id, never by index: `dashboard_host_order`
//! re-sorts under an auto-save rename or a sync apply, and an index kept
//! across that would select a stranger. `card_context_menu` made the
//! same choice for the same reason.

use uuid::Uuid;

/// The selected host cards. Session-only, cleared by Esc, by a plain
/// click, by every move, by a view change, and by leaving the folder,
/// search, filter or view mode it was built in (`rescope`); `prune`
/// drops ids the list no longer has, so a host deleted elsewhere
/// cannot linger in the count.
#[derive(Debug, Clone, Default)]
pub(crate) struct DashSelection {
    /// Selected ids in the order they were added.
    pub(crate) ids: Vec<Uuid>,
    /// The end a Shift+click extends from: the last card toggled on
    /// by a plain toggle, so a range reads the way file managers do.
    pub(crate) anchor: Option<Uuid>,
    /// What the dashboard was showing when the selection was built. A
    /// selection belongs to ONE view of the hosts: leaving it (another
    /// folder, another search, another filter, another view mode) ends
    /// it, so no verb can act on hosts the user picked somewhere they no
    /// longer are. See `rescope`.
    pub(crate) scope: SelectionScope,
}

/// The inputs that decide which hosts the dashboard shows. Two equal
/// scopes show the same rows (up to a tree fold, which the batch verbs
/// answer by reading the selection through the visible order).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SelectionScope {
    pub(crate) group: Option<Uuid>,
    pub(crate) search: String,
    pub(crate) view_mode: crate::state::HostViewMode,
    pub(crate) cloud_profile: Option<Uuid>,
    pub(crate) tags: Vec<String>,
}

impl DashSelection {
    pub(crate) fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub(crate) fn contains(&self, id: Uuid) -> bool {
        self.ids.contains(&id)
    }

    /// Flip one card; a card toggled ON becomes the anchor.
    pub(crate) fn toggle(&mut self, id: Uuid) {
        if let Some(pos) = self.ids.iter().position(|x| *x == id) {
            self.ids.remove(pos);
            if self.anchor == Some(id) {
                self.anchor = self.ids.last().copied();
            }
        } else {
            self.ids.push(id);
            self.anchor = Some(id);
        }
    }

    /// Add every id of `range` (a Shift+click over the visible order),
    /// keeping what was already selected. The anchor stays where it
    /// was, so a second Shift+click re-ranges from the same end.
    pub(crate) fn extend(&mut self, range: impl IntoIterator<Item = Uuid>) {
        for id in range {
            if !self.ids.contains(&id) {
                self.ids.push(id);
            }
        }
    }

    pub(crate) fn clear(&mut self) {
        self.ids.clear();
        self.anchor = None;
    }

    /// Follow the dashboard to `scope`: a selection built under another
    /// scope is dropped. `true` when that cleared something.
    pub(crate) fn rescope(&mut self, scope: SelectionScope) -> bool {
        if self.scope == scope {
            return false;
        }
        self.scope = scope;
        let had = !self.ids.is_empty();
        self.clear();
        had
    }

    /// Drop every id that is no longer a connection.
    pub(crate) fn prune(&mut self, alive: impl Fn(Uuid) -> bool) {
        self.ids.retain(|id| alive(*id));
        if self.anchor.is_some_and(|a| !self.ids.contains(&a)) {
            self.anchor = self.ids.last().copied();
        }
    }
}

/// A press on a host card that may become a drag onto a folder. Armed
/// on the global left press (the card's own `button` captures the press,
/// so a `press_hit_reporter` around the card is what names it), promoted
/// past a movement threshold in `MouseMoved`, resolved on the global
/// release against the folder under the cursor.
#[derive(Debug, Clone)]
pub(crate) struct CardDrag {
    /// The hosts travelling: the whole selection when the pressed card
    /// was part of it, else just that card.
    pub(crate) ids: Vec<Uuid>,
    /// Cursor position at press, for the move threshold.
    pub(crate) start: iced::Point,
    /// Promoted past the threshold (a real drag, not a click).
    pub(crate) active: bool,
    /// What the ghost pill says: the host's label, or "N hosts".
    pub(crate) label: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_moves_the_anchor_with_the_last_addition() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut sel = DashSelection::default();
        sel.toggle(a);
        sel.toggle(b);
        assert_eq!(sel.anchor, Some(b));
        sel.toggle(b);
        assert_eq!(sel.anchor, Some(a));
        sel.toggle(a);
        assert!(sel.is_empty());
        assert_eq!(sel.anchor, None);
    }

    #[test]
    fn a_new_scope_drops_the_selection_and_the_same_one_keeps_it() {
        let a = Uuid::new_v4();
        let mut sel = DashSelection::default();
        sel.toggle(a);
        assert!(!sel.rescope(SelectionScope::default()));
        assert_eq!(sel.ids, vec![a]);
        let folder = SelectionScope { group: Some(Uuid::new_v4()), ..Default::default() };
        assert!(sel.rescope(folder.clone()));
        assert!(sel.is_empty());
        assert_eq!(sel.anchor, None);
        // Selecting inside the new scope is kept while it holds.
        sel.toggle(a);
        assert!(!sel.rescope(folder.clone()));
        assert_eq!(sel.ids, vec![a]);
        let searched = SelectionScope { search: "db".into(), ..folder };
        assert!(sel.rescope(searched));
        assert!(sel.is_empty());
    }

    #[test]
    fn prune_drops_the_dead_and_re_anchors() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut sel = DashSelection::default();
        sel.toggle(a);
        sel.toggle(b);
        sel.prune(|id| id == a);
        assert_eq!(sel.ids, vec![a]);
        assert_eq!(sel.anchor, Some(a));
    }
}
