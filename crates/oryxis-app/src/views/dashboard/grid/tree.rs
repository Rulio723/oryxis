//! Dashboard grid: TREE view mode (issue #102). The mRemoteNG shape
//! at dashboard scale: every level visible at once, folders fold in
//! place (sharing the terminal-sidebar tree's expansion set), no
//! drill-down for manual folders.
//!
//! Rows are DENSE on purpose - this is what separates the tree from
//! the list mode next to it. A compact ~30 px line (small icon, label
//! and subtitle on ONE baseline, no card border, hover fills the full
//! row width), the fold chevron on the LEADING edge where every tree
//! control puts it, and vertical guide lines through the indent
//! columns so nesting reads as structure instead of a margin. The
//! hover kebab, right-click menu, privacy redaction and the vault
//! keynav ring all ride the same messages as the grid cards.
//!
//! Construction order is display order on purpose: the keynav section
//! is recorded from the returned tuples, and the Menu-key anchor rides
//! the ringed card's `bounds_reporter` (see `apply_card_wash`).

use super::*;

/// Indent per tree level. Sidebar-scale: the dense rows are ~30 px
/// tall, so the 18 px sidebar step reads correctly here (the old
/// full-height cards needed 28 px to register at all).
const INDENT: f32 = 18.0;
/// Fixed box for the leading fold chevron (folders) or its spacer
/// (leaves), so icons at one level share a left edge.
const LEAD: f32 = 18.0;
/// Icon badge size inside a dense row.
const ROW_ICON: f32 = 22.0;
/// Content height of a dense row (the guides and the chevron box are
/// FIXED to it rather than `Length::Fill`: a fill-height child inside
/// a shrink Row collapses in the iced flex pass, which zeroed whole
/// rows out of the layout).
const ROW_H: f32 = 26.0;

/// What sits in a row's leading slot and its trailing idle slot.
enum TreeLead {
    /// Manual folder: leading chevron mirroring the fold state.
    Fold { expanded: bool },
    /// Row that opens another screen (dynamic group, session group):
    /// leading spacer, trailing drill-in chevron while not hovered.
    Drill,
    /// Host: leading spacer, no idle trailing affordance.
    Leaf,
}

/// One row of the tree as the walk decided it, before any widget is
/// built. The walk is the single account of what the tree shows and in
/// which order: the renderer turns entries into rows, and the batch
/// actions read the host entries out of the same list, so "the hosts
/// the user sees, in the order they see them" cannot drift between the
/// picture and a batch connect or delete.
pub(crate) enum TreeEntry<'a> {
    Folder {
        group: &'a oryxis_core::models::Group,
        count_text: String,
        brand: Option<&'static str>,
        expanded: bool,
        depth: usize,
    },
    Dynamic {
        group: &'a oryxis_core::models::Group,
        query: &'a oryxis_core::models::cloud::CloudQuery,
        depth: usize,
    },
    Session { idx: usize, depth: usize },
    Host { idx: usize, depth: usize },
}

impl Oryxis {
    /// Every row of the tree, top to bottom, as the same
    /// `(element, color, DashNavItem)` tuples the grid emits.
    pub(crate) fn dashboard_tree_cards(&self) -> Vec<(Element<'_, Message>, Color, DashNavItem)> {
        let privacy_terms = self.privacy_terms();
        self.dashboard_tree_entries()
            .into_iter()
            .map(|entry| match entry {
                TreeEntry::Folder { group, count_text, brand, expanded, depth } => {
                    let (el, color) =
                        self.dash_tree_folder_row(group, count_text, brand, expanded, depth);
                    (el, color, DashNavItem::Group(group.id))
                }
                TreeEntry::Dynamic { group, query, depth } => {
                    let (el, color) = self.dash_tree_dynamic_group_row(group, query, depth);
                    (el, color, DashNavItem::Group(group.id))
                }
                TreeEntry::Session { idx, depth } => {
                    let (el, color) =
                        self.dash_tree_session_row(idx, &self.session_groups[idx], depth);
                    (el, color, DashNavItem::SessionGroup(idx))
                }
                TreeEntry::Host { idx, depth } => {
                    let (el, color) = self.dash_tree_host_row(idx, &privacy_terms, depth);
                    (el, color, DashNavItem::Host(idx))
                }
            })
            .collect()
    }

    /// The host rows of the tree, as indices into `self.connections`,
    /// in display order: what `dashboard_host_order` answers for the
    /// grid and list modes. Hosts inside collapsed folders are not on
    /// screen and are not in it.
    pub(crate) fn dashboard_tree_host_order(&self) -> Vec<usize> {
        self.dashboard_tree_entries()
            .into_iter()
            .filter_map(|entry| match entry {
                TreeEntry::Host { idx, .. } => Some(idx),
                _ => None,
            })
            .collect()
    }

    /// The walk behind both of the above: every entry of the tree, top
    /// to bottom, with the filters, the search and the fold state
    /// applied.
    fn dashboard_tree_entries(&self) -> Vec<TreeEntry<'_>> {
        let search_lower = self.host_search.to_lowercase();
        let searching = !search_lower.trim().is_empty();
        // Provider hiding, counts, brand inference and the filter
        // chips: the same pre-pass the folder cards run.
        let pre = self.dash_grid_pre_pass();
        let hidden_profiles = &pre.hidden_profiles;
        let hidden_groups = &pre.hidden_groups;
        let cloud_filter_groups = &pre.cloud_filter_groups;
        let tag_filter_groups = &pre.tag_filter_groups;
        let infer_brand = |gid: &Uuid| pre.infer_brand(self, gid);

        // Which host indices pass the non-search filters (provider
        // hiding, cloud-profile chip, tag filter). The search filter
        // is applied in the walk, where a matching ancestor short-
        // circuits it (a folder that matches shows all its children).
        let host_passes = |i: usize| -> bool {
            let conn = &self.connections[i];
            if conn
                .cloud_ref
                .as_ref()
                .is_some_and(|r| hidden_profiles.contains(&r.profile_id))
            {
                return false;
            }
            if let Some(filter_pid) = self.host_filter_cloud_profile
                && conn.cloud_ref.as_ref().map(|r| r.profile_id) != Some(filter_pid)
            {
                return false;
            }
            if !self.host_filter_tags.is_empty()
                && !conn.tags.iter().any(|tg| {
                    self.host_filter_tags.iter().any(|f| f.eq_ignore_ascii_case(tg))
                })
            {
                return false;
            }
            true
        };
        let host_search_match = |i: usize| -> bool {
            !searching || crate::util::host_matches_search(&self.connections[i], &search_lower)
        };
        let group_passes = |g: &oryxis_core::models::Group| -> bool {
            !hidden_groups.contains(&g.id)
                && cloud_filter_groups.as_ref().is_none_or(|v| v.contains(&g.id))
                && tag_filter_groups.as_ref().is_none_or(|v| v.contains(&g.id))
        };

        // Search visibility per group is decided BEFORE any card is
        // built (construction must follow display order: the keynav
        // section is recorded from the emitted tuples); see
        // `search_visible_entry` below. Memoised across the walk.
        let mut search_memo: std::collections::HashMap<Uuid, bool> =
            std::collections::HashMap::new();

        let mut rows: Vec<TreeEntry<'_>> = Vec::new();
        let mut visited: std::collections::HashSet<Uuid> = std::collections::HashSet::new();

        // Roots: parentless groups plus broken-ancestry ones (dangling
        // or cyclic parents degrade to root, the dashboard policy).
        let mut roots: Vec<usize> = (0..self.groups.len())
            .filter(|&i| {
                let g = &self.groups[i];
                g.parent_id.is_none()
                    || !oryxis_core::models::Group::is_reachable_from_root(&self.groups, g.id)
            })
            .collect();
        self.hosts_sort.sort_items(
            &mut roots,
            |&i| self.groups[i].label.clone(),
            |&i| self.groups[i].created_at,
        );
        for i in roots {
            self.tree_walk_group(
                &mut rows,
                &self.groups[i],
                0,
                searching,
                &search_lower,
                false,
                &mut search_memo,
                &group_passes,
                &host_passes,
                &host_search_match,
                &infer_brand,
                &pre.direct_host_count,
                &pre.nested_group_count,
                &mut visited,
            );
        }

        // Root session groups (no folder, or a dangling folder id).
        let group_exists = |gid: Uuid| self.groups.iter().any(|g| g.id == gid);
        let mut root_sessions: Vec<usize> = (0..self.session_groups.len())
            .filter(|&i| {
                self.session_groups[i]
                    .group_id
                    .filter(|gid| group_exists(*gid))
                    .is_none()
            })
            .collect();
        self.hosts_sort.sort_items(
            &mut root_sessions,
            |&i| self.session_groups[i].label.clone(),
            |&i| self.session_groups[i].created_at,
        );
        for i in root_sessions {
            let sg = &self.session_groups[i];
            if searching && !sg.label.to_lowercase().contains(&search_lower) {
                continue;
            }
            rows.push(TreeEntry::Session { idx: i, depth: 0 });
        }

        // Root hosts: no group, or a group id that no longer resolves.
        let mut root_hosts: Vec<usize> = (0..self.connections.len())
            .filter(|&i| {
                self.connections[i]
                    .group_id
                    .filter(|gid| group_exists(*gid))
                    .is_none()
                    && host_passes(i)
                    && host_search_match(i)
            })
            .collect();
        self.hosts_sort.sort_items(
            &mut root_hosts,
            |&i| self.connections[i].label.clone(),
            |&i| self.connections[i].created_at,
        );
        rows.extend(root_hosts.into_iter().map(|idx| TreeEntry::Host { idx, depth: 0 }));
        rows
    }

    /// Emit one group's row and, when expanded, its subtree - strictly
    /// in display order (subfolders, session groups, hosts).
    /// `ancestor_match` carries a search hit on any ANCESTOR folder
    /// down the recursion: a folder that matches shows its WHOLE
    /// subtree, subfolders included, not just its direct rows.
    #[allow(clippy::too_many_arguments)]
    fn tree_walk_group<'a>(
        &'a self,
        rows: &mut Vec<TreeEntry<'a>>,
        group: &'a oryxis_core::models::Group,
        depth: usize,
        searching: bool,
        search_lower: &str,
        ancestor_match: bool,
        search_memo: &mut std::collections::HashMap<Uuid, bool>,
        group_passes: &dyn Fn(&oryxis_core::models::Group) -> bool,
        host_passes: &dyn Fn(usize) -> bool,
        host_search_match: &dyn Fn(usize) -> bool,
        infer_brand: &dyn Fn(&Uuid) -> Option<&'static str>,
        direct_host_count: &std::collections::HashMap<Uuid, usize>,
        nested_group_count: &std::collections::HashMap<Uuid, usize>,
        visited: &mut std::collections::HashSet<Uuid>,
    ) {
        if !visited.insert(group.id) {
            return;
        }
        if !group_passes(group) {
            return;
        }
        let label_match = ancestor_match
            || !searching
            || group.label.to_lowercase().contains(search_lower);
        if searching
            && !label_match
            && !search_visible_entry(self, group.id, search_lower, search_memo)
        {
            return;
        }
        let gid = group.id;

        if let Some(query) = group.cloud_query.as_ref() {
            // Dynamic (ECS / K8s) groups keep their drill-down: the
            // dedicated cloud-group screen (task list, refresh,
            // transport) is richer than inline rows at this scale.
            rows.push(TreeEntry::Dynamic { group, query, depth });
            return;
        }

        let expanded = searching || self.hosts_tree_expanded.contains(&gid);
        let direct_hosts = direct_host_count.get(&gid).copied().unwrap_or(0);
        let nested_groups = nested_group_count.get(&gid).copied().unwrap_or(0);
        let count_text = crate::i18n::host_count(direct_hosts + nested_groups);
        rows.push(TreeEntry::Folder {
            group,
            count_text,
            brand: infer_brand(&gid),
            expanded,
            depth,
        });
        if !expanded {
            return;
        }

        let mut children: Vec<usize> = (0..self.groups.len())
            .filter(|&i| self.groups[i].parent_id == Some(gid))
            .collect();
        self.hosts_sort.sort_items(
            &mut children,
            |&i| self.groups[i].label.clone(),
            |&i| self.groups[i].created_at,
        );
        for i in children {
            self.tree_walk_group(
                rows,
                &self.groups[i],
                depth + 1,
                searching,
                search_lower,
                // A hit on THIS folder (or above) short-circuits the
                // whole subtree's filters.
                searching && label_match,
                search_memo,
                group_passes,
                host_passes,
                host_search_match,
                infer_brand,
                direct_host_count,
                nested_group_count,
                visited,
            );
        }

        let mut sessions: Vec<usize> = (0..self.session_groups.len())
            .filter(|&i| self.session_groups[i].group_id == Some(gid))
            .collect();
        self.hosts_sort.sort_items(
            &mut sessions,
            |&i| self.session_groups[i].label.clone(),
            |&i| self.session_groups[i].created_at,
        );
        for i in sessions {
            let sg = &self.session_groups[i];
            if searching
                && !label_match
                && !sg.label.to_lowercase().contains(search_lower)
            {
                continue;
            }
            rows.push(TreeEntry::Session { idx: i, depth: depth + 1 });
        }

        let mut hosts: Vec<usize> = (0..self.connections.len())
            .filter(|&i| {
                self.connections[i].group_id == Some(gid)
                    && host_passes(i)
                    && (label_match || host_search_match(i))
            })
            .collect();
        self.hosts_sort.sort_items(
            &mut hosts,
            |&i| self.connections[i].label.clone(),
            |&i| self.connections[i].created_at,
        );
        rows.extend(hosts.into_iter().map(|idx| TreeEntry::Host { idx, depth: depth + 1 }));
    }

    /// A manual folder as a dense tree row: leading fold chevron,
    /// icon chip, label with the record count inline, hover kebab.
    /// Press toggles the expansion in place (the same expansion set
    /// as the terminal-sidebar tree).
    fn dash_tree_folder_row<'a>(
        &'a self,
        group: &'a oryxis_core::models::Group,
        count_text: String,
        inferred_brand: Option<&'static str>,
        expanded: bool,
        depth: usize,
    ) -> (Element<'a, Message>, Color) {
        let gid = group.id;
        // Same icon precedence as `manual_folder_card`: explicit brand,
        // inferred brand, explicit non-brand icon, generic cube.
        let explicit_brand = group
            .icon
            .as_deref()
            .filter(|s| !s.is_empty())
            .and_then(crate::os_icon::canonical_brand_id);
        let (folder_glyph, folder_bg): (BrandIcon, Color) =
            if let Some(brand) = explicit_brand.or(inferred_brand) {
                let glyph = crate::os_icon::custom_icon_glyph(brand);
                let bg = group
                    .color
                    .as_deref()
                    .and_then(crate::os_icon::parse_hex_color)
                    .unwrap_or_else(|| {
                        crate::os_icon::provider_icon(brand, OryxisColors::t().accent).1
                    });
                (glyph, bg)
            } else if let Some(custom) =
                group.icon.as_deref().filter(|s| !s.is_empty())
            {
                let glyph = crate::os_icon::custom_icon_glyph(custom);
                let bg = group
                    .color
                    .as_deref()
                    .and_then(crate::os_icon::parse_hex_color)
                    .unwrap_or_else(|| OryxisColors::t().accent);
                (glyph, bg)
            } else {
                (
                    BrandIcon::Glyph(iced_fonts::lucide::boxes()),
                    OryxisColors::t().accent,
                )
            };
        let icon_box = self.dash_tree_row_icon(folder_bg, &group.label, folder_glyph);
        let hovered = self.hover.folder_card == Some(gid);
        let el = self.dash_tree_row(
            depth,
            TreeLead::Fold { expanded },
            icon_box,
            text(group.label.clone())
                .size(13)
                .color(OryxisColors::t().text_primary)
                .wrapping(iced::widget::text::Wrapping::None)
                .into(),
            Some(
                text(count_text)
                    .size(10)
                    .color(OryxisColors::t().text_muted)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .into(),
            ),
            Some(Message::Ai(crate::app::AiMessage::HostsTreeToggleGroup(gid))),
            hovered,
            Message::Tabs(TabsMessage::ShowFolderActions(gid)),
            Message::Tabs(TabsMessage::FolderCardHovered(gid)),
            Message::Tabs(TabsMessage::FolderCardUnhovered(gid)),
            // A host dragged over the row: the fill promises the drop.
            self.card_drag.as_ref().is_some_and(|d| d.active)
                && self.card_drop_target() == Some(Some(gid)),
        );
        (el, folder_bg)
    }

    /// A host as a dense tree row: leading spacer (leaf), icon chip,
    /// label + subtitle on one baseline, hover kebab. Press connects.
    /// Privacy redaction mirrors `dashboard_host_card`: label and
    /// address mask, hover reveals.
    fn dash_tree_host_row<'a>(
        &'a self,
        idx: usize,
        privacy_terms: &[String],
        depth: usize,
    ) -> (Element<'a, Message>, Color) {
        let conn = &self.connections[idx];
        let hovered = self.hover.card == Some(idx) || self.card_context_menu == Some(conn.id);
        let dragging_this = self
            .card_drag
            .as_ref()
            .is_some_and(|d| d.active && d.ids.contains(&conn.id));
        let display_label = if self.privacy_active(conn) && self.hover.card != Some(idx) {
            crate::widgets::redact_for_display(
                &conn.label,
                privacy_terms,
                self.privacy_classes(),
            )
        } else {
            conn.label.clone()
        };
        let is_connected = self.tabs.iter().any(|t| t.label == conn.label);
        let auth_label = crate::util::auth_method_label(&conn.auth_method);
        let subtitle = if self.prefs.show_host_address {
            use oryxis_core::models::connection::ConnectionProtocol;
            let address = crate::util::host_address_label(conn);
            let address = if self.privacy_active(conn) && self.hover.card != Some(idx) {
                crate::widgets::mask_blocks(&address)
            } else {
                address
            };
            match conn.protocol {
                // Serial, Raw and Local have no auth method to append:
                // what `address` already shows (line params, endpoint,
                // shell) is the whole subtitle.
                ConnectionProtocol::Serial
                | ConnectionProtocol::Raw
                | ConnectionProtocol::Local => address,
                ConnectionProtocol::RemoteDesktop => {
                    format!("{} · {}", address, conn.rd_kind)
                }
                _ => format!("{} · {}", address, auth_label),
            }
        } else {
            auth_label.to_string()
        };
        let default_fallback = if is_connected {
            OryxisColors::t().success
        } else {
            OryxisColors::t().accent
        };
        let (os_glyph, icon_color) = crate::os_icon::resolve_for(
            conn.detected_os.as_deref(),
            conn.custom_icon.as_deref(),
            conn.custom_color.as_deref(),
            conn.username.as_deref(),
            default_fallback,
        );
        let host_style = crate::widgets::resolve_host_icon_style(
            conn.icon_style.as_deref(),
            &self.prefs.default_host_icon,
        );
        let badge_color = conn
            .custom_color
            .as_deref()
            .or(conn.color.as_deref())
            .and_then(crate::widgets::parse_hex_color)
            .unwrap_or(icon_color);
        let icon_box = crate::widgets::host_icon(
            host_style,
            badge_color,
            &display_label,
            Some(os_glyph.view(12.0, Color::WHITE)),
            ROW_ICON,
        );

        // Cloud origin: brand glyph on the subtitle's leading edge,
        // muted label + orphan pill when the resource is gone -
        // the same signals as the card, one line tall.
        let cloud: Option<(&'static str, Color, bool)> = conn.cloud_ref.as_ref().map(|cr| {
            let provider = self
                .cloud_profiles
                .iter()
                .find(|p| p.id == cr.profile_id)
                .map(|p| p.provider.as_str())
                .unwrap_or("cloud");
            let brand_key = crate::os_icon::provider_brand_key(provider);
            let is_orphan = cr.orphaned_at.is_some();
            let (_g, brand_color) =
                crate::os_icon::provider_icon(brand_key, OryxisColors::t().accent);
            let badge = if is_orphan {
                OryxisColors::t().text_muted
            } else {
                brand_color
            };
            (brand_key, badge, is_orphan)
        });
        let is_orphan = matches!(cloud, Some((_, _, true)));
        let label_color = if is_orphan {
            OryxisColors::t().text_muted
        } else {
            OryxisColors::t().text_primary
        };
        let label_el: Element<'_, Message> = if is_orphan {
            let muted = OryxisColors::t().text_muted;
            let pill = container(
                text(t("host_orphan_label")).size(9).color(muted),
            )
            .padding(Padding { top: 1.0, right: 6.0, bottom: 1.0, left: 6.0 })
            .style(move |_| container::Style {
                background: Some(Background::Color(Color { a: 0.10, ..muted })),
                border: Border {
                    radius: Radius::from(6.0),
                    color: Color { a: 0.30, ..muted },
                    width: 1.0,
                },
                ..Default::default()
            });
            dir_row(vec![
                text(display_label.clone())
                    .size(13)
                    .color(label_color)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .into(),
                Space::new().width(6).into(),
                pill.into(),
            ])
            .align_y(iced::Alignment::Center)
            .into()
        } else {
            text(display_label.clone())
                .size(13)
                .color(label_color)
                .wrapping(iced::widget::text::Wrapping::None)
                .into()
        };
        let subtitle_el: Element<'_, Message> = match &cloud {
            Some((brand_key, color, _)) => dir_row(vec![
                crate::os_icon::custom_icon_glyph(brand_key).view(10.0, *color),
                Space::new().width(4).into(),
                text(subtitle)
                    .size(10)
                    .color(OryxisColors::t().text_muted)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .into(),
            ])
            .align_y(iced::Alignment::Center)
            .into(),
            None => text(subtitle)
                .size(10)
                .color(OryxisColors::t().text_muted)
                .wrapping(iced::widget::text::Wrapping::None)
                .into(),
        };

        let el = self.dash_tree_row(
            depth,
            TreeLead::Leaf,
            icon_box,
            label_el,
            Some(subtitle_el),
            // A row in an active drag loses its press, the card's rule
            // (`dashboard_host_card`): the fork's `button` publishes on a
            // release only while `on_press` is set in that frame, so a
            // drag abandoned back over its own row cannot dial the host.
            (!dragging_this).then_some(Message::Tabs(TabsMessage::CardPressed(idx))),
            hovered,
            Message::Tabs(TabsMessage::ShowCardMenu(idx)),
            Message::Tabs(TabsMessage::CardHovered(idx)),
            Message::Tabs(TabsMessage::CardUnhovered(idx)),
            self.dash_selection.contains(conn.id),
        );
        // Same press account as the card (issue #230): a tree row can
        // start a drag onto a folder row too.
        let el = crate::widgets::press_hit_reporter(el, self.card_press.clone(), conn.id);
        (el, badge_color)
    }

    /// A saved session group as a dense tree row. Press restores the
    /// arrangement; the idle trailing chevron keeps the "opens a
    /// container" affordance the card had.
    fn dash_tree_session_row<'a>(
        &'a self,
        idx: usize,
        group: &'a oryxis_core::models::SessionGroup,
        depth: usize,
    ) -> (Element<'a, Message>, Color) {
        let bg_color = group
            .color
            .as_deref()
            .and_then(crate::os_icon::parse_hex_color)
            .unwrap_or_else(|| OryxisColors::t().accent);
        let glyph = group
            .icon_style
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(crate::os_icon::custom_icon_glyph)
            .unwrap_or(BrandIcon::Glyph(iced_fonts::lucide::boxes()));
        let icon_box = self.dash_tree_row_icon(bg_color, &group.label, glyph);
        let panes = count_leaves(&group.layout);
        let subtitle = format!("{} {}", panes, t("session_group_panes"));
        let menu_open = matches!(
            self.overlay.as_ref().map(|o| &o.content),
            Some(crate::state::OverlayContent::SessionGroupActions(i)) if *i == idx
        );
        let hovered = self.hover.session_group_card == Some(idx) || menu_open;
        let el = self.dash_tree_row(
            depth,
            TreeLead::Drill,
            icon_box,
            text(group.label.clone())
                .size(13)
                .color(OryxisColors::t().text_primary)
                .wrapping(iced::widget::text::Wrapping::None)
                .into(),
            Some(
                text(subtitle)
                    .size(10)
                    .color(OryxisColors::t().text_muted)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .into(),
            ),
            Some(Message::SessionGroup(SessionGroupMessage::OpenSessionGroup(idx))),
            hovered,
            Message::SessionGroup(SessionGroupMessage::ShowSessionGroupMenu(idx)),
            Message::SessionGroup(SessionGroupMessage::SessionGroupCardHovered(idx)),
            Message::SessionGroup(SessionGroupMessage::SessionGroupCardUnhovered(idx)),
            false,
        );
        (el, bg_color)
    }

    /// A dynamic (cloud-query) group as a dense tree row. Press opens
    /// the dedicated cloud-group screen, same as the card.
    fn dash_tree_dynamic_group_row<'a>(
        &'a self,
        group: &'a oryxis_core::models::Group,
        query: &'a oryxis_core::models::cloud::CloudQuery,
        depth: usize,
    ) -> (Element<'a, Message>, Color) {
        let gid = group.id;
        let subtitle = match &query.kind {
            oryxis_core::models::cloud::CloudQueryKind::EcsTasks { cluster, .. } => {
                format!("ECS · {cluster}")
            }
            oryxis_core::models::cloud::CloudQueryKind::K8sPods {
                context, namespace, ..
            } => format!("K8s · {context}/{namespace}"),
        };
        let query_brand: &str = match query.kind {
            oryxis_core::models::cloud::CloudQueryKind::EcsTasks { .. } => "ecs",
            oryxis_core::models::cloud::CloudQueryKind::K8sPods { .. } => "kubernetes",
        };
        let icon_id: &str =
            group.icon.as_deref().filter(|s| !s.is_empty()).unwrap_or(query_brand);
        let folder_glyph = crate::os_icon::custom_icon_glyph(icon_id);
        let folder_bg = group
            .color
            .as_deref()
            .and_then(crate::os_icon::parse_hex_color)
            .unwrap_or_else(|| {
                crate::os_icon::provider_icon(icon_id, OryxisColors::t().accent).1
            });
        let icon_box = self.dash_tree_row_icon(folder_bg, &group.label, folder_glyph);
        let hovered = self.hover.dynamic_group_card == Some(gid);
        let el = self.dash_tree_row(
            depth,
            TreeLead::Drill,
            icon_box,
            text(group.label.clone())
                .size(13)
                .color(OryxisColors::t().text_primary)
                .wrapping(iced::widget::text::Wrapping::None)
                .into(),
            Some(
                text(subtitle)
                    .size(10)
                    .color(OryxisColors::t().text_muted)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .into(),
            ),
            Some(Message::Navigation(NavigationMessage::OpenGroup(gid))),
            hovered,
            Message::Cloud(CloudMessage::ShowDynamicGroupCardMenu(gid)),
            Message::Cloud(CloudMessage::DynamicGroupCardHovered(gid)),
            Message::Cloud(CloudMessage::DynamicGroupCardUnhovered(gid)),
            false,
        );
        (el, folder_bg)
    }

    /// Icon badge for a dense row, honouring the global default shape
    /// like the cards do (Circular / Square / Outline / Initials).
    fn dash_tree_row_icon<'a>(
        &self,
        bg: Color,
        label: &str,
        glyph: BrandIcon,
    ) -> Element<'a, Message> {
        let host_style =
            crate::widgets::resolve_host_icon_style(None, &self.prefs.default_host_icon);
        crate::widgets::host_icon(
            host_style,
            bg,
            label,
            Some(glyph.view(12.0, Color::WHITE)),
            ROW_ICON,
        )
    }

    /// The dense-row chassis every tree entry shares: indent guides,
    /// leading fold chevron / spacer, icon, one-baseline label +
    /// subtitle, full-width hover fill, trailing kebab overlay,
    /// MouseArea hover + right-click wiring.
    #[allow(clippy::too_many_arguments)]
    fn dash_tree_row<'a>(
        &'a self,
        depth: usize,
        lead: TreeLead,
        icon: Element<'a, Message>,
        label: Element<'a, Message>,
        subtitle: Option<Element<'a, Message>>,
        on_press: Option<Message>,
        hovered: bool,
        kebab_msg: Message,
        on_enter: Message,
        on_exit: Message,
        // Selected host, or a folder under a dragged host: the accent
        // fill either way, the two never apply to the same row.
        highlighted: bool,
    ) -> Element<'a, Message> {
        let rtl = crate::i18n::is_rtl_layout();

        // Indent guides: one vertical hairline per ancestor level,
        // centred in its indent column, so nesting reads as structure.
        // Inside the button on purpose: the hover fill and the keynav
        // ring span the full row width, like every real tree control.
        let mut cells: Vec<Element<'a, Message>> = (0..depth)
            .map(|_| {
                container(
                    container(Space::new())
                        .width(Length::Fixed(1.0))
                        .height(Length::Fixed(ROW_H))
                        .style(|_| container::Style {
                            background: Some(Background::Color(
                                OryxisColors::t().border,
                            )),
                            ..Default::default()
                        }),
                )
                .width(Length::Fixed(INDENT))
                .align_x(iced::alignment::Horizontal::Center)
                .into()
            })
            .collect();

        // Leading slot: the fold chevron is the tree affordance, so it
        // sits where every tree control puts it. Leaves reserve the
        // same box so icons at one level share a left edge.
        let lead_el: Element<'a, Message> = match lead {
            TreeLead::Fold { expanded } => {
                let chevron = if expanded {
                    iced_fonts::lucide::chevron_down()
                } else if rtl {
                    iced_fonts::lucide::chevron_left()
                } else {
                    iced_fonts::lucide::chevron_right()
                };
                container(chevron.size(13).color(OryxisColors::t().text_muted))
                    .center_x(Length::Fixed(LEAD))
                    .center_y(Length::Fixed(ROW_H))
                    .into()
            }
            TreeLead::Drill | TreeLead::Leaf => {
                Space::new().width(LEAD).into()
            }
        };
        cells.push(lead_el);
        cells.push(icon);
        cells.push(Space::new().width(7).into());
        cells.push(label);
        if let Some(sub) = subtitle {
            cells.push(Space::new().width(8).into());
            cells.push(sub);
        }
        // Fill the remaining width so the row is clickable (and the
        // hover fill paints) all the way across.
        cells.push(Space::new().width(Length::Fill).into());

        // 24 px trailing pad reserves the kebab overlay slot, same as
        // the cards, so subtitles never slide under the ⋮.
        let row_padding = if rtl {
            Padding { top: 4.0, right: 4.0, bottom: 4.0, left: 24.0 }
        } else {
            Padding { top: 4.0, right: 24.0, bottom: 4.0, left: 4.0 }
        };
        let row_btn = button(
            dir_row(cells).align_y(iced::Alignment::Center),
        )
        .on_press_maybe(on_press)
        .width(Length::Fill)
        .padding(row_padding)
        .style(move |_, status| {
            // No idle chrome: a border per row at this density is
            // noise, and the transparent ground is what makes the
            // guides + indentation carry the structure. Hover / press
            // fill the full row instead.
            let bg = match status {
                _ if highlighted => Some(OryxisColors::t().bg_selected),
                BtnStatus::Hovered => Some(OryxisColors::t().bg_hover),
                BtnStatus::Pressed => Some(OryxisColors::t().bg_selected),
                _ => None,
            };
            button::Style {
                background: bg.map(Background::Color),
                border: Border {
                    radius: Radius::from(6.0),
                    color: Color::TRANSPARENT,
                    width: 0.0,
                },
                ..Default::default()
            }
        });

        // Trailing overlay: ⋮ on hover (drill rows show their muted
        // drill-in chevron while idle; folds and leaves show nothing,
        // the fold state already lives on the leading edge).
        let show_drill_idle = matches!(lead, TreeLead::Drill) && !hovered;
        let trailing: Element<'a, Message> = if hovered {
            crate::widgets::card_kebab_button(
                OryxisColors::t().text_muted,
                true,
                kebab_msg.clone(),
            )
            .into()
        } else if show_drill_idle {
            let chevron = if rtl {
                iced_fonts::lucide::chevron_left()
            } else {
                iced_fonts::lucide::chevron_right()
            };
            container(chevron.size(13).color(OryxisColors::t().text_muted))
                .center_x(Length::Fixed(22.0))
                .center_y(Length::Fixed(22.0))
                .into()
        } else {
            Space::new().into()
        };
        let stacked = crate::widgets::card_trailing_overlay(row_btn.into(), trailing);
        let wrapped = MouseArea::new(stacked)
            .on_enter(on_enter)
            .on_exit(on_exit)
            .on_right_press(kebab_msg);
        Element::from(container(wrapped).width(Length::Fill).clip(true))
    }
}

/// Entry shim so the memoised recursion can be called with `&self`
/// borrows already split (the walk holds `rows` mutably).
fn search_visible_entry(
    app: &Oryxis,
    gid: Uuid,
    search_lower: &str,
    memo: &mut std::collections::HashMap<Uuid, bool>,
) -> bool {
    fn rec(
        app: &Oryxis,
        gid: Uuid,
        search_lower: &str,
        memo: &mut std::collections::HashMap<Uuid, bool>,
    ) -> bool {
        if let Some(&v) = memo.get(&gid) {
            return v;
        }
        memo.insert(gid, false);
        let Some(group) = app.groups.iter().find(|g| g.id == gid) else {
            return false;
        };
        let v = group.label.to_lowercase().contains(search_lower)
            || app.connections.iter().any(|c| {
                c.group_id == Some(gid) && crate::util::host_matches_search(c, search_lower)
            })
            || app.session_groups.iter().any(|sg| {
                sg.group_id == Some(gid) && sg.label.to_lowercase().contains(search_lower)
            })
            || app
                .groups
                .iter()
                .filter(|g| g.parent_id == Some(gid))
                .any(|g| rec(app, g.id, search_lower, memo));
        memo.insert(gid, v);
        v
    }
    rec(app, gid, search_lower, memo)
}
