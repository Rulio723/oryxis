//! Dashboard toolbar, the breadcrumb on the left, and the trailing
//! action button (`+ host` for manual folders, `⬇ Discover` for
//! cloud-linked ones, nothing for dynamic groups).

use iced::border::Radius;
use iced::widget::button::Status as BtnStatus;
use iced::widget::{button, container, text, MouseArea, Space};
use iced::{Background, Border, Color, Element, Length, Padding};

use crate::app::{EditorMessage, CloudMessage, NavigationMessage, Message, Oryxis, TabsMessage};
use crate::i18n::t;
use crate::theme::OryxisColors;
use crate::widgets::dir_row;

impl Oryxis {
    pub(super) fn dashboard_toolbar(&self) -> Element<'_, Message> {
        // ── Toolbar ──
        let toolbar_left: Element<'_, Message> = if let Some(gid) = self.active_group {
            // Compact folder header: a back arrow (one level up, root
            // when the folder is top-level) + folder glyph + the
            // current group's label. Replaced the full breadcrumb
            // chain (owner call 2026-07-23): with nested subgroups the
            // chain ate the toolbar's width; the arrow covers the same
            // navigation one hop at a time, SFTP-style.
            let current = self.groups.iter().find(|g| g.id == gid);
            let label = current.map(|g| g.label.clone()).unwrap_or_default();
            // A dangling parent (deleted on another device) backs out
            // to root, matching how the grid re-homes the subtree.
            let parent = current
                .and_then(|g| g.parent_id)
                .filter(|pid| self.groups.iter().any(|g| g.id == *pid));
            let back_msg = match parent {
                Some(pid) => Message::Navigation(NavigationMessage::OpenGroup(pid)),
                // Top level: ChangeView(Dashboard) clears the active
                // group (the Home-tab path), landing on the root list.
                None => Message::Navigation(NavigationMessage::ChangeView(
                    crate::state::View::Dashboard,
                )),
            };
            // Physical direction flips under RTL ("back" points at the
            // trailing edge there).
            let back_glyph = if crate::i18n::is_rtl_layout() {
                iced_fonts::lucide::arrow_right()
            } else {
                iced_fonts::lucide::arrow_left()
            };
            // The arrow is also where a dragged host goes to leave
            // this folder (issue #230): dropping on it moves the host
            // one level up, the only door out of a folder by drag.
            let back_drop = self.card_drag.as_ref().is_some_and(|d| d.active)
                && self.hover.folder_back;
            let back_btn = button(
                container(back_glyph.size(16).color(OryxisColors::t().text_primary))
                    .center_x(Length::Fixed(28.0))
                    .center_y(Length::Fixed(28.0)),
            )
            .on_press(back_msg)
            .padding(0)
            .style(move |_, status| {
                let bg = match status {
                    _ if back_drop => OryxisColors::t().bg_selected,
                    BtnStatus::Hovered => OryxisColors::t().bg_hover,
                    BtnStatus::Pressed => OryxisColors::t().bg_selected,
                    _ => Color::TRANSPARENT,
                };
                let border = if back_drop {
                    Border { radius: Radius::from(6.0), color: OryxisColors::t().accent, width: 2.0 }
                } else {
                    Border { radius: Radius::from(6.0), ..Default::default() }
                };
                button::Style {
                    background: Some(Background::Color(bg)),
                    border,
                    ..Default::default()
                }
            });
            let back_btn = MouseArea::new(back_btn)
                .on_enter(Message::Tabs(TabsMessage::FolderBackHovered))
                .on_exit(Message::Tabs(TabsMessage::FolderBackUnhovered));
            dir_row(vec![
                crate::views::terminal::icon_tooltip(back_btn.into(), t("back")),
                Space::new().width(8).into(),
                iced_fonts::lucide::folder().size(18).color(OryxisColors::t().accent).into(),
                Space::new().width(6).into(),
                text(label)
                    .size(20)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .color(OryxisColors::t().text_primary)
                    .into(),
            ])
            .align_y(iced::Alignment::Center)
            .into()
        } else {
            // Title dropped (redundant with the section nav); the search
            // field fills this slot in the toolbar instead.
            Space::new().into()
        };

        // "+ Host [▾]" split button, primary half opens the manual
        // SSH editor (unchanged), the chevron half opens the add menu
        // overlay: import a `.oryxis` file (vault or shared host) plus
        // cloud discovery per configured profile. Launching from the
        // Hosts view keeps every "add a host" path in one place (the
        // user naturally goes here to add hosts). Layout mirrors the
        // keychain "+ ADD ▼" split exactly so both toolbars stay
        // visually consistent. The chevron is always emitted so import
        // stays reachable even before any cloud profile exists.
        let rtl = crate::i18n::is_rtl_layout();
        // Pre-compute the rounded-corner radii so the leading half
        // rounds the leading edge and the chevron rounds the trailing
        // edge, flipped under RTL.
        let label_radius = if rtl {
            Radius { top_left: 0.0, bottom_left: 0.0, top_right: 6.0, bottom_right: 6.0 }
        } else {
            Radius { top_left: 6.0, bottom_left: 6.0, top_right: 0.0, bottom_right: 0.0 }
        };
        let chevron_radius = if rtl {
            Radius { top_left: 6.0, bottom_left: 6.0, top_right: 0.0, bottom_right: 0.0 }
        } else {
            Radius { top_left: 0.0, bottom_left: 0.0, top_right: 6.0, bottom_right: 6.0 }
        };

        let primary_btn = button(
            container(
                dir_row(vec![
                    text("+").size(13).font(iced::Font {
                        weight: iced::font::Weight::Bold,
                        ..iced::Font::new(crate::theme::SYSTEM_UI_FAMILY)
                    }).color(OryxisColors::t().button_text).into(),
                    Space::new().width(4).into(),
                    text(t("host_btn")).size(11).font(iced::Font {
                        weight: iced::font::Weight::Bold,
                        ..iced::Font::new(crate::theme::SYSTEM_UI_FAMILY)
                    }).color(OryxisColors::t().button_text).into(),
                ]).align_y(iced::Alignment::Center),
            )
            .center_y(Length::Fixed(24.0))
            .center_x(Length::Fixed(72.0)),
        )
        .on_press(Message::Editor(EditorMessage::ShowNewConnection))
        .style(move |_, status| {
            let bg = match status {
                BtnStatus::Hovered => OryxisColors::t().button_bg_hover,
                _ => OryxisColors::t().button_bg,
            };
            button::Style {
                background: Some(Background::Color(bg)),
                border: Border { radius: label_radius, ..Default::default() },
                ..Default::default()
            }
        });

        // 1px divider between the two halves, same alpha-tinted black
        // the keychain split uses.
        let separator = container(Space::new().width(1).height(16))
            .style(|_| container::Style {
                background: Some(Background::Color(Color { a: 0.3, ..Color::BLACK })),
                ..Default::default()
            });
        let chevron_btn = button(
            container(
                iced_fonts::lucide::chevron_down::<iced::Theme>()
                    .size(12)
                    .color(OryxisColors::t().button_text),
            )
            .center_y(Length::Fixed(24.0))
            .padding(Padding { top: 0.0, right: 4.0, bottom: 0.0, left: 4.0 }),
        )
        .on_press(Message::Cloud(CloudMessage::ShowCloudProviderPicker))
        .style(move |_, status| {
            let bg = match status {
                BtnStatus::Hovered => OryxisColors::t().button_bg_hover,
                _ => OryxisColors::t().button_bg,
            };
            button::Style {
                background: Some(Background::Color(bg)),
                border: Border { radius: chevron_radius, ..Default::default() },
                ..Default::default()
            }
        });
        // Keyboard-navigation focus rings on each split half; the
        // recording (visual order) happens at row assembly below.
        let primary_el = self
            .keynav_toolbar_ring(crate::keynav::ToolbarItem::Primary, primary_btn.into());
        let chevron_el = self.keynav_toolbar_ring(
            crate::keynav::ToolbarItem::PrimaryChevron,
            chevron_btn.into(),
        );
        // Report the split group's on-screen rect so the chevron's
        // dropdown anchors to the real button (2 px below, trailing
        // edges aligned) in every layout, vertical rail included.
        let action_group: Element<'_, Message> = crate::widgets::bounds_reporter(
            dir_row(vec![primary_el, separator.into(), chevron_el])
                .align_y(iced::Alignment::Center),
            self.toolbar_split_btn_bounds.clone(),
        );

        // Context-aware toolbar action: inside a dynamic group there
        // is no "+ host", tasks come from the cloud resolver. Inside
        // a provider folder (= a manual folder linked to a cloud
        // profile via its children's `cloud_ref`/`cloud_query`),
        // "+ HOST" turns into "+ DISCOVER" so the user lands directly
        // in the right import flow.
        // Alongside the element, expose which keynav items the resolved
        // action contributes (in visual order) so the row assembly can
        // record exactly what rendered.
        let (resolved_action, resolved_items): (
            Element<'_, Message>,
            Vec<crate::keynav::ToolbarItem>,
        ) = if let Some(gid) = self.active_group {
            // Is this a dynamic group?
            let dynamic_query_profile = self
                .groups
                .iter()
                .find(|g| g.id == gid)
                .and_then(|g| g.cloud_query.as_ref())
                .map(|q| q.profile_id);
            if dynamic_query_profile.is_some() {
                // Dynamic group → no "+ host" button. Reserve the
                // same vertical slot the visible button would occupy
                // so the breadcrumb row keeps its height. Iced's
                // button widget adds its own DEFAULT_PADDING (5 top
                // + 5 bottom) on top of the inner container's
                // `center_y(Length::Fixed(24.0))`, so the rendered
                // button is 24 + 10 = 34 px tall. Anchoring the
                // slot to 34 keeps the breadcrumb glyph baseline at
                // the same y-position across views; iced's Space
                // also ignores `height` when `width == 0`, so use a
                // 1 px-wide sliver to actually force the height.
                (
                    Space::new()
                        .width(Length::Fixed(1.0))
                        .height(Length::Fixed(34.0))
                        .into(),
                    Vec::new(),
                )
            } else {
                // Manual folder: derive the linked profile from any
                // child host's cloud_ref or any child dynamic group's
                // cloud_query.
                let linked_profile = self
                    .connections
                    .iter()
                    .filter(|c| c.group_id == Some(gid))
                    .find_map(|c| c.cloud_ref.as_ref().map(|r| r.profile_id))
                    .or_else(|| {
                        self.groups
                            .iter()
                            .filter(|g| g.parent_id == Some(gid))
                            .find_map(|g| g.cloud_query.as_ref().map(|q| q.profile_id))
                    });
                match linked_profile {
                    Some(pid) => {
                        let fg = OryxisColors::t().button_text;
                        let discover: Element<'_, Message> = button(
                            container(
                                dir_row(vec![
                                    iced_fonts::lucide::download()
                                        .size(13)
                                        .color(fg)
                                        .into(),
                                    Space::new().width(4).into(),
                                    text(t("cloud_discover"))
                                        .size(11)
                                        .font(iced::Font {
                                            weight: iced::font::Weight::Bold,
                                            ..iced::Font::new(crate::theme::SYSTEM_UI_FAMILY)
                                        })
                                        .color(fg)
                                        .into(),
                                ])
                                .align_y(iced::Alignment::Center),
                            )
                            .center_y(Length::Fixed(24.0))
                            .padding(Padding {
                                top: 0.0,
                                right: 14.0,
                                bottom: 0.0,
                                left: 14.0,
                            }),
                        )
                        .on_press(Message::Cloud(CloudMessage::ShowCloudDiscover(pid)))
                        .style(|_, status| {
                            let bg = match status {
                                BtnStatus::Hovered => OryxisColors::t().button_bg_hover,
                                _ => OryxisColors::t().button_bg,
                            };
                            button::Style {
                                background: Some(Background::Color(bg)),
                                border: Border { radius: Radius::from(6.0), ..Default::default() },
                                ..Default::default()
                            }
                        })
                        .into();
                        let item = crate::keynav::ToolbarItem::CloudDiscover(pid);
                        (self.keynav_toolbar_ring(item, discover), vec![item])
                    }
                    None => (
                        action_group,
                        vec![
                            crate::keynav::ToolbarItem::Primary,
                            crate::keynav::ToolbarItem::PrimaryChevron,
                        ],
                    ),
                }
            }
        } else {
            (
                action_group,
                vec![
                    crate::keynav::ToolbarItem::Primary,
                    crate::keynav::ToolbarItem::PrimaryChevron,
                ],
            )
        };

        // Sort dropdown trigger, sits just before the "+ Host" /
        // "+ Discover" action. Glyph reflects the active sort so the
        // current mode is readable without opening the menu.
        let sort_btn = self.keynav_toolbar_ring(
            crate::keynav::ToolbarItem::Sort,
            crate::widgets::bounds_reporter(
                crate::widgets::sort_toolbar_button(
                    crate::state::SortMenuKind::Hosts,
                    self.hosts_sort,
                ),
                self.toolbar_sort_btn_bounds.clone(),
            ),
        );

        // Tag filter, only rendered once at least one host is tagged
        // (or a filter is active and needs clearing). Accent-filled
        // while active so a narrowed list is visibly narrowed.
        let show_tag_filter = self.host_tag_filter_available();
        let tag_filter_btn: Element<'_, Message> = if show_tag_filter {
            dir_row(vec![
                self.keynav_toolbar_ring(
                    crate::keynav::ToolbarItem::TagFilter,
                    // Report the button's bounds so the dropdown anchors
                    // under it (like the "+ Host" split menu) instead of
                    // at the cursor.
                    crate::widgets::bounds_reporter(
                        crate::widgets::tag_filter_toolbar_button(
                            self.host_filter_tags.len(),
                            Message::Navigation(NavigationMessage::ShowHostTagFilterMenu),
                        ),
                        self.host_tag_filter_btn_bounds.clone(),
                    ),
                ),
                Space::new().width(6).into(),
            ])
            .align_y(iced::Alignment::Center)
            .into()
        } else {
            Space::new().into()
        };

        // Grid/List toggle, hidden once the window is so narrow that the
        // grid already renders as a single column (list == grid there).
        let nav_width = self.vault_rail_width();
        let panel_open = self.cloud_discover.visible || self.panels.host_panel;
        let panel_width = if panel_open { self.panel_width } else { 0.0 };
        let available = (self.window_size.width
            - nav_width
            - self.side_strip_reserve()
            - panel_width
            - 48.0)
            .max(0.0);
        let responsive_cols =
            crate::widgets::card_grid_columns(available, crate::app::CARD_WIDTH, 12.0);
        // Narrow windows used to hide the toggle (grid == list at one
        // column), but the TREE mode is meaningful at any width - and
        // hiding the button would strand a user who cycled into tree
        // with no way back (issue #102).
        let show_view_toggle = responsive_cols > 1
            || self.prefs.host_view_mode != crate::state::HostViewMode::Grid;
        let view_toggle: Element<'_, Message> = if show_view_toggle {
            dir_row(vec![
                self.keynav_toolbar_ring(
                    crate::keynav::ToolbarItem::ViewToggle,
                    crate::widgets::host_view_toggle_button(self.prefs.host_view_mode),
                ),
                Space::new().width(6).into(),
            ])
            .align_y(iced::Alignment::Center)
            .into()
        } else {
            Space::new().into()
        };

        // Multi-select mode (issue #230): an icon square like the view
        // cycler, the tag filter and the sort trigger it sits beside,
        // carrying the mode's glyph and the app's own "on" wash while the
        // mode is live. What a click MEANS changes with it, but the change
        // is announced where it acts (the check on every host card, the
        // selection bar above the grid) rather than by the button's shape.
        //
        // Hidden inside a dynamic cloud group, where the cards are
        // resolved tasks and nothing on screen is a saved host to select.
        let show_multi_select = !self.active_group_is_dynamic();
        let multi_select_toggle: Element<'_, Message> = if show_multi_select {
            dir_row(vec![
                Space::new().width(6).into(),
                self.keynav_toolbar_ring(
                    crate::keynav::ToolbarItem::MultiSelect,
                    crate::widgets::host_multi_select_toggle_button(self.dash_multi_select),
                ),
            ])
            .align_y(iced::Alignment::Center)
            .into()
        } else {
            Space::new().into()
        };

        // ── Responsive collapse ──
        // #1: search yields before the folder name. #2: but the search
        // keeps a usable min-width, so once it hits that the breadcrumb
        // clips instead; only when the min won't fit at all does the search
        // fold to a floating-field icon. #3: when the whole button cluster
        // can't fit alongside the icon, every action folds into a single
        // `…` overflow menu (so the toolbar shows just the search + `…`).
        const SEARCH_MIN: f32 = 180.0;
        const ICON: f32 = 44.0;
        const GAP_SC: f32 = 10.0; // search ↔ cluster
        const GAP_BS: f32 = 12.0; // breadcrumb ↔ search
        const BC_FLOOR: f32 = 50.0;
        let in_group = self.active_group.is_some();
        let leading_w = self.toolbar_leading_width();
        let cluster_w = self.toolbar_cluster_width();
        let toolbar_w = self.toolbar_content_width();
        let (search_collapsed, buttons_overflow) = self.toolbar_tiers();
        let overflow_open = matches!(
            self.overlay.as_ref().map(|o| &o.content),
            Some(crate::state::OverlayContent::ToolbarOverflow)
        );

        // Breadcrumb width. The inline trailing is the full cluster, or
        // just the 44px `…` once the buttons have folded. While the search
        // is a field, cap the breadcrumb so the Fill search keeps at least
        // SEARCH_MIN (the name clips before the search shrinks past
        // usable). Once the search is an icon, the breadcrumb takes
        // whatever the icon + `…` leave.
        let trailing_w = if buttons_overflow { ICON } else { cluster_w };
        let left_el: Element<'_, Message> = if in_group {
            let (cap, clip_to_cap) = if search_collapsed {
                let c = (toolbar_w - ICON - GAP_SC - GAP_BS - trailing_w).max(0.0);
                (c, true)
            } else {
                let zone = toolbar_w - trailing_w - GAP_SC - GAP_BS;
                let c = (zone - SEARCH_MIN).max(BC_FLOOR);
                (c, leading_w > c)
            };
            if clip_to_cap {
                container(toolbar_left)
                    .width(Length::Fixed(cap))
                    .clip(true)
                    .into()
            } else {
                container(toolbar_left).clip(true).into()
            }
        } else {
            toolbar_left
        };

        // Record the rendered actions for the keyboard router, in
        // visual (leading-to-trailing) order; the focus rings were
        // applied at each build site above.
        self.keynav_toolbar_reset();
        if search_collapsed {
            self.keynav_toolbar_record(crate::keynav::ToolbarItem::SearchIcon);
        }
        if buttons_overflow {
            self.keynav_toolbar_record(crate::keynav::ToolbarItem::Overflow);
        } else {
            if show_view_toggle {
                self.keynav_toolbar_record(crate::keynav::ToolbarItem::ViewToggle);
            }
            if show_tag_filter {
                self.keynav_toolbar_record(crate::keynav::ToolbarItem::TagFilter);
            }
            self.keynav_toolbar_record(crate::keynav::ToolbarItem::Sort);
            if show_multi_select {
                self.keynav_toolbar_record(crate::keynav::ToolbarItem::MultiSelect);
            }
            for it in &resolved_items {
                self.keynav_toolbar_record(*it);
            }
        }

        let mut row_items: Vec<Element<'_, Message>> = vec![left_el];
        if in_group {
            row_items.push(Space::new().width(12).into());
        }
        let search_slot = self.vault_search_slot(search_collapsed);
        row_items.push(if search_collapsed {
            self.keynav_toolbar_ring(crate::keynav::ToolbarItem::SearchIcon, search_slot)
        } else {
            search_slot
        });
        row_items.push(Space::new().width(10).into());
        if buttons_overflow {
            // Every action folds into the one `…` menu; the split/sort
            // triggers are off screen, so blank their anchor cells.
            self.keynav_toolbar_zero_trigger_bounds();
            row_items.push(self.keynav_toolbar_ring(
                crate::keynav::ToolbarItem::Overflow,
                crate::widgets::bounds_reporter(
                    crate::widgets::toolbar_overflow_icon(overflow_open),
                    self.toolbar_overflow_btn_bounds.clone(),
                ),
            ));
        } else {
            row_items.push(view_toggle);
            row_items.push(tag_filter_btn);
            row_items.push(sort_btn);
            // The multi-select square carries the 6px gap between it and
            // the sort trigger; `sort_btn` has none of its own, and the
            // 8px Space below is what stands before the primary action.
            row_items.push(multi_select_toggle);
            row_items.push(Space::new().width(8).into());
            row_items.push(resolved_action);
        }

        // Let the row size to its natural height (button chrome included)
        // so the action button keeps its true visual size.
        let toolbar = container(dir_row(row_items).align_y(iced::Alignment::Center))
            // Top padding matches the 24px side padding so the page's inner
            // spacing is uniform on the X and Y axes.
            .padding(Padding { top: 16.0, right: 24.0, bottom: 16.0, left: 24.0 })
            .width(Length::Fill);
        toolbar.into()
    }
}
