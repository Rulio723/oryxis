//! Keys screen: toolbar, key + identity card grids. Split out of views/keys.rs.

use super::*;
use crate::widgets::empty_state_icon;
use iced::widget::column;

/// Width of the empty state's centered action block (hero CTA, the "or"
/// divider and every secondary action), so the column reads as one
/// object. Matches `cta_button`'s own width and the dashboard's block.
const EMPTY_BLOCK_WIDTH: f32 = 380.0;

impl Oryxis {
    pub(crate) fn view_keys(&self) -> Element<'_, Message> {
        // ── Header toolbar ──
        // Split button: leading half "+ ADD" (opens menu), vertical
        // separator, trailing half "▼" chevron (also opens menu). Both
        // halves invoke the same toggle so the dropdown appears below
        // regardless of which half the user clicks. The leading half
        // gets its outer corners rounded; under RTL `dir_row` swaps the
        // order, so we also swap which physical corners each half
        // rounds, otherwise the rounded edge ends up in the middle.
        let rtl = crate::i18n::is_rtl_layout();
        let label_radius = if rtl {
            // Label sits on the right edge in RTL → round right corners.
            Radius { top_left: 0.0, bottom_left: 0.0, top_right: 6.0, bottom_right: 6.0 }
        } else {
            Radius { top_left: 6.0, bottom_left: 6.0, top_right: 0.0, bottom_right: 0.0 }
        };
        let chevron_radius = if rtl {
            Radius { top_left: 6.0, bottom_left: 6.0, top_right: 0.0, bottom_right: 0.0 }
        } else {
            Radius { top_left: 0.0, bottom_left: 0.0, top_right: 6.0, bottom_right: 6.0 }
        };

        let add_label = button(
            container(
                dir_row(vec![
                    text("+").size(13).font(iced::Font {
                        weight: iced::font::Weight::Bold,
                        ..iced::Font::new(crate::theme::SYSTEM_UI_FAMILY)
                    }).color(OryxisColors::t().button_text).into(),
                    Space::new().width(4).into(),
                    text(t("add_btn")).size(11).font(iced::Font {
                        weight: iced::font::Weight::Bold,
                        ..iced::Font::new(crate::theme::SYSTEM_UI_FAMILY)
                    }).color(OryxisColors::t().button_text).into(),
                ])
                .align_y(iced::Alignment::Center),
            )
            .center_y(Length::Fixed(24.0))
            .center_x(Length::Fixed(72.0)),
        )
        .on_press(Message::Keys(KeysMessage::ToggleKeychainAddMenu))
        .style(move |_, status| {
            let bg = match status {
                BtnStatus::Hovered => OryxisColors::t().button_bg_hover,
                _ => OryxisColors::t().button_bg,
            };
            button::Style {
                background: Some(Background::Color(bg)),
                border: Border {
                    radius: label_radius,
                    ..Default::default()
                },
                ..Default::default()
            }
        });

        let separator = container(Space::new().width(1).height(16))
            .style(|_| container::Style {
                background: Some(Background::Color(Color { a: 0.3, ..Color::BLACK })),
                ..Default::default()
            });

        // Chevron half, match the left half's vertical metrics so both halves
        // render at identical heights. Lateral padding is kept to the minimum
        // that still gives the glyph breathing room.
        let add_chevron = button(
            container(
                iced_fonts::lucide::chevron_down::<iced::Theme>()
                    .size(12).color(OryxisColors::t().button_text),
            )
            .center_y(Length::Fixed(24.0))
            .padding(Padding { top: 0.0, right: 4.0, bottom: 0.0, left: 4.0 }),
        )
        .on_press(Message::Keys(KeysMessage::ToggleKeychainAddMenu))
        .style(move |_, status| {
            let bg = match status {
                BtnStatus::Hovered => OryxisColors::t().button_bg_hover,
                _ => OryxisColors::t().button_bg,
            };
            button::Style {
                background: Some(Background::Color(bg)),
                border: Border {
                    radius: chevron_radius,
                    ..Default::default()
                },
                ..Default::default()
            }
        });

        // Report the split group's rect so the ADD dropdown anchors to
        // the real button (2 px below, trailing edges aligned) in every
        // layout, vertical rail included.
        let add_btn: Element<'_, Message> = crate::widgets::bounds_reporter(
            dir_row(vec![
                add_label.into(),
                separator.into(),
                add_chevron.into(),
            ])
            .align_y(iced::Alignment::Center),
            self.toolbar_split_btn_bounds.clone(),
        );

        let sort_btn = crate::widgets::bounds_reporter(
            crate::widgets::sort_toolbar_button(
                crate::state::SortMenuKind::Keys,
                self.keys_sort,
            ),
            self.toolbar_sort_btn_bounds.clone(),
        );

        // Responsive collapse: search yields first, then folds to an
        // icon; when the buttons can't fit they all move into a `…` menu.
        // `keynav_toolbar_slot` records each rendered action for the
        // keyboard router (push order == visual order here).
        let (search_collapsed, buttons_overflow) = self.toolbar_tiers();
        self.keynav_toolbar_reset();
        let search_slot = self.vault_search_slot(search_collapsed);
        let mut row_items: Vec<Element<'_, Message>> = vec![
            if search_collapsed {
                self.keynav_toolbar_slot(crate::keynav::ToolbarItem::SearchIcon, search_slot)
            } else {
                search_slot
            },
            Space::new().width(10).into(),
        ];
        if buttons_overflow {
            // The split/sort triggers are off screen: blank their
            // anchor cells so the menus fall back cleanly.
            self.keynav_toolbar_zero_trigger_bounds();
            row_items.push(self.keynav_toolbar_slot(
                crate::keynav::ToolbarItem::Overflow,
                crate::widgets::bounds_reporter(
                    crate::widgets::toolbar_overflow_icon(matches!(
                        self.overlay.as_ref().map(|o| &o.content),
                        Some(crate::state::OverlayContent::ToolbarOverflow)
                    )),
                    self.toolbar_overflow_btn_bounds.clone(),
                ),
            ));
        } else {
            row_items.push(self.keynav_toolbar_slot(crate::keynav::ToolbarItem::Sort, sort_btn));
            row_items.push(Space::new().width(8).into());
            // Both split halves open the same add menu; one keynav stop.
            row_items
                .push(self.keynav_toolbar_slot(crate::keynav::ToolbarItem::Primary, add_btn));
        }
        let toolbar = container(dir_row(row_items).align_y(iced::Alignment::Center))
            .padding(Padding { top: 16.0, right: 24.0, bottom: 16.0, left: 24.0 })
            .width(Length::Fill);

        // ── Search bar ──
        // Collapses to zero height in Workspace mode where the search
        // lives on the contextual sub-nav (`view_vault_sub_nav`),
        // matching the host-grid / snippets / history treatment.
        // Search now lives in the toolbar (`vault_search_field`); the
        // legacy below-toolbar search bar collapses to nothing.
        let search_bar: Element<'_, Message> = Space::new().into();

        // ── Status message ──
        // While the import / identity sidebars are open, the panel surfaces
        // its own error/success right next to the field that caused it
        // duplicating the message in the main keychain area is just noise.
        let panel_open =
            self.panels.key_panel || self.panels.identity_panel || self.panels.key_generate_panel;
        let status: Element<'_, Message> = if panel_open {
            Space::new().into()
        } else if let Some(err) = &self.keys_ui.error {
            container(Element::from(text(err.clone()).size(12).color(OryxisColors::t().error)))
                .padding(Padding { top: 0.0, right: 24.0, bottom: 8.0, left: 24.0 })
                .into()
        } else if let Some(ok) = &self.keys_ui.success {
            container(Element::from(text(ok.clone()).size(12).color(OryxisColors::t().success)))
                .padding(Padding { top: 0.0, right: 24.0, bottom: 8.0, left: 24.0 })
                .into()
        } else {
            Space::new().into()
        };

        // ── Keys grid ──
        // Section title in a Fill container so it anchors to the
        // card grid's leading edge (column align_x can push a
        // shrink-fit text past the card border otherwise).
        let section_title = container(
            container(
                text(t("keys_section")).size(14).color(OryxisColors::t().text_muted),
            )
            .width(Length::Fill)
            .align_x(crate::widgets::dir_align_x()),
        )
        .padding(Padding { top: 4.0, right: 0.0, bottom: 8.0, left: 0.0 });

        // Filter keys by search query. Apply the toolbar sort by
        // reordering the index list first so EditKey(idx) / DeleteKey
        // still target the canonical vault index, even though the
        // rendered order changes.
        let search_lower = self.keys_ui.search.to_lowercase();
        let mut key_order: Vec<usize> = (0..self.keys.len()).collect();
        self.keys_sort.sort_items(
            &mut key_order,
            |&i| self.keys[i].label.clone(),
            |&i| self.keys[i].created_at,
        );
        let filtered_keys: Vec<(usize, &SshKey)> = key_order
            .into_iter()
            .map(|i| (i, &self.keys[i]))
            .filter(|(_, k)| {
                search_lower.is_empty() || k.label.to_lowercase().contains(&search_lower)
            })
            .collect();

        let mut cards: Vec<Element<'_, Message>> = Vec::new();

        // The full-page empty state only applies when the whole keychain
        // is empty: a vault with identities but no SSH keys must still
        // render the identities section below (issue #70, credentials
        // looked "lost" because this early return hid them).
        if self.keys.is_empty() && self.identities.is_empty() {
            // No toolbar when empty: search is hidden and the "+ ADD ▾"
            // menu's own entries render as real buttons below instead
            // (avoids an orphaned action button, and a dropdown on an
            // otherwise blank screen hides every path but the hero
            // behind a chevron: with only the two key CTAs here, a fresh
            // vault could not reach the identity form at all).
            // Side panels are hoisted to `view_main` (active_side_panel).
            // Un-record the toolbar items registered above; none of
            // them render on this path. The content rows are cleared
            // here and re-recorded below, in display order.
            self.keynav_toolbar_reset();
            self.keynav_clear_content();
            let mut actions = self.add_key_actions();
            // The catalog's first entry is the primary one; it becomes
            // the filled hero CTA and the rest the secondary stack.
            let primary = actions.remove(0);
            let mut items: Vec<Element<'_, Message>> = vec![
                empty_state_icon(
                    iced_fonts::lucide::key_round()
                        .size(32)
                        .color(OryxisColors::t().text_muted)
                        .into(),
                ),
                Space::new().height(20).into(),
                text(crate::i18n::t("add_key_title"))
                    .size(20)
                    .color(OryxisColors::t().text_primary)
                    .into(),
                Space::new().height(8).into(),
                text(crate::i18n::t("add_key_desc"))
                    .size(13)
                    .color(OryxisColors::t().text_muted)
                    .align_x(iced::alignment::Horizontal::Center)
                    .into(),
                Space::new().height(24).into(),
                self.content_action_slot(
                    crate::keynav::RowAction::activate(primary.msg.clone()),
                    8.0,
                    crate::widgets::cta_button(primary.label.to_string(), primary.msg),
                ),
                Space::new().height(24).into(),
                crate::views::add_actions::or_divider(EMPTY_BLOCK_WIDTH),
                Space::new().height(16).into(),
            ];
            for action in actions {
                items.push(self.content_action_slot(
                    crate::keynav::RowAction::activate(action.msg.clone()),
                    8.0,
                    crate::views::add_actions::secondary_action_button(action, EMPTY_BLOCK_WIDTH),
                ));
                items.push(Space::new().height(8).into());
            }
            let empty_state = container(
                iced::widget::Column::with_children(items).align_x(iced::Alignment::Center),
            )
            .center(Length::Fill);
            let main_content = column![search_bar, status, empty_state]
                .width(Length::Fill)
                .height(Length::Fill);
            return main_content.into();
        } else if filtered_keys.is_empty() && !self.keys.is_empty() {
            let no_results = container(
                text(t("no_keys_match")).size(13).color(OryxisColors::t().text_muted),
            )
            .padding(24)
            .width(CARD_WIDTH);
            cards.push(no_results.into());
        }

        for &(idx, key) in &filtered_keys {
            let algo = format!("{} {}", t("type_label"), key.algorithm);
            let key_style = crate::widgets::resolve_host_icon_style(
                None,
                &self.prefs.default_host_icon,
            );
            let glyph_el: Element<'_, Message> = iced_fonts::lucide::key_round()
                .size(16)
                .line_height(1.0)
                .color(Color::WHITE)
                .into();
            let icon_box = crate::widgets::host_icon(
                key_style,
                OryxisColors::t().accent,
                &key.label,
                Some(glyph_el),
                32.0,
            );

            // Floating ⋮ kebab: lives in a Stack overlay on the trailing
            // corner so it doesn't take inline width. Always mounted with
            // a transparent glyph + no-hover bg when not active so the
            // surrounding MouseArea bounds stay stable.
            let key_kb_selected = self.keynav.selected_in(crate::keynav::FocusZone::Content)
                == Some(crate::keynav::NavItem::Key(idx));
            let key_show_dots = self.hover.key_card == Some(idx)
                || self.keys_ui.context_menu == Some(idx)
                || key_kb_selected;
            let key_rtl = crate::i18n::is_rtl_layout();
            // Match the dashboard host-card geometry exactly: the host
            // card wraps its row in `container(...).padding(...)` and
            // lets the outer button add its `DEFAULT_PADDING` (5/10/5
            // /10), producing a 13/16/13/12 effective padding. Since
            // keychain cards override `button.padding()` directly,
            // they need explicit values that match that effective
            // size, otherwise they render ~10 px shorter and ~4 px
            // tighter on the leading edge than the host cards next to
            // them. Trailing stays at 24 to clear the kebab overlay.
            let card_pad_trailing = 24.0_f32;
            let card_padding = if key_rtl {
                Padding { top: 13.0, right: 12.0, bottom: 13.0, left: card_pad_trailing }
            } else {
                Padding { top: 13.0, right: card_pad_trailing, bottom: 13.0, left: 12.0 }
            };

            // Subtitle line: the algorithm, plus a type flag (B2.1 /
            // B3, Termius-style: the row reads as the key's kind). A
            // security key wins over the certificate flag when both
            // apply, it is the more load-bearing fact (signing happens
            // on the hardware token via the agent; the cert shows in
            // the editor).
            let algo_text: Element<'_, Message> = text(algo)
                .size(11)
                .color(OryxisColors::t().text_muted)
                .wrapping(iced::widget::text::Wrapping::None)
                .into();
            let flag = if key.algorithm.is_security_key() {
                Some(t("key_badge_security_key"))
            } else if key.certificate.is_some() {
                Some(t("cert_flag"))
            } else {
                None
            };
            let key_subtitle: Element<'_, Message> = if let Some(flag) = flag {
                dir_row(vec![
                    algo_text,
                    text(" · ").size(11).color(OryxisColors::t().text_muted).into(),
                    text(flag)
                        .size(11)
                        .color(OryxisColors::t().accent)
                        .wrapping(iced::widget::text::Wrapping::None)
                        .into(),
                ])
                .align_y(iced::Alignment::Center)
                .into()
            } else {
                algo_text
            };

            let card = button(
                dir_row(vec![
                    icon_box,
                    Space::new().width(8).into(),
                    column![
                        text(&key.label)
                            .size(13)
                            .color(OryxisColors::t().text_primary)
                            .wrapping(iced::widget::text::Wrapping::None),
                        Space::new().height(2),
                        key_subtitle,
                    ]
                    .width(Length::Fill)
                    .align_x(crate::widgets::dir_align_x())
                    .clip(true)
                    .into(),
                ]).align_y(iced::Alignment::Center),
            )
            .on_press(Message::Keys(KeysMessage::EditKey(idx)))
            .padding(card_padding)
            .width(Length::Fill)
            .style(|_, status| {
                let (bg, border_color, border_width) = match status {
                    BtnStatus::Hovered => (OryxisColors::t().bg_hover, OryxisColors::t().accent, 1.5),
                    BtnStatus::Pressed => (OryxisColors::t().bg_selected, OryxisColors::t().accent, 2.0),
                    _ => (OryxisColors::t().bg_surface, OryxisColors::t().border, 1.0),
                };
                button::Style {
                    background: Some(Background::Color(bg)),
                    border: Border { radius: Radius::from(10.0), color: border_color, width: border_width },
                    ..Default::default()
                }
            });

            let key_dots_glyph_color = if key_show_dots {
                OryxisColors::t().text_muted
            } else {
                Color::TRANSPARENT
            };
            let dots_btn = crate::widgets::card_kebab_button(
                key_dots_glyph_color,
                key_show_dots,
                Message::Keys(KeysMessage::ShowKeyMenu(idx)),
            );
            let key_dots_align = if key_rtl {
                iced::alignment::Horizontal::Left
            } else {
                iced::alignment::Horizontal::Right
            };
            let key_dots_pad = if key_rtl {
                Padding { top: 0.0, right: 0.0, bottom: 0.0, left: 8.0 }
            } else {
                Padding { top: 0.0, right: 8.0, bottom: 0.0, left: 0.0 }
            };
            let dots_overlay = container(dots_btn)
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(key_dots_align)
                .align_y(iced::alignment::Vertical::Center)
                .padding(key_dots_pad);
            let card_element: Element<'_, Message> = iced::widget::Stack::new()
                .push(card)
                .push(dots_overlay)
                .into();

            // Wrap in MouseArea for right-click + hover events that
            // drive the dots-button visibility.
            let wrapped = MouseArea::new(card_element)
                .on_enter(Message::Tabs(TabsMessage::KeyCardHovered(idx)))
                .on_exit(Message::Tabs(TabsMessage::KeyCardUnhovered(idx)))
                .on_right_press(Message::Keys(KeysMessage::ShowKeyMenu(idx)));

            let card_el: Element<'_, Message> =
                container(wrapped).width(Length::Fill).clip(true).into();
            let card_el = self.card_wash(card_el, OryxisColors::t().accent);
            cards.push(self.keynav_ring_content(key_kb_selected, card_el));
        }

        // Responsive grid: column count derived from the current window
        // width minus the visible chrome (left nav + optional right panel
        // + horizontal padding around the grid). When the user resizes
        // the window or opens/closes the side panel, the next view()
        // recomputes `cols` and the cards rewrap accordingly instead of
        // disappearing into clipped overflow.
        let nav_width = self.vault_rail_width();
        let panel_width = if self.panels.key_panel
            || self.panels.identity_panel
            || self.panels.key_generate_panel
        {
            self.panel_width
        } else {
            0.0
        };
        // 24 px of horizontal padding on each side of the grid column,
        // plus ~12 px reserved for the scrollbar gutter on the trailing
        // edge. Keep this in sync with the `padding` set on the
        // scrollable column further down.
        let available = (self.window_size.width
            - nav_width
            - self.side_strip_reserve()
            - panel_width
            - 60.0)
            .max(0.0);
        let cols = card_grid_columns(available, CARD_WIDTH, 12.0);
        let keys_grid_elem = distribute_card_grid(cards, cols, 12.0, 12.0);

        // ── Identities section ──
        let identity_section_title = container(
            container(
                text(t("identities")).size(14).color(OryxisColors::t().text_muted),
            )
            .width(Length::Fill)
            .align_x(crate::widgets::dir_align_x()),
        )
        .padding(Padding { top: 16.0, right: 0.0, bottom: 8.0, left: 0.0 });

        let mut identity_order: Vec<usize> = (0..self.identities.len()).collect();
        self.keys_sort.sort_items(
            &mut identity_order,
            |&i| self.identities[i].label.clone(),
            |&i| self.identities[i].created_at,
        );
        let filtered_identities: Vec<(usize, &Identity)> = identity_order
            .into_iter()
            .map(|i| (i, &self.identities[i]))
            .filter(|(_, i)| {
                search_lower.is_empty() || i.label.to_lowercase().contains(&search_lower)
            })
            .collect();

        let mut identity_cards: Vec<Element<'_, Message>> = Vec::new();

        if filtered_identities.is_empty() && self.identities.is_empty() {
            // Don't show identities section at all when empty
        } else if filtered_identities.is_empty() {
            let no_results = container(
                text(t("no_identities_match")).size(13).color(OryxisColors::t().text_muted),
            )
            .padding(24)
            .width(CARD_WIDTH);
            identity_cards.push(no_results.into());
        }

        for (idx, identity) in &filtered_identities {
            let idx = *idx;
            // Build subtitle describing auth methods
            let mut parts: Vec<String> = Vec::new();
            if let Some(u) = &identity.username {
                parts.push(u.clone());
            }
            let has_pw = self.identities_with_password.contains(&identity.id);
            if has_pw {
                parts.push("\u{25CF}\u{25CF}\u{25CF}\u{25CF}".into());
            }
            if let Some(kid) = identity.key_id
                && let Some(k) = self.keys.iter().find(|k| k.id == kid) {
                    parts.push(k.label.clone());
            }
            let subtitle = if parts.is_empty() { t("no_credentials").to_string() } else { parts.join(", ") };

            let id_style = crate::widgets::resolve_host_icon_style(
                None,
                &self.prefs.default_host_icon,
            );
            let id_glyph_el: Element<'_, Message> = iced_fonts::lucide::user()
                .size(16)
                .line_height(1.0)
                .color(Color::WHITE)
                .into();
            let icon_box = crate::widgets::host_icon(
                id_style,
                OryxisColors::t().accent,
                &identity.label,
                Some(id_glyph_el),
                32.0,
            );

            // Floating ⋮ kebab in a Stack overlay on the trailing corner,
            // same pattern as host / key cards.
            let id_kb_selected = self.keynav.selected_in(crate::keynav::FocusZone::Content)
                == Some(crate::keynav::NavItem::Identity(idx));
            let id_show_dots = self.hover.identity_card == Some(idx)
                || self.identity_context_menu == Some(idx)
                || id_kb_selected;
            let id_rtl = crate::i18n::is_rtl_layout();
            // Match the host-card geometry (see key card comment
            // above): 13 top/bottom + 12 leading + 24 trailing brings
            // the identity card to the same visible footprint as the
            // host folder cards on the dashboard, fixing the "card has
            // no padding" feel (was 2 leading) and the 9-px height
            // gap to host cards (was 8 top/bottom).
            let id_pad_trailing = 24.0_f32;
            let id_card_padding = if id_rtl {
                Padding { top: 13.0, right: 12.0, bottom: 13.0, left: id_pad_trailing }
            } else {
                Padding { top: 13.0, right: id_pad_trailing, bottom: 13.0, left: 12.0 }
            };

            let card = button(
                dir_row(vec![
                    icon_box,
                    Space::new().width(8).into(),
                    column![
                        text(&identity.label)
                            .size(13)
                            .color(OryxisColors::t().text_primary)
                            .wrapping(iced::widget::text::Wrapping::None),
                        Space::new().height(2),
                        text(subtitle)
                            .size(11)
                            .color(OryxisColors::t().text_muted)
                            .wrapping(iced::widget::text::Wrapping::None),
                    ]
                    .width(Length::Fill)
                    .align_x(crate::widgets::dir_align_x())
                    .clip(true)
                    .into(),
                ]).align_y(iced::Alignment::Center),
            )
            .on_press(Message::Keys(KeysMessage::EditIdentity(idx)))
            .padding(id_card_padding)
            .width(Length::Fill)
            .style(|_, status| {
                let (bg, border_color, border_width) = match status {
                    BtnStatus::Hovered => (OryxisColors::t().bg_hover, OryxisColors::t().accent, 1.5),
                    BtnStatus::Pressed => (OryxisColors::t().bg_selected, OryxisColors::t().accent, 2.0),
                    _ => (OryxisColors::t().bg_surface, OryxisColors::t().border, 1.0),
                };
                button::Style {
                    background: Some(Background::Color(bg)),
                    border: Border { radius: Radius::from(10.0), color: border_color, width: border_width },
                    ..Default::default()
                }
            });

            let id_dots_glyph_color = if id_show_dots {
                OryxisColors::t().text_muted
            } else {
                Color::TRANSPARENT
            };
            let dots_btn = crate::widgets::card_kebab_button(
                id_dots_glyph_color,
                id_show_dots,
                Message::Keys(KeysMessage::ShowIdentityMenu(idx)),
            );
            let id_dots_align = if id_rtl {
                iced::alignment::Horizontal::Left
            } else {
                iced::alignment::Horizontal::Right
            };
            let id_dots_pad = if id_rtl {
                Padding { top: 0.0, right: 0.0, bottom: 0.0, left: 8.0 }
            } else {
                Padding { top: 0.0, right: 8.0, bottom: 0.0, left: 0.0 }
            };
            let dots_overlay = container(dots_btn)
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(id_dots_align)
                .align_y(iced::alignment::Vertical::Center)
                .padding(id_dots_pad);
            let card_element: Element<'_, Message> = iced::widget::Stack::new()
                .push(card)
                .push(dots_overlay)
                .into();

            let wrapped = MouseArea::new(card_element)
                .on_enter(Message::Tabs(TabsMessage::IdentityCardHovered(idx)))
                .on_exit(Message::Tabs(TabsMessage::IdentityCardUnhovered(idx)))
                .on_right_press(Message::Keys(KeysMessage::ShowIdentityMenu(idx)));

            let id_card_el: Element<'_, Message> =
                container(wrapped).width(Length::Fill).clip(true).into();
            let id_card_el = self.card_wash(id_card_el, OryxisColors::t().accent);
            identity_cards.push(self.keynav_ring_content(id_kb_selected, id_card_el));
        }

        let identity_grid_elem = distribute_card_grid(identity_cards, cols, 12.0, 12.0);

        // Record the keyboard-navigation order as two Tab sections
        // (Keys, then Identities), both chunked to the same column
        // count the grids render with; arrows flow across both.
        {
            let cw = cols.max(1);
            let key_nav: Vec<crate::keynav::NavItem> = filtered_keys
                .iter()
                .map(|(i, _)| crate::keynav::NavItem::Key(*i))
                .collect();
            let id_nav: Vec<crate::keynav::NavItem> = filtered_identities
                .iter()
                .map(|(i, _)| crate::keynav::NavItem::Identity(*i))
                .collect();
            self.keynav_set_content_sections(vec![
                key_nav.chunks(cw).map(|c| c.to_vec()).collect(),
                id_nav.chunks(cw).map(|c| c.to_vec()).collect(),
            ]);
        }

        // Combine keys and identities into one scrollable area. Either
        // section hides entirely when its list is empty (the both-empty
        // case never reaches here, it takes the empty-state return above).
        let mut all_rows: Vec<Element<'_, Message>> = Vec::new();
        if !self.keys.is_empty() {
            all_rows.push(section_title.into());
            all_rows.push(keys_grid_elem);
        }
        if !self.identities.is_empty() {
            all_rows.push(identity_section_title.into());
            all_rows.push(identity_grid_elem);
        }

        // Right padding here also pushes the content away from the
        // scrollbar, keep it slim so the scrollbar reads as flush
        // against the panel edge rather than floating in dead space.
        // The column needs `Length::Fill` for `align_x` to have any
        // slack to align inside, without it the column shrinks to
        // content and rows hug the leading edge regardless.
        let grid = scrollable(
            column(all_rows)
                .width(Length::Fill)
                .padding(Padding { top: 0.0, right: 24.0, bottom: 24.0, left: 24.0 })
                .align_x(crate::widgets::dir_align_x()),
        )
        // Stable id so the keyboard router can keep the selected card
        // scrolled into view.
        .id(iced::widget::Id::new("keys-grid-scroll"))
        .height(Length::Fill);

        // ── Main content ──
        // Side panels (key import / identity editor) are hoisted to
        // `view_main` (active_side_panel) so they cover the sub-nav band.
        column![toolbar, search_bar, status, grid]
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
