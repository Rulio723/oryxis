//! Per-host terminal theme picker, opened from the "Terminal Theme"
//! row in the host editor. Renders a column of palette swatch cards;
//! the first card is the "inherit global theme" sentinel. Selecting a
//! card commits to `editor_form.terminal_theme` and closes the modal.
//!
//! Keyboard: it is `Modal::ThemePicker` on the modal ring. The filter,
//! the Dark / Light chips, every card and Close record in display
//! order, so Tab / arrows walk the whole dialog and Enter picks; the
//! filter keeps the caret (`modal_surface_has_input`).

use iced::border::Radius;
use iced::widget::{column, container, scrollable, text, Space};
use iced::{Background, Border, Element, Length};

use crate::app::{EditorMessage, Message, Oryxis};
use crate::i18n::t;
use crate::theme::OryxisColors;
use crate::widgets::styled_button;

/// Widget id of the picker's filter field, so the ring's Enter can
/// focus it.
const HOST_THEME_PICKER_FILTER_ID: &str = "host-theme-picker-filter";

impl Oryxis {
    pub(crate) fn view_terminal_theme_picker(&self) -> Element<'_, Message> {
        self.modal_nav_reset();
        // Header, title + short description matching the row in the
        // host editor that opened this modal.
        let header = column![
            text(t("terminal_theme")).size(16).font(iced::Font {
                weight: iced::font::Weight::Bold,
                ..iced::Font::new(crate::theme::SYSTEM_UI_FAMILY)
            }).color(OryxisColors::t().text_primary),
            Space::new().height(4),
            text(t("host_terminal_theme_desc"))
                .size(11)
                .color(OryxisColors::t().text_muted),
        ];

        // Filter, matched against every card's visible label (the
        // inherit sentinel participates too): one rule, no special
        // cases, same contract as the Settings gallery.
        let picker_filter = self.theme_ui.picker_filter.trim().to_lowercase();
        let picker_tone = self.theme_ui.picker_tone;
        let shows = |label: &str, traits: Option<&[oryxis_terminal::ThemeTrait]>| {
            crate::theme_tags::theme_matches(&picker_filter, picker_tone, label, traits)
        };
        // Recorded in display order: the filter first (Enter focuses
        // it), then the chips under it.
        let filter_id = iced::widget::Id::new(HOST_THEME_PICKER_FILTER_ID);
        let filter_idx =
            self.modal_nav_record(crate::keynav::RowAction::input(filter_id.clone()));
        let filter_input = self.modal_nav_ring_at(
            filter_idx,
            8.0,
            false,
            iced::widget::text_input(t("filter_placeholder"), &self.theme_ui.picker_filter)
                .id(filter_id)
                .on_input(|v| Message::Editor(EditorMessage::EditorThemePickerFilterChanged(v)))
                .padding(10)
                .size(13)
                .style(crate::widgets::rounded_input_style)
                .into(),
        );
        let tone_chips: Vec<Element<'_, Message>> = crate::theme_tags::TONE_CHOICES
            .iter()
            .map(|(tone, key)| {
                let msg = Message::Editor(EditorMessage::EditorThemePickerToneChanged(*tone));
                self.modal_nav_slot(
                    crate::keynav::RowAction::activate(msg.clone()),
                    14.0,
                    false,
                    crate::theme_tags::tone_chip(t(key), picker_tone == *tone, msg),
                )
            })
            .collect();
        // Every card records its own pick on the ring, in the order the
        // column shows them.
        let card = |el: Element<'static, Message>, pick: Message| -> Element<'static, Message> {
            self.modal_nav_slot(crate::keynav::RowAction::activate(pick), 10.0, false, el)
        };

        // Cards, first row is the inherit sentinel, the rest are
        // real palette previews. Click commits + closes via the
        // EditorTerminalThemeChanged handler. The inherit row renders
        // as a real theme card previewing the GLOBAL palette (it used
        // to be an input-looking box that read as a text field), so
        // "use global" shows exactly what inheriting means.
        let mut cards: Vec<Element<'_, Message>> = Vec::new();
        let global_name = self.resolve_global_terminal_theme_name();
        let global_palette = self
            .terminal_palette_for_name(&global_name)
            .unwrap_or_default();
        let inherit_label = format!(
            "{} ({})",
            t("terminal_theme_inherit_global"),
            global_name,
        );
        let global_traits = global_palette.traits();
        if shows(&inherit_label, Some(&global_traits)) {
            let pick = Message::Editor(EditorMessage::EditorTerminalThemeChanged(String::new()));
            cards.push(card(
                crate::widgets::terminal_theme_card(
                    global_palette,
                    &inherit_label,
                    self.editor_form.terminal_theme.is_none(),
                    pick.clone(),
                ),
                pick,
            ));
        }
        for theme in oryxis_terminal::TerminalTheme::ALL.iter() {
            let traits = theme.traits();
            if !shows(theme.name(), Some(&traits)) {
                continue;
            }
            let is_selected =
                self.editor_form.terminal_theme.as_deref() == Some(theme.name());
            let pick =
                Message::Editor(EditorMessage::EditorTerminalThemeChanged(theme.name().to_string()));
            cards.push(card(
                crate::widgets::terminal_theme_card(
                    theme.palette(),
                    theme.name(),
                    is_selected,
                    pick.clone(),
                ),
                pick,
            ));
        }
        // User-defined themes, selectable per host like the built-ins.
        for ct in self.custom_terminal_themes.iter() {
            let palette = self.terminal_palette_for_name(&ct.name).unwrap_or_default();
            let traits = palette.traits();
            if !shows(&ct.name, Some(&traits)) {
                continue;
            }
            let is_selected =
                self.editor_form.terminal_theme.as_deref() == Some(ct.name.as_str());
            let pick = Message::Editor(EditorMessage::EditorTerminalThemeChanged(ct.name.clone()));
            cards.push(card(
                crate::widgets::terminal_theme_card(palette, &ct.name, is_selected, pick.clone()),
                pick,
            ));
        }

        let scroll_area = scrollable(
            column(cards).spacing(8).padding(iced::Padding {
                top: 0.0,
                right: 10.0,
                bottom: 0.0,
                left: 0.0,
            }),
        )
        .height(Length::Fill);

        let close_msg = Message::Editor(EditorMessage::EditorCloseThemePicker);
        let close_btn = self.modal_nav_slot(
            crate::keynav::RowAction::activate(close_msg.clone()),
            8.0,
            false,
            styled_button(t("close"), close_msg, OryxisColors::t().bg_hover),
        );
        // Dismiss action hugs the trailing edge (dialog convention),
        // mirrored under RTL.
        let close_align = if crate::i18n::is_rtl_layout() {
            iced::alignment::Horizontal::Left
        } else {
            iced::alignment::Horizontal::Right
        };

        let dialog = container(
            column![
                header,
                Space::new().height(12),
                filter_input,
                Space::new().height(8),
                crate::widgets::dir_row(tone_chips).spacing(6),
                Space::new().height(12),
                scroll_area,
                Space::new().height(12),
                container(close_btn)
                    .width(Length::Fill)
                    .align_x(close_align),
            ],
        )
        .padding(20)
        .width(Length::Fixed(480.0))
        .height(Length::Fixed(560.0))
        .style(|_| container::Style {
            background: Some(Background::Color(OryxisColors::t().bg_primary)),
            border: Border {
                radius: Radius::from(12.0),
                color: OryxisColors::t().border,
                width: 1.0,
            },
            ..Default::default()
        });

        // Bare card; `widgets::modal_overlay` (the caller) owns centering,
        // the absorbing scrim, and the click-trap.
        dialog.into()
    }
}
