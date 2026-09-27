//! The group editor's "Defaults" section (D4): the per-parameter values
//! every host inside the group inherits unless it sets its own.
//!
//! Collapsed unless the group already sets something. Most groups are
//! just folders, and seven inheritance fields would otherwise be the
//! loudest thing in a panel whose usual job is renaming.
//!
//! Every picker carries an explicit "not set" row rather than a blank
//! one, because "no value" is a real choice here and has to be
//! selectable, not just typeable.

use iced::widget::{button, column, container, pick_list, text, text_input, Space};
use iced::{Background, Border, Color, Element, Length, Padding};

use crate::app::{Message, NavigationMessage, Oryxis, TabsMessage};
use crate::i18n::t;
use crate::theme::OryxisColors;
use crate::widgets::{dir_align_x, dir_row, panel_field};

impl Oryxis {
    /// The whole section: a disclosure header plus, when open, the
    /// fields. Rows record on the panel keynav ring in build order, the
    /// panel contract, so the walk matches what is on screen.
    pub(crate) fn group_defaults_section(&self) -> Element<'_, Message> {
        let mut col = column![self.group_defaults_header()].spacing(10);
        if !self.group_edit.defaults_open {
            return col.into();
        }

        col = col.push(
            container(
                text(t("group_defaults_desc"))
                    .size(11)
                    .color(OryxisColors::t().text_muted),
            )
            .padding(Padding { top: 0.0, right: 4.0, bottom: 2.0, left: 4.0 }),
        );

        // Username, plain text like the host's own field. The secret
        // half never lives here: that is what the identity is for.
        col = col.push(panel_field(
            t("username"),
            self.panel_nav_slot(
                crate::keynav::RowAction::input(iced::widget::Id::new("group-default-username")),
                crate::widgets::INPUT_RADIUS,
                text_input(t("group_default_inherit"), &self.group_edit.username)
                    .id(iced::widget::Id::new("group-default-username"))
                    .on_input(|v| Message::Tabs(TabsMessage::GroupEditDefaultUsername(v)))
                    .padding(10)
                    .style(crate::widgets::rounded_input_style)
                    .align_x(dir_align_x())
                    .into(),
            ),
        ));

        col = col.push(self.group_default_picker(
            t("identity"),
            "group-default-identity",
            self.identities.iter().map(|i| i.label.clone()).collect(),
            self.group_edit.identity_label.clone(),
            |v| Message::Tabs(TabsMessage::GroupEditDefaultIdentity(v)),
        ));
        col = col.push(self.group_default_picker(
            t("group_default_proxy"),
            "group-default-proxy",
            self.proxy_identities.iter().map(|p| p.label.clone()).collect(),
            self.group_edit.proxy_identity_label.clone(),
            |v| Message::Tabs(TabsMessage::GroupEditDefaultProxyIdentity(v)),
        ));

        // Terminal theme: built-ins plus the user's own, by NAME (the
        // stored value is the name, so no id mapping is involved).
        let mut themes: Vec<String> = oryxis_terminal::TerminalTheme::ALL
            .iter()
            .map(|t| t.name().to_string())
            .collect();
        themes.extend(self.custom_terminal_themes.iter().map(|t| t.name.clone()));
        col = col.push(self.group_default_picker(
            t("terminal_theme"),
            "group-default-theme",
            themes,
            self.group_edit.terminal_theme.clone(),
            |v| Message::Tabs(TabsMessage::GroupEditDefaultTheme(v)),
        ));

        col = col.push(self.group_default_picker(
            t("group_default_snippet"),
            "group-default-snippet",
            self.snippets.iter().map(|s| s.label.clone()).collect(),
            self.group_edit.startup_snippet_label.clone(),
            |v| Message::Tabs(TabsMessage::GroupEditDefaultSnippet(v)),
        ));

        // Port is the one field that is NOT inherited at connect time:
        // it prefills a host created inside the group and never touches
        // one that already exists. The hint says so, because a default
        // that only applies sometimes is otherwise a trap.
        col = col.push(panel_field(
            t("port"),
            self.panel_nav_slot(
                crate::keynav::RowAction::input(iced::widget::Id::new("group-default-port")),
                crate::widgets::INPUT_RADIUS,
                text_input(t("group_default_inherit"), &self.group_edit.port)
                    .id(iced::widget::Id::new("group-default-port"))
                    .on_input(|v| Message::Tabs(TabsMessage::GroupEditDefaultPort(v)))
                    .padding(10)
                    .style(crate::widgets::rounded_input_style)
                    .align_x(dir_align_x())
                    .into(),
            ),
        ));
        col = col.push(
            container(
                text(t("group_default_port_hint"))
                    .size(10)
                    .color(OryxisColors::t().text_muted),
            )
            .padding(Padding { top: 0.0, right: 4.0, bottom: 4.0, left: 4.0 }),
        );

        col = col.push(self.group_default_env_vars());
        col.into()
    }

    /// Disclosure header. Shows a count when the section is collapsed
    /// but the group does set something, so a closed section can never
    /// hide the fact that inheritance is in play.
    fn group_defaults_header(&self) -> Element<'_, Message> {
        let open = self.group_edit.defaults_open;
        let chevron = if open {
            iced_fonts::lucide::chevron_down::<iced::Theme>()
        } else if crate::i18n::is_rtl_layout() {
            iced_fonts::lucide::chevron_left()
        } else {
            iced_fonts::lucide::chevron_right()
        };
        let set_count = self.group_edit_defaults().map(count_set).unwrap_or(0);
        let mut label = dir_row(vec![
            chevron.size(12).color(OryxisColors::t().text_muted).into(),
            Space::new().width(6).into(),
            text(t("group_defaults_title"))
                .size(12)
                .color(OryxisColors::t().text_secondary)
                .into(),
        ]);
        if !open && set_count > 0 {
            label = label.push(Space::new().width(6));
            label = label.push(
                text(format!("({set_count})"))
                    .size(11)
                    .color(OryxisColors::t().accent),
            );
        }
        self.panel_nav_slot(
            crate::keynav::RowAction::activate(Message::Tabs(TabsMessage::GroupEditToggleDefaults)),
            6.0,
            button(container(label.align_y(iced::Alignment::Center)).width(Length::Fill))
                .on_press(Message::Tabs(TabsMessage::GroupEditToggleDefaults))
                .padding(Padding { top: 6.0, right: 4.0, bottom: 6.0, left: 4.0 })
                .width(Length::Fill)
                .style(|_, status| {
                    let bg = match status {
                        button::Status::Hovered => OryxisColors::t().bg_hover,
                        button::Status::Pressed => OryxisColors::t().bg_selected,
                        _ => Color::TRANSPARENT,
                    };
                    button::Style {
                        background: Some(Background::Color(bg)),
                        border: Border {
                            radius: iced::border::Radius::from(6.0),
                            ..Default::default()
                        },
                        ..Default::default()
                    }
                })
                .into(),
        )
    }

    /// One "pick a thing, or nothing" row.
    ///
    /// The "not set" option is a real row rather than an empty
    /// selection: leaving a value unset is the DEFAULT state of every
    /// field here, so the user needs a way back to it once they have
    /// chosen something.
    fn group_default_picker<'a>(
        &'a self,
        label: &'a str,
        id: &'static str,
        options: Vec<String>,
        selected: Option<String>,
        on_pick: impl Fn(Option<String>) -> Message + 'a,
    ) -> Element<'a, Message> {
        let none_label = t("group_default_inherit").to_string();
        let mut rows = vec![none_label.clone()];
        rows.extend(options);
        let shown = selected.clone().unwrap_or_else(|| none_label.clone());
        let none_for_pick = none_label.clone();
        panel_field(
            label,
            self.panel_nav_slot(
                crate::keynav::RowAction::input(iced::widget::Id::new(id)),
                crate::widgets::INPUT_RADIUS,
                pick_list(Some(shown), rows, |s: &String| s.clone())
                    .on_select(move |v: String| {
                        // The sentinel row maps back to "unset" rather
                        // than being stored as a label of its own.
                        on_pick((v != none_for_pick).then_some(v))
                    })
                    .id(iced::widget::Id::new(id))
                    .on_open(Message::Navigation(NavigationMessage::PickOpenChanged(true)))
                    .on_close(Message::Navigation(NavigationMessage::PickOpenChanged(false)))
                    .width(200)
                    .padding(10)
                    .style(crate::widgets::rounded_pick_list_style)
                    .into(),
            ),
        )
    }

    /// Environment variables the group contributes. Merged by name with
    /// the host's and the other ancestors', so this list adds to what a
    /// host has rather than replacing it.
    fn group_default_env_vars(&self) -> Element<'_, Message> {
        let mut col = column![
            container(
                text(t("env_vars"))
                    .size(11)
                    .color(OryxisColors::t().text_secondary),
            )
            .padding(Padding { top: 4.0, right: 4.0, bottom: 0.0, left: 4.0 }),
        ]
        .spacing(6);

        for (idx, var) in self.group_edit.env_vars.iter().enumerate() {
            col = col.push(
                dir_row(vec![
                    // Same static-id limitation the host editor's env
                    // rows and the port-forward rows carry: an `Id` has
                    // to be `&'static str`, and these are per-index, so
                    // the two inputs stay mouse-only and the remove
                    // button is the keyboard row.
                    text_input("LC_EXAMPLE", &var.key)
                        .on_input(move |v| Message::Tabs(TabsMessage::GroupEditEnvKey(idx, v)))
                        .padding(8)
                        .width(Length::FillPortion(2))
                        .style(crate::widgets::rounded_input_style)
                        .align_x(dir_align_x())
                        .into(),
                    Space::new().width(6).into(),
                    text_input(t("env_value_placeholder"), &var.value)
                        .on_input(move |v| Message::Tabs(TabsMessage::GroupEditEnvValue(idx, v)))
                        .padding(8)
                        .width(Length::FillPortion(3))
                        .style(crate::widgets::rounded_input_style)
                        .align_x(dir_align_x())
                        .into(),
                    Space::new().width(4).into(),
                    self.panel_nav_slot(
                        crate::keynav::RowAction::activate(Message::Tabs(
                            TabsMessage::GroupEditEnvRemove(idx),
                        )),
                        6.0,
                        button(
                            iced_fonts::lucide::trash()
                                .size(12)
                                .color(OryxisColors::t().error),
                        )
                        .on_press(Message::Tabs(TabsMessage::GroupEditEnvRemove(idx)))
                        .padding(Padding { top: 6.0, right: 8.0, bottom: 6.0, left: 8.0 })
                        .style(|_, status| {
                            let bg = match status {
                                button::Status::Hovered => OryxisColors::t().bg_hover,
                                button::Status::Pressed => OryxisColors::t().bg_selected,
                                _ => Color::TRANSPARENT,
                            };
                            button::Style {
                                background: Some(Background::Color(bg)),
                                border: Border {
                                    radius: iced::border::Radius::from(6.0),
                                    ..Default::default()
                                },
                                ..Default::default()
                            }
                        })
                        .into(),
                    ),
                ])
                .align_y(iced::Alignment::Center),
            );
        }

        col = col.push(self.panel_nav_slot(
            crate::keynav::RowAction::activate(Message::Tabs(TabsMessage::GroupEditEnvAdd)),
            6.0,
            button(
                dir_row(vec![
                    iced_fonts::lucide::plus()
                        .size(12)
                        .color(OryxisColors::t().accent)
                        .into(),
                    Space::new().width(6).into(),
                    text(t("add")).size(11).color(OryxisColors::t().accent).into(),
                ])
                .align_y(iced::Alignment::Center),
            )
            .on_press(Message::Tabs(TabsMessage::GroupEditEnvAdd))
            .padding(Padding { top: 6.0, right: 8.0, bottom: 6.0, left: 8.0 })
            .style(|_, status| {
                let bg = match status {
                    button::Status::Hovered => OryxisColors::t().bg_hover,
                    button::Status::Pressed => OryxisColors::t().bg_selected,
                    _ => Color::TRANSPARENT,
                };
                button::Style {
                    background: Some(Background::Color(bg)),
                    border: Border {
                        radius: iced::border::Radius::from(6.0),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            })
            .into(),
        ));
        col.into()
    }
}

/// How many fields the group actually sets, for the collapsed header's
/// badge.
fn count_set(defaults: oryxis_core::models::group::GroupDefaults) -> usize {
    usize::from(defaults.username.is_some())
        + usize::from(defaults.identity_id.is_some())
        + usize::from(defaults.proxy_identity_id.is_some())
        + usize::from(defaults.port.is_some())
        + usize::from(defaults.terminal_theme.is_some())
        + usize::from(defaults.startup_snippet_id.is_some())
        + usize::from(!defaults.env_vars.is_empty())
}
