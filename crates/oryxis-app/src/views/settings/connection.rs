//! Settings -> Connection section view. Split out of views/settings/mod.rs.

use super::*;
use iced::widget::column;

impl Oryxis {
    pub(crate) fn view_settings_connection(&self) -> Element<'_, Message> {
        // Keyboard rows are recorded in visual order. The defaults card
        // renders first, so the keepalive section (previously built up
        // here) is now constructed after it, matching the render order.
        self.keynav_settings_reset();

        // Defaults pre-filled into a NEW host form (so the user doesn't
        // re-toggle agent forwarding / re-type a port every time).
        let term_default_options: Vec<String> = [
            "xterm-256color", "xterm", "screen-256color", "tmux-256color",
            "screen", "linux", "vt220", "vt100", "ansi",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // The localized "(none)" sentinel shared by the entity-reference
        // pickers (identity / key / group / proxy): selecting it clears the
        // default; any other option is a saved entity's label.
        let none_label = crate::i18n::t("new_default_none").to_string();

        // Auth method picker, options + current selection mirror the host
        // editor's auth picker so the labels match.
        let offer_security_key =
            crate::util::security_key_method_offered(&self.prefs.default_auth_method);
        let auth_options: Vec<String> = [
            Some(crate::i18n::t("auth_auto")), Some(crate::i18n::t("auth_password")),
            Some(crate::i18n::t("auth_key")),
            offer_security_key.then(|| crate::i18n::t("auth_security_key")),
            Some(crate::i18n::t("auth_certificate")),
            Some(crate::i18n::t("auth_agent")), Some(crate::i18n::t("auth_interactive")),
        ]
        .into_iter()
        .flatten()
        .map(|s| s.to_string())
        .collect();
        let auth_selected = crate::util::auth_method_label(&self.prefs.default_auth_method);

        let mut identity_options = vec![none_label.clone()];
        identity_options.extend(self.identities.iter().map(|i| i.label.clone()));
        let identity_selected = self
            .prefs.default_identity_id
            .and_then(|id| self.identities.iter().find(|i| i.id == id).map(|i| i.label.clone()))
            .unwrap_or_else(|| none_label.clone());

        let mut key_options = vec![none_label.clone()];
        key_options.extend(self.keys.iter().map(|k| k.label.clone()));
        let key_selected = self
            .prefs.default_key_id
            .and_then(|id| self.keys.iter().find(|k| k.id == id).map(|k| k.label.clone()))
            .unwrap_or_else(|| none_label.clone());

        // Parent group: only the visible (non-phantom) groups, matching
        // the host editor's group combo. Options are breadcrumb paths
        // so subgroups are distinguishable (and pickable as defaults).
        let visible_groups = self.visible_group_ids();
        let mut group_options = vec![none_label.clone()];
        group_options.extend(
            self.groups
                .iter()
                .filter(|g| visible_groups.contains(&g.id))
                .map(|g| oryxis_core::models::Group::path_of(&self.groups, g.id)),
        );
        let group_selected = self
            .prefs.default_group_id
            .filter(|id| self.groups.iter().any(|g| g.id == *id))
            .map(|id| oryxis_core::models::Group::path_of(&self.groups, id))
            .unwrap_or_else(|| none_label.clone());

        let mut proxy_options = vec![none_label.clone()];
        proxy_options.extend(self.proxy_identities.iter().map(|p| p.label.clone()));
        let proxy_selected = self
            .prefs.default_proxy_identity_id
            .and_then(|id| {
                self.proxy_identities.iter().find(|p| p.id == id).map(|p| p.label.clone())
            })
            .unwrap_or_else(|| none_label.clone());

        let encoding_options: Vec<String> = [
            "UTF-8", "Big5", "GBK", "gb18030", "Shift_JIS", "EUC-JP", "EUC-KR",
            "ISO-8859-1", "ISO-8859-15", "windows-1251", "windows-1252", "KOI8-R",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let encoding_selected =
            self.prefs.default_encoding.clone().unwrap_or_else(|| "UTF-8".to_string());

        // A labeled pick_list row (label on the leading edge, picker
        // trailing). `label_key` is an i18n key resolved here. Recording
        // wrapper: Left/Right cycle the options from the keyboard.
        let pick_row = |label_key: &'static str,
                        options: Vec<String>,
                        selected: String,
                        on_select: fn(String) -> Message|
         -> Element<'_, Message> {
            self.nav_pick_row(
                crate::i18n::t(label_key),
                options,
                selected,
                |s: &String| s.clone(),
                220.0,
                on_select,
            )
        };

        // The card is long once every default field is shown, so the header
        // doubles as a collapse toggle (chevron points down when open, into
        // the leading edge when collapsed). Hidden fields keep their state.
        let collapsed = self.prefs.defaults_collapsed;
        let chevron = if collapsed {
            if crate::i18n::is_rtl_layout() {
                iced_fonts::lucide::chevron_left()
            } else {
                iced_fonts::lucide::chevron_right()
            }
        } else {
            iced_fonts::lucide::chevron_down()
        };
        let defaults_header = button(
            dir_row(vec![
                column![
                    text(crate::i18n::t("new_connection_defaults"))
                        .size(13)
                        .color(OryxisColors::t().text_primary),
                    Space::new().height(4),
                    text(t("new_connection_defaults_desc"))
                        .size(11)
                        .color(OryxisColors::t().text_muted),
                ]
                .width(Length::Fill)
                .into(),
                Space::new().width(8).into(),
                chevron.size(16).color(OryxisColors::t().text_muted).into(),
            ])
            .align_y(iced::Alignment::Center),
        )
        .on_press(Message::Settings(SettingsMessage::ToggleDefaultsCollapsed))
        .padding(4)
        .width(Length::Fill)
        .style(|_, status| button::Style {
            background: match status {
                BtnStatus::Hovered | BtnStatus::Pressed => Some(Background::Color(
                    iced::Color { a: 0.12, ..OryxisColors::t().accent },
                )),
                _ => None,
            },
            text_color: OryxisColors::t().text_primary,
            border: Border { radius: Radius::from(6.0), ..Default::default() },
            ..Default::default()
        });

        // Enter toggles the collapse from the keyboard, same as clicking
        // the header.
        let defaults_header = self.settings_nav_slot_labeled(
            t("new_connection_defaults"),
            crate::keynav::RowAction::activate(Message::Settings(SettingsMessage::ToggleDefaultsCollapsed)),
            6.0,
            defaults_header.into(),
        );

        let mut new_conn_defaults_col = column![defaults_header];
        if !collapsed {
            new_conn_defaults_col = new_conn_defaults_col
                .push(Space::new().height(10))
                .push(self.nav_toggle_row(crate::i18n::t("forward_ssh_agent"), self.prefs.default_agent_forwarding, Message::Settings(SettingsMessage::ToggleDefaultAgentForwarding)))
                .push(Space::new().height(10))
                .push(dir_row(vec![
                    text(crate::i18n::t("port")).size(13).color(OryxisColors::t().text_secondary).into(),
                    Space::new().width(Length::Fill).into(),
                    self.settings_nav_slot_labeled(
                        t("port"),
                        crate::keynav::RowAction::input(iced::widget::Id::new("set-connection-default-port")),
                        10.0,
                        text_input("22", &self.prefs.default_port)
                            .id(iced::widget::Id::new("set-connection-default-port"))
                            .on_input(|v| Message::Settings(SettingsMessage::DefaultPortChanged(v)))
                            .padding(10).width(120)
                            .style(crate::widgets::rounded_input_style).align_x(dir_align_x()).into(),
                    ),
                ]).align_y(iced::Alignment::Center))
                .push(Space::new().height(10))
                .push(dir_row(vec![
                    text(crate::i18n::t("host_keepalive")).size(13).color(OryxisColors::t().text_secondary).into(),
                    Space::new().width(Length::Fill).into(),
                    self.settings_nav_slot_labeled(
                        t("host_keepalive"),
                        crate::keynav::RowAction::input(iced::widget::Id::new("set-connection-default-keepalive")),
                        10.0,
                        text_input(&self.prefs.keepalive_interval, &self.prefs.default_keepalive)
                            .id(iced::widget::Id::new("set-connection-default-keepalive"))
                            .on_input(|v| Message::Settings(SettingsMessage::DefaultKeepaliveChanged(v)))
                            .padding(10).width(120)
                            .style(crate::widgets::rounded_input_style).align_x(dir_align_x()).into(),
                    ),
                ]).align_y(iced::Alignment::Center))
                .push(Space::new().height(10))
                .push(self.nav_pick_row(
                    crate::i18n::t("host_terminal_type"),
                    term_default_options,
                    self.prefs.default_terminal_type.clone(),
                    |s: &String| s.clone(),
                    200.0,
                    |v| Message::Settings(SettingsMessage::DefaultTerminalTypeChanged(v)),
                ))
                .push(Space::new().height(10))
                .push(dir_row(vec![
                    text(t("username")).size(13).color(OryxisColors::t().text_secondary).into(),
                    Space::new().width(Length::Fill).into(),
                    self.settings_nav_slot_labeled(
                        t("username"),
                        crate::keynav::RowAction::input(iced::widget::Id::new("set-connection-default-username")),
                        10.0,
                        text_input("", &self.prefs.default_username)
                            .id(iced::widget::Id::new("set-connection-default-username"))
                            .on_input(|v| Message::Settings(SettingsMessage::DefaultUsernameChanged(v)))
                            .padding(10).width(220)
                            .style(crate::widgets::rounded_input_style).align_x(dir_align_x()).into(),
                    ),
                ]).align_y(iced::Alignment::Center))
                .push(Space::new().height(10))
                .push(pick_row("auth_method", auth_options, auth_selected, |v| Message::Settings(SettingsMessage::DefaultAuthMethodChanged(v))))
                .push(Space::new().height(10))
                .push(pick_row("identity", identity_options, identity_selected, |v| Message::Settings(SettingsMessage::DefaultIdentityChanged(v))))
                .push(Space::new().height(10))
                .push(pick_row("ssh_key", key_options, key_selected, |v| Message::Settings(SettingsMessage::DefaultKeyChanged(v))))
                .push(Space::new().height(10))
                .push(pick_row("parent_group", group_options, group_selected, |v| Message::Settings(SettingsMessage::DefaultGroupChanged(v))))
                .push(Space::new().height(10))
                .push(pick_row("default_proxy", proxy_options, proxy_selected, |v| Message::Settings(SettingsMessage::DefaultProxyChanged(v))))
                .push(Space::new().height(10))
                .push(self.nav_toggle_row(t("expose_to_mcp"), self.prefs.default_mcp_enabled, Message::Settings(SettingsMessage::ToggleDefaultMcpEnabled)))
                .push(Space::new().height(10))
                .push(pick_row("host_encoding", encoding_options, encoding_selected, |v| Message::Settings(SettingsMessage::DefaultEncodingChanged(v))));

            // Environment-variables list editor, same add/remove/edit-row
            // shape as the host editor's env-vars block. Built here (it
            // only renders while expanded) so the add button records after
            // the rows above it. The per-row inputs and remove buttons are
            // not recorded: the fork's widget ids are static-only, so
            // index-addressed inputs cannot be keyboard-focused.
            let mut env_block = column![dir_row(vec![
                column![
                    text(t("env_vars")).size(13).color(OryxisColors::t().text_secondary),
                    Space::new().height(2),
                    text(t("env_vars_desc")).size(11).color(OryxisColors::t().text_muted),
                ]
                .width(Length::Fill)
                .into(),
                Space::new().width(8).into(),
                self.settings_nav_slot_labeled(
                    t("env_vars"),
                    crate::keynav::RowAction::activate(Message::Settings(SettingsMessage::DefaultAddEnvVar)),
                    4.0,
                    button(text("+").size(14).color(OryxisColors::t().text_primary))
                        .on_press(Message::Settings(SettingsMessage::DefaultAddEnvVar))
                        .style(|_, _| button::Style {
                            background: Some(Background::Color(OryxisColors::t().bg_hover)),
                            border: Border { radius: Radius::from(4.0), ..Default::default() },
                            text_color: OryxisColors::t().text_primary,
                            ..Default::default()
                        })
                        .padding(Padding { top: 2.0, right: 8.0, bottom: 2.0, left: 8.0 })
                        .into(),
                ),
            ])
            .align_y(iced::Alignment::Center)];
            for (i, e) in self.prefs.default_env_vars.iter().enumerate() {
                let idx = i;
                env_block = env_block.push(Space::new().height(8));
                env_block = env_block.push(
                    dir_row(vec![
                        text_input("LC_EXAMPLE", &e.key)
                            .on_input(move |v| Message::Settings(SettingsMessage::DefaultEnvVarKeyChanged(idx, v)))
                            .padding(6)
                            .width(Length::FillPortion(2))
                            .style(crate::widgets::rounded_input_style)
                            .align_x(dir_align_x())
                            .into(),
                        text("=").size(12).color(OryxisColors::t().text_muted).into(),
                        text_input("value", &e.value)
                            .on_input(move |v| Message::Settings(SettingsMessage::DefaultEnvVarValueChanged(idx, v)))
                            .padding(6)
                            .width(Length::FillPortion(3))
                            .style(crate::widgets::rounded_input_style)
                            .align_x(dir_align_x())
                            .into(),
                        button(text("\u{00D7}").size(11).color(OryxisColors::t().error))
                            .on_press(Message::Settings(SettingsMessage::DefaultRemoveEnvVar(idx)))
                            .style(|_, _| button::Style {
                                background: None,
                                border: Border::default(),
                                text_color: OryxisColors::t().error,
                                ..Default::default()
                            })
                            .padding(Padding { top: 2.0, right: 4.0, bottom: 2.0, left: 4.0 })
                            .into(),
                    ])
                    .align_y(iced::Alignment::Center)
                    .spacing(4),
                );
            }
            new_conn_defaults_col = new_conn_defaults_col
                .push(Space::new().height(14))
                .push(env_block);
        }
        let new_conn_defaults_section = panel_section(new_conn_defaults_col);

        // Session behaviour shares one card: keepalive, the
        // auto-reconnect pair and OS detection are all "what happens
        // while connected" knobs, so they live together instead of
        // one box per item.
        let session_section = panel_section(column![
            text(crate::i18n::t("keepalive_interval")).size(13).color(OryxisColors::t().text_primary),
            Space::new().height(4),
            text(t("setting_keepalive_desc"))
                .size(11).color(OryxisColors::t().text_muted),
            Space::new().height(8),
            self.settings_nav_slot_labeled(
                t("keepalive_interval"),
                crate::keynav::RowAction::input(iced::widget::Id::new("set-connection-keepalive")),
                10.0,
                text_input("30", &self.prefs.keepalive_interval)
                    .id(iced::widget::Id::new("set-connection-keepalive"))
                    .on_input(|v| Message::Settings(SettingsMessage::SettingKeepaliveChanged(v)))
                    .padding(10)
                    .width(240)
                    .style(crate::widgets::rounded_input_style).align_x(dir_align_x())
                    .into(),
            ),
            Space::new().height(16),
            // Connection reuse (F2). On by default: it removes a
            // handshake, a key exchange and an authentication from
            // every repeat open, and the failover makes it safe.
            self.nav_toggle_row(
                crate::i18n::t("setting_connection_reuse"),
                self.prefs.ssh_connection_reuse,
                Message::Settings(SettingsMessage::SettingToggleConnectionReuse),
            ),
            Space::new().height(4),
            text(t("setting_connection_reuse_hint"))
                .size(11).color(OryxisColors::t().text_muted),
            Space::new().height(16),
            self.nav_toggle_row(
                crate::i18n::t("auto_reconnect"),
                self.prefs.auto_reconnect,
                Message::Settings(SettingsMessage::SettingToggleAutoReconnect),
            ),
            Space::new().height(4),
            text(t("setting_reconnect_desc"))
                .size(11).color(OryxisColors::t().text_muted),
            Space::new().height(8),
            text(crate::i18n::t("max_reconnect_attempts")).size(12).color(OryxisColors::t().text_secondary),
            Space::new().height(4),
            self.settings_nav_slot_labeled(
                t("max_reconnect_attempts"),
                crate::keynav::RowAction::input(iced::widget::Id::new("set-connection-max-reconnect")),
                10.0,
                text_input("5", &self.prefs.max_reconnect_attempts)
                    .id(iced::widget::Id::new("set-connection-max-reconnect"))
                    .on_input(|v| Message::Settings(SettingsMessage::SettingMaxReconnectChanged(v)))
                    .padding(10)
                    .width(240)
                    .style(crate::widgets::rounded_input_style).align_x(dir_align_x())
                    .into(),
            ),
            Space::new().height(16),
            self.nav_toggle_row(
                crate::i18n::t("os_detection"),
                self.prefs.os_detection,
                Message::Settings(SettingsMessage::SettingToggleOsDetection),
            ),
            Space::new().height(4),
            text(t("setting_os_detect_desc"))
                .size(11).color(OryxisColors::t().text_muted),
        ]);

        scrollable(
            container(
                column![
                    new_conn_defaults_section,
                    Space::new().height(12),
                    session_section,
                    Space::new().height(12),
                    // Login automations live here rather than in a rail
                    // view of their own: they are host configuration, and
                    // the flow that creates them is the host editor.
                    self.login_scripts_section(),
                    Space::new().height(24),
                ]
                .width(Length::Fill)
                .align_x(dir_align_x()),
            )
            .padding(Padding { top: 24.0, right: 24.0, bottom: 24.0, left: 24.0 }),
        )
        // Stable id so the keyboard router can keep the selected row
        // in view.
        .id(iced::widget::Id::new("settings-connection-scroll"))
        .on_scroll(|s| Message::Settings(SettingsMessage::SectionScrolled(s.viewport.relative_offset().y)))
        .height(Length::Fill)
        .into()
    }
}
