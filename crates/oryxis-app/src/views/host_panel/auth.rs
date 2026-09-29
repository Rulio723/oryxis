//! Host editor: the SSH Authentication rows (auth-method picker, key
//! picker, agent forwarding).
use super::*;

impl Oryxis {
    pub(super) fn hp_row_auth_method(&self, is_ssh: bool) -> Element<'_, Message> {
        // Auth method (SSH > Authentication). Left/Right cycle the same
        // options the pick_list offers.
        let mut auth_options = vec![
            t("auth_auto").to_string(),
            t("auth_password").to_string(),
            t("auth_key").to_string(),
        ];
        if crate::util::security_key_method_offered(&self.editor_form.auth_method) {
            auth_options.push(t("auth_security_key").to_string());
        }
        auth_options.extend([
            t("auth_certificate").to_string(),
            t("auth_agent").to_string(),
            t("auth_interactive").to_string(),
            t("auth_password_prompt").to_string(),
        ]);
        let auth_selected = crate::util::auth_method_label(&self.editor_form.auth_method);
        // Focusable select: Tab reaches it, Enter/Space open it, the
        // widget owns arrows/Esc while focused (fork support).
        let row_auth_method: Element<'_, Message> = if is_ssh {
            panel_option_row(
            iced_fonts::lucide::shield(),
            t("auth_method"),
            self.panel_nav_slot(
                crate::keynav::RowAction::input(iced::widget::Id::new("editor-pick-auth-method")),
                crate::widgets::INPUT_RADIUS,
                pick_list(Some(auth_selected), auth_options, |s: &String| s.clone())
                    .on_select(|v| Message::Editor(EditorMessage::EditorAuthMethodChanged(v)))
                    .id(iced::widget::Id::new("editor-pick-auth-method"))
                    .on_open(Message::Navigation(NavigationMessage::PickOpenChanged(true)))
                    .on_close(Message::Navigation(NavigationMessage::PickOpenChanged(false)))
                    // Wider than the usual 120px so the longest option
                    // ("Password (ask...)" and its translations) is not truncated.
                    .width(200)
                    .padding(10)
                    .style(crate::widgets::rounded_pick_list_style)
                    .into(),
            ),
            )
        } else {
            empty()
        };
        row_auth_method
    }

    pub(super) fn hp_ssh_key_row(&self, is_ssh: bool) -> Option<Element<'_, Message>> {
        // Key row (SSH > Authentication): only when Auth Method is `Key`,
        // `SecurityKey`, `Certificate` or `Agent` (the chosen-method's
        // field) and no identity is set (an identity provides its own
        // key). Layout is [key icon] [combo] [+ Key]. Built after the
        // auth-method row so its keyboard rows record right below it,
        // matching the layout. Under `Certificate` the combo lists only
        // keys that carry a certificate (`editor_key_options` filters)
        // and the hint below surfaces the cert's validity; under
        // `SecurityKey` it lists only hardware keys and the hint spells
        // out that nothing else will be offered; under `Agent` the pick
        // is the preferred agent identity (B3: offered first, security
        // keys sorted to the top) with a delegation help line; under
        // `Key` no hint is shown, the method is strictly the bare key.
        let cert_mode = self.editor_form.auth_method == AuthMethod::Certificate;
        let agent_mode = self.editor_form.auth_method == AuthMethod::Agent;
        let hardware_mode = self.editor_form.auth_method == AuthMethod::SecurityKey;
        let ssh_key_row: Option<Element<'_, Message>> = if is_ssh
            && self.editor_form.selected_identity.is_none()
            && (self.editor_form.auth_method == AuthMethod::Key
                || cert_mode
                || agent_mode
                || hardware_mode)
        {
            // "+ Key" is clickable, opens the existing key import panel;
            // under `Certificate` it reads "+ Certificate" and lands with
            // the cert field focused, since that is the missing piece the
            // user came for.
            let (add_key_msg, add_key_label) = if cert_mode {
                (Message::Keys(KeysMessage::ShowKeyPanelCertFocus), t("add_certificate_btn"))
            } else {
                (Message::Keys(KeysMessage::ShowKeyPanel), t("add_key_btn"))
            };
            let add_key_btn = self.panel_nav_slot(
                crate::keynav::RowAction::activate(add_key_msg.clone()),
                6.0,
                button(
                    text(add_key_label).size(12).color(OryxisColors::t().accent),
                )
                .on_press(add_key_msg)
                .padding(Padding { top: 4.0, right: 8.0, bottom: 4.0, left: 8.0 })
                .style(|_, status| {
                    let bg = match status {
                        BtnStatus::Hovered => Color { a: 0.1, ..OryxisColors::t().accent },
                        _ => Color::TRANSPARENT,
                    };
                    button::Style {
                        background: Some(Background::Color(bg)),
                        border: Border { radius: Radius::from(6.0), ..Default::default() },
                        ..Default::default()
                    }
                })
                .into(),
            );
            // Forced-selection searchable key combo (same pattern as the
            // startup combo): options + clear-on-focus built in
            // `rebuild_editor_combos` / `EditorKeyComboOpened`.
            let key_selected = self
                .editor_form
                .selected_key
                .clone()
                .unwrap_or_else(|| "(none)".into());
            // Keyboard row: Left/Right cycle the saved keys (the combo
            // itself cannot be focused by id in the fork).
            let (key_prev, key_next) = crate::keynav::slots::cycle_pair(
                self.editor_key_combo.options(),
                &key_selected,
                |v| Message::Editor(EditorMessage::EditorKeyChanged(v)),
            );
            let key_combo: Element<'_, Message> = self.panel_nav_slot(
                crate::keynav::RowAction::picker(key_prev, key_next),
                10.0,
                iced::widget::combo_box(
                    &self.editor_key_combo,
                    // Owned placeholder: post-refactor it is an 'a
                    // fragment, and this String is frame-local. The
                    // selection stays a borrow (cloned by the widget).
                    key_selected.clone(),
                    Some(&key_selected),
                    |v| Message::Editor(EditorMessage::EditorKeyChanged(v)),
                )
                .on_open(Message::Editor(EditorMessage::EditorKeyComboOpened))
                // Blur has to put the COMMITTED pick back in the box.
                // The fork restores it inside the `on_close` arm only
                // (`combo_box::update`), so a combo without one keeps
                // showing text that was typed and never selected, and
                // the host then saves with the key the form still
                // holds. Nothing to handle, the restore is the point.
                .on_close(Message::NoOp)
                .padding(10)
                .input_style(crate::widgets::rounded_input_style)
                .menu_style(crate::widgets::combo_menu_style)
                .width(Length::Fill)
                .into(),
            );
            let key_row = dir_row(vec![
                iced_fonts::lucide::key_round()
                    .size(13)
                    .color(OryxisColors::t().text_muted)
                    .into(),
                Space::new().width(10).into(),
                key_combo,
                Space::new().width(8).into(),
                add_key_btn,
            ])
            .align_y(iced::Alignment::Center);

            // Certificate hint (B2.1): only under the `Certificate`
            // method, where the cert is what actually authenticates.
            // Three states: the selected key's cert with its validity
            // (warning color if expired), a stale selection whose cert
            // was removed since, or an empty filtered list (no key in
            // the vault carries a cert yet). Under `Agent` (B3) the row
            // explains the preferred-identity pick and how hardware keys
            // reach the agent (FIDO2 / PKCS#11 delegation). Under
            // `SecurityKey` it states that nothing but the token is
            // offered and, when no signable hardware key is in the vault,
            // which file to import to get one.
            let cert_hint: Option<Element<'_, Message>> = if agent_mode {
                Some(
                    iced::widget::Column::new()
                        .push(
                            container(
                                text(t("preferred_agent_key"))
                                    .size(11)
                                    .color(OryxisColors::t().text_muted),
                            )
                            .width(Length::Fill)
                            .align_x(dir_align_x()),
                        )
                        .push(Space::new().height(2))
                        .push(
                            container(
                                text(t("pkcs11_help"))
                                    .size(11)
                                    .color(OryxisColors::t().text_muted),
                            )
                            .width(Length::Fill)
                            .align_x(dir_align_x()),
                        )
                        .width(Length::Fill)
                        .into(),
                )
            } else if hardware_mode {
                // The hardware-only mode has one failure shape the user
                // cannot see from an empty combo: a security key that is
                // in the vault but carries only its public half (a B3
                // import, or one pulled from a peer) cannot be signed
                // with, so the pick list stays empty and the reason has
                // to be on screen. Naming the file to import is the whole
                // fix, so the hint says which one.
                // A `_sk` file picked up from `~/.ssh` counts as well: the
                // hint is about having SOMETHING the token can sign with.
                let signable = self
                    .keys
                    .iter()
                    .any(|k| k.algorithm.is_security_key() && k.has_private)
                    || matches!(
                        self.editor_form.disk_key_status,
                        oryxis_vault::DiskKeyStatus::Ready { .. }
                    );
                let mut col = iced::widget::Column::new();
                if !oryxis_ssh::sk::native_signing_supported() {
                    // A host synced from a machine that can drive a token,
                    // opened on one that cannot: say so rather than let the
                    // connect fail with a transport error.
                    col = col
                        .push(
                            container(
                                text(t("security_key_unsupported_platform"))
                                    .size(11)
                                    .color(OryxisColors::t().warning),
                            )
                            .width(Length::Fill)
                            .align_x(dir_align_x()),
                        )
                        .push(Space::new().height(2));
                } else if !signable {
                    col = col
                        .push(
                            container(
                                text(t("security_key_none_imported"))
                                    .size(11)
                                    .color(OryxisColors::t().warning),
                            )
                            .width(Length::Fill)
                            .align_x(dir_align_x()),
                        )
                        .push(Space::new().height(2));
                }
                Some(
                    col.push(
                        container(
                            text(t("security_key_help"))
                                .size(11)
                                .color(OryxisColors::t().text_muted),
                        )
                        .width(Length::Fill)
                        .align_x(dir_align_x()),
                    )
                    .width(Length::Fill)
                    .into(),
                )
            } else if !cert_mode {
                None
            } else if !self.keys.iter().any(|k| k.certificate.is_some())
                // A disk key with its `<key>-cert.pub` sibling is a
                // certificate this host can offer, so the "no key in
                // the vault carries one" warning would contradict the
                // disk block right below it.
                && !matches!(
                    self.editor_form.disk_key_status,
                    oryxis_vault::DiskKeyStatus::Ready { certificate: true, .. }
                )
            {
                Some(
                    container(
                        text(t("cert_no_keys_hint")).size(11).color(OryxisColors::t().warning),
                    )
                    .width(Length::Fill)
                    .align_x(dir_align_x())
                    .into(),
                )
            } else {
                let selected = self.keys.iter().find(|k| k.label == key_selected);
                match selected.and_then(|k| k.certificate.as_deref()) {
                    Some(line) => ssh_key::Certificate::from_openssh(line.trim()).ok().map(
                        |cert| {
                            let now = chrono::Utc::now().timestamp().max(0) as u64;
                            let expired = cert.valid_before() != 0
                                && cert.valid_before() != u64::MAX
                                && now > cert.valid_before();
                            let until = match chrono::DateTime::<chrono::Utc>::from_timestamp(
                                cert.valid_before().min(i64::MAX as u64) as i64,
                                0,
                            ) {
                                Some(dt)
                                    if cert.valid_before() != 0
                                        && cert.valid_before() != u64::MAX =>
                                {
                                    dt.with_timezone(&chrono::Local)
                                        .format("%Y-%m-%d")
                                        .to_string()
                                }
                                _ => String::new(),
                            };
                            let (label, color) = if expired {
                                (
                                    format!("{} · {}", t("cert_attach"), t("cert_expired")),
                                    OryxisColors::t().warning,
                                )
                            } else if until.is_empty() {
                                (t("cert_attach").to_string(), OryxisColors::t().text_muted)
                            } else {
                                (
                                    format!(
                                        "{} · {} {}",
                                        t("cert_attach"),
                                        t("cert_valid_until"),
                                        until
                                    ),
                                    OryxisColors::t().text_muted,
                                )
                            };
                            container(text(label).size(11).color(color))
                                .width(Length::Fill)
                                .align_x(dir_align_x())
                                .into()
                        },
                    ),
                    // A selected key without a cert (removed after this
                    // host was saved): warn instead of failing silently
                    // at connect time.
                    None if selected.is_some() => Some(
                        container(
                            text(t("cert_key_no_cert_hint"))
                                .size(11)
                                .color(OryxisColors::t().warning),
                        )
                        .width(Length::Fill)
                        .align_x(dir_align_x())
                        .into(),
                    ),
                    None => None,
                }
            };

            let mut col = iced::widget::Column::new()
                .push(key_row)
                .width(Length::Fill)
                .align_x(dir_align_x());
            if let Some(hint) = cert_hint {
                col = col.push(Space::new().height(4)).push(hint);
            }
            Some(col.into())
        } else {
            None
        };
        ssh_key_row
    }

    /// The disk key source (SSH > Authentication): the opt-in toggle,
    /// the `IdentityFile` path it reads, and what that currently
    /// resolves to.
    ///
    /// Shown for the methods that offer a key at all (`Key` / `Auto` /
    /// `Certificate` / `SecurityKey`, the gate `resolve_credentials`
    /// applies), and
    /// not under `Agent`, whose key lives in the agent process. Under
    /// `SecurityKey` the scan reads only the `_sk` files
    /// (`connect_methods::disk_key_wanted`). It sits below the vault-key
    /// picker because that is the precedence: the disk fills the gap the
    /// vault leaves, never the other way round.
    ///
    /// The status line is the half that matters. A key that is present
    /// but unusable (passphrase-protected, most often) used to be
    /// indistinguishable from no key at all, which is the failure this
    /// whole source exists to end, so the hint names the file and the
    /// obstacle rather than just going quiet.
    pub(super) fn hp_disk_key_block(&self, is_ssh: bool) -> Element<'_, Message> {
        use oryxis_vault::DiskKeyStatus as St;
        let cert_mode = self.editor_form.auth_method == AuthMethod::Certificate;
        let offers_key = matches!(
            self.editor_form.auth_method,
            AuthMethod::Key | AuthMethod::Auto | AuthMethod::Certificate | AuthMethod::SecurityKey
        );
        if !is_ssh || !offers_key || self.editor_form.selected_identity.is_some() {
            return empty();
        }
        let mut items = iced::widget::Column::new().push(self.panel_nav_slot(
            crate::keynav::RowAction::activate(Message::Editor(
                EditorMessage::EditorUseDiskKeyToggled
            )),
            8.0,
            container(
                dir_row(vec![
                    iced_fonts::lucide::file_key()
                        .size(13)
                        .color(OryxisColors::t().text_muted)
                        .into(),
                    Space::new().width(10).into(),
                    text(t("use_disk_key"))
                        .size(13)
                        .color(OryxisColors::t().text_secondary)
                        .into(),
                    Space::new().width(Length::Fill).into(),
                    {
                        let on = self.editor_form.use_disk_key;
                        let bg = if on {
                            OryxisColors::t().success
                        } else {
                            OryxisColors::t().bg_hover
                        };
                        let fg = crate::theme::contrast_text_for(bg);
                        button(
                            text(if on {
                                crate::i18n::t("toggle_on")
                            } else {
                                crate::i18n::t("toggle_off")
                            })
                            .size(12)
                            .color(fg),
                        )
                        .on_press(Message::Editor(EditorMessage::EditorUseDiskKeyToggled))
                        .style(move |_theme, _status| button::Style {
                            background: Some(Background::Color(bg)),
                            border: Border {
                                radius: Radius::from(4.0),
                                ..Default::default()
                            },
                            text_color: fg,
                            ..Default::default()
                        })
                        .into()
                    },
                ])
                .align_y(iced::Alignment::Center)
            )
            .padding(Padding {
                top: 8.0,
                right: 0.0,
                bottom: 8.0,
                left: 0.0,
            })
            .into(),
        ));
        if !self.editor_form.use_disk_key {
            return items.into();
        }
        // Keyboard rows: the field first (Tab focuses the input by id),
        // then Browse as its own stop, matching the visual order.
        self.panel_nav_record(crate::keynav::RowAction::input(iced::widget::Id::new(
            "editor-identity-file",
        )));
        let browse = self.panel_nav_slot(
            crate::keynav::RowAction::activate(Message::Editor(
                EditorMessage::EditorBrowseIdentityFile,
            )),
            6.0,
            button(
                text(t("browse"))
                    .size(12)
                    .color(OryxisColors::t().accent),
            )
            .on_press(Message::Editor(EditorMessage::EditorBrowseIdentityFile))
            .padding(Padding {
                top: 4.0,
                right: 8.0,
                bottom: 4.0,
                left: 8.0,
            })
            .style(|_, status| {
                let bg = match status {
                    BtnStatus::Hovered => Color {
                        a: 0.1,
                        ..OryxisColors::t().accent
                    },
                    _ => Color::TRANSPARENT,
                };
                button::Style {
                    background: Some(Background::Color(bg)),
                    border: Border {
                        radius: Radius::from(6.0),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            })
            .into(),
        );
        items = items.push(
            dir_row(vec![
                Space::new().width(23).into(),
                text_input(t("disk_key_path"), &self.editor_form.identity_file)
                    .id(iced::widget::Id::new("editor-identity-file"))
                    .on_input(|v| Message::Editor(EditorMessage::EditorIdentityFileChanged(v)))
                    .on_submit_maybe(self.hp_submit())
                    .padding(10)
                    .style(crate::widgets::rounded_input_style)
                    .align_x(dir_align_x())
                    .into(),
                Space::new().width(8).into(),
                browse,
            ])
            .align_y(iced::Alignment::Center),
        );
        let (hint, color) = match &self.editor_form.disk_key_status {
            // The toggle is on, so `Off` cannot happen here; treat it
            // like "nothing resolved" rather than inventing a state.
            St::Off | St::NotFound => (
                t("disk_key_none").to_string(),
                OryxisColors::t().text_muted,
            ),
            // Under `Certificate` the certificate IS the credential, so
            // a key without its `<key>-cert.pub` sibling resolves fine
            // and still cannot authenticate. Saying "will use it" there
            // would be the same silent dead end this source exists to
            // remove.
            St::Ready { path, certificate } if cert_mode && !certificate => (
                t("disk_key_no_cert").replace("{path}", path),
                OryxisColors::t().warning,
            ),
            St::Ready { path, .. } => (
                t("disk_key_using").replace("{path}", path),
                OryxisColors::t().text_muted,
            ),
            St::Encrypted(path) => (
                t("disk_key_locked").replace("{path}", path),
                OryxisColors::t().warning,
            ),
            St::Unreadable(path, err) | St::Unusable(path, err) => (
                t("disk_key_problem")
                    .replace("{path}", path)
                    .replace("{error}", err),
                OryxisColors::t().warning,
            ),
        };
        items = items
            .push(Space::new().height(4))
            .push(
                container(text(hint).size(11).color(color))
                    .width(Length::Fill)
                    .align_x(dir_align_x()),
            )
            .push(Space::new().height(2))
            .push(
                container(
                    text(t("disk_key_help"))
                        .size(11)
                        .color(OryxisColors::t().text_muted),
                )
                .width(Length::Fill)
                .align_x(dir_align_x()),
            );
        items.into()
    }

    pub(super) fn hp_row_agent_fwd(&self, is_ssh: bool) -> Element<'_, Message> {
        // Agent forwarding (SSH > Authentication). `share` (not the key
        // glyph) so it doesn't read as a duplicate of the Key row above.
        let row_agent_fwd: Element<'_, Message> = if is_ssh {
            self.panel_nav_slot(
            crate::keynav::RowAction::activate(Message::Editor(EditorMessage::EditorToggleAgentForwarding)),
            8.0,
            container(
                dir_row(vec![
                    iced_fonts::lucide::share().size(14).color(OryxisColors::t().text_muted).into(),
                    Space::new().width(10).into(),
                    text(t("forward_ssh_agent")).size(13).color(OryxisColors::t().text_secondary).into(),
                    Space::new().width(Length::Fill).into(),
                    {
                        let on = self.editor_form.agent_forwarding;
                        let bg = if on { OryxisColors::t().success } else { OryxisColors::t().bg_hover };
                        let fg = crate::theme::contrast_text_for(bg);
                        button(text(if on { crate::i18n::t("toggle_on") } else { crate::i18n::t("toggle_off") }).size(12).color(fg))
                            .on_press(Message::Editor(EditorMessage::EditorToggleAgentForwarding))
                            .style(move |_theme, _status| button::Style {
                                background: Some(Background::Color(bg)),
                                border: Border { radius: Radius::from(4.0), ..Default::default() },
                                text_color: fg,
                                ..Default::default()
                            })
                            .into()
                    },
                ]).align_y(iced::Alignment::Center)
            )
            .padding(Padding { top: 8.0, right: 0.0, bottom: 8.0, left: 0.0 }).into(),
            )
        } else {
            empty()
        };
        row_agent_fwd
    }

    pub(super) fn hp_row_x11_fwd(&self, is_ssh: bool) -> Element<'_, Message> {
        // X11 forwarding (SSH > Authentication), directly under agent
        // forwarding: both are channel requests sent before the shell
        // starts, and users look for them together.
        let row_x11_fwd: Element<'_, Message> = if is_ssh {
            self.panel_nav_slot(
            crate::keynav::RowAction::activate(Message::Editor(EditorMessage::EditorToggleX11Forwarding)),
            8.0,
            container(
                dir_row(vec![
                    iced_fonts::lucide::monitor().size(14).color(OryxisColors::t().text_muted).into(),
                    Space::new().width(10).into(),
                    text(t("forward_x11")).size(13).color(OryxisColors::t().text_secondary).into(),
                    Space::new().width(Length::Fill).into(),
                    {
                        let on = self.editor_form.x11_forwarding;
                        let bg = if on { OryxisColors::t().success } else { OryxisColors::t().bg_hover };
                        let fg = crate::theme::contrast_text_for(bg);
                        button(text(if on { crate::i18n::t("toggle_on") } else { crate::i18n::t("toggle_off") }).size(12).color(fg))
                            .on_press(Message::Editor(EditorMessage::EditorToggleX11Forwarding))
                            .style(move |_theme, _status| button::Style {
                                background: Some(Background::Color(bg)),
                                border: Border { radius: Radius::from(4.0), ..Default::default() },
                                text_color: fg,
                                ..Default::default()
                            })
                            .into()
                    },
                ]).align_y(iced::Alignment::Center)
            )
            .padding(Padding { top: 8.0, right: 0.0, bottom: 8.0, left: 0.0 }).into(),
            )
        } else {
            empty()
        };
        row_x11_fwd
    }
}
