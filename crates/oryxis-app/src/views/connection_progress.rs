//! Connection progress screen (shown while connecting to SSH) with host-key
//! verification dialog inline.

use iced::alignment::Horizontal;
use iced::border::Radius;
use iced::widget::{button, column, container, pick_list, row, scrollable, text, text_input, Space};
use iced::{Background, Border, Color, Element, Length, Padding};

use crate::app::{SshMessage, Message, Oryxis};
use crate::state::ConnectionStep;
use crate::theme::OryxisColors;

/// Tone of a timeline step, telling the story at a glance: kickoff and
/// network work ride the accent, the secured channel and an accepted
/// login read as success, credentials-in-flight as warning. Errors are
/// resolved by the caller (they override the step's own tone).
fn step_color(step: ConnectionStep) -> Color {
    match step {
        ConnectionStep::Starting
        | ConnectionStep::Connecting
        | ConnectionStep::OpeningSession => OryxisColors::t().accent,
        ConnectionStep::Handshake | ConnectionStep::Authenticated => OryxisColors::t().success,
        ConnectionStep::Authenticating => OryxisColors::t().warning,
    }
}

/// Glyph inside a timeline node disc: what this line was DOING, one
/// icon per step so adjacent lines never repeat a symbol (kickoff,
/// dialing, secured channel, credentials, accepted login, PTY setup).
fn step_glyph(step: ConnectionStep, color: Color) -> Element<'static, Message> {
    match step {
        ConnectionStep::Starting => iced_fonts::lucide::play().size(15).color(color).into(),
        ConnectionStep::Connecting => iced_fonts::lucide::plug().size(15).color(color).into(),
        ConnectionStep::Handshake => {
            iced_fonts::lucide::shield_check().size(15).color(color).into()
        }
        ConnectionStep::Authenticating => {
            iced_fonts::lucide::key_round().size(15).color(color).into()
        }
        ConnectionStep::Authenticated => iced_fonts::lucide::check().size(15).color(color).into(),
        ConnectionStep::OpeningSession => {
            iced_fonts::lucide::terminal().size(15).color(color).into()
        }
    }
}

impl Oryxis {
    /// Resolve the `Connection` a progress screen is connecting to. Saved
    /// hosts resolve by stored index first (set at connect time), guarded
    /// by a label check so a reordered list can't grab the wrong host,
    /// then fall back to a label search. Quick connects resolve straight
    /// from the ephemeral store.
    fn progress_connection(
        &self,
        progress: &crate::state::ConnectionProgress,
    ) -> Option<&oryxis_core::models::Connection> {
        match progress.origin {
            crate::state::ProgressOrigin::Saved(id) => self
                .connections
                .iter()
                .find(|c| c.id == id)
                .or_else(|| self.connections.iter().find(|c| c.label == progress.label)),
            crate::state::ProgressOrigin::Quick(id) => {
                self.quick_connects.get(&id).map(|e| &e.conn)
            }
        }
    }

    /// Whether Privacy Mode applies to this progress screen at all,
    /// before the reveal toggle. The resolved connection's per-host
    /// override wins; an unresolvable one falls back to the global
    /// setting. Also gates the eye toggle in the header.
    fn progress_privacy_on(&self, progress: &crate::state::ConnectionProgress) -> bool {
        self.progress_connection(progress)
            .map(|c| self.privacy_active(c))
            .unwrap_or_else(|| self.privacy_global_active())
    }

    /// Redact a connection-progress string under Privacy Mode. The text is
    /// our own controlled format ("Connecting to <host>...", `SSH host:port`),
    /// so on top of the generic IP / `user@host` masking we also replace this
    /// host's known hostname / username literally, which catches plain DNS
    /// names the regex can't. Returns the input unchanged when off or while
    /// the eye toggle reveals.
    fn redact_progress(
        &self,
        progress: &crate::state::ConnectionProgress,
        s: &str,
    ) -> String {
        if !self.progress_privacy_on(progress) || self.privacy.revealed {
            return s.to_string();
        }
        let conn = self.progress_connection(progress);
        let mut out = crate::widgets::redact_for_display(s, &self.privacy_terms(), self.privacy_classes());
        if let Some(c) = conn {
            if !c.hostname.is_empty() {
                out = out.replace(&c.hostname, &crate::widgets::mask_blocks(&c.hostname));
            }
            if let Some(u) = c.username.as_deref().filter(|u| !u.is_empty()) {
                out = out.replace(u, &crate::widgets::mask_blocks(u));
            }
            // The route-context log line names the proxy endpoint, whose
            // DNS hostname the generic regex can't catch. Resolve it the
            // same way the connect does: identity reference wins over the
            // inline config.
            let proxy_host = c
                .proxy_identity_id
                .and_then(|pid| self.proxy_identities.iter().find(|p| p.id == pid))
                .map(|p| p.host.as_str())
                .or(c.proxy.as_ref().map(|p| p.host.as_str()));
            if let Some(h) = proxy_host.filter(|h| !h.is_empty()) {
                out = out.replace(h, &crate::widgets::mask_blocks(h));
            }
        }
        out
    }

    /// Whether this frame's card owns the modal key layer, and so
    /// records its rows. Read once per frame: a card under a dialog,
    /// a menu or one of its own prompts leaves the recording to them.
    fn progress_keys_owned(&self) -> bool {
        matches!(
            self.modal_nav_surface(),
            Some((crate::keynav::ModalSurface::ConnectProgress, _))
        )
    }

    /// One of the card's buttons as a keyboard row, in display order;
    /// the plain button when the card does not own the keys this frame.
    fn progress_slot<'a>(
        &self,
        owned: bool,
        msg: Message,
        radius: f32,
        contrast: bool,
        el: Element<'a, Message>,
    ) -> Element<'a, Message> {
        if owned {
            self.modal_nav_slot(crate::keynav::RowAction::activate(msg), radius, contrast, el)
        } else {
            el
        }
    }

    pub(crate) fn view_connection_progress(&self) -> Element<'_, Message> {
        let progress = match &self.connecting {
            Some(p) => p,
            None => return Space::new().into(),
        };
        // Keyboard rows (issue #52 convention), recorded in DISPLAY order
        // and with NO default row: the card appears by itself, so only a
        // row the keyboard ringed may act (`handle_modal_nav_key`).
        let owned = self.progress_keys_owned();
        if owned {
            self.modal_nav_reset();
        }

        let failed = progress.failed;

        // Header: host badge mirrors the configured icon for this host
        // (per-host custom icon/color + shape from the icon_style setting),
        // falling back to the detected OS brand. "Edit Host" lives here on
        // the trailing edge when failed, freeing the bottom action row.
        // The badge stayed teal before because a missing match collapsed
        // every field to None and the brand color never resolved.
        let conn = self.progress_connection(progress);
        let badge_style = crate::widgets::resolve_host_icon_style(
            conn.and_then(|c| c.icon_style.as_deref()),
            &self.prefs.default_host_icon,
        );
        // Two-step color, mirroring the dashboard host card: resolve the
        // brand color from detected OS / custom icon, then let an explicit
        // custom_color / legacy color hex override it.
        let (glyph, icon_color) = crate::os_icon::resolve_for(
            conn.and_then(|c| c.detected_os.as_deref()),
            conn.and_then(|c| c.custom_icon.as_deref()),
            conn.and_then(|c| c.custom_color.as_deref()),
            conn.and_then(|c| c.username.as_deref()),
            OryxisColors::t().accent,
        );
        let badge_color = conn
            .and_then(|c| c.custom_color.as_deref().or(c.color.as_deref()))
            .and_then(crate::widgets::parse_hex_color)
            .unwrap_or(icon_color);
        let glyph_el: Element<'_, Message> = glyph.view(20.0, Color::WHITE);
        let badge = crate::widgets::host_icon(badge_style, badge_color, &progress.label, Some(glyph_el), 40.0);

        let mut header_children: Vec<Element<'_, Message>> = vec![
            badge,
            Space::new().width(14).into(),
            column![
                // A quick-connect label embeds `user@host`, so the label
                // is redacted like every other string on this screen.
                text(self.redact_progress(progress, &progress.label))
                    .size(16).color(OryxisColors::t().text_primary),
                Space::new().height(2),
                text(self.redact_progress(progress, &progress.hostname))
                    .size(12).color(OryxisColors::t().text_muted),
            ]
            .width(Length::Fill)
            .align_x(crate::widgets::dir_align_x())
            .into(),
        ];
        if self.progress_privacy_on(progress) {
            // Same eye affordance as Logs / Known Hosts, so the masked
            // header and host-key prompt can be revealed in place.
            header_children.push(self.progress_slot(
                owned,
                Message::TogglePrivacyReveal,
                6.0,
                false,
                crate::widgets::privacy_reveal_btn(self.privacy.revealed),
            ));
        }
        // Saved hosts offer Edit only once the connect failed (the card
        // resolves in seconds and the host has a permanent editor on its
        // dashboard card). A quick connect offers it in EVERY state: the
        // ad-hoc host exists nowhere else, so mid-prompt is exactly when
        // a typo'd user/port needs fixing; the handler cancels the
        // in-flight attempt and opens the temporary-host edit flow.
        let is_quick_origin =
            matches!(progress.origin, crate::state::ProgressOrigin::Quick(_));
        if failed || is_quick_origin {
            if self.progress_privacy_on(progress) {
                header_children.push(Space::new().width(8).into());
            }
            let edit_btn: Element<'_, Message> = button(
                container(text(crate::i18n::t("edit_host")).size(13).color(OryxisColors::t().text_primary))
                    .padding(Padding { top: 8.0, right: 16.0, bottom: 8.0, left: 16.0 }),
            )
            .on_press(Message::Ssh(SshMessage::SshEditFromProgress))
            .style(|_, status| button::Style {
                background: Some(Background::Color(match status {
                    button::Status::Hovered | button::Status::Pressed => OryxisColors::t().bg_hover,
                    _ => OryxisColors::t().bg_surface,
                })),
                border: Border { radius: Radius::from(8.0), ..Default::default() },
                ..Default::default()
            })
            .into();
            header_children.push(self.progress_slot(
                owned,
                Message::Ssh(SshMessage::SshEditFromProgress),
                8.0,
                false,
                edit_btn,
            ));
        }

        let header = container(crate::widgets::dir_row(header_children).align_y(iced::Alignment::Center))
            .padding(Padding { top: 24.0, right: 0.0, bottom: 16.0, left: 0.0 });

        // Pre-auth banner (RFC 4252 §5.4): legal notices / MFA
        // instructions the server sent before authentication. Rendered
        // across every branch, it matters most while the KBI prompt is
        // up, and passes the same Privacy Mode redaction as the rest of
        // the screen. Long legal banners scroll inside a capped box.
        let banner_block: Element<'_, Message> = match &progress.banner {
            Some(banner) => {
                let body = self.redact_progress(progress, banner);
                // No `max_height` on this fork's Container: derive the box
                // height from the line count and cap it, so a one-line
                // banner stays a chip and a legal wall scrolls at 140 px.
                let box_h = (body.lines().count() as f32 * 17.0 + 22.0).min(140.0);
                column![
                    Space::new().height(10),
                    container(
                        iced::widget::scrollable(
                            text(body)
                                .size(12)
                                .color(OryxisColors::t().text_secondary),
                        )
                        .width(Length::Fill),
                    )
                    .height(Length::Fixed(box_h))
                    .width(Length::Fill)
                    .padding(10)
                    .style(|_| container::Style {
                        background: Some(Background::Color(OryxisColors::t().bg_surface)),
                        border: Border {
                            radius: Radius::from(8.0),
                            color: OryxisColors::t().border,
                            width: 1.0,
                        },
                        ..Default::default()
                    }),
                ]
                .into()
            }
            None => Space::new().into(),
        };

        // What a command proxy said while this dial was pending (issue
        // #223): login instructions, a browser URL, "credentials expired,
        // refreshing". Every line is SHOWN, but only a URL from the
        // proxy's STDERR (the local process the user approved) becomes a
        // button: a line before the SSH banner may be the remote server's
        // own, relayed by a proxy like `nc %h %p`. Each button names the
        // host it opens and acts only on a click. Built here, right after
        // the banner, so its link rows are recorded in display order.
        let proxy_block: Element<'_, Message> = if progress.proxy_output.is_empty() {
            Space::new().into()
        } else {
            let joined = progress
                .proxy_output
                .iter()
                .map(|l| l.text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let body = self.redact_progress(progress, &joined);
            let box_h = (body.lines().count() as f32 * 17.0 + 22.0).min(140.0);
            let mut links: Vec<Element<'_, Message>> = Vec::new();
            for url in proxy_output_urls(&progress.proxy_output) {
                let label = crate::i18n::t("proxy_open_link_host")
                    .replace("{host}", &url_host_label(&url));
                let msg = Message::OpenUrl(url);
                let btn = crate::widgets::styled_button_owned(
                    label,
                    Some(msg.clone()),
                    OryxisColors::t().accent,
                );
                links.push(self.progress_slot(owned, msg, 8.0, true, btn));
            }
            let mut col = column![
                Space::new().height(10),
                text(crate::i18n::t("proxy_output_title"))
                    .size(11)
                    .color(OryxisColors::t().text_muted),
                Space::new().height(4),
                container(
                    iced::widget::scrollable(
                        text(body)
                            .size(12)
                            .font(iced::Font::MONOSPACE)
                            .color(OryxisColors::t().text_secondary),
                    )
                    .width(Length::Fill),
                )
                .height(Length::Fixed(box_h))
                .width(Length::Fill)
                .padding(10)
                .style(|_| container::Style {
                    background: Some(Background::Color(OryxisColors::t().bg_surface)),
                    border: Border {
                        radius: Radius::from(8.0),
                        color: OryxisColors::t().border,
                        width: 1.0,
                    },
                    ..Default::default()
                }),
            ];
            if !links.is_empty() {
                col = col.push(Space::new().height(8));
                col = col.push(crate::widgets::dir_row(links).spacing(8));
            }
            col.into()
        };

        // Pulse for the in-flight timeline node while still connecting.
        // Triangular wave 0 -> 1 -> 0 over ~800 ms, driven by the 100 ms
        // connect_anim_tick subscription (only alive while connecting).
        let tick = self.connect_anim_tick;
        let phase = ((tick % 8) as f32) / 8.0;
        let pulse = if phase < 0.5 { phase * 2.0 } else { (1.0 - phase) * 2.0 };

        // A batch connect still owes dials (issue #230): say how many and
        // offer to drop them, in every state of the card, so a batch of
        // thirty hosts can be stopped without sitting through each one.
        // The dial on screen stays the user's to finish or close. Built
        // here, ahead of the action row it sits above, so its keyboard
        // row is recorded in display order.
        let batch_row: Option<Element<'_, Message>> = (!self.batch_dials.is_empty()).then(|| {
            let queued = text(
                crate::i18n::t("batch_connect_queued")
                    .replace("{hosts}", &crate::i18n::host_count(self.batch_dials.len())),
            )
            .size(12)
            .color(OryxisColors::t().text_muted);
            let cancel_msg = Message::Tabs(crate::app::TabsMessage::BatchConnectCancelRemaining);
            let cancel = self.progress_slot(
                owned,
                cancel_msg.clone(),
                8.0,
                false,
                crate::widgets::styled_button(
                    crate::i18n::t("batch_connect_cancel_remaining"),
                    cancel_msg,
                    OryxisColors::t().bg_hover,
                ),
            );
            crate::widgets::dir_row(vec![queued.into(), Space::new().width(Length::Fill).into(), cancel])
                .align_y(iced::Alignment::Center)
                .into()
        });

        // Host key verification or normal status/log timeline.
        let (status_widget, body_widget, bottom): (
            Element<'_, Message>,
            Element<'_, Message>,
            Element<'_, Message>,
        ) = if let Some(ref legacy) = self.pending_legacy_algo {
            // Server speaks only legacy algorithms in some category. Offer
            // to enable them (weaker) or cancel.
            // A quick-connect host resolves from the ephemeral store; it
            // also has nothing to persist, so the "always" button hides.
            let is_quick = self.quick_connects.contains_key(&legacy.conn_id)
                && !self.connections.iter().any(|c| c.id == legacy.conn_id);
            let host_label = self
                .connections
                .iter()
                .find(|c| c.id == legacy.conn_id)
                .or_else(|| self.quick_connects.get(&legacy.conn_id).map(|e| &e.conn))
                .map(|c| c.label.clone())
                .unwrap_or_default();
            let cat_key = match legacy.category {
                oryxis_ssh::NegCategory::Cipher => "algo_ciphers",
                oryxis_ssh::NegCategory::Kex => "algo_kex",
                oryxis_ssh::NegCategory::Mac => "algo_macs",
                oryxis_ssh::NegCategory::HostKey => "algo_host_keys",
            };
            let status: Element<'_, Message> = text(crate::i18n::t("legacy_algo_title"))
                .size(14)
                .color(OryxisColors::t().warning)
                .into();
            // Redacted: a quick-connect label embeds `user@host`.
            let desc = crate::i18n::t("legacy_algo_desc")
                .replace("{host}", &self.redact_progress(progress, &host_label))
                .replace("{category}", crate::i18n::t(cat_key));
            let mut body_col = column![
                text(desc).size(13).color(OryxisColors::t().text_secondary),
                Space::new().height(10),
                text(crate::i18n::t("legacy_algo_offers"))
                    .size(12)
                    .color(OryxisColors::t().text_muted),
                Space::new().height(4),
            ];
            for off in &legacy.server_offers {
                body_col = body_col.push(
                    text(format!("  {off}")).size(12).color(OryxisColors::t().text_primary),
                );
            }
            let body: Element<'_, Message> = body_col.into();
            // Keyboard rows with no default, like the rest of the card:
            // enabling weaker algorithms is a choice, never a stray Enter.
            let cancel_msg = Message::Ssh(SshMessage::LegacyAlgoCancel);
            let once_msg = Message::Ssh(SshMessage::LegacyAlgoAccept { remember: false });
            let mut btm_row = row![
                self.progress_slot(
                    owned,
                    cancel_msg.clone(),
                    8.0,
                    false,
                    crate::widgets::styled_button(
                        crate::i18n::t("cancel"),
                        cancel_msg,
                        OryxisColors::t().text_muted,
                    ),
                ),
                Space::new().width(Length::Fill),
                self.progress_slot(
                    owned,
                    once_msg.clone(),
                    8.0,
                    is_quick,
                    crate::widgets::styled_button(
                        crate::i18n::t("legacy_algo_connect_once"),
                        once_msg,
                        if is_quick {
                            OryxisColors::t().accent
                        } else {
                            OryxisColors::t().bg_hover
                        },
                    ),
                ),
            ];
            if !is_quick {
                let always_msg = Message::Ssh(SshMessage::LegacyAlgoAccept { remember: true });
                btm_row = btm_row.push(Space::new().width(8)).push(self.progress_slot(
                    owned,
                    always_msg.clone(),
                    8.0,
                    true,
                    crate::widgets::styled_button(
                        crate::i18n::t("legacy_algo_always"),
                        always_msg,
                        OryxisColors::t().accent,
                    ),
                ));
            }
            let btm: Element<'_, Message> = btm_row.align_y(iced::Alignment::Center).into();
            (status, body, btm)
        } else if let Some(ref kbi) = self.pending_kbi_prompt {
            // Keyboard-interactive (2FA / OTP). `name` and the prompt labels
            // are server strings, never translated; only the chrome (title
            // fallback, buttons) goes through i18n. They can carry
            // `user@host` ("Password for root@203.0.113.7"), so they pass
            // through the same Privacy Mode redaction as the rest of the
            // screen.
            let title = if kbi.name.trim().is_empty() {
                crate::i18n::t("kbi_title").to_string()
            } else {
                self.redact_progress(progress, &kbi.name)
            };
            let status: Element<'_, Message> =
                text(title).size(14).color(OryxisColors::t().accent).into();

            let mut body_col = column![].push(Space::new().height(8));

            if !kbi.instructions.trim().is_empty() {
                body_col = body_col
                    .push(text(self.redact_progress(progress, &kbi.instructions)).size(13).color(OryxisColors::t().text_secondary))
                    .push(Space::new().height(12));
            }

            for (i, prompt) in kbi.prompts.iter().enumerate() {
                let prompt_label = self.redact_progress(progress, &prompt.prompt);
                let value = self.kbi_inputs.get(i).map(|s| s.as_str()).unwrap_or("");
                let mut input = text_input(prompt_label.clone(), value)
                    .on_input(move |v| Message::Ssh(SshMessage::SshKbiInput(i, v.into())))
                    .on_submit(Message::Ssh(SshMessage::SshKbiSubmit))
                    .padding(10)
                    .size(14);
                // First field gets the shared id so the prompt handler can
                // focus it (type-and-Enter without a click).
                if i == 0 {
                    input = input.id(iced::widget::Id::new(crate::state::KBI_FIRST_INPUT_ID));
                }
                // echo == false means a secret (password / OTP): mask it.
                if !prompt.echo {
                    input = input.secure(true);
                }
                body_col = body_col
                    .push(text(prompt_label.clone()).size(12).color(OryxisColors::t().text_muted))
                    .push(Space::new().height(4))
                    .push(input)
                    .push(Space::new().height(12));
            }

            // Quick-connect prompt: offer the saved identities / keys as an
            // alternative to answering the challenge by hand.
            if let Some(qid) = self.pending_kbi_quick
                && let Some(section) = self.view_quick_auth_switch(qid)
            {
                body_col = body_col.push(section).push(Space::new().height(12));
            }

            let body: Element<'_, Message> = container(body_col)
                .width(Length::Fill)
                .height(Length::Fill)
                .padding(Padding { top: 8.0, right: 16.0, bottom: 8.0, left: 16.0 })
                .style(|_| container::Style {
                    background: Some(Background::Color(OryxisColors::t().bg_sidebar)),
                    border: Border { radius: Radius::from(10.0), ..Default::default() },
                    ..Default::default()
                })
                .into();

            let cancel_btn = button(
                container(text(crate::i18n::t("cancel")).size(13).color(OryxisColors::t().text_primary))
                    .padding(Padding { top: 10.0, right: 24.0, bottom: 10.0, left: 24.0 }),
            )
            .on_press(Message::Ssh(SshMessage::SshKbiCancel))
            .style(|_, status| button::Style {
                background: Some(Background::Color(match status {
                    button::Status::Hovered | button::Status::Pressed => OryxisColors::t().bg_hover,
                    _ => OryxisColors::t().bg_surface,
                })),
                border: Border { radius: Radius::from(8.0), ..Default::default() },
                ..Default::default()
            });

            let submit_btn = {
                let fg = crate::theme::contrast_text_for(OryxisColors::t().accent);
                button(
                    container(
                        text(crate::i18n::t("kbi_submit"))
                            .size(13)
                            .font(iced::Font {
                                weight: iced::font::Weight::Semibold,
                                ..iced::Font::new(crate::theme::SYSTEM_UI_FAMILY)
                            })
                            .color(fg),
                    )
                    .padding(Padding { top: 10.0, right: 24.0, bottom: 10.0, left: 24.0 }),
                )
                .on_press(Message::Ssh(SshMessage::SshKbiSubmit))
                .style(|_, status| button::Style {
                    background: Some(Background::Color(match status {
                        // No dedicated hover tone in the palette; nudge the fill
                        // toward the text colour, as the host-key buttons do.
                        button::Status::Hovered | button::Status::Pressed => crate::theme::mix(
                            OryxisColors::t().accent,
                            OryxisColors::t().text_primary,
                            0.15,
                        ),
                        _ => OryxisColors::t().accent,
                    })),
                    border: Border { radius: Radius::from(8.0), ..Default::default() },
                    ..Default::default()
                })
            };

            let btm: Element<'_, Message> = row![
                cancel_btn,
                Space::new().width(Length::Fill),
                submit_btn,
            ].align_y(iced::Alignment::Center).into();

            (status, body, btm)
        } else if let Some(ref query) = self.pending_proxy_command {
            // Before the handshake, before the host key: this dial is
            // about to run a local process, so it outranks every other
            // prompt this screen can show. Body and buttons come from
            // `views::proxy_command`, shared with the standalone card
            // `root_view` stacks for dials that have no progress screen.
            let status: Element<'_, Message> = text(crate::i18n::t("proxy_cmd_title"))
                .size(14)
                .color(OryxisColors::t().warning)
                .into();

            let endpoint = self.redact_progress(
                progress,
                &format!("{}:{}", query.target_host, query.target_port),
            );
            let body: Element<'_, Message> = container(
                column![
                    Space::new().height(8),
                    crate::views::proxy_command::proxy_command_body(query, &endpoint),
                ],
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(Padding { top: 8.0, right: 16.0, bottom: 8.0, left: 16.0 })
            .style(|_| container::Style {
                background: Some(Background::Color(OryxisColors::t().bg_sidebar)),
                border: Border { radius: Radius::from(10.0), ..Default::default() },
                ..Default::default()
            })
            .into();

            (status, body, self.proxy_command_buttons())
        } else if let Some(ref query) = self.pending_host_key {
            let is_changed = matches!(query.status, oryxis_ssh::HostKeyStatus::Changed { .. });

            let question_text = if is_changed {
                crate::i18n::t("hk_warning_title")
            } else {
                crate::i18n::t("hk_unknown_title")
            };
            let question_color = if is_changed { OryxisColors::t().error } else { OryxisColors::t().warning };

            let status: Element<'_, Message> = text(question_text).size(14).color(question_color).into();

            let mut body_col = column![];

            if is_changed {
                body_col = body_col
                    .push(Space::new().height(8))
                    .push(text(crate::i18n::t("hk_warning_desc")).size(13).color(OryxisColors::t().error))
                    .push(Space::new().height(12));
                if let oryxis_ssh::HostKeyStatus::Changed { ref old_fingerprint } = query.status {
                    body_col = body_col
                        .push(text(format!("{} {}", crate::i18n::t("hk_old_fingerprint"), old_fingerprint)).size(12).color(OryxisColors::t().text_muted))
                        .push(Space::new().height(8));
                }
            } else {
                body_col = body_col
                    .push(Space::new().height(8))
                    .push(text(
                        crate::i18n::t("hk_unknown_desc")
                            .replace("{host}", &self.redact_progress(progress, &query.hostname)),
                    ).size(13).color(OryxisColors::t().text_secondary))
                    .push(Space::new().height(12));
            }

            body_col = body_col
                .push(text(
                    crate::i18n::t("hk_fingerprint_sha256").replace("{key_type}", &query.key_type),
                ).size(13).color(OryxisColors::t().text_secondary))
                .push(Space::new().height(8))
                .push(text(&query.fingerprint).size(14).color(OryxisColors::t().text_primary))
                .push(Space::new().height(16))
                .push(text(crate::i18n::t("hk_add_question")).size(13).color(OryxisColors::t().text_secondary));

            let body: Element<'_, Message> = container(body_col)
                .width(Length::Fill)
                .height(Length::Fill)
                .padding(Padding { top: 8.0, right: 16.0, bottom: 8.0, left: 16.0 })
                .style(|_| container::Style {
                    background: Some(Background::Color(OryxisColors::t().bg_sidebar)),
                    border: Border { radius: Radius::from(10.0), ..Default::default() },
                    ..Default::default()
                })
                .into();

            (status, body, self.host_key_buttons())
        } else {
            // Normal connection progress / failure: the journey bar on top
            // answers the state at a glance (and keeps the screen alive
            // while dialing); the vertical timeline below stays the
            // detailed log.
            let status_text = if failed {
                crate::i18n::t("connection_failed_log")
            } else {
                crate::i18n::t("connecting_status")
            };
            let status_color = if failed { OryxisColors::t().error } else { OryxisColors::t().text_secondary };
            let title = container(
                text(status_text)
                    .size(15)
                    .font(iced::Font {
                        weight: iced::font::Weight::Semibold,
                        ..iced::Font::new(crate::theme::SYSTEM_UI_FAMILY)
                    })
                    .color(status_color),
            )
            .width(Length::Fill)
            .align_x(Horizontal::Center);
            let status: Element<'_, Message> = column![
                Space::new().height(8),
                title,
                Space::new().height(4),
            ]
            .into();

            (status, self.view_connection_log_timeline(progress, failed, pulse), self.view_connection_log_buttons(progress, failed, owned))
        };

        let bottom: Element<'_, Message> = match batch_row {
            Some(batch_row) => column![batch_row, Space::new().height(12), bottom]
                .width(Length::Fill)
                .into(),
            None => bottom,
        };

        container(
            column![
                header,
                status_widget,
                banner_block,
                proxy_block,
                Space::new().height(12),
                body_widget,
                Space::new().height(16),
                bottom,
            ]
            .padding(32)
            .width(500)
            .height(Length::Fill),
        )
        .center_x(Length::Fill)
        .height(Length::Fill)
        .style(|_| container::Style {
            background: Some(Background::Color(OryxisColors::t().bg_primary)),
            ..Default::default()
        })
        .into()
    }

    /// The saved identities and keys a quick-connect host can switch to,
    /// in the order the selector lists them. Shared by the selector and
    /// its keyboard row, which picks from the same list.
    pub(crate) fn quick_auth_options(&self) -> Vec<crate::state::QuickAuthOption> {
        let mut options: Vec<crate::state::QuickAuthOption> =
            Vec::with_capacity(self.identities.len() + self.keys.len());
        for i in &self.identities {
            // Surface the identity's username: picking it switches the
            // login user, so the label must say who you'd become.
            let label = match i.username.as_deref().filter(|u| !u.trim().is_empty()) {
                Some(u) => format!("{}: {} ({u})", crate::i18n::t("identity"), i.label),
                None => format!("{}: {}", crate::i18n::t("identity"), i.label),
            };
            options.push(crate::state::QuickAuthOption {
                choice: crate::state::QuickAuthChoice::Identity(i.id),
                label,
            });
        }
        for k in &self.keys {
            options.push(crate::state::QuickAuthOption {
                choice: crate::state::QuickAuthChoice::Key(k.id),
                label: format!("{}: {}", crate::i18n::t("auth_key"), k.label),
            });
        }
        options
    }

    /// The "or authenticate with a saved identity / key" selector for a
    /// quick-connect host, offered inside the keyboard-interactive prompt
    /// modal and on the failed-connect screen. `None` when the vault has
    /// nothing to offer. Selecting an option mutates the ephemeral entry
    /// and retries the connect with it (`QuickAuthSwitch`).
    pub(crate) fn view_quick_auth_switch(
        &self,
        quick_id: uuid::Uuid,
    ) -> Option<Element<'_, Message>> {
        let options = self.quick_auth_options();
        if options.is_empty() {
            return None;
        }
        // Action picker, never a state picker: nothing is pre-selected and
        // choosing an option fires the switch immediately.
        let pick = pick_list(
            None::<crate::state::QuickAuthOption>,
            options,
            |o: &crate::state::QuickAuthOption| o.label.clone(),
        )
        .on_select(move |o| Message::Ssh(SshMessage::QuickAuthSwitch(quick_id, o.choice)))
        .placeholder(crate::i18n::t("quick_auth_pick"))
        .width(Length::Fill)
        .padding(10)
        .text_size(13)
        .style(crate::widgets::rounded_pick_list_style);
        Some(
            column![
                text(crate::i18n::t("quick_auth_alt"))
                    .size(12)
                    .color(OryxisColors::t().text_muted),
                Space::new().height(6),
                pick,
            ]
            .width(Length::Fill)
            .into(),
        )
    }

    /// The log box rendered as a vertical timeline: one node per log line,
    /// linked by a rail line, message text to the right. `selectable_group`
    /// gives continuous drag-selection across lines (Ctrl+C copies the joined
    /// text); the "Copy logs" button below grabs the whole log regardless.
    fn view_connection_log_timeline(
        &self,
        progress: &crate::state::ConnectionProgress,
        failed: bool,
        pulse: f32,
    ) -> Element<'_, Message> {
        let n = progress.logs.len();
        let mut rows: Vec<Element<'_, Message>> = Vec::with_capacity(n);

        for (i, (step, msg)) in progress.logs.iter().enumerate() {
            let is_error = msg.starts_with("Error");
            let is_last = i + 1 == n;
            // The in-flight node pulses only while we're still connecting.
            let is_active = !failed && is_last;

            // The old text_muted for Connecting made the enlarged discs
            // read as disabled, so every step carries a real color now
            // (see step_color). Errors get the alert glyph in the same
            // disc shape so the column stays visually aligned.
            let node_color = if is_error { OryxisColors::t().error } else { step_color(*step) };
            let glyph: Element<'_, Message> = if is_error {
                iced_fonts::lucide::circle_alert().size(15).color(node_color).into()
            } else {
                step_glyph(*step, node_color)
            };

            // Marker: a tinted 28 px disc around the glyph. The in-flight
            // node breathes: its ring width, halo alpha and tint ride the
            // pulse; settled nodes keep a quiet 1 px ring.
            let (ring_w, ring_a, tint_a) = if is_active {
                (2.0 + pulse * 2.0, 0.40 + pulse * 0.45, 0.18 + pulse * 0.12)
            } else if is_error {
                (1.0, 0.60, 0.18)
            } else {
                (1.0, 0.35, 0.14)
            };
            let marker: Element<'_, Message> = container(glyph)
                .center_x(Length::Fixed(28.0))
                .center_y(Length::Fixed(28.0))
                .style(move |_| container::Style {
                    background: Some(Background::Color(Color { a: tint_a, ..node_color })),
                    border: Border {
                        radius: Radius::from(14.0),
                        color: Color { a: ring_a, ..node_color },
                        width: ring_w,
                    },
                    ..Default::default()
                })
                .into();

            // Connector descends from this node toward the next one. Dimmed
            // so it reads as a guide line, not a solid bar. The segment
            // feeding the in-flight node carries a spark sliding down the
            // rail (portion-split overlay, no pixel math), so the motion
            // points at the step that's actually working. Omitted on the
            // last node so the line doesn't dangle below the final marker.
            // The segment is tinted like the node it FEEDS (the one below),
            // so the lead-in to an error is red, not the color of the step
            // that happened to precede it.
            let feeds_active = !failed && i + 2 == n;
            let connector: Element<'_, Message> = if is_last {
                Space::new().into()
            } else {
                let (next_step, next_msg) = &progress.logs[i + 1];
                let next_color = if next_msg.starts_with("Error") {
                    OryxisColors::t().error
                } else {
                    step_color(*next_step)
                };
                let line_color = Color { a: 0.55, ..next_color };
                let line: Element<'_, Message> = container(Space::new())
                    .width(Length::Fixed(2.0))
                    .height(Length::Fill)
                    .style(move |_| container::Style {
                        background: Some(Background::Color(line_color)),
                        ..Default::default()
                    })
                    .into();
                if feeds_active {
                    // Spark riding the same tint, eased lap ~1.2 s on the
                    // 100 ms anim tick. Even-sized (8 px, flush with the
                    // stack) so its center lands on the same integer x as
                    // the 2 px rail; an odd size centers at a half pixel
                    // and snaps visibly off the line on fractional DPI.
                    let lap = (self.connect_anim_tick % 12) as f32 / 12.0;
                    let eased = lap * lap * (3.0 - 2.0 * lap);
                    let pos = ((eased * 1000.0) as u16).clamp(1, 999);
                    let spark = container(Space::new())
                        .width(Length::Fixed(8.0))
                        .height(Length::Fixed(8.0))
                        .style(move |_| container::Style {
                            background: Some(Background::Color(next_color)),
                            border: Border {
                                radius: Radius::from(4.0),
                                color: Color { a: 0.35, ..next_color },
                                width: 2.0,
                            },
                            ..Default::default()
                        });
                    iced::widget::Stack::with_children(vec![
                        container(line).center_x(Length::Fixed(8.0)).height(Length::Fill).into(),
                        column![
                            Space::new().height(Length::FillPortion(pos)),
                            container(spark).center_x(Length::Fixed(8.0)),
                            Space::new().height(Length::FillPortion(1000 - pos)),
                        ]
                        .height(Length::Fill)
                        .into(),
                    ])
                    .width(Length::Fixed(8.0))
                    .height(Length::Fill)
                    .into()
                } else {
                    line
                }
            };

            // Rail: the marker, then the fill connector. The column is
            // Fill-height so the connector stretches to the row's height
            // (driven by the message cell) -- except on the last row,
            // which has no connector and whose one-line message cell is
            // SHORTER than the 28 px disc: a Fill rail would adopt that
            // height and squash the disc into an ellipse, so it shrinks
            // to the marker instead.
            let mut rail = column![marker, connector]
                .align_x(Horizontal::Center)
                .width(Length::Fixed(32.0));
            if !is_last {
                rail = rail.height(Length::Fill);
            }

            // Selectable message, top-padded to sit centered against the
            // disc's first line. Bottom padding (except last) gives the
            // rows breathing room and lets the connector span cleanly to
            // the next node.
            let span: iced::widget::text::Span<'_, ()> =
                iced::widget::text::Span::new(self.redact_progress(progress, msg))
                    .color(OryxisColors::t().text_secondary);
            let message = iced::widget::rich_text::<(), Message, _>([span])
                .size(13)
                .selectable(true);
            let message_cell = container(message).width(Length::Fill).padding(Padding {
                top: 6.0,
                right: 0.0,
                bottom: if is_last { 0.0 } else { 20.0 },
                left: 0.0,
            });

            rows.push(
                crate::widgets::dir_row(vec![
                    rail.into(),
                    Space::new().width(10).into(),
                    message_cell.into(),
                ])
                .align_y(iced::Alignment::Start)
                .height(Length::Shrink)
                .into(),
            );
        }

        let timeline = column(rows).padding(Padding { top: 14.0, right: 16.0, bottom: 14.0, left: 12.0 });
        let log_list = scrollable(iced::widget::selectable_group::<(), Message, _, _>(timeline))
            .height(Length::Fill);

        container(log_list)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(OryxisColors::t().bg_sidebar)),
                border: Border { radius: Radius::from(10.0), ..Default::default() },
                ..Default::default()
            })
            .into()
    }

    /// Bottom action row for the failed state: "Copy logs" on the leading
    /// edge, then Close / Start over on the trailing edge ("Edit Host" lives
    /// in the header). While connecting (not failed) there are no buttons.
    fn view_connection_log_buttons(
        &self,
        progress: &crate::state::ConnectionProgress,
        failed: bool,
        owned: bool,
    ) -> Element<'_, Message> {
        if !failed {
            return Space::new().into();
        }

        // Quick connect that died in the auth stage (a publickey-only
        // server never even raises the interactive prompt): offer the
        // saved identities / keys right where the failure landed. Earlier
        // stages (DNS, TCP, handshake) aren't auth problems, so the
        // selector would be noise there. It renders ABOVE the button row,
        // so it is recorded first: display order is the walk order.
        let switch_section = match progress.origin {
            crate::state::ProgressOrigin::Quick(id)
                if progress.step == ConnectionStep::Authenticating =>
            {
                self.view_quick_auth_switch(id).map(|section| {
                    if !owned {
                        return section;
                    }
                    // An ACTION picker: nothing is selected, and picking
                    // retries with the choice. Left / Right pick the first
                    // / last option (the mouse's one click, from the
                    // keyboard); Enter on the row does nothing, because a
                    // pick_list cannot be opened from code.
                    let options = self.quick_auth_options();
                    let pick = |o: Option<&crate::state::QuickAuthOption>| {
                        o.map(|o| Message::Ssh(SshMessage::QuickAuthSwitch(id, o.choice)))
                    };
                    let idx = self.modal_nav_record(crate::keynav::RowAction::picker(
                        pick(options.last()),
                        pick(options.first()),
                    ));
                    self.modal_nav_ring_at(idx, 8.0, false, section)
                })
            }
            _ => None,
        };

        // Whole-log payload for the clipboard: host header + every line.
        let mut payload = format!("{}\n{}\n", progress.label, progress.hostname);
        for (_, m) in &progress.logs {
            payload.push_str(m);
            payload.push('\n');
        }

        let copy_btn = button(
            container(
                row![
                    iced_fonts::lucide::copy().size(13).color(OryxisColors::t().text_secondary),
                    Space::new().width(8),
                    text(crate::i18n::t("copy_logs")).size(13).color(OryxisColors::t().text_primary),
                ]
                .align_y(iced::Alignment::Center),
            )
            .padding(Padding { top: 10.0, right: 18.0, bottom: 10.0, left: 18.0 }),
        )
        .on_press(Message::CopyToClipboard(payload.clone()))
        .style(|_, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => OryxisColors::t().bg_hover,
                _ => OryxisColors::t().bg_surface,
            })),
            border: Border { radius: Radius::from(8.0), ..Default::default() },
            ..Default::default()
        });

        let close_btn = button(
            container(text(crate::i18n::t("close")).size(13).color(OryxisColors::t().text_primary))
                .padding(Padding { top: 10.0, right: 24.0, bottom: 10.0, left: 24.0 }),
        )
        .on_press(Message::Ssh(SshMessage::SshCloseProgress))
        .style(|_, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => OryxisColors::t().bg_hover,
                _ => OryxisColors::t().bg_surface,
            })),
            border: Border { radius: Radius::from(8.0), ..Default::default() },
            ..Default::default()
        });

        let start_over_btn = {
            let fg = crate::theme::contrast_text_for(OryxisColors::t().success);
            button(
                container(
                    text(crate::i18n::t("start_over"))
                        .size(13)
                        .font(iced::Font {
                            weight: iced::font::Weight::Semibold,
                            ..iced::Font::new(crate::theme::SYSTEM_UI_FAMILY)
                        })
                        .color(fg),
                )
                .padding(Padding { top: 10.0, right: 24.0, bottom: 10.0, left: 24.0 }),
            )
            .on_press(Message::Ssh(SshMessage::SshRetry))
            .style(|_, status| button::Style {
                background: Some(Background::Color(match status {
                    // No dedicated hover tone in the palette; nudge the fill
                    // toward the text colour, as the host-key buttons do.
                    button::Status::Hovered | button::Status::Pressed => crate::theme::mix(
                        OryxisColors::t().success,
                        OryxisColors::t().text_primary,
                        0.15,
                    ),
                    _ => OryxisColors::t().success,
                })),
                border: Border { radius: Radius::from(8.0), ..Default::default() },
                ..Default::default()
            })
        };

        // Recorded in reading order (Copy, Close, Start over), the same
        // logical order `dir_row` lays out and mirrors under RTL.
        let copy_btn = self.progress_slot(
            owned,
            Message::CopyToClipboard(payload),
            8.0,
            false,
            copy_btn.into(),
        );
        let close_btn = self.progress_slot(
            owned,
            Message::Ssh(SshMessage::SshCloseProgress),
            8.0,
            false,
            close_btn.into(),
        );
        let start_over_btn = self.progress_slot(
            owned,
            Message::Ssh(SshMessage::SshRetry),
            8.0,
            true,
            start_over_btn.into(),
        );
        let buttons = crate::widgets::dir_row(vec![
            copy_btn,
            Space::new().width(Length::Fill).into(),
            close_btn,
            Space::new().width(8).into(),
            start_over_btn,
        ])
        .align_y(iced::Alignment::Center);
        match switch_section {
            Some(section) => column![section, Space::new().height(14), buttons]
                .width(Length::Fill)
                .into(),
            None => buttons.into(),
        }
    }
}

/// The web links the local proxy printed on its STDERR, in order, each
/// once, at most three (a login prints one; a card of buttons would bury
/// the card). Lines from before the SSH banner are skipped: they may be
/// the remote server's (see `oryxis_ssh::ProxyOutputSource`). Trailing
/// punctuation that is almost always sentence, not URL, is trimmed.
fn proxy_output_urls(lines: &[oryxis_ssh::ProxyOutputLine]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in lines.iter().filter(|l| l.is_local()) {
        for word in line.text.split_whitespace() {
            let start = word.find("https://").or_else(|| word.find("http://"));
            let Some(start) = start else { continue };
            let url = word[start..].trim_end_matches(['.', ',', ';', ':', ')', ']', '>', '"', '\'']);
            if url.len() > "https://".len() && !out.iter().any(|u| u == url) {
                out.push(url.to_string());
                if out.len() == 3 {
                    return out;
                }
            }
        }
    }
    out
}

/// The host a link opens, as the button names it: what sits between
/// `://` and the path, with any `user@` in front dropped (in
/// `https://sso.example@evil.example/` the browser goes to
/// `evil.example`, so that is what the button must say).
fn url_host_label(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    host.to_string()
}

#[cfg(test)]
mod proxy_output_tests {
    use super::{proxy_output_urls, url_host_label};
    use oryxis_ssh::{ProxyOutputLine, ProxyOutputSource};

    fn stderr(text: &str) -> ProxyOutputLine {
        ProxyOutputLine { text: text.to_string(), source: ProxyOutputSource::Stderr }
    }

    fn before_banner(text: &str) -> ProxyOutputLine {
        ProxyOutputLine { text: text.to_string(), source: ProxyOutputSource::BeforeBanner }
    }

    #[test]
    fn the_login_url_a_proxy_prints_is_found_once() {
        let lines = vec![
            stderr("WARN Expired SSH credentials found. Will refresh..."),
            stderr("Open https://sso.example/device?code=AB-12 in a browser."),
            stderr("(or visit <https://sso.example/device?code=AB-12>)"),
        ];
        assert_eq!(proxy_output_urls(&lines), vec!["https://sso.example/device?code=AB-12"]);
    }

    #[test]
    fn a_line_without_a_link_offers_none() {
        assert!(proxy_output_urls(&[stderr("token refreshed, connecting")]).is_empty());
        assert!(proxy_output_urls(&[stderr("see https://")]).is_empty());
    }

    #[test]
    fn a_link_before_the_banner_is_shown_but_never_offered() {
        // A relaying proxy hands over the remote server's own lines.
        let lines = vec![
            before_banner("Login: https://evil.example/sso"),
            stderr("Open https://sso.example/device in a browser."),
        ];
        assert_eq!(proxy_output_urls(&lines), vec!["https://sso.example/device"]);
        assert!(proxy_output_urls(&[before_banner("https://evil.example/x")]).is_empty());
    }

    #[test]
    fn the_button_names_the_host_the_browser_goes_to() {
        assert_eq!(url_host_label("https://sso.example/device?code=1"), "sso.example");
        assert_eq!(url_host_label("https://sso.example:8443/x"), "sso.example:8443");
        assert_eq!(url_host_label("https://sso.example@evil.example/x"), "evil.example");
        assert_eq!(url_host_label("http://host.example"), "host.example");
    }
}
