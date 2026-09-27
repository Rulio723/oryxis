//! Settings > Sync: "Install on one of your hosts", the relay wizard's
//! second level (E3), and its consent modal. Split out of
//! views/settings/sync.rs.
//!
//! The block lives INSIDE the wizard card, below the level-1 test: it
//! reads the wizard's domain, public port and token, so a person who
//! filled those in for the copy-paste path has nothing to retype.

use super::*;
use iced::widget::column;

use crate::relay_deploy::Privilege;
#[cfg(test)]
use crate::relay_deploy::RelayDeployStep;

/// Height of the streamed log pane.
const LOG_HEIGHT: f32 = 180.0;
/// Height of the script pane in the consent modal.
const SCRIPT_HEIGHT: f32 = 320.0;

impl Oryxis {
    /// The deploy section of the relay wizard card. Rows record on the
    /// Settings ring in visual order, like the wizard rows above them.
    pub(super) fn sync_relay_deploy_block(&self) -> iced::widget::Column<'_, Message> {
        let d = &self.sync.relay_deploy;
        let c = OryxisColors::t();
        let mut col: iced::widget::Column<'_, Message> =
            column![self.settings_nav_slot_labeled(
                t("relay_deploy_button"),
                crate::keynav::RowAction::activate(Message::Sync(SyncMessage::DeployToggle)),
                6.0,
                styled_button(
                    t("relay_deploy_button"),
                    Message::Sync(SyncMessage::DeployToggle),
                    c.button_bg,
                ),
            )];
        if !d.open {
            return col;
        }
        col = col
            .push(Space::new().height(8))
            .push(text(t("relay_deploy_intro")).size(11).color(c.text_muted))
            .push(Space::new().height(10));

        // Host picker trigger (the SFTP sync card's shape).
        let selected_conn = d
            .host_id
            .and_then(|id| self.connections.iter().find(|c| c.id == id));
        let trigger_inner: Element<'_, Message> = if let Some(conn) = selected_conn {
            dir_row(vec![
                super::host_picker::host_badge(conn, &self.prefs.default_host_icon, 22.0),
                Space::new().width(10).into(),
                text(conn.label.clone()).size(13).color(c.text_primary).into(),
                Space::new().width(Length::Fill).into(),
                text("\u{25BE}").size(12).color(c.text_muted).into(),
            ])
            .align_y(iced::Alignment::Center)
            .into()
        } else {
            dir_row(vec![
                text(t("select_a_host")).size(13).color(c.text_muted).into(),
                Space::new().width(Length::Fill).into(),
                text("\u{25BE}").size(12).color(c.text_muted).into(),
            ])
            .align_y(iced::Alignment::Center)
            .into()
        };
        // Everything the plan is built from is frozen while a probe or
        // run is in flight: disabled here and refused in the handlers.
        // A frozen control still records its slot, as an INERT one
        // (`RowAction::default()`: Enter does nothing): dropping it
        // would renumber every row after it while the ring kept its
        // index, and the next Enter would land on a different row.
        let editable = !d.busy;
        let inert = crate::keynav::RowAction::default;
        let host_btn: Element<'_, Message> = button(trigger_inner)
            .on_press_maybe(editable.then_some(Message::Sync(SyncMessage::DeployHostPickerOpen)))
            .padding(10)
            .width(300)
            .style(|_, status| {
                let c = OryxisColors::t();
                let border = match status {
                    BtnStatus::Hovered | BtnStatus::Pressed => c.accent_hover,
                    _ => c.border,
                };
                button::Style {
                    background: Some(Background::Color(c.bg_surface)),
                    text_color: c.text_primary,
                    border: Border { radius: Radius::from(8.0), width: 1.0, color: border },
                    ..Default::default()
                }
            })
            .into();
        let host_pick = self.settings_nav_slot_labeled(
            t("host"),
            if editable {
                crate::keynav::RowAction::activate(Message::Sync(SyncMessage::DeployHostPickerOpen))
            } else {
                inert()
            },
            8.0,
            host_btn,
        );
        col = col.push(panel_field(t("host"), host_pick)).push(Space::new().height(8));

        // Relay port.
        let port_field: Element<'_, Message> = text_input("8080", &d.port)
            .id(iced::widget::Id::new("set-sync-deploy-port"))
            .on_input_maybe(
                editable.then_some(|v| Message::Sync(SyncMessage::DeployPortChanged(v))),
            )
            .padding(8)
            .width(120)
            .style(crate::widgets::rounded_input_style)
            .align_x(dir_align_x())
            .into();
        let port_input = self.settings_nav_slot_labeled(
            t("relay_deploy_port"),
            if editable {
                crate::keynav::RowAction::input(iced::widget::Id::new("set-sync-deploy-port"))
            } else {
                inert()
            },
            10.0,
            port_field,
        );
        col = col
            .push(panel_field(t("relay_deploy_port"), port_input))
            .push(Space::new().height(8));

        // TLS via Caddy on the host.
        col = col
            .push(if editable {
                self.nav_toggle_row(
                    t("relay_deploy_caddy"),
                    d.use_caddy,
                    Message::Sync(SyncMessage::DeployCaddyToggled),
                )
            } else {
                // Shown, not offered: the handler refuses the toggle
                // while busy, and the switch carries no message. Same
                // slot `nav_toggle_row` records, inert.
                self.settings_nav_slot_labeled(
                    t("relay_deploy_caddy"),
                    inert(),
                    8.0,
                    crate::widgets::toggle_row(t("relay_deploy_caddy"), d.use_caddy, Message::NoOp),
                )
            })
            .push(Space::new().height(4))
            .push(
                text(if d.use_caddy {
                    t("relay_deploy_caddy_hint")
                } else {
                    t("relay_deploy_http_warning")
                })
                .size(11)
                .color(if d.use_caddy { c.text_muted } else { c.warning }),
            )
            .push(Space::new().height(12));

        // Actions: Check host, then Review & run or Copy script once a
        // plan exists. While busy they are disabled and their slots are
        // inert, so keyboard Enter can neither double-fire a probe nor
        // land on a renumbered row.
        let probe_msg = (!d.busy).then_some(Message::Sync(SyncMessage::DeployProbe));
        let probe_btn = styled_button_opt(t("relay_deploy_probe"), probe_msg.clone(), c.button_bg);
        let probe_btn: Element<'_, Message> = self.settings_nav_slot(
            probe_msg.map_or_else(inert, crate::keynav::RowAction::activate),
            6.0,
            probe_btn,
        );
        let mut actions: Vec<Element<'_, Message>> = vec![probe_btn];
        if let (Some(plan), Some(probe)) = (&d.plan, &d.probe) {
            actions.push(Space::new().width(8).into());
            if probe.privilege != Privilege::None {
                let m = (!d.busy).then_some(Message::Sync(SyncMessage::DeployReview));
                actions.push(self.settings_nav_slot(
                    m.clone().map_or_else(inert, crate::keynav::RowAction::activate),
                    6.0,
                    styled_button_opt(t("relay_deploy_review"), m, c.accent),
                ));
                actions.push(Space::new().width(8).into());
            }
            let copy = (!d.busy).then(|| Message::CopyToClipboard(plan.consent_script()));
            actions.push(self.settings_nav_slot(
                copy.clone().map_or_else(inert, crate::keynav::RowAction::activate),
                6.0,
                styled_button_opt(t("relay_deploy_copy_script"), copy, c.button_bg),
            ));
        }
        col = col.push(dir_row(actions).align_y(iced::Alignment::Center));

        // Progress line while a probe or run is in flight.
        if let (true, Some(step)) = (d.busy, d.step) {
            col = col.push(Space::new().height(8)).push(
                text(format!("{}\u{2026}", t(step.label_key())))
                    .size(11)
                    .color(c.text_muted),
            );
        }

        // Outcome line.
        if let Some(result) = &d.result {
            let (txt, color) = match result {
                Ok(url) => (t("relay_deploy_done").replace("{url}", url), c.success),
                Err(e) => (e.clone(), c.error),
            };
            col = col.push(Space::new().height(8)).push(text(txt).size(11).color(color));
            if let Some(hint) = &d.result_hint {
                col = col
                    .push(Space::new().height(2))
                    .push(text(hint.clone()).size(11).color(c.text_muted));
            }
        }

        // The streamed log, monospace and LTR by nature (command
        // output), with a copy button.
        if !d.log.is_empty() {
            let lines: Vec<Element<'_, Message>> = d
                .log
                .iter()
                .map(|l| {
                    text(l.clone())
                        .size(10)
                        .font(iced::Font::MONOSPACE)
                        .color(if l.starts_with('\u{2717}') { c.error } else { c.text_secondary })
                        .into()
                })
                .collect();
            let log_pane = container(
                scrollable(column(lines).spacing(1).width(Length::Fill))
                    .height(Length::Fixed(LOG_HEIGHT))
                    .anchor_bottom(),
            )
            .width(Length::Fill)
            .padding(10)
            .style(|_| container::Style {
                background: Some(Background::Color(OryxisColors::t().bg_surface)),
                border: Border {
                    radius: Radius::from(6.0),
                    color: OryxisColors::t().border,
                    width: 1.0,
                },
                ..Default::default()
            });
            let copy = Message::CopyToClipboard(d.log.join("\n"));
            col = col
                .push(Space::new().height(10))
                .push(
                    dir_row(vec![
                        text(t("relay_deploy_log")).size(12).color(c.text_secondary).into(),
                        Space::new().width(Length::Fill).into(),
                        self.settings_nav_slot(
                            crate::keynav::RowAction::activate(copy.clone()),
                            6.0,
                            styled_button(t("terminal_copy"), copy, c.button_bg),
                        ),
                    ])
                    .align_y(iced::Alignment::Center),
                )
                .push(Space::new().height(4))
                .push(log_pane);
        }
        col
    }

    /// "Run these commands on <host>?": the whole plan, verbatim, then
    /// Cancel (default row) / Copy / Run. Rendered by `main_layout`
    /// through `modal_overlay`; the scrim and Esc both cancel.
    pub(crate) fn build_relay_deploy_confirm_dialog(&self) -> Element<'_, Message> {
        use crate::keynav::RowAction;
        let c = OryxisColors::t();
        self.modal_nav_reset();
        let d = &self.sync.relay_deploy;
        let Some(plan) = &d.plan else {
            // The flag is up with no plan: a state no handler produces.
            // Render the cancel-only shell rather than a blank overlay.
            return container(
                column![self.modal_nav_slot_default(
                    RowAction::activate(Message::Sync(SyncMessage::DeployConfirmCancel)),
                    6.0,
                    false,
                    styled_button(
                        t("cancel"),
                        Message::Sync(SyncMessage::DeployConfirmCancel),
                        c.text_muted,
                    ),
                )]
                .padding(24),
            )
            .style(|_| container::Style {
                background: Some(Background::Color(OryxisColors::t().bg_surface)),
                border: Border { radius: Radius::from(12.0), color: OryxisColors::t().border, width: 1.0 },
                ..Default::default()
            })
            .into();
        };

        let how = match plan.privilege {
            Privilege::Root => "root".to_string(),
            Privilege::Sudo => format!("{} (sudo)", plan.user),
            Privilege::None => plan.user.clone(),
        };
        let script = plan.consent_script();
        let script_pane = container(
            scrollable(
                text(script.clone())
                    .size(10)
                    .font(iced::Font::MONOSPACE)
                    .color(c.text_primary),
            )
            .height(Length::Fixed(SCRIPT_HEIGHT)),
        )
        .width(Length::Fill)
        .padding(10)
        .style(|_| container::Style {
            background: Some(Background::Color(OryxisColors::t().bg_primary)),
            border: Border {
                radius: Radius::from(6.0),
                color: OryxisColors::t().border,
                width: 1.0,
            },
            ..Default::default()
        });

        let cancel = self.modal_nav_slot_default(
            RowAction::activate(Message::Sync(SyncMessage::DeployConfirmCancel)),
            6.0,
            false,
            styled_button(
                t("cancel"),
                Message::Sync(SyncMessage::DeployConfirmCancel),
                c.text_muted,
            ),
        );
        let copy_msg = Message::CopyToClipboard(script);
        let copy = self.modal_nav_slot(
            RowAction::activate(copy_msg.clone()),
            6.0,
            false,
            styled_button(t("relay_deploy_copy_script"), copy_msg, c.button_bg),
        );
        let run_label = t("relay_deploy_run").replace("{host}", &plan.host_label);
        let run = self.modal_nav_slot(
            RowAction::activate(Message::Sync(SyncMessage::DeployRun)),
            6.0,
            true,
            crate::widgets::styled_button_owned(
                run_label,
                Some(Message::Sync(SyncMessage::DeployRun)),
                c.accent,
            ),
        );

        let dialog = container(
            column![
                text(t("relay_deploy_consent_title").replace("{host}", &plan.host_label))
                    .size(16)
                    .color(c.text_primary),
                Space::new().height(6),
                text(
                    t("relay_deploy_consent_desc")
                        .replace("{host}", &plan.host_label)
                        .replace("{user}", &how)
                )
                .size(13)
                .color(c.text_secondary),
                Space::new().height(4),
                text(format!(
                    "{}  \u{00B7}  sha256 {}",
                    t("relay_deploy_asset_line")
                        .replace("{name}", &plan.asset.name)
                        .replace("{version}", &plan.asset.version),
                    plan.asset.sha256,
                ))
                .size(11)
                .font(iced::Font::MONOSPACE)
                .color(c.text_muted),
                Space::new().height(12),
                script_pane,
                Space::new().height(16),
                dir_row(vec![
                    cancel,
                    Space::new().width(8).into(),
                    copy,
                    Space::new().width(Length::Fill).into(),
                    run,
                ])
                .align_y(iced::Alignment::Center),
            ]
            .padding(24)
            .width(680)
            .align_x(dir_align_x()),
        )
        .style(|_| container::Style {
            background: Some(Background::Color(OryxisColors::t().bg_surface)),
            border: Border { radius: Radius::from(12.0), color: OryxisColors::t().border, width: 1.0 },
            ..Default::default()
        });
        dialog.into()
    }
}

/// Whether a step is the one the progress line names. Kept as a free
/// function so a test can pin the label mapping without a view.
#[cfg(test)]
pub(crate) fn step_label(step: RelayDeployStep) -> &'static str {
    t(step.label_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_step_has_an_english_label() {
        for step in [
            RelayDeployStep::Probe,
            RelayDeployStep::Download,
            RelayDeployStep::Upload,
            RelayDeployStep::Install,
            RelayDeployStep::Service,
            RelayDeployStep::Caddy,
            RelayDeployStep::Health,
            RelayDeployStep::Adopt,
        ] {
            assert_ne!(step_label(step), "???", "{step:?}");
        }
    }
}
