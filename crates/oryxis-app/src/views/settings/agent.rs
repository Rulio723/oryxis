//! Settings -> SSH Agent section view. The enable toggle lives on the
//! Features & Plugins screen (like AI / SFTP / Sync); this section
//! holds the runtime knobs (per-signature confirm, external adds, the
//! Windows OpenSSH pipe alias) plus the socket path and setup
//! snippets, and collapses to nothing while the agent is disabled
//! (toggle-hidden rule), same as the SFTP section.

use super::*;
use iced::widget::column;

impl Oryxis {
    pub(crate) fn view_settings_agent(&self) -> Element<'_, Message> {
        // Keyboard rows are recorded in visual order at construction,
        // so everything below is built only when it actually renders
        // (agent enabled + a listener on this platform).
        self.keynav_settings_reset();

        let mut content_col: iced::widget::Column<'_, Message> = column![]
            .width(Length::Fill)
            .align_x(dir_align_x());

        if let Some(socket) = crate::agent_server::listener_socket_display()
            && self.agent.enabled
        {
            let confirm = self.settings_nav_slot_labeled(
                t("agent_server_confirm"),
                crate::keynav::RowAction::activate(Message::Agent(AgentMessage::AgentConfirmToggled(
                    !self.agent.confirm,
                ))),
                8.0,
                crate::widgets::toggle_row_desc(
                    t("agent_server_confirm"),
                    t("agent_server_confirm_desc"),
                    self.agent.confirm,
                    Message::Agent(AgentMessage::AgentConfirmToggled(!self.agent.confirm)),
                ),
            );

            let allow_add = self.settings_nav_slot_labeled(
                t("agent_allow_add"),
                crate::keynav::RowAction::activate(Message::Agent(AgentMessage::AgentAllowAddToggled(
                    !self.agent.allow_add,
                ))),
                8.0,
                crate::widgets::toggle_row_desc(
                    t("agent_allow_add"),
                    t("agent_allow_add_desc"),
                    self.agent.allow_add,
                    Message::Agent(AgentMessage::AgentAllowAddToggled(!self.agent.allow_add)),
                ),
            );

            // The OpenSSH alias is a Windows concept (fixed pipe name);
            // unix clients point SSH_AUTH_SOCK / IdentityAgent wherever
            // they like, so the row would be dead weight there.
            let openssh_pipe: Element<'_, Message> = if cfg!(windows) {
                let toggle = self.settings_nav_slot_labeled(
                    t("agent_openssh_pipe"),
                    crate::keynav::RowAction::activate(Message::Agent(AgentMessage::AgentOpensshPipeToggled(
                        !self.agent.openssh_pipe,
                    ))),
                    8.0,
                    crate::widgets::toggle_row_desc(
                        t("agent_openssh_pipe"),
                        t("agent_openssh_pipe_desc"),
                        self.agent.openssh_pipe,
                        Message::Agent(AgentMessage::AgentOpensshPipeToggled(!self.agent.openssh_pipe)),
                    ),
                );
                match &self.agent.alias_error {
                    Some(err) => column![
                        Space::new().height(12),
                        toggle,
                        Space::new().height(6),
                        text(err.clone()).size(11).color(OryxisColors::t().error),
                    ]
                    .into(),
                    None => column![Space::new().height(12), toggle].into(),
                }
            } else {
                Space::new().into()
            };

            let copy_btn = |label_key: &'static str, msg: Message| -> Element<'_, Message> {
                self.settings_nav_slot_labeled(
                    t(label_key),
                    crate::keynav::RowAction::activate(msg.clone()),
                    6.0,
                    styled_button(t(label_key), msg, OryxisColors::t().bg_selected),
                )
            };

            let path_row = dir_row(vec![
                text(socket)
                    .size(11)
                    .font(iced::Font::MONOSPACE)
                    .color(OryxisColors::t().text_secondary)
                    .into(),
                Space::new().width(Length::Fill).into(),
                copy_btn("agent_server_copy_path", Message::Agent(AgentMessage::CopyAgentPath)),
            ])
            .align_y(iced::Alignment::Center);

            // Live roster tally: how many vault keys the agent serves
            // and how many externally added keys it holds right now.
            // The external count is the #98 diagnostic: KeePassXC keys
            // are swept on vault lock, and without this line the only
            // symptom of an empty roster was a failed auth downstream.
            let vault_served = self.keys.iter().filter(|k| k.expose_via_agent).count();
            let status_row: Element<'_, Message> = {
                let mut parts = vec![
                    text(format!("{}: {}", t("agent_vault_keys_served"), vault_served))
                        .size(11)
                        .color(OryxisColors::t().text_secondary)
                        .into(),
                ];
                if self.agent.allow_add
                    && let Some(rt) = &self.agent.runtime
                {
                    let held = rt.external_key_count();
                    parts.push(Space::new().width(16).into());
                    parts.push(
                        text(format!("{}: {}", t("agent_external_keys_held"), held))
                            .size(11)
                            .color(if held == 0 {
                                OryxisColors::t().text_muted
                            } else {
                                OryxisColors::t().text_secondary
                            })
                            .into(),
                    );
                }
                dir_row(parts).into()
            };

            content_col = content_col
                .push(panel_section(column![
                    confirm,
                    Space::new().height(12),
                    allow_add,
                    openssh_pipe,
                ]))
                .push(Space::new().height(12))
                .push(panel_section(column![
                    panel_field(t("agent_server_path"), path_row.into()),
                    Space::new().height(8),
                    status_row,
                    Space::new().height(10),
                    {
                        // `IdentityAgent` in ~/.ssh/config is the portable form and
                        // the ONLY one Windows-native OpenSSH honors for a pipe.
                        // The `SSH_AUTH_SOCK` export is a unix-shell idiom, so it
                        // only appears there (its snippet is a unix-socket path).
                        let mut row = vec![copy_btn(
                            "agent_server_snippet_ssh_config",
                            Message::Agent(AgentMessage::CopyAgentSnippet(crate::state::AgentSnippetKind::SshConfig)),
                        )];
                        if cfg!(unix) {
                            row.push(Space::new().width(8).into());
                            row.push(copy_btn(
                                "agent_server_snippet_env",
                                Message::Agent(AgentMessage::CopyAgentSnippet(crate::state::AgentSnippetKind::ShellEnv)),
                            ));
                        }
                        dir_row(row)
                    },
                ]));
        }
        content_col = content_col.push(Space::new().height(24));

        scrollable(
            container(content_col)
                .padding(Padding { top: 24.0, right: 24.0, bottom: 24.0, left: 24.0 }),
        )
        // Stable id so the keyboard router can keep the selected row
        // in view.
        .id(iced::widget::Id::new("settings-agent-scroll"))
        .on_scroll(|s| Message::Settings(SettingsMessage::SectionScrolled(s.viewport.relative_offset().y)))
        .height(Length::Fill)
        .into()
    }
}
