//! Settings -> AI assistant section view. Split out of views/settings/mod.rs.

use super::*;
use iced::widget::column;

impl Oryxis {
    pub(crate) fn view_settings_ai(&self) -> Element<'_, Message> {
        // Keyboard rows are recorded in visual order.
        self.keynav_settings_reset();
        // Enable/disable lives on the Plugins screen now; this
        // section only renders while AI is enabled.
        let mut content_col = column![
            // The assistant runs commands on connected servers
            // (some auto-execute); keep the warning in view.
            text(crate::i18n::t("ai_enable_warning")).size(12).color(OryxisColors::t().text_muted),
        ]
        .width(Length::Fill)
        .align_x(dir_align_x());

        if self.ai.enabled {
            let current_info = crate::ai::provider_info(&self.ai.provider);
            let provider_options: Vec<String> = crate::ai::PROVIDERS
                .iter()
                .map(|p| p.display.to_string())
                .collect();

            let (prov_prev, prov_next) = crate::keynav::slots::cycle_pair(
                &provider_options,
                &current_info.display.to_string(),
                |v| Message::Ai(AiMessage::AiProviderChanged(v)),
            );
            let provider_pick: Element<'_, Message> = self.settings_nav_slot_labeled(
                t("provider"),
                crate::keynav::RowAction::picker(prov_prev, prov_next),
                10.0,
                pick_list(
                    Some(current_info.display.to_string()),
                    provider_options,
                    |s: &String| s.clone(),
                )
                .on_select(|v| Message::Ai(AiMessage::AiProviderChanged(v)))
                .on_open(Message::Navigation(NavigationMessage::PickOpenChanged(true)))
                .on_close(Message::Navigation(NavigationMessage::PickOpenChanged(false)))
                .width(220)
                .padding(10)
                .style(crate::widgets::rounded_pick_list_style)
                .into(),
            );

            let model_input: Element<'_, Message> = self.settings_nav_slot_labeled(
                t("model"),
                crate::keynav::RowAction::input(iced::widget::Id::new("set-ai-model")),
                10.0,
                text_input(t("ai_model_placeholder"), &self.ai.model)
                    .id(iced::widget::Id::new("set-ai-model"))
                    .on_input(|v| Message::Ai(AiMessage::AiModelChanged(v)))
                    .padding(10)
                    .width(300)
                    .style(crate::widgets::rounded_input_style)
                    .align_x(dir_align_x())
                    .into(),
            );

            let mut provider_col = column![
                panel_field(t("provider"), provider_pick),
                Space::new().height(12),
                panel_field(t("model"), model_input),
                Space::new().height(12),
                self.settings_nav_slot_labeled(
                    t("ai_reasoning"),
                    crate::keynav::RowAction::activate(Message::Ai(
                        AiMessage::ToggleAiReasoning,
                    )),
                    8.0,
                    crate::widgets::toggle_row_desc(
                        t("ai_reasoning"),
                        t("ai_reasoning_desc"),
                        self.ai.reasoning,
                        Message::Ai(AiMessage::ToggleAiReasoning),
                    ),
                ),
                Space::new().height(12),
                self.settings_nav_slot_labeled(
                    t("ai_save_history"),
                    crate::keynav::RowAction::activate(Message::Ai(
                        AiMessage::ToggleAiSaveHistory,
                    )),
                    8.0,
                    crate::widgets::toggle_row_desc(
                        t("ai_save_history"),
                        t("ai_save_history_desc"),
                        self.ai.save_history,
                        Message::Ai(AiMessage::ToggleAiSaveHistory),
                    ),
                ),
            ];

            if current_info.kind == crate::ai::ProviderKind::Custom {
                let url_input: Element<'_, Message> = self.settings_nav_slot_labeled(
                    t("api_url"),
                    crate::keynav::RowAction::input(iced::widget::Id::new("set-ai-url")),
                    10.0,
                    text_input("https://api.example.com/v1/chat/completions", &self.ai.api_url)
                        .id(iced::widget::Id::new("set-ai-url"))
                        .on_input(|v| Message::Ai(AiMessage::AiApiUrlChanged(v)))
                        .padding(10)
                        .width(300)
                        .style(crate::widgets::rounded_input_style)
                        .align_x(dir_align_x())
                        .into(),
                );
                provider_col = provider_col
                    .push(Space::new().height(12))
                    .push(panel_field(crate::i18n::t("api_url"), url_input));
            }

            // When a key is already stored, the input is cleared
            // for security but the placeholder communicates that
            // a key exists, typing replaces it on save.
            let key_placeholder = if self.ai.api_key_set {
                t("ai_key_saved_placeholder")
            } else {
                "sk-..."
            };
            // Keyboard rows: Enter on the ringed row focuses the input
            // via its id; the reveal eye is the next arrow stop. The
            // field row is recorded before the widget is built (the
            // eye slot records during construction). Built here, after
            // the Custom API-URL row, so the rows record in visual
            // order.
            let key_row_idx = self
                .settings_nav_record_labeled(t("api_key"), crate::keynav::RowAction::input(
                    iced::widget::Id::new("set-ai-key"),
                ));
            let key_input: Element<'_, Message> = self.settings_nav_ring_at(
                key_row_idx,
                10.0,
                container(
                    crate::widgets::password_input_with_eye_nav(
                        key_placeholder,
                        &self.ai.api_key,
                        |v| Message::Ai(AiMessage::AiApiKeyChanged(v.into())),
                        Some(Message::Ai(AiMessage::SaveAiApiKey)),
                        self.revealed_secrets
                            .contains(&crate::state::SecretField::AiApiKey),
                        Message::Settings(SettingsMessage::ToggleSecretVisibility(
                            crate::state::SecretField::AiApiKey,
                        )),
                        10.0,
                        Some(iced::widget::Id::new("set-ai-key")),
                        |eye| self.settings_nav_slot(
                            crate::keynav::RowAction::activate(
                                Message::Settings(SettingsMessage::ToggleSecretVisibility(
                                    crate::state::SecretField::AiApiKey,
                                )),
                            ),
                            6.0,
                            eye,
                        ),
                    ),
                )
                .width(280)
                .into(),
            );
            let save_btn = self.settings_nav_slot(
                crate::keynav::RowAction::activate(Message::Ai(AiMessage::SaveAiApiKey)),
                6.0,
                styled_button(crate::i18n::t("save"), Message::Ai(AiMessage::SaveAiApiKey), OryxisColors::t().accent),
            );
            let key_status: Element<'_, Message> = if self.ai.api_key_set {
                dir_row(vec![
                    iced_fonts::lucide::circle_check().size(13).color(OryxisColors::t().success).into(),
                    Space::new().width(6).into(),
                    text(t("api_key_saved")).size(12).color(OryxisColors::t().success).into(),
                ])
                .align_y(iced::Alignment::Center)
                .into()
            } else {
                dir_row(vec![
                    iced_fonts::lucide::circle_alert().size(13).color(OryxisColors::t().text_muted).into(),
                    Space::new().width(6).into(),
                    text(t("no_api_key")).size(12).color(OryxisColors::t().text_muted).into(),
                ])
                .align_y(iced::Alignment::Center)
                .into()
            };

            provider_col = provider_col
                .push(Space::new().height(12))
                .push(panel_field(
                    crate::i18n::t("api_key"),
                    dir_row(vec![key_input, Space::new().width(8).into(), save_btn])
                        .align_y(iced::Alignment::Center)
                        .into(),
                ))
                .push(Space::new().height(4))
                .push(key_status);

            content_col = content_col
                .push(Space::new().height(12))
                .push(panel_section(provider_col));

            // System prompt, multi-line editor that grows with the
            // content. `Length::Shrink` lets the editor auto-resize
            // to fit its text, capped by the panel's scroll area.
            let prompt_editor: Element<'_, Message> = iced::widget::text_editor(&self.ai.system_prompt)
                .placeholder(t("ai_system_prompt_placeholder"))
                .on_action(|v| Message::Ai(AiMessage::AiSystemPromptAction(v)))
                .padding(10)
                .height(Length::Shrink)
                .style(crate::widgets::rounded_text_editor_style)
                .into();
            let prompt_section = panel_section(column![
                panel_field(t("additional_system_prompt"), prompt_editor),
                Space::new().height(4),
                text(t("ai_system_prompt_desc"))
                    .size(11).color(OryxisColors::t().text_muted),
            ]);
            content_col = content_col
                .push(Space::new().height(12))
                .push(prompt_section);
        }

        scrollable(
            container(content_col)
                .padding(Padding { top: 24.0, right: 24.0, bottom: 24.0, left: 24.0 }),
        )
        // Stable id so the keyboard router can keep the selected row
        // in view.
        .id(iced::widget::Id::new("settings-ai-scroll"))
        .on_scroll(|s| Message::Settings(SettingsMessage::SectionScrolled(s.viewport.relative_offset().y)))
        .height(Length::Fill)
        .into()
    }
}
