//! AI chat sidebar rendering: the assistant message bubbles + the custom
//! markdown viewer that injects Copy / Play buttons into fenced code
//! blocks. The chat tab body itself (message list + input) stays inline in
//! the sidebar shell (`terminal.rs::view_terminal_sidebar`); this module
//! holds the heavy per-message rendering it calls into.

use iced::border::Radius;
use iced::widget::{container, text};
use iced::{Background, Border, Color, Element, Length, Padding};

use crate::app::{AiMessage, Message, Oryxis};
use crate::i18n::t;
use crate::state::{ChatMessage, ChatRole};
use crate::theme::OryxisColors;

impl Oryxis {
    /// Markdown settings shared by every assistant bubble in the chat
    /// sidebar. Built once per sidebar render by the caller; deriving
    /// the style from the theme per message per frame was measurable
    /// on long conversations.
    ///
    /// Compact heading scale, `with_text_size` ramps h1=2x and
    /// h2=1.75x base which reads as huge in a narrow sidebar. We
    /// override to a tighter ladder anchored at 13 px body.
    /// SauceCodePro Nerd Font is bundled in main.rs and carries the
    /// full Nerd Font PUA glyph set. Wire it into the markdown style
    /// so inline `code` and fenced code blocks render
    /// Powerline/Devicon/etc. glyphs the user pastes or the AI emits,
    /// matching what the terminal panel already shows. Body prose
    /// stays on the proportional default; cosmic-text's PUA fallback
    /// isn't reliable enough to count on for non-code text.
    pub(crate) fn chat_markdown_settings(&self) -> iced::widget::markdown::Settings {
        let nerd = iced::Font::new("SauceCodePro Nerd Font");
        // Colours (links, inline-code highlight, code-block chrome) come
        // from the theme's `markdown::Catalog`; only the fonts, sizes and
        // line height are ours. The line height is pinned to the same
        // 1.3 the application default is (`main.rs`): markdown passes its
        // own to every text it builds, so the app-wide pin alone would
        // leave the chat at iced's new 1.375.
        iced::widget::markdown::Settings {
            font: iced::widget::markdown::Settings::default().font,
            inline_code_font: nerd,
            code_block_font: nerd,
            line_height: iced::widget::text::LineHeight::Relative(1.3),
            text_size: 13.into(),
            h1_size: 17.into(),
            h2_size: 15.into(),
            h3_size: 14.into(),
            h4_size: 13.into(),
            h5_size: 13.into(),
            h6_size: 13.into(),
            inline_code_size: 12.into(),
            code_block_size: 12.into(),
            spacing: 8.into(),
            selectable: true,
            group_selection: true,
        }
    }

    pub(crate) fn view_chat_message<'a>(
        &'a self,
        msg: &'a ChatMessage,
        md_settings: iced::widget::markdown::Settings,
    ) -> Element<'a, Message> {
        match msg.role {
            ChatRole::Tool => {
                // A tool execution: the command that ran on a monospace line,
                // and (once captured) its output in a scrollable block. While
                // the output is pending the global "Thinking..." row signals
                // activity, so the bubble just shows the command.
                let nerd = iced::Font::new("SauceCodePro Nerd Font");
                let command = msg
                    .tool
                    .as_ref()
                    .map(|t| t.command.clone())
                    .unwrap_or_else(|| msg.content.clone());
                let cmd_line = iced::widget::row![
                    text("❯").size(12).font(nerd).color(OryxisColors::t().success),
                    iced::widget::Space::new().width(6),
                    text(command)
                        .size(12)
                        .font(nerd)
                        .color(OryxisColors::t().text_primary),
                ]
                .align_y(iced::Alignment::Center);

                let mut col = iced::widget::column![cmd_line].spacing(6);
                if let Some(output) = msg.tool.as_ref().and_then(|t| t.output.as_ref())
                    && !output.trim().is_empty()
                {
                    let out_block = iced::widget::scrollable(
                        container(
                            text(output.clone())
                                .size(11)
                                .font(nerd)
                                .color(OryxisColors::t().text_secondary),
                        )
                        .padding(Padding { top: 6.0, right: 8.0, bottom: 6.0, left: 8.0 })
                        .width(Length::Fill),
                    )
                    .height(Length::Shrink);
                    col = col.push(
                        container(out_block)
                            .height(Length::Shrink.max(220.0))
                            .width(Length::Fill)
                            .style(|_| container::Style {
                                background: Some(Background::Color(Color {
                                    r: 0.09,
                                    g: 0.09,
                                    b: 0.11,
                                    a: 1.0,
                                })),
                                border: Border {
                                    radius: Radius::from(6.0),
                                    ..Default::default()
                                },
                                ..Default::default()
                            }),
                    );
                }

                let bubble = container(col)
                    .padding(Padding { top: 8.0, right: 10.0, bottom: 8.0, left: 10.0 })
                    .width(Length::Fill)
                    .style(|_| container::Style {
                        background: Some(Background::Color(OryxisColors::t().bg_surface)),
                        border: Border {
                            radius: Radius::from(8.0),
                            ..Default::default()
                        },
                        ..Default::default()
                    });
                container(bubble)
                    .width(Length::Fill)
                    .align_x(iced::alignment::Horizontal::Left)
                    .into()
            }
            ChatRole::User => {
                // The accent fill pairs with the per-theme `button_text`
                // (same rule the rest of the CTA buttons follow). User
                // messages stay capped at 280 px and right-aligned to
                // keep the standard chat shape.
                let bubble = container(
                    text(msg.content.as_str())
                        .size(13)
                        .color(OryxisColors::t().button_text),
                )
                .padding(Padding { top: 8.0, right: 12.0, bottom: 8.0, left: 12.0 })
                .width(Length::Shrink.max(280.0))
                .style(|_| container::Style {
                    background: Some(Background::Color(OryxisColors::t().accent)),
                    border: Border { radius: Radius::from(12.0), ..Default::default() },
                    ..Default::default()
                });

                container(bubble)
                    .width(Length::Fill)
                    .align_x(iced::alignment::Horizontal::Right)
                    .into()
            }
            ChatRole::Assistant => {
                // Markdown items are pre-parsed when the message is added
                // to history (state.rs::ChatMessage.parsed_md). The view
                // needs to borrow that slice, so it must outlive the
                // returned Element, which is why we cache, instead of
                // parsing per render.
                // Heading scale / fonts come from `md_settings`, built
                // once per sidebar render in `chat_markdown_settings`.
                // Custom viewer overrides `code_block` to add Copy +
                // Play buttons inside each fenced block; everything
                // else (paragraphs, headings, lists) renders with the
                // default markdown behaviour.
                let md: Element<'_, Message> = iced::widget::markdown::view_with(
                    &msg.parsed_md,
                    md_settings,
                    &ChatMdViewer {
                        theme: self.theme(),
                    },
                );

                // Bubble fills the sidebar width, earlier we clamped
                // at 300 px which left a wide empty strip when the user
                // dragged the sidebar wider. The chat is the only thing
                // in this column, so wider = more useful. Per-code-block
                // Copy / Play buttons are injected by `ChatMdViewer`
                // inside each fenced code block; the bubble itself
                // doesn't need a separate copy affordance.
                let bubble = container(md)
                    .padding(Padding { top: 8.0, right: 12.0, bottom: 8.0, left: 12.0 })
                    .width(Length::Fill)
                    .style(|_| container::Style {
                        background: Some(Background::Color(OryxisColors::t().bg_surface)),
                        text_color: Some(OryxisColors::t().text_primary),
                        border: Border { radius: Radius::from(12.0), ..Default::default() },
                        ..Default::default()
                    });

                container(bubble)
                    .width(Length::Fill)
                    .align_x(iced::alignment::Horizontal::Left)
                    .into()
            }
            ChatRole::System => {
                let bubble = container(
                    text(msg.content.as_str()).size(11).color(OryxisColors::t().text_muted),
                )
                .padding(Padding { top: 6.0, right: 10.0, bottom: 6.0, left: 10.0 })
                .width(Length::Shrink.max(300.0))
                .style(|_| container::Style {
                    background: Some(Background::Color(Color { r: 0.12, g: 0.12, b: 0.14, a: 1.0 })),
                    border: Border { radius: Radius::from(8.0), ..Default::default() },
                    ..Default::default()
                });

                container(bubble)
                    .width(Length::Fill)
                    .align_x(iced::alignment::Horizontal::Left)
                    .into()
            }
            ChatRole::PendingTool => {
                // AI proposed a `risky` command, show it inline with
                // RUN / ALWAYS RUN / DENY buttons. Warning-tinted
                // surface so the user notices it's an action prompt,
                // not a regular message.
                // The three action messages each need an owned copy of
                // the command; the displayed text below borrows it.
                let cmd_for_run = msg.content.clone();
                let cmd_for_always = msg.content.clone();
                let cmd_for_deny = msg.content.clone();
                let warning_subtle = Color {
                    a: 0.12,
                    ..OryxisColors::t().warning
                };
                let warning_border = Color {
                    a: 0.45,
                    ..OryxisColors::t().warning
                };
                let bubble = container(
                    iced::widget::column![
                        iced::widget::row![
                            iced_fonts::lucide::triangle_alert()
                                .size(13)
                                .color(OryxisColors::t().warning),
                            iced::widget::Space::new().width(6),
                            text(t("ai_wants_to_run"))
                                .size(12)
                                .font(iced::Font {
                                    weight: iced::font::Weight::Semibold,
                                    ..iced::Font::new(
                                        crate::theme::SYSTEM_UI_FAMILY
                                    )
                                })
                                .color(OryxisColors::t().text_primary),
                        ]
                        .align_y(iced::Alignment::Center),
                        iced::widget::Space::new().height(6),
                        container(
                            text(msg.content.as_str())
                                .size(12)
                                .font(iced::Font::new("SauceCodePro Nerd Font"))
                                .color(OryxisColors::t().text_primary),
                        )
                        .padding(Padding {
                            top: 6.0,
                            right: 8.0,
                            bottom: 6.0,
                            left: 8.0,
                        })
                        .width(Length::Fill)
                        .style(|_| container::Style {
                            background: Some(Background::Color(
                                OryxisColors::t().bg_surface,
                            )),
                            border: Border {
                                radius: Radius::from(6.0),
                                ..Default::default()
                            },
                            ..Default::default()
                        }),
                        iced::widget::Space::new().height(8),
                        iced::widget::row![
                            pending_tool_btn(
                                t("ai_tool_run"),
                                Message::Ai(AiMessage::ChatToolApprove(cmd_for_run)),
                                OryxisColors::t().accent,
                                OryxisColors::t().button_text,
                            ),
                            pending_tool_btn(
                                t("ai_tool_always"),
                                Message::Ai(AiMessage::ChatToolApproveAlways(cmd_for_always)),
                                OryxisColors::t().success,
                                OryxisColors::t().button_text,
                            ),
                            pending_tool_btn(
                                t("ai_tool_deny"),
                                Message::Ai(AiMessage::ChatToolDeny(cmd_for_deny)),
                                OryxisColors::t().bg_hover,
                                OryxisColors::t().text_primary,
                            ),
                        ]
                        .spacing(6)
                        .align_y(iced::Alignment::Center),
                    ],
                )
                .padding(Padding {
                    top: 10.0,
                    right: 12.0,
                    bottom: 10.0,
                    left: 12.0,
                })
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(Background::Color(warning_subtle)),
                    border: Border {
                        radius: Radius::from(12.0),
                        color: warning_border,
                        width: 1.0,
                    },
                    ..Default::default()
                });

                container(bubble)
                    .width(Length::Fill)
                    .align_x(iced::alignment::Horizontal::Left)
                    .into()
            }
            ChatRole::Error => {
                // Distinct error treatment: red-tinted border, alert
                // icon, "Retry" button. Stops a transient API blip from
                // looking like an actual model reply that the user
                // would otherwise scroll past.
                let bubble = container(
                    iced::widget::column![
                        iced::widget::row![
                            iced_fonts::lucide::circle_alert()
                                .size(13)
                                .color(OryxisColors::t().error),
                            iced::widget::Space::new().width(6),
                            text(t("ai_provider_failed"))
                                .size(12)
                                .color(OryxisColors::t().error),
                        ]
                        .align_y(iced::Alignment::Center),
                        iced::widget::Space::new().height(4),
                        // WordOrGlyph: API error payloads are long JSON
                        // tokens with no spaces; Word wrapping can't break
                        // them and they'd overflow the card border.
                        text(msg.content.as_str())
                            .size(11)
                            .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
                            .color(OryxisColors::t().text_muted),
                        iced::widget::Space::new().height(8),
                        crate::widgets::styled_button(
                            t("retry"),
                            Message::Ai(AiMessage::ChatRetry),
                            OryxisColors::t().accent,
                        ),
                    ],
                )
                .padding(Padding { top: 8.0, right: 12.0, bottom: 8.0, left: 12.0 })
                .width(Length::Fill)
                .style(|_| container::Style {
                    background: Some(Background::Color(Color {
                        a: 0.10,
                        ..OryxisColors::t().error
                    })),
                    border: Border {
                        radius: Radius::from(12.0),
                        color: Color {
                            a: 0.40,
                            ..OryxisColors::t().error
                        },
                        width: 1.0,
                    },
                    ..Default::default()
                });

                container(bubble)
                    .width(Length::Fill)
                    .align_x(iced::alignment::Horizontal::Left)
                    .into()
            }
        }
    }
}

/// Custom markdown viewer that injects Copy / Play buttons inside each
/// fenced code block. Everything else (paragraphs, headings, lists)
/// renders with the iced default. Text widgets in iced 0.14 aren't
/// selectable, so the Copy button is the user's escape hatch for
/// pulling commands out of the assistant's response.
struct ChatMdViewer {
    theme: iced::Theme,
}

impl<'a>
    iced::widget::markdown::Viewer<
        'a,
        Message,
        iced::Theme,
        iced::Renderer,
    > for ChatMdViewer
{
    fn theme(&self) -> &iced::Theme {
        &self.theme
    }

    fn highlighter(
        &self,
    ) -> &dyn iced::widget::markdown::Highlighter<iced::Code, iced::Theme> {
        iced::widget::markdown::Catalog::highlighter(&self.theme)
    }

    fn on_link_click(_url: iced::widget::markdown::Uri) -> Message {
        Message::NoOp
    }

    fn code_block(
        &self,
        settings: iced::widget::markdown::Settings,
        _language: Option<&'a str>,
        code: &'a str,
        lines: &'a [iced::widget::markdown::Text],
    ) -> Element<'a, Message> {
        // Reuse the stock code-block rendering for the actual text /
        // syntax highlighting / horizontal scroll, then stack a tiny
        // toolbar of Copy + Play in the top-right corner. Built with
        // `MouseArea` instead of `button(...)` because the `button`
        // widget chain inside our chat scrollable swallows clicks
        // (same iced quirk `chat_header_btn` works around, see its
        // comment below).
        let body: Element<'a, Message> = iced::widget::markdown::code_block(
            self,
            settings,
            lines,
            Self::on_link_click,
        );
        let copy = iced::widget::MouseArea::new(
            container(
                iced_fonts::lucide::copy()
                    .size(12)
                    .color(OryxisColors::t().text_muted),
            )
            .padding(Padding {
                top: 3.0,
                right: 5.0,
                bottom: 3.0,
                left: 5.0,
            })
            .style(|_| container::Style {
                background: Some(Background::Color(Color {
                    a: 0.10,
                    ..OryxisColors::t().text_secondary
                })),
                border: Border {
                    radius: Radius::from(4.0),
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        .on_press(Message::CopyToClipboard(code.to_string()))
        .interaction(iced::mouse::Interaction::Pointer);
        let play = iced::widget::MouseArea::new(
            container(
                iced_fonts::lucide::play()
                    .size(12)
                    .color(OryxisColors::t().success),
            )
            .padding(Padding {
                top: 3.0,
                right: 5.0,
                bottom: 3.0,
                left: 5.0,
            })
            .style(|_| container::Style {
                background: Some(Background::Color(Color {
                    a: 0.12,
                    ..OryxisColors::t().success
                })),
                border: Border {
                    radius: Radius::from(4.0),
                    ..Default::default()
                },
                ..Default::default()
            }),
        )
        // Manually clicking Play is the user's explicit go-ahead, so
        // we route it through `ChatToolApprove` (run once) and skip
        // the risk gate, re-prompting after a deliberate Play would
        // be redundant.
        .on_press(Message::Ai(AiMessage::ChatToolApprove(code.to_string())))
        .interaction(iced::mouse::Interaction::Pointer);
        let toolbar = container(
            iced::widget::row![copy, iced::widget::Space::new().width(4), play]
                .align_y(iced::Alignment::Center),
        )
        .width(Length::Fill)
        .align_x(iced::alignment::Horizontal::Right)
        .padding(Padding {
            top: 4.0,
            right: 4.0,
            bottom: 0.0,
            left: 0.0,
        });
        iced::widget::Stack::new()
            .push(body)
            .push(toolbar)
            .into()
    }

}

/// Compact segmented Plan / Ask / Auto picker for the chat sidebar. The
/// active mode is accent-filled; the others are quiet outline chips that
/// light up on hover. Each chip sends `ChatModeChanged`, which applies to
/// the active tab and becomes the default for new tabs. A tooltip on each
/// chip explains what the mode does.
pub(crate) fn chat_mode_picker<'a>(current: crate::state::ChatMode) -> Element<'a, Message> {
    use crate::state::ChatMode;
    let chip = |mode: ChatMode, tip_key: &'a str| -> Element<'a, Message> {
        let selected = mode == current;
        let label = text(t(mode.label_key()))
            .size(11)
            .font(iced::Font {
                weight: iced::font::Weight::Semibold,
                ..iced::Font::new(crate::theme::SYSTEM_UI_FAMILY)
            })
            .color(if selected {
                OryxisColors::t().button_text
            } else {
                OryxisColors::t().text_secondary
            });
        let btn = iced::widget::button(label)
            .padding(Padding { top: 3.0, right: 10.0, bottom: 3.0, left: 10.0 })
            .on_press(Message::Ai(AiMessage::ChatModeChanged(mode)))
            .style(move |_, status| {
                let c = OryxisColors::t();
                let bg = if selected {
                    c.accent
                } else {
                    match status {
                        iced::widget::button::Status::Hovered => c.bg_hover,
                        _ => Color::TRANSPARENT,
                    }
                };
                iced::widget::button::Style {
                    background: Some(Background::Color(bg)),
                    text_color: if selected {
                        c.button_text
                    } else {
                        c.text_secondary
                    },
                    border: Border {
                        radius: Radius::from(6.0),
                        width: 1.0,
                        color: if selected { c.accent } else { c.border },
                    },
                    ..Default::default()
                }
            });
        crate::views::terminal::icon_tooltip(btn.into(), t(tip_key))
    };
    iced::widget::row![
        chip(ChatMode::Plan, "ai_mode_plan_tip"),
        chip(ChatMode::Ask, "ai_mode_ask_tip"),
        chip(ChatMode::Auto, "ai_mode_auto_tip"),
    ]
    .spacing(4)
    .align_y(iced::Alignment::Center)
    .into()
}

/// Filled chip-button used by the PendingTool confirmation prompt
/// (`Run` / `Always` / `Deny`). Kept on `MouseArea` (fires on press)
/// historically because clicks here appeared to be "eaten"; the real
/// cause was the terminal canvas capturing every left release
/// (`oryxis-terminal/src/widget.rs`), now gated to only capture releases
/// over itself, so plain `button` works in the sidebar again.
fn pending_tool_btn<'a>(
    label: &'a str,
    msg: Message,
    bg: Color,
    fg: Color,
) -> Element<'a, Message> {
    use iced::widget::MouseArea;
    MouseArea::new(
        container(
            text(label.to_owned())
                .size(12)
                .font(iced::Font {
                    weight: iced::font::Weight::Semibold,
                    ..iced::Font::new(crate::theme::SYSTEM_UI_FAMILY)
                })
                .color(fg),
        )
        .padding(Padding {
            top: 5.0,
            right: 12.0,
            bottom: 5.0,
            left: 12.0,
        })
        .style(move |_| container::Style {
            background: Some(Background::Color(bg)),
            border: Border {
                radius: Radius::from(6.0),
                ..Default::default()
            },
            ..Default::default()
        }),
    )
    .on_press(msg)
    .interaction(iced::mouse::Interaction::Pointer)
    .into()
}
