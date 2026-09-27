//! The password-suggest popup (issue #117): credential rows offered at
//! a password prompt, anchored under the terminal caret.
//!
//! It rides the overlay-menu machinery for positioning and chrome but
//! is NOT a menu: it never becomes the keyboard's owner, so it does not
//! record `RowAction` slots and does not appear in `modal_nav_surface`.
//! Selection is a local index in the overlay content, driven by
//! `handle_password_suggest_key`, because the surface underneath is a
//! live PTY and every key not aimed at the popup has to reach it.

use super::*;
use crate::state::PasswordSource;
use iced::widget::column;

/// Vertical metrics of the popup. The builder draws by these and
/// [`password_suggest_menu_height`] sums them, so the height the layout
/// places the box by cannot drift from the box that gets painted.
const TITLE_SIZE: f32 = 11.0;
const LABEL_SIZE: f32 = 12.0;
const SUBLABEL_SIZE: f32 = 10.0;
const HINT_SIZE: f32 = 10.0;
/// The key glyph, which sets the row's floor when the credential has no
/// username to print under its label.
const ICON_SIZE: f32 = 14.0;
const TITLE_PAD: Padding = Padding {
    top: 2.0,
    right: 12.0,
    bottom: 4.0,
    left: 12.0,
};
const ROW_PAD: Padding = Padding {
    top: 6.0,
    right: 12.0,
    bottom: 6.0,
    left: 12.0,
};
const HINT_PAD: Padding = Padding {
    top: 4.0,
    right: 12.0,
    bottom: 2.0,
    left: 12.0,
};
const COLUMN_SPACING: f32 = 2.0;
/// The popup never eats more than this much of the window. A vault with
/// a dozen identities would otherwise cover the terminal the prompt it
/// is answering lives in; past this the list scrolls instead of growing.
const MAX_WINDOW_FRACTION: f32 = 0.6;
/// Scrollable id of the row list, so keyboard navigation can drive it.
pub(crate) const SCROLL_ID: &str = "password-suggest-scroll";

/// Drawn height of one text line. iced's default line height is 1.3x
/// the font size, which the harness measures back exactly (size 12
/// reports 16 px, size 10 reports 13).
fn line_height(size: f32) -> f32 {
    size * 1.3
}

/// Drawn height of one credential row. Two lines when the credential
/// carries a username, and never shorter than the key glyph beside it.
pub(crate) fn password_suggest_row_height(entry: &PasswordSource) -> f32 {
    let labels = if entry.sublabel.is_empty() {
        line_height(LABEL_SIZE)
    } else {
        line_height(LABEL_SIZE) + line_height(SUBLABEL_SIZE)
    };
    ROW_PAD.top + labels.max(line_height(ICON_SIZE)) + ROW_PAD.bottom
}

/// Height of the row list itself: every row plus the gaps between them.
/// This is the scrollable's CONTENT height when the list overflows.
pub(crate) fn password_suggest_rows_height(entries: &[PasswordSource]) -> f32 {
    let rows: f32 = entries.iter().map(password_suggest_row_height).sum();
    rows + (entries.len().saturating_sub(1)) as f32 * COLUMN_SPACING
}

/// Distance from the top of the row list to the top of row `idx`.
pub(crate) fn password_suggest_row_top(entries: &[PasswordSource], idx: usize) -> f32 {
    entries
        .iter()
        .take(idx)
        .map(|e| password_suggest_row_height(e) + COLUMN_SPACING)
        .sum()
}

/// Everything in the box that is NOT a row: the outer padding, the
/// title, the hint and the two gaps around the list.
fn chrome_height() -> f32 {
    let title = TITLE_PAD.top + line_height(TITLE_SIZE) + TITLE_PAD.bottom;
    let hint = HINT_PAD.top + line_height(HINT_SIZE) + HINT_PAD.bottom;
    2.0 * super::menus::MENU_CHROME_PAD_V + title + hint + 2.0 * COLUMN_SPACING
}

/// Resolved vertical layout of the popup for the current window.
pub(crate) struct PopupLayout {
    /// On-screen height of the whole box.
    pub total: f32,
    /// Height handed to the row list, when the list has to scroll.
    /// `None` means every row fits and no scrollable is mounted at all.
    pub rows_viewport: Option<f32>,
}

/// Measure the popup instead of estimating it, because three things
/// ride on the number: the clamp that keeps the box inside the window,
/// the flip over the caret, and now the scroll. The generic per-item
/// guess in `overlay_menu_height` had no way to express a row that is
/// two lines tall only when the credential carries a username, and it
/// came out 26 px short on a one-row popup, which is exactly the hint
/// line plus the bottom padding that a prompt on the last terminal row
/// rendered off the bottom edge of the window.
///
/// The cap is a share of the WINDOW, with one floor: a full row always
/// fits, however short the window gets. A box showing its title and its
/// hint around a sliver of a row offers nothing to pick.
pub(crate) fn password_suggest_layout(entries: &[PasswordSource], window_h: f32) -> PopupLayout {
    let chrome = chrome_height();
    let natural = chrome + password_suggest_rows_height(entries);
    let tallest = entries
        .iter()
        .map(password_suggest_row_height)
        .fold(0.0_f32, f32::max);
    let cap = (window_h * MAX_WINDOW_FRACTION).max(chrome + tallest);
    if natural <= cap {
        return PopupLayout {
            total: natural,
            rows_viewport: None,
        };
    }
    let viewport = cap - chrome;
    PopupLayout {
        total: chrome + viewport,
        rows_viewport: Some(viewport),
    }
}

/// Longest target the title prints before eliding: the popup is a
/// fixed 260 px, and the title is measured as one line.
const TARGET_MAX_CHARS: usize = 32;

fn elide_target(target: &str) -> String {
    if target.chars().count() <= TARGET_MAX_CHARS {
        return target.to_string();
    }
    let head: String = target.chars().take(TARGET_MAX_CHARS - 1).collect();
    format!("{head}\u{2026}")
}

impl Oryxis {
    /// Borrows nothing: every label is cloned into an owned widget, so
    /// the returned element outlives both `self` and the overlay it was
    /// built from (which are two different lifetimes at the call site).
    pub(crate) fn build_menu_password_suggest(
        &self,
        entries: &[crate::state::PasswordSource],
        selected: Option<usize>,
        prompt_for: Option<&str>,
    ) -> Element<'static, Message> {
        // A prompt naming another machine says so in the title, on the
        // one line the layout measures (no wrap, long names elided), so
        // the height the box is placed by stays the height it draws.
        let title_text = match prompt_for {
            Some(target) => crate::i18n::t("password_suggest_title_for")
                .replace("{target}", &elide_target(target)),
            None => crate::i18n::t("password_suggest_title").to_string(),
        };
        let title = container(
            text(title_text)
                .size(TITLE_SIZE)
                .wrapping(iced::widget::text::Wrapping::None)
                .color(OryxisColors::t().text_muted),
        )
        .padding(TITLE_PAD)
        .width(Length::Fill)
        .align_x(dir_align_x());

        // The rows are their own column so the list can be handed a
        // viewport when it overflows; the title and the hint stay
        // OUTSIDE it, because scrolling away the box's own labels would
        // leave a floating stack of credentials with nothing naming it.
        let mut list = iced::widget::Column::new()
            .spacing(COLUMN_SPACING)
            .width(Length::Fill);

        for (idx, entry) in entries.iter().enumerate() {
            let is_selected = selected == Some(idx);
            let mut labels = column![text(entry.label.clone())
                .size(LABEL_SIZE)
                .color(OryxisColors::t().text_primary)];
            if !entry.sublabel.is_empty() {
                labels = labels.push(
                    text(entry.sublabel.clone())
                        .size(SUBLABEL_SIZE)
                        .color(OryxisColors::t().text_muted),
                );
            }
            let row: Element<'static, Message> = button(
                container(
                    dir_row(vec![
                        iced_fonts::lucide::key_round()
                            .size(ICON_SIZE)
                            .color(if is_selected {
                                OryxisColors::t().accent
                            } else {
                                OryxisColors::t().text_secondary
                            })
                            .into(),
                        Space::new().width(8).into(),
                        labels.into(),
                    ])
                    .align_y(iced::Alignment::Center),
                )
                .width(Length::Fill)
                .align_x(dir_align_x()),
            )
            // The row's own index, not the selection: iced fires
            // `on_enter` off a cursor MOVE, so a popup that opens under
            // a stationary pointer (the caret is exactly where the user
            // last clicked) never sees a hover, and a pick that read
            // the selection back would silently do nothing.
            .on_press(Message::Terminal(TerminalMessage::PasswordSuggestPick(idx)))
            .width(Length::Fill)
            .padding(ROW_PAD)
            .style(move |_, status| {
                // The keyboard selection reads like a hover, so the two
                // input paths look the same to the user.
                let bg = if is_selected
                    || matches!(
                        status,
                        iced::widget::button::Status::Hovered
                            | iced::widget::button::Status::Pressed
                    ) {
                    OryxisColors::t().bg_hover
                } else {
                    Color::TRANSPARENT
                };
                button::Style {
                    background: Some(Background::Color(bg)),
                    border: Border {
                        radius: Radius::from(4.0),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            })
            .into();
            // No hover wiring on purpose. The button's own `Hovered`
            // status already highlights the row under the cursor, and
            // hover must never reach `selected`: that would arm Enter,
            // and the popup opens at the caret, right where the pointer
            // usually sits. `selected` is the KEYBOARD's, exclusively.
            list = list.push(row);
        }

        let hint = container(
            text(crate::i18n::t("password_suggest_hint"))
                .size(HINT_SIZE)
                .color(OryxisColors::t().text_muted),
        )
        .padding(HINT_PAD)
        .width(Length::Fill)
        .align_x(dir_align_x());

        // A list that fits is laid out unbounded, so no scrollbar eats
        // width and no gutter shows on the common one-or-two-credential
        // popup. Past the cap it gets a fixed viewport and scrolls, and
        // reports its offset so the keyboard can scroll only when the
        // selection would leave it.
        let layout = password_suggest_layout(entries, self.window_size.height);
        let list: Element<'static, Message> = match layout.rows_viewport {
            Some(h) => iced::widget::scrollable(list)
                .id(iced::widget::Id::new(SCROLL_ID))
                .width(Length::Fill)
                .height(Length::Fixed(h))
                .on_scroll(|scroll| {
                    Message::Terminal(TerminalMessage::PasswordSuggestScrolled(
                        scroll.viewport.absolute_offset().y,
                    ))
                })
                .into(),
            None => list.into(),
        };

        column![title, list, hint]
            .spacing(COLUMN_SPACING)
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::PasswordSourceKind;

    fn entry(sublabel: &str) -> PasswordSource {
        PasswordSource {
            label: "ops-admin".into(),
            sublabel: sublabel.into(),
            kind: PasswordSourceKind::Identity(uuid::Uuid::nil()),
        }
    }

    /// A window tall enough that the cap never bites.
    const ROOMY: f32 = 750.0;

    fn list(n: usize) -> Vec<PasswordSource> {
        (0..n).map(|_| entry("wilson")).collect()
    }

    #[test]
    fn one_credential_with_a_username_measures_what_the_harness_drew() {
        // Measured through the harness at 1200x750: chrome 6+6, title
        // 2+14+4, row 6+16+13+6, hint 4+13+2, three 2 px gaps. The old
        // per-item estimate answered 70 for this popup, and the 26 px
        // it was short is exactly the hint line and the bottom padding
        // that rendered off the window at a prompt on the last row.
        let l = password_suggest_layout(&[entry("wilson")], ROOMY);
        assert!(
            (l.total - 96.0).abs() < 1.0,
            "expected ~96 px for a one-line-subtitle row, got {}",
            l.total
        );
        assert!(l.rows_viewport.is_none(), "one row must not scroll");
    }

    #[test]
    fn a_credential_without_a_username_is_a_shorter_row() {
        // A host saved with no username prints no subtitle, so a flat
        // per-entry constant would be wrong in both directions.
        let with = password_suggest_layout(&[entry("wilson")], ROOMY).total;
        let without = password_suggest_layout(&[entry("")], ROOMY).total;
        let delta = with - without;
        // It does not shrink by the whole subtitle line: with only one
        // label left the row bottoms out on the 14 px key glyph, which
        // is taller than the 12 px label beside it.
        assert!(delta > 0.0 && delta < line_height(SUBLABEL_SIZE));
        let floor = line_height(LABEL_SIZE) + line_height(SUBLABEL_SIZE) - line_height(ICON_SIZE);
        assert!((delta - floor).abs() < 0.01, "got {delta}, expected {floor}");
    }

    #[test]
    fn every_extra_credential_adds_its_own_row() {
        let one = password_suggest_layout(&list(1), ROOMY).total;
        let two = password_suggest_layout(&list(2), ROOMY).total;
        assert!((two - one - (41.0 + COLUMN_SPACING)).abs() < 1.0);
    }

    #[test]
    fn a_long_list_stops_growing_at_the_cap_and_scrolls_instead() {
        // 20 identities with passwords is an ordinary vault, and at
        // ~43 px each they would otherwise bury the terminal the prompt
        // lives in.
        let l = password_suggest_layout(&list(20), ROOMY);
        assert!((l.total - ROOMY * MAX_WINDOW_FRACTION).abs() < 0.01);
        let vp = l.rows_viewport.expect("a capped list must scroll");
        assert!((l.total - chrome_height() - vp).abs() < 0.01);
        // The viewport is what the scroll math measures against, so it
        // must be short of the content it is scrolling.
        assert!(vp < password_suggest_rows_height(&list(20)));
    }

    #[test]
    fn a_full_row_survives_however_short_the_window_is() {
        // The floor beats the fraction: 60% of a 200 px window is less
        // than this popup's own chrome, and a box showing a title and a
        // hint around a sliver of a row offers nothing to pick.
        let l = password_suggest_layout(&list(20), 200.0);
        let vp = l.rows_viewport.expect("still scrolling");
        assert!(
            vp >= password_suggest_row_height(&entry("wilson")),
            "one whole row must fit, got {vp}"
        );
        assert!(l.total > 200.0 * MAX_WINDOW_FRACTION);
    }

    #[test]
    fn row_tops_stack_by_their_own_heights() {
        // Rows are not uniform, so the scroll offset cannot be
        // `idx * ROW_H` the way the SFTP list computes it.
        let mixed = vec![entry(""), entry("wilson"), entry("")];
        assert_eq!(password_suggest_row_top(&mixed, 0), 0.0);
        assert_eq!(
            password_suggest_row_top(&mixed, 1),
            password_suggest_row_height(&mixed[0]) + COLUMN_SPACING
        );
        assert_eq!(
            password_suggest_row_top(&mixed, 2),
            password_suggest_row_height(&mixed[0])
                + password_suggest_row_height(&mixed[1])
                + 2.0 * COLUMN_SPACING
        );
        // The content height is the last row's bottom.
        assert_eq!(
            password_suggest_rows_height(&mixed),
            password_suggest_row_top(&mixed, 2) + password_suggest_row_height(&mixed[2])
        );
    }
}
