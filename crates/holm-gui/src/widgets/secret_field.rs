//! The secret field: Holm's own password entry, used instead of `egui::TextEdit`.
//!
//! `TextEdit` keeps its text in a growing `String`, copies it into undo history and
//! layout caches, publishes it to screen readers as the node's value, and supports
//! select, copy and cut. This widget does none of that. It reads raw input events while
//! it has focus and writes them straight into a [`SecretInput`], which never grows and
//! wipes itself. It paints a fixed row of 12 dots whenever the buffer is non-empty, so
//! neither the screen nor the accessibility tree shows the secret or its length.
//!
//! An eye button sits inside the box. While the pointer is held down on it (and still
//! over it, and the window has focus) the secret is painted as plain text instead of
//! dots. Nothing is stored: each frame decides again from the live pointer state, so a
//! release, a drag-off, a window blur or a lock hides the text at once.
//!
//! [`secret_area`] is the same widget with a taller box, for a multiline secret such as
//! a private key: Enter types a newline instead of submitting, the box shows a fixed
//! block of dots, and while the eye is held the secret is painted under the box by
//! [`paint_secret`], wrapped, on as many lines as it has.

use eframe::egui::{
    self, Align2, CornerRadius, CursorIcon, Event, Key, Role, Sense, StrokeKind, TextStyle, pos2,
    vec2,
};

use crate::messages::EYE_LABEL;
use crate::secret_input::SecretInput;

/// Width of the whole field, in points.
const FIELD_WIDTH: f32 = 280.0;
/// Height of the label row above the box, in points.
const LABEL_HEIGHT: f32 = 20.0;
/// Height of the box that holds the dots, in points.
const BOX_HEIGHT: f32 = 30.0;
/// How many dots stand for a non-empty secret, whatever its length.
const DOTS: usize = 12;
/// Radius of one dot, in points.
const DOT_RADIUS: f32 = 3.5;
/// Distance between dot centres, in points.
const DOT_STEP: f32 = 12.0;
/// Space between the box's left edge and the first dot centre, in points.
const DOT_INSET: f32 = 14.0;
/// Inset of the revealed text from the box's left edge, in points.
const TEXT_INSET: f32 = 8.0;
/// Height of a secret area's box, in points: room for several rows of dots.
const AREA_HEIGHT: f32 = 96.0;
/// Rows of dots in a non-empty secret area, whatever its length or line count.
const AREA_DOT_ROWS: u8 = 3;
/// Distance between rows of dots in a secret area, in points.
const AREA_ROW_STEP: f32 = 28.0;

/// Which box a field draws.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoxKind {
    /// One line. Enter submits.
    Line,
    /// Several lines. Enter types a newline.
    Area,
}

impl BoxKind {
    fn height(self) -> f32 {
        match self {
            BoxKind::Line => BOX_HEIGHT,
            BoxKind::Area => AREA_HEIGHT,
        }
    }

    fn dot_rows(self) -> u8 {
        match self {
            BoxKind::Line => 1,
            BoxKind::Area => AREA_DOT_ROWS,
        }
    }
}

/// What happened to a [`secret_field`] this frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecretFieldOutput {
    /// Enter was pressed while the field had focus.
    pub submitted: bool,
    /// The secret changed (typed or deleted characters).
    pub changed: bool,
    /// The field has keyboard focus.
    pub has_focus: bool,
    /// Cmd+V was pressed while the field had focus. The field does not paste by itself;
    /// the caller decides what to put in.
    pub paste_requested: bool,
    /// The eye button is held down this frame, so the secret is painted as text.
    pub revealing: bool,
}

/// Draws a secret field labelled `label` that types into `buf`.
///
/// `id_salt` must be unique within the parent `Ui`. The field takes focus on click (or
/// through the accessibility Focus action). While focused it reads `Event::Text`,
/// Backspace, Enter and Cmd+V, and ignores every other event: there is no selection,
/// undo, copy or cut. Its AccessKit node has the role `PasswordInput` and the fixed
/// label only: no value and no description.
pub fn secret_field(
    ui: &mut egui::Ui,
    id_salt: &str,
    label: &'static str,
    buf: &mut SecretInput,
) -> SecretFieldOutput {
    draw(ui, id_salt, label, buf, BoxKind::Line)
}

/// Draws a multiline secret field labelled `label` that types into `buf`.
///
/// Same rules as [`secret_field`]: the AccessKit node is `PasswordInput` with the fixed
/// label only, no value and no description, and there is no selection, undo, copy or
/// cut. Enter types a newline (kept only if `buf` was made with
/// [`SecretInput::with_multiline_capacity`]) and never sets `submitted`. While the eye is
/// held, the secret is painted under the box with [`paint_secret`]; the box itself
/// shows a fixed block of dots otherwise.
pub fn secret_area(
    ui: &mut egui::Ui,
    id_salt: &str,
    label: &'static str,
    buf: &mut SecretInput,
) -> SecretFieldOutput {
    draw(ui, id_salt, label, buf, BoxKind::Area)
}

/// The shared body of [`secret_field`] and [`secret_area`].
fn draw(
    ui: &mut egui::Ui,
    id_salt: &str,
    label: &'static str,
    buf: &mut SecretInput,
    kind: BoxKind,
) -> SecretFieldOutput {
    let id = ui.make_persistent_id(id_salt);
    let (_, rect) = ui.allocate_space(vec2(FIELD_WIDTH, LABEL_HEIGHT + kind.height()));
    let response = ui
        .interact(rect, id, Sense::click())
        .on_hover_cursor(CursorIcon::Text);

    // The eye is registered after the field, so it wins the hit test where they overlap.
    let eye_rect = eye_rect(rect);
    let eye_id = ui.make_persistent_id((id_salt, "eye"));
    let eye = ui
        // click_and_drag, not click: a click-only press is dropped by egui after 0.8 s or a
        // 6 pt move, which would end the hold early.
        .interact(eye_rect, eye_id, Sense::click_and_drag())
        .on_hover_cursor(CursorIcon::Default);
    let window_focused = ui.input(|i| i.focused && i.viewport().focused != Some(false));
    let held_by_pointer =
        eye.is_pointer_button_down_on() && eye.contains_pointer() && window_focused;
    let held_by_key = eye.has_focus() && window_focused && ui.input(|i| i.key_down(Key::Space));
    let revealing = held_by_pointer || held_by_key;

    // Holding the eye must not take typing focus away from the field. A pointer press moves
    // focus. While the eye has keyboard focus, an allowlist stays on the eye: Space (key
    // press and release, and its " " text, which is the reveal key and never typed), Tab
    // (focus navigation), key releases, and anything that is not input. Every other key
    // press, text, paste or cut hands focus to the field in the same frame so it is read
    // there and nothing is dropped. Egui has no keys for bare modifiers, so those never
    // reach this match.
    let input_for_field = eye.has_focus()
        && ui.input(|i| {
            i.events.iter().any(|e| match e {
                Event::Text(t) => t != " ",
                Event::Key {
                    key, pressed: true, ..
                } => !matches!(key, Key::Space | Key::Tab),
                Event::Paste(_) | Event::Cut => true,
                _ => false,
            })
        });
    if response.clicked() || eye.is_pointer_button_down_on() || input_for_field {
        // Input while the eye has focus hands focus to the field instead of dropping it.
        response.request_focus();
    }

    let mut out = SecretFieldOutput {
        has_focus: response.has_focus(),
        revealing,
        ..SecretFieldOutput::default()
    };
    if out.has_focus {
        read_events(ui, buf, &mut out, kind);
    }

    ui.ctx().accesskit_node_builder(id, |node| {
        node.set_role(Role::PasswordInput);
        node.set_label(label);
    });
    ui.ctx().accesskit_node_builder(eye_id, |node| {
        node.set_role(Role::Button);
        node.set_label(EYE_LABEL);
    });

    // An area's revealed text is painted under the box, wrapped, not clipped into it.
    let painted_below = kind == BoxKind::Area && revealing && !buf.is_empty();
    if ui.is_rect_visible(rect) {
        let content = if buf.is_empty() || painted_below {
            Content::Empty
        } else if revealing {
            Content::Text(buf.expose_for_paint())
        } else {
            Content::Dots
        };
        paint(ui, rect, label, content, out.has_focus, revealing, kind);
    }
    if painted_below {
        paint_secret(ui, buf.expose_for_paint());
    }
    out
}

/// Paints `text` read-only in monospace, wrapped to the panel, on as many lines as it
/// has. Painted, not a widget: no text edit, no selection, no accessibility value.
///
/// The galley egui lays out from `text` is a plain copy that is not wiped (the known
/// galley-cache gap). Never also put the text in a widget.
pub(crate) fn paint_secret(ui: &mut egui::Ui, text: &str) {
    let font = TextStyle::Monospace.resolve(ui.style());
    let color = ui.visuals().strong_text_color();
    let galley = ui
        .painter()
        .layout(text.to_owned(), font, color, ui.available_width());
    let (rect, _) = ui.allocate_exact_size(galley.size(), Sense::hover());
    ui.painter().galley(rect.min, galley, color);
}

/// The square eye button at the right end of the box.
fn eye_rect(rect: egui::Rect) -> egui::Rect {
    egui::Rect::from_min_size(
        pos2(rect.max.x - BOX_HEIGHT, rect.min.y + LABEL_HEIGHT),
        vec2(BOX_HEIGHT, BOX_HEIGHT),
    )
}

/// What the box shows.
enum Content<'a> {
    Empty,
    Dots,
    Text(&'a str),
}

/// Applies this frame's input events to `buf`. Only text, Backspace, Enter and Cmd+V
/// count; everything else is ignored. The events are read in place, never cloned. In a
/// line Enter submits; in an area it types a newline.
fn read_events(ui: &egui::Ui, buf: &mut SecretInput, out: &mut SecretFieldOutput, kind: BoxKind) {
    ui.input(|input| {
        for event in &input.events {
            match event {
                Event::Text(text) => {
                    let before = buf.char_count();
                    buf.push_str(text);
                    out.changed |= buf.char_count() != before;
                }
                Event::Key {
                    key: Key::Backspace,
                    pressed: true,
                    ..
                } => {
                    if !buf.is_empty() {
                        buf.pop_char();
                        out.changed = true;
                    }
                }
                Event::Key {
                    key: Key::Enter,
                    pressed: true,
                    repeat,
                    ..
                } => match kind {
                    BoxKind::Line => out.submitted |= !*repeat,
                    BoxKind::Area => {
                        let before = buf.char_count();
                        buf.push_str("\n");
                        out.changed |= buf.char_count() != before;
                    }
                },
                Event::Key {
                    key: Key::V,
                    pressed: true,
                    repeat: false,
                    modifiers,
                    ..
                } if modifiers.command => out.paste_requested = true,
                _ => {}
            }
        }
    });
}

/// Paints the label, the box, the eye and the content: nothing, a fixed block of
/// [`DOTS`] dots per row, or (while the eye is held, line only) the secret as one line
/// of text.
fn paint(
    ui: &egui::Ui,
    rect: egui::Rect,
    label: &str,
    content: Content<'_>,
    focused: bool,
    eye_down: bool,
    kind: BoxKind,
) {
    let visuals = ui.visuals();
    let painter = ui.painter();
    painter.text(
        rect.min,
        Align2::LEFT_TOP,
        label,
        TextStyle::Body.resolve(ui.style()),
        visuals.text_color(),
    );
    let field = egui::Rect::from_min_size(
        pos2(rect.min.x, rect.min.y + LABEL_HEIGHT),
        vec2(rect.width(), kind.height()),
    );
    let stroke = if focused {
        visuals.selection.stroke
    } else {
        visuals.widgets.inactive.bg_stroke
    };
    painter.rect(
        field,
        CornerRadius::same(4),
        visuals.extreme_bg_color,
        stroke,
        StrokeKind::Inside,
    );
    match content {
        Content::Empty => {}
        Content::Dots => {
            for row in 0..kind.dot_rows() {
                let y = field.min.y + BOX_HEIGHT / 2.0 + f32::from(row) * AREA_ROW_STEP;
                for i in 0..DOTS {
                    #[expect(
                        clippy::cast_precision_loss,
                        reason = "i is below DOTS (12), exact in f32"
                    )]
                    let x = field.min.x + DOT_INSET + i as f32 * DOT_STEP;
                    painter.circle_filled(pos2(x, y), DOT_RADIUS, visuals.text_color());
                }
            }
        }
        Content::Text(text) => {
            let mut area = field;
            area.max.x -= BOX_HEIGHT;
            painter.with_clip_rect(area).text(
                pos2(area.min.x + TEXT_INSET, area.center().y),
                Align2::LEFT_CENTER,
                text,
                TextStyle::Body.resolve(ui.style()),
                visuals.text_color(),
            );
        }
    }
    paint_eye(ui, eye_rect(rect), eye_down);
}

/// Draws the eye from lines and a diamond. No circles (the dots are circles), and no
/// emoji (the app installs one font, which has no eye glyph).
fn paint_eye(ui: &egui::Ui, rect: egui::Rect, down: bool) {
    let visuals = ui.visuals();
    let painter = ui.painter();
    let color = if down {
        visuals.selection.stroke.color
    } else {
        visuals.weak_text_color()
    };
    let stroke = egui::Stroke::new(1.5, color);
    let c = rect.center();
    let half_w = 8.0_f32;
    let half_h = 5.0_f32;
    let steps = 12_u8;
    let arc = |sign: f32| -> Vec<egui::Pos2> {
        (0..=steps)
            .map(|k| {
                let t = f32::from(k) / f32::from(steps) * 2.0 - 1.0;
                pos2(c.x + t * half_w, c.y + sign * half_h * (1.0 - t * t))
            })
            .collect()
    };
    painter.add(egui::Shape::line(arc(-1.0), stroke));
    painter.add(egui::Shape::line(arc(1.0), stroke));
    let r = 2.5_f32;
    painter.add(egui::Shape::convex_polygon(
        vec![
            pos2(c.x - r, c.y),
            pos2(c.x, c.y - r),
            pos2(c.x + r, c.y),
            pos2(c.x, c.y + r),
        ],
        color,
        egui::Stroke::NONE,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_input::MASTER_CAP;
    use egui::accesskit::Role;
    use egui::epaint::Shape;
    use egui::{Event, Key, Modifiers, OutputCommand};
    use egui_kittest::Harness;
    use egui_kittest::kittest::{NodeT, Queryable};

    const LABEL: &str = "Master password";
    const OTHER_LABEL: &str = "Confirm master password";

    struct Form {
        first: SecretInput,
        second: SecretInput,
        last: SecretFieldOutput,
        pastes: usize,
        submits: usize,
    }

    impl Form {
        fn new() -> Form {
            Form {
                first: SecretInput::with_capacity(MASTER_CAP),
                second: SecretInput::with_capacity(MASTER_CAP),
                last: SecretFieldOutput::default(),
                pastes: 0,
                submits: 0,
            }
        }
    }

    fn harness() -> Harness<'static, Form> {
        let mut harness = Harness::builder()
            .with_context_setup(crate::fonts::install_fonts)
            .build_ui_state(
                |ui, form: &mut Form| {
                    let out = secret_field(ui, "first", LABEL, &mut form.first);
                    form.pastes += usize::from(out.paste_requested);
                    form.submits += usize::from(out.submitted);
                    form.last = out;
                    let _ = secret_field(ui, "second", OTHER_LABEL, &mut form.second);
                },
                Form::new(),
            );
        harness.run();
        harness
    }

    fn focus_first(harness: &mut Harness<'static, Form>) {
        harness.get_by_label(LABEL).click();
        harness.run();
        assert!(harness.state().last.has_focus);
    }

    fn dots<S>(harness: &Harness<'static, S>) -> usize {
        harness
            .output()
            .shapes
            .iter()
            .filter(|clipped| matches!(clipped.shape, Shape::Circle(_)))
            .count()
    }

    #[test]
    fn typing_fills_buffer() {
        let mut harness = harness();
        focus_first(&mut harness);
        harness.event(Event::Text("abc".to_owned()));
        harness.step();
        assert_eq!(harness.state().first.char_count(), 3);
        assert!(harness.state().last.changed);
        harness.key_press(Key::Backspace);
        harness.run();
        assert_eq!(harness.state().first.char_count(), 2);
        assert!(harness.state().second.is_empty());
    }

    #[test]
    fn unfocused_field_ignores_text() {
        let mut harness = harness();
        harness.event(Event::Text("abc".to_owned()));
        harness.key_press(Key::Enter);
        harness.run();
        assert!(harness.state().first.is_empty());
        assert!(harness.state().second.is_empty());
        assert_eq!(harness.state().submits, 0);
        assert!(!harness.state().last.has_focus);

        // Focus moves to the second field: text goes there only.
        harness.get_by_label(OTHER_LABEL).click();
        harness.run();
        harness.event(Event::Text("xy".to_owned()));
        harness.run();
        assert!(harness.state().first.is_empty());
        assert_eq!(harness.state().second.char_count(), 2);
    }

    #[test]
    fn accessibility_focus_action_focuses() {
        let mut harness = harness();
        harness.get_by_label(LABEL).focus();
        harness.run();
        assert!(harness.state().last.has_focus);
        harness.event(Event::Text("ab".to_owned()));
        harness.run();
        assert_eq!(harness.state().first.char_count(), 2);
    }

    #[test]
    fn enter_submits() {
        let mut harness = harness();
        focus_first(&mut harness);
        harness.key_press(Key::Enter);
        harness.run();
        assert_eq!(harness.state().submits, 1);
        assert!(harness.state().first.is_empty());
    }

    #[test]
    fn secret_field_publishes_no_value() {
        let mut harness = harness();
        focus_first(&mut harness);
        harness.event(Event::Text("EXAMPLE-pw".to_owned()));
        harness.run();
        assert_eq!(harness.state().first.char_count(), 10);

        let node = harness.get_by_label(LABEL);
        let access = node.accesskit_node();
        assert_eq!(access.role(), Role::PasswordInput);
        assert_eq!(node.value(), None);
        assert_eq!(access.label().as_deref(), Some(LABEL));
        assert_eq!(access.description(), None);
        assert!(node.is_focused());
    }

    #[test]
    fn copy_cut_and_selection_ignored() {
        let mut harness = harness();
        focus_first(&mut harness);
        harness.event(Event::Text("abc".to_owned()));
        harness.run();
        let before = harness.output().platform_output.commands.clone();
        assert!(before.is_empty());

        harness.event(Event::Copy);
        harness.event(Event::Cut);
        harness.key_press_modifiers(Modifiers::COMMAND, Key::A);
        harness.step();

        assert_eq!(harness.state().first.char_count(), 3);
        let output = &harness.output().platform_output;
        assert_eq!(output.commands, before);
        assert!(
            !output
                .commands
                .iter()
                .any(|c| matches!(c, OutputCommand::CopyText(_)))
        );
        assert!(output.ime.is_none());
        assert_eq!(harness.state().pastes, 0);
    }

    #[test]
    fn cmd_v_requests_paste() {
        let mut harness = harness();
        focus_first(&mut harness);
        harness.key_press_modifiers(Modifiers::COMMAND, Key::V);
        harness.run();
        assert_eq!(harness.state().pastes, 1);
        // The field does not paste by itself (Task 5 does), and a plain V is not a paste.
        assert!(harness.state().first.is_empty());
        harness.key_press(Key::V);
        harness.run();
        assert_eq!(harness.state().pastes, 1);
    }

    #[test]
    fn unfocused_cmd_v_is_not_a_paste() {
        let mut harness = harness();
        harness.key_press_modifiers(Modifiers::COMMAND, Key::V);
        harness.run();
        assert_eq!(harness.state().pastes, 0);
    }

    #[test]
    fn held_enter_and_held_paste_fire_once() {
        let mut harness = harness();
        focus_first(&mut harness);
        for repeat in [false, true, true] {
            harness.event(Event::Key {
                key: Key::Enter,
                physical_key: None,
                pressed: true,
                repeat,
                modifiers: Modifiers::NONE,
            });
            harness.event(Event::Key {
                key: Key::V,
                physical_key: None,
                pressed: true,
                repeat,
                modifiers: Modifiers::COMMAND,
            });
        }
        harness.step();
        assert_eq!(harness.state().submits, 1);
        assert_eq!(harness.state().pastes, 1);
    }

    #[test]
    fn paste_and_ime_events_are_ignored() {
        let mut harness = harness();
        focus_first(&mut harness);
        harness.event(Event::Paste("EXAMPLE-pasted".to_owned()));
        harness.event(Event::Ime(egui::ImeEvent::Commit("EXAMPLE-ime".to_owned())));
        harness.step();
        assert!(harness.state().first.is_empty());
        assert_eq!(harness.state().pastes, 0);
    }

    #[test]
    fn dots_hide_the_length() {
        let mut harness = harness();
        assert_eq!(dots(&harness), 0);
        focus_first(&mut harness);
        harness.event(Event::Text("a".to_owned()));
        harness.run();
        assert_eq!(dots(&harness), 12);
        harness.event(Event::Text("bcdefghijklmnopqrstuvwxyz".to_owned()));
        harness.run();
        assert_eq!(dots(&harness), 12);
    }

    // ---- press-and-hold eye ----

    use crate::messages::EYE_LABEL;
    use egui::{PointerButton, Pos2};

    fn eye_pos<S>(harness: &Harness<'static, S>) -> Pos2 {
        harness
            .get_all_by_role_and_label(Role::Button, EYE_LABEL)
            .next()
            .expect("first eye")
            .rect()
            .center()
    }

    fn press_eye<S>(harness: &mut Harness<'static, S>) {
        let pos = eye_pos(harness);
        harness.hover_at(pos);
        harness.step();
        harness.drag_at(pos);
        harness.step();
    }

    fn type_secret(harness: &mut Harness<'static, Form>) {
        focus_first(harness);
        harness.event(Event::Text("EXAMPLE-pw".to_owned()));
        harness.run();
    }

    fn texts<S>(harness: &Harness<'static, S>) -> Vec<String> {
        harness
            .output()
            .shapes
            .iter()
            .filter_map(|clipped| match &clipped.shape {
                Shape::Text(t) => Some(t.galley.text().to_owned()),
                _ => None,
            })
            .collect()
    }

    fn secret_texts(harness: &Harness<'static, Form>) -> usize {
        texts(harness)
            .iter()
            .filter(|t| t.contains("EXAMPLE-pw"))
            .count()
    }

    #[test]
    fn eye_hold_paints_text_not_dots() {
        let mut harness = harness();
        type_secret(&mut harness);
        assert_eq!(dots(&harness), 12);
        assert_eq!(secret_texts(&harness), 0);
        press_eye(&mut harness);
        assert!(harness.state().last.revealing);
        assert_eq!(dots(&harness), 0);
        assert_eq!(secret_texts(&harness), 1);
    }

    #[test]
    fn eye_release_hides() {
        let mut harness = harness();
        type_secret(&mut harness);
        press_eye(&mut harness);
        assert!(harness.state().last.revealing);
        let pos = eye_pos(&harness);
        harness.event(Event::PointerButton {
            pos,
            button: PointerButton::Primary,
            pressed: false,
            modifiers: Modifiers::NONE,
        });
        harness.run();
        assert!(!harness.state().last.revealing);
        assert_eq!(dots(&harness), 12);
        assert_eq!(secret_texts(&harness), 0);
    }

    #[test]
    fn eye_drag_off_hides() {
        let mut harness = harness();
        type_secret(&mut harness);
        press_eye(&mut harness);
        assert!(harness.state().last.revealing);
        harness.hover_at(Pos2::new(5.0, 400.0));
        harness.step();
        assert!(!harness.state().last.revealing);
        assert_eq!(secret_texts(&harness), 0);
        assert_eq!(dots(&harness), 12);
    }

    #[test]
    fn eye_is_not_a_toggle() {
        let mut harness = harness();
        type_secret(&mut harness);
        let pos = eye_pos(&harness);
        harness.hover_at(pos);
        harness.step();
        harness.drag_at(pos);
        harness.step();
        harness.drop_at(pos);
        harness.run();
        // A full click has finished: nothing stays revealed.
        harness.hover_at(pos);
        harness.run();
        assert!(!harness.state().last.revealing);
        assert_eq!(secret_texts(&harness), 0);
        assert_eq!(dots(&harness), 12);
    }

    #[test]
    fn eye_hides_on_window_blur() {
        let mut harness = harness();
        type_secret(&mut harness);
        press_eye(&mut harness);
        assert!(harness.state().last.revealing);
        harness.input_mut().focused = false;
        harness.event(Event::WindowFocused(false));
        harness.step();
        assert!(!harness.state().last.revealing);
        assert_eq!(secret_texts(&harness), 0);
        assert_eq!(dots(&harness), 12);
    }

    #[test]
    fn eye_label_and_role() {
        let mut harness = harness();
        type_secret(&mut harness);
        assert_eq!(
            harness
                .get_all_by_role_and_label(Role::Button, EYE_LABEL)
                .count(),
            2
        );
        let node = harness.get_by_role_and_label(Role::PasswordInput, LABEL);
        assert_eq!(node.value(), None);
        press_eye(&mut harness);
        // Even while revealed, the tree never carries the secret.
        let leaked = harness.root().children_recursive().any(|n| {
            let a = n.accesskit_node();
            [a.label(), a.value(), a.description()]
                .iter()
                .flatten()
                .any(|t| t.contains("EXAMPLE"))
        });
        assert!(!leaked);
    }

    #[test]
    fn eye_long_hold_keeps_reveal() {
        let mut harness = harness();
        type_secret(&mut harness);
        press_eye(&mut harness);
        assert!(harness.state().last.revealing);
        // 140 steps of 0.25 s: far past egui's 0.8 s click timeout.
        for _ in 0..140 {
            harness.step();
            assert!(harness.state().last.revealing);
        }
        assert_eq!(secret_texts(&harness), 1);
        assert_eq!(dots(&harness), 0);
    }

    #[test]
    fn eye_small_drag_off_hides() {
        let mut harness = harness();
        type_secret(&mut harness);
        let eye = harness
            .get_all_by_role_and_label(Role::Button, EYE_LABEL)
            .next()
            .expect("first eye")
            .rect();
        let inside = Pos2::new(eye.min.x + 2.0, eye.center().y);
        harness.hover_at(inside);
        harness.step();
        harness.drag_at(inside);
        harness.step();
        assert!(harness.state().last.revealing);
        // 5 pt left: out of the eye, but under egui's 6 pt click-drag threshold.
        harness.hover_at(Pos2::new(inside.x - 5.0, inside.y));
        harness.step();
        assert!(!harness.state().last.revealing);
        assert_eq!(secret_texts(&harness), 0);
        assert_eq!(dots(&harness), 12);
    }

    fn space(harness: &mut Harness<'static, Form>, pressed: bool, repeat: bool) {
        harness.event(Event::Key {
            key: Key::Space,
            physical_key: None,
            pressed,
            repeat,
            modifiers: Modifiers::NONE,
        });
        if pressed {
            harness.event(Event::Text(" ".to_owned()));
        }
        harness.step();
    }

    fn focus_eye(harness: &mut Harness<'static, Form>) {
        harness
            .get_all_by_role_and_label(Role::Button, EYE_LABEL)
            .next()
            .expect("first eye")
            .focus();
        harness.run();
    }

    #[test]
    // kittest runs one frame per event, so Key::Space and Text(" ") cannot share a frame here
    // as they do under egui-winit. Do not drop the `t != " "` filter because this is green.
    fn space_on_focused_eye_reveals_and_never_types() {
        let mut harness = harness();
        type_secret(&mut harness);
        focus_eye(&mut harness);
        assert!(!harness.state().last.has_focus);
        space(&mut harness, true, false);
        assert!(harness.state().last.revealing);
        space(&mut harness, true, true);
        assert!(harness.state().last.revealing);
        assert_eq!(harness.state().first.char_count(), 10);
        space(&mut harness, false, false);
        harness.run();
        assert!(!harness.state().last.revealing);
        assert_eq!(harness.state().first.char_count(), 10);
        assert_eq!(secret_texts(&harness), 0);
    }

    #[test]
    fn typing_with_eye_focused_goes_to_the_field() {
        let mut harness = harness();
        type_secret(&mut harness);
        focus_eye(&mut harness);
        harness.event(Event::Text("x".to_owned()));
        harness.run();
        assert_eq!(harness.state().first.char_count(), 11);
        assert!(harness.state().last.has_focus);
        assert!(harness.state().second.is_empty());
    }

    #[test]
    fn paste_with_eye_focused_goes_to_the_field() {
        let mut harness = harness();
        type_secret(&mut harness);
        focus_eye(&mut harness);
        harness.key_press_modifiers(Modifiers::COMMAND, Key::V);
        harness.run();
        assert_eq!(harness.state().pastes, 1);
        assert!(harness.state().last.has_focus);
        assert_eq!(harness.state().first.char_count(), 10);
    }

    #[test]
    fn enter_with_eye_focused_submits() {
        let mut harness = harness();
        type_secret(&mut harness);
        focus_eye(&mut harness);
        harness.key_press(Key::Enter);
        harness.run();
        assert_eq!(harness.state().submits, 1);
        assert!(harness.state().last.has_focus);
        assert_eq!(harness.state().first.char_count(), 10);
    }

    #[test]
    fn backspace_with_eye_focused_goes_to_the_field() {
        let mut harness = harness();
        type_secret(&mut harness);
        focus_eye(&mut harness);
        harness.key_press(Key::Backspace);
        harness.run();
        assert_eq!(harness.state().first.char_count(), 9);
        assert!(harness.state().last.has_focus);
    }

    // ---- multiline secret area ----

    use crate::secret_input::MULTILINE_SECRET_CAP;

    const AREA_LABEL: &str = "SSH private key";

    struct Area {
        buf: SecretInput,
        last: SecretFieldOutput,
    }

    fn area_harness() -> Harness<'static, Area> {
        let mut harness = Harness::builder()
            .with_context_setup(crate::fonts::install_fonts)
            .build_ui_state(
                |ui, area: &mut Area| {
                    area.last = secret_area(ui, "area", AREA_LABEL, &mut area.buf);
                },
                Area {
                    buf: SecretInput::with_multiline_capacity(MULTILINE_SECRET_CAP),
                    last: SecretFieldOutput::default(),
                },
            );
        harness.run();
        harness
    }

    fn tree_has_example<S>(harness: &Harness<'static, S>) -> bool {
        harness.root().children_recursive().any(|n| {
            let a = n.accesskit_node();
            [a.label(), a.value(), a.description()]
                .iter()
                .flatten()
                .any(|t| t.contains("EXAMPLE"))
        })
    }

    #[test]
    fn secret_area_types_newlines_and_publishes_no_value() {
        let mut harness = area_harness();
        harness.get_by_label(AREA_LABEL).click();
        harness.run();
        assert!(harness.state().last.has_focus);
        harness.event(Event::Text("EXAMPLE-one".to_owned()));
        harness.key_press(Key::Enter);
        harness.event(Event::Text("EXAMPLE-two".to_owned()));
        harness.run();
        assert_eq!(
            harness.state().buf.expose_for_paint(),
            "EXAMPLE-one\nEXAMPLE-two"
        );
        assert!(!harness.state().last.submitted, "Enter is a newline here");

        let node = harness.get_by_role_and_label(Role::PasswordInput, AREA_LABEL);
        assert_eq!(node.value(), None);
        assert_eq!(node.accesskit_node().description(), None);
        assert!(!tree_has_example(&harness));
        // A fixed block of dots, and no secret text painted.
        assert_eq!(dots(&harness), 12 * usize::from(AREA_DOT_ROWS));
        assert!(texts(&harness).iter().all(|t| !t.contains("EXAMPLE")));
    }

    #[test]
    fn secret_area_hold_paints_below_and_release_hides() {
        let mut harness = area_harness();
        harness.get_by_label(AREA_LABEL).click();
        harness.run();
        harness.event(Event::Text("EXAMPLE-one".to_owned()));
        harness.key_press(Key::Enter);
        harness.event(Event::Text("EXAMPLE-two".to_owned()));
        harness.run();

        press_eye(&mut harness);
        assert!(harness.state().last.revealing);
        assert_eq!(dots(&harness), 0);
        assert!(
            texts(&harness)
                .iter()
                .any(|t| t.contains("EXAMPLE-one\nEXAMPLE-two"))
        );
        assert!(!tree_has_example(&harness), "painted, never in the tree");

        let pos = eye_pos(&harness);
        harness.event(Event::PointerButton {
            pos,
            button: PointerButton::Primary,
            pressed: false,
            modifiers: Modifiers::NONE,
        });
        harness.run();
        assert!(!harness.state().last.revealing);
        assert!(texts(&harness).iter().all(|t| !t.contains("EXAMPLE")));
    }

    #[test]
    fn tab_and_modifier_keys_stay_on_the_eye() {
        let mut harness = harness();
        type_secret(&mut harness);
        focus_eye(&mut harness);
        harness.key_press_modifiers(Modifiers::SHIFT, Key::Space);
        harness.run();
        assert!(!harness.state().last.has_focus);
        // Tab from the field lands on the eye and must not be pulled back to the field.
        harness.get_by_label(LABEL).focus();
        harness.run();
        assert!(harness.state().last.has_focus);
        harness.key_press(Key::Tab);
        harness.run();
        assert!(!harness.state().last.has_focus);
        assert_eq!(harness.state().first.char_count(), 10);
    }
}
