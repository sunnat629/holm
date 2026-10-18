//! The secret field: Holm's own password entry, used instead of `egui::TextEdit`.
//!
//! `TextEdit` keeps its text in a growing `String`, copies it into undo history and
//! layout caches, publishes it to screen readers as the node's value, and supports
//! select, copy and cut. This widget does none of that. It reads raw input events while
//! it has focus and writes them straight into a [`SecretInput`], which never grows and
//! wipes itself. It paints a fixed row of 12 dots whenever the buffer is non-empty, so
//! neither the screen nor the accessibility tree shows the secret or its length.

use eframe::egui::{
    self, Align2, CornerRadius, CursorIcon, Event, Key, Role, Sense, StrokeKind, TextStyle, pos2,
    vec2,
};

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
    let id = ui.make_persistent_id(id_salt);
    let (_, rect) = ui.allocate_space(vec2(FIELD_WIDTH, LABEL_HEIGHT + BOX_HEIGHT));
    let response = ui
        .interact(rect, id, Sense::click())
        .on_hover_cursor(CursorIcon::Text);
    if response.clicked() {
        response.request_focus();
    }

    let mut out = SecretFieldOutput {
        has_focus: response.has_focus(),
        ..SecretFieldOutput::default()
    };
    if out.has_focus {
        read_events(ui, buf, &mut out);
    }

    ui.ctx().accesskit_node_builder(id, |node| {
        node.set_role(Role::PasswordInput);
        node.set_label(label);
    });

    if ui.is_rect_visible(rect) {
        paint(ui, rect, label, !buf.is_empty(), out.has_focus);
    }
    out
}

/// Applies this frame's input events to `buf`. Only text, Backspace, Enter and Cmd+V
/// count; everything else is ignored. The events are read in place, never cloned.
fn read_events(ui: &egui::Ui, buf: &mut SecretInput, out: &mut SecretFieldOutput) {
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
                    repeat: false,
                    ..
                } => out.submitted = true,
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

/// Paints the label, the box and, for a non-empty secret, exactly [`DOTS`] dots.
fn paint(ui: &egui::Ui, rect: egui::Rect, label: &str, filled: bool, focused: bool) {
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
        vec2(rect.width(), BOX_HEIGHT),
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
    if filled {
        for i in 0..DOTS {
            #[expect(
                clippy::cast_precision_loss,
                reason = "i is below DOTS (12), exact in f32"
            )]
            let x = field.min.x + DOT_INSET + i as f32 * DOT_STEP;
            painter.circle_filled(pos2(x, field.center().y), DOT_RADIUS, visuals.text_color());
        }
    }
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

    fn dots(harness: &Harness<'static, Form>) -> usize {
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
}
