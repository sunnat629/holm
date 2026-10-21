//! The selected item, read-only: one `match` over the four item shapes.
//!
//! Every secret field starts hidden (a row of dots) and has a Reveal and a Copy button.
//! At most one field shows at a time, for a short while (`revealed` holds which one and
//! until when, on the UI clock). A shown field hides on its timer, when the window loses
//! focus, when another item is selected, on Edit and on lock (the last three drop the
//! whole [`ItemView`]).
//!
//! A login's password shows in a plain non-selectable label, as before. Every other
//! revealed field is painted straight from the item's wiping buffer, so it is never in
//! a text edit, never selectable and never in an accessibility label or value.
//!
//! A recovery phrase is gated: "Reveal…" opens a password field, the check runs on the
//! worker ([`Job::RevealPhrase`]), and the words come back in a wiping
//! [`SecretText`] that is dropped as soon as the phrase hides. Every reveal asks for
//! the password again.
//!
//! Every Copy goes through Holm's clipboard and `io.copied`, so the app schedules its
//! clear the same way for every field.

use std::time::Duration;

use eframe::egui;
use holm_core::error::CoreError;
use holm_core::item::{Item, ItemData};
use holm_core::settings::{REHIDE_PASSWORD_SECS, REHIDE_PHRASE_SECS};
use holm_core::text::SecretText;
use holm_core::throttle::ThrottleStatus;
use zeroize::Zeroizing;

use super::FieldIo;
use crate::messages;
use crate::secret_input::{MASTER_CAP, SecretInput};
use crate::worker::Job;

/// Label of the edit button.
pub(crate) const EDIT_LABEL: &str = "Edit";
/// Label of the login password's reveal button.
pub(crate) const REVEAL_LABEL: &str = "Reveal";
/// Label of the hide button of whichever field shows.
pub(crate) const HIDE_LABEL: &str = "Hide";
/// Label of the login password's copy button.
pub(crate) const COPY_LABEL: &str = "Copy";
/// Labels of the notes buttons (logins, crypto addresses and recovery phrases).
const REVEAL_NOTES: &str = "Reveal notes";
const COPY_NOTES: &str = "Copy notes";
/// Labels of a crypto address's buttons.
const REVEAL_ADDRESS: &str = "Reveal address";
const COPY_ADDRESS: &str = "Copy address";
const REVEAL_MEMO: &str = "Reveal memo";
const COPY_MEMO: &str = "Copy memo";
/// Labels of a secure note's buttons.
const REVEAL_NOTE: &str = "Reveal note";
const COPY_NOTE: &str = "Copy note";
/// Labels of a recovery phrase's buttons.
const REVEAL_PHRASE: &str = "Reveal\u{2026}";
const SHOW_PHRASE: &str = "Show phrase";
const COPY_PHRASE: &str = "Copy phrase";
const CANCEL_LABEL: &str = "Cancel";
/// How a hidden field looks.
pub(crate) const DOTS: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";

/// Which secret field is showing. Holds no text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RevealField {
    /// A login's password.
    Password,
    /// The notes of a login, crypto address or recovery phrase.
    Notes,
    /// A crypto address.
    Address,
    /// A crypto address's memo.
    Memo,
    /// A secure note's body.
    Body,
    /// A recovery phrase, after the password check.
    Phrase,
}

impl RevealField {
    /// How long this field shows before it hides by itself.
    fn shows_for(self) -> Duration {
        let secs = match self {
            RevealField::Phrase => REHIDE_PHRASE_SECS,
            _ => REHIDE_PASSWORD_SECS,
        };
        Duration::from_secs(u64::from(secs))
    }
}

/// What the item view asks the vault view to do.
pub(crate) enum ItemAction {
    /// Nothing.
    None,
    /// Open the login form for this item.
    Edit,
    /// Work for the worker: the phrase check.
    Job(Job),
}

/// The reveal state of the selected item. No `Debug`: it can hold the phrase and the
/// typed password. Dropping it wipes both.
pub(crate) struct ItemView {
    /// The field that shows and when it hides (UI clock time).
    revealed: Option<(RevealField, Duration)>,
    /// The open phrase gate's password field. Wipes itself on drop.
    phrase_gate: Option<SecretInput>,
    /// The phrase words while they show. Wipes itself on drop.
    phrase: Option<SecretText>,
    /// The fixed line under the gate after a failed check.
    gate_error: Option<&'static str>,
    /// The line after a Copy, or from the app's clipboard clear.
    copy_note: Option<String>,
}

impl ItemView {
    /// Everything hidden, no gate open.
    pub(crate) fn new() -> ItemView {
        ItemView {
            revealed: None,
            phrase_gate: None,
            phrase: None,
            gate_error: None,
            copy_note: None,
        }
    }

    /// Whether a field shows.
    pub(crate) fn is_revealed(&self) -> bool {
        self.revealed.is_some()
    }

    /// Hides whatever shows and wipes the phrase words. The gate stays as it is.
    pub(crate) fn hide(&mut self) {
        self.revealed = None;
        self.phrase = None;
    }

    /// Shows `field` from `now`. Any other field hides; the phrase words go unless the
    /// phrase is the field.
    fn reveal(&mut self, field: RevealField, now: Duration) {
        if field != RevealField::Phrase {
            self.phrase = None;
        }
        self.revealed = Some((field, now + field.shows_for()));
    }

    /// Hides a shown field when its time is up or the window lost focus.
    pub(crate) fn tick(&mut self, now: Duration, focused: bool) {
        if let Some((_, until)) = self.revealed
            && (now >= until || !focused)
        {
            self.hide();
        }
    }

    /// Whether the gate's field is empty and no phrase is held.
    pub(crate) fn buffers_empty(&self) -> bool {
        self.phrase.is_none() && self.phrase_gate.as_ref().is_none_or(SecretInput::is_empty)
    }

    /// Characters typed into the gate's field.
    pub(crate) fn secret_char_count(&self) -> usize {
        self.phrase_gate.as_ref().map_or(0, SecretInput::char_count)
    }

    /// Sets or clears the line under the Copy buttons.
    pub(crate) fn set_copy_note(&mut self, note: Option<String>) {
        self.copy_note = note;
    }

    /// Takes the worker's answer to the phrase check. On success the gate closes and
    /// the phrase shows from `now`; a failure stays on the gate with its line. Words
    /// that arrive when no gate is open are dropped (wiped) unseen.
    pub(crate) fn on_phrase_done(
        &mut self,
        result: &Result<(), CoreError>,
        phrase: Option<SecretText>,
        now: Duration,
    ) {
        if self.phrase_gate.is_none() {
            return;
        }
        match (result, phrase) {
            (Ok(()), Some(words)) => {
                self.phrase_gate = None;
                self.gate_error = None;
                self.reveal(RevealField::Phrase, now);
                self.phrase = Some(words);
            }
            (Ok(()), None) => self.gate_error = Some(messages::PHRASE_FAILED),
            (Err(e), _) => self.gate_error = Some(messages::phrase_error(e)),
        }
    }

    /// When `field` shows until, if it shows.
    fn until(&self, field: RevealField) -> Option<Duration> {
        self.revealed
            .and_then(|(shown, until)| (shown == field).then_some(until))
    }
}

/// Draws `item` read-only and returns what the user asked for. `now` is the UI clock;
/// `throttle` is the session's password throttle, for the phrase gate.
pub(crate) fn show_item(
    ui: &mut egui::Ui,
    item: &Item,
    view: &mut ItemView,
    now: Duration,
    throttle: &ThrottleStatus,
    io: &mut FieldIo<'_>,
) -> ItemAction {
    ui.heading(item.title());
    ui.add_space(8.0);
    let mut action = ItemAction::None;
    match item.data() {
        ItemData::Login {
            username,
            password,
            urls,
            notes,
        } => {
            ui.label(format!("Username: {}", username.as_str()));
            if let Some(url) = urls.first() {
                ui.label(format!("Web address: {}", url.as_str()));
            }
            ui.add_space(4.0);
            password_row(ui, view, now, io, password);
            if !notes.expose().is_empty() {
                secret_row(ui, view, now, io, Row::NOTES, notes);
            }
        }
        ItemData::CryptoAddress {
            chain,
            address,
            memo,
            notes,
        } => {
            if !chain.is_empty() {
                ui.label(format!("Chain: {}", chain.as_str()));
            }
            ui.add_space(4.0);
            secret_row(ui, view, now, io, Row::ADDRESS, address);
            if !memo.expose().is_empty() {
                secret_row(ui, view, now, io, Row::MEMO, memo);
            }
            if !notes.expose().is_empty() {
                secret_row(ui, view, now, io, Row::NOTES, notes);
            }
        }
        ItemData::RecoveryPhrase { notes, .. } => {
            if let Some(job) = phrase_rows(ui, item, view, now, throttle, io) {
                action = ItemAction::Job(job);
            }
            if !notes.expose().is_empty() {
                secret_row(ui, view, now, io, Row::NOTES, notes);
            }
        }
        ItemData::SecureNote { body } => {
            secret_row(ui, view, now, io, Row::BODY, body);
        }
    }
    if let Some(note) = &view.copy_note {
        ui.label(note.as_str());
    }
    ui.add_space(8.0);
    if matches!(item.data(), ItemData::Login { .. }) {
        if ui.button(EDIT_LABEL).clicked() {
            action = ItemAction::Edit;
        }
    } else {
        ui.label(messages::EDIT_IN_CLI);
    }
    action
}

/// A login's password row, as before this view existed: the password shows in a
/// monospace, non-selectable label.
fn password_row(
    ui: &mut egui::Ui,
    view: &mut ItemView,
    now: Duration,
    io: &mut FieldIo<'_>,
    password: &SecretText,
) {
    ui.horizontal(|ui| {
        ui.label("Password:");
        match view.until(RevealField::Password) {
            Some(until) => {
                ui.add(
                    egui::Label::new(egui::RichText::new(password.expose()).monospace())
                        .selectable(false),
                );
                countdown(ui, until, now);
                if ui.button(HIDE_LABEL).clicked() {
                    view.hide();
                }
            }
            None => {
                ui.label(DOTS);
                if ui.button(REVEAL_LABEL).clicked() {
                    view.reveal(RevealField::Password, now);
                }
            }
        }
        if ui.button(COPY_LABEL).clicked() {
            copy(io, password.expose(), &mut view.copy_note);
        }
    });
}

/// The words and buttons of one secret row other than a login's password.
struct Row {
    field: RevealField,
    name: &'static str,
    reveal: &'static str,
    copy: &'static str,
}

impl Row {
    const NOTES: Row = Row {
        field: RevealField::Notes,
        name: "Notes:",
        reveal: REVEAL_NOTES,
        copy: COPY_NOTES,
    };
    const ADDRESS: Row = Row {
        field: RevealField::Address,
        name: "Address:",
        reveal: REVEAL_ADDRESS,
        copy: COPY_ADDRESS,
    };
    const MEMO: Row = Row {
        field: RevealField::Memo,
        name: "Memo:",
        reveal: REVEAL_MEMO,
        copy: COPY_MEMO,
    };
    const BODY: Row = Row {
        field: RevealField::Body,
        name: "Note:",
        reveal: REVEAL_NOTE,
        copy: COPY_NOTE,
    };
}

/// One secret row: its name, dots and Reveal (or the countdown and Hide), and Copy.
/// While shown, the value is painted under the row, on as many lines as it needs.
fn secret_row(
    ui: &mut egui::Ui,
    view: &mut ItemView,
    now: Duration,
    io: &mut FieldIo<'_>,
    row: Row,
    value: &SecretText,
) {
    let until = view.until(row.field);
    ui.horizontal(|ui| {
        ui.label(row.name);
        match until {
            Some(until) => {
                countdown(ui, until, now);
                if ui.button(HIDE_LABEL).clicked() {
                    view.hide();
                }
            }
            None => {
                ui.label(DOTS);
                if ui.button(row.reveal).clicked() {
                    view.reveal(row.field, now);
                }
            }
        }
        if ui.button(row.copy).clicked() {
            copy(io, value.expose(), &mut view.copy_note);
        }
    });
    // Drawn only if it still shows after this frame's clicks.
    if until.is_some() && view.until(row.field).is_some() {
        paint_secret(ui, value.expose());
    }
}

/// The phrase row and, while open, its password gate. Returns the check job when the
/// gate is submitted; the typed password moves into it and the field is left empty.
fn phrase_rows(
    ui: &mut egui::Ui,
    item: &Item,
    view: &mut ItemView,
    now: Duration,
    throttle: &ThrottleStatus,
    io: &mut FieldIo<'_>,
) -> Option<Job> {
    let until = view
        .until(RevealField::Phrase)
        .filter(|_| view.phrase.is_some());
    ui.horizontal(|ui| {
        ui.label("Phrase:");
        match until {
            Some(until) => {
                countdown(ui, until, now);
                if ui.button(HIDE_LABEL).clicked() {
                    view.hide();
                }
                // Copy exists only while the phrase shows.
                if let Some(words) = &view.phrase
                    && ui.button(COPY_PHRASE).clicked()
                {
                    copy(io, words.expose(), &mut view.copy_note);
                }
            }
            None => {
                ui.label(DOTS);
                if view.phrase_gate.is_none() && ui.button(REVEAL_PHRASE).clicked() {
                    // A new reveal always asks again, with an empty field.
                    view.phrase_gate = Some(SecretInput::with_capacity(MASTER_CAP));
                    view.gate_error = None;
                }
            }
        }
    });
    if let Some(words) = &view.phrase {
        paint_secret(ui, words.expose());
    }
    let gate = view.phrase_gate.as_mut()?;
    ui.add_space(4.0);
    let field = io.secret_field(
        ui,
        "phrase-password",
        messages::PHRASE_PASSWORD_LABEL,
        gate,
        &mut view.gate_error,
    );
    if field.changed {
        view.gate_error = None;
    }
    let mut job = None;
    let mut cancel = false;
    ui.horizontal(|ui| {
        let ready = !gate.is_empty() && throttle.retry_after.is_none();
        let clicked = ui
            .add_enabled(ready, egui::Button::new(SHOW_PHRASE))
            .clicked();
        if (clicked || field.submitted) && ready {
            job = Some(Job::RevealPhrase {
                id: item.id(),
                password: gate.take_master_password(),
            });
        }
        if ui.button(CANCEL_LABEL).clicked() {
            cancel = true;
        }
    });
    // While throttled the live wait replaces the fixed text.
    if let Some(wait) = throttle.retry_after.and(messages::throttle_line(throttle)) {
        ui.label(wait);
    } else if let Some(error) = view.gate_error {
        ui.label(error);
    }
    if cancel {
        view.phrase_gate = None;
        view.gate_error = None;
    }
    job
}

/// "Visible · hides in N s", rounded up to whole seconds.
fn countdown(ui: &mut egui::Ui, until: Duration, now: Duration) {
    let left = until.saturating_sub(now);
    let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
    ui.label(format!("Visible \u{b7} hides in {secs} s"));
}

/// Paints `text` read-only in monospace, wrapped to the panel, on as many lines as it
/// has. Painted, not a widget: no text edit, no selection, no accessibility value.
fn paint_secret(ui: &mut egui::Ui, text: &str) {
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let color = ui.visuals().strong_text_color();
    let galley = ui
        .painter()
        .layout(text.to_owned(), font, color, ui.available_width());
    let (rect, _) = ui.allocate_exact_size(galley.size(), egui::Sense::hover());
    ui.painter().galley(rect.min, galley, color);
}

/// Copies `text` through Holm's clipboard (concealed, never egui's `copy_text`) and
/// hands a wiping copy to the app, which schedules the clear. Sets the line after it.
fn copy(io: &mut FieldIo<'_>, text: &str, note: &mut Option<String>) {
    *note = Some(match io.clipboard.set(text) {
        Ok(()) => {
            io.copied = Some(Zeroizing::new(text.to_owned()));
            messages::copied_note(io.clear_secs)
        }
        Err(_) => messages::COPY_FAILED.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn with_phrase(now: Duration) -> ItemView {
        let mut view = ItemView::new();
        view.phrase_gate = Some(SecretInput::with_capacity(MASTER_CAP));
        view.on_phrase_done(
            &Ok(()),
            Some(SecretText::new("EXAMPLE words".to_owned())),
            now,
        );
        view
    }

    #[test]
    fn phrase_shows_for_sixty_seconds_then_is_wiped() {
        let mut view = with_phrase(secs(10));
        assert!(view.phrase_gate.is_none(), "the gate closes");
        view.tick(secs(69), true);
        assert!(view.phrase.is_some());
        view.tick(secs(70), true);
        assert!(view.phrase.is_none());
        assert!(!view.is_revealed());
        assert!(view.buffers_empty());
    }

    #[test]
    fn blur_hides_and_wipes() {
        let mut view = with_phrase(secs(0));
        view.tick(secs(1), false);
        assert!(view.phrase.is_none());
        let mut view = ItemView::new();
        view.reveal(RevealField::Address, secs(0));
        view.tick(secs(1), false);
        assert!(!view.is_revealed());
    }

    #[test]
    fn other_field_wipes_the_phrase() {
        let mut view = with_phrase(secs(0));
        view.reveal(RevealField::Notes, secs(1));
        assert!(view.phrase.is_none());
        assert_eq!(view.until(RevealField::Notes), Some(secs(31)));
    }

    #[test]
    fn failed_check_keeps_the_gate_with_its_line() {
        let mut view = ItemView::new();
        view.phrase_gate = Some(SecretInput::with_capacity(MASTER_CAP));
        view.on_phrase_done(&Err(CoreError::WrongPassword), None, secs(0));
        assert!(view.phrase_gate.is_some());
        assert_eq!(view.gate_error, Some(messages::WRONG_PASSWORD));
        assert!(!view.is_revealed());
    }

    #[test]
    fn words_without_an_open_gate_are_dropped() {
        let mut view = ItemView::new();
        view.on_phrase_done(
            &Ok(()),
            Some(SecretText::new("EXAMPLE words".to_owned())),
            secs(0),
        );
        assert!(view.phrase.is_none());
        assert!(!view.is_revealed());
    }
}
