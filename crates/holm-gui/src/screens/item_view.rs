//! The selected item, read-only: one `match` over the four item shapes.
//!
//! Every secret field starts hidden (a row of dots) and has a Reveal and a Copy button.
//! At most one field shows at a time, for a short while (`revealed` holds which one and
//! until when, on the UI clock). A shown field hides on its timer, when the window loses
//! focus, when another item is selected, on Edit and on lock (the last three drop the
//! whole [`ItemView`]).
//!
//! The view reads the item's [`EntryView`] (public fields and presence flags) and holds
//! no secret until a reveal. A Reveal asks the session once ([`Session::reveal`]) and
//! keeps the value in a wiping [`SecretText`] inside [`Revealed`]; every hide path
//! drops it. A Copy reveals, hands the text to the clipboard and drops it in the same
//! call. Every revealed field, a login's password included, is painted straight from
//! that buffer, so it is never in a text edit, never selectable and never in an
//! accessibility label or value.
//!
//! A recovery phrase is gated: "Reveal…" opens a password field, the check runs on the
//! worker ([`Job::RevealPhrase`]), and the words come back in a wiping
//! [`SecretText`] that is dropped as soon as the phrase hides. Every reveal asks for
//! the password again.
//!
//! Every Copy goes through Holm's clipboard and `io.copied`, so the app schedules its
//! clear the same way for every field.
//!
//! Custom fields follow the built-in ones on every item type. The user's label is its
//! own plain label, never a button name. A text value is a plain label. A date is shown
//! as `YYYY-MM-DD`. A reminder sits on its own line under [`messages::REMIND_ON`].
//! Secret and multiline values take the same secret row as notes, with the fixed Reveal
//! and Copy labels, and hide after [`REHIDE_PASSWORD_SECS`].
//!
//! Recovery codes show a count line, then one row per code: its number, dots (struck
//! through and weak once used), Copy for an unused code, and Mark used or Mark unused.
//! A code is never painted or put in a label. Mark returns a [`Job::SetCodeUsed`]: only
//! the index changes, no secret is decrypted.
//!
//! Crypto addresses, recovery phrases and secure notes keep their built-in fields
//! read-only, but "Edit fields" opens the item once, builds a [`FieldEditor`] for the
//! custom fields alone and drops the item.
//! Save sends [`Job::SetFields`]; Cancel drops the editor, which wipes its buffers.

use std::time::Duration;

use eframe::egui;
use holm_core::error::CoreError;
use holm_core::fields::format_date;
use holm_core::item::{ItemId, SecretSlot};
use holm_core::session::Session;
use holm_core::settings::{REHIDE_PASSWORD_SECS, REHIDE_PHRASE_SECS};
use holm_core::text::SecretText;
use holm_core::throttle::ThrottleStatus;
use holm_core::view::{EntryView, FieldDetail, PublicView};
use holm_platform::fs_store::FsStore;
use zeroize::Zeroizing;

use super::FieldIo;
use super::fields::FieldEditor;
use crate::messages;
use crate::secret_input::{MASTER_CAP, SecretInput};
use crate::widgets::secret_field::paint_secret;
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
/// Label of the custom field editor's save button.
const SAVE_FIELDS: &str = "Save";
/// Label of a recovery code's button that marks it used.
pub(crate) const MARK_USED: &str = "Mark used";
/// Label of a recovery code's button that marks it unused again.
pub(crate) const MARK_UNUSED: &str = "Mark unused";
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
    /// A custom secret or multiline field, by its 0-based position on the item.
    Custom(u8),
}

impl RevealField {
    /// How long this field shows before it hides by itself.
    fn shows_for(self) -> Duration {
        let secs = match self {
            RevealField::Phrase => REHIDE_PHRASE_SECS,
            RevealField::Password
            | RevealField::Notes
            | RevealField::Address
            | RevealField::Memo
            | RevealField::Body
            | RevealField::Custom(_) => REHIDE_PASSWORD_SECS,
        };
        Duration::from_secs(u64::from(secs))
    }

    /// The session slot for this field. The phrase has none: it has its own gate.
    fn slot(self) -> Option<SecretSlot> {
        match self {
            RevealField::Password => Some(SecretSlot::Password),
            RevealField::Notes => Some(SecretSlot::Notes),
            RevealField::Address => Some(SecretSlot::Address),
            RevealField::Memo => Some(SecretSlot::Memo),
            RevealField::Body => Some(SecretSlot::Body),
            RevealField::Custom(position) => Some(SecretSlot::Field { position }),
            RevealField::Phrase => None,
        }
    }
}

/// What the item view asks the vault view to do.
pub(crate) enum ItemAction {
    /// Nothing.
    None,
    /// Open the login form for this item.
    Edit,
    /// Work for the worker: the phrase check, or a code mark.
    Job(Job),
}

/// The one secret that shows: which field, when it hides (UI clock time) and its text.
/// No `Debug`; the text wipes when this drops.
struct Revealed {
    field: RevealField,
    until: Duration,
    text: SecretText,
}

/// What the item view needs to open a secret: the item, the session and the UI clock.
struct Ctx<'a> {
    id: ItemId,
    session: &'a Session<FsStore>,
    now: Duration,
}

/// The reveal state of the selected item. No `Debug`: it can hold a secret and the
/// typed password. Dropping it wipes both. Before a reveal it holds no secret at all.
pub(crate) struct ItemView {
    /// The field that shows, its text and when it hides.
    revealed: Option<Revealed>,
    /// The open phrase gate's password field. Wipes itself on drop.
    phrase_gate: Option<SecretInput>,
    /// The fixed line under the gate after a failed check.
    gate_error: Option<&'static str>,
    /// The line after a Copy, or from the app's clipboard clear.
    copy_note: Option<String>,
    /// The fixed line after a reveal, copy or edit that could not open the item.
    error: Option<&'static str>,
    /// The open custom field editor of a non-login item. Wipes itself on drop.
    fields: Option<FieldEditor>,
}

impl ItemView {
    /// Everything hidden, no gate open.
    pub(crate) fn new() -> ItemView {
        ItemView {
            revealed: None,
            phrase_gate: None,
            gate_error: None,
            copy_note: None,
            error: None,
            fields: None,
        }
    }

    /// Whether a field shows.
    pub(crate) fn is_revealed(&self) -> bool {
        self.revealed.is_some()
    }

    /// Hides whatever shows and wipes it. The gate stays as it is.
    pub(crate) fn hide(&mut self) {
        self.revealed = None;
    }

    /// Opens `field` from the session once and shows it from `ctx.now`. Any other
    /// field hides. A failure hides everything and sets the fixed line.
    fn reveal(&mut self, ctx: &Ctx<'_>, field: RevealField) {
        self.revealed = None;
        let Some(slot) = field.slot() else {
            return;
        };
        match ctx.session.reveal(ctx.id, slot) {
            Ok(text) => {
                self.error = None;
                self.revealed = Some(Revealed {
                    field,
                    until: ctx.now + field.shows_for(),
                    text,
                });
            }
            Err(e) => self.error = Some(messages::item_error(&e)),
        }
    }

    /// Copies one secret through the clipboard. The value lives only inside this call.
    fn copy_slot(&mut self, ctx: &Ctx<'_>, slot: SecretSlot, io: &mut FieldIo<'_>) {
        match ctx.session.reveal(ctx.id, slot) {
            Ok(text) => {
                self.error = None;
                copy(io, text.expose(), &mut self.copy_note);
            }
            Err(e) => self.error = Some(messages::item_error(&e)),
        }
    }

    /// Hides a shown field when its time is up or the window lost focus.
    pub(crate) fn tick(&mut self, now: Duration, focused: bool) {
        if let Some(shown) = &self.revealed
            && (now >= shown.until || !focused)
        {
            self.hide();
        }
    }

    /// Whether the gate's field is empty and no phrase is held. A revealed field is the
    /// vault's own text painted for a moment, not a typed buffer, so it does not count
    /// (the tests read [`ItemView::is_revealed`] for it).
    pub(crate) fn buffers_empty(&self) -> bool {
        self.text(RevealField::Phrase).is_none()
            && self.phrase_gate.as_ref().is_none_or(SecretInput::is_empty)
            && self.fields.is_none()
    }

    /// Characters typed into the gate's field and the field editor's secret buffers.
    pub(crate) fn secret_char_count(&self) -> usize {
        self.phrase_gate.as_ref().map_or(0, SecretInput::char_count)
            + self
                .fields
                .as_ref()
                .map_or(0, FieldEditor::secret_char_count)
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
                self.revealed = Some(Revealed {
                    field: RevealField::Phrase,
                    until: now + RevealField::Phrase.shows_for(),
                    text: words,
                });
            }
            (Ok(()), None) => self.gate_error = Some(messages::PHRASE_FAILED),
            (Err(e), _) => self.gate_error = Some(messages::phrase_error(e)),
        }
    }

    /// When `field` shows until, if it shows.
    fn until(&self, field: RevealField) -> Option<Duration> {
        self.revealed
            .as_ref()
            .and_then(|r| (r.field == field).then_some(r.until))
    }

    /// The text of `field`, if it shows.
    fn text(&self, field: RevealField) -> Option<&SecretText> {
        self.revealed
            .as_ref()
            .and_then(|r| (r.field == field).then_some(&r.text))
    }
}

/// Draws `entry` read-only and returns what the user asked for. `now` is the UI clock;
/// `throttle` is the session's password throttle, for the phrase gate. Rows come from
/// the presence flags; no secret is read until a Reveal or Copy.
pub(crate) fn show_item(
    ui: &mut egui::Ui,
    entry: EntryView<'_>,
    session: &Session<FsStore>,
    view: &mut ItemView,
    now: Duration,
    throttle: &ThrottleStatus,
    io: &mut FieldIo<'_>,
) -> ItemAction {
    let cx = Ctx {
        id: entry.id(),
        session,
        now,
    };
    ui.heading(crate::fonts::display(entry.title()).as_ref());
    ui.add_space(8.0);
    let mut action = ItemAction::None;
    let is_login = matches!(entry.public(), PublicView::Login { .. });
    match entry.public() {
        PublicView::Login {
            username,
            urls,
            has_password,
            has_notes,
        } => {
            ui.label(format!("Username: {username}"));
            if let Some(url) = urls.first() {
                ui.label(format!("Web address: {url}"));
            }
            ui.add_space(4.0);
            if has_password {
                secret_row(ui, &cx, view, io, Row::PASSWORD);
            }
            if has_notes {
                secret_row(ui, &cx, view, io, Row::NOTES);
            }
        }
        PublicView::CryptoAddress {
            chain,
            has_address,
            has_memo,
            has_notes,
        } => {
            if !chain.is_empty() {
                ui.label(format!("Chain: {chain}"));
            }
            ui.add_space(4.0);
            if has_address {
                secret_row(ui, &cx, view, io, Row::ADDRESS);
            }
            if has_memo {
                secret_row(ui, &cx, view, io, Row::MEMO);
            }
            if has_notes {
                secret_row(ui, &cx, view, io, Row::NOTES);
            }
        }
        PublicView::RecoveryPhrase { has_notes } => {
            if let Some(job) = phrase_rows(ui, &cx, view, throttle, io) {
                action = ItemAction::Job(job);
            }
            if has_notes {
                secret_row(ui, &cx, view, io, Row::NOTES);
            }
        }
        PublicView::SecureNote { has_body } => {
            if has_body {
                secret_row(ui, &cx, view, io, Row::BODY);
            }
        }
    }
    if view.fields.is_some() {
        if let Some(job) = edit_fields(ui, cx.id, view, io) {
            action = ItemAction::Job(job);
        }
    } else if let Some(job) = custom_rows(ui, &cx, &entry, view, io) {
        action = ItemAction::Job(job);
    }
    if let Some(note) = &view.copy_note {
        ui.label(note.as_str());
    }
    if let Some(error) = view.error {
        ui.label(error);
    }
    ui.add_space(8.0);
    if is_login {
        if ui.button(EDIT_LABEL).clicked() {
            action = ItemAction::Edit;
        }
    } else {
        ui.label(messages::EDIT_IN_CLI);
        if view.fields.is_none() && ui.button(messages::EDIT_FIELDS).clicked() {
            // Nothing stays revealed under the editor. The item opens once, for the
            // editor's draft, and drops at the end of this block.
            view.hide();
            match session.open_item(cx.id) {
                Ok(item) => {
                    view.error = None;
                    view.fields = FieldEditor::from_fields(item.fields());
                }
                Err(e) => view.error = Some(messages::item_error(&e)),
            }
        }
    }
    action
}

/// The open custom field editor with Save and Cancel. Returns the save job when the
/// draft builds; the editor then closes. A broken rule keeps the draft and its line.
fn edit_fields(
    ui: &mut egui::Ui,
    id: ItemId,
    view: &mut ItemView,
    io: &mut FieldIo<'_>,
) -> Option<Job> {
    let editor = view.fields.as_mut()?;
    ui.add_space(4.0);
    editor.show(ui, io);
    let mut save = false;
    let mut cancel = false;
    ui.horizontal(|ui| {
        save = ui.button(SAVE_FIELDS).clicked();
        cancel = ui.button(CANCEL_LABEL).clicked();
    });
    if cancel {
        view.fields = None;
        return None;
    }
    if save && let Ok(fields) = editor.build() {
        view.fields = None;
        return Some(Job::SetFields(id, fields));
    }
    None
}

/// The words and buttons of one secret row. `name` is a fixed name or a custom field's
/// label; the button labels are always fixed.
struct Row<'a> {
    field: RevealField,
    name: &'a str,
    reveal: &'static str,
    copy: &'static str,
}

impl Row<'static> {
    const PASSWORD: Row<'static> = Row {
        field: RevealField::Password,
        name: "Password:",
        reveal: REVEAL_LABEL,
        copy: COPY_LABEL,
    };
    const NOTES: Row<'static> = Row {
        field: RevealField::Notes,
        name: "Notes:",
        reveal: REVEAL_NOTES,
        copy: COPY_NOTES,
    };
    const ADDRESS: Row<'static> = Row {
        field: RevealField::Address,
        name: "Address:",
        reveal: REVEAL_ADDRESS,
        copy: COPY_ADDRESS,
    };
    const MEMO: Row<'static> = Row {
        field: RevealField::Memo,
        name: "Memo:",
        reveal: REVEAL_MEMO,
        copy: COPY_MEMO,
    };
    const BODY: Row<'static> = Row {
        field: RevealField::Body,
        name: "Note:",
        reveal: REVEAL_NOTE,
        copy: COPY_NOTE,
    };
}

/// One secret row: its name, dots and Reveal (or the countdown and Hide), and Copy.
/// While shown, the value is painted under the row, on as many lines as it needs. A
/// Reveal opens the value once; the paint reads the held text; a Copy opens, copies and
/// drops.
fn secret_row(
    ui: &mut egui::Ui,
    cx: &Ctx<'_>,
    view: &mut ItemView,
    io: &mut FieldIo<'_>,
    row: Row<'_>,
) {
    let until = view.until(row.field);
    ui.horizontal(|ui| {
        ui.label(row.name);
        match until {
            Some(until) => {
                countdown(ui, until, cx.now);
                if ui.button(HIDE_LABEL).clicked() {
                    view.hide();
                }
            }
            None => {
                ui.label(DOTS);
                if ui.button(row.reveal).clicked() {
                    view.reveal(cx, row.field);
                }
            }
        }
        if ui.button(row.copy).clicked()
            && let Some(slot) = row.field.slot()
        {
            view.copy_slot(cx, slot, io);
        }
    });
    // Drawn only if it showed at the start of this frame and still shows after its
    // clicks. A reveal made this frame paints from the next one.
    if until.is_some()
        && let Some(text) = view.text(row.field)
    {
        paint_secret(ui, text.expose());
    }
}

/// Every custom field of `entry`, in order. Text and dates are plain labels; secret and
/// multiline values take the secret row (dots, Reveal, Copy, painted while shown). The
/// user's label is always its own `ui.label`, never part of a button. Returns the job
/// when a recovery code was marked used or unused.
fn custom_rows(
    ui: &mut egui::Ui,
    cx: &Ctx<'_>,
    entry: &EntryView<'_>,
    view: &mut ItemView,
    io: &mut FieldIo<'_>,
) -> Option<Job> {
    let fields = entry.fields();
    if fields.is_empty() {
        return None;
    }
    let mut job = None;
    ui.add_space(4.0);
    for field in &fields {
        let position = field.position();
        match field.detail() {
            FieldDetail::Text(text) => {
                ui.horizontal(|ui| {
                    ui.label(field.label());
                    ui.label(*text);
                });
            }
            FieldDetail::Date(date) => {
                let bytes = format_date(*date);
                ui.horizontal(|ui| {
                    ui.label(field.label());
                    ui.label(date_text(&bytes));
                });
            }
            FieldDetail::RecoveryCodes { used } => {
                let left = used.iter().filter(|u| !**u).count();
                let total = used.len();
                ui.horizontal(|ui| {
                    ui.label(field.label());
                    ui.label(egui::RichText::new(format!("{left} of {total} left")).weak());
                });
                if let Some(mark) = code_rows(ui, cx, view, io, position, used) {
                    job = Some(mark);
                }
            }
            FieldDetail::Secret | FieldDetail::MultilineSecret => {
                let row = Row {
                    field: RevealField::Custom(position),
                    name: field.label(),
                    reveal: REVEAL_LABEL,
                    copy: COPY_LABEL,
                };
                secret_row(ui, cx, view, io, row);
            }
        }
        if let Some(expiry) = field.expiry() {
            let bytes = format_date(expiry);
            ui.horizontal(|ui| {
                ui.label(messages::REMIND_ON);
                ui.label(date_text(&bytes));
            });
        }
    }
    job
}

/// One row per recovery code of the field at `position`: its number, dots (struck
/// through and weak when used), Copy for an unused code, and the mark button. The code
/// itself is never in a label. Returns the job for a mark: only the used flag changes.
fn code_rows(
    ui: &mut egui::Ui,
    cx: &Ctx<'_>,
    view: &mut ItemView,
    io: &mut FieldIo<'_>,
    position: u8,
    used: &[bool],
) -> Option<Job> {
    let mut job = None;
    for (i, &is_used) in used.iter().enumerate() {
        // A field holds at most a few dozen codes, so every index fits in a u8.
        let Ok(index) = u8::try_from(i) else {
            break;
        };
        ui.push_id((position, i), |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("{}.", i + 1));
                let dots = egui::RichText::new(DOTS);
                if is_used {
                    ui.label(dots.strikethrough().weak());
                } else {
                    ui.label(dots);
                    if ui.button(COPY_LABEL).clicked() {
                        view.copy_slot(cx, SecretSlot::Code { position, index }, io);
                    }
                }
                let mark = if is_used { MARK_UNUSED } else { MARK_USED };
                if ui.button(mark).clicked() {
                    job = Some(mark_job(cx.id, position, index, is_used));
                }
            });
        });
    }
    job
}

/// The job that flips one code's flag: used becomes unused and back.
fn mark_job(id: ItemId, position: u8, index: u8, was_used: bool) -> Job {
    Job::SetCodeUsed {
        id,
        position,
        index,
        used: !was_used,
    }
}

/// The ten ASCII bytes of [`format_date`] as text.
fn date_text(bytes: &[u8; 10]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("")
}

/// The phrase row and, while open, its password gate. Returns the check job when the
/// gate is submitted; the typed password moves into it and the field is left empty.
fn phrase_rows(
    ui: &mut egui::Ui,
    cx: &Ctx<'_>,
    view: &mut ItemView,
    throttle: &ThrottleStatus,
    io: &mut FieldIo<'_>,
) -> Option<Job> {
    let until = view.until(RevealField::Phrase);
    ui.horizontal(|ui| {
        ui.label("Phrase:");
        match until {
            Some(until) => {
                countdown(ui, until, cx.now);
                if ui.button(HIDE_LABEL).clicked() {
                    view.hide();
                }
                // Copy exists only while the phrase shows.
                if let Some(r) = &view.revealed
                    && r.field == RevealField::Phrase
                    && ui.button(COPY_PHRASE).clicked()
                {
                    copy(io, r.text.expose(), &mut view.copy_note);
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
    if let Some(words) = view.text(RevealField::Phrase) {
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
                id: cx.id,
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
    use crate::clipboard::NoClipboard;
    use holm_core::clock::SystemClock;
    use holm_core::fields::{FieldValue, RecoveryCode, try_field};
    use holm_core::item::{ItemData, ItemInput};
    use holm_core::text::Text;
    use holm_crypto::MasterPassword;
    use holm_crypto::kdf::KdfParams;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// An unlocked session with one login that has a password and a recovery-codes
    /// field. The directory must outlive the session.
    fn session_with_login() -> (tempfile::TempDir, Session<FsStore>, ItemId) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Holm").join("holm.vault");
        holm_platform::paths::ensure_vault_dir(&path).unwrap();
        let mut session = Session::new(FsStore::new(path), Box::new(SystemClock::new()));
        let password = MasterPassword::new("correct-Horse-battery-staple-EXAMPLE-9".to_owned());
        session.create(&password, &KdfParams::FLOOR).unwrap();
        let codes = vec![
            RecoveryCode::new(SecretText::new("EXAMPLE-code-1".to_owned()), false),
            RecoveryCode::new(SecretText::new("EXAMPLE-code-2".to_owned()), true),
        ];
        let input = ItemInput {
            title: Text::new("Example".to_owned()),
            category: None,
            favourite: false,
            fields: vec![
                try_field(
                    Text::new("Backup".to_owned()),
                    FieldValue::RecoveryCodes(codes),
                    None,
                )
                .unwrap(),
            ],
            data: ItemData::Login {
                username: Text::new("ada@example.com".to_owned()),
                password: SecretText::new("EXAMPLE-pass".to_owned()),
                urls: Vec::new(),
                notes: SecretText::new(String::new()),
            },
        };
        let id = session.add_item(input).unwrap();
        (dir, session, id)
    }

    fn ctx(session: &Session<FsStore>, id: ItemId, now: Duration) -> Ctx<'_> {
        Ctx { id, session, now }
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
    fn item_view_holds_no_secret_before_reveal() {
        let (_dir, session, id) = session_with_login();
        let view = ItemView::new();
        assert!(view.revealed.is_none());
        assert!(view.buffers_empty());
        // Reading the entry for painting gives presence flags only.
        let entry = session.entry(id).unwrap();
        assert!(matches!(
            entry.public(),
            PublicView::Login {
                has_password: true,
                has_notes: false,
                ..
            }
        ));
        assert!(!format!("{:?}", entry.fields()).contains("EXAMPLE-code"));
    }

    #[test]
    fn reveal_drops_on_timer() {
        let (_dir, session, id) = session_with_login();
        let mut view = ItemView::new();
        view.reveal(&ctx(&session, id, secs(10)), RevealField::Password);
        assert_eq!(
            view.text(RevealField::Password).map(SecretText::expose),
            Some("EXAMPLE-pass")
        );
        assert_eq!(
            view.until(RevealField::Password),
            Some(secs(10 + u64::from(REHIDE_PASSWORD_SECS)))
        );
        view.tick(secs(39), true);
        assert!(view.is_revealed());
        view.tick(secs(40), true);
        assert!(view.revealed.is_none());
        assert!(view.buffers_empty());
    }

    #[test]
    fn reveal_drops_on_blur() {
        let (_dir, session, id) = session_with_login();
        let mut view = ItemView::new();
        view.reveal(&ctx(&session, id, secs(0)), RevealField::Password);
        view.tick(secs(1), false);
        assert!(view.revealed.is_none());
        let mut view = with_phrase(secs(0));
        view.tick(secs(1), false);
        assert!(view.revealed.is_none());
    }

    #[test]
    fn reveal_drops_on_select() {
        // Selecting another item replaces the whole view; the old one wipes on drop.
        let (_dir, session, id) = session_with_login();
        let mut view = ItemView::new();
        view.reveal(&ctx(&session, id, secs(0)), RevealField::Password);
        assert!(view.is_revealed());
        view = ItemView::new();
        assert!(!view.is_revealed());
        assert!(view.buffers_empty());
    }

    #[test]
    fn another_reveal_replaces_the_first_and_a_miss_sets_the_line() {
        let (_dir, session, id) = session_with_login();
        let mut view = with_phrase(secs(0));
        view.reveal(&ctx(&session, id, secs(1)), RevealField::Password);
        assert!(view.text(RevealField::Phrase).is_none());
        assert!(view.text(RevealField::Password).is_some());
        // Position 0 holds recovery codes, so the session has no secret in that slot.
        view.reveal(&ctx(&session, id, secs(2)), RevealField::Custom(0));
        assert!(view.revealed.is_none());
        assert_eq!(view.error, Some(messages::ITEM_OPEN_FAILED));
    }

    #[test]
    fn copy_keeps_no_secret() {
        let (_dir, session, id) = session_with_login();
        let mut view = ItemView::new();
        let mut clipboard = NoClipboard;
        let mut io = FieldIo {
            clipboard: &mut clipboard,
            focus: super::super::FieldFocus::None,
            clear_secs: 30,
            copied: None,
        };
        view.copy_slot(&ctx(&session, id, secs(0)), SecretSlot::Password, &mut io);
        assert!(view.revealed.is_none(), "a copy never leaves a value held");
        assert!(view.buffers_empty());
        assert_eq!(view.copy_note.as_deref(), Some(messages::COPY_FAILED));
        // A code copies through its own slot, with the same result.
        view.copy_slot(
            &ctx(&session, id, secs(0)),
            SecretSlot::Code {
                position: 0,
                index: 0,
            },
            &mut io,
        );
        assert!(view.revealed.is_none());
        assert_eq!(view.error, None);
    }

    #[test]
    fn mark_used_sends_set_code_used() {
        let (_dir, mut session, id) = session_with_login();
        let job = mark_job(id, 0, 0, false);
        assert_eq!(format!("{job:?}"), "Job::SetCodeUsed(<item hidden>)");
        let Job::SetCodeUsed {
            id: jid,
            position,
            index,
            used,
        } = job
        else {
            panic!("a mark builds SetCodeUsed");
        };
        assert!(used, "an unused code becomes used");
        session.set_code_used(jid, position, index, used).unwrap();
        let entry = session.entry(id).unwrap();
        let fields = entry.fields();
        assert_eq!(
            fields[0].detail(),
            &FieldDetail::RecoveryCodes {
                used: vec![true, true]
            }
        );
        let Job::SetCodeUsed { used, .. } = mark_job(id, 0, 1, true) else {
            panic!("a mark builds SetCodeUsed");
        };
        assert!(!used, "a used code becomes unused");
    }

    #[test]
    fn damaged_item_message() {
        let id = ItemId::random().unwrap();
        let e = CoreError::DamagedItem(id);
        assert_eq!(messages::item_error(&e), messages::ITEM_DAMAGED);
        assert_eq!(messages::save_error(&e), messages::ITEM_DAMAGED);
        assert_eq!(
            messages::import_apply_error(&e, true),
            messages::ITEM_DAMAGED
        );
        assert_eq!(messages::export_error(&e), messages::ITEM_DAMAGED);
        assert_ne!(messages::ITEM_DAMAGED, messages::SELECT_OR_ADD);
        assert_eq!(
            messages::item_error(&CoreError::GenerationExhausted(id)),
            messages::ITEM_EDIT_LIMIT
        );
    }

    #[test]
    fn phrase_shows_for_sixty_seconds_then_is_wiped() {
        let mut view = with_phrase(secs(10));
        assert!(view.phrase_gate.is_none(), "the gate closes");
        view.tick(secs(69), true);
        assert!(view.text(RevealField::Phrase).is_some());
        view.tick(secs(70), true);
        assert!(view.text(RevealField::Phrase).is_none());
        assert!(!view.is_revealed());
        assert!(view.buffers_empty());
    }

    #[test]
    fn failed_check_keeps_the_gate_with_its_line() {
        let mut view = ItemView::new();
        view.phrase_gate = Some(SecretInput::with_capacity(MASTER_CAP));
        view.on_phrase_done(&Err(CoreError::WrongPassword), None, secs(0));
        assert!(view.phrase_gate.is_some());
        assert_eq!(view.gate_error, Some(messages::PHRASE_WRONG_PASSWORD));
        assert!(!view.is_revealed());
    }

    #[test]
    fn custom_field_hides_after_thirty_seconds() {
        let (_dir, session, id) = session_with_login();
        let mut view = ItemView::new();
        // Position 0 is a recovery-codes field, not a secret: the reveal misses.
        view.reveal(&ctx(&session, id, secs(0)), RevealField::Custom(0));
        assert!(!view.is_revealed());
        assert!(view.error.is_some());
        assert_eq!(RevealField::Custom(3).shows_for(), secs(30));
    }

    #[test]
    fn field_editor_counts_and_drops() {
        let mut view = ItemView::new();
        assert!(view.buffers_empty());
        view.fields = Some(FieldEditor::new());
        assert!(!view.buffers_empty());
        assert_eq!(view.secret_char_count(), 0);
        view.fields = None;
        assert!(view.buffers_empty());
    }

    #[test]
    fn words_without_an_open_gate_are_dropped() {
        let mut view = ItemView::new();
        view.on_phrase_done(
            &Ok(()),
            Some(SecretText::new("EXAMPLE words".to_owned())),
            secs(0),
        );
        assert!(view.revealed.is_none());
        assert!(!view.is_revealed());
    }
}
