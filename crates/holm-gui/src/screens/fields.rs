//! The custom field editor: the draft list of an item's custom fields.
//!
//! Each draft row owns a label ([`LineBuf`]), a kind, one [`SecretInput`] for a secret
//! or multiline value, and fixed-size text buffers for a text value, a date and a
//! reminder date. Labels, text values and dates are display text and use `TextEdit`
//! over a `LineBuf`; a secret value only ever goes through `secret_field` or
//! `secret_area`, never a `TextEdit`, a label, a button name or `Debug`.
//!
//! Every buffer wipes itself on drop, so removing a row, changing its kind or dropping
//! the editor (Cancel, lock) leaves no copy of a value behind. [`FieldEditor::build`]
//! copies the draft into validated [`CustomField`]s and keeps the draft when a rule
//! fails, so the user can fix it.

use core::fmt;
use std::sync::LazyLock;

use eframe::egui;
use egui::TextBuffer as _;
use holm_core::fields::{
    CustomField, FieldKind, FieldPreset, FieldValue, RecoveryCode, format_date, parse_date,
    parse_recovery_codes, preset_fields, try_field,
};
use holm_core::rules::{FieldError, MAX_CUSTOM_FIELDS};
use holm_core::text::{SecretText, Text};

use super::FieldIo;
use super::login_form::{LineBuf, line_field, line_field_hint};
use crate::messages::{self, ADD_FIELD, MOVE_DOWN, MOVE_UP, PRESET_LABEL, REMIND_ON, REMOVE_FIELD};
use crate::secret_input::{ITEM_SECRET_CAP, MULTILINE_SECRET_CAP, SecretInput};

/// Label of a row's name box.
const FIELD_NAME_LABEL: &str = "Field name";
/// Label of the picker of suggested names.
const SUGGEST_LABEL: &str = "Suggested names";
/// Label of the kind picker.
const KIND_LABEL: &str = "Kind";
/// Label of a text value's box.
const TEXT_VALUE_LABEL: &str = "Value";
/// Label of a date value's box.
const DATE_VALUE_LABEL: &str = "Date (YYYY-MM-DD)";
/// Label of a secret value's field.
const SECRET_VALUE_LABEL: &str = "Secret value";
/// Label of a multiline secret's field.
const MULTILINE_VALUE_LABEL: &str = "Secret text";
/// Label of a recovery codes list's field.
const CODES_VALUE_LABEL: &str = "Recovery code list";
/// The line under a recovery codes field.
const CODES_HINT: &str = "One code per line, up to 20.";
/// What a picker shows before anything is picked.
const CHOOSE: &str = "Choose\u{2026}";
/// Hint shown in an empty date box.
const DATE_HINT: &str = "YYYY-MM-DD";

/// The presets the picker offers, with their fixed display names.
const PRESETS: [(FieldPreset, &str); 11] = [
    (FieldPreset::Email, "Email"),
    (FieldPreset::Cloudflare, "Cloudflare"),
    (FieldPreset::GitHub, "GitHub"),
    (FieldPreset::Server, "Server"),
    (FieldPreset::Database, "Database"),
    (FieldPreset::Aws, "AWS"),
    (FieldPreset::ApiKey, "API key"),
    (FieldPreset::WiFi, "Wi-Fi"),
    (FieldPreset::BankCard, "Bank card"),
    (FieldPreset::RecoveryCodes, "Recovery codes"),
    (FieldPreset::Custom, "Custom (empty)"),
];

/// Names suggested beyond the preset labels.
const EXTRA_SUGGESTIONS: [&str; 4] = ["URL", "Certificate", "PIN", "Recovery code"];

/// Every preset label (once each, in preset order), then [`EXTRA_SUGGESTIONS`]. Picking
/// one fills the label box, which stays editable; a label not in this list is saved if
/// it passes `try_field`. Built from `preset_fields` so it cannot drift from core.
pub(crate) static LABEL_SUGGESTIONS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let mut out: Vec<&'static str> = Vec::new();
    for (preset, _) in PRESETS {
        for field in preset_fields(preset) {
            if !out.contains(&field.label) {
                out.push(field.label);
            }
        }
    }
    for extra in EXTRA_SUGGESTIONS {
        if !out.contains(&extra) {
            out.push(extra);
        }
    }
    out
});

/// The kind of a draft row's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Plain text, shown in the clear.
    Text,
    /// A one-line secret.
    Secret,
    /// A secret on several lines, such as a private key.
    Multiline,
    /// A calendar date.
    Date,
    /// One-time recovery codes, one per line.
    Codes,
}

impl Kind {
    /// Every kind, in picker order.
    const ALL: [Kind; 5] = [
        Kind::Text,
        Kind::Secret,
        Kind::Multiline,
        Kind::Date,
        Kind::Codes,
    ];

    /// Whether this kind's secret box keeps typed newlines.
    fn keeps_newlines(self) -> bool {
        matches!(self, Kind::Multiline | Kind::Codes)
    }

    /// The fixed name the picker shows.
    fn name(self) -> &'static str {
        match self {
            Kind::Text => "Text",
            Kind::Secret => "Secret",
            Kind::Multiline => "Multiline secret",
            Kind::Date => "Date",
            Kind::Codes => "Recovery codes",
        }
    }

    /// The editor kind for a core field kind.
    fn from_core(kind: &FieldKind) -> Kind {
        match kind {
            FieldKind::Text => Kind::Text,
            FieldKind::Secret => Kind::Secret,
            FieldKind::MultilineSecret => Kind::Multiline,
            FieldKind::RecoveryCodes => Kind::Codes,
            FieldKind::Date => Kind::Date,
        }
    }

    /// The kind of a stored value.
    fn of(value: &FieldValue) -> Kind {
        match value {
            FieldValue::Text(_) => Kind::Text,
            FieldValue::Secret(_) => Kind::Secret,
            FieldValue::MultilineSecret(_) => Kind::Multiline,
            FieldValue::RecoveryCodes(_) => Kind::Codes,
            FieldValue::Date(_) => Kind::Date,
        }
    }
}

/// A fresh, empty secret buffer for `kind`: multiline and codes keep newlines.
fn secret_buffer(kind: Kind) -> SecretInput {
    if kind.keeps_newlines() {
        SecretInput::with_multiline_capacity(MULTILINE_SECRET_CAP)
    } else {
        SecretInput::with_capacity(ITEM_SECRET_CAP)
    }
}

/// A wiping deep copy of `codes`, used flags included.
fn copy_codes(codes: &[RecoveryCode]) -> Vec<RecoveryCode> {
    codes
        .iter()
        .map(|code| {
            RecoveryCode::new(
                SecretText::new(code.code().expose().to_owned()),
                code.used(),
            )
        })
        .collect()
}

/// The ten ASCII bytes of [`format_date`] as text.
fn date_text(bytes: &[u8; 10]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("")
}

/// One draft field. Every buffer wipes itself on drop.
struct DraftRow {
    /// The field's name, typed or picked.
    label: LineBuf,
    /// Which value buffer counts.
    kind: Kind,
    /// The value of a text field.
    text: LineBuf,
    /// The value of a secret or multiline field.
    secret: SecretInput,
    /// The value of a date field, as typed `YYYY-MM-DD`.
    date: LineBuf,
    /// The optional reminder date, as typed `YYYY-MM-DD`. Empty means none.
    reminder: LineBuf,
    /// A deep copy of the codes the field held when the draft was made, with their used
    /// flags. Used when the codes box is left empty. Only set for [`Kind::Codes`]; the
    /// codes wipe themselves on drop.
    kept: Option<Vec<RecoveryCode>>,
}

impl fmt::Debug for DraftRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DraftRow")
            .field("kind", &self.kind)
            .field("label_len", &self.label.len())
            .field("text_len", &self.text.len())
            .field("secret", &self.secret)
            .field("date_len", &self.date.len())
            .field("reminder_len", &self.reminder.len())
            .field("kept_count", &self.kept.as_ref().map(Vec::len))
            .finish()
    }
}

impl DraftRow {
    /// A row named `label` of `kind`, with every value empty.
    fn new(label: LineBuf, kind: Kind) -> DraftRow {
        DraftRow {
            label,
            kind,
            text: LineBuf::new(),
            secret: secret_buffer(kind),
            date: LineBuf::new(),
            reminder: LineBuf::new(),
            kept: None,
        }
    }

    /// A row filled from a stored field, or `None` when a value does not fit its buffer.
    fn from_field(field: &CustomField) -> Option<DraftRow> {
        let kind = Kind::of(field.value());
        let mut row = DraftRow::new(LineBuf::from_text(field.label())?, kind);
        match field.value() {
            FieldValue::Text(text) => row.text = LineBuf::from_text(text.as_str())?,
            FieldValue::Secret(value) => {
                row.secret = SecretInput::from_secret(value.expose(), ITEM_SECRET_CAP)?;
            }
            FieldValue::MultilineSecret(value) => {
                row.secret =
                    SecretInput::from_multiline_secret(value.expose(), MULTILINE_SECRET_CAP)?;
            }
            FieldValue::Date(date) => {
                row.date = LineBuf::from_text(date_text(&format_date(*date)))?;
            }
            FieldValue::RecoveryCodes(codes) => row.kept = Some(copy_codes(codes)),
        }
        if let Some(expiry) = field.expiry() {
            row.reminder = LineBuf::from_text(date_text(&format_date(expiry)))?;
        }
        Some(row)
    }

    /// Switches the kind and wipes every value buffer. The reminder stays.
    fn set_kind(&mut self, kind: Kind) {
        if kind == self.kind {
            return;
        }
        // Replacing a LineBuf drops the old one, which wipes it.
        self.text = LineBuf::new();
        self.date = LineBuf::new();
        self.secret.clear();
        // Any change leaves the codes kind or enters it, so kept codes never carry over.
        self.kept = None;
        if kind.keeps_newlines() != self.kind.keeps_newlines() {
            // The newline rule is fixed per buffer; the old (already wiped) one drops.
            self.secret = secret_buffer(kind);
        }
        self.kind = kind;
    }

    /// Fills the label with a suggestion. Returns whether it fit.
    fn apply_suggestion(&mut self, suggestion: &str) -> bool {
        match LineBuf::from_text(suggestion) {
            Some(label) => {
                self.label = label;
                true
            }
            None => false,
        }
    }

    /// A validated field built from copies of this row's buffers; the row is unchanged.
    fn to_field(&self) -> Result<CustomField, FieldError> {
        let value = match self.kind {
            Kind::Text => FieldValue::Text(Text::new(self.text.as_str().to_owned())),
            Kind::Secret => FieldValue::Secret(copy_secret(&self.secret)),
            Kind::Multiline => FieldValue::MultilineSecret(copy_secret(&self.secret)),
            // An empty box keeps the stored codes; typed text replaces them, all unused.
            Kind::Codes => FieldValue::RecoveryCodes(match &self.kept {
                Some(kept) if self.secret.is_empty() => copy_codes(kept),
                _ => parse_recovery_codes(self.secret.expose_for_paint())?,
            }),
            Kind::Date => {
                FieldValue::Date(parse_date(self.date.as_str()).ok_or(FieldError::BadDate)?)
            }
        };
        let expiry = if self.reminder.is_empty() {
            None
        } else {
            Some(parse_date(self.reminder.as_str()).ok_or(FieldError::BadDate)?)
        };
        let label = Text::new(self.label.as_str().to_owned());
        try_field(label, value, expiry)
    }

    /// Draws the row's boxes. Returns whether anything changed.
    fn show(
        &mut self,
        ui: &mut egui::Ui,
        io: &mut FieldIo<'_>,
        refused: &mut Option<&'static str>,
    ) -> bool {
        let mut touched = line_field(ui, io, FIELD_NAME_LABEL, &mut self.label);

        let mut suggestion = None;
        egui::ComboBox::from_label(SUGGEST_LABEL)
            .selected_text(CHOOSE)
            .show_ui(ui, |ui| {
                for name in LABEL_SUGGESTIONS.iter() {
                    if ui.selectable_label(false, *name).clicked() {
                        suggestion = Some(*name);
                    }
                }
            });
        if let Some(name) = suggestion {
            touched |= self.apply_suggestion(name);
        }

        let mut kind = self.kind;
        egui::ComboBox::from_label(KIND_LABEL)
            .selected_text(kind.name())
            .show_ui(ui, |ui| {
                for option in Kind::ALL {
                    ui.selectable_value(&mut kind, option, option.name());
                }
            });
        if kind != self.kind {
            self.set_kind(kind);
            touched = true;
        }

        touched |= match self.kind {
            Kind::Text => line_field(ui, io, TEXT_VALUE_LABEL, &mut self.text),
            Kind::Date => line_field_hint(ui, io, DATE_VALUE_LABEL, DATE_HINT, &mut self.date),
            Kind::Secret => {
                io.secret_field(
                    ui,
                    "custom-secret",
                    SECRET_VALUE_LABEL,
                    &mut self.secret,
                    refused,
                )
                .changed
            }
            Kind::Multiline => {
                io.secret_area(
                    ui,
                    "custom-area",
                    MULTILINE_VALUE_LABEL,
                    &mut self.secret,
                    refused,
                )
                .changed
            }
            Kind::Codes => {
                let changed = io
                    .secret_area(
                        ui,
                        "custom-codes",
                        CODES_VALUE_LABEL,
                        &mut self.secret,
                        refused,
                    )
                    .changed;
                ui.label(CODES_HINT);
                if let Some(kept) = &self.kept
                    && self.secret.is_empty()
                {
                    ui.label(messages::codes_kept_line(kept.len()));
                }
                changed
            }
        };
        touched |= line_field_hint(ui, io, REMIND_ON, DATE_HINT, &mut self.reminder);
        touched
    }
}

/// A wiping copy of `buf`'s secret, for `try_field`. The copy is one exact-size
/// allocation moved straight into a `SecretText`, so nothing unwiped is left behind.
fn copy_secret(buf: &SecretInput) -> SecretText {
    SecretText::new(buf.expose_for_paint().to_owned())
}

/// A row button pressed this frame.
#[derive(Clone, Copy)]
enum RowAction {
    Up(usize),
    Down(usize),
    Remove(usize),
}

/// The draft of an item's custom fields. Dropping it wipes every buffer.
pub(crate) struct FieldEditor {
    /// The draft rows, in saved order.
    rows: Vec<DraftRow>,
    /// The fixed line for the last problem.
    error: Option<&'static str>,
}

impl fmt::Debug for FieldEditor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldEditor")
            .field("rows", &self.rows)
            .field("error", &self.error)
            .finish()
    }
}

impl FieldEditor {
    /// An empty draft: the preset picker shows.
    pub(crate) fn new() -> FieldEditor {
        FieldEditor {
            rows: Vec::new(),
            error: None,
        }
    }

    /// A draft filled from stored fields, or `None` when a value does not fit a buffer
    /// (the caller then keeps the fields read-only, so nothing is cut off).
    pub(crate) fn from_fields(fields: &[CustomField]) -> Option<FieldEditor> {
        let mut rows = Vec::with_capacity(fields.len());
        for field in fields {
            rows.push(DraftRow::from_field(field)?);
        }
        Some(FieldEditor { rows, error: None })
    }

    /// Number of draft rows.
    pub(crate) fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the draft has no rows.
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Whether the preset picker shows: only while the draft is empty.
    pub(crate) fn shows_preset(&self) -> bool {
        self.rows.is_empty()
    }

    /// Fills an empty draft with `preset`'s labels and kinds, every value empty. Date
    /// rows are skipped. Does nothing (and returns `false`) when the draft has rows.
    pub(crate) fn apply_preset(&mut self, preset: FieldPreset) -> bool {
        if !self.shows_preset() {
            return false;
        }
        for field in preset_fields(preset) {
            if self.rows.len() >= MAX_CUSTOM_FIELDS {
                break;
            }
            let kind = Kind::from_core(&field.kind);
            if kind == Kind::Date {
                continue;
            }
            let Some(label) = LineBuf::from_text(field.label) else {
                continue;
            };
            self.rows.push(DraftRow::new(label, kind));
        }
        !self.rows.is_empty()
    }

    /// Whether another row fits.
    pub(crate) fn can_add(&self) -> bool {
        self.rows.len() < MAX_CUSTOM_FIELDS
    }

    /// Adds an empty text row at the end. Returns `false` at the limit.
    pub(crate) fn add_field(&mut self) -> bool {
        if !self.can_add() {
            return false;
        }
        self.rows.push(DraftRow::new(LineBuf::new(), Kind::Text));
        true
    }

    /// Whether row `index` can move up.
    pub(crate) fn can_move_up(&self, index: usize) -> bool {
        index > 0 && index < self.rows.len()
    }

    /// Whether row `index` can move down.
    pub(crate) fn can_move_down(&self, index: usize) -> bool {
        index + 1 < self.rows.len()
    }

    /// Swaps row `index` with the one above it, if it can move.
    pub(crate) fn move_up(&mut self, index: usize) {
        if self.can_move_up(index) {
            self.rows.swap(index - 1, index);
        }
    }

    /// Swaps row `index` with the one below it, if it can move.
    pub(crate) fn move_down(&mut self, index: usize) {
        if self.can_move_down(index) {
            self.rows.swap(index, index + 1);
        }
    }

    /// Removes row `index`; its buffers wipe as they drop.
    pub(crate) fn remove(&mut self, index: usize) {
        if index < self.rows.len() {
            self.rows.remove(index);
        }
    }

    /// The draft as validated fields, in order. On the first broken rule the draft is
    /// kept as it is, the fixed line for the rule is set, and the rule is returned.
    pub(crate) fn build(&mut self) -> Result<Vec<CustomField>, FieldError> {
        let mut out = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            match row.to_field() {
                Ok(field) => out.push(field),
                Err(e) => {
                    self.error = Some(messages::field_error(&e));
                    return Err(e);
                }
            }
        }
        self.error = None;
        Ok(out)
    }

    /// Characters typed into secret buffers, for the unsaved-changes check.
    pub(crate) fn secret_char_count(&self) -> usize {
        self.rows.iter().map(|row| row.secret.char_count()).sum()
    }

    /// Draws the preset picker (empty draft only), every row with its buttons, and Add.
    /// Returns whether the draft changed.
    pub(crate) fn show(&mut self, ui: &mut egui::Ui, io: &mut FieldIo<'_>) -> bool {
        let mut touched = false;
        if self.shows_preset() {
            let mut picked = None;
            egui::ComboBox::from_label(PRESET_LABEL)
                .selected_text(CHOOSE)
                .show_ui(ui, |ui| {
                    for (preset, name) in PRESETS {
                        if ui.selectable_label(false, name).clicked() {
                            picked = Some(preset);
                        }
                    }
                });
            if let Some(preset) = picked {
                touched |= self.apply_preset(preset);
            }
        }

        let count = self.rows.len();
        let mut refused = None;
        let mut action = None;
        for (index, row) in self.rows.iter_mut().enumerate() {
            ui.push_id(("custom-field", index), |ui| {
                ui.separator();
                touched |= row.show(ui, io, &mut refused);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(index > 0, egui::Button::new(MOVE_UP))
                        .clicked()
                    {
                        action = Some(RowAction::Up(index));
                    }
                    if ui
                        .add_enabled(index + 1 < count, egui::Button::new(MOVE_DOWN))
                        .clicked()
                    {
                        action = Some(RowAction::Down(index));
                    }
                    if ui.button(REMOVE_FIELD).clicked() {
                        action = Some(RowAction::Remove(index));
                    }
                });
            });
        }
        if let Some(action) = action {
            touched = true;
            match action {
                RowAction::Up(index) => self.move_up(index),
                RowAction::Down(index) => self.move_down(index),
                RowAction::Remove(index) => self.remove(index),
            }
        }

        ui.add_space(4.0);
        if ui
            .add_enabled(self.can_add(), egui::Button::new(ADD_FIELD))
            .clicked()
        {
            touched |= self.add_field();
        }
        if touched {
            self.error = None;
        }
        if refused.is_some() {
            self.error = refused;
        }
        if let Some(error) = self.error {
            ui.label(error);
        }
        touched
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::text::CharIndex;
    use holm_core::fields::codes_left;

    fn text_field(label: &str, value: &str) -> CustomField {
        try_field(
            Text::new(label.to_owned()),
            FieldValue::Text(Text::new(value.to_owned())),
            None,
        )
        .expect("a valid field")
    }

    fn named(editor: &mut FieldEditor, label: &str) {
        assert!(editor.add_field());
        let row = editor.rows.last_mut().expect("a row");
        row.label.insert_text(label, CharIndex(0));
    }

    #[test]
    fn preset_fills_labels_and_kinds_only() {
        let mut editor = FieldEditor::new();
        assert!(editor.shows_preset());
        assert!(editor.apply_preset(FieldPreset::Server));
        assert_eq!(editor.len(), 5);
        let expected: Vec<_> = preset_fields(FieldPreset::Server)
            .iter()
            .filter(|f| Kind::from_core(&f.kind) != Kind::Date)
            .collect();
        assert_eq!(expected.len(), editor.len());
        for (row, preset) in editor.rows.iter().zip(expected) {
            assert_eq!(row.label.as_str(), preset.label);
            assert_eq!(row.kind, Kind::from_core(&preset.kind));
            assert!(row.secret.is_empty());
            assert!(row.text.is_empty());
            assert!(row.date.is_empty());
            assert!(row.reminder.is_empty());
        }
        assert_eq!(editor.secret_char_count(), 0);
    }

    #[test]
    fn custom_preset_adds_no_rows() {
        let mut editor = FieldEditor::new();
        assert!(!editor.apply_preset(FieldPreset::Custom));
        assert_eq!(editor.len(), 0);
        assert!(editor.shows_preset(), "the picker stays");
    }

    #[test]
    fn preset_hidden_when_fields_exist() {
        let mut editor =
            FieldEditor::from_fields(&[text_field("Host", "example.com")]).expect("fits");
        assert!(!editor.shows_preset());
        assert!(!editor.apply_preset(FieldPreset::Server));
        assert_eq!(editor.len(), 1);
        assert_eq!(editor.rows[0].label.as_str(), "Host");
        assert_eq!(editor.rows[0].text.as_str(), "example.com");

        // An added row hides the picker too.
        let mut fresh = FieldEditor::new();
        assert!(fresh.add_field());
        assert!(!fresh.shows_preset());
    }

    #[test]
    fn reorder_up_down() {
        let mut editor = FieldEditor::new();
        named(&mut editor, "A");
        named(&mut editor, "B");
        assert!(!editor.can_move_up(0));
        assert!(editor.can_move_down(0));
        assert!(!editor.can_move_down(1));
        editor.move_down(0);
        assert_eq!(editor.rows[0].label.as_str(), "B");
        assert_eq!(editor.rows[1].label.as_str(), "A");
        // Disabled moves do nothing.
        editor.move_up(0);
        editor.move_down(1);
        assert_eq!(editor.rows[0].label.as_str(), "B");
        editor.move_up(1);
        assert_eq!(editor.rows[0].label.as_str(), "A");
    }

    #[test]
    fn add_field_stops_at_10() {
        let mut editor = FieldEditor::new();
        for _ in 0..10 {
            assert!(editor.can_add());
            assert!(editor.add_field());
        }
        assert_eq!(editor.len(), 10);
        assert!(!editor.can_add());
        assert!(!editor.add_field());
        assert_eq!(editor.len(), 10);
    }

    #[test]
    fn kind_change_wipes_the_value() {
        let mut editor = FieldEditor::new();
        named(&mut editor, "Token");
        let row = &mut editor.rows[0];
        row.set_kind(Kind::Secret);
        row.secret.push_str("EXAMPLE-field-secret");
        row.reminder.insert_text("2026-11-05", CharIndex(0));
        row.set_kind(Kind::Text);
        assert!(row.secret.is_empty());
        assert!(row.text.is_empty());
        assert_eq!(row.reminder.as_str(), "2026-11-05", "the reminder stays");

        row.text.insert_text("EXAMPLE-text", CharIndex(0));
        row.set_kind(Kind::Multiline);
        assert!(row.text.is_empty());
        assert!(row.secret.is_empty());
        // The new buffer keeps newlines.
        row.secret.push_str("a\nb");
        assert_eq!(row.secret.char_count(), 3);
        row.set_kind(Kind::Secret);
        assert!(row.secret.is_empty());
        row.secret.push_str("a\nb");
        assert_eq!(row.secret.char_count(), 2, "single-line drops the newline");
    }

    #[test]
    fn editor_debug_has_no_secret() {
        let mut editor = FieldEditor::new();
        named(&mut editor, "EXAMPLE-label");
        named(&mut editor, "EXAMPLE-label-two");
        editor.rows[0].set_kind(Kind::Secret);
        editor.rows[0].secret.push_str("EXAMPLE-field-secret");
        editor.rows[0]
            .reminder
            .insert_text("EXAMPLE-date", CharIndex(0));
        editor.rows[1]
            .text
            .insert_text("EXAMPLE-text", CharIndex(0));
        let shown = format!("{editor:?}");
        assert!(!shown.contains("EXAMPLE"), "{shown}");
        assert!(shown.contains("Secret"));
        assert!(shown.contains("label_len"));
    }

    #[test]
    fn build_keeps_the_draft_on_error() {
        let mut editor = FieldEditor::new();
        assert!(editor.add_field());
        editor.rows[0].set_kind(Kind::Secret);
        editor.rows[0].secret.push_str("EXAMPLE-field-secret");
        assert!(editor.build().is_err(), "an empty name is refused");
        assert!(editor.error.is_some());
        assert_eq!(editor.len(), 1);
        assert_eq!(editor.rows[0].secret.char_count(), 20);

        editor.rows[0].label.insert_text("Token", CharIndex(0));
        let fields = editor.build().expect("valid now");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].label(), "Token");
        assert!(matches!(
            fields[0].value(),
            FieldValue::Secret(s) if s.expose() == "EXAMPLE-field-secret"
        ));
        assert!(editor.error.is_none());
    }

    #[test]
    fn suggestions_hold_presets_and_extras() {
        for extra in EXTRA_SUGGESTIONS {
            assert!(LABEL_SUGGESTIONS.contains(&extra), "{extra}");
        }
        for (preset, _) in PRESETS {
            for field in preset_fields(preset) {
                assert!(LABEL_SUGGESTIONS.contains(&field.label));
            }
        }
        let mut editor = FieldEditor::new();
        assert!(editor.add_field());
        assert!(editor.rows[0].apply_suggestion("PIN"));
        assert_eq!(editor.rows[0].label.as_str(), "PIN");
    }

    fn codes_field(text: &str, used: &[usize]) -> CustomField {
        let mut codes = parse_recovery_codes(text).expect("valid codes");
        for &index in used {
            codes[index].set_used(true);
        }
        try_field(
            Text::new("Codes".to_owned()),
            FieldValue::RecoveryCodes(codes),
            None,
        )
        .expect("a valid field")
    }

    #[test]
    fn existing_codes_are_kept_when_the_box_is_empty() {
        let field = codes_field("EXAMPLE-1\nEXAMPLE-2", &[1]);
        let mut editor = FieldEditor::from_fields(&[field]).expect("codes fit the editor");
        assert_eq!(editor.rows[0].kind, Kind::Codes);
        let built = editor.build().expect("kept codes build");
        let FieldValue::RecoveryCodes(codes) = built[0].value() else {
            panic!("kind changed");
        };
        assert_eq!(codes_left(codes), (1, 2), "used flags survive");
    }

    #[test]
    fn typed_codes_replace_the_kept_ones() {
        let field = codes_field("EXAMPLE-1\nEXAMPLE-2", &[0, 1]);
        let mut editor = FieldEditor::from_fields(&[field]).expect("codes fit the editor");
        editor.rows[0]
            .secret
            .push_str("EXAMPLE-3\nEXAMPLE-4\nEXAMPLE-5");
        let built = editor.build().expect("typed codes build");
        let FieldValue::RecoveryCodes(codes) = built[0].value() else {
            panic!("kind changed");
        };
        assert_eq!(codes_left(codes), (3, 3), "a typed list starts all unused");
    }

    #[test]
    fn empty_codes_without_kept_are_refused() {
        let mut editor = FieldEditor::new();
        assert!(editor.apply_preset(FieldPreset::RecoveryCodes));
        assert_eq!(editor.rows[0].kind, Kind::Codes);
        assert!(editor.build().is_err());
        assert!(editor.error.is_some());
    }

    #[test]
    fn leaving_the_codes_kind_drops_the_kept_codes() {
        let field = codes_field("EXAMPLE-1", &[]);
        let mut editor = FieldEditor::from_fields(&[field]).expect("codes fit the editor");
        assert!(editor.rows[0].kept.is_some());
        editor.rows[0].set_kind(Kind::Text);
        assert!(editor.rows[0].kept.is_none());
        let shown = format!("{editor:?}");
        assert!(!shown.contains("EXAMPLE"), "{shown}");
    }
}
