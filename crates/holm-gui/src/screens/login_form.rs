//! The login form: title, username, web address and password, for adding a login or
//! editing one.
//!
//! Title, username and address are plain text fields, held in a zeroizing, fixed-size
//! buffer ([`LineBuf`]) so the editor can never grow it (a growth would leave an
//! unwiped copy behind). The password goes through the secret field widget and a
//! [`SecretInput`]. Notes and any web addresses after the first are not shown; an edit
//! keeps them as they are stored.
//!
//! Custom fields live in a [`FieldEditor`]. An edit fills it from the stored fields, so
//! saving never drops one; a new login starts with an empty editor and its preset
//! picker. Fields handed back after a failed save that do not fit the editor are held
//! as they are and passed through unchanged.

use core::fmt;
use core::ops::Range;

use eframe::egui;
use egui::text::CharIndex;
use holm_core::category::CategoryId;
use holm_core::fields::{CustomField, FieldValue};
use holm_core::item::{Item, ItemData, ItemId, ItemInput};
use holm_core::rules::{FieldError, MAX_LINE_BYTES};
use holm_core::text::{SecretText, Text};
use zeroize::Zeroizing;

use super::FieldIo;
use super::fields::FieldEditor;
use crate::secret_input::{ITEM_SECRET_CAP, SecretInput};

/// Label of the title field.
pub(crate) const TITLE_LABEL: &str = "Title";
/// Label of the username field.
pub(crate) const USERNAME_LABEL: &str = "Username";
/// Label of the web address field.
pub(crate) const URL_LABEL: &str = "Web address";
/// Label of the password field.
pub(crate) const PASSWORD_LABEL: &str = "Password";
/// Label of the save button.
pub(crate) const SAVE_LABEL: &str = "Save";
/// Label of the cancel button.
pub(crate) const CANCEL_LABEL: &str = "Cancel";
/// Heading of the custom fields section.
pub(crate) const CUSTOM_FIELDS_LABEL: &str = "Custom fields";
/// Shown in place of the editor when held fields are passed through unchanged.
pub(crate) const HELD_FIELDS_NOTE: &str =
    "Custom fields are too long to edit here. They are kept as they are.";

/// The form's custom fields.
enum Fields {
    /// The draft editor.
    Editable(FieldEditor),
    /// Fields that do not fit the editor, moved back into the next input unchanged.
    Held(Vec<CustomField>),
}

impl fmt::Debug for Fields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fields::Editable(editor) => editor.fmt(f),
            Fields::Held(held) => write!(f, "Held({})", held.len()),
        }
    }
}

impl Fields {
    /// An empty editor: the preset picker shows.
    fn blank() -> Fields {
        Fields::Editable(FieldEditor::new())
    }

    /// The editor filled from owned fields, or the fields held as they are when a value
    /// does not fit. The owned fields drop (and wipe) once copied into the editor.
    fn from_owned(fields: Vec<CustomField>) -> Fields {
        match FieldEditor::from_fields(&fields) {
            Some(editor) => Fields::Editable(editor),
            None => Fields::Held(fields),
        }
    }

    /// The fields as validated values, leaving an empty editor behind. On a broken rule
    /// nothing changes: the editor keeps its draft and shows the rule's line.
    fn take_built(&mut self) -> Result<Vec<CustomField>, FieldError> {
        let built = match self {
            Fields::Editable(editor) => editor.build()?,
            Fields::Held(held) => core::mem::take(held),
        };
        // The old editor drops here, wiping its buffers.
        *self = Fields::blank();
        Ok(built)
    }

    /// Whether there are no fields or draft rows.
    fn is_empty(&self) -> bool {
        match self {
            Fields::Editable(editor) => editor.is_empty(),
            Fields::Held(held) => held.is_empty(),
        }
    }

    /// Characters held in secret values.
    fn secret_char_count(&self) -> usize {
        match self {
            Fields::Editable(editor) => editor.secret_char_count(),
            Fields::Held(held) => held
                .iter()
                .map(|field| match field.value() {
                    FieldValue::Secret(s) | FieldValue::MultilineSecret(s) => {
                        s.expose().chars().count()
                    }
                    FieldValue::RecoveryCodes(codes) => codes
                        .iter()
                        .map(|code| code.code().expose().chars().count())
                        .sum(),
                    FieldValue::Text(_) | FieldValue::Date(_) => 0,
                })
                .sum(),
        }
    }

    /// Draws the editor, or the note for held fields. Returns whether anything changed.
    fn show(&mut self, ui: &mut egui::Ui, io: &mut FieldIo<'_>) -> bool {
        match self {
            Fields::Editable(editor) => editor.show(ui, io),
            Fields::Held(_) => {
                ui.label(HELD_FIELDS_NOTE);
                false
            }
        }
    }
}

/// A single-line text buffer that never reallocates and wipes itself on drop.
///
/// Its storage is allocated once at [`MAX_LINE_BYTES`]; input that would not fit is
/// cut off, and control characters are dropped. Because it never grows, no copy of a
/// typed value is left behind in freed memory.
pub(crate) struct LineBuf(Zeroizing<String>);

impl LineBuf {
    /// An empty buffer with its full capacity allocated.
    pub(crate) fn new() -> LineBuf {
        LineBuf(Zeroizing::new(String::with_capacity(MAX_LINE_BYTES)))
    }

    /// A buffer holding `text`, or `None` when it does not fit.
    pub(crate) fn from_text(text: &str) -> Option<LineBuf> {
        let mut buf = LineBuf::new();
        (text.len() <= MAX_LINE_BYTES).then(|| {
            buf.0.push_str(text);
            buf
        })
    }

    /// Moves the content out as [`Text`] (no copy) and leaves the buffer empty.
    pub(crate) fn take_text(&mut self) -> Text {
        let moved = core::mem::replace(&mut *self.0, String::with_capacity(MAX_LINE_BYTES));
        Text::new(moved)
    }

    /// Whether the buffer holds nothing.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Byte length of the content.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Byte offset of char index `i`, or the end.
    fn byte_at(&self, i: usize) -> usize {
        self.0
            .char_indices()
            .nth(i)
            .map_or(self.0.len(), |(b, _)| b)
    }
}

impl egui::TextBuffer for LineBuf {
    fn is_mutable(&self) -> bool {
        true
    }

    fn as_str(&self) -> &str {
        &self.0
    }

    fn insert_text(&mut self, text: &str, char_index: CharIndex) -> usize {
        let mut at = self.byte_at(char_index.0);
        let mut inserted = 0;
        for c in text.chars().filter(|c| !c.is_control()) {
            if self.0.len() + c.len_utf8() > MAX_LINE_BYTES {
                break;
            }
            self.0.insert(at, c);
            at += c.len_utf8();
            inserted += 1;
        }
        inserted
    }

    fn delete_char_range(&mut self, char_range: Range<CharIndex>) {
        let start = self.byte_at(char_range.start.0);
        let end = self.byte_at(char_range.end.0);
        if start < end {
            self.0.drain(start..end);
        }
    }

    fn type_id(&self) -> core::any::TypeId {
        core::any::TypeId::of::<Self>()
    }
}

/// What the user did with the form this frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FormAction {
    /// Nothing yet.
    None,
    /// Save was pressed.
    Save,
    /// Cancel was pressed.
    Cancel,
}

/// The form. Every buffer wipes itself when the form drops.
pub(crate) struct LoginForm {
    /// The item being edited, or `None` for a new login.
    pub(crate) id: Option<ItemId>,
    /// The stored item's category, carried through an edit unchanged.
    category: Option<CategoryId>,
    /// The stored item's favourite flag, carried through an edit unchanged.
    favourite: bool,
    /// The custom fields: the editor, or fields held unchanged.
    fields: Fields,
    /// The title being typed.
    title: LineBuf,
    /// The username being typed.
    username: LineBuf,
    /// The first web address being typed. Empty means no address.
    url: LineBuf,
    /// The password being typed.
    pub(crate) password: SecretInput,
    /// The fixed line for the last problem.
    pub(crate) error: Option<&'static str>,
}

impl fmt::Debug for LoginForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginForm")
            .field("editing", &self.id.is_some())
            .field("title_len", &self.title.len())
            .field("username_len", &self.username.len())
            .field("url_len", &self.url.len())
            .field("password", &self.password)
            .field("fields", &self.fields)
            .field("error", &self.error)
            .finish()
    }
}

impl LoginForm {
    /// An empty form for a new login. The field editor is empty, so its preset picker
    /// shows.
    pub(crate) fn new_blank() -> LoginForm {
        LoginForm {
            id: None,
            category: None,
            favourite: false,
            fields: Fields::blank(),
            title: LineBuf::new(),
            username: LineBuf::new(),
            url: LineBuf::new(),
            password: SecretInput::with_capacity(ITEM_SECRET_CAP),
            error: None,
        }
    }

    /// A form filled from a stored login. `None` when `item` is not a login or one of
    /// its values (custom fields included) does not fit a buffer (the caller then shows
    /// the item read-only: nothing is cut off, and nothing changed is ever saved).
    pub(crate) fn from_item(item: &Item) -> Option<LoginForm> {
        let ItemData::Login {
            username,
            password,
            urls,
            ..
        } = item.data()
        else {
            return None;
        };
        Some(LoginForm {
            id: Some(item.id()),
            category: item.category(),
            favourite: item.favourite(),
            fields: Fields::Editable(FieldEditor::from_fields(item.fields())?),
            title: LineBuf::from_text(item.title())?,
            username: LineBuf::from_text(username.as_str())?,
            url: LineBuf::from_text(urls.first().map_or("", Text::as_str))?,
            password: SecretInput::from_secret(password.expose(), ITEM_SECRET_CAP)?,
            error: None,
        })
    }

    /// Refills a form from an input that was taken out by [`LoginForm::take_input`] but
    /// not sent (it failed a check), and shows `error`.
    pub(crate) fn from_input(
        id: Option<ItemId>,
        input: ItemInput,
        error: &'static str,
    ) -> LoginForm {
        let ItemInput {
            title,
            category,
            favourite,
            data,
            fields,
        } = input;
        let mut form = LoginForm::new_blank();
        form.id = id;
        form.category = category;
        form.favourite = favourite;
        form.fields = Fields::from_owned(fields);
        form.error = Some(error);
        form.title = LineBuf::from_text(title.as_str()).unwrap_or_else(LineBuf::new);
        if let ItemData::Login {
            username,
            password,
            urls,
            ..
        } = data
        {
            form.username = LineBuf::from_text(username.as_str()).unwrap_or_else(LineBuf::new);
            form.url = LineBuf::from_text(urls.first().map_or("", Text::as_str))
                .unwrap_or_else(LineBuf::new);
            // The input came out of a capped buffer, so this always fits. If it ever did
            // not, refuse in debug builds rather than blank the password.
            let restored = SecretInput::from_secret(password.expose(), ITEM_SECRET_CAP);
            debug_assert!(restored.is_some(), "a taken password always fits its cap");
            if let Some(p) = restored {
                form.password = p;
            }
        }
        form
    }

    /// Moves the fields out into an [`ItemInput`] (no copies) and leaves the form
    /// empty. An empty address field means no address; otherwise it is the first
    /// address and `kept_urls` (the stored ones after the first) follow it. The custom
    /// fields are built first: if one breaks a rule, nothing is moved, the editor shows
    /// the rule's line, and the rule is returned.
    pub(crate) fn take_input(
        &mut self,
        kept_notes: SecretText,
        kept_urls: Vec<Text>,
    ) -> Result<ItemInput, FieldError> {
        let fields = self.fields.take_built()?;
        let title = self.title.take_text();
        let username = self.username.take_text();
        let first = self.url.take_text();
        let mut urls = Vec::with_capacity(1 + kept_urls.len());
        if !first.as_str().is_empty() {
            urls.push(first);
        }
        urls.extend(kept_urls);
        Ok(ItemInput {
            fields,
            title,
            category: self.category,
            favourite: self.favourite,
            data: ItemData::Login {
                username,
                password: self.password.take_secret_text(),
                urls,
                notes: kept_notes,
            },
        })
    }

    /// Whether every buffer is empty, custom fields included.
    pub(crate) fn buffers_empty(&self) -> bool {
        self.title.is_empty()
            && self.username.is_empty()
            && self.url.is_empty()
            && self.password.is_empty()
            && self.fields.is_empty()
    }

    /// Characters held by the password and the custom secret values.
    pub(crate) fn secret_char_count(&self) -> usize {
        self.password.char_count() + self.fields.secret_char_count()
    }

    /// Draws the form and reports what was pressed.
    pub(crate) fn show(&mut self, ui: &mut egui::Ui, io: &mut FieldIo<'_>) -> FormAction {
        ui.heading(if self.id.is_some() {
            "Edit login"
        } else {
            "New login"
        });
        ui.add_space(8.0);
        let mut touched = false;
        touched |= line_field(ui, io, TITLE_LABEL, &mut self.title);
        touched |= line_field(ui, io, USERNAME_LABEL, &mut self.username);
        touched |= line_field(ui, io, URL_LABEL, &mut self.url);
        ui.add_space(4.0);
        let mut refused = None;
        touched |= io
            .secret_field(
                ui,
                "login-password",
                PASSWORD_LABEL,
                &mut self.password,
                &mut refused,
            )
            .changed;
        ui.add_space(8.0);
        ui.label(CUSTOM_FIELDS_LABEL);
        touched |= self.fields.show(ui, io);
        if touched {
            self.error = None;
        }
        if refused.is_some() {
            self.error = refused;
        }
        ui.add_space(8.0);
        let mut action = FormAction::None;
        ui.horizontal(|ui| {
            if ui.button(SAVE_LABEL).clicked() {
                action = FormAction::Save;
            }
            if ui.button(CANCEL_LABEL).clicked() {
                action = FormAction::Cancel;
            }
        });
        if let Some(error) = self.error {
            ui.label(error);
        }
        action
    }
}

/// One labelled single-line field. Notes its focus in `io` (a Cmd+V then pastes into it
/// through `HolmApp`'s `raw_input_hook`). Returns whether the text changed.
pub(crate) fn line_field(
    ui: &mut egui::Ui,
    io: &mut FieldIo<'_>,
    label: &'static str,
    buf: &mut LineBuf,
) -> bool {
    line_field_inner(ui, io, label, None, buf)
}

/// Like [`line_field`], with `hint` shown while the field is empty.
pub(crate) fn line_field_hint(
    ui: &mut egui::Ui,
    io: &mut FieldIo<'_>,
    label: &'static str,
    hint: &'static str,
    buf: &mut LineBuf,
) -> bool {
    line_field_inner(ui, io, label, Some(hint), buf)
}

/// Shared body of [`line_field`] and [`line_field_hint`].
fn line_field_inner(
    ui: &mut egui::Ui,
    io: &mut FieldIo<'_>,
    label: &'static str,
    hint: Option<&'static str>,
    buf: &mut LineBuf,
) -> bool {
    let label_id = ui.label(label).id;
    let mut edit = egui::TextEdit::singleline(buf)
        .char_limit(MAX_LINE_BYTES / 4)
        .desired_width(320.0);
    if let Some(hint) = hint {
        edit = edit.hint_text(hint);
    }
    let response = ui.add(edit).labelled_by(label_id);
    io.note_plain(response.has_focus());
    response.changed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::TextBuffer as _;

    fn filled() -> LoginForm {
        let mut form = LoginForm::new_blank();
        form.title.insert_text("Example Mail", CharIndex(0));
        form.username.insert_text("ada@example.com", CharIndex(0));
        form.url
            .insert_text("https://mail.example.com", CharIndex(0));
        form.password.push_str("EXAMPLE-zq9-pass");
        form
    }

    #[test]
    fn to_input_moves_fields_and_keeps_notes_and_extra_urls() {
        let mut form = filled();
        let input = form
            .take_input(
                SecretText::new("EXAMPLE note".to_owned()),
                vec![Text::new("https://second.example.com".to_owned())],
            )
            .expect("no custom fields");
        assert!(form.buffers_empty(), "the form is empty after the move");
        assert_eq!(input.title.as_str(), "Example Mail");
        let ItemData::Login {
            username,
            password,
            urls,
            notes,
        } = input.data
        else {
            panic!("a login");
        };
        assert_eq!(username.as_str(), "ada@example.com");
        assert_eq!(password.expose(), "EXAMPLE-zq9-pass");
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].as_str(), "https://mail.example.com");
        assert_eq!(urls[1].as_str(), "https://second.example.com");
        assert_eq!(notes.expose(), "EXAMPLE note");
    }

    #[test]
    fn blank_url_means_no_url() {
        let mut form = filled();
        form.url.delete_char_range(CharIndex(0)..CharIndex(100));
        assert!(form.url.is_empty());
        let input = form
            .take_input(SecretText::new(String::new()), Vec::new())
            .expect("no custom fields");
        let ItemData::Login { urls, .. } = input.data else {
            panic!("a login");
        };
        assert!(urls.is_empty());
    }

    #[test]
    fn line_buf_never_grows_past_its_cap() {
        let mut buf = LineBuf::new();
        let before = buf.0.as_ptr();
        let long = "a".repeat(MAX_LINE_BYTES + 50);
        let n = buf.insert_text(&long, CharIndex(0));
        assert_eq!(n, MAX_LINE_BYTES);
        assert_eq!(buf.len(), MAX_LINE_BYTES);
        assert_eq!(buf.0.as_ptr(), before, "no reallocation");
        assert_eq!(buf.insert_text("é", CharIndex(0)), 0, "full");
    }

    #[test]
    fn line_buf_drops_control_chars_and_edits_by_char() {
        let mut buf = LineBuf::new();
        assert_eq!(buf.insert_text("a\nb\tc", CharIndex(0)), 3);
        assert_eq!(buf.as_str(), "abc");
        buf.insert_text("é", CharIndex(1));
        assert_eq!(buf.as_str(), "aébc");
        buf.delete_char_range(CharIndex(1)..CharIndex(3));
        assert_eq!(buf.as_str(), "ac");
    }

    #[test]
    fn debug_shows_lengths_only() {
        let form = filled();
        let shown = format!("{form:?}");
        for secret in ["Example Mail", "ada@example.com", "mail.example.com", "zq9"] {
            assert!(!shown.contains(secret), "{shown}");
        }
        assert!(shown.contains("title_len"));
    }

    #[test]
    fn from_input_restores_fields_with_error() {
        let mut form = filled();
        let input = form
            .take_input(SecretText::new(String::new()), Vec::new())
            .expect("no custom fields");
        let back = LoginForm::from_input(None, input, "Add a title.");
        assert_eq!(back.title.as_str(), "Example Mail");
        assert_eq!(back.error, Some("Add a title."));
        assert!(!back.password.is_empty());
    }

    #[test]
    fn edit_keeps_the_stored_category_and_favourite() {
        use holm_core::clock::SystemClock;
        use holm_core::session::Session;
        use holm_crypto::MasterPassword;
        use holm_crypto::kdf::KdfParams;
        use holm_platform::fs_store::FsStore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Holm").join("holm.vault");
        holm_platform::paths::ensure_vault_dir(&path).unwrap();
        let mut session = Session::new(FsStore::new(path), Box::new(SystemClock::new()));
        let password = MasterPassword::new("correct-Horse-battery-staple-EXAMPLE-9".to_owned());
        session.create(&password, &KdfParams::FLOOR).unwrap();
        let mut form = filled();
        let mut input = form
            .take_input(SecretText::new(String::new()), Vec::new())
            .expect("no custom fields");
        let category = session.add_category("Example").unwrap();
        input.category = Some(category);
        let id = session.add_item(input).unwrap();
        session.set_favourite(id, true).unwrap();

        let mut form = LoginForm::from_item(session.item(id).unwrap()).unwrap();
        let input = form
            .take_input(SecretText::new(String::new()), Vec::new())
            .expect("no custom fields");
        assert!(input.favourite, "favourite is carried through an edit");
        assert_eq!(
            input.category,
            Some(category),
            "category is carried through an edit"
        );
        let mut back = LoginForm::from_input(Some(id), input, "x");
        let again = back
            .take_input(SecretText::new(String::new()), Vec::new())
            .expect("no custom fields");
        assert!(again.favourite, "and through a refill");
        assert_eq!(again.category, Some(category), "category too");
    }

    #[test]
    fn login_edit_keeps_custom_fields() {
        use holm_core::clock::SystemClock;
        use holm_core::fields::try_field;
        use holm_core::session::Session;
        use holm_crypto::MasterPassword;
        use holm_crypto::kdf::KdfParams;
        use holm_platform::fs_store::FsStore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Holm").join("holm.vault");
        holm_platform::paths::ensure_vault_dir(&path).unwrap();
        let mut session = Session::new(FsStore::new(path), Box::new(SystemClock::new()));
        let password = MasterPassword::new("correct-Horse-battery-staple-EXAMPLE-9".to_owned());
        session.create(&password, &KdfParams::FLOOR).unwrap();

        let mut form = filled();
        let input = form
            .take_input(SecretText::new(String::new()), Vec::new())
            .expect("no custom fields");
        let id = session.add_item(input).unwrap();
        let secret = "EXAMPLE-custom-s\u{e9}cret 42!";
        let field = try_field(
            Text::new("Recovery code".to_owned()),
            FieldValue::Secret(SecretText::new(secret.to_owned())),
            None,
        )
        .unwrap();
        session.set_custom_fields(id, vec![field]).unwrap();

        let mut form = LoginForm::from_item(session.item(id).unwrap()).expect("fits");
        assert!(!form.buffers_empty());
        assert_eq!(form.secret_char_count(), {
            "EXAMPLE-zq9-pass".chars().count() + secret.chars().count()
        });
        assert!(!format!("{form:?}").contains("EXAMPLE"));
        let input = form
            .take_input(SecretText::new(String::new()), Vec::new())
            .expect("stored fields rebuild");
        assert!(form.buffers_empty(), "the editor is empty after the move");
        assert_eq!(input.fields.len(), 1, "an edit never drops a stored field");
        assert_eq!(input.fields[0].label(), "Recovery code");
        match input.fields[0].value() {
            FieldValue::Secret(s) => assert_eq!(s.expose().as_bytes(), secret.as_bytes()),
            _ => panic!("still a secret"),
        }
    }

    #[test]
    fn new_login_shows_preset() {
        let form = LoginForm::new_blank();
        let Fields::Editable(editor) = &form.fields else {
            panic!("a new login has an editor");
        };
        assert!(editor.is_empty());
        assert!(editor.shows_preset());
        assert!(form.buffers_empty());
        assert_eq!(form.secret_char_count(), 0);
    }
}
