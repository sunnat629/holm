//! `add`, `edit`, `rm` and `passwd`.
//!
//! Public fields (title, username, web addresses, chain, category) come from flags.
//! Every secret is typed at a hidden prompt: never a flag, the environment or a pipe.
//! Flags are checked against the item type before any secret is asked for.

use std::io::Write;
use std::mem;
use std::path::Path;

use holm_core::category::{CategoryId, name_key};
use holm_core::error::CoreError;
use holm_core::fields::{
    CalendarDate, CustomField, FieldKind, FieldPreset, FieldValue, RecoveryCode, insert_field,
    move_field, parse_date, parse_recovery_codes, preset_fields, remove_field, try_field,
};
use holm_core::generator::generate_password;
use holm_core::item::{Item, ItemData, ItemId, ItemInput, ItemType};
use holm_core::rules::{
    FieldError, MAX_CUSTOM_FIELDS, MAX_LINE_BYTES, MAX_MULTILINE_SECRET_BYTES, MAX_NOTE_BYTES,
    MAX_RECOVERY_CODE_BYTES, MAX_RECOVERY_CODES, MAX_SECRET_BYTES,
};
use holm_core::search::{Query, View};
use holm_core::session::Session;
use holm_core::strength;
use holm_core::text::{GatedSecret, SecretText, Text};
use holm_platform::fs_store::FsStore;
use zeroize::Zeroizing;

use crate::Env;
use crate::args::{
    AddArgs, BAD_DATE, CategoryArg, EditArgs, ExpiryEdit, FieldEdit, MISSING_VALUE, NewPassword,
    RefArgs, RmArgs, SECRET_ON_COMMAND_LINE,
};
use crate::output::{CliError, clean, read_error, write_error};
use crate::term::Terminal;
use crate::vault::{self, MAX_PASSWORD_BYTES};

/// One prompt for a custom secret or multiline value. The label stays off the prompt.
const FIELD_PROMPT: &str = "Field value: ";

/// The first 8 hex digits of an id, as `list` shows it.
fn short(id: holm_core::item::ItemId) -> String {
    let mut hex = id.to_hex();
    hex.truncate(8);
    hex
}

/// Moves typed text into a secret field without another copy.
fn secret_of(mut typed: Zeroizing<String>) -> SecretText {
    SecretText::new(mem::take(&mut *typed))
}

/// Moves a parsed field into wiping vault text without a copy.
fn text_of(mut typed: Zeroizing<String>) -> Text {
    Text::new(mem::take(&mut *typed))
}

/// A copy of a stored secret, straight into a wiping field.
fn keep(s: &SecretText) -> SecretText {
    SecretText::new(s.expose().to_owned())
}

/// A copy of a stored public field.
fn keep_text(t: &Text) -> Text {
    Text::new(t.as_str().to_owned())
}

/// One hidden entry.
fn hidden(term: &mut dyn Terminal, prompt: &str, max: usize) -> Result<SecretText, CliError> {
    Ok(secret_of(term.secret(prompt, max)?))
}

/// A new secret typed twice. The two must match.
fn twice(
    term: &mut dyn Terminal,
    prompt: &str,
    again: &str,
    max: usize,
) -> Result<SecretText, CliError> {
    let first = term.secret(prompt, max)?;
    let second = term.secret(again, max)?;
    if *first != *second {
        return Err(CliError::SecretsDiffer);
    }
    drop(second);
    Ok(secret_of(first))
}

/// A login password from the vault's generator settings. Never printed.
fn generated(session: &Session<FsStore>) -> Result<SecretText, CliError> {
    let settings = session.settings().map_err(|_| CliError::Failed)?;
    generate_password(&settings.password).map_err(|_| CliError::GenerateFailed)
}

/// The category with this name (compared as the core compares names).
fn category_named(session: &Session<FsStore>, name: &str) -> Result<CategoryId, CliError> {
    let key = name_key(name);
    let categories = session.categories().map_err(|_| CliError::Failed)?;
    categories
        .iter()
        .find(|c| name_key(c.name()) == key)
        .map(|c| c.id())
        .ok_or(CliError::UnknownCategory)
}

/// Asks for `word` at a visible prompt. Anything else is [`CliError::NotConfirmed`].
pub(crate) fn confirm(term: &mut dyn Terminal, prompt: &str, word: &str) -> Result<(), CliError> {
    match term.line(prompt, MAX_LINE_BYTES, None)? {
        Some(typed) if typed.trim() == word => Ok(()),
        _ => Err(CliError::NotConfirmed),
    }
}

/// `holm add TYPE --title T …`: asks for the new item's secrets, adds it, and prints
/// the new id's first 8 hex digits.
///
/// # Errors
/// [`CliError::UnknownCategory`] before any secret prompt, [`CliError::SecretsDiffer`],
/// a terminal error, or [`write_error`] of the add.
pub fn add(
    path: &Path,
    args: AddArgs,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let mut opened = vault::open(path, env, term, err)?;
    add_to(&mut opened.session, args, term, out)
}

/// The body of [`add`] on an open session, for `holm shell` too.
pub(crate) fn add_to(
    session: &mut Session<FsStore>,
    args: AddArgs,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let category = match &args.category {
        None => None,
        Some(name) => Some(category_named(session, name)?),
    };
    let notes = |term: &mut dyn Terminal, ask: bool| -> Result<SecretText, CliError> {
        if ask {
            hidden(term, "Notes: ", MAX_NOTE_BYTES)
        } else {
            Ok(SecretText::new(String::new()))
        }
    };
    let data = match args.item_type {
        ItemType::Login => {
            let password = if args.generate {
                generated(session)?
            } else {
                twice(
                    term,
                    "Password: ",
                    "Repeat the password: ",
                    MAX_SECRET_BYTES,
                )?
            };
            ItemData::Login {
                username: text_of(args.username.unwrap_or_default()),
                password,
                urls: args.urls.into_iter().map(text_of).collect(),
                notes: notes(term, args.with_notes)?,
            }
        }
        ItemType::CryptoAddress => ItemData::CryptoAddress {
            chain: text_of(args.chain.unwrap_or_default()),
            address: hidden(term, "Address: ", MAX_LINE_BYTES)?,
            memo: hidden(term, "Memo (Enter for none): ", MAX_LINE_BYTES)?,
            notes: notes(term, args.with_notes)?,
        },
        ItemType::RecoveryPhrase => ItemData::RecoveryPhrase {
            phrase: GatedSecret::new(twice(
                term,
                "Recovery phrase: ",
                "Repeat the recovery phrase: ",
                MAX_SECRET_BYTES,
            )?),
            notes: notes(term, args.with_notes)?,
        },
        ItemType::SecureNote => ItemData::SecureNote {
            body: hidden(term, "Note: ", MAX_NOTE_BYTES)?,
        },
    };
    // Preset rows come after the item's own secrets, so a codes prompt is last.
    let (fields, empty_count) = match args.preset {
        Some(preset) => fields_from_preset(preset, term)?,
        None => (Vec::new(), 0),
    };
    let input = ItemInput {
        fields,
        title: text_of(args.title),
        category,
        favourite: args.favourite,
        data,
    };
    let id = session.add_item(input).map_err(|e| write_error(&e))?;
    if empty_count > 0 {
        writeln!(out, "Added {empty_count} custom fields with empty values.")?;
    }
    writeln!(out, "Added {}.", short(id))?;
    Ok(())
}

/// True if every flag of `args` fits an item of type `t`.
fn edit_fits(args: &EditArgs, t: ItemType) -> bool {
    t == ItemType::Login
        || (args.username.is_none()
            && args.urls.is_empty()
            && !args.clear_urls
            && args.new_password.is_none())
}

/// `holm edit REF …`: changes the given fields and keeps everything else, secrets
/// included.
///
/// Order: open, find the item, refuse a trashed item or a flag that does not fit its
/// type, find the category, then ask for any new secret.
///
/// # Errors
/// [`CliError::InTrash`] and [`CliError::TypeChange`] before any secret prompt,
/// [`CliError::UnknownCategory`], [`CliError::SecretsDiffer`], a terminal error, or
/// [`write_error`] of the update.
pub fn edit(
    path: &Path,
    args: EditArgs,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let mut opened = vault::open(path, env, term, err)?;
    edit_in(&mut opened.session, args, term, out)
}

/// The body of [`edit`] on an open session, for `holm shell` too.
///
/// A field prompt runs before any stored secret is copied. Cancelling it saves
/// nothing. `update_item` ignores custom fields, so a field change goes through
/// [`Session::set_custom_fields`] after the other edits.
pub(crate) fn edit_in(
    session: &mut Session<FsStore>,
    mut args: EditArgs,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let id = vault::resolve_any(session, &args.reference)?;
    let (item_type, kept_category) = {
        let item = session.open_item(id).map_err(|_| CliError::NotFound)?;
        if item.trashed().is_some() {
            return Err(CliError::InTrash);
        }
        if !edit_fits(&args, item.item_type()) {
            return Err(CliError::TypeChange);
        }
        reject_command_line_secret(&args, &item)?;
        (item.item_type(), item.category())
    };
    let category = match &args.category {
        None => kept_category,
        Some(CategoryArg::Uncategorised) => None,
        Some(CategoryArg::Named(name)) => Some(category_named(session, name)?),
    };
    let (new_password, new_notes) = prompt_builtin(item_type, &args, session, term)?;
    let fields = prepare_fields(session, id, &mut args, term)?;
    if item_changes(&args) {
        let input = {
            let item = session.open_item(id).map_err(|_| CliError::NotFound)?;
            updated_input(&item, &mut args, category, new_password, new_notes)
        };
        session
            .update_item(id, input)
            .map_err(|e| write_error(&e))?;
    } else {
        drop(new_password);
        drop(new_notes);
    }
    if let Some(fields) = fields {
        session
            .set_custom_fields(id, fields)
            .map_err(|e| write_error(&e))?;
    }
    writeln!(out, "Updated {}.", short(id))?;
    Ok(())
}

fn item_changes(args: &EditArgs) -> bool {
    args.title.is_some()
        || args.username.is_some()
        || !args.urls.is_empty()
        || args.clear_urls
        || args.category.is_some()
        || args.favourite.is_some()
        || args.new_password.is_some()
        || args.new_notes
}

fn prompt_builtin(
    item_type: ItemType,
    args: &EditArgs,
    session: &Session<FsStore>,
    term: &mut dyn Terminal,
) -> Result<(Option<SecretText>, Option<SecretText>), CliError> {
    let new_password = match args.new_password {
        None => None,
        Some(NewPassword::Typed) => Some(twice(
            term,
            "New password: ",
            "Repeat the new password: ",
            MAX_SECRET_BYTES,
        )?),
        Some(NewPassword::Generate) => Some(generated(session)?),
    };
    let new_notes = if args.new_notes {
        let prompt = if item_type == ItemType::SecureNote {
            "New note: "
        } else {
            "New notes: "
        };
        Some(hidden(term, prompt, MAX_NOTE_BYTES)?)
    } else {
        None
    };
    Ok((new_password, new_notes))
}

fn updated_input(
    item: &Item,
    args: &mut EditArgs,
    category: Option<CategoryId>,
    new_password: Option<SecretText>,
    new_notes: Option<SecretText>,
) -> ItemInput {
    let keep_or = |new: Option<SecretText>, old: &SecretText| new.unwrap_or_else(|| keep(old));
    let data = match item.data() {
        ItemData::Login {
            username,
            password,
            urls,
            notes,
        } => {
            let mut all: Vec<Text> = if args.clear_urls {
                Vec::new()
            } else {
                urls.iter().map(keep_text).collect()
            };
            all.extend(mem::take(&mut args.urls).into_iter().map(text_of));
            ItemData::Login {
                username: args
                    .username
                    .take()
                    .map_or_else(|| keep_text(username), text_of),
                password: keep_or(new_password, password),
                urls: all,
                notes: keep_or(new_notes, notes),
            }
        }
        ItemData::CryptoAddress {
            chain,
            address,
            memo,
            notes,
        } => {
            drop(new_password);
            ItemData::CryptoAddress {
                chain: keep_text(chain),
                address: keep(address),
                memo: keep(memo),
                notes: keep_or(new_notes, notes),
            }
        }
        // An empty phrase keeps the stored one; the CLI never reads it.
        ItemData::RecoveryPhrase { notes, .. } => {
            drop(new_password);
            ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(SecretText::new(String::new())),
                notes: keep_or(new_notes, notes),
            }
        }
        ItemData::SecureNote { body } => {
            drop(new_password);
            ItemData::SecureNote {
                body: keep_or(new_notes, body),
            }
        }
    };
    ItemInput {
        fields: Vec::new(),
        title: args
            .title
            .take()
            .map_or_else(|| keep_text_str(item.title()), text_of),
        category,
        favourite: args.favourite.unwrap_or(item.favourite()),
        data,
    }
}

/// A secret `--value` on `--field-set` is refused once the stored kind is known.
/// The buffer is wiped when [`EditArgs`] drops.
fn reject_command_line_secret(args: &EditArgs, item: &Item) -> Result<(), CliError> {
    if args.field_value.is_none() {
        return Ok(());
    }
    let secret = match &args.fields {
        FieldEdit::Add { kind, .. } => secret_kind(*kind),
        FieldEdit::Set { position, .. } => {
            let index = position_index(*position)?;
            let field = item
                .fields()
                .get(index)
                .ok_or(CliError::Field(FieldError::NoSuchIndex))?;
            secret_kind(field.kind())
        }
        FieldEdit::Remove { .. } | FieldEdit::Move { .. } | FieldEdit::None => false,
    };
    if secret {
        Err(CliError::Usage(SECRET_ON_COMMAND_LINE))
    } else {
        Ok(())
    }
}

fn secret_kind(kind: FieldKind) -> bool {
    matches!(
        kind,
        FieldKind::Secret | FieldKind::MultilineSecret | FieldKind::RecoveryCodes
    )
}

fn prepare_fields(
    session: &Session<FsStore>,
    id: ItemId,
    args: &mut EditArgs,
    term: &mut dyn Terminal,
) -> Result<Option<Vec<CustomField>>, CliError> {
    match mem::replace(&mut args.fields, FieldEdit::None) {
        FieldEdit::None => Ok(None),
        FieldEdit::Add {
            label,
            kind,
            expiry,
        } => Ok(Some(add_field(
            session,
            id,
            label,
            kind,
            expiry,
            &mut args.field_value,
            term,
        )?)),
        FieldEdit::Remove { position } => {
            args.field_value = None;
            Ok(Some(remove_at(session, id, position)?))
        }
        FieldEdit::Move { from, to } => {
            args.field_value = None;
            Ok(Some(move_at(session, id, from, to)?))
        }
        FieldEdit::Set { position, expiry } => Ok(Some(set_field(
            session,
            id,
            position,
            expiry,
            &mut args.field_value,
            term,
        )?)),
    }
}

fn add_field(
    session: &Session<FsStore>,
    id: ItemId,
    label: String,
    kind: FieldKind,
    expiry: Option<CalendarDate>,
    field_value: &mut Option<Zeroizing<String>>,
    term: &mut dyn Terminal,
) -> Result<Vec<CustomField>, CliError> {
    let len = session
        .entry(id)
        .map_err(|_| CliError::NotFound)?
        .fields()
        .len();
    if len >= MAX_CUSTOM_FIELDS {
        return Err(CliError::Field(FieldError::TooManyFields));
    }
    let value = read_value(kind, field_value, term)?;
    let field = try_field(Text::new(label), value, expiry).map_err(CliError::Field)?;
    let mut fields = copy_fields(
        session
            .open_item(id)
            .map_err(|_| CliError::NotFound)?
            .fields(),
    )?;
    let end = fields.len();
    insert_field(&mut fields, end, field).map_err(CliError::Field)?;
    Ok(fields)
}

fn set_field(
    session: &Session<FsStore>,
    id: ItemId,
    position: u8,
    expiry: ExpiryEdit,
    field_value: &mut Option<Zeroizing<String>>,
    term: &mut dyn Terminal,
) -> Result<Vec<CustomField>, CliError> {
    let index = position_index(position)?;
    let (label, kind, old_expiry) = {
        let entry = session.entry(id).map_err(|_| CliError::NotFound)?;
        let fields = entry.fields();
        let field = fields
            .get(index)
            .ok_or(CliError::Field(FieldError::NoSuchIndex))?;
        (field.label().to_owned(), field.kind(), field.expiry())
    };
    if secret_kind(kind) && field_value.is_some() {
        *field_value = None;
        return Err(CliError::Usage(SECRET_ON_COMMAND_LINE));
    }
    let value = read_value(kind, field_value, term)?;
    let expiry = match expiry {
        ExpiryEdit::Unchanged => old_expiry,
        ExpiryEdit::Clear => None,
        ExpiryEdit::Set(date) => Some(date),
    };
    let field = try_field(Text::new(label), value, expiry).map_err(CliError::Field)?;
    let mut fields = copy_fields(
        session
            .open_item(id)
            .map_err(|_| CliError::NotFound)?
            .fields(),
    )?;
    replace_at(&mut fields, index, field)?;
    Ok(fields)
}

fn replace_at(
    fields: &mut Vec<CustomField>,
    index: usize,
    field: CustomField,
) -> Result<(), CliError> {
    let removed = remove_field(fields, index).map_err(CliError::Field)?;
    if let Err(error) = insert_field(fields, index, field) {
        let _ = insert_field(fields, index, removed);
        return Err(CliError::Field(error));
    }
    Ok(())
}

fn remove_at(
    session: &Session<FsStore>,
    id: ItemId,
    position: u8,
) -> Result<Vec<CustomField>, CliError> {
    let index = position_index(position)?;
    if index >= field_len(session, id)? {
        return Err(CliError::Field(FieldError::NoSuchIndex));
    }
    let mut fields = copy_fields(
        session
            .open_item(id)
            .map_err(|_| CliError::NotFound)?
            .fields(),
    )?;
    remove_field(&mut fields, index).map_err(CliError::Field)?;
    Ok(fields)
}

fn move_at(
    session: &Session<FsStore>,
    id: ItemId,
    from: u8,
    to: u8,
) -> Result<Vec<CustomField>, CliError> {
    let from = position_index(from)?;
    let to = position_index(to)?;
    let len = field_len(session, id)?;
    if from >= len || to >= len {
        return Err(CliError::Field(FieldError::NoSuchIndex));
    }
    let mut fields = copy_fields(
        session
            .open_item(id)
            .map_err(|_| CliError::NotFound)?
            .fields(),
    )?;
    move_field(&mut fields, from, to).map_err(CliError::Field)?;
    Ok(fields)
}

fn field_len(session: &Session<FsStore>, id: ItemId) -> Result<usize, CliError> {
    Ok(session
        .entry(id)
        .map_err(|_| CliError::NotFound)?
        .fields()
        .len())
}

fn read_value(
    kind: FieldKind,
    field_value: &mut Option<Zeroizing<String>>,
    term: &mut dyn Terminal,
) -> Result<FieldValue, CliError> {
    match kind {
        FieldKind::Secret => {
            if field_value.is_some() {
                *field_value = None;
                return Err(CliError::Usage(SECRET_ON_COMMAND_LINE));
            }
            Ok(FieldValue::Secret(secret_of(
                term.secret(FIELD_PROMPT, MAX_SECRET_BYTES)?,
            )))
        }
        FieldKind::MultilineSecret => {
            if field_value.is_some() {
                *field_value = None;
                return Err(CliError::Usage(SECRET_ON_COMMAND_LINE));
            }
            Ok(FieldValue::MultilineSecret(secret_of(
                term.secret(FIELD_PROMPT, MAX_MULTILINE_SECRET_BYTES)?,
            )))
        }
        FieldKind::RecoveryCodes => {
            if field_value.is_some() {
                *field_value = None;
                return Err(CliError::Usage(SECRET_ON_COMMAND_LINE));
            }
            let typed = type_codes(term)?;
            codes_value(&typed)
        }
        FieldKind::Text => {
            let typed = field_value.take().ok_or(CliError::Usage(MISSING_VALUE))?;
            Ok(FieldValue::Text(text_of(typed)))
        }
        FieldKind::Date => {
            let typed = field_value.take().ok_or(CliError::Usage(MISSING_VALUE))?;
            let date = parse_date(&typed).ok_or(CliError::Usage(BAD_DATE))?;
            drop(typed);
            Ok(FieldValue::Date(date))
        }
    }
}

/// The hidden prompt for a recovery codes list, one code per line.
fn type_codes(term: &mut dyn Terminal) -> Result<Zeroizing<String>, CliError> {
    Ok(term.secret(
        FIELD_PROMPT,
        MAX_RECOVERY_CODES * (MAX_RECOVERY_CODE_BYTES + 1),
    )?)
}

/// Typed codes as a field value. An error names the rule only, never a code.
fn codes_value(typed: &str) -> Result<FieldValue, CliError> {
    let codes = parse_recovery_codes(typed).map_err(CliError::Field)?;
    Ok(FieldValue::RecoveryCodes(codes))
}

fn position_index(position: u8) -> Result<usize, CliError> {
    let index = usize::from(position)
        .checked_sub(1)
        .ok_or(CliError::Field(FieldError::NoSuchIndex))?;
    if index >= MAX_CUSTOM_FIELDS {
        Err(CliError::Field(FieldError::NoSuchIndex))
    } else {
        Ok(index)
    }
}

fn copy_fields(fields: &[CustomField]) -> Result<Vec<CustomField>, CliError> {
    fields.iter().map(copy_field).collect()
}

fn copy_field(field: &CustomField) -> Result<CustomField, CliError> {
    let value = match field.value() {
        FieldValue::Text(text) => FieldValue::Text(Text::new(text.as_str().to_owned())),
        FieldValue::Secret(text) => FieldValue::Secret(SecretText::new(text.expose().to_owned())),
        FieldValue::MultilineSecret(text) => {
            FieldValue::MultilineSecret(SecretText::new(text.expose().to_owned()))
        }
        FieldValue::Date(date) => FieldValue::Date(*date),
        FieldValue::RecoveryCodes(codes) => FieldValue::RecoveryCodes(
            codes
                .iter()
                .map(|code| {
                    RecoveryCode::new(
                        SecretText::new(code.code().expose().to_owned()),
                        code.used(),
                    )
                })
                .collect(),
        ),
    };
    try_field(Text::new(field.label().to_owned()), value, field.expiry()).map_err(CliError::Field)
}

/// The preset's rows, and how many of them were stored with an empty value.
///
/// A codes list cannot be empty, so it is asked for at the hidden prompt; nothing
/// typed skips the row. A date row has no empty value and is skipped.
fn fields_from_preset(
    preset: FieldPreset,
    term: &mut dyn Terminal,
) -> Result<(Vec<CustomField>, usize), CliError> {
    let mut fields = Vec::new();
    let mut empty = 0;
    for row in preset_fields(preset) {
        let value = match row.kind {
            FieldKind::Text => FieldValue::Text(Text::new(String::new())),
            FieldKind::Secret => FieldValue::Secret(SecretText::new(String::new())),
            FieldKind::MultilineSecret => {
                FieldValue::MultilineSecret(SecretText::new(String::new()))
            }
            FieldKind::RecoveryCodes => {
                let typed = type_codes(term)?;
                if typed.trim().is_empty() {
                    continue;
                }
                codes_value(&typed)?
            }
            FieldKind::Date => continue,
        };
        if !matches!(value, FieldValue::RecoveryCodes(_)) {
            empty += 1;
        }
        fields.push(
            try_field(Text::new(row.label.to_owned()), value, None).map_err(CliError::Field)?,
        );
    }
    Ok((fields, empty))
}

fn keep_text_str(s: &str) -> Text {
    Text::new(s.to_owned())
}

/// `holm rm REF` moves an item to the Trash. `holm rm --forever REF` deletes a
/// trashed item for good, after `delete` is typed at a visible prompt.
///
/// # Errors
/// [`CliError::InTrash`], [`CliError::NotInTrash`] (before the prompt),
/// [`CliError::NotConfirmed`], a terminal error, or [`write_error`] of the change.
pub fn rm(
    path: &Path,
    args: &RmArgs,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let mut opened = vault::open(path, env, term, err)?;
    rm_in(&mut opened.session, args, term, out)
}

/// The body of [`rm`] on an open session, for `holm shell` too.
pub(crate) fn rm_in(
    session: &mut Session<FsStore>,
    args: &RmArgs,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let id = vault::resolve_any(session, &args.reference)?;
    let trashed = session
        .entry(id)
        .map_err(|_| CliError::NotFound)?
        .trashed()
        .is_some();
    if !args.forever {
        session.trash(id).map_err(|e| write_error(&e))?;
        writeln!(
            out,
            "Moved to the Trash. Run holm rm --forever to delete it for good."
        )?;
        return Ok(());
    }
    if !trashed {
        return Err(CliError::NotInTrash);
    }
    confirm(term, "Type delete to remove this item for good: ", "delete")?;
    session.delete_forever(id).map_err(|e| write_error(&e))?;
    writeln!(out, "Deleted for good.")?;
    Ok(())
}

/// `holm restore REF`: takes a trashed item out of the Trash.
///
/// # Errors
/// [`CliError::NotInTrash`] for an active item, [`CliError::NotFound`],
/// [`CliError::Ambiguous`], or [`write_error`] of the change.
pub fn restore(
    path: &Path,
    args: &RefArgs,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let mut opened = vault::open(path, env, term, err)?;
    restore_in(&mut opened.session, args, out)
}

/// The body of [`restore`] on an open session, for `holm shell` too.
pub(crate) fn restore_in(
    session: &mut Session<FsStore>,
    args: &RefArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    // Only the Trash is searched, so a prefix can't pick an active item by chance.
    let id = match vault::resolve(session, &args.reference, View::Trash) {
        Ok(id) => id,
        Err(CliError::NotFound) => {
            return Err(
                match vault::resolve(session, &args.reference, View::Active) {
                    Ok(_) => CliError::NotInTrash,
                    Err(_) => CliError::NotFound,
                },
            );
        }
        Err(e) => return Err(e),
    };
    session.restore(id).map_err(|e| write_error(&e))?;
    writeln!(out, "Restored {}.", short(id))?;
    Ok(())
}

/// `holm empty-trash`: deletes everything in the Trash for good, after the word
/// `empty` is typed. Anything else leaves the Trash alone.
///
/// # Errors
/// A terminal error, or [`write_error`] of the change.
pub fn empty_trash(
    path: &Path,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let mut opened = vault::open(path, env, term, err)?;
    empty_trash_in(&mut opened.session, term, out)
}

/// The body of [`empty_trash`] on an open session, for `holm shell` too.
pub(crate) fn empty_trash_in(
    session: &mut Session<FsStore>,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let query = Query {
        view: View::Trash,
        ..Query::default()
    };
    let n = session.search(&query).map_err(|_| CliError::Failed)?.len();
    if n == 0 {
        writeln!(out, "Trash is empty.")?;
        return Ok(());
    }
    let noun = if n == 1 { "item" } else { "items" };
    let prompt = format!("Type empty to delete {n} {noun} forever: ");
    let typed = term.line(&prompt, MAX_LINE_BYTES, None)?;
    if typed.as_ref().is_none_or(|t| t.trim() != "empty") {
        writeln!(out, "Nothing deleted.")?;
        return Ok(());
    }
    let removed = session.empty_trash().map_err(|e| write_error(&e))?;
    let noun = if removed == 1 { "item" } else { "items" };
    writeln!(out, "Deleted {removed} {noun} forever.")?;
    Ok(())
}

/// `holm passwd`: changes the master password.
///
/// Order: open, verify the current password, ask for the new one and its repeat,
/// then call [`Session::change_password`]. A weak new password is refused before
/// the repeat. Both password checks use the session throttle.
///
/// # Errors
/// [`CliError::WeakPassword`], [`CliError::SecretsDiffer`],
/// [`CliError::WrongPassword`], [`CliError::Throttled`],
/// [`CliError::PasswordChangeKept`], [`CliError::PasswordChangeUncertain`], or a
/// terminal error.
pub fn passwd(
    path: &Path,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let mut opened = vault::open(path, env, term, err)?;
    passwd_in(&mut opened.session, env, term, out, err)
}

/// The body of [`passwd`] on an open session, for `holm shell` too: it starts at
/// the current password.
pub(crate) fn passwd_in(
    session: &mut Session<FsStore>,
    env: &Env,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let current = vault::master(term.secret("Current master password: ", MAX_PASSWORD_BYTES)?);
    session
        .verify_password(&current)
        .map_err(|e| read_error(&e))?;
    let new = vault::master(term.secret("New master password: ", MAX_PASSWORD_BYTES)?);
    let report = strength::check(&new);
    if !report.verdict.acceptable {
        // zxcvbn's feedback is fixed text from its tables; it never quotes the input.
        if let Some(warning) = &report.warning {
            writeln!(err, "{}", clean(warning))?;
        }
        for tip in &report.suggestions {
            writeln!(err, "Tip: {}", clean(tip))?;
        }
        return Err(CliError::WeakPassword);
    }
    let repeat =
        vault::master(term.secret("Repeat the new master password: ", MAX_PASSWORD_BYTES)?);
    // Compared in NFC form, as the key derivation sees them.
    if new.to_kdf_bytes().expose() != repeat.to_kdf_bytes().expose() {
        return Err(CliError::SecretsDiffer);
    }
    drop(repeat);
    match session.change_password(&current, &new, &env.kdf) {
        Ok(()) => {}
        // The session now holds the new keys and is dirty: one more save puts the
        // whole vault under the new password.
        Err(CoreError::PasswordChangeUncertain(_)) => {
            if session.save().is_err() {
                return Err(CliError::PasswordChangeUncertain);
            }
        }
        Err(CoreError::Store(_) | CoreError::Body(_) | CoreError::Vault(_)) => {
            return Err(CliError::PasswordChangeKept);
        }
        Err(e) => return Err(write_error(&e)),
    }
    writeln!(
        out,
        "Changed the master password. Use the new one from now on."
    )?;
    Ok(())
}
