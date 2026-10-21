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
use holm_core::generator::generate_password;
use holm_core::item::{ItemData, ItemInput, ItemType};
use holm_core::rules::{MAX_LINE_BYTES, MAX_NOTE_BYTES, MAX_SECRET_BYTES};
use holm_core::search::{Query, View};
use holm_core::session::Session;
use holm_core::strength;
use holm_core::text::{GatedSecret, SecretText, Text};
use holm_platform::fs_store::FsStore;
use zeroize::Zeroizing;

use crate::Env;
use crate::args::{AddArgs, CategoryArg, EditArgs, NewPassword, RefArgs, RmArgs};
use crate::output::{CliError, clean, write_error};
use crate::term::Terminal;
use crate::vault::{self, MAX_PASSWORD_BYTES};

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
                username: Text::new(args.username.unwrap_or_default()),
                password,
                urls: args.urls.into_iter().map(Text::new).collect(),
                notes: notes(term, args.with_notes)?,
            }
        }
        ItemType::CryptoAddress => ItemData::CryptoAddress {
            chain: Text::new(args.chain.unwrap_or_default()),
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
    let input = ItemInput {
        title: Text::new(args.title),
        category,
        favourite: args.favourite,
        data,
    };
    let id = session.add_item(input).map_err(|e| write_error(&e))?;
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
pub(crate) fn edit_in(
    session: &mut Session<FsStore>,
    args: EditArgs,
    term: &mut dyn Terminal,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let id = vault::resolve_any(session, &args.reference)?;
    let item = session.item(id).map_err(|_| CliError::NotFound)?;
    if item.trashed().is_some() {
        return Err(CliError::InTrash);
    }
    if !edit_fits(&args, item.item_type()) {
        return Err(CliError::TypeChange);
    }
    let category = match &args.category {
        None => item.category(),
        Some(CategoryArg::Uncategorised) => None,
        Some(CategoryArg::Named(name)) => Some(category_named(session, name)?),
    };
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
        let (prompt, max) = if item.item_type() == ItemType::SecureNote {
            ("New note: ", MAX_NOTE_BYTES)
        } else {
            ("New notes: ", MAX_NOTE_BYTES)
        };
        Some(hidden(term, prompt, max)?)
    } else {
        None
    };
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
            all.extend(args.urls.into_iter().map(Text::new));
            ItemData::Login {
                username: args.username.map_or_else(|| keep_text(username), Text::new),
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
        } => ItemData::CryptoAddress {
            chain: keep_text(chain),
            address: keep(address),
            memo: keep(memo),
            notes: keep_or(new_notes, notes),
        },
        // An empty phrase keeps the stored one; the CLI never reads it.
        ItemData::RecoveryPhrase { notes, .. } => ItemData::RecoveryPhrase {
            phrase: GatedSecret::new(SecretText::new(String::new())),
            notes: keep_or(new_notes, notes),
        },
        ItemData::SecureNote { body } => ItemData::SecureNote {
            body: keep_or(new_notes, body),
        },
    };
    let input = ItemInput {
        title: args
            .title
            .map_or_else(|| keep_text_str(item.title()), Text::new),
        category,
        favourite: args.favourite.unwrap_or(item.favourite()),
        data,
    };
    session
        .update_item(id, input)
        .map_err(|e| write_error(&e))?;
    writeln!(out, "Updated {}.", short(id))?;
    Ok(())
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
        .item(id)
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
            return Err(match vault::resolve(session, &args.reference, View::Active) {
                Ok(_) => CliError::NotInTrash,
                Err(_) => CliError::NotFound,
            });
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
/// Order: open, the current password, the new one (a weak one is refused before the
/// repeat), the repeat, then [`Session::change_password`], which checks the current
/// password through the throttle and writes a whole new vault.
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
