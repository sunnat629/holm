//! `--copy`: put one value on the clipboard, wait, then clear it.
//!
//! The copy runs in the foreground: Holm waits for the clear time or for Enter, then
//! empties the clipboard, but only if it still holds Holm's value. If another app put
//! something there meanwhile, Holm leaves it alone. If the clipboard can't be read
//! back, Holm clears it anyway and says so. The vault is locked and its
//! folder lock released before the wait starts, so the GUI can open it meanwhile.
//! A copied value is never printed.

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use holm_core::clock::Clock;
use holm_core::fields::FieldValue;
use holm_core::generator::{
    PassphraseSpec, PasswordSpec, UsernameSpec, generate_passphrase, generate_password,
    generate_username,
};
use holm_core::item::{ItemData, ItemId};
use holm_core::session::Session;
use holm_core::settings::CLIPBOARD_DEFAULT_SECS;
use holm_core::text::Text;
use holm_platform::clip_clear::{self, ClearOutcome, PendingClear};
use holm_platform::fs_store::FsStore;
use zeroize::Zeroizing;

use crate::Env;
use crate::args::{CopyField, GenArgs, GenKind};
use crate::output::{CliError, date_text, read_error};
use crate::term::Terminal;
use crate::vault::{self, MAX_PASSWORD_BYTES};

/// The prompt that re-checks the master password before a recovery phrase is copied.
pub const AGAIN_PROMPT: &str = "Master password again: ";

/// The clipboard as a trait, shared with the shell and the GUI.
pub use holm_platform::clip_clear::Clip;

/// Holm's value was there and is gone now.
const CLEARED: &str = "Clipboard cleared.";
/// Another app's copy replaced Holm's value.
const LEFT_ALONE: &str = "The clipboard changed since Holm copied to it, so Holm left it alone.";
/// The clipboard could not be read before the clear, but could after it.
const CLEARED_UNREADABLE: &str =
    "Holm couldn't read the clipboard to check it, so it cleared it anyway.";
/// The clipboard could not be read after the clear.
const CLEARED_UNCHECKED: &str =
    "Holm cleared the clipboard but couldn't read it back to check that it's empty.";

/// The clear after a copy: empties the clipboard if it holds `value` or can't be
/// read (fail closed: Holm never leaves its value there because a read failed), and
/// leaves another app's copy alone. Returns the line that says what happened.
///
/// # Errors
/// [`CliError::ClearFailed`] if `value` is still there after the clear.
pub(crate) fn clear_copied(clip: &mut dyn Clip, value: &str) -> Result<&'static str, CliError> {
    match clip_clear::clear_copied(clip, value) {
        ClearOutcome::Cleared => Ok(CLEARED),
        ClearOutcome::LeftAlone => Ok(LEFT_ALONE),
        ClearOutcome::ClearedUnreadable => Ok(CLEARED_UNREADABLE),
        ClearOutcome::ClearedUnchecked => Ok(CLEARED_UNCHECKED),
        ClearOutcome::StillThere => Err(CliError::ClearFailed),
    }
}

/// Opens the clipboard, before anything is asked, so a system without one says so
/// at once.
pub(crate) fn open_clip(env: &Env) -> Result<Box<dyn Clip>, CliError> {
    (env.clip)().map_err(|_| CliError::NoClipboard)
}

/// The value of `field` on item `id`, copied into a wiping buffer.
///
/// A recovery phrase is shown only after the master password is typed again
/// ([`AGAIN_PROMPT`]); a wrong one counts against the throttle.
///
/// # Errors
/// [`CliError::NotFound`], [`CliError::NoSuchField`] if the item's type has no such
/// field or `field=N` is past its custom fields, [`CliError::EmptyField`], a terminal
/// error, [`CliError::WrongPassword`] or [`CliError::Throttled`]. A custom field does
/// not ask for the master password again.
pub fn value_of(
    session: &mut Session<FsStore>,
    id: ItemId,
    field: CopyField,
    term: &mut dyn Terminal,
) -> Result<Zeroizing<String>, CliError> {
    if let CopyField::Custom(index) = field {
        return custom_value(session, id, index);
    }
    let item = session.item(id).map_err(|_| CliError::NotFound)?;
    let value = match (field, item.data()) {
        (CopyField::Phrase, ItemData::RecoveryPhrase { .. }) => {
            let password = vault::master(term.secret(AGAIN_PROMPT, MAX_PASSWORD_BYTES)?);
            let phrase = session
                .reveal_phrase(id, &password)
                .map_err(|e| read_error(&e))?;
            // Straight from the vault's buffer into a wiping one.
            Zeroizing::new(phrase.to_owned())
        }
        (CopyField::Password, ItemData::Login { password, .. }) => {
            Zeroizing::new(password.expose().to_owned())
        }
        (CopyField::Username, ItemData::Login { username, .. }) => {
            Zeroizing::new(username.as_str().to_owned())
        }
        (CopyField::Url, ItemData::Login { urls, .. }) => {
            Zeroizing::new(urls.first().map_or("", Text::as_str).to_owned())
        }
        (CopyField::Address, ItemData::CryptoAddress { address, .. }) => {
            Zeroizing::new(address.expose().to_owned())
        }
        (CopyField::Memo, ItemData::CryptoAddress { memo, .. }) => {
            Zeroizing::new(memo.expose().to_owned())
        }
        (
            CopyField::Notes,
            ItemData::Login { notes, .. }
            | ItemData::CryptoAddress { notes, .. }
            | ItemData::RecoveryPhrase { notes, .. },
        ) => Zeroizing::new(notes.expose().to_owned()),
        (CopyField::Body, ItemData::SecureNote { body }) => {
            Zeroizing::new(body.expose().to_owned())
        }
        _ => return Err(CliError::NoSuchField),
    };
    if value.is_empty() {
        return Err(CliError::EmptyField);
    }
    Ok(value)
}

/// Custom field `index` (0-based) in a wiping buffer. Never printed.
fn custom_value(
    session: &Session<FsStore>,
    id: ItemId,
    index: u8,
) -> Result<Zeroizing<String>, CliError> {
    let item = session.item(id).map_err(|_| CliError::NotFound)?;
    let Some(field) = item.fields().get(usize::from(index)) else {
        return Err(CliError::NoSuchField);
    };
    let value = match field.value() {
        FieldValue::Text(text) => Zeroizing::new(text.as_str().to_owned()),
        FieldValue::Secret(text) | FieldValue::MultilineSecret(text) => {
            Zeroizing::new(text.expose().to_owned())
        }
        FieldValue::Date(date) => Zeroizing::new(date_text(*date)),
    };
    if value.is_empty() {
        return Err(CliError::EmptyField);
    }
    Ok(value)
}

/// Puts `value` on the clipboard, waits up to `secs` seconds (on either of `clock`'s
/// clocks, so a sleep cannot stretch it) or until Enter, then clears the clipboard if
/// it still holds `value` or can't be read ([`clear_copied`]).
///
/// The clear runs even when the message or the wait fails; that error is returned
/// after it.
///
/// # Errors
/// [`CliError::CopyFailed`] if the clipboard refused the value,
/// [`CliError::ClearFailed`] if the value is still there after the clear, or a
/// terminal or output error.
pub fn copy_and_wait(
    value: Zeroizing<String>,
    secs: u32,
    clip: &mut dyn Clip,
    term: &mut dyn Terminal,
    err: &mut dyn Write,
    clock: &dyn Clock,
) -> Result<(), CliError> {
    clip.set(&value).map_err(|_| CliError::CopyFailed)?;
    // One clamp for every client: the wait and the message use the clamped time.
    let pending = PendingClear::new(value, secs, clock);
    let wait = pending.due().saturating_sub(clock.monotonic());
    let until = Instant::now() + wait;
    let said = writeln!(
        err,
        "Copied. Holm clears the clipboard in {} seconds. Press Enter to clear it now.",
        (wait + Duration::from_millis(500)).as_secs()
    );
    // The wait also ends when the clear is due on either clock: `until` is monotonic,
    // and a Mac asleep stops that clock, so after a wake only the wall clock shows
    // that the time has passed.
    let due = || pending.is_due(clock);
    let waited = term.wait_for_key_interruptible(until, Some(&due));
    let cleared = clear_copied(clip, pending.value());
    drop(pending);
    let cleared = cleared?;
    said?;
    waited?;
    writeln!(err, "{cleared}")?;
    Ok(())
}

/// `holm get REF --copy FIELD`: open, read the value and the clear time, lock the
/// vault and release its folder, then copy and wait.
///
/// # Errors
/// [`CliError::NoClipboard`] before any prompt, the errors of [`vault::open`],
/// [`vault::resolve_any`], [`value_of`] and [`copy_and_wait`].
pub fn get_copy(
    path: &Path,
    reference: &str,
    field: CopyField,
    env: &Env,
    term: &mut dyn Terminal,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let mut clip = open_clip(env)?;
    let (value, secs) = {
        let mut opened = vault::open(path, env, term, err)?;
        let id = vault::resolve_any(&opened.session, reference)?;
        let value = value_of(&mut opened.session, id, field, term)?;
        let settings = opened.session.settings().map_err(|_| CliError::Failed)?;
        (value, settings.clipboard_clear_secs)
        // `opened` drops here: the session locks and the folder lock is released.
    };
    let clock = (env.clock)();
    copy_and_wait(value, secs, clip.as_mut(), term, err, &*clock)
}

/// `holm gen [KIND] --copy`: a new value from the default spec, copied for
/// [`CLIPBOARD_DEFAULT_SECS`] seconds. No vault is opened and nothing is printed to
/// `out`.
///
/// # Errors
/// [`CliError::NoClipboard`], [`CliError::GenerateFailed`], or the errors of
/// [`copy_and_wait`].
pub fn gen_copy(
    args: &GenArgs,
    env: &Env,
    term: &mut dyn Terminal,
    err: &mut dyn Write,
) -> Result<(), CliError> {
    let mut clip = open_clip(env)?;
    let value = gen_secret(args.kind)?;
    let clock = (env.clock)();
    copy_and_wait(
        value,
        CLIPBOARD_DEFAULT_SECS,
        clip.as_mut(),
        term,
        err,
        &*clock,
    )
}

/// A new value of `kind` from the default spec, in a wiping buffer.
///
/// # Errors
/// [`CliError::GenerateFailed`].
pub(crate) fn gen_secret(kind: GenKind) -> Result<Zeroizing<String>, CliError> {
    let failed = |_| CliError::GenerateFailed;
    Ok(match kind {
        GenKind::Password => Zeroizing::new(
            generate_password(&PasswordSpec::DEFAULT)
                .map_err(failed)?
                .expose()
                .to_owned(),
        ),
        GenKind::Passphrase => Zeroizing::new(
            generate_passphrase(&PassphraseSpec::DEFAULT)
                .map_err(failed)?
                .expose()
                .to_owned(),
        ),
        GenKind::Username => Zeroizing::new(
            generate_username(&UsernameSpec::DEFAULT)
                .map_err(failed)?
                .as_str()
                .to_owned(),
        ),
    })
}
