//! The field rules: limits, the [`Field`] and [`FieldError`] types, and the checks every
//! text field goes through. This module imports nothing from [`crate::item`] or
//! [`crate::category`]; both build on it.

/// Most items one vault may hold.
pub const MAX_ITEMS: usize = 50_000;
/// Longest single-line field in bytes: title, username, each URL, chain, address, memo.
pub const MAX_LINE_BYTES: usize = 1024;
/// Longest password or recovery phrase in bytes.
pub const MAX_SECRET_BYTES: usize = 4096;
/// Longest notes or note body in bytes.
pub const MAX_NOTE_BYTES: usize = 65_536;
/// Most URLs on one login.
pub const MAX_URLS: usize = 32;

/// Most custom fields on one item.
pub const MAX_CUSTOM_FIELDS: usize = 10;
/// Longest custom label in Unicode scalar values.
pub const MAX_LABEL_CHARS: usize = 64;
/// Longest multiline custom secret in bytes.
pub const MAX_MULTILINE_SECRET_BYTES: usize = 16 * 1024;
/// Most codes in one recovery code list.
pub const MAX_RECOVERY_CODES: usize = 20;
/// Longest single recovery code in bytes.
pub const MAX_RECOVERY_CODE_BYTES: usize = 64;
/// A reminder this many UTC days ahead, or sooner, counts as expiring.
///
/// Already-past reminders count as well. Callers pass the UTC date in.
/// This constant does not read a clock.
pub const EXPIRING_WITHIN_DAYS: u32 = 30;

/// A field that failed a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// Item title.
    Title,
    /// Login username.
    Username,
    /// Login password.
    Password,
    /// A login URL.
    Url,
    /// Notes.
    Notes,
    /// Crypto chain name.
    Chain,
    /// Crypto address.
    Address,
    /// Crypto memo.
    Memo,
    /// Recovery phrase.
    Phrase,
    /// Secure note body.
    Body,
    /// Category name.
    CategoryName,
    /// Custom field label.
    CustomLabel,
    /// Custom field value.
    CustomValue,
    /// Custom field date or reminder.
    CustomDate,
}

/// A field rule that failed. It names the field and never holds the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FieldError {
    /// The field must not be empty.
    #[error("{0:?} must not be empty")]
    Empty(Field),
    /// The field is longer than allowed.
    #[error("{0:?} is too long")]
    TooLong(Field),
    /// The field has a character that is not allowed.
    #[error("{0:?} contains a character that is not allowed")]
    ForbiddenChar(Field),
    /// A login has more than [`MAX_URLS`] URLs.
    #[error("too many URLs")]
    TooManyUrls,
    /// The value is reserved.
    #[error("{0:?} is a reserved name")]
    Reserved(Field),
    /// An item has more than [`MAX_CUSTOM_FIELDS`] custom fields.
    #[error("An item can have at most 10 custom fields")]
    TooManyFields,
    /// The numbers do not describe a real Gregorian day.
    #[error("That date is not a real calendar day")]
    BadDate,
    /// The requested field position is absent or invalid.
    #[error("That field is not on the item")]
    NoSuchIndex,
    /// A recovery code list is empty or has more than [`MAX_RECOVERY_CODES`] codes.
    #[error("A recovery code list holds 1 to 20 codes")]
    BadCodeCount,
}

/// Bidirectional controls that can disguise text, beyond `char::is_control`.
fn is_bidi(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// True if `c` may not appear in a one-line display field.
pub(crate) fn is_forbidden_display_char(c: char) -> bool {
    c.is_control() || is_bidi(c)
}

/// A one-line display field: length cap, then no controls or bidi.
pub(crate) fn display_field(field: Field, s: &str) -> Result<(), FieldError> {
    if s.len() > MAX_LINE_BYTES {
        return Err(FieldError::TooLong(field));
    }
    if s.chars().any(is_forbidden_display_char) {
        return Err(FieldError::ForbiddenChar(field));
    }
    Ok(())
}

/// A one-line secret: length cap, then no NUL, CR or LF.
pub(crate) fn line_secret(field: Field, s: &str, max: usize) -> Result<(), FieldError> {
    if s.len() > max {
        return Err(FieldError::TooLong(field));
    }
    if s.chars().any(|c| matches!(c, '\0' | '\r' | '\n')) {
        return Err(FieldError::ForbiddenChar(field));
    }
    Ok(())
}

/// A multi-line field: length cap, then no NUL.
pub(crate) fn multi_line(field: Field, s: &str, max: usize) -> Result<(), FieldError> {
    if s.len() > max {
        return Err(FieldError::TooLong(field));
    }
    if s.contains('\0') {
        return Err(FieldError::ForbiddenChar(field));
    }
    Ok(())
}

pub(crate) fn non_blank(field: Field, s: &str) -> Result<(), FieldError> {
    if s.trim().is_empty() {
        Err(FieldError::Empty(field))
    } else {
        Ok(())
    }
}
