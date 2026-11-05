//! Custom fields and checked Gregorian dates, independent of clocks and I/O.
//!
//! Expiry math takes a [`CalendarDate`] for today. It does not read a clock.

use crate::rules::{
    Field, FieldError, MAX_CUSTOM_FIELDS, MAX_LABEL_CHARS, MAX_MULTILINE_SECRET_BYTES,
    MAX_SECRET_BYTES, is_forbidden_display_char, line_secret, multi_line, non_blank,
};
use crate::text::{SecretText, Text};
use core::fmt;

/// A real Gregorian day in years 1 through 9999, without a time or timezone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CalendarDate {
    year: u16,
    month: u8,
    day: u8,
}

impl CalendarDate {
    pub(crate) fn from_parts(year: u16, month: u8, day: u8) -> Result<Self, FieldError> {
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return Err(FieldError::BadDate),
        };
        if !(1..=9999).contains(&year) || day == 0 || day > days {
            return Err(FieldError::BadDate);
        }
        Ok(Self { year, month, day })
    }

    pub(crate) fn parts(self) -> (u16, u8, u8) {
        (self.year, self.month, self.day)
    }
}

/// Parses exactly ten ASCII bytes in `YYYY-MM-DD` form, checking the calendar day.
#[must_use]
pub fn parse_date(s: &str) -> Option<CalendarDate> {
    let bytes: &[u8; 10] = s.as_bytes().try_into().ok()?;
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let digits = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[5], bytes[6], bytes[8], bytes[9],
    ];
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let digit = |i: usize| u16::from(bytes[i] - b'0');
    let year = digit(0) * 1000 + digit(1) * 100 + digit(2) * 10 + digit(3);
    let month = (bytes[5] - b'0') * 10 + bytes[6] - b'0';
    let day = (bytes[8] - b'0') * 10 + bytes[9] - b'0';
    CalendarDate::from_parts(year, month, day).ok()
}

/// Formats a checked date as ten ASCII bytes, without allocating.
#[must_use]
pub fn format_date(d: CalendarDate) -> [u8; 10] {
    let mut out = *b"0000-00-00";
    // Each remainder is in 0..=9, so taking the low byte loses nothing.
    let digit = |n: u16| b'0' + (n % 10).to_le_bytes()[0];
    out[0] = digit(d.year / 1000);
    out[1] = digit(d.year / 100);
    out[2] = digit(d.year / 10);
    out[3] = digit(d.year);
    out[5] = b'0' + d.month / 10;
    out[6] = b'0' + d.month % 10;
    out[8] = b'0' + d.day / 10;
    out[9] = b'0' + d.day % 10;
    out
}

/// Days since 1970-01-01, using Howard Hinnant's public-domain civil algorithm.
#[must_use]
pub fn epoch_day(d: CalendarDate) -> i32 {
    let year = i32::from(d.year) - i32::from(d.month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i32::from(d.month) + if d.month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month + 2) / 5 + i32::from(d.day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The UTC calendar day of a Unix instant, or `None` outside years 1 through 9999.
#[must_use]
pub fn from_unix_secs(secs: i64) -> Option<CalendarDate> {
    let days = secs.div_euclid(86_400);
    let first = CalendarDate {
        year: 1,
        month: 1,
        day: 1,
    };
    let last = CalendarDate {
        year: 9999,
        month: 12,
        day: 31,
    };
    if !(i64::from(epoch_day(first))..=i64::from(epoch_day(last))).contains(&days) {
        return None;
    }
    // Range check comes before the civil arithmetic, including the epoch offset.
    let shifted = i32::try_from(days).ok()? + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let march_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * march_month + 2) / 5 + 1;
    let month = march_month + if march_month < 10 { 3 } else { -9 };
    let year = year + i32::from(month <= 2);
    CalendarDate::from_parts(
        u16::try_from(year).ok()?,
        u8::try_from(month).ok()?,
        u8::try_from(day).ok()?,
    )
    .ok()
}

/// The kind of a custom value, with no content attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    /// A single display line.
    Text,
    /// A single secret line.
    Secret,
    /// Secret text that may contain newlines.
    MultilineSecret,
    /// A calendar day.
    Date,
}

/// A custom value. Secret variants own wiping text; no variant implements `Clone`.
pub enum FieldValue {
    /// One display line, never searched.
    Text(Text),
    /// One secret line, hidden until revealed.
    Secret(SecretText),
    /// Multiline secret text, hidden until revealed.
    MultilineSecret(SecretText),
    /// A calendar day, independent of the reminder date.
    Date(CalendarDate),
}

impl FieldValue {
    fn kind(&self) -> FieldKind {
        match self {
            Self::Text(_) => FieldKind::Text,
            Self::Secret(_) => FieldKind::Secret,
            Self::MultilineSecret(_) => FieldKind::MultilineSecret,
            Self::Date(_) => FieldKind::Date,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Text(value) => value.as_str().len(),
            Self::Secret(value) | Self::MultilineSecret(value) => value.expose().len(),
            Self::Date(_) => 10,
        }
    }
}

impl fmt::Debug for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldValue")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// A validated custom field. Its position is its index in the item's list.
pub struct CustomField {
    label: Text,
    value: FieldValue,
    expiry: Option<CalendarDate>,
}

impl CustomField {
    /// The display label.
    #[must_use]
    pub fn label(&self) -> &str {
        self.label.as_str()
    }

    /// The kind carried by the value.
    #[must_use]
    pub fn kind(&self) -> FieldKind {
        self.value.kind()
    }

    /// The value, keeping secrets inside their wiping types.
    #[must_use]
    pub fn value(&self) -> &FieldValue {
        &self.value
    }

    /// The optional reminder date.
    #[must_use]
    pub fn expiry(&self) -> Option<CalendarDate> {
        self.expiry
    }
}

impl fmt::Debug for CustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomField")
            .field("kind", &self.kind())
            .field("label_len", &self.label().len())
            .field("expiry", &self.expiry.is_some())
            .finish()
    }
}

/// Builds a field only after checking its label, value and optional expiry.
///
/// # Errors
/// Returns the first broken field rule, without any input text.
pub fn try_field(
    label: Text,
    value: FieldValue,
    expiry: Option<CalendarDate>,
) -> Result<CustomField, FieldError> {
    let field = CustomField {
        label,
        value,
        expiry,
    };
    validate_field(&field)?;
    Ok(field)
}

fn validate_field(field: &CustomField) -> Result<(), FieldError> {
    non_blank(Field::CustomLabel, field.label())?;
    if field.label().chars().count() > MAX_LABEL_CHARS {
        return Err(FieldError::TooLong(Field::CustomLabel));
    }
    if field.label().chars().any(is_forbidden_display_char) {
        return Err(FieldError::ForbiddenChar(Field::CustomLabel));
    }
    match field.value() {
        FieldValue::Text(value) => {
            line_secret(Field::CustomValue, value.as_str(), MAX_SECRET_BYTES)?;
            if value.as_str().chars().any(is_forbidden_display_char) {
                return Err(FieldError::ForbiddenChar(Field::CustomValue));
            }
        }
        FieldValue::Secret(value) => {
            line_secret(Field::CustomValue, value.expose(), MAX_SECRET_BYTES)?
        }
        FieldValue::MultilineSecret(value) => multi_line(
            Field::CustomValue,
            value.expose(),
            MAX_MULTILINE_SECRET_BYTES,
        )?,
        FieldValue::Date(date) => {
            CalendarDate::from_parts(date.year, date.month, date.day)?;
        }
    }
    if let Some(date) = field.expiry {
        CalendarDate::from_parts(date.year, date.month, date.day)?;
    }
    Ok(())
}

pub(crate) fn validate_fields(fields: &[CustomField]) -> Result<(), FieldError> {
    if fields.len() > MAX_CUSTOM_FIELDS {
        return Err(FieldError::TooManyFields);
    }
    for field in fields {
        validate_field(field)?;
    }
    Ok(())
}

/// Inserts `field` at `index`. `index == fields.len()` appends.
///
/// The list is checked again after the insert. On error it is unchanged.
///
/// # Errors
/// [`FieldError::NoSuchIndex`] when `index` is past the length.
/// [`FieldError::TooManyFields`] when the list already holds [`MAX_CUSTOM_FIELDS`]
/// fields. Any other [`FieldError`] when the inserted field breaks a field rule.
pub fn insert_field(
    fields: &mut Vec<CustomField>,
    index: usize,
    field: CustomField,
) -> Result<(), FieldError> {
    if index > fields.len() {
        return Err(FieldError::NoSuchIndex);
    }
    if fields.len() >= MAX_CUSTOM_FIELDS {
        return Err(FieldError::TooManyFields);
    }
    fields.insert(index, field);
    if let Err(error) = validate_fields(fields) {
        // The inserted field is dropped here, so a secret in it is wiped.
        fields.remove(index);
        return Err(error);
    }
    Ok(())
}

/// Removes the field at `index` and returns it.
///
/// The list is checked again after the removal. On error the field is put back.
///
/// # Errors
/// [`FieldError::NoSuchIndex`] when `index` is not a current position.
pub fn remove_field(
    fields: &mut Vec<CustomField>,
    index: usize,
) -> Result<CustomField, FieldError> {
    if index >= fields.len() {
        return Err(FieldError::NoSuchIndex);
    }
    let field = fields.remove(index);
    if let Err(error) = validate_fields(fields) {
        fields.insert(index, field);
        return Err(error);
    }
    Ok(field)
}

/// Moves the field at `from` so that it lands at `to`.
///
/// Both indexes are positions in the current list. The same index checks the
/// list and leaves the order as it is. The list is checked again after the move.
/// On error the original order is restored.
///
/// # Errors
/// [`FieldError::NoSuchIndex`] when `from` or `to` is not a current position.
pub fn move_field(fields: &mut Vec<CustomField>, from: usize, to: usize) -> Result<(), FieldError> {
    if from >= fields.len() || to >= fields.len() {
        return Err(FieldError::NoSuchIndex);
    }
    if from != to {
        let field = fields.remove(from);
        fields.insert(to, field);
    }
    if let Err(error) = validate_fields(fields) {
        if from != to {
            let field = fields.remove(to);
            fields.insert(from, field);
        }
        return Err(error);
    }
    Ok(())
}

/// How many UTC days until a reminder, or that the reminder is already past.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryStatus {
    /// Days from today until the reminder. Zero means the reminder is today.
    InDays(u32),
    /// The reminder is before today.
    Expired,
}

/// The status of `expiry` on `today`. Equal dates are [`ExpiryStatus::InDays`]`(0)`.
#[must_use]
pub fn expiry_status(expiry: CalendarDate, today: CalendarDate) -> ExpiryStatus {
    let delta = i64::from(epoch_day(expiry)) - i64::from(epoch_day(today));
    if delta < 0 {
        return ExpiryStatus::Expired;
    }
    // Supported dates are a few million days apart, so this conversion fits.
    ExpiryStatus::InDays(u32::try_from(delta).unwrap_or(u32::MAX))
}

/// The earliest reminder in `fields`.
///
/// Fields with no reminder are skipped. This reads [`CustomField::expiry`] only.
/// It does not read [`CustomField::value`].
#[must_use]
pub fn soonest_expiry(fields: &[CustomField]) -> Option<CalendarDate> {
    fields.iter().filter_map(CustomField::expiry).min()
}

/// Whether the soonest reminder falls on or before `today` plus `within_days`.
///
/// A list with no reminder is false. Days are UTC dates from [`epoch_day`].
/// `within_days` is widened to `i64` so a large window cannot wrap.
#[must_use]
pub fn is_expiring(fields: &[CustomField], today: CalendarDate, within_days: u32) -> bool {
    let Some(soonest) = soonest_expiry(fields) else {
        return false;
    };
    let limit = i64::from(epoch_day(today)) + i64::from(within_days);
    i64::from(epoch_day(soonest)) <= limit
}

/// A starter list of labels and kinds. Applying one does not fill values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldPreset {
    /// Username, password and server.
    Email,
    /// Email, API key, origin CA key and account id.
    Cloudflare,
    /// Username, personal access token and SSH key.
    GitHub,
    /// Host, port, username, password and SSH key.
    Server,
    /// Host, port, database, username and password.
    Database,
    /// Access key id, secret access key and region.
    Aws,
    /// Service, API key and endpoint.
    ApiKey,
    /// Network name and password.
    WiFi,
    /// Cardholder, number, expiry and CVV.
    BankCard,
    /// No rows.
    Custom,
}

/// One preset row. It has a label and a kind, and no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresetField {
    /// Display label.
    pub label: &'static str,
    /// Kind of this row.
    pub kind: FieldKind,
}

const fn preset_row(label: &'static str, kind: FieldKind) -> PresetField {
    PresetField { label, kind }
}

const EMAIL: &[PresetField] = &[
    preset_row("Username", FieldKind::Text),
    preset_row("Password", FieldKind::Secret),
    preset_row("Server", FieldKind::Text),
];

const CLOUDFLARE: &[PresetField] = &[
    preset_row("Email", FieldKind::Text),
    preset_row("Global API key", FieldKind::Secret),
    preset_row("Origin CA key", FieldKind::MultilineSecret),
    preset_row("Account ID", FieldKind::Text),
];

const GITHUB: &[PresetField] = &[
    preset_row("Username", FieldKind::Text),
    preset_row("Personal access token", FieldKind::Secret),
    preset_row("SSH private key", FieldKind::MultilineSecret),
];

const SERVER: &[PresetField] = &[
    preset_row("Host", FieldKind::Text),
    preset_row("Port", FieldKind::Text),
    preset_row("Username", FieldKind::Text),
    preset_row("Password", FieldKind::Secret),
    preset_row("SSH private key", FieldKind::MultilineSecret),
];

const DATABASE: &[PresetField] = &[
    preset_row("Host", FieldKind::Text),
    preset_row("Port", FieldKind::Text),
    preset_row("Database", FieldKind::Text),
    preset_row("Username", FieldKind::Text),
    preset_row("Password", FieldKind::Secret),
];

const AWS: &[PresetField] = &[
    preset_row("Access key ID", FieldKind::Text),
    preset_row("Secret access key", FieldKind::Secret),
    preset_row("Region", FieldKind::Text),
];

const API_KEY: &[PresetField] = &[
    preset_row("Service", FieldKind::Text),
    preset_row("API key", FieldKind::Secret),
    preset_row("Endpoint", FieldKind::Text),
];

const WIFI: &[PresetField] = &[
    preset_row("Network name", FieldKind::Text),
    preset_row("Password", FieldKind::Secret),
];

const BANK_CARD: &[PresetField] = &[
    preset_row("Cardholder", FieldKind::Text),
    preset_row("Number", FieldKind::Secret),
    preset_row("Expiry", FieldKind::Date),
    preset_row("CVV", FieldKind::Secret),
];

/// Labels and kinds for `preset`. [`FieldPreset::Custom`] is an empty slice.
///
/// The rows have no values. A caller that stores them starts from empty values.
#[must_use]
pub fn preset_fields(preset: FieldPreset) -> &'static [PresetField] {
    match preset {
        FieldPreset::Email => EMAIL,
        FieldPreset::Cloudflare => CLOUDFLARE,
        FieldPreset::GitHub => GITHUB,
        FieldPreset::Server => SERVER,
        FieldPreset::Database => DATABASE,
        FieldPreset::Aws => AWS,
        FieldPreset::ApiKey => API_KEY,
        FieldPreset::WiFi => WIFI,
        FieldPreset::BankCard => BANK_CARD,
        FieldPreset::Custom => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::EXPIRING_WITHIN_DAYS;
    use static_assertions::assert_not_impl_any;

    fn field(label: &str, value: &str, expiry: Option<CalendarDate>) -> CustomField {
        try_field(
            Text::new(label.to_owned()),
            FieldValue::Text(Text::new(value.to_owned())),
            expiry,
        )
        .unwrap()
    }

    fn names(fields: &[CustomField]) -> Vec<&str> {
        fields.iter().map(CustomField::label).collect()
    }

    fn shift(today: CalendarDate, days: i64) -> CalendarDate {
        from_unix_secs(i64::from(epoch_day(today)) * 86_400 + days * 86_400).unwrap()
    }

    #[test]
    fn public_types_are_not_serde() {
        assert_not_impl_any!(CustomField: serde::Serialize, serde::de::DeserializeOwned);
        assert_not_impl_any!(FieldValue: serde::Serialize, serde::de::DeserializeOwned);
        assert_not_impl_any!(CalendarDate: serde::Serialize, serde::de::DeserializeOwned);
        // `Item` and `ItemInput` are not `Clone`, so these stay non-`Clone`.
        // A secret value is moved, not copied.
        assert_not_impl_any!(CustomField: Clone, Copy);
        assert_not_impl_any!(FieldValue: Clone, Copy);
    }

    #[test]
    fn unix_epoch_is_1970_01_01() {
        assert_eq!(from_unix_secs(0), parse_date("1970-01-01"));
        assert_eq!(from_unix_secs(86_400), parse_date("1970-01-02"));
        assert_eq!(from_unix_secs(-1), parse_date("1969-12-31"));
        assert_eq!(epoch_day(parse_date("1970-01-01").unwrap()), 0);
        assert_eq!(
            epoch_day(parse_date("2024-03-01").unwrap())
                - epoch_day(parse_date("2024-02-28").unwrap()),
            2
        );
    }

    #[test]
    fn date_syntax_and_utc_bounds() {
        for bad in [
            "",
            "2024-2-29",
            "2024-02-029",
            "2024/02/29",
            " 2024-02-29",
            "2024-02-29\n",
            "２０２４-02-29",
            "0000-01-01",
            "10000-01-01",
            "1900-02-29",
        ] {
            assert!(parse_date(bad).is_none());
        }
        for good in ["0001-01-01", "9999-12-31", "2000-02-29", "2024-02-29"] {
            let date = parse_date(good).unwrap();
            assert_eq!(format_date(date).as_slice(), good.as_bytes());
            assert_eq!(
                from_unix_secs(i64::from(epoch_day(date)) * 86_400),
                Some(date)
            );
        }
        let first = i64::from(epoch_day(parse_date("0001-01-01").unwrap())) * 86_400;
        let last = i64::from(epoch_day(parse_date("9999-12-31").unwrap())) * 86_400;
        assert_eq!(from_unix_secs(first - 1), None);
        assert_eq!(from_unix_secs(last + 86_399), parse_date("9999-12-31"));
        assert_eq!(from_unix_secs(last + 86_400), None);
        assert_eq!(from_unix_secs(i64::MIN), None);
        assert_eq!(from_unix_secs(i64::MAX), None);
    }

    #[test]
    fn custom_field_character_rules() {
        let make = |label: &str, value| try_field(Text::new(label.into()), value, None);
        assert_eq!(
            make("  ", FieldValue::Text(Text::new(String::new()))).unwrap_err(),
            FieldError::Empty(Field::CustomLabel)
        );
        for bad in [
            "EXAMPLE\0",
            "EXAMPLE\r",
            "EXAMPLE\n",
            "EXAMPLE\t",
            "EXAMPLE\u{202e}",
        ] {
            assert_eq!(
                make("EXAMPLE", FieldValue::Text(Text::new(bad.into()))).unwrap_err(),
                FieldError::ForbiddenChar(Field::CustomValue)
            );
        }
        for bad in ["EXAMPLE\0", "EXAMPLE\r", "EXAMPLE\n"] {
            assert!(make("EXAMPLE", FieldValue::Secret(SecretText::new(bad.into()))).is_err());
        }
        assert!(
            make(
                "EXAMPLE",
                FieldValue::Secret(SecretText::new("EXAMPLE\t\u{202e}".into()))
            )
            .is_ok()
        );
        assert!(
            make(
                "EXAMPLE",
                FieldValue::MultilineSecret(SecretText::new("EXAMPLE\r\n\t".into()))
            )
            .is_ok()
        );
        assert!(
            make(
                "EXAMPLE",
                FieldValue::MultilineSecret(SecretText::new("EXAMPLE\0".into()))
            )
            .is_err()
        );
    }

    #[test]
    fn insert_remove_move_roundtrip() {
        let mut fields = Vec::new();
        insert_field(&mut fields, 0, field("a", "va", None)).unwrap();
        insert_field(&mut fields, 1, field("b", "vb", None)).unwrap();
        insert_field(&mut fields, 2, field("c", "vc", None)).unwrap();
        assert_eq!(names(&fields), ["a", "b", "c"]);
        let end = fields.len() - 1;
        move_field(&mut fields, 0, end).unwrap();
        assert_eq!(names(&fields), ["b", "c", "a"]);
        assert_eq!(fields[2].kind(), FieldKind::Text);
        let FieldValue::Text(text) = fields[2].value() else {
            panic!("moved field changed kind");
        };
        assert_eq!(text.as_str(), "va");
        let end = fields.len() - 1;
        let removed = remove_field(&mut fields, end).unwrap();
        assert_eq!(removed.label(), "a");
        assert_eq!(names(&fields), ["b", "c"]);
    }

    #[test]
    fn eleventh_field_refused() {
        let mut fields: Vec<CustomField> = (0..MAX_CUSTOM_FIELDS)
            .map(|i| field(&format!("f{i}"), "", None))
            .collect();
        let before: Vec<String> = fields.iter().map(|item| item.label().to_owned()).collect();
        let end = fields.len();
        let error = insert_field(&mut fields, end, field("extra", "", None)).unwrap_err();
        assert_eq!(error, FieldError::TooManyFields);
        let after: Vec<String> = fields.iter().map(|item| item.label().to_owned()).collect();
        assert_eq!(after, before);
    }

    #[test]
    fn bad_index_refused() {
        let mut fields = vec![field("alpha", "", None)];
        let end = fields.len();
        let error = remove_field(&mut fields, end).unwrap_err();
        assert_eq!(error, FieldError::NoSuchIndex);
        assert!(!error.to_string().contains("alpha"));
        assert_eq!(names(&fields), ["alpha"]);
    }

    #[test]
    fn soonest_of_three() {
        let day3 = parse_date("2026-01-03").unwrap();
        let day10 = parse_date("2026-01-10").unwrap();
        let fields = [
            field("later", "", Some(day10)),
            field("sooner", "", Some(day3)),
            field("open", "", None),
        ];
        assert_eq!(soonest_expiry(&fields), Some(day3));
        assert_eq!(soonest_expiry(&fields[2..]), None);
    }

    #[test]
    fn expiry_status_days() {
        let today = parse_date("2026-11-05").unwrap();
        assert_eq!(
            expiry_status(parse_date("2026-11-06").unwrap(), today),
            ExpiryStatus::InDays(1)
        );
        assert_eq!(expiry_status(today, today), ExpiryStatus::InDays(0));
        assert_eq!(
            expiry_status(parse_date("2026-11-04").unwrap(), today),
            ExpiryStatus::Expired
        );
    }

    #[test]
    fn expiring_window() {
        let today = parse_date("2026-11-05").unwrap();
        let window = i64::from(EXPIRING_WITHIN_DAYS);
        assert!(is_expiring(
            &[field("edge", "", Some(shift(today, window)))],
            today,
            EXPIRING_WITHIN_DAYS
        ));
        assert!(!is_expiring(
            &[field("past-edge", "", Some(shift(today, window + 1)))],
            today,
            EXPIRING_WITHIN_DAYS
        ));
        assert!(is_expiring(
            &[field("yesterday", "", Some(shift(today, -1)))],
            today,
            EXPIRING_WITHIN_DAYS
        ));
        assert!(!is_expiring(
            &[field("open", "", None)],
            today,
            EXPIRING_WITHIN_DAYS
        ));
    }

    #[test]
    fn preset_server_is_labels_and_kinds() {
        let rows = preset_fields(FieldPreset::Server);
        let got: Vec<(&str, FieldKind)> = rows.iter().map(|row| (row.label, row.kind)).collect();
        assert_eq!(
            got.as_slice(),
            [
                ("Host", FieldKind::Text),
                ("Port", FieldKind::Text),
                ("Username", FieldKind::Text),
                ("Password", FieldKind::Secret),
                ("SSH private key", FieldKind::MultilineSecret),
            ]
            .as_slice()
        );
    }

    #[test]
    fn preset_custom_is_empty() {
        assert!(preset_fields(FieldPreset::Custom).is_empty());
    }

    #[test]
    fn presets_fit_in_ten() {
        for preset in [
            FieldPreset::Email,
            FieldPreset::Cloudflare,
            FieldPreset::GitHub,
            FieldPreset::Server,
            FieldPreset::Database,
            FieldPreset::Aws,
            FieldPreset::ApiKey,
            FieldPreset::WiFi,
            FieldPreset::BankCard,
            FieldPreset::Custom,
        ] {
            assert!(preset_fields(preset).len() <= MAX_CUSTOM_FIELDS);
        }
    }

    #[test]
    fn debug_has_no_secret_length() {
        let secret = "EXAMPLE-secret-with-a-length-of-31";
        let field = try_field(
            Text::new("pin".to_owned()),
            FieldValue::Secret(SecretText::new(secret.to_owned())),
            None,
        )
        .unwrap();
        let shown = format!("{field:?} {:?}", field.value());
        assert!(!shown.contains("EXAMPLE"), "{shown}");
        assert!(!shown.contains(&secret.len().to_string()), "{shown}");
        assert!(!shown.contains("value_len"), "{shown}");
    }
}
