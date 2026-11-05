//! Custom fields and checked Gregorian dates, independent of clocks and I/O.

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
            .field("value_len", &self.len())
            .finish()
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
            .field("value_len", &self.value.len())
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

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    #[test]
    fn public_types_are_not_serde() {
        assert_not_impl_any!(CustomField: serde::Serialize, serde::de::DeserializeOwned);
        assert_not_impl_any!(FieldValue: serde::Serialize, serde::de::DeserializeOwned);
        assert_not_impl_any!(CalendarDate: serde::Serialize, serde::de::DeserializeOwned);
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
}
