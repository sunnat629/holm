//! Crate-private wire types for the vault body.
//!
//! The public item, settings and generator types have no `Serialize` or `Deserialize`,
//! so no code outside this crate can turn them into bytes or build them from bytes. The
//! body codec in [`crate::body`] goes through the types here. Output types borrow from
//! the domain value. Input types hold wiping strings, and every conversion back to a
//! domain value re-runs the field rules, so a stored vault cannot smuggle in a value the
//! rules refuse.
//!
//! Decoding is hostile-input parsing, so every length and count is bounded while it is
//! read: a string is at most [`MAX_WIRE_STR_BYTES`], and each list has its own cap
//! ([`BoundedVec`]). A crafted length prefix is refused before anything is allocated for
//! it.

use crate::body::BodyError;
use crate::category::{Category, CategoryId, MAX_CATEGORIES, validate_category_name};
use crate::fields::{
    CalendarDate, CustomField, FieldValue, RecoveryCode, try_field, validate_fields,
};
use crate::generator::{PassphraseSpec, PasswordSpec, UsernameSpec};
use crate::index::{
    BackupNote, BackupPrompt, EntryPublic, FieldEntry, FieldEntryKind, Index, ItemEntry, RecordRef,
};
use crate::item::{Item, ItemData, ItemId, PhraseRule, Timestamp, validate_item};
use crate::record::{RecordSecrets, SealedData, SealedField, SealedValue};
use crate::rules::{
    FieldError, MAX_CUSTOM_FIELDS, MAX_ITEMS, MAX_NOTE_BYTES, MAX_RECOVERY_CODES, MAX_URLS,
};
use crate::settings::Settings;
use crate::text::{GatedSecret, SecretText, Text};
use core::fmt;
use core::marker::PhantomData;
use holm_crypto::aead::NONCE_LEN;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

/// Longest string the decoder accepts: the largest field cap ([`MAX_NOTE_BYTES`]).
/// Each field's own, smaller cap is checked by the field rules after decoding.
pub(crate) const MAX_WIRE_STR_BYTES: usize = MAX_NOTE_BYTES;

/// The most elements a decoded list reserves room for up front. A longer list grows as
/// it is read, so a large length prefix on a short input costs no large allocation.
const PREALLOC_CAP: usize = 1024;

/// A string that wipes itself, for decoding. At most [`MAX_WIRE_STR_BYTES`] bytes.
struct WireStr(Zeroizing<String>);

impl<'de> Deserialize<'de> for WireStr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<WireStr, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = WireStr;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a string of at most {MAX_WIRE_STR_BYTES} bytes")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<WireStr, E> {
                if s.len() > MAX_WIRE_STR_BYTES {
                    return Err(E::invalid_length(s.len(), &self));
                }
                // One exact allocation, straight into the wiping wrapper.
                Ok(WireStr(Zeroizing::new(s.to_owned())))
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<WireStr, E> {
                let s = Zeroizing::new(s);
                if s.len() > MAX_WIRE_STR_BYTES {
                    return Err(E::invalid_length(s.len(), &self));
                }
                Ok(WireStr(s))
            }
        }
        d.deserialize_string(V)
    }
}

impl WireStr {
    fn text(mut self) -> Text {
        Text::new(core::mem::take(&mut *self.0))
    }
    fn secret(mut self) -> SecretText {
        SecretText::new(core::mem::take(&mut *self.0))
    }
}

/// A list of at most `MAX` elements, for decoding.
///
/// A declared length above `MAX` is refused before any element is read, and at most
/// [`PREALLOC_CAP`] slots are reserved up front. The elements are wire structs whose
/// text lives in separate heap buffers, so growing the list moves only pointers,
/// lengths and plain fields, never secret bytes.
pub(crate) struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    pub(crate) fn into_inner(self) -> Vec<T> {
        self.0
    }

    pub(crate) fn iter(&self) -> core::slice::Iter<'_, T> {
        self.0.iter()
    }
}

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<BoundedVec<T, MAX>, D::Error> {
        struct V<T, const MAX: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for V<T, MAX> {
            type Value = BoundedVec<T, MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a list of at most {MAX} elements")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let hint = seq.size_hint().unwrap_or(0);
                if hint > MAX {
                    return Err(de::Error::invalid_length(hint, &self));
                }
                let mut v = Vec::with_capacity(hint.min(PREALLOC_CAP));
                while let Some(x) = seq.next_element()? {
                    if v.len() == MAX {
                        return Err(de::Error::invalid_length(MAX + 1, &self));
                    }
                    v.push(x);
                }
                Ok(BoundedVec(v))
            }
        }
        d.deserialize_seq(V(PhantomData))
    }
}

/// An item as written.
#[cfg(test)]
#[derive(Serialize)]
pub(crate) struct ItemOutV1<'a> {
    id: ItemId,
    title: &'a str,
    category: Option<CategoryId>,
    favourite: bool,
    created: Timestamp,
    updated: Timestamp,
    trashed: Option<Timestamp>,
    data: DataOutV1<'a>,
}

#[cfg(test)]
#[derive(Serialize)]
enum DataOutV1<'a> {
    Login {
        username: &'a str,
        password: &'a str,
        urls: Vec<&'a str>,
        notes: &'a str,
    },
    CryptoAddress {
        chain: &'a str,
        address: &'a str,
        memo: &'a str,
        notes: &'a str,
    },
    RecoveryPhrase {
        phrase: &'a str,
        notes: &'a str,
    },
    SecureNote {
        body: &'a str,
    },
}

#[cfg(test)]
impl<'a> ItemOutV1<'a> {
    /// Borrows `item` for writing.
    pub(crate) fn new(item: &'a Item) -> ItemOutV1<'a> {
        let data = match &item.data {
            ItemData::Login {
                username,
                password,
                urls,
                notes,
            } => DataOutV1::Login {
                username: username.as_str(),
                password: password.expose(),
                urls: urls.iter().map(Text::as_str).collect(),
                notes: notes.expose(),
            },
            ItemData::CryptoAddress {
                chain,
                address,
                memo,
                notes,
            } => DataOutV1::CryptoAddress {
                chain: chain.as_str(),
                address: address.expose(),
                memo: memo.expose(),
                notes: notes.expose(),
            },
            ItemData::RecoveryPhrase { phrase, notes } => DataOutV1::RecoveryPhrase {
                phrase: phrase.expose(),
                notes: notes.expose(),
            },
            ItemData::SecureNote { body } => DataOutV1::SecureNote {
                body: body.expose(),
            },
        };
        ItemOutV1 {
            id: item.id,
            title: item.title.as_str(),
            category: item.category,
            favourite: item.favourite,
            created: item.created,
            updated: item.updated,
            trashed: item.trashed,
            data,
        }
    }
}

/// An item as read. Nothing here is trusted until [`ItemInV1::into_item`] returns `Ok`.
#[derive(Deserialize)]
pub(crate) struct ItemInV1 {
    id: ItemId,
    title: WireStr,
    category: Option<CategoryId>,
    favourite: bool,
    created: Timestamp,
    updated: Timestamp,
    trashed: Option<Timestamp>,
    data: DataInV1,
}

#[derive(Deserialize)]
enum DataInV1 {
    Login {
        username: WireStr,
        password: WireStr,
        urls: BoundedVec<WireStr, MAX_URLS>,
        notes: WireStr,
    },
    CryptoAddress {
        chain: WireStr,
        address: WireStr,
        memo: WireStr,
        notes: WireStr,
    },
    RecoveryPhrase {
        phrase: WireStr,
        notes: WireStr,
    },
    SecureNote {
        body: WireStr,
    },
}

impl DataInV1 {
    fn into_data(self) -> ItemData {
        match self {
            DataInV1::Login {
                username,
                password,
                urls,
                notes,
            } => ItemData::Login {
                username: username.text(),
                password: password.secret(),
                urls: urls.into_inner().into_iter().map(WireStr::text).collect(),
                notes: notes.secret(),
            },
            DataInV1::CryptoAddress {
                chain,
                address,
                memo,
                notes,
            } => ItemData::CryptoAddress {
                chain: chain.text(),
                address: address.secret(),
                memo: memo.secret(),
                notes: notes.secret(),
            },
            DataInV1::RecoveryPhrase { phrase, notes } => ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(phrase.secret()),
                notes: notes.secret(),
            },
            DataInV1::SecureNote { body } => ItemData::SecureNote {
                body: body.secret(),
            },
        }
    }
}

impl ItemInV1 {
    /// Builds the item and runs every field rule on it.
    ///
    /// # Errors
    /// Returns the first [`FieldError`] found.
    pub(crate) fn into_item(self) -> Result<Item, FieldError> {
        let title = self.title.text();
        let data = self.data.into_data();
        validate_item(&title, &data, PhraseRule::Required)?;
        Ok(Item {
            id: self.id,
            title,
            category: self.category,
            favourite: self.favourite,
            created: self.created,
            updated: self.updated,
            trashed: self.trashed,
            data,
            fields: Vec::new(),
        })
    }
}

/// An item as written.
#[derive(Serialize)]
pub(crate) struct ItemOut<'a> {
    id: ItemId,
    title: &'a str,
    category: Option<CategoryId>,
    favourite: bool,
    created: Timestamp,
    updated: Timestamp,
    trashed: Option<Timestamp>,
    data: DataOut<'a>,
    fields: Vec<CustomFieldOut<'a>>,
}

#[derive(Serialize)]
enum DataOut<'a> {
    Login {
        username: &'a str,
        password: &'a str,
        urls: Vec<&'a str>,
        notes: &'a str,
    },
    CryptoAddress {
        chain: &'a str,
        address: &'a str,
        memo: &'a str,
        notes: &'a str,
    },
    RecoveryPhrase {
        phrase: &'a str,
        notes: &'a str,
    },
    SecureNote {
        body: &'a str,
    },
}

impl<'a> ItemOut<'a> {
    /// Borrows `item` for writing.
    pub(crate) fn new(item: &'a Item) -> ItemOut<'a> {
        let data = match &item.data {
            ItemData::Login {
                username,
                password,
                urls,
                notes,
            } => DataOut::Login {
                username: username.as_str(),
                password: password.expose(),
                urls: urls.iter().map(Text::as_str).collect(),
                notes: notes.expose(),
            },
            ItemData::CryptoAddress {
                chain,
                address,
                memo,
                notes,
            } => DataOut::CryptoAddress {
                chain: chain.as_str(),
                address: address.expose(),
                memo: memo.expose(),
                notes: notes.expose(),
            },
            ItemData::RecoveryPhrase { phrase, notes } => DataOut::RecoveryPhrase {
                phrase: phrase.expose(),
                notes: notes.expose(),
            },
            ItemData::SecureNote { body } => DataOut::SecureNote {
                body: body.expose(),
            },
        };
        ItemOut {
            id: item.id,
            title: item.title.as_str(),
            category: item.category,
            favourite: item.favourite,
            created: item.created,
            updated: item.updated,
            trashed: item.trashed,
            data,
            fields: (0u8..)
                .zip(&item.fields)
                .map(|(position, field)| CustomFieldOut::new(position, field))
                .collect(),
        }
    }
}

/// An item as read. Nothing here is trusted until [`ItemIn::into_item`] returns `Ok`.
#[derive(Deserialize)]
pub(crate) struct ItemIn {
    id: ItemId,
    title: WireStr,
    category: Option<CategoryId>,
    favourite: bool,
    created: Timestamp,
    updated: Timestamp,
    trashed: Option<Timestamp>,
    data: DataIn,
    fields: BoundedVec<CustomFieldIn, MAX_CUSTOM_FIELDS>,
}

#[derive(Deserialize)]
enum DataIn {
    Login {
        username: WireStr,
        password: WireStr,
        urls: BoundedVec<WireStr, MAX_URLS>,
        notes: WireStr,
    },
    CryptoAddress {
        chain: WireStr,
        address: WireStr,
        memo: WireStr,
        notes: WireStr,
    },
    RecoveryPhrase {
        phrase: WireStr,
        notes: WireStr,
    },
    SecureNote {
        body: WireStr,
    },
}

impl DataIn {
    fn into_data(self) -> ItemData {
        match self {
            DataIn::Login {
                username,
                password,
                urls,
                notes,
            } => ItemData::Login {
                username: username.text(),
                password: password.secret(),
                urls: urls.into_inner().into_iter().map(WireStr::text).collect(),
                notes: notes.secret(),
            },
            DataIn::CryptoAddress {
                chain,
                address,
                memo,
                notes,
            } => ItemData::CryptoAddress {
                chain: chain.text(),
                address: address.secret(),
                memo: memo.secret(),
                notes: notes.secret(),
            },
            DataIn::RecoveryPhrase { phrase, notes } => ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(phrase.secret()),
                notes: notes.secret(),
            },
            DataIn::SecureNote { body } => ItemData::SecureNote {
                body: body.secret(),
            },
        }
    }
}

impl ItemIn {
    /// True when any custom field holds recovery codes, which schema 2 cannot hold.
    pub(crate) fn has_recovery_codes(&self) -> bool {
        self.fields
            .iter()
            .any(|field| matches!(field.value, CustomValueIn::RecoveryCodes(_)))
    }

    /// Builds the item and runs every field rule on it.
    ///
    /// # Errors
    /// Returns the first [`FieldError`] found.
    pub(crate) fn into_item(self) -> Result<Item, FieldError> {
        let title = self.title.text();
        let data = self.data.into_data();
        validate_item(&title, &data, PhraseRule::Required)?;
        let mut wire_fields = self.fields.into_inner();
        wire_fields.sort_unstable_by_key(|field| field.position);
        let mut fields = Vec::with_capacity(wire_fields.len());
        for (position, field) in wire_fields.into_iter().enumerate() {
            if usize::from(field.position) != position {
                return Err(FieldError::NoSuchIndex);
            }
            fields.push(field.into_field()?);
        }
        validate_fields(&fields)?;
        Ok(Item {
            id: self.id,
            title,
            category: self.category,
            favourite: self.favourite,
            created: self.created,
            updated: self.updated,
            trashed: self.trashed,
            data,
            fields,
        })
    }
}

/// The date wire order is part of schemas 2 and 3: year, month, day.
#[derive(Serialize, Deserialize)]
struct DateWire {
    year: u16,
    month: u8,
    day: u8,
}

impl DateWire {
    fn new(date: CalendarDate) -> Self {
        let (year, month, day) = date.parts();
        Self { year, month, day }
    }

    fn into_date(self) -> Result<CalendarDate, FieldError> {
        CalendarDate::from_parts(self.year, self.month, self.day)
    }
}

#[derive(Serialize)]
struct RecoveryCodeOut<'a> {
    code: &'a str,
    used: bool,
}

#[derive(Deserialize)]
struct RecoveryCodeIn {
    code: WireStr,
    used: bool,
}

/// Variant order is the postcard index. Index 4, `RecoveryCodes`, is new in schema 3.
#[derive(Serialize)]
enum CustomValueOut<'a> {
    Text(&'a str),
    Secret(&'a str),
    MultilineSecret(&'a str),
    Date(DateWire),
    RecoveryCodes(Vec<RecoveryCodeOut<'a>>),
}

#[derive(Serialize)]
struct CustomFieldOut<'a> {
    position: u8,
    label: &'a str,
    value: CustomValueOut<'a>,
    expiry: Option<DateWire>,
}

impl<'a> CustomFieldOut<'a> {
    fn new(position: u8, field: &'a CustomField) -> Self {
        let value = match field.value() {
            FieldValue::Text(value) => CustomValueOut::Text(value.as_str()),
            FieldValue::Secret(value) => CustomValueOut::Secret(value.expose()),
            FieldValue::MultilineSecret(value) => CustomValueOut::MultilineSecret(value.expose()),
            FieldValue::Date(date) => CustomValueOut::Date(DateWire::new(*date)),
            FieldValue::RecoveryCodes(codes) => CustomValueOut::RecoveryCodes(
                codes
                    .iter()
                    .map(|code| RecoveryCodeOut {
                        code: code.code().expose(),
                        used: code.used(),
                    })
                    .collect(),
            ),
        };
        Self {
            position,
            label: field.label(),
            value,
            expiry: field.expiry().map(DateWire::new),
        }
    }
}

/// Variant order is the postcard index. Index 4, `RecoveryCodes`, is new in schema 3.
#[derive(Deserialize)]
enum CustomValueIn {
    Text(WireStr),
    Secret(WireStr),
    MultilineSecret(WireStr),
    Date(DateWire),
    RecoveryCodes(BoundedVec<RecoveryCodeIn, MAX_RECOVERY_CODES>),
}

#[derive(Deserialize)]
struct CustomFieldIn {
    position: u8,
    label: WireStr,
    value: CustomValueIn,
    expiry: Option<DateWire>,
}

impl CustomFieldIn {
    fn into_field(self) -> Result<CustomField, FieldError> {
        let value = match self.value {
            CustomValueIn::Text(value) => FieldValue::Text(value.text()),
            CustomValueIn::Secret(value) => FieldValue::Secret(value.secret()),
            CustomValueIn::MultilineSecret(value) => FieldValue::MultilineSecret(value.secret()),
            CustomValueIn::Date(date) => FieldValue::Date(date.into_date()?),
            CustomValueIn::RecoveryCodes(codes) => FieldValue::RecoveryCodes(
                codes
                    .into_inner()
                    .into_iter()
                    .map(|code| RecoveryCode::new(code.code.secret(), code.used))
                    .collect(),
            ),
        };
        try_field(
            self.label.text(),
            value,
            self.expiry.map(DateWire::into_date).transpose()?,
        )
    }
}

/// A category as written.
#[derive(Serialize)]
pub(crate) struct CategoryOut<'a> {
    id: CategoryId,
    name: &'a str,
}

impl<'a> CategoryOut<'a> {
    /// Borrows `c` for writing.
    pub(crate) fn new(c: &'a Category) -> CategoryOut<'a> {
        CategoryOut {
            id: c.id,
            name: c.name.as_str(),
        }
    }
}

/// A category as read.
#[derive(Deserialize)]
pub(crate) struct CategoryIn {
    id: CategoryId,
    name: WireStr,
}

impl CategoryIn {
    /// Builds the category and runs the name rules on it.
    ///
    /// # Errors
    /// Returns the [`FieldError`] for the first rule broken.
    pub(crate) fn into_category(self) -> Result<Category, FieldError> {
        validate_category_name(&self.name.0)?;
        Ok(Category {
            id: self.id,
            name: self.name.text(),
        })
    }
}

/// The settings as written and read. They hold no secrets, so one `Copy` type serves
/// both ways. Nothing here is trusted: [`crate::body`] clamps the result into range.
///
/// Every conversion destructures the whole struct, so a new settings field cannot be
/// left out of the wire format by accident: it stops the build instead.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub(crate) struct SettingsWire {
    auto_lock_secs: u32,
    clipboard_clear_secs: u32,
    lock_on_sleep: bool,
    password: PasswordSpecWire,
    passphrase: PassphraseSpecWire,
    username: UsernameSpecWire,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct PasswordSpecWire {
    length: u16,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    avoid_lookalikes: bool,
    min_digits: u8,
    min_symbols: u8,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct PassphraseSpecWire {
    words: u8,
    separator: char,
    capitalise: bool,
    add_number: bool,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct UsernameSpecWire {
    words: u8,
    digits: u8,
}

impl SettingsWire {
    /// Copies `s` for writing.
    pub(crate) fn new(s: &Settings) -> SettingsWire {
        let Settings {
            auto_lock_secs,
            clipboard_clear_secs,
            lock_on_sleep,
            password,
            passphrase,
            username,
        } = *s;
        let PasswordSpec {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            avoid_lookalikes,
            min_digits,
            min_symbols,
        } = password;
        let PassphraseSpec {
            words: phrase_words,
            separator,
            capitalise,
            add_number,
        } = passphrase;
        let UsernameSpec {
            words: user_words,
            digits: user_digits,
        } = username;
        SettingsWire {
            auto_lock_secs,
            clipboard_clear_secs,
            lock_on_sleep,
            password: PasswordSpecWire {
                length,
                lowercase,
                uppercase,
                digits,
                symbols,
                avoid_lookalikes,
                min_digits,
                min_symbols,
            },
            passphrase: PassphraseSpecWire {
                words: phrase_words,
                separator,
                capitalise,
                add_number,
            },
            username: UsernameSpecWire {
                words: user_words,
                digits: user_digits,
            },
        }
    }

    /// The settings as read. Not yet range-checked.
    pub(crate) fn into_settings(self) -> Settings {
        let SettingsWire {
            auto_lock_secs,
            clipboard_clear_secs,
            lock_on_sleep,
            password,
            passphrase,
            username,
        } = self;
        let PasswordSpecWire {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            avoid_lookalikes,
            min_digits,
            min_symbols,
        } = password;
        let PassphraseSpecWire {
            words: phrase_words,
            separator,
            capitalise,
            add_number,
        } = passphrase;
        let UsernameSpecWire {
            words: user_words,
            digits: user_digits,
        } = username;
        Settings {
            auto_lock_secs,
            clipboard_clear_secs,
            lock_on_sleep,
            password: PasswordSpec {
                length,
                lowercase,
                uppercase,
                digits,
                symbols,
                avoid_lookalikes,
                min_digits,
                min_symbols,
            },
            passphrase: PassphraseSpec {
                words: phrase_words,
                separator,
                capitalise,
                add_number,
            },
            username: UsernameSpec {
                words: user_words,
                digits: user_digits,
            },
        }
    }
}

/// The whole body as written, after the 2-byte schema version. The field order is the
/// format: [`BodyInV1`] must list the same fields in the same order.
#[cfg(test)]
#[derive(Serialize)]
pub(crate) struct BodyOutV1<'a> {
    pub(crate) settings: SettingsWire,
    pub(crate) categories: Vec<CategoryOut<'a>>,
    pub(crate) items: Vec<ItemOutV1<'a>>,
    pub(crate) next_category_id: u32,
}

/// The whole body as read. Nothing here is trusted until [`crate::body`] has converted
/// and checked it.
#[derive(Deserialize)]
pub(crate) struct BodyInV1 {
    pub(crate) settings: SettingsWire,
    pub(crate) categories: BoundedVec<CategoryIn, MAX_CATEGORIES>,
    pub(crate) items: BoundedVec<ItemInV1, MAX_ITEMS>,
    pub(crate) next_category_id: u32,
}

/// The whole body as written, after the 2-byte schema version. The field order is the
/// format: [`BodyIn`] must list the same fields in the same order.
#[derive(Serialize)]
pub(crate) struct BodyOut<'a> {
    pub(crate) settings: SettingsWire,
    pub(crate) categories: Vec<CategoryOut<'a>>,
    pub(crate) items: Vec<ItemOut<'a>>,
    pub(crate) next_category_id: u32,
}

/// The whole body as read. Nothing here is trusted until [`crate::body`] has converted
/// and checked it.
#[derive(Deserialize)]
pub(crate) struct BodyIn {
    pub(crate) settings: SettingsWire,
    pub(crate) categories: BoundedVec<CategoryIn, MAX_CATEGORIES>,
    pub(crate) items: BoundedVec<ItemIn, MAX_ITEMS>,
    pub(crate) next_category_id: u32,
}

// ---------------------------------------------------------------------------
// Format v2: the index and the records.
// ---------------------------------------------------------------------------

/// The record table entry as written and read: plain numbers and bytes. The range
/// rules (generation, ciphertext length) are checked by [`crate::index`].
#[derive(Clone, Copy, Serialize, Deserialize)]
struct RecordRefWire {
    generation: u64,
    nonce: [u8; NONCE_LEN],
    ct_len: u32,
}

impl RecordRefWire {
    fn new(r: &RecordRef) -> Self {
        Self {
            generation: r.generation,
            nonce: r.nonce,
            ct_len: r.ct_len,
        }
    }

    fn into_ref(self) -> RecordRef {
        RecordRef {
            generation: self.generation,
            nonce: self.nonce,
            ct_len: self.ct_len,
        }
    }
}

/// Variant order is the postcard index and the item type tag.
#[derive(Serialize)]
enum PublicOut<'a> {
    Login {
        username: &'a str,
        urls: Vec<&'a str>,
        has_password: bool,
        has_notes: bool,
    },
    CryptoAddress {
        chain: &'a str,
        has_address: bool,
        has_memo: bool,
        has_notes: bool,
    },
    RecoveryPhrase {
        has_notes: bool,
    },
    SecureNote {
        has_body: bool,
    },
}

impl<'a> PublicOut<'a> {
    fn new(p: &'a EntryPublic) -> Self {
        match p {
            EntryPublic::Login {
                username,
                urls,
                has_password,
                has_notes,
            } => PublicOut::Login {
                username: username.as_str(),
                urls: urls.iter().map(Text::as_str).collect(),
                has_password: *has_password,
                has_notes: *has_notes,
            },
            EntryPublic::CryptoAddress {
                chain,
                has_address,
                has_memo,
                has_notes,
            } => PublicOut::CryptoAddress {
                chain: chain.as_str(),
                has_address: *has_address,
                has_memo: *has_memo,
                has_notes: *has_notes,
            },
            EntryPublic::RecoveryPhrase { has_notes } => PublicOut::RecoveryPhrase {
                has_notes: *has_notes,
            },
            EntryPublic::SecureNote { has_body } => PublicOut::SecureNote {
                has_body: *has_body,
            },
        }
    }
}

#[derive(Deserialize)]
enum PublicIn {
    Login {
        username: WireStr,
        urls: BoundedVec<WireStr, MAX_URLS>,
        has_password: bool,
        has_notes: bool,
    },
    CryptoAddress {
        chain: WireStr,
        has_address: bool,
        has_memo: bool,
        has_notes: bool,
    },
    RecoveryPhrase {
        has_notes: bool,
    },
    SecureNote {
        has_body: bool,
    },
}

impl PublicIn {
    fn into_public(self) -> EntryPublic {
        match self {
            PublicIn::Login {
                username,
                urls,
                has_password,
                has_notes,
            } => EntryPublic::Login {
                username: username.text(),
                urls: urls.into_inner().into_iter().map(WireStr::text).collect(),
                has_password,
                has_notes,
            },
            PublicIn::CryptoAddress {
                chain,
                has_address,
                has_memo,
                has_notes,
            } => EntryPublic::CryptoAddress {
                chain: chain.text(),
                has_address,
                has_memo,
                has_notes,
            },
            PublicIn::RecoveryPhrase { has_notes } => EntryPublic::RecoveryPhrase { has_notes },
            PublicIn::SecureNote { has_body } => EntryPublic::SecureNote { has_body },
        }
    }
}

/// Variant order matches [`CustomValueOut`] for the kinds they share.
#[derive(Serialize)]
enum FieldKindOut<'a> {
    Text(&'a str),
    Secret,
    MultilineSecret,
    Date(DateWire),
    RecoveryCodes(&'a [bool]),
}

#[derive(Serialize)]
struct FieldEntryOut<'a> {
    position: u8,
    label: &'a str,
    kind: FieldKindOut<'a>,
    expiry: Option<DateWire>,
}

impl<'a> FieldEntryOut<'a> {
    fn new(f: &'a FieldEntry) -> Self {
        let kind = match &f.kind {
            FieldEntryKind::Text(t) => FieldKindOut::Text(t.as_str()),
            FieldEntryKind::Secret => FieldKindOut::Secret,
            FieldEntryKind::MultilineSecret => FieldKindOut::MultilineSecret,
            FieldEntryKind::Date(d) => FieldKindOut::Date(DateWire::new(*d)),
            FieldEntryKind::RecoveryCodes { used } => FieldKindOut::RecoveryCodes(used),
        };
        Self {
            position: f.position,
            label: f.label.as_str(),
            kind,
            expiry: f.expiry.map(DateWire::new),
        }
    }
}

#[derive(Deserialize)]
enum FieldKindIn {
    Text(WireStr),
    Secret,
    MultilineSecret,
    Date(DateWire),
    RecoveryCodes(BoundedVec<bool, MAX_RECOVERY_CODES>),
}

#[derive(Deserialize)]
struct FieldEntryIn {
    position: u8,
    label: WireStr,
    kind: FieldKindIn,
    expiry: Option<DateWire>,
}

impl FieldEntryIn {
    fn into_entry(self) -> Result<FieldEntry, FieldError> {
        let kind = match self.kind {
            FieldKindIn::Text(t) => FieldEntryKind::Text(t.text()),
            FieldKindIn::Secret => FieldEntryKind::Secret,
            FieldKindIn::MultilineSecret => FieldEntryKind::MultilineSecret,
            FieldKindIn::Date(d) => FieldEntryKind::Date(d.into_date()?),
            FieldKindIn::RecoveryCodes(used) => FieldEntryKind::RecoveryCodes {
                used: used.into_inner(),
            },
        };
        Ok(FieldEntry {
            position: self.position,
            label: self.label.text(),
            kind,
            expiry: self.expiry.map(DateWire::into_date).transpose()?,
        })
    }
}

/// One index entry as written. Field order is the format (spec 2.6).
#[derive(Serialize)]
struct EntryOut<'a> {
    id: ItemId,
    public: PublicOut<'a>,
    title: &'a str,
    category: Option<CategoryId>,
    favourite: bool,
    created: Timestamp,
    updated: Timestamp,
    trashed: Option<Timestamp>,
    fields: Vec<FieldEntryOut<'a>>,
    record: RecordRefWire,
}

impl<'a> EntryOut<'a> {
    fn new(e: &'a ItemEntry) -> Self {
        Self {
            id: e.id,
            public: PublicOut::new(&e.public),
            title: e.title.as_str(),
            category: e.category,
            favourite: e.favourite,
            created: e.created,
            updated: e.updated,
            trashed: e.trashed,
            fields: e.fields.iter().map(FieldEntryOut::new).collect(),
            record: RecordRefWire::new(&e.record),
        }
    }
}

#[derive(Deserialize)]
struct EntryIn {
    id: ItemId,
    public: PublicIn,
    title: WireStr,
    category: Option<CategoryId>,
    favourite: bool,
    created: Timestamp,
    updated: Timestamp,
    trashed: Option<Timestamp>,
    fields: BoundedVec<FieldEntryIn, MAX_CUSTOM_FIELDS>,
    record: RecordRefWire,
}

impl EntryIn {
    fn into_entry(self) -> Result<ItemEntry, FieldError> {
        let fields = self.fields.into_inner();
        let mut out = Vec::with_capacity(fields.len());
        for f in fields {
            out.push(f.into_entry()?);
        }
        Ok(ItemEntry {
            id: self.id,
            title: self.title.text(),
            category: self.category,
            favourite: self.favourite,
            created: self.created,
            updated: self.updated,
            trashed: self.trashed,
            public: self.public.into_public(),
            fields: out,
            record: self.record.into_ref(),
        })
    }
}

/// Variant order is the postcard index.
#[derive(Clone, Copy, Serialize, Deserialize)]
enum BackupPromptWire {
    AfterUnlock,
    AfterPasswordChange,
    Done,
}

impl BackupPromptWire {
    fn new(p: BackupPrompt) -> Self {
        match p {
            BackupPrompt::AfterUnlock => Self::AfterUnlock,
            BackupPrompt::AfterPasswordChange => Self::AfterPasswordChange,
            BackupPrompt::Done => Self::Done,
        }
    }

    fn into_prompt(self) -> BackupPrompt {
        match self {
            Self::AfterUnlock => BackupPrompt::AfterUnlock,
            Self::AfterPasswordChange => BackupPrompt::AfterPasswordChange,
            Self::Done => BackupPrompt::Done,
        }
    }
}

#[derive(Serialize)]
struct BackupNoteOut<'a> {
    tag: &'a str,
    prompt: BackupPromptWire,
}

#[derive(Deserialize)]
struct BackupNoteIn {
    tag: WireStr,
    prompt: BackupPromptWire,
}

/// The index as written, after the 2-byte schema version. The field order is the
/// format: [`IndexIn`] must list the same fields in the same order.
#[derive(Serialize)]
pub(crate) struct IndexOut<'a> {
    settings: SettingsWire,
    categories: Vec<CategoryOut<'a>>,
    entries: Vec<EntryOut<'a>>,
    next_category_id: u32,
    migration_backup: Option<BackupNoteOut<'a>>,
}

impl<'a> IndexOut<'a> {
    /// Borrows `index` for writing.
    pub(crate) fn new(index: &'a Index) -> Self {
        Self {
            settings: SettingsWire::new(&index.settings),
            categories: index.categories.iter().map(CategoryOut::new).collect(),
            entries: index.entries.iter().map(EntryOut::new).collect(),
            next_category_id: index.next_category_id,
            migration_backup: index.migration_backup.as_ref().map(|n| BackupNoteOut {
                tag: n.tag.as_str(),
                prompt: BackupPromptWire::new(n.prompt),
            }),
        }
    }
}

/// The index as read. Nothing here is trusted until [`IndexIn::into_index`] and
/// [`Index::decode`] have checked it.
#[derive(Deserialize)]
pub(crate) struct IndexIn {
    settings: SettingsWire,
    categories: BoundedVec<CategoryIn, MAX_CATEGORIES>,
    entries: BoundedVec<EntryIn, MAX_ITEMS>,
    next_category_id: u32,
    migration_backup: Option<BackupNoteIn>,
}

impl IndexIn {
    /// Builds the domain values. A date that is not a real day, a category name that
    /// breaks its rule or a bad backup tag is refused here.
    ///
    /// # Errors
    /// [`BodyError::Invalid`] for a broken field rule, [`BodyError::Malformed`] for a
    /// bad backup tag.
    pub(crate) fn into_index(self) -> Result<Index, BodyError> {
        let wire_categories = self.categories.into_inner();
        let mut categories = Vec::with_capacity(wire_categories.len());
        for c in wire_categories {
            categories.push(c.into_category().map_err(|_| BodyError::Invalid)?);
        }
        let wire_entries = self.entries.into_inner();
        let mut entries = Vec::with_capacity(wire_entries.len());
        for e in wire_entries {
            entries.push(e.into_entry().map_err(|_| BodyError::Invalid)?);
        }
        let migration_backup = match self.migration_backup {
            None => None,
            Some(n) => {
                let tag = n.tag.0.to_string();
                if !BackupNote::tag_is_valid(&tag) {
                    return Err(BodyError::Malformed);
                }
                Some(BackupNote {
                    tag,
                    prompt: n.prompt.into_prompt(),
                })
            }
        };
        Ok(Index {
            settings: self.settings.into_settings(),
            categories,
            entries,
            next_category_id: self.next_category_id,
            migration_backup,
        })
    }
}

/// The sealed values of a record, by kind. The variant order is the item type tag and
/// matches [`PublicOut`].
#[derive(Serialize)]
enum SealedDataOut<'a> {
    Login {
        password: &'a str,
        notes: &'a str,
    },
    CryptoAddress {
        address: &'a str,
        memo: &'a str,
        notes: &'a str,
    },
    RecoveryPhrase {
        phrase: &'a str,
        notes: &'a str,
    },
    SecureNote {
        body: &'a str,
    },
}

#[derive(Serialize)]
enum SealedValueOut<'a> {
    Secret(&'a str),
    MultilineSecret(&'a str),
    RecoveryCodes(Vec<&'a str>),
}

#[derive(Serialize)]
struct SealedFieldOut<'a> {
    position: u8,
    value: SealedValueOut<'a>,
}

/// A record as written, after the 2-byte schema version.
#[derive(Serialize)]
pub(crate) struct RecordOut<'a> {
    data: SealedDataOut<'a>,
    custom: Vec<SealedFieldOut<'a>>,
}

impl<'a> RecordOut<'a> {
    /// Borrows `r` for writing.
    pub(crate) fn new(r: &'a RecordSecrets) -> Self {
        let data = match &r.data {
            SealedData::Login { password, notes } => SealedDataOut::Login {
                password: password.expose(),
                notes: notes.expose(),
            },
            SealedData::CryptoAddress {
                address,
                memo,
                notes,
            } => SealedDataOut::CryptoAddress {
                address: address.expose(),
                memo: memo.expose(),
                notes: notes.expose(),
            },
            SealedData::RecoveryPhrase { phrase, notes } => SealedDataOut::RecoveryPhrase {
                phrase: phrase.expose(),
                notes: notes.expose(),
            },
            SealedData::SecureNote { body } => SealedDataOut::SecureNote {
                body: body.expose(),
            },
        };
        let custom = r
            .custom
            .iter()
            .map(|f| SealedFieldOut {
                position: f.position,
                value: match &f.value {
                    SealedValue::Secret(s) => SealedValueOut::Secret(s.expose()),
                    SealedValue::MultilineSecret(s) => SealedValueOut::MultilineSecret(s.expose()),
                    SealedValue::RecoveryCodes(codes) => SealedValueOut::RecoveryCodes(
                        codes.iter().map(SecretText::expose).collect(),
                    ),
                },
            })
            .collect();
        Self { data, custom }
    }
}

#[derive(Deserialize)]
enum SealedDataIn {
    Login {
        password: WireStr,
        notes: WireStr,
    },
    CryptoAddress {
        address: WireStr,
        memo: WireStr,
        notes: WireStr,
    },
    RecoveryPhrase {
        phrase: WireStr,
        notes: WireStr,
    },
    SecureNote {
        body: WireStr,
    },
}

#[derive(Deserialize)]
enum SealedValueIn {
    Secret(WireStr),
    MultilineSecret(WireStr),
    RecoveryCodes(BoundedVec<WireStr, MAX_RECOVERY_CODES>),
}

#[derive(Deserialize)]
struct SealedFieldIn {
    position: u8,
    value: SealedValueIn,
}

/// A record as read. Nothing here is trusted until [`RecordSecrets::decode`] has
/// checked it against its index entry.
#[derive(Deserialize)]
pub(crate) struct RecordIn {
    data: SealedDataIn,
    custom: BoundedVec<SealedFieldIn, MAX_CUSTOM_FIELDS>,
}

impl RecordIn {
    /// Moves the strings into their wiping types.
    pub(crate) fn into_secrets(self) -> RecordSecrets {
        let data = match self.data {
            SealedDataIn::Login { password, notes } => SealedData::Login {
                password: password.secret(),
                notes: notes.secret(),
            },
            SealedDataIn::CryptoAddress {
                address,
                memo,
                notes,
            } => SealedData::CryptoAddress {
                address: address.secret(),
                memo: memo.secret(),
                notes: notes.secret(),
            },
            SealedDataIn::RecoveryPhrase { phrase, notes } => SealedData::RecoveryPhrase {
                phrase: GatedSecret::new(phrase.secret()),
                notes: notes.secret(),
            },
            SealedDataIn::SecureNote { body } => SealedData::SecureNote {
                body: body.secret(),
            },
        };
        let custom = self
            .custom
            .into_inner()
            .into_iter()
            .map(|f| SealedField {
                position: f.position,
                value: match f.value {
                    SealedValueIn::Secret(s) => SealedValue::Secret(s.secret()),
                    SealedValueIn::MultilineSecret(s) => SealedValue::MultilineSecret(s.secret()),
                    SealedValueIn::RecoveryCodes(codes) => SealedValue::RecoveryCodes(
                        codes
                            .into_inner()
                            .into_iter()
                            .map(WireStr::secret)
                            .collect(),
                    ),
                },
            })
            .collect();
        RecordSecrets { data, custom }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Field;

    fn t(s: &str) -> Text {
        Text::new(s.into())
    }
    fn st(s: &str) -> SecretText {
        SecretText::new(s.into())
    }
    fn item(data: ItemData) -> Item {
        Item {
            fields: Vec::new(),
            id: ItemId::from_hex(&"ab".repeat(16)).unwrap(),
            title: t("Example Mail"),
            category: Some(CategoryId(2)),
            favourite: true,
            created: Timestamp(1),
            updated: Timestamp(2),
            trashed: None,
            data,
        }
    }
    fn round(i: &Item) -> Result<Item, FieldError> {
        let json = serde_json::to_string(&ItemOut::new(i)).unwrap();
        serde_json::from_str::<ItemIn>(&json).unwrap().into_item()
    }

    #[test]
    fn every_kind_roundtrips() {
        let datas = [
            ItemData::Login {
                username: t("ada"),
                password: st("EXAMPLE-pw"),
                urls: vec![t("https://example.com")],
                notes: st("n\nm"),
            },
            ItemData::CryptoAddress {
                chain: t("EXAMPLE"),
                address: st("EXAMPLE-addr"),
                memo: st("memo"),
                notes: st(""),
            },
            ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(st("EXAMPLE words")),
                notes: st(""),
            },
            ItemData::SecureNote { body: st("body") },
        ];
        for d in datas {
            let i = item(d);
            let back = round(&i).unwrap();
            assert_eq!(back.id(), i.id());
            assert_eq!(back.title(), i.title());
            assert_eq!(back.category(), i.category());
            assert!(back.favourite());
            assert_eq!(back.item_type(), i.item_type());
            assert_eq!(
                serde_json::to_string(&ItemOut::new(&back)).unwrap(),
                serde_json::to_string(&ItemOut::new(&i)).unwrap()
            );
        }
    }

    #[test]
    fn decoding_reruns_the_field_rules() {
        let mut i = item(ItemData::SecureNote { body: st("ok") });
        i.title = t("bad\u{202E}title");
        assert_eq!(
            round(&i).err(),
            Some(FieldError::ForbiddenChar(Field::Title))
        );
        let i = item(ItemData::RecoveryPhrase {
            phrase: GatedSecret::new(st("")),
            notes: st(""),
        });
        assert_eq!(round(&i).err(), Some(FieldError::Empty(Field::Phrase)));
        let i = item(ItemData::Login {
            username: t(""),
            password: st("a\nb"),
            urls: vec![],
            notes: st(""),
        });
        assert_eq!(
            round(&i).err(),
            Some(FieldError::ForbiddenChar(Field::Password))
        );
    }

    #[test]
    fn unknown_fields_are_refused() {
        let json = r#"{"id":"x","extra":1}"#;
        assert!(serde_json::from_str::<ItemIn>(json).is_err());
    }

    #[test]
    fn category_roundtrips_and_is_checked() {
        let c = Category {
            id: CategoryId(5),
            name: t("Family"),
        };
        let json = serde_json::to_string(&CategoryOut::new(&c)).unwrap();
        let back = serde_json::from_str::<CategoryIn>(&json)
            .unwrap()
            .into_category()
            .unwrap();
        assert_eq!(back.name(), "Family");
        assert_eq!(back.id(), CategoryId(5));
        let bad = r#"{"id":1,"name":"uncategorised"}"#;
        assert_eq!(
            serde_json::from_str::<CategoryIn>(bad)
                .unwrap()
                .into_category()
                .err(),
            Some(FieldError::Reserved(Field::CategoryName))
        );
    }
}
