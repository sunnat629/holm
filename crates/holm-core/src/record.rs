//! The sealed part of an item in format v2: one record per item.
//!
//! Spec sections 2.3 and 2.6. A record holds everything behind Reveal, Copy or the
//! phrase gate: the password, notes, address, memo, phrase or note body, the custom
//! `Secret` and `MultilineSecret` values and the recovery code strings. The rest of the
//! item lives in the index ([`crate::index::ItemEntry`]).
//!
//! Layout (record schema [`RECORD_SCHEMA_V1`]): a `u16` little-endian version, then the
//! `postcard` encoding of the item type tag with its sealed values, then the sealed
//! custom values in position order. Padding to [`crate::padding::RECORD_PAD_BLOCK`] is
//! added and removed by the envelope.
//!
//! [`RecordSecrets::decode`] treats its input as hostile and checks it against the
//! index entry it claims to belong to. Every mismatch is an error that the caller maps
//! to `DamagedItem`. [`split`] and [`join`] convert between an [`Item`] and the pair
//! (entry, record); both consume their input so no second copy of a secret exists.

use crate::body::{BodyError, encode_wire};
use crate::error::CoreError;
use crate::fields::{CustomField, FieldValue, RecoveryCode, validate_fields};
use crate::index::{EntryPublic, FieldEntry, FieldEntryKind, ItemEntry, RecordRef};
use crate::item::{Item, ItemData, PhraseRule, SecretSlot, validate_item};
use crate::padding::MAX_RECORD_PADDED;
use crate::text::{GatedSecret, SecretText};
use crate::wire::{RecordIn, RecordOut};
use core::fmt;
use holm_crypto::SecretBuf;

/// The record schema this build writes and reads.
pub const RECORD_SCHEMA_V1: u16 = 1;

/// Length of the schema version prefix in bytes.
const VERSION_LEN: usize = 2;

/// The sealed values of one item, by kind. No `Clone`; `Debug` prints nothing secret.
pub(crate) enum SealedData {
    /// Login password and notes.
    Login {
        password: SecretText,
        notes: SecretText,
    },
    /// Crypto address, memo and notes.
    CryptoAddress {
        address: SecretText,
        memo: SecretText,
        notes: SecretText,
    },
    /// Recovery phrase and notes. The phrase stays gated.
    RecoveryPhrase {
        phrase: GatedSecret,
        notes: SecretText,
    },
    /// Secure note body.
    SecureNote { body: SecretText },
}

/// One sealed custom value.
pub(crate) enum SealedValue {
    Secret(SecretText),
    MultilineSecret(SecretText),
    RecoveryCodes(Vec<SecretText>),
}

/// A sealed custom field: its position in the item's list and its value.
pub(crate) struct SealedField {
    pub(crate) position: u8,
    pub(crate) value: SealedValue,
}

/// Everything in a record. No `Clone`, no `PartialEq`, and `Debug` prints counts only.
pub(crate) struct RecordSecrets {
    pub(crate) data: SealedData,
    pub(crate) custom: Vec<SealedField>,
}

impl fmt::Debug for RecordSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.data {
            SealedData::Login { .. } => "Login",
            SealedData::CryptoAddress { .. } => "CryptoAddress",
            SealedData::RecoveryPhrase { .. } => "RecoveryPhrase",
            SealedData::SecureNote { .. } => "SecureNote",
        };
        f.debug_struct("RecordSecrets")
            .field("kind", &kind)
            .field("custom", &self.custom.len())
            .finish()
    }
}

impl RecordSecrets {
    /// Encodes the record: the schema version, then postcard.
    ///
    /// # Errors
    /// [`BodyError::Invalid`] if the encoding would not fit [`MAX_RECORD_PADDED`],
    /// [`BodyError::Encode`] if postcard fails.
    pub(crate) fn encode(&self) -> Result<SecretBuf, BodyError> {
        let buf = encode_wire(&RecordOut::new(self), RECORD_SCHEMA_V1)?;
        if buf.len() > MAX_RECORD_PADDED {
            return Err(BodyError::Invalid);
        }
        Ok(buf)
    }

    /// Decodes a record and checks it against `entry`.
    ///
    /// Any failure means the record is damaged: [`BodyError::TooShort`] under 2 bytes;
    /// [`BodyError::Malformed`] for input over [`MAX_RECORD_PADDED`], a schema other
    /// than [`RECORD_SCHEMA_V1`], a bad encoding or trailing bytes;
    /// [`BodyError::Invalid`] if the record does not match the entry (type, field
    /// positions and kinds, code counts, presence flags) or breaks a field rule.
    ///
    /// # Errors
    /// As listed above.
    pub(crate) fn decode(plaintext: &[u8], entry: &ItemEntry) -> Result<RecordSecrets, BodyError> {
        if plaintext.len() > MAX_RECORD_PADDED {
            return Err(BodyError::Malformed);
        }
        let (version, rest) = plaintext
            .split_first_chunk::<VERSION_LEN>()
            .ok_or(BodyError::TooShort)?;
        if u16::from_le_bytes(*version) != RECORD_SCHEMA_V1 {
            return Err(BodyError::Malformed);
        }
        let (wire, leftover) =
            postcard::take_from_bytes::<RecordIn>(rest).map_err(|_| BodyError::Malformed)?;
        if !leftover.is_empty() {
            return Err(BodyError::Malformed);
        }
        let secrets = wire.into_secrets();
        // Join checks the shape and the presence flags; the item rules then run on the
        // whole item, so the field rules have one implementation.
        let item = join(entry, secrets)?;
        validate_item(&item.title, &item.data, PhraseRule::Required)
            .map_err(|_| BodyError::Invalid)?;
        validate_fields(&item.fields).map_err(|_| BodyError::Invalid)?;
        let (_entry, secrets) = split(item);
        Ok(secrets)
    }
}

/// Moves the one secret named by `slot` out of the record; every other value drops (and
/// is wiped) here. The recovery phrase is never returned: it is not a slot.
///
/// # Errors
/// [`CoreError::NoSuchSecret`] if the record has no value in that slot: a slot of
/// another item kind, a position that is not a `Secret` or `MultilineSecret` field, a
/// field that holds no codes, a code index past the end, or the phrase.
pub(crate) fn take_slot(secrets: RecordSecrets, slot: SecretSlot) -> Result<SecretText, CoreError> {
    let RecordSecrets { data, custom } = secrets;
    match slot {
        SecretSlot::Field { position } => {
            let field = custom.into_iter().find(|f| f.position == position);
            match field.map(|f| f.value) {
                Some(SealedValue::Secret(v) | SealedValue::MultilineSecret(v)) => Ok(v),
                _ => Err(CoreError::NoSuchSecret),
            }
        }
        SecretSlot::Code { position, index } => {
            let field = custom.into_iter().find(|f| f.position == position);
            match field.map(|f| f.value) {
                Some(SealedValue::RecoveryCodes(codes)) => codes
                    .into_iter()
                    .nth(usize::from(index))
                    .ok_or(CoreError::NoSuchSecret),
                _ => Err(CoreError::NoSuchSecret),
            }
        }
        plain => match (plain, data) {
            (SecretSlot::Password, SealedData::Login { password, .. }) => Ok(password),
            (
                SecretSlot::Notes,
                SealedData::Login { notes, .. }
                | SealedData::CryptoAddress { notes, .. }
                | SealedData::RecoveryPhrase { notes, .. },
            ) => Ok(notes),
            (SecretSlot::Address, SealedData::CryptoAddress { address, .. }) => Ok(address),
            (SecretSlot::Memo, SealedData::CryptoAddress { memo, .. }) => Ok(memo),
            (SecretSlot::Body, SealedData::SecureNote { body }) => Ok(body),
            _ => Err(CoreError::NoSuchSecret),
        },
    }
}

/// Takes an item apart into its index entry and its record. The entry has no sealed
/// record yet ([`RecordRef::UNSEALED`]). Consumes `item`: every secret moves, none is
/// copied.
pub(crate) fn split(item: Item) -> (ItemEntry, RecordSecrets) {
    let Item {
        id,
        title,
        category,
        favourite,
        created,
        updated,
        trashed,
        data,
        fields,
    } = item;
    let (public, sealed) = match data {
        ItemData::Login {
            username,
            password,
            urls,
            notes,
        } => (
            EntryPublic::Login {
                username,
                urls,
                has_password: !password.is_empty(),
                has_notes: !notes.is_empty(),
            },
            SealedData::Login { password, notes },
        ),
        ItemData::CryptoAddress {
            chain,
            address,
            memo,
            notes,
        } => (
            EntryPublic::CryptoAddress {
                chain,
                has_address: !address.is_empty(),
                has_memo: !memo.is_empty(),
                has_notes: !notes.is_empty(),
            },
            SealedData::CryptoAddress {
                address,
                memo,
                notes,
            },
        ),
        ItemData::RecoveryPhrase { phrase, notes } => (
            EntryPublic::RecoveryPhrase {
                has_notes: !notes.is_empty(),
            },
            SealedData::RecoveryPhrase { phrase, notes },
        ),
        ItemData::SecureNote { body } => (
            EntryPublic::SecureNote {
                has_body: !body.is_empty(),
            },
            SealedData::SecureNote { body },
        ),
    };
    let mut entry_fields = Vec::with_capacity(fields.len());
    let mut custom = Vec::new();
    for (position, field) in (0u8..).zip(fields) {
        let (label, value, expiry) = field.into_parts();
        let kind = match value {
            FieldValue::Text(t) => FieldEntryKind::Text(t),
            FieldValue::Date(d) => FieldEntryKind::Date(d),
            FieldValue::Secret(s) => {
                custom.push(SealedField {
                    position,
                    value: SealedValue::Secret(s),
                });
                FieldEntryKind::Secret
            }
            FieldValue::MultilineSecret(s) => {
                custom.push(SealedField {
                    position,
                    value: SealedValue::MultilineSecret(s),
                });
                FieldEntryKind::MultilineSecret
            }
            FieldValue::RecoveryCodes(codes) => {
                let used = codes.iter().map(RecoveryCode::used).collect();
                custom.push(SealedField {
                    position,
                    value: SealedValue::RecoveryCodes(
                        codes.into_iter().map(RecoveryCode::into_code).collect(),
                    ),
                });
                FieldEntryKind::RecoveryCodes { used }
            }
        };
        entry_fields.push(FieldEntry {
            position,
            label,
            kind,
            expiry,
        });
    }
    let entry = ItemEntry {
        id,
        title,
        category,
        favourite,
        created,
        updated,
        trashed,
        public,
        fields: entry_fields,
        record: RecordRef::UNSEALED,
    };
    (
        entry,
        RecordSecrets {
            data: sealed,
            custom,
        },
    )
}

/// Joins an index entry and its record into an item, checking that they belong
/// together: same type, the sealed custom fields exactly where the entry says, code
/// counts equal to the used flags, presence flags equal to the values. The field rules
/// are not run here; [`RecordSecrets::decode`] runs them.
///
/// # Errors
/// [`BodyError::Invalid`] on any mismatch. The record's secrets are dropped (and
/// wiped) on the way out.
pub(crate) fn join(entry: &ItemEntry, secrets: RecordSecrets) -> Result<Item, BodyError> {
    let RecordSecrets { data, custom } = secrets;
    let data = match (&entry.public, data) {
        (
            EntryPublic::Login {
                username,
                urls,
                has_password,
                has_notes,
            },
            SealedData::Login { password, notes },
        ) => {
            if *has_password == password.is_empty() || *has_notes == notes.is_empty() {
                return Err(BodyError::Invalid);
            }
            ItemData::Login {
                username: username.clone(),
                password,
                urls: urls.clone(),
                notes,
            }
        }
        (
            EntryPublic::CryptoAddress {
                chain,
                has_address,
                has_memo,
                has_notes,
            },
            SealedData::CryptoAddress {
                address,
                memo,
                notes,
            },
        ) => {
            if *has_address == address.is_empty()
                || *has_memo == memo.is_empty()
                || *has_notes == notes.is_empty()
            {
                return Err(BodyError::Invalid);
            }
            ItemData::CryptoAddress {
                chain: chain.clone(),
                address,
                memo,
                notes,
            }
        }
        (
            EntryPublic::RecoveryPhrase { has_notes },
            SealedData::RecoveryPhrase { phrase, notes },
        ) => {
            if *has_notes == notes.is_empty() {
                return Err(BodyError::Invalid);
            }
            ItemData::RecoveryPhrase { phrase, notes }
        }
        (EntryPublic::SecureNote { has_body }, SealedData::SecureNote { body }) => {
            if *has_body == body.is_empty() {
                return Err(BodyError::Invalid);
            }
            ItemData::SecureNote { body }
        }
        _ => return Err(BodyError::Invalid),
    };
    let mut sealed = custom.into_iter();
    let mut fields = Vec::with_capacity(entry.fields.len());
    for fe in &entry.fields {
        let value = match &fe.kind {
            FieldEntryKind::Text(t) => FieldValue::Text(t.clone()),
            FieldEntryKind::Date(d) => FieldValue::Date(*d),
            sealed_kind => {
                let s = sealed.next().ok_or(BodyError::Invalid)?;
                if s.position != fe.position {
                    return Err(BodyError::Invalid);
                }
                match (sealed_kind, s.value) {
                    (FieldEntryKind::Secret, SealedValue::Secret(v)) => FieldValue::Secret(v),
                    (FieldEntryKind::MultilineSecret, SealedValue::MultilineSecret(v)) => {
                        FieldValue::MultilineSecret(v)
                    }
                    (FieldEntryKind::RecoveryCodes { used }, SealedValue::RecoveryCodes(codes))
                        if codes.len() == used.len() =>
                    {
                        FieldValue::RecoveryCodes(
                            codes
                                .into_iter()
                                .zip(used)
                                .map(|(code, used)| RecoveryCode::new(code, *used))
                                .collect(),
                        )
                    }
                    _ => return Err(BodyError::Invalid),
                }
            }
        };
        fields.push(CustomField::from_parts(fe.label.clone(), value, fe.expiry));
    }
    if sealed.next().is_some() {
        return Err(BodyError::Invalid);
    }
    Ok(Item {
        id: entry.id,
        title: entry.title.clone(),
        category: entry.category,
        favourite: entry.favourite,
        created: entry.created,
        updated: entry.updated,
        trashed: entry.trashed,
        data,
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::CategoryId;
    use crate::fields::{CalendarDate, FieldValue};
    use crate::index::MAX_RECORD_CT;
    use crate::item::{ItemId, Timestamp};
    use crate::padding::{RECORD_PAD_BLOCK, pad_to};
    use crate::rules::{MAX_MULTILINE_SECRET_BYTES, MAX_NOTE_BYTES, MAX_SECRET_BYTES};
    use crate::text::Text;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(RecordSecrets: Clone, serde::Serialize, serde::de::DeserializeOwned);
    assert_not_impl_any!(SealedData: Clone, serde::Serialize, serde::de::DeserializeOwned);

    fn t(s: &str) -> Text {
        Text::new(s.into())
    }
    fn st(s: &str) -> SecretText {
        SecretText::new(s.into())
    }

    fn item(n: u8, data: ItemData, fields: Vec<CustomField>) -> Item {
        Item {
            id: ItemId::from_hex(&format!("{n:02x}").repeat(16)).unwrap(),
            title: t("Example"),
            category: Some(CategoryId(1)),
            favourite: true,
            created: Timestamp(1),
            updated: Timestamp(2),
            trashed: None,
            data,
            fields,
        }
    }

    fn field(label: &str, value: FieldValue) -> CustomField {
        crate::fields::try_field(t(label), value, None).unwrap()
    }

    fn login() -> Item {
        item(
            1,
            ItemData::Login {
                username: t("ada"),
                password: st("hunter2"),
                urls: vec![t("https://example.com")],
                notes: st("n"),
            },
            vec![
                field("Site", FieldValue::Text(t("example"))),
                field("PIN", FieldValue::Secret(st("1234"))),
                field(
                    "Since",
                    FieldValue::Date(CalendarDate::from_parts(2026, 1, 2).unwrap()),
                ),
                field(
                    "Codes",
                    FieldValue::RecoveryCodes(vec![
                        RecoveryCode::new(st("aaaa"), false),
                        RecoveryCode::new(st("bbbb"), true),
                    ]),
                ),
                field("Long", FieldValue::MultilineSecret(st("a\nb"))),
            ],
        )
    }

    fn crypto() -> Item {
        item(
            2,
            ItemData::CryptoAddress {
                chain: t("Bitcoin"),
                address: st("bc1qexample"),
                memo: st(""),
                notes: st(""),
            },
            vec![],
        )
    }

    fn phrase() -> Item {
        item(
            3,
            ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(st("one two three")),
                notes: st("notes"),
            },
            vec![],
        )
    }

    fn note() -> Item {
        item(4, ItemData::SecureNote { body: st("body") }, vec![])
    }

    fn all() -> [fn() -> Item; 4] {
        [login, crypto, phrase, note]
    }

    fn assert_items_eq(a: &Item, b: &Item) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.title, b.title);
        assert_eq!(a.category, b.category);
        assert_eq!(a.favourite, b.favourite);
        assert_eq!(a.created, b.created);
        assert_eq!(a.updated, b.updated);
        assert_eq!(a.trashed, b.trashed);
        match (&a.data, &b.data) {
            (
                ItemData::Login {
                    username: u1,
                    password: p1,
                    urls: r1,
                    notes: n1,
                },
                ItemData::Login {
                    username: u2,
                    password: p2,
                    urls: r2,
                    notes: n2,
                },
            ) => {
                assert_eq!(u1, u2);
                assert_eq!(p1.expose(), p2.expose());
                assert_eq!(r1, r2);
                assert_eq!(n1.expose(), n2.expose());
            }
            (
                ItemData::CryptoAddress {
                    chain: c1,
                    address: a1,
                    memo: m1,
                    notes: n1,
                },
                ItemData::CryptoAddress {
                    chain: c2,
                    address: a2,
                    memo: m2,
                    notes: n2,
                },
            ) => {
                assert_eq!(c1, c2);
                assert_eq!(a1.expose(), a2.expose());
                assert_eq!(m1.expose(), m2.expose());
                assert_eq!(n1.expose(), n2.expose());
            }
            (
                ItemData::RecoveryPhrase {
                    phrase: p1,
                    notes: n1,
                },
                ItemData::RecoveryPhrase {
                    phrase: p2,
                    notes: n2,
                },
            ) => {
                assert_eq!(p1.expose(), p2.expose());
                assert_eq!(n1.expose(), n2.expose());
            }
            (ItemData::SecureNote { body: b1 }, ItemData::SecureNote { body: b2 }) => {
                assert_eq!(b1.expose(), b2.expose());
            }
            _ => panic!("item types differ"),
        }
        assert_eq!(a.fields.len(), b.fields.len());
        for (x, y) in a.fields.iter().zip(&b.fields) {
            assert_eq!(x.label(), y.label());
            assert_eq!(x.expiry(), y.expiry());
            match (x.value(), y.value()) {
                (FieldValue::Text(p), FieldValue::Text(q)) => assert_eq!(p, q),
                (FieldValue::Date(p), FieldValue::Date(q)) => assert_eq!(p, q),
                (FieldValue::Secret(p), FieldValue::Secret(q))
                | (FieldValue::MultilineSecret(p), FieldValue::MultilineSecret(q)) => {
                    assert_eq!(p.expose(), q.expose());
                }
                (FieldValue::RecoveryCodes(p), FieldValue::RecoveryCodes(q)) => {
                    assert_eq!(p.len(), q.len());
                    for (c, d) in p.iter().zip(q) {
                        assert_eq!(c.code().expose(), d.code().expose());
                        assert_eq!(c.used(), d.used());
                    }
                }
                _ => panic!("field kinds differ"),
            }
        }
    }

    #[test]
    fn split_join_roundtrip_each_kind() {
        for make in all() {
            let (entry, secrets) = split(make());
            let back = join(&entry, secrets).unwrap();
            assert_items_eq(&make(), &back);
        }
    }

    #[test]
    fn split_sets_presence_flags() {
        let (e, _) = split(login());
        assert!(matches!(
            e.public,
            EntryPublic::Login {
                has_password: true,
                has_notes: true,
                ..
            }
        ));
        let (e, _) = split(crypto());
        assert!(matches!(
            e.public,
            EntryPublic::CryptoAddress {
                has_address: true,
                has_memo: false,
                has_notes: false,
                ..
            }
        ));
        let (e, _) = split(note());
        assert!(matches!(
            e.public,
            EntryPublic::SecureNote { has_body: true }
        ));
        assert_eq!(e.record, RecordRef::UNSEALED);
    }

    fn encoded(i: Item) -> (ItemEntry, Vec<u8>) {
        let (entry, secrets) = split(i);
        let bytes = secrets.encode().unwrap().expose().to_vec();
        (entry, bytes)
    }

    fn decode_err(bytes: &[u8], entry: &ItemEntry) -> Option<BodyError> {
        RecordSecrets::decode(bytes, entry).err()
    }

    #[test]
    fn record_roundtrip_each_kind() {
        for make in all() {
            let (entry, bytes) = encoded(make());
            let secrets = RecordSecrets::decode(&bytes, &entry).unwrap();
            let back = join(&entry, secrets).unwrap();
            assert_items_eq(&make(), &back);
        }
    }

    #[test]
    fn record_cross_check_type() {
        let (_, bytes) = encoded(note());
        let (entry, _) = split(login());
        assert_eq!(decode_err(&bytes, &entry), Some(BodyError::Invalid));
    }

    #[test]
    fn record_cross_check_positions_and_kinds() {
        // The sealed PIN sits at another position in the entry.
        let (mut entry, bytes) = encoded(login());
        entry.fields[1].position = 7;
        assert_eq!(decode_err(&bytes, &entry), Some(BodyError::Invalid));
        // The entry lists a plain field where the record has a sealed one.
        let (mut entry, bytes) = encoded(login());
        entry.fields[1].kind = FieldEntryKind::Text(t("x"));
        assert_eq!(decode_err(&bytes, &entry), Some(BodyError::Invalid));
        // The entry lists a sealed field the record lacks.
        let (entry, _) = split(login());
        let (_, bytes) = encoded({
            let mut l = login();
            l.fields.remove(1);
            l
        });
        assert_eq!(decode_err(&bytes, &entry), Some(BodyError::Invalid));
        // A sealed field of another kind than the entry's.
        let (mut entry, bytes) = encoded(login());
        entry.fields[1].kind = FieldEntryKind::MultilineSecret;
        assert_eq!(decode_err(&bytes, &entry), Some(BodyError::Invalid));
    }

    #[test]
    fn record_cross_check_code_count() {
        let (mut entry, bytes) = encoded(login());
        entry.fields[3].kind = FieldEntryKind::RecoveryCodes {
            used: vec![false, true, false],
        };
        assert_eq!(decode_err(&bytes, &entry), Some(BodyError::Invalid));
    }

    #[test]
    fn record_cross_check_presence_flags() {
        let (mut entry, bytes) = encoded(login());
        entry.public = EntryPublic::Login {
            username: t("ada"),
            urls: vec![t("https://example.com")],
            has_password: false,
            has_notes: true,
        };
        assert_eq!(decode_err(&bytes, &entry), Some(BodyError::Invalid));
        let (mut entry, bytes) = encoded(crypto());
        entry.public = EntryPublic::CryptoAddress {
            chain: t("Bitcoin"),
            has_address: true,
            has_memo: true, // the record's memo is empty
            has_notes: false,
        };
        assert_eq!(decode_err(&bytes, &entry), Some(BodyError::Invalid));
    }

    #[test]
    fn record_rules_apply() {
        // A blank phrase breaks the item rules.
        let mut p = phrase();
        if let ItemData::RecoveryPhrase { phrase, .. } = &mut p.data {
            *phrase = GatedSecret::new(st("   "));
        }
        let (entry, bytes) = encoded(p);
        assert_eq!(decode_err(&bytes, &entry), Some(BodyError::Invalid));
    }

    #[test]
    fn record_schema_and_trailing_bytes() {
        let (entry, bytes) = encoded(note());
        for v in [0u8, 2, 4] {
            let mut raw = bytes.clone();
            raw[0] = v;
            assert_eq!(decode_err(&raw, &entry), Some(BodyError::Malformed));
        }
        assert_eq!(decode_err(&[1], &entry), Some(BodyError::TooShort));
        assert_eq!(decode_err(&[], &entry), Some(BodyError::TooShort));
        let mut raw = bytes.clone();
        raw.push(0);
        assert_eq!(decode_err(&raw, &entry), Some(BodyError::Malformed));
        let long = vec![0u8; MAX_RECORD_PADDED + 1];
        assert_eq!(decode_err(&long, &entry), Some(BodyError::Malformed));
    }

    #[test]
    fn maxed_record_fits_cap() {
        let big = |n: usize| st(&"a".repeat(n));
        let fields = (0..10)
            .map(|k| {
                field(
                    &format!("F{k}"),
                    FieldValue::MultilineSecret(big(MAX_MULTILINE_SECRET_BYTES)),
                )
            })
            .collect();
        let i = item(
            9,
            ItemData::Login {
                username: t("u"),
                password: big(MAX_SECRET_BYTES),
                urls: vec![],
                notes: big(MAX_NOTE_BYTES),
            },
            fields,
        );
        let (entry, secrets) = split(i);
        let bytes = secrets.encode().unwrap();
        assert!(bytes.len() <= MAX_RECORD_PADDED);
        assert!(pad_to(bytes.expose(), RECORD_PAD_BLOCK, MAX_RECORD_PADDED).is_ok());
        assert!(RecordSecrets::decode(bytes.expose(), &entry).is_ok());
        // The biggest record's ciphertext fits the index range.
        const { assert!(MAX_RECORD_PADDED + 16 <= MAX_RECORD_CT) };
    }

    #[test]
    fn take_slot_each_kind() {
        let take = |i: Item, slot| take_slot(split(i).1, slot).map(|v| v.expose().to_owned());
        assert_eq!(take(login(), SecretSlot::Password).unwrap(), "hunter2");
        assert_eq!(take(login(), SecretSlot::Notes).unwrap(), "n");
        assert_eq!(
            take(login(), SecretSlot::Field { position: 1 }).unwrap(),
            "1234"
        );
        assert_eq!(
            take(login(), SecretSlot::Field { position: 4 }).unwrap(),
            "a\nb"
        );
        assert_eq!(
            take(
                login(),
                SecretSlot::Code {
                    position: 3,
                    index: 0
                }
            )
            .unwrap(),
            "aaaa"
        );
        assert_eq!(
            take(
                login(),
                SecretSlot::Code {
                    position: 3,
                    index: 1
                }
            )
            .unwrap(),
            "bbbb"
        );
        assert_eq!(take(crypto(), SecretSlot::Address).unwrap(), "bc1qexample");
        assert_eq!(take(crypto(), SecretSlot::Memo).unwrap(), "");
        assert_eq!(take(phrase(), SecretSlot::Notes).unwrap(), "notes");
        assert_eq!(take(note(), SecretSlot::Body).unwrap(), "body");
    }

    #[test]
    fn take_slot_wrong_kind_refused() {
        let take = |i: Item, slot| take_slot(split(i).1, slot).err();
        let none = Some(CoreError::NoSuchSecret);
        assert_eq!(take(note(), SecretSlot::Password), none);
        assert_eq!(take(login(), SecretSlot::Body), none);
        assert_eq!(take(login(), SecretSlot::Address), none);
        assert_eq!(take(crypto(), SecretSlot::Notes), None);
        assert_eq!(take(crypto(), SecretSlot::Password), none);
        assert_eq!(take(phrase(), SecretSlot::Memo), none);
        // A plain Text field, a Date field, a missing position, and the wrong field kind.
        assert_eq!(take(login(), SecretSlot::Field { position: 0 }), none);
        assert_eq!(take(login(), SecretSlot::Field { position: 2 }), none);
        assert_eq!(take(login(), SecretSlot::Field { position: 9 }), none);
        assert_eq!(take(login(), SecretSlot::Field { position: 3 }), none);
        assert_eq!(
            take(
                login(),
                SecretSlot::Code {
                    position: 1,
                    index: 0
                }
            ),
            none
        );
        assert_eq!(
            take(
                login(),
                SecretSlot::Code {
                    position: 3,
                    index: 2
                }
            ),
            none
        );
        assert_eq!(take(note(), SecretSlot::Field { position: 0 }), none);
    }

    #[test]
    fn take_slot_phrase_refused() {
        // No slot names the phrase: every slot on a phrase item that is not Notes fails.
        let slots = [
            SecretSlot::Password,
            SecretSlot::Address,
            SecretSlot::Memo,
            SecretSlot::Body,
            SecretSlot::Field { position: 0 },
            SecretSlot::Code {
                position: 0,
                index: 0,
            },
        ];
        for slot in slots {
            assert_eq!(
                take_slot(split(phrase()).1, slot).err(),
                Some(CoreError::NoSuchSecret),
                "{slot:?}"
            );
        }
        // Notes returns the notes, never the phrase.
        let notes = take_slot(split(phrase()).1, SecretSlot::Notes).unwrap();
        assert_eq!(notes.expose(), "notes");
    }

    #[test]
    fn record_debug_has_no_text() {
        let (_, secrets) = split(login());
        let d = format!("{secrets:?}");
        for s in ["hunter2", "1234", "aaaa"] {
            assert!(!d.contains(s), "{d}");
        }
        assert!(d.contains("Login"));
    }

    mod props {
        use super::*;
        use crate::index::{Index, RecordRef};
        use proptest::prelude::*;

        #[derive(Clone, Debug)]
        enum FieldSpec {
            Text(String),
            Secret(String),
            Multi(String),
            Date(u16, u8, u8),
            Codes(Vec<(String, bool)>),
        }

        #[derive(Clone, Debug)]
        enum DataSpec {
            Login(String, String, Vec<String>, String),
            Crypto(String, String, String, String),
            Phrase(String, String),
            Note(String),
        }

        /// A year, month and day for an expiry.
        type DateParts = (u16, u8, u8);

        #[derive(Clone, Debug)]
        struct Spec {
            title: String,
            favourite: bool,
            created: i64,
            updated: i64,
            trashed: Option<i64>,
            data: DataSpec,
            fields: Vec<(FieldSpec, Option<DateParts>)>,
        }

        fn date() -> impl Strategy<Value = (u16, u8, u8)> {
            (2000u16..2100, 1u8..=12, 1u8..=28)
        }

        fn field_spec() -> impl Strategy<Value = FieldSpec> {
            prop_oneof![
                "[a-z]{1,10}".prop_map(FieldSpec::Text),
                "[ -~]{1,10}".prop_map(FieldSpec::Secret),
                "[a-z]{1,5}(\n[a-z]{1,5}){0,2}".prop_map(FieldSpec::Multi),
                date().prop_map(|(y, m, d)| FieldSpec::Date(y, m, d)),
                prop::collection::vec(("[a-z0-9]{1,8}", any::<bool>()), 1..=5)
                    .prop_map(FieldSpec::Codes),
            ]
        }

        fn data_spec() -> impl Strategy<Value = DataSpec> {
            prop_oneof![
                (
                    "[a-z]{0,10}",
                    "[ -~]{0,30}",
                    prop::collection::vec("https://[a-z]{1,10}\\.com", 0..=3),
                    "[ -~]{0,30}"
                )
                    .prop_map(|(u, p, r, n)| DataSpec::Login(u, p, r, n)),
                (
                    "[a-z]{1,10}",
                    "[a-z0-9]{1,20}",
                    "[ -~]{0,10}",
                    "[ -~]{0,30}"
                )
                    .prop_map(|(c, a, m, n)| DataSpec::Crypto(c, a, m, n)),
                ("[a-z]{1,10}( [a-z]{1,10}){0,5}", "[ -~]{0,30}")
                    .prop_map(|(p, n)| DataSpec::Phrase(p, n)),
                "[ -~]{0,40}".prop_map(DataSpec::Note),
            ]
        }

        fn spec() -> impl Strategy<Value = Spec> {
            (
                "[A-Za-z][A-Za-z0-9 ]{0,19}",
                any::<bool>(),
                any::<i64>(),
                any::<i64>(),
                prop::option::of(any::<i64>()),
                data_spec(),
                prop::collection::vec((field_spec(), prop::option::of(date())), 0..=4),
            )
                .prop_map(
                    |(title, favourite, created, updated, trashed, data, fields)| Spec {
                        title,
                        favourite,
                        created,
                        updated,
                        trashed,
                        data,
                        fields,
                    },
                )
        }

        fn build(n: u8, s: &Spec) -> Item {
            let data = match &s.data {
                DataSpec::Login(u, p, r, nt) => ItemData::Login {
                    username: t(u),
                    password: st(p),
                    urls: r.iter().map(|x| t(x)).collect(),
                    notes: st(nt),
                },
                DataSpec::Crypto(c, a, m, nt) => ItemData::CryptoAddress {
                    chain: t(c),
                    address: st(a),
                    memo: st(m),
                    notes: st(nt),
                },
                DataSpec::Phrase(p, nt) => ItemData::RecoveryPhrase {
                    phrase: GatedSecret::new(st(p)),
                    notes: st(nt),
                },
                DataSpec::Note(b) => ItemData::SecureNote { body: st(b) },
            };
            let fields = s
                .fields
                .iter()
                .enumerate()
                .map(|(i, (f, expiry))| {
                    let value = match f {
                        FieldSpec::Text(v) => FieldValue::Text(t(v)),
                        FieldSpec::Secret(v) => FieldValue::Secret(st(v)),
                        FieldSpec::Multi(v) => FieldValue::MultilineSecret(st(v)),
                        FieldSpec::Date(y, m, d) => {
                            FieldValue::Date(CalendarDate::from_parts(*y, *m, *d).unwrap())
                        }
                        FieldSpec::Codes(c) => FieldValue::RecoveryCodes(
                            c.iter()
                                .map(|(v, u)| RecoveryCode::new(st(v), *u))
                                .collect(),
                        ),
                    };
                    let expiry = expiry.map(|(y, m, d)| CalendarDate::from_parts(y, m, d).unwrap());
                    crate::fields::try_field(t(&format!("L{i}")), value, expiry).unwrap()
                })
                .collect();
            let mut i = item(n, data, fields);
            i.title = t(s.title.trim_end());
            i.favourite = s.favourite;
            i.created = Timestamp(s.created);
            i.updated = Timestamp(s.updated);
            i.trashed = s.trashed.map(Timestamp);
            i
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

            /// Split, encode, decode, join, split and encode again: the bytes match.
            #[test]
            fn record_roundtrip_any(s in spec()) {
                let (entry, secrets) = split(build(1, &s));
                let a = secrets.encode().unwrap();
                let back = RecordSecrets::decode(a.expose(), &entry).unwrap();
                let b = back.encode().unwrap();
                prop_assert_eq!(a.expose(), b.expose());
                // The padded form is a block multiple within the cap.
                let padded = pad_to(a.expose(), RECORD_PAD_BLOCK, MAX_RECORD_PADDED).unwrap();
                prop_assert_eq!(padded.len() % RECORD_PAD_BLOCK, 0);
            }


            /// Splitting then joining then splitting again changes nothing.
            #[test]
            fn split_join_identity_any(s in spec()) {
                let (e1, s1) = split(build(1, &s));
                let b1 = s1.encode().unwrap();
                let joined = join(&e1, s1).unwrap();
                let (e2, s2) = split(joined);
                let b2 = s2.encode().unwrap();
                prop_assert_eq!(b1.expose(), b2.expose());
                let sealed = |mut e: ItemEntry| {
                    e.record = RecordRef { generation: 1, nonce: [1; 24], ct_len: 272 };
                    let mut index = Index::new_default();
                    index.entries.push(e);
                    index.encode().unwrap().expose().to_vec()
                };
                prop_assert_eq!(sealed(e1), sealed(e2));
            }

            /// An index of split entries encodes, decodes and encodes to the same bytes.
            #[test]
            fn index_roundtrip_any(specs in prop::collection::vec(spec(), 0..=6)) {
                let mut index = Index::new_default();
                for (n, s) in (1u8..).zip(&specs) {
                    let (mut entry, _) = split(build(n, s));
                    entry.record = RecordRef {
                        generation: u64::from(n),
                        nonce: [n; 24],
                        ct_len: u32::try_from(RECORD_PAD_BLOCK + 16).unwrap(),
                    };
                    index.entries.push(entry);
                }
                let a = index.encode().unwrap();
                let back = Index::decode(a.expose()).unwrap();
                let b = back.encode().unwrap();
                prop_assert_eq!(a.expose(), b.expose());
                prop_assert_eq!(back.entries.len(), specs.len());
            }
        }
    }
}
