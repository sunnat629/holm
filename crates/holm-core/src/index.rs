//! The index of a format v2 vault: everything Holm shows without a Reveal button.
//!
//! Spec section 2.3 and 2.6. The index holds the settings, the categories, and one
//! [`ItemEntry`] per item: id, title, category, the public parts of the item (username,
//! URLs, chain, custom Text and Date values, labels, expiry, used flags), one presence
//! flag per sealed value, and the table entry that points at the item's sealed record
//! ([`RecordRef`]). It holds no secret text: there is no `SecretText`, `GatedSecret` or
//! `SecretBuf` anywhere in these types, and a test keeps it that way.
//!
//! Layout (body schema [`BODY_SCHEMA_V4`]): a `u16` little-endian version, then the
//! `postcard` encoding of the settings, the categories, the entries, the next category
//! id and, last, the migration backup note. Padding is added and removed by the
//! envelope, not here.
//!
//! [`Index::decode`] treats its input as hostile, as [`crate::body`] does. It refuses a
//! newer schema, rejects trailing bytes, bounds every length and count while parsing,
//! then re-runs every public field rule. The rules are the existing ones: each entry is
//! checked through [`validate_item`] and [`try_field`] with placeholder secrets, so the
//! public rules have one implementation. [`Index::encode`] runs the same checks first.

use crate::body::{BodyError, check_categories, encode_wire};
use crate::category::{BUILT_IN_CATEGORIES, Category, CategoryId, validate_category_name};
use crate::fields::{CalendarDate, FieldKind, FieldValue, RecoveryCode, try_field};
use crate::item::{ItemData, ItemId, ItemType, PhraseRule, Timestamp, validate_item};
use crate::padding::{MAX_RECORD_PADDED, RECORD_PAD_BLOCK};
use crate::rules::{Field, FieldError, MAX_CUSTOM_FIELDS, MAX_ITEMS, MAX_RECOVERY_CODES, MAX_URLS};
use crate::settings::Settings;
use crate::text::{GatedSecret, SecretText, Text};
use crate::wire::{IndexIn, IndexOut};
use core::fmt;
use holm_crypto::SecretBuf;
use holm_crypto::aead::{NONCE_LEN, TAG_LEN};

/// The index schema this build writes and reads. Schemas 1 to 3 exist only in format 1.
pub const BODY_SCHEMA_V4: u16 = 4;

/// Length of the schema version prefix in bytes.
const VERSION_LEN: usize = 2;

/// Smallest sealed record: one padded block and the tag.
pub(crate) const MIN_RECORD_CT: usize = RECORD_PAD_BLOCK + TAG_LEN;
/// Largest sealed record: the padded cap and the tag.
pub(crate) const MAX_RECORD_CT: usize = MAX_RECORD_PADDED + TAG_LEN;

/// Where an item's sealed record is: its place in the table (spec 2.5).
///
/// `generation` counts the seals of this item and is part of the record's associated
/// data. A decoded index always has `generation >= 1`; [`RecordRef::UNSEALED`] (0) marks
/// an entry that has no record yet, and [`Index::encode`] refuses it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordRef {
    /// Number of times this item's record has been sealed, from 1.
    pub(crate) generation: u64,
    /// The nonce the record was sealed with.
    pub(crate) nonce: [u8; NONCE_LEN],
    /// Length of the record ciphertext, tag included.
    pub(crate) ct_len: u32,
}

impl RecordRef {
    /// An entry whose record has not been sealed yet.
    pub(crate) const UNSEALED: RecordRef = RecordRef {
        generation: 0,
        nonce: [0; NONCE_LEN],
        ct_len: 0,
    };

    /// The ciphertext length in bytes, or `None` if it does not fit `usize`.
    pub(crate) fn ct_len_usize(&self) -> Option<usize> {
        usize::try_from(self.ct_len).ok()
    }

    /// The range rules of spec 2.8, without the running sum.
    fn in_range(&self) -> Result<(), RefError> {
        if self.generation == 0 {
            return Err(RefError::Generation);
        }
        let len = self.ct_len_usize().ok_or(RefError::CtLen)?;
        if !(MIN_RECORD_CT..=MAX_RECORD_CT).contains(&len)
            || !(len - TAG_LEN).is_multiple_of(RECORD_PAD_BLOCK)
        {
            return Err(RefError::CtLen);
        }
        Ok(())
    }
}

impl fmt::Debug for RecordRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordRef")
            .field("generation", &self.generation)
            .field("ct_len", &self.ct_len)
            .finish_non_exhaustive()
    }
}

/// Why a [`RecordRef`] is out of range.
#[derive(Clone, Copy)]
enum RefError {
    Generation,
    CtLen,
}

/// The public part of an item, by kind. The `has_*` flags say whether the sealed value
/// is non-empty, so a detail view can hide empty rows without decrypting the record.
/// No variant holds secret text. `Debug` prints the kind only.
pub enum EntryPublic {
    /// A website or app login.
    Login {
        /// Account name, shown in the clear.
        username: Text,
        /// Sites this login is for.
        urls: Vec<Text>,
        /// Whether the sealed password is non-empty.
        has_password: bool,
        /// Whether the sealed notes are non-empty.
        has_notes: bool,
    },
    /// A crypto address.
    CryptoAddress {
        /// Chain name.
        chain: Text,
        /// Whether the sealed address is non-empty.
        has_address: bool,
        /// Whether the sealed memo is non-empty.
        has_memo: bool,
        /// Whether the sealed notes are non-empty.
        has_notes: bool,
    },
    /// A recovery phrase. The phrase itself is always present.
    RecoveryPhrase {
        /// Whether the sealed notes are non-empty.
        has_notes: bool,
    },
    /// A secure note.
    SecureNote {
        /// Whether the sealed body is non-empty.
        has_body: bool,
    },
}

impl EntryPublic {
    /// The kind of item this is.
    #[must_use]
    pub fn item_type(&self) -> ItemType {
        match self {
            EntryPublic::Login { .. } => ItemType::Login,
            EntryPublic::CryptoAddress { .. } => ItemType::CryptoAddress,
            EntryPublic::RecoveryPhrase { .. } => ItemType::RecoveryPhrase,
            EntryPublic::SecureNote { .. } => ItemType::SecureNote,
        }
    }
}

impl fmt::Debug for EntryPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EntryPublic::Login { .. } => "Login",
            EntryPublic::CryptoAddress { .. } => "CryptoAddress",
            EntryPublic::RecoveryPhrase { .. } => "RecoveryPhrase",
            EntryPublic::SecureNote { .. } => "SecureNote",
        })
    }
}

/// What the index keeps of a custom field's value.
///
/// Text and Date values are public. The three secret kinds keep nothing but their
/// kind; recovery codes keep their used flags (the "N of M left" count), not the codes.
pub enum FieldEntryKind {
    /// A display line, shown in the clear.
    Text(Text),
    /// A secret line, sealed in the record.
    Secret,
    /// Secret text that may contain newlines, sealed in the record.
    MultilineSecret,
    /// A calendar day.
    Date(CalendarDate),
    /// Recovery codes, sealed in the record; only the used flags are here.
    RecoveryCodes {
        /// One flag per code, in order.
        used: Vec<bool>,
    },
}

impl FieldEntryKind {
    /// The kind with no content attached.
    #[must_use]
    pub fn kind(&self) -> FieldKind {
        match self {
            FieldEntryKind::Text(_) => FieldKind::Text,
            FieldEntryKind::Secret => FieldKind::Secret,
            FieldEntryKind::MultilineSecret => FieldKind::MultilineSecret,
            FieldEntryKind::Date(_) => FieldKind::Date,
            FieldEntryKind::RecoveryCodes { .. } => FieldKind::RecoveryCodes,
        }
    }

    /// True when the value lives in the record.
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        matches!(
            self,
            FieldEntryKind::Secret
                | FieldEntryKind::MultilineSecret
                | FieldEntryKind::RecoveryCodes { .. }
        )
    }
}

impl fmt::Debug for FieldEntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind())
    }
}

/// A custom field as the index keeps it. Its position is its index in the entry's list.
pub struct FieldEntry {
    pub(crate) position: u8,
    pub(crate) label: Text,
    pub(crate) kind: FieldEntryKind,
    pub(crate) expiry: Option<CalendarDate>,
}

impl FieldEntry {
    /// The position in the item's field list.
    #[must_use]
    pub fn position(&self) -> u8 {
        self.position
    }
    /// The display label.
    #[must_use]
    pub fn label(&self) -> &str {
        self.label.as_str()
    }
    /// The kind, with the public value where there is one.
    #[must_use]
    pub fn kind(&self) -> &FieldEntryKind {
        &self.kind
    }
    /// The optional reminder date.
    #[must_use]
    pub fn expiry(&self) -> Option<CalendarDate> {
        self.expiry
    }
}

impl fmt::Debug for FieldEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldEntry")
            .field("kind", &self.kind.kind())
            .field("label_len", &self.label.as_str().len())
            .field("expiry", &self.expiry.is_some())
            .finish()
    }
}

/// One item as the index keeps it. No `Clone`; `Debug` prints the id and the kind only.
pub struct ItemEntry {
    pub(crate) id: ItemId,
    pub(crate) title: Text,
    pub(crate) category: Option<CategoryId>,
    pub(crate) favourite: bool,
    pub(crate) created: Timestamp,
    pub(crate) updated: Timestamp,
    pub(crate) trashed: Option<Timestamp>,
    pub(crate) public: EntryPublic,
    pub(crate) fields: Vec<FieldEntry>,
    pub(crate) record: RecordRef,
}

impl ItemEntry {
    /// The item id.
    #[must_use]
    pub fn id(&self) -> ItemId {
        self.id
    }
    /// The title.
    #[must_use]
    pub fn title(&self) -> &str {
        self.title.as_str()
    }
    /// The category, if any.
    #[must_use]
    pub fn category(&self) -> Option<CategoryId> {
        self.category
    }
    /// Whether the item is a favourite.
    #[must_use]
    pub fn favourite(&self) -> bool {
        self.favourite
    }
    /// When the item was created.
    #[must_use]
    pub fn created(&self) -> Timestamp {
        self.created
    }
    /// When the item was last changed.
    #[must_use]
    pub fn updated(&self) -> Timestamp {
        self.updated
    }
    /// When the item was moved to the trash, if it was.
    #[must_use]
    pub fn trashed(&self) -> Option<Timestamp> {
        self.trashed
    }
    /// The kind of this item.
    #[must_use]
    pub fn item_type(&self) -> ItemType {
        self.public.item_type()
    }
    /// The public data of this item.
    #[must_use]
    pub fn public(&self) -> &EntryPublic {
        &self.public
    }
    /// Custom fields in their stored order.
    #[must_use]
    pub fn fields(&self) -> &[FieldEntry] {
        &self.fields
    }
}

impl fmt::Debug for ItemEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemEntry")
            .field("id", &self.id)
            .field("item_type", &self.item_type())
            .finish_non_exhaustive()
    }
}

/// The note the index keeps about the migration backup (spec 4.3).
pub(crate) struct BackupNote {
    pub(crate) tag: String,
    pub(crate) prompt: BackupPrompt,
}

/// How far the backup prompts have got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupPrompt {
    /// Ask after the next good unlock.
    AfterUnlock,
    /// Ask again after a password change.
    AfterPasswordChange,
    /// The owner chose; do not ask again.
    Done,
}

/// Length of a backup tag: `v1-` and 16 lowercase hex characters.
const BACKUP_TAG_LEN: usize = 19;

impl BackupNote {
    /// True when `tag` is `v1-` and 16 lowercase hex characters, which keeps it safe to
    /// use inside a file name.
    pub(crate) fn tag_is_valid(tag: &str) -> bool {
        tag.len() == BACKUP_TAG_LEN
            && tag.starts_with("v1-")
            && tag[3..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

impl fmt::Debug for BackupNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupNote")
            .field("prompt", &self.prompt)
            .finish_non_exhaustive()
    }
}

/// Everything inside the index. No `Clone`; `Debug` prints counts only.
pub(crate) struct Index {
    pub(crate) settings: Settings,
    pub(crate) categories: Vec<Category>,
    pub(crate) entries: Vec<ItemEntry>,
    pub(crate) next_category_id: u32,
    pub(crate) migration_backup: Option<BackupNote>,
}

impl fmt::Debug for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Index")
            .field("categories", &self.categories.len())
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl Index {
    /// The index of a new vault: default settings, the built-in categories with ids 1
    /// to 3, no entries and no backup note.
    pub(crate) fn new_default() -> Index {
        let categories: Vec<Category> = (1..)
            .zip(BUILT_IN_CATEGORIES)
            .map(|(id, name)| Category {
                id: CategoryId(id),
                name: Text::new(name.to_owned()),
            })
            .collect();
        Index {
            settings: Settings::default(),
            categories,
            entries: Vec::new(),
            next_category_id: 4,
            migration_backup: None,
        }
    }

    /// The sum of the entries' ciphertext lengths, or `None` on overflow.
    pub(crate) fn records_total(&self) -> Option<u64> {
        self.entries
            .iter()
            .try_fold(0u64, |sum, e| sum.checked_add(u64::from(e.record.ct_len)))
    }

    /// Encodes the index: the schema version, then postcard.
    ///
    /// The data is checked first with the rules [`Index::decode`] applies, so an index
    /// Holm writes is one it can open again. An entry with no sealed record
    /// ([`RecordRef::UNSEALED`]) is refused.
    ///
    /// # Errors
    /// [`BodyError::Invalid`] if the data breaks a rule, [`BodyError::Encode`] if
    /// postcard fails.
    pub(crate) fn encode(&self) -> Result<SecretBuf, BodyError> {
        self.settings.validate().map_err(|_| BodyError::Invalid)?;
        self.check()?;
        let out = IndexOut::new(self);
        encode_wire(&out, BODY_SCHEMA_V4)
    }

    /// Decodes and checks an index.
    ///
    /// Order: [`BodyError::TooShort`] under 2 bytes; [`BodyError::NewerSchema`] above
    /// [`BODY_SCHEMA_V4`]; [`BodyError::Malformed`] for a lower schema (they exist only
    /// in format 1), a bad encoding, a length or count over its cap, trailing bytes, a
    /// bad backup tag, a zero generation or a ciphertext length out of range;
    /// [`BodyError::Invalid`] if a field rule or cross-check fails. Out-of-range
    /// settings are clamped into range, not refused.
    ///
    /// The running sum of ciphertext lengths against the records region is checked by
    /// the caller, which knows the region ([`Index::records_total`]).
    ///
    /// # Errors
    /// As listed above.
    pub(crate) fn decode(plaintext: &[u8]) -> Result<Index, BodyError> {
        let (version, rest) = plaintext
            .split_first_chunk::<VERSION_LEN>()
            .ok_or(BodyError::TooShort)?;
        let version = u16::from_le_bytes(*version);
        if version > BODY_SCHEMA_V4 {
            return Err(BodyError::NewerSchema(version));
        }
        if version != BODY_SCHEMA_V4 {
            return Err(BodyError::Malformed);
        }
        let (wire, leftover) =
            postcard::take_from_bytes::<IndexIn>(rest).map_err(|_| BodyError::Malformed)?;
        if !leftover.is_empty() {
            return Err(BodyError::Malformed);
        }
        let mut index = wire.into_index()?;
        for entry in &index.entries {
            entry.record.in_range().map_err(|_| BodyError::Malformed)?;
        }
        for entry in &index.entries {
            check_entry(entry).map_err(|_| BodyError::Invalid)?;
        }
        index.check_structure()?;
        index.settings.clamp_to_policy();
        Ok(index)
    }

    /// Every rule, for encoding.
    fn check(&self) -> Result<(), BodyError> {
        for c in &self.categories {
            validate_category_name(c.name()).map_err(|_| BodyError::Invalid)?;
        }
        for entry in &self.entries {
            check_entry(entry).map_err(|_| BodyError::Invalid)?;
            entry.record.in_range().map_err(|_| BodyError::Invalid)?;
        }
        if let Some(note) = &self.migration_backup
            && !BackupNote::tag_is_valid(&note.tag)
        {
            return Err(BodyError::Invalid);
        }
        self.check_structure()
    }

    /// The cross-checks: limits, categories, unique item ids, known categories.
    fn check_structure(&self) -> Result<(), BodyError> {
        if self.entries.len() > MAX_ITEMS {
            return Err(BodyError::Invalid);
        }
        let ids = check_categories(&self.categories, self.next_category_id)?;
        let mut item_ids: Vec<ItemId> = self.entries.iter().map(|e| e.id).collect();
        item_ids.sort_unstable();
        if item_ids.windows(2).any(|w| w[0] == w[1]) {
            return Err(BodyError::Invalid);
        }
        if self
            .entries
            .iter()
            .filter_map(|e| e.category)
            .any(|c| ids.binary_search(&c).is_err())
        {
            return Err(BodyError::Invalid);
        }
        Ok(())
    }
}

/// Placeholder for a sealed value when an entry is run through the field rules. It
/// passes every rule a sealed value can be held to without the record.
const PLACEHOLDER: &str = "x";

/// Runs the existing public field rules over one entry.
///
/// The entry is turned into an item whose sealed values are placeholders and given to
/// [`validate_item`] and [`try_field`], so there is one implementation of the title,
/// username, URL, chain, label, Text, Date and expiry rules. The sealed values are
/// checked against their own rules later, when the record is opened.
pub(crate) fn check_entry(entry: &ItemEntry) -> Result<(), FieldError> {
    let placeholder = || SecretText::new(PLACEHOLDER.to_owned());
    let empty = || SecretText::new(String::new());
    let data = match &entry.public {
        EntryPublic::Login { username, urls, .. } => ItemData::Login {
            username: username.clone(),
            password: empty(),
            urls: urls.clone(),
            notes: empty(),
        },
        EntryPublic::CryptoAddress {
            has_address: false, ..
        } => return Err(FieldError::Empty(Field::Address)),
        EntryPublic::CryptoAddress { chain, .. } => ItemData::CryptoAddress {
            chain: chain.clone(),
            address: placeholder(),
            memo: empty(),
            notes: empty(),
        },
        EntryPublic::RecoveryPhrase { .. } => ItemData::RecoveryPhrase {
            phrase: GatedSecret::new(placeholder()),
            notes: empty(),
        },
        EntryPublic::SecureNote { .. } => ItemData::SecureNote { body: empty() },
    };
    validate_item(&entry.title, &data, PhraseRule::Required)?;
    if entry.fields.len() > MAX_CUSTOM_FIELDS {
        return Err(FieldError::TooManyFields);
    }
    for (position, field) in entry.fields.iter().enumerate() {
        if usize::from(field.position) != position {
            return Err(FieldError::NoSuchIndex);
        }
        let value = match &field.kind {
            FieldEntryKind::Text(text) => FieldValue::Text(text.clone()),
            FieldEntryKind::Secret => FieldValue::Secret(placeholder()),
            FieldEntryKind::MultilineSecret => FieldValue::MultilineSecret(placeholder()),
            FieldEntryKind::Date(date) => FieldValue::Date(*date),
            FieldEntryKind::RecoveryCodes { used } => {
                if used.len() > MAX_RECOVERY_CODES {
                    return Err(FieldError::BadCodeCount);
                }
                FieldValue::RecoveryCodes(
                    used.iter()
                        .map(|u| RecoveryCode::new(placeholder(), *u))
                        .collect(),
                )
            }
        };
        try_field(field.label.clone(), value, field.expiry)?;
    }
    if let EntryPublic::Login { urls, .. } = &entry.public
        && urls.len() > MAX_URLS
    {
        return Err(FieldError::TooManyUrls);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::CalendarDate;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(Index: Clone, serde::Serialize, serde::de::DeserializeOwned);
    assert_not_impl_any!(ItemEntry: Clone, serde::Serialize, serde::de::DeserializeOwned);
    assert_not_impl_any!(EntryPublic: Clone, serde::Serialize, serde::de::DeserializeOwned);
    assert_not_impl_any!(FieldEntry: Clone, serde::Serialize, serde::de::DeserializeOwned);

    #[rustfmt::skip]
    const V4_DEFAULT_GOLDEN: [u8; 52] = [
        4, 0,                         // index schema 4, little-endian
        172, 2, 30, 1,                // auto-lock 300 (varint), clipboard 30, lock on sleep
        20, 1, 1, 1, 1, 0, 1, 1,      // password: length 20, sets, no look-alike filter, minimums
        6, 1, 45, 0, 0,               // passphrase: 6 words, separator "-", flags
        2, 3,                         // username: 2 words, 3 digits
        3,                            // 3 categories
        1, 8, b'P', b'e', b'r', b's', b'o', b'n', b'a', b'l',
        2, 4, b'W', b'o', b'r', b'k',
        3, 9, b'C', b'o', b'm', b'm', b'u', b'n', b'i', b't', b'y',
        0,                            // no entries
        4,                            // next category id
        0,                            // no backup note
    ];

    pub(crate) fn t(s: &str) -> Text {
        Text::new(s.into())
    }

    fn entry_id(n: u8) -> ItemId {
        ItemId::from_hex(&format!("{n:02x}").repeat(16)).unwrap()
    }

    pub(crate) fn sealed_ref(ct_len: u32) -> RecordRef {
        RecordRef {
            generation: 1,
            nonce: [9; NONCE_LEN],
            ct_len,
        }
    }

    pub(crate) fn note_entry(n: u8) -> ItemEntry {
        ItemEntry {
            id: entry_id(n),
            title: t("Example note"),
            category: Some(CategoryId(1)),
            favourite: false,
            created: Timestamp(1),
            updated: Timestamp(2),
            trashed: None,
            public: EntryPublic::SecureNote { has_body: true },
            fields: Vec::new(),
            record: sealed_ref(u32::try_from(MIN_RECORD_CT).unwrap()),
        }
    }

    pub(crate) fn rich_entry(n: u8) -> ItemEntry {
        ItemEntry {
            id: entry_id(n),
            title: t("Example mail"),
            category: None,
            favourite: true,
            created: Timestamp(10),
            updated: Timestamp(20),
            trashed: Some(Timestamp(30)),
            public: EntryPublic::Login {
                username: t("ada@example.com"),
                urls: vec![t("https://example.com")],
                has_password: true,
                has_notes: false,
            },
            fields: vec![
                FieldEntry {
                    position: 0,
                    label: t("Site"),
                    kind: FieldEntryKind::Text(t("example")),
                    expiry: None,
                },
                FieldEntry {
                    position: 1,
                    label: t("PIN"),
                    kind: FieldEntryKind::Secret,
                    expiry: None,
                },
                FieldEntry {
                    position: 2,
                    label: t("Since"),
                    kind: FieldEntryKind::Date(CalendarDate::from_parts(2026, 1, 2).unwrap()),
                    expiry: Some(CalendarDate::from_parts(2027, 3, 4).unwrap()),
                },
                FieldEntry {
                    position: 3,
                    label: t("Codes"),
                    kind: FieldEntryKind::RecoveryCodes {
                        used: vec![false, true, false],
                    },
                    expiry: None,
                },
                FieldEntry {
                    position: 4,
                    label: t("Long"),
                    kind: FieldEntryKind::MultilineSecret,
                    expiry: None,
                },
            ],
            record: sealed_ref(u32::try_from(MIN_RECORD_CT + RECORD_PAD_BLOCK).unwrap()),
        }
    }

    pub(crate) fn index_with(entries: Vec<ItemEntry>) -> Index {
        Index {
            entries,
            ..Index::new_default()
        }
    }

    fn bytes(index: &Index) -> Vec<u8> {
        index.encode().unwrap().expose().to_vec()
    }

    #[test]
    fn default_index_golden() {
        assert_eq!(bytes(&Index::new_default()), V4_DEFAULT_GOLDEN);
        let back = Index::decode(&V4_DEFAULT_GOLDEN).unwrap();
        assert_eq!(back.settings, Settings::default());
        assert_eq!(back.next_category_id, 4);
        assert_eq!(back.categories.len(), 3);
        assert!(back.entries.is_empty());
        assert!(back.migration_backup.is_none());
    }

    #[test]
    fn entries_roundtrip() {
        let index = index_with(vec![rich_entry(1), note_entry(2)]);
        let first = bytes(&index);
        let back = Index::decode(&first).unwrap();
        assert_eq!(back.entries.len(), 2);
        let e = &back.entries[0];
        assert_eq!(e.title(), "Example mail");
        assert!(e.favourite());
        assert_eq!(e.trashed(), Some(Timestamp(30)));
        assert_eq!(e.item_type(), ItemType::Login);
        assert_eq!(e.fields().len(), 5);
        assert!(matches!(
            e.fields()[3].kind(),
            FieldEntryKind::RecoveryCodes { used } if used == &[false, true, false]
        ));
        assert_eq!(e.record, rich_entry(1).record);
        assert_eq!(bytes(&back), first);
    }

    #[test]
    fn index_backup_note_roundtrip() {
        let mut index = Index::new_default();
        for prompt in [
            BackupPrompt::AfterUnlock,
            BackupPrompt::AfterPasswordChange,
            BackupPrompt::Done,
        ] {
            index.migration_backup = Some(BackupNote {
                tag: "v1-0123456789abcdef".to_owned(),
                prompt,
            });
            let back = Index::decode(&bytes(&index)).unwrap();
            let note = back.migration_backup.unwrap();
            assert_eq!(note.tag, "v1-0123456789abcdef");
            assert_eq!(note.prompt, prompt);
        }
    }

    #[test]
    fn index_backup_note_bad_tag_malformed() {
        let mut index = Index::new_default();
        index.migration_backup = Some(BackupNote {
            tag: "v1-0123456789abcdef".to_owned(),
            prompt: BackupPrompt::Done,
        });
        let good = bytes(&index);
        assert!(Index::decode(&good).is_ok());
        // The note is the tail: Some (1), tag length, tag bytes, prompt (Done = 2).
        let head = &good[..good.len() - (1 + 1 + 19 + 1)];
        // Tags that would be unsafe or odd in a file name.
        for bad in [
            "v1-0123456789abcdeF",
            "v2-0123456789abcdef",
            "v1-0123456789abcde/",
            "v1-0123456789abcd",
            "../../etc/passwdxx",
            "v1-0123456789abcdef0",
            "",
        ] {
            let mut raw = head.to_vec();
            raw.push(1);
            raw.push(u8::try_from(bad.len()).unwrap());
            raw.extend_from_slice(bad.as_bytes());
            raw.push(2);
            assert_eq!(
                Index::decode(&raw).err(),
                Some(BodyError::Malformed),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn encode_refuses_bad_tag() {
        let mut index = Index::new_default();
        index.migration_backup = Some(BackupNote {
            tag: "../x".to_owned(),
            prompt: BackupPrompt::Done,
        });
        assert_eq!(index.encode().err(), Some(BodyError::Invalid));
    }

    #[test]
    fn index_rejects_schema_3() {
        let mut raw = V4_DEFAULT_GOLDEN.to_vec();
        for v in [1u8, 2, 3] {
            raw[0] = v;
            assert_eq!(Index::decode(&raw).err(), Some(BodyError::Malformed));
        }
        raw[0] = 0;
        assert_eq!(Index::decode(&raw).err(), Some(BodyError::Malformed));
        raw[1] = 1; // 256, a newer schema
        assert_eq!(Index::decode(&raw).err(), Some(BodyError::NewerSchema(256)));
    }

    #[test]
    fn index_rejects_newer_schema() {
        let mut raw = V4_DEFAULT_GOLDEN.to_vec();
        raw[0] = 5;
        assert_eq!(Index::decode(&raw).err(), Some(BodyError::NewerSchema(5)));
        assert_eq!(Index::decode(&[4]).err(), Some(BodyError::TooShort));
    }

    #[test]
    fn index_trailing_bytes_malformed() {
        let mut raw = V4_DEFAULT_GOLDEN.to_vec();
        raw.push(0);
        assert_eq!(Index::decode(&raw).err(), Some(BodyError::Malformed));
    }

    #[test]
    fn index_entry_count_cap_before_reserve() {
        // A count of 2^60 with no entry behind it: refused before any reserve.
        let mut raw = V4_DEFAULT_GOLDEN[..V4_DEFAULT_GOLDEN.len() - 3].to_vec();
        raw.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x10]);
        raw.extend_from_slice(&[4, 0]);
        assert_eq!(Index::decode(&raw).err(), Some(BodyError::Malformed));
        // One past the cap is refused too.
        let mut raw = V4_DEFAULT_GOLDEN[..V4_DEFAULT_GOLDEN.len() - 3].to_vec();
        raw.extend_from_slice(&[0xd1, 0x86, 0x03]); // 50 001
        raw.extend_from_slice(&[4, 0]);
        assert_eq!(Index::decode(&raw).err(), Some(BodyError::Malformed));
    }

    fn with_record(mut e: ItemEntry, r: RecordRef) -> ItemEntry {
        e.record = r;
        e
    }

    #[test]
    fn index_ct_len_out_of_range() {
        let min = u32::try_from(MIN_RECORD_CT).unwrap();
        let max = u32::try_from(MAX_RECORD_CT).unwrap();
        // Writing refuses these (Invalid); a hand-built index shows decode does too.
        for bad in [0, 1, min - 1, min + 1, min + 255, max + 256, u32::MAX] {
            let index = index_with(vec![with_record(note_entry(1), sealed_ref(bad))]);
            assert_eq!(index.encode().err(), Some(BodyError::Invalid), "{bad}");
        }
        for good in [min, min + 256, max] {
            let index = index_with(vec![with_record(note_entry(1), sealed_ref(good))]);
            assert!(Index::decode(&bytes(&index)).is_ok(), "{good}");
        }
    }

    #[test]
    fn index_ct_len_out_of_range_malformed_on_decode() {
        let good = bytes(&index_with(vec![note_entry(1)]));
        let n = good.len();
        // The entry ends with ct_len (272 as the varint 0x90 0x02), then the next
        // category id (4) and the absent backup note (0).
        assert_eq!(&good[n - 4..], &[0x90, 0x02, 4, 0]);
        // 273 (not a block multiple), 16 (too small), 262 241 (past the cap).
        for patch in [&[0x91, 0x02][..], &[0x10], &[0xe1, 0x80, 0x10]] {
            let mut raw = good[..n - 4].to_vec();
            raw.extend_from_slice(patch);
            raw.extend_from_slice(&[4, 0]);
            assert_eq!(
                Index::decode(&raw).err(),
                Some(BodyError::Malformed),
                "{patch:?}"
            );
        }
    }

    #[test]
    fn index_generation_zero_malformed() {
        let index = index_with(vec![note_entry(1)]);
        let good = bytes(&index);
        let n = good.len();
        // The generation byte sits before the nonce, which sits before the 4 tail bytes
        // (ct_len varint, category id, absent backup note).
        let at = n - 4 - NONCE_LEN - 1;
        assert_eq!(good[at], 1);
        let mut patched = good;
        patched[at] = 0;
        assert_eq!(Index::decode(&patched).err(), Some(BodyError::Malformed));
        // And the writer refuses an unsealed entry.
        let unsealed = index_with(vec![with_record(note_entry(1), RecordRef::UNSEALED)]);
        assert_eq!(unsealed.encode().err(), Some(BodyError::Invalid));
    }

    #[test]
    fn duplicate_ids_and_unknown_categories_invalid() {
        let dup = index_with(vec![note_entry(1), note_entry(1)]);
        assert_eq!(dup.encode().err(), Some(BodyError::Invalid));
        let mut e = note_entry(1);
        e.category = Some(CategoryId(99));
        assert_eq!(index_with(vec![e]).encode().err(), Some(BodyError::Invalid));
    }

    #[test]
    fn field_positions_must_be_in_order() {
        let mut e = rich_entry(1);
        e.fields[1].position = 3;
        assert_eq!(index_with(vec![e]).encode().err(), Some(BodyError::Invalid));
    }

    #[test]
    fn public_rules_apply_to_entries() {
        let mut e = note_entry(1);
        e.title = t("bad\u{202E}title");
        assert_eq!(index_with(vec![e]).encode().err(), Some(BodyError::Invalid));
        let mut e = rich_entry(1);
        e.fields[3].kind = FieldEntryKind::RecoveryCodes { used: vec![] };
        assert_eq!(index_with(vec![e]).encode().err(), Some(BodyError::Invalid));
        let mut e = rich_entry(1);
        e.fields[0].label = t("   ");
        assert_eq!(index_with(vec![e]).encode().err(), Some(BodyError::Invalid));
    }

    #[test]
    fn entry_debug_has_no_text() {
        let e = rich_entry(1);
        let d = format!(
            "{e:?} {:?} {:?} {:?}",
            e.public(),
            e.fields()[0],
            e.fields()[0].kind()
        );
        for secret in [
            "Example mail",
            "ada@example.com",
            "example.com",
            "PIN",
            "Site",
        ] {
            assert!(!d.contains(secret), "{d}");
        }
        assert!(d.contains("Login"));
        assert!(d.contains("Text"));
        let idx = format!("{:?}", index_with(vec![rich_entry(1)]));
        assert!(!idx.contains("Example"));
    }

    #[test]
    fn records_total_adds_ct_lens() {
        let index = index_with(vec![note_entry(1), rich_entry(2)]);
        let a = u64::try_from(MIN_RECORD_CT).unwrap();
        assert_eq!(index.records_total(), Some(a + a + 256));
    }
}
