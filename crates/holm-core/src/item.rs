//! Items and the item-level field rules.
//!
//! An [`Item`] is one vault entry. Its text lives in wiping types from [`crate::text`].
//! `validate_item` is the single implementation of the item rules (the per-field
//! checks live in [`crate::rules`]): adding, updating and decoding a stored vault all
//! call it. A [`FieldError`] names the field that failed
//! and never carries the value.

use crate::category::CategoryId;
use crate::rules::{
    Field, FieldError, MAX_LINE_BYTES, MAX_NOTE_BYTES, MAX_SECRET_BYTES, MAX_URLS, display_field,
    line_secret, multi_line, non_blank,
};
use crate::text::{GatedSecret, SecretText, Text};
use core::fmt;
use holm_crypto::{CryptoError, fill_random};
use serde::{Deserialize, Serialize};

/// A random 128-bit item identifier, shown as 32 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ItemId([u8; 16]);

impl ItemId {
    /// A fresh random id from the operating system.
    ///
    /// # Errors
    /// Returns [`CryptoError`] if the system random source fails.
    pub fn random() -> Result<ItemId, CryptoError> {
        let mut b = [0u8; 16];
        fill_random(&mut b)?;
        Ok(ItemId(b))
    }

    /// The id as 32 lowercase hex characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(32);
        for b in self.0 {
            s.push(char::from(HEX[usize::from(b >> 4)]));
            s.push(char::from(HEX[usize::from(b & 15)]));
        }
        s
    }

    /// Parses exactly 32 lowercase hex characters.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<ItemId> {
        let b = s.as_bytes();
        if b.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for (slot, pair) in out.iter_mut().zip(b.as_chunks::<2>().0) {
            *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Some(ItemId(out))
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Unix time in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(pub i64);

/// The kind of an item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ItemType {
    /// Username, password and URLs.
    Login,
    /// A crypto address with chain and memo.
    CryptoAddress,
    /// A recovery phrase, readable only after a password check.
    RecoveryPhrase,
    /// Free text.
    SecureNote,
}

/// The kind-specific content of an item. No `Clone`; `Debug` prints the variant only.
pub enum ItemData {
    /// A website or app login.
    Login {
        /// Account name.
        username: Text,
        /// Password.
        password: SecretText,
        /// Sites this login is for.
        urls: Vec<Text>,
        /// Free notes.
        notes: SecretText,
    },
    /// A crypto address.
    CryptoAddress {
        /// Chain name, such as a network label.
        chain: Text,
        /// The address.
        address: SecretText,
        /// Memo or tag.
        memo: SecretText,
        /// Free notes.
        notes: SecretText,
    },
    /// A recovery phrase.
    RecoveryPhrase {
        /// The phrase, gated behind a password check.
        phrase: GatedSecret,
        /// Free notes.
        notes: SecretText,
    },
    /// A secure note.
    SecureNote {
        /// The note text.
        body: SecretText,
    },
}

impl ItemData {
    /// The kind of this data.
    #[must_use]
    pub fn item_type(&self) -> ItemType {
        match self {
            ItemData::Login { .. } => ItemType::Login,
            ItemData::CryptoAddress { .. } => ItemType::CryptoAddress,
            ItemData::RecoveryPhrase { .. } => ItemType::RecoveryPhrase,
            ItemData::SecureNote { .. } => ItemType::SecureNote,
        }
    }
}

impl fmt::Debug for ItemData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ItemData::Login { .. } => "Login",
            ItemData::CryptoAddress { .. } => "CryptoAddress",
            ItemData::RecoveryPhrase { .. } => "RecoveryPhrase",
            ItemData::SecureNote { .. } => "SecureNote",
        })
    }
}

/// One vault entry.
pub struct Item {
    pub(crate) id: ItemId,
    pub(crate) title: Text,
    pub(crate) category: Option<CategoryId>,
    pub(crate) favourite: bool,
    pub(crate) created: Timestamp,
    pub(crate) updated: Timestamp,
    pub(crate) trashed: Option<Timestamp>,
    pub(crate) data: ItemData,
}

impl Item {
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
    /// The kind-specific data.
    #[must_use]
    pub fn data(&self) -> &ItemData {
        &self.data
    }
    /// The kind of this item.
    #[must_use]
    pub fn item_type(&self) -> ItemType {
        self.data.item_type()
    }
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("item_type", &self.item_type())
            .finish_non_exhaustive()
    }
}

/// What a caller supplies to add or update an item.
pub struct ItemInput {
    /// Title.
    pub title: Text,
    /// Category, if any.
    pub category: Option<CategoryId>,
    /// Favourite flag.
    pub favourite: bool,
    /// Kind-specific data.
    pub data: ItemData,
}

impl ItemInput {
    /// Checks every field rule, for adding a new item.
    ///
    /// # Errors
    /// Returns the first [`FieldError`] found.
    pub fn validate(&self) -> Result<(), FieldError> {
        validate_item(&self.title, &self.data, PhraseRule::Required)
    }

    /// Like [`ItemInput::validate`], but an empty phrase is allowed: it means "keep the
    /// stored phrase".
    pub(crate) fn validate_for_update(&self) -> Result<(), FieldError> {
        validate_item(&self.title, &self.data, PhraseRule::EmptyKeeps)
    }
}

/// Whether an empty recovery phrase is an error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PhraseRule {
    /// Adding or decoding: the phrase must be present.
    Required,
    /// Updating: an empty phrase keeps the stored one.
    EmptyKeeps,
}

/// The one implementation of the item field rules. Validation reports the failing
/// field, never its value.
///
/// # Errors
/// Returns the first [`FieldError`] found.
pub(crate) fn validate_item(
    title: &Text,
    data: &ItemData,
    phrase: PhraseRule,
) -> Result<(), FieldError> {
    non_blank(Field::Title, title.as_str())?;
    display_field(Field::Title, title.as_str())?;
    match data {
        ItemData::Login {
            username,
            password,
            urls,
            notes,
        } => {
            display_field(Field::Username, username.as_str())?;
            line_secret(Field::Password, password.expose(), MAX_SECRET_BYTES)?;
            if urls.len() > MAX_URLS {
                return Err(FieldError::TooManyUrls);
            }
            for url in urls {
                let u = url.as_str();
                if u.is_empty() {
                    return Err(FieldError::Empty(Field::Url));
                }
                if u.trim() != u {
                    return Err(FieldError::ForbiddenChar(Field::Url));
                }
                display_field(Field::Url, u)?;
            }
            multi_line(Field::Notes, notes.expose(), MAX_NOTE_BYTES)?;
        }
        ItemData::CryptoAddress {
            chain,
            address,
            memo,
            notes,
        } => {
            display_field(Field::Chain, chain.as_str())?;
            non_blank(Field::Address, address.expose())?;
            line_secret(Field::Address, address.expose(), MAX_LINE_BYTES)?;
            line_secret(Field::Memo, memo.expose(), MAX_LINE_BYTES)?;
            multi_line(Field::Notes, notes.expose(), MAX_NOTE_BYTES)?;
        }
        ItemData::RecoveryPhrase { phrase: p, notes } => {
            if phrase == PhraseRule::Required && p.expose().trim().is_empty() {
                return Err(FieldError::Empty(Field::Phrase));
            }
            multi_line(Field::Phrase, p.expose(), MAX_SECRET_BYTES)?;
            multi_line(Field::Notes, notes.expose(), MAX_NOTE_BYTES)?;
        }
        ItemData::SecureNote { body } => {
            multi_line(Field::Body, body.expose(), MAX_NOTE_BYTES)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::CategoryId;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(ItemData: Clone, Copy);
    assert_not_impl_any!(Item: Clone, Copy);
    assert_not_impl_any!(ItemData: serde::Serialize, serde::de::DeserializeOwned);
    assert_not_impl_any!(Item: serde::Serialize, serde::de::DeserializeOwned);

    fn t(s: &str) -> Text {
        Text::new(s.into())
    }
    fn st(s: &str) -> SecretText {
        SecretText::new(s.into())
    }
    fn login() -> ItemData {
        ItemData::Login {
            username: t("ada@example.com"),
            password: st("EXAMPLE-pw"),
            urls: vec![],
            notes: st(""),
        }
    }
    fn login_with(username: &str, password: &str, urls: Vec<Text>, notes: &str) -> ItemData {
        ItemData::Login {
            username: t(username),
            password: st(password),
            urls,
            notes: st(notes),
        }
    }
    fn check(title: &str, data: ItemData) -> Result<(), FieldError> {
        ItemInput {
            title: t(title),
            category: None,
            favourite: false,
            data,
        }
        .validate()
    }
    fn phrase(p: &str) -> ItemData {
        ItemData::RecoveryPhrase {
            phrase: GatedSecret::new(st(p)),
            notes: st(""),
        }
    }

    #[test]
    fn item_debug_has_no_text() {
        let item = Item {
            id: ItemId([7; 16]),
            title: t("Example Mail"),
            category: Some(CategoryId(1)),
            favourite: false,
            created: Timestamp(1),
            updated: Timestamp(2),
            trashed: None,
            data: login(),
        };
        let d = format!("{item:?} {:?}", item.data());
        assert!(!d.contains("Example Mail"));
        assert!(!d.contains("ada@example.com"));
        assert!(!d.contains("EXAMPLE-pw"));
        assert!(d.contains("Login"));
        assert_eq!(item.title(), "Example Mail");
    }

    #[test]
    fn item_id_random_differs_and_hex_roundtrips() {
        let a = ItemId::random().unwrap();
        let b = ItemId::random().unwrap();
        assert_ne!(a, b);
        assert_eq!(ItemId::from_hex(&a.to_hex()), Some(a));
        assert_eq!(a.to_hex().len(), 32);
        assert_eq!(format!("{a}"), a.to_hex());
        assert_eq!(format!("{a:?}"), a.to_hex());
        assert_eq!(ItemId::from_hex("zz"), None);
        assert_eq!(ItemId::from_hex(&"A".repeat(32)), None);
        assert_eq!(ItemId::from_hex(&"a".repeat(31)), None);
    }

    #[test]
    fn item_id_serde_roundtrips() {
        let a = ItemId([9; 16]);
        let s = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<ItemId>(&s).unwrap(), a);
    }

    #[test]
    fn title_required() {
        assert_eq!(check("  ", login()), Err(FieldError::Empty(Field::Title)));
        assert_eq!(check("", login()), Err(FieldError::Empty(Field::Title)));
        assert_eq!(check("Mail", login()), Ok(()));
    }

    #[test]
    fn crypto_address_required() {
        let d = |a: &str| ItemData::CryptoAddress {
            chain: t("EXAMPLE"),
            address: st(a),
            memo: st(""),
            notes: st(""),
        };
        assert_eq!(check("W", d("")), Err(FieldError::Empty(Field::Address)));
        assert_eq!(check("W", d("EXAMPLE-addr")), Ok(()));
    }

    #[test]
    fn phrase_required_on_add() {
        assert_eq!(
            check("P", phrase("")),
            Err(FieldError::Empty(Field::Phrase))
        );
        assert_eq!(check("P", phrase("EXAMPLE words")), Ok(()));
    }

    #[test]
    fn empty_phrase_allowed_on_update() {
        let i = ItemInput {
            title: t("P"),
            category: None,
            favourite: false,
            data: phrase(""),
        };
        assert_eq!(i.validate_for_update(), Ok(()));
    }

    #[test]
    fn display_fields_reject_controls_and_bidi() {
        for bad in ['\u{202E}', '\u{7}', '\n', '\u{85}'] {
            assert_eq!(
                check(&format!("a{bad}b"), login()),
                Err(FieldError::ForbiddenChar(Field::Title)),
                "{bad:?}"
            );
        }
        assert_eq!(
            check("T", login_with("a\u{2066}b", "x", vec![], "")),
            Err(FieldError::ForbiddenChar(Field::Username))
        );
        let chain = ItemData::CryptoAddress {
            chain: t("x\ty"),
            address: st("a"),
            memo: st(""),
            notes: st(""),
        };
        assert_eq!(
            check("T", chain),
            Err(FieldError::ForbiddenChar(Field::Chain))
        );
    }

    #[test]
    fn password_allows_spaces_tabs_unicode() {
        assert_eq!(
            check("T", login_with("", " pa\u{301}ss\tword ", vec![], "")),
            Ok(())
        );
        for bad in ["a\nb", "a\0b", "a\rb"] {
            assert_eq!(
                check("T", login_with("", bad, vec![], "")),
                Err(FieldError::ForbiddenChar(Field::Password))
            );
        }
    }

    #[test]
    fn notes_allow_newlines_and_tabs() {
        assert_eq!(
            check("T", login_with("", "x", vec![], "line1\r\nline2\tend")),
            Ok(())
        );
        let n = ItemData::SecureNote {
            body: st("a\nb\tc"),
        };
        assert_eq!(check("T", n), Ok(()));
        assert_eq!(check("T", phrase("one\ntwo")), Ok(()));
    }

    #[test]
    fn notes_reject_nul() {
        assert_eq!(
            check("T", login_with("", "x", vec![], "a\0b")),
            Err(FieldError::ForbiddenChar(Field::Notes))
        );
        let n = ItemData::SecureNote { body: st("a\0b") };
        assert_eq!(check("T", n), Err(FieldError::ForbiddenChar(Field::Body)));
        assert_eq!(
            check("T", phrase("a\0b")),
            Err(FieldError::ForbiddenChar(Field::Phrase))
        );
    }

    #[test]
    fn length_limits_exact() {
        assert_eq!(check(&"a".repeat(1024), login()), Ok(()));
        assert_eq!(
            check(&"a".repeat(1025), login()),
            Err(FieldError::TooLong(Field::Title))
        );
        assert_eq!(
            check("T", login_with("", &"a".repeat(4096), vec![], "")),
            Ok(())
        );
        assert_eq!(
            check("T", login_with("", &"a".repeat(4097), vec![], "")),
            Err(FieldError::TooLong(Field::Password))
        );
        assert_eq!(
            check("T", login_with("", "x", vec![], &"a".repeat(65_536))),
            Ok(())
        );
        assert_eq!(
            check("T", login_with("", "x", vec![], &"a".repeat(65_537))),
            Err(FieldError::TooLong(Field::Notes))
        );
        let urls = |n: usize| (0..n).map(|_| t("https://example.com")).collect::<Vec<_>>();
        assert_eq!(check("T", login_with("", "x", urls(32), "")), Ok(()));
        assert_eq!(
            check("T", login_with("", "x", urls(33), "")),
            Err(FieldError::TooManyUrls)
        );
        assert_eq!(
            check("T", phrase(&"a".repeat(4097))),
            Err(FieldError::TooLong(Field::Phrase))
        );
    }

    #[test]
    fn url_rules() {
        let u = |s: &str| check("T", login_with("", "x", vec![t(s)], ""));
        assert_eq!(check("T", login_with("", "x", vec![], "")), Ok(()));
        assert_eq!(u("https://example.com"), Ok(()));
        assert_eq!(u(""), Err(FieldError::Empty(Field::Url)));
        assert_eq!(
            u(" https://example.com"),
            Err(FieldError::ForbiddenChar(Field::Url))
        );
        assert_eq!(
            u("https://example.com "),
            Err(FieldError::ForbiddenChar(Field::Url))
        );
    }

    #[test]
    fn error_messages_name_field_not_value() {
        assert_eq!(
            FieldError::ForbiddenChar(Field::Password).to_string(),
            "Password contains a character that is not allowed"
        );
        assert_eq!(
            FieldError::Empty(Field::Title).to_string(),
            "Title must not be empty"
        );
        assert_eq!(FieldError::TooManyUrls.to_string(), "too many URLs");
    }
}
