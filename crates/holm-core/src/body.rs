//! The vault body: what the envelope encrypts.
//!
//! Layout (spec section 6, `docs/DECISIONS.md`): a `u16` little-endian schema version
//! ([`BODY_SCHEMA_VERSION`]), then the `postcard` encoding of the settings, the
//! categories, the items and the next category id, in that order. Padding is added
//! and removed by the envelope, not here.
//!
//! [`VaultData::decode`] treats its input as hostile even though the envelope has
//! authenticated it: a buggy or newer writer is enough to produce bad bytes. It refuses
//! a newer schema rather than drop fields it does not know, rejects trailing bytes,
//! bounds every length and count while parsing, then re-runs every field rule and the
//! cross-checks (unique ids, known categories) before anything is returned.
//! [`VaultData::encode`] runs the same checks first, so Holm never writes a body that it
//! would refuse to open.

use crate::category::{
    BUILT_IN_CATEGORIES, Category, CategoryId, MAX_CATEGORIES, name_key, validate_category_name,
};
use crate::item::{Item, ItemId, PhraseRule, validate_item};
use crate::rules::MAX_ITEMS;
use crate::settings::Settings;
use crate::text::Text;
use crate::wire::{BodyIn, BodyOut, CategoryOut, ItemOut, SettingsWire};
use core::fmt;
use holm_crypto::SecretBuf;
use zeroize::Zeroizing;

/// The body schema this build writes and the only one it reads.
pub const BODY_SCHEMA_VERSION: u16 = 1;

/// Length of the schema version prefix in bytes.
const VERSION_LEN: usize = 2;

/// Why a body could not be decoded or encoded. No variant carries vault data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BodyError {
    /// Fewer than the 2 bytes of the schema version.
    #[error("the vault body is too short")]
    TooShort,
    /// The body was written by a newer Holm. It is refused, never rewritten, so its
    /// newer fields are not lost.
    #[error("this vault uses body schema {0}, which needs a newer version of Holm")]
    NewerSchema(u16),
    /// A schema version that no Holm has written.
    #[error("unknown vault body schema {0}")]
    UnknownSchema(u16),
    /// The bytes are not a well-formed body: a bad encoding, a length or count over its
    /// limit, or bytes left over at the end.
    #[error("the vault body is malformed")]
    Malformed,
    /// The body is well formed but breaks a rule: a field rule, a duplicate id, an
    /// unknown category, or a limit.
    #[error("the vault body contains invalid data")]
    Invalid,
    /// The body could not be encoded.
    #[error("the vault body could not be encoded")]
    Encode,
}

/// Everything inside the encrypted body. No `Clone`, and `Debug` prints counts only.
pub struct VaultData {
    pub(crate) settings: Settings,
    pub(crate) categories: Vec<Category>,
    pub(crate) items: Vec<Item>,
    pub(crate) next_category_id: u32,
}

impl fmt::Debug for VaultData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultData")
            .field("categories", &self.categories.len())
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
}

impl VaultData {
    /// The data of a new vault: default settings, the built-in categories with ids 1 to
    /// 3, and no items.
    #[must_use]
    pub fn new_default() -> VaultData {
        let categories: Vec<Category> = (1..)
            .zip(BUILT_IN_CATEGORIES)
            .map(|(id, name)| Category {
                id: CategoryId(id),
                name: Text::new(name.to_owned()),
            })
            .collect();
        VaultData {
            settings: Settings::default(),
            next_category_id: 4,
            categories,
            items: Vec::new(),
        }
    }

    /// Number of items, including trashed ones.
    #[must_use]
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Encodes the body: the schema version, then postcard.
    ///
    /// The data is checked first with the same rules [`VaultData::decode`] applies, so
    /// a body Holm writes is always one it can open again. The size is measured before
    /// anything is written, and the plaintext goes into one zeroed buffer of exactly
    /// that size, so it is never copied by a growing `Vec`.
    ///
    /// # Errors
    /// [`BodyError::Invalid`] if the data or the settings break a rule,
    /// [`BodyError::Encode`] if postcard fails.
    pub fn encode(&self) -> Result<SecretBuf, BodyError> {
        self.settings.validate().map_err(|_| BodyError::Invalid)?;
        self.check()?;
        self.encode_unchecked()
    }

    /// [`VaultData::encode`] without the checks. Tests use it to build bodies that
    /// the decoder must refuse.
    fn encode_unchecked(&self) -> Result<SecretBuf, BodyError> {
        let out = BodyOut {
            settings: SettingsWire::new(&self.settings),
            categories: self.categories.iter().map(CategoryOut::new).collect(),
            items: self.items.iter().map(ItemOut::new).collect(),
            next_category_id: self.next_category_id,
        };
        let size = postcard::serialize_with_flavor(&out, postcard::ser_flavors::Size::default())
            .map_err(|_| BodyError::Encode)?;
        let total = size.checked_add(VERSION_LEN).ok_or(BodyError::Encode)?;
        let mut buf = Zeroizing::new(vec![0u8; total]);
        let (version, rest) = buf.split_at_mut(VERSION_LEN);
        version.copy_from_slice(&BODY_SCHEMA_VERSION.to_le_bytes());
        let written = postcard::to_slice(&out, rest)
            .map_err(|_| BodyError::Encode)?
            .len();
        // Unreachable: the same value was just measured.
        if written != size {
            return Err(BodyError::Encode);
        }
        // Moves the Vec (pointer, length, capacity) into the SecretBuf: no copy.
        Ok(SecretBuf::from_vec(core::mem::take(&mut *buf)))
    }

    /// Decodes and checks a body.
    ///
    /// Order: [`BodyError::TooShort`] under 2 bytes; [`BodyError::NewerSchema`] for a
    /// version above [`BODY_SCHEMA_VERSION`]; [`BodyError::UnknownSchema`] for version
    /// 0; [`BodyError::Malformed`] if postcard fails, a length or count is over its cap,
    /// or bytes are left over; [`BodyError::Invalid`] if a field rule or cross-check
    /// fails. Out-of-range settings are then clamped into range, not refused, so a vault
    /// never becomes unopenable over a setting.
    ///
    /// # Errors
    /// As listed above.
    pub fn decode(plaintext: &[u8]) -> Result<VaultData, BodyError> {
        let (version, rest) = plaintext
            .split_first_chunk::<VERSION_LEN>()
            .ok_or(BodyError::TooShort)?;
        let version = u16::from_le_bytes(*version);
        if version > BODY_SCHEMA_VERSION {
            return Err(BodyError::NewerSchema(version));
        }
        if version != BODY_SCHEMA_VERSION {
            return Err(BodyError::UnknownSchema(version));
        }
        let (wire, leftover) =
            postcard::take_from_bytes::<BodyIn>(rest).map_err(|_| BodyError::Malformed)?;
        if !leftover.is_empty() {
            return Err(BodyError::Malformed);
        }
        // The conversions run every field rule; the cross-checks follow.
        let mut data = VaultData::from_wire(wire)?;
        data.check_structure()?;
        data.settings.clamp_to_policy();
        Ok(data)
    }

    /// Builds the domain values. Each conversion runs that value's field rules.
    fn from_wire(wire: BodyIn) -> Result<VaultData, BodyError> {
        let wire_categories = wire.categories.into_inner();
        let mut categories = Vec::with_capacity(wire_categories.len());
        for c in wire_categories {
            categories.push(c.into_category().map_err(|_| BodyError::Invalid)?);
        }
        let wire_items = wire.items.into_inner();
        let mut items = Vec::with_capacity(wire_items.len());
        for i in wire_items {
            items.push(i.into_item().map_err(|_| BodyError::Invalid)?);
        }
        Ok(VaultData {
            settings: wire.settings.into_settings(),
            categories,
            items,
            next_category_id: wire.next_category_id,
        })
    }

    /// Everything [`VaultData::decode`] checks, for encoding: every field rule, then
    /// the cross-checks.
    fn check(&self) -> Result<(), BodyError> {
        for c in &self.categories {
            validate_category_name(c.name()).map_err(|_| BodyError::Invalid)?;
        }
        for item in &self.items {
            validate_item(&item.title, &item.data, PhraseRule::Required)
                .map_err(|_| BodyError::Invalid)?;
        }
        self.check_structure()
    }

    /// The cross-checks: the limits, unique category ids and names, the next category
    /// id above every id in use, unique item ids, and every item's category exists.
    fn check_structure(&self) -> Result<(), BodyError> {
        if self.items.len() > MAX_ITEMS || self.categories.len() > MAX_CATEGORIES {
            return Err(BodyError::Invalid);
        }

        let mut ids: Vec<CategoryId> = self.categories.iter().map(|c| c.id).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return Err(BodyError::Invalid);
        }
        if ids.last().is_some_and(|max| max.0 >= self.next_category_id) {
            return Err(BodyError::Invalid);
        }
        let mut keys = Vec::with_capacity(self.categories.len());
        for c in &self.categories {
            keys.push(name_key(c.name()));
        }
        keys.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        if keys.windows(2).any(|w| w[0].as_str() == w[1].as_str()) {
            return Err(BodyError::Invalid);
        }

        let mut item_ids: Vec<ItemId> = self.items.iter().map(|i| i.id).collect();
        item_ids.sort_unstable();
        if item_ids.windows(2).any(|w| w[0] == w[1]) {
            return Err(BodyError::Invalid);
        }
        if self
            .items
            .iter()
            .filter_map(|i| i.category)
            .any(|c| ids.binary_search(&c).is_err())
        {
            return Err(BodyError::Invalid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::PasswordSpec;
    use crate::item::{ItemData, Timestamp};
    use crate::settings::{AUTO_LOCK_MAX_SECS, AUTO_LOCK_MIN_SECS, CLIPBOARD_MAX_SECS};
    use crate::text::{GatedSecret, SecretText};
    use static_assertions::assert_not_impl_any;
    use std::time::{Duration, Instant};

    assert_not_impl_any!(VaultData: Clone, serde::Serialize, serde::de::DeserializeOwned);

    fn t(s: &str) -> Text {
        Text::new(s.into())
    }
    fn st(s: &str) -> SecretText {
        SecretText::new(s.into())
    }
    fn item(n: u8, category: Option<u32>, data: ItemData) -> Item {
        Item {
            id: ItemId::from_hex(&format!("{n:02x}").repeat(16)).unwrap(),
            title: t("Exämple Mail ✉"),
            category: category.map(CategoryId),
            favourite: n.is_multiple_of(2),
            created: Timestamp(-5),
            updated: Timestamp(1_700_000_000),
            trashed: (n == 3).then_some(Timestamp(i64::MAX)),
            data,
        }
    }
    fn every_type() -> Vec<Item> {
        vec![
            item(
                1,
                Some(1),
                ItemData::Login {
                    username: t("ådå@example.com"),
                    password: st("EXAMPLE-pw-ünï"),
                    urls: (0..32)
                        .map(|i| t(&format!("https://example.com/{i}")))
                        .collect(),
                    notes: st(""),
                },
            ),
            item(
                2,
                None,
                ItemData::CryptoAddress {
                    chain: t("EXAMPLE-chain"),
                    address: st("EXAMPLE-addr"),
                    memo: st("mémo"),
                    notes: st("multi\nline"),
                },
            ),
            item(
                3,
                Some(3),
                ItemData::RecoveryPhrase {
                    phrase: GatedSecret::new(st(&"ä".repeat(2048))),
                    notes: st(""),
                },
            ),
            item(
                4,
                Some(2),
                ItemData::SecureNote {
                    body: st("Nötë body\n"),
                },
            ),
        ]
    }
    fn data_with(items: Vec<Item>) -> VaultData {
        let mut d = VaultData::new_default();
        d.items = items;
        d
    }
    fn bytes(d: &VaultData) -> Vec<u8> {
        d.encode().unwrap().expose().to_vec()
    }
    /// Encodes without the pre-encode checks, to build bodies the decoder must refuse.
    fn unchecked(d: &VaultData) -> Vec<u8> {
        d.encode_unchecked().unwrap().expose().to_vec()
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
    }

    #[test]
    fn default_data_exact() {
        let d = VaultData::new_default();
        assert_eq!(d.settings, Settings::default());
        let cats: Vec<(u32, &str)> = d.categories.iter().map(|c| (c.id.0, c.name())).collect();
        assert_eq!(cats, [(1, "Personal"), (2, "Work"), (3, "Community")]);
        assert_eq!(d.next_category_id, 4);
        assert!(d.items.is_empty());
        assert_eq!(d.item_count(), 0);
        assert_eq!(
            format!("{d:?}"),
            "VaultData { categories: 3, items: 0, .. }"
        );
    }

    #[test]
    fn roundtrip_every_item_type() {
        let d = data_with(every_type());
        let phrase_len = match &d.items[2].data {
            ItemData::RecoveryPhrase { phrase, .. } => phrase.expose().len(),
            _ => 0,
        };
        assert_eq!(phrase_len, 4096);
        let back = VaultData::decode(bytes(&d).as_slice()).unwrap();
        assert_eq!(back.settings, d.settings);
        assert_eq!(back.next_category_id, d.next_category_id);
        assert_eq!(back.categories.len(), d.categories.len());
        for (a, b) in back.categories.iter().zip(&d.categories) {
            assert_eq!((a.id, a.name()), (b.id, b.name()));
        }
        assert_eq!(back.item_count(), 4);
        for (a, b) in back.items.iter().zip(&d.items) {
            assert_items_eq(a, b);
        }
    }

    #[test]
    fn roundtrip_non_default_settings() {
        let mut d = VaultData::new_default();
        d.settings.auto_lock_secs = 3600;
        d.settings.clipboard_clear_secs = 5;
        d.settings.lock_on_sleep = false;
        d.settings.password.length = 64;
        d.settings.passphrase.separator = ' ';
        d.settings.username.digits = 0;
        let back = VaultData::decode(bytes(&d).as_slice()).unwrap();
        assert_eq!(back.settings, d.settings);
    }

    /// The schema v1 encoding of a new vault, byte for byte. If this test fails, the
    /// body format changed: existing vaults would no longer open, so the change needs a
    /// schema bump, not an edit here.
    #[test]
    fn default_body_golden() {
        #[rustfmt::skip]
        const GOLDEN: [u8; 51] = [
            1, 0,                         // schema version 1, little-endian
            172, 2, 30, 1,                // auto-lock 300 (varint), clipboard 30, lock on sleep
            20, 1, 1, 1, 1, 0, 1, 1,      // password: length 20, sets, no look-alike filter, minimums
            6, 1, 45, 0, 0,               // passphrase: 6 words, separator "-", flags
            2, 3,                         // username: 2 words, 3 digits
            3,                            // 3 categories
            1, 8, b'P', b'e', b'r', b's', b'o', b'n', b'a', b'l',
            2, 4, b'W', b'o', b'r', b'k',
            3, 9, b'C', b'o', b'm', b'm', b'u', b'n', b'i', b't', b'y',
            0,                            // no items
            4,                            // next category id
        ];
        assert_eq!(VaultData::new_default().encode().unwrap().expose(), GOLDEN);
        let back = VaultData::decode(&GOLDEN).unwrap();
        assert_eq!(back.settings, Settings::default());
        assert_eq!(back.next_category_id, 4);
        assert_eq!(back.categories.len(), 3);
    }

    #[test]
    fn encoded_starts_with_version() {
        let b = bytes(&VaultData::new_default());
        assert_eq!(b[..2], [1, 0]);
        assert_eq!(BODY_SCHEMA_VERSION.to_le_bytes(), [1, 0]);
    }

    #[test]
    fn empty_is_too_short() {
        assert_eq!(VaultData::decode(&[]).unwrap_err(), BodyError::TooShort);
        assert_eq!(VaultData::decode(&[1]).unwrap_err(), BodyError::TooShort);
    }

    #[test]
    fn newer_schema_refused() {
        let mut b = bytes(&VaultData::new_default());
        b[..2].copy_from_slice(&[2, 0]);
        assert_eq!(
            VaultData::decode(&b).unwrap_err(),
            BodyError::NewerSchema(2)
        );
        assert_eq!(
            VaultData::decode(&[0xff, 0xff]).unwrap_err(),
            BodyError::NewerSchema(u16::MAX)
        );
    }

    #[test]
    fn schema_zero_refused() {
        let mut b = bytes(&VaultData::new_default());
        b[..2].copy_from_slice(&[0, 0]);
        assert_eq!(
            VaultData::decode(&b).unwrap_err(),
            BodyError::UnknownSchema(0)
        );
    }

    #[test]
    fn version_only_is_malformed() {
        assert_eq!(
            VaultData::decode(&[1, 0]).unwrap_err(),
            BodyError::Malformed
        );
    }

    #[test]
    fn trailing_byte_malformed() {
        let mut b = bytes(&VaultData::new_default());
        assert!(VaultData::decode(&b).is_ok());
        b.push(0);
        assert_eq!(VaultData::decode(&b).unwrap_err(), BodyError::Malformed);
    }

    #[test]
    fn every_prefix_fails_without_panic() {
        let items = every_type();
        assert_eq!(items.len(), 4, "all four item types");
        let b = bytes(&data_with(items));
        for n in 0..b.len() {
            assert!(VaultData::decode(&b[..n]).is_err(), "prefix of {n} bytes");
        }
        assert!(VaultData::decode(&b).is_ok());
    }

    #[test]
    fn huge_length_prefix_no_alloc() {
        let settings = postcard::to_allocvec(&SettingsWire::new(&Settings::default())).unwrap();
        let count = postcard::to_allocvec(&(1u64 << 40)).unwrap();
        assert_eq!(count.len(), 6);
        let mut b = vec![1, 0];
        b.extend_from_slice(&settings);
        b.extend_from_slice(&count);
        b.resize(2 + settings.len() + 20, 0);
        let start = Instant::now();
        assert_eq!(VaultData::decode(&b).unwrap_err(), BodyError::Malformed);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn counts_over_the_cap_are_refused_while_parsing() {
        // A declared count one over each cap, followed by nothing: refused on the count.
        let settings = postcard::to_allocvec(&SettingsWire::new(&Settings::default())).unwrap();
        let mut b = vec![1, 0];
        b.extend_from_slice(&settings);
        b.extend_from_slice(&postcard::to_allocvec(&(MAX_CATEGORIES as u64 + 1)).unwrap());
        assert_eq!(VaultData::decode(&b).unwrap_err(), BodyError::Malformed);
        let mut b = vec![1, 0];
        b.extend_from_slice(&settings);
        b.push(0); // no categories
        b.extend_from_slice(&postcard::to_allocvec(&(MAX_ITEMS as u64 + 1)).unwrap());
        assert_eq!(VaultData::decode(&b).unwrap_err(), BodyError::Malformed);
    }

    #[test]
    fn duplicate_item_ids_invalid() {
        let mut items = every_type();
        items[1].id = items[0].id;
        let d = data_with(items);
        assert_eq!(d.encode().unwrap_err(), BodyError::Invalid);
        assert_eq!(
            VaultData::decode(&unchecked(&d)).unwrap_err(),
            BodyError::Invalid
        );
    }

    #[test]
    fn dangling_category_invalid() {
        let mut items = every_type();
        items[0].category = Some(CategoryId(9));
        let d = data_with(items);
        assert_eq!(d.encode().unwrap_err(), BodyError::Invalid);
        assert_eq!(
            VaultData::decode(&unchecked(&d)).unwrap_err(),
            BodyError::Invalid
        );
    }

    #[test]
    fn bidi_title_invalid() {
        let mut items = every_type();
        items[0].title = t("Mail\u{202E}lmth.exe");
        let d = data_with(items);
        assert_eq!(d.encode().unwrap_err(), BodyError::Invalid);
        assert_eq!(
            VaultData::decode(&unchecked(&d)).unwrap_err(),
            BodyError::Invalid
        );
    }

    #[test]
    fn empty_phrase_invalid() {
        let d = data_with(vec![item(
            7,
            None,
            ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(st("  ")),
                notes: st(""),
            },
        )]);
        assert_eq!(
            VaultData::decode(&unchecked(&d)).unwrap_err(),
            BodyError::Invalid
        );
    }

    #[test]
    fn bidi_category_name_invalid() {
        let mut d = VaultData::new_default();
        d.categories[1].name = t("Work\u{2066}");
        assert_eq!(d.encode().unwrap_err(), BodyError::Invalid);
        assert_eq!(
            VaultData::decode(&unchecked(&d)).unwrap_err(),
            BodyError::Invalid
        );
    }

    #[test]
    fn category_cross_checks_invalid() {
        let cases: [fn(&mut VaultData); 4] = [
            // duplicate id
            |d| d.categories[1].id = CategoryId(1),
            // duplicate name after trim, NFC and case folding
            |d| d.categories[1].name = t(" PERSONAL "),
            // next id not above every id
            |d| d.next_category_id = 3,
            // reserved name
            |d| d.categories[2].name = t("uncategorised"),
        ];
        for change in cases {
            let mut d = VaultData::new_default();
            change(&mut d);
            assert_eq!(d.encode().unwrap_err(), BodyError::Invalid);
            assert_eq!(
                VaultData::decode(&unchecked(&d)).unwrap_err(),
                BodyError::Invalid
            );
        }
    }

    #[test]
    fn out_of_range_settings_clamped() {
        let cases = [
            (0, 30, AUTO_LOCK_MIN_SECS, 30),
            (999_999, 30, AUTO_LOCK_MAX_SECS, 30),
            (300, 0, 300, 5),
            (300, 1000, 300, CLIPBOARD_MAX_SECS),
        ];
        for (auto, clip, want_auto, want_clip) in cases {
            let mut d = VaultData::new_default();
            d.settings.auto_lock_secs = auto;
            d.settings.clipboard_clear_secs = clip;
            assert_eq!(d.encode().unwrap_err(), BodyError::Invalid);
            let back = VaultData::decode(&unchecked(&d)).unwrap();
            assert_eq!(back.settings.auto_lock_secs, want_auto);
            assert_eq!(back.settings.clipboard_clear_secs, want_clip);
        }
        let mut d = VaultData::new_default();
        d.settings.password.length = 3;
        let back = VaultData::decode(&unchecked(&d)).unwrap();
        assert_eq!(back.settings.password, PasswordSpec::DEFAULT);
        assert_eq!(back.settings.validate(), Ok(()));
    }

    #[test]
    fn over_long_string_refused_while_parsing() {
        let d = data_with(vec![item(
            5,
            None,
            ItemData::SecureNote {
                body: st(&"x".repeat(crate::wire::MAX_WIRE_STR_BYTES + 1)),
            },
        )]);
        assert_eq!(
            VaultData::decode(&unchecked(&d)).unwrap_err(),
            BodyError::Malformed
        );
    }

    #[test]
    fn too_many_urls_refused() {
        let d = data_with(vec![item(
            6,
            None,
            ItemData::Login {
                username: t(""),
                password: st(""),
                urls: (0..33)
                    .map(|i| t(&format!("https://e.example/{i}")))
                    .collect(),
                notes: st(""),
            },
        )]);
        assert_eq!(d.encode().unwrap_err(), BodyError::Invalid);
        assert_eq!(
            VaultData::decode(&unchecked(&d)).unwrap_err(),
            BodyError::Malformed
        );
    }

    #[test]
    fn errors_name_no_data() {
        for e in [
            BodyError::TooShort,
            BodyError::NewerSchema(2),
            BodyError::UnknownSchema(0),
            BodyError::Malformed,
            BodyError::Invalid,
            BodyError::Encode,
        ] {
            let msg = e.to_string();
            assert!(!msg.is_empty());
            assert!(!msg.to_lowercase().contains("password"));
        }
    }

    /// Writes the fuzz seeds under `fuzz/seeds/`. Run by hand after a body or
    /// envelope change: `cargo test -p holm-core --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore = "writes files into fuzz/seeds"]
    fn write_fuzz_seeds() {
        use crate::fuzzing::seal_with_kek;
        use holm_crypto::SecretKey;
        use std::path::PathBuf;

        let seeds = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds");
        let default_body = bytes(&VaultData::new_default());
        let four_items = bytes(&data_with(every_type()));
        let settings = postcard::to_allocvec(&SettingsWire::new(&Settings::default())).unwrap();
        let mut huge_count = vec![1, 0];
        huge_count.extend_from_slice(&settings);
        huge_count.extend_from_slice(&postcard::to_allocvec(&(1u64 << 40)).unwrap());

        let decode = seeds.join("decode_body");
        std::fs::create_dir_all(&decode).unwrap();
        std::fs::write(decode.join("default"), &default_body).unwrap();
        std::fs::write(decode.join("four_items"), &four_items).unwrap();
        std::fs::write(decode.join("huge_count"), &huge_count).unwrap();

        // `open_fixed_key` takes an `arbitrary`-encoded `Input`: a 4-byte LE
        // variant selector (0 picks `RawFile`, u32::MAX picks `Sealed`), then
        // each `Vec<u8>` byte after a 1 ("one more"), ended by a 0.
        fn arb_bytes(out: &mut Vec<u8>, v: &[u8]) {
            for &b in v {
                out.extend_from_slice(&[1, b]);
            }
            out.push(0);
        }
        let kek = SecretKey::from_bytes(&mut [7; 32]);
        let open = seeds.join("open_fixed_key");
        std::fs::create_dir_all(&open).unwrap();
        for (name, body) in [("default", &default_body), ("four_items", &four_items)] {
            let file = seal_with_kek(&kek, body).unwrap();
            let mut raw = 0u32.to_le_bytes().to_vec();
            arb_bytes(&mut raw, &file);
            std::fs::write(open.join(format!("raw_{name}")), raw).unwrap();
            let mut sealed = u32::MAX.to_le_bytes().to_vec();
            arb_bytes(&mut sealed, body);
            arb_bytes(&mut sealed, &[]); // no edits
            std::fs::write(open.join(format!("sealed_{name}")), sealed).unwrap();
        }
    }

    /// Spec section 12: any valid body survives `decode(encode())` unchanged.
    mod props {
        use super::*;
        use crate::generator::{PassphraseSpec, UsernameSpec};
        use proptest::collection::vec;
        use proptest::option;
        use proptest::prelude::*;
        use proptest::sample::{self, Index};

        /// One-line display text: no controls or bidi, precomposed non-ASCII only.
        const LINE: &str = "[a-zA-Z0-9 ._@:/#äéñ✉日本-]{0,40}";
        /// Non-blank one-line display text.
        const TITLE: &str = "[a-zA-Zä✉][a-zA-Z0-9 ._@:/#äéñ✉日本-]{0,40}";
        /// One-line secret: anything but NUL, CR and LF, tabs and bidi included.
        const SECRET: &str = "[ -~äé\t\u{202E}]{0,40}";
        /// Non-blank one-line secret.
        const ADDRESS: &str = "[a-zA-Z0-9][ -~äé\t]{0,40}";
        /// Multi-line text.
        const MULTI: &str = "[a-zA-Z0-9 .äé✉\n\t\r\u{202E}-]{0,80}";
        /// Non-blank multi-line text.
        const PHRASE: &str = "[a-z][a-z \n]{0,60}";
        /// A canonical URL (Task 2): non-empty, no outer spaces, display rules.
        const URL: &str = "[a-z]([a-zA-Z0-9 ./:?=&%#äé-]{0,30}[a-z0-9/])?";

        fn item_data() -> impl Strategy<Value = ItemData> {
            prop_oneof![
                (LINE, SECRET, vec(URL, 0..=32), MULTI).prop_map(|(u, p, urls, n)| {
                    ItemData::Login {
                        username: t(&u),
                        password: st(&p),
                        urls: urls.iter().map(|s| t(s)).collect(),
                        notes: st(&n),
                    }
                }),
                (LINE, ADDRESS, SECRET, MULTI).prop_map(|(c, a, m, n)| {
                    ItemData::CryptoAddress {
                        chain: t(&c),
                        address: st(&a),
                        memo: st(&m),
                        notes: st(&n),
                    }
                }),
                (PHRASE, MULTI).prop_map(|(p, n)| ItemData::RecoveryPhrase {
                    phrase: GatedSecret::new(st(&p)),
                    notes: st(&n),
                }),
                MULTI.prop_map(|b| ItemData::SecureNote { body: st(&b) }),
            ]
        }

        /// An item with a placeholder id, its raw id bytes, and the index used to
        /// pick its category (`None` = uncategorised).
        fn item_parts() -> impl Strategy<Value = (Item, [u8; 16], Option<Index>)> {
            (
                any::<[u8; 16]>(),
                TITLE,
                option::of(any::<Index>()),
                any::<bool>(),
                any::<i64>(),
                any::<i64>(),
                option::of(any::<i64>()),
                item_data(),
            )
                .prop_map(
                    |(id, title, cat, favourite, created, updated, trashed, data)| {
                        let item = Item {
                            id: ItemId::from_hex(&"00".repeat(16)).unwrap(),
                            title: t(&title),
                            category: None,
                            favourite,
                            created: Timestamp(created),
                            updated: Timestamp(updated),
                            trashed: trashed.map(Timestamp),
                            data,
                        };
                        (item, id, cat)
                    },
                )
        }

        /// Generator specs that vary; any combination that fails `validate` falls back to
        /// the default, so every result is valid and the defaults still appear.
        fn specs() -> impl Strategy<Value = (PasswordSpec, PassphraseSpec, UsernameSpec)> {
            (
                (12u16..=128, any::<[bool; 5]>(), 0u8..=4, 0u8..=4),
                (
                    6u8..=20,
                    sample::select(vec![' ', '-', '.', '_']),
                    any::<bool>(),
                    any::<bool>(),
                ),
                (1u8..=3, 0u8..=6),
            )
                .prop_map(
                    |(
                        (length, f, min_digits, min_symbols),
                        (words, separator, capitalise, add_number),
                        (uw, ud),
                    )| {
                        let pw = PasswordSpec {
                            length,
                            lowercase: f[0],
                            uppercase: f[1],
                            digits: f[2],
                            symbols: f[3],
                            avoid_lookalikes: f[4],
                            min_digits,
                            min_symbols,
                        };
                        let pp = PassphraseSpec {
                            words,
                            separator,
                            capitalise,
                            add_number,
                        };
                        let un = UsernameSpec {
                            words: uw,
                            digits: ud,
                        };
                        (
                            if pw.validate().is_ok() {
                                pw
                            } else {
                                PasswordSpec::DEFAULT
                            },
                            if pp.validate().is_ok() {
                                pp
                            } else {
                                PassphraseSpec::DEFAULT
                            },
                            if un.validate().is_ok() {
                                un
                            } else {
                                UsernameSpec::DEFAULT
                            },
                        )
                    },
                )
        }

        fn vault() -> impl Strategy<Value = VaultData> {
            (
                vec("[a-zA-Zä✉][a-zA-Z0-9 äé✉]{0,20}", 0..4),
                0u32..1000,
                vec(item_parts(), 0..6),
                AUTO_LOCK_MIN_SECS..=AUTO_LOCK_MAX_SECS,
                crate::settings::CLIPBOARD_MIN_SECS..=CLIPBOARD_MAX_SECS,
                any::<bool>(),
                specs(),
            )
                .prop_map(|(names, gap, parts, auto_lock, clipboard, sleep, specs)| {
                    let mut d = VaultData::new_default();
                    for (i, name) in names.iter().enumerate() {
                        // The number keeps names unique and apart from the built-ins.
                        let id = d.next_category_id;
                        d.categories.push(Category {
                            id: CategoryId(id),
                            name: t(&format!("{i} {name}")),
                        });
                        d.next_category_id = id + 1;
                    }
                    d.next_category_id += gap;
                    for (n, (mut item, mut id, cat)) in parts.into_iter().enumerate() {
                        // Unique ids: the first byte is the item's position.
                        id[0] = u8::try_from(n).unwrap();
                        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
                        item.id = ItemId::from_hex(&hex).unwrap();
                        item.category = cat.map(|i| i.get(&d.categories).id);
                        d.items.push(item);
                    }
                    d.settings.auto_lock_secs = auto_lock;
                    d.settings.clipboard_clear_secs = clipboard;
                    d.settings.lock_on_sleep = sleep;
                    (
                        d.settings.password,
                        d.settings.passphrase,
                        d.settings.username,
                    ) = specs;
                    d
                })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]
            #[test]
            fn body_roundtrip_any(data in vault()) {
                let encoded = data.encode().expect("generated data is valid");
                let back = VaultData::decode(encoded.expose()).expect("decodes");
                prop_assert_eq!(&back.settings, &data.settings);
                prop_assert_eq!(back.next_category_id, data.next_category_id);
                prop_assert_eq!(back.categories.len(), data.categories.len());
                for (a, b) in back.categories.iter().zip(&data.categories) {
                    prop_assert_eq!(a.id, b.id);
                    prop_assert_eq!(a.name(), b.name());
                }
                prop_assert_eq!(back.items.len(), data.items.len());
                for (a, b) in back.items.iter().zip(&data.items) {
                    assert_items_eq(a, b);
                }
                // Encoding is deterministic: the same data gives the same bytes.
                let again = back.encode().expect("re-encodes");
                prop_assert_eq!(again.expose(), encoded.expose());
            }
        }
    }
}
