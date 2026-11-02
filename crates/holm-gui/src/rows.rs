//! The rows of the item list: built once from the session's items, then owned by the
//! vault view, so a frame never walks the vault.

use core::cmp::Ordering;
use core::fmt;

use holm_core::category::Category;
use holm_core::item::{ItemId, ItemType};
use holm_core::search::ItemSummary;
use holm_core::text::Text;

/// The subtitle of a crypto address with no chain name.
pub const CRYPTO_SUBTITLE: &str = "Crypto address";
/// The subtitle of every recovery phrase.
pub const PHRASE_SUBTITLE: &str = "Recovery phrase";
/// The subtitle of every secure note.
pub const NOTE_SUBTITLE: &str = "Secure note";

/// One line of the item list. The title and subtitle are zeroizing text.
pub struct ItemRow {
    /// Which item the row stands for.
    pub id: ItemId,
    /// What kind of item it is.
    pub kind: ItemType,
    /// The item's title.
    pub title: Text,
    /// See [`subtitle`]: never a secret.
    pub subtitle: Text,
    /// The name of the item's category, if it has one. Never a secret.
    pub category: Option<Text>,
    /// The category's index in the session's category list, which picks the avatar
    /// colour. `None` when the item has no category.
    pub category_slot: Option<usize>,
}

impl fmt::Debug for ItemRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemRow")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("title_len", &self.title.as_str().len())
            .field("subtitle_len", &self.subtitle.as_str().len())
            .field(
                "category_len",
                &self.category.as_ref().map(|c| c.as_str().len()),
            )
            .field("category_slot", &self.category_slot)
            .finish()
    }
}

/// Builds the rows for every item in `summaries` (from `Session::search`), sorted by
/// title (ignoring case), then by id. `categories` gives the names for the badges.
#[must_use]
pub fn build_rows(summaries: &[ItemSummary<'_>], categories: &[Category]) -> Vec<ItemRow> {
    let mut rows: Vec<ItemRow> = summaries
        .iter()
        .map(|s| {
            let slot = s
                .category
                .and_then(|id| categories.iter().position(|c| c.id() == id));
            ItemRow {
                id: s.id,
                kind: s.item_type,
                title: Text::new(s.title.to_owned()),
                subtitle: Text::new(subtitle(s).to_owned()),
                category: slot
                    .and_then(|i| categories.get(i))
                    .map(|c| Text::new(c.name().to_owned())),
                category_slot: slot,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        cmp_ignoring_case(a.title.as_str(), b.title.as_str()).then_with(|| a.id.cmp(&b.id))
    });
    rows
}

/// The line under a row's title, by type: a login's username (else its first web
/// address, else nothing), a crypto address's chain (else [`CRYPTO_SUBTITLE`]), and a
/// fixed word for a phrase or a note. Never a secret field.
fn subtitle<'a>(s: &ItemSummary<'a>) -> &'a str {
    match s.item_type {
        ItemType::Login => s.subtitle.unwrap_or(""),
        ItemType::CryptoAddress => s
            .subtitle
            .filter(|c| !c.is_empty())
            .unwrap_or(CRYPTO_SUBTITLE),
        ItemType::RecoveryPhrase => PHRASE_SUBTITLE,
        ItemType::SecureNote => NOTE_SUBTITLE,
    }
}

/// Compares two strings char by char on their lowercase forms, without allocating.
fn cmp_ignoring_case(a: &str, b: &str) -> Ordering {
    a.chars()
        .flat_map(char::to_lowercase)
        .cmp(b.chars().flat_map(char::to_lowercase))
}

#[cfg(test)]
mod tests {
    use super::*;
    use holm_core::clock::SystemClock;
    use holm_core::item::{ItemData, ItemInput};
    use holm_core::search::Query;
    use holm_core::session::Session;
    use holm_core::text::{GatedSecret, SecretText};
    use holm_crypto::MasterPassword;
    use holm_crypto::kdf::KdfParams;
    use holm_platform::fs_store::FsStore;

    fn input(title: &str, username: &str, urls: &[&str]) -> ItemInput {
        ItemInput {
            title: Text::new(title.to_owned()),
            category: None,
            favourite: false,
            data: ItemData::Login {
                username: Text::new(username.to_owned()),
                password: SecretText::new("EXAMPLE-pass".to_owned()),
                urls: urls.iter().map(|u| Text::new((*u).to_owned())).collect(),
                notes: SecretText::new(String::new()),
            },
        }
    }

    fn rows_for(inputs: Vec<ItemInput>) -> Vec<ItemRow> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Holm").join("holm.vault");
        holm_platform::paths::ensure_vault_dir(&path).unwrap();
        let mut session = Session::new(FsStore::new(path), Box::new(SystemClock::new()));
        let password = MasterPassword::new("correct-Horse-battery-staple-EXAMPLE-9".to_owned());
        session.create(&password, &KdfParams::FLOOR).unwrap();
        for i in inputs {
            session.add_item(i).unwrap();
        }
        build_rows(
            &session.search(&Query::default()).unwrap(),
            session.categories().unwrap(),
        )
    }

    #[test]
    fn row_carries_the_category_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Holm").join("holm.vault");
        holm_platform::paths::ensure_vault_dir(&path).unwrap();
        let mut session = Session::new(FsStore::new(path), Box::new(SystemClock::new()));
        let password = MasterPassword::new("correct-Horse-battery-staple-EXAMPLE-9".to_owned());
        session.create(&password, &KdfParams::FLOOR).unwrap();
        let work = session.add_category("Projects").unwrap();
        let mut a = input("a", "", &[]);
        a.category = Some(work);
        session.add_item(a).unwrap();
        session.add_item(input("b", "", &[])).unwrap();
        let rows = build_rows(
            &session.search(&Query::default()).unwrap(),
            session.categories().unwrap(),
        );
        assert_eq!(
            rows[0].category.as_ref().map(Text::as_str),
            Some("Projects")
        );
        assert!(rows[1].category.is_none());
        // Projects follows the built-in Personal, Work and Community.
        assert_eq!(rows[0].category_slot, Some(3));
        assert_eq!(rows[1].category_slot, None);
    }

    #[test]
    fn rows_sorted_case_insensitive_then_id() {
        let rows = rows_for(vec![
            input("banana", "", &[]),
            input("Apple", "", &[]),
            input("apple", "", &[]),
        ]);
        let titles: Vec<String> = rows
            .iter()
            .map(|r| r.title.as_str().to_lowercase())
            .collect();
        assert_eq!(titles, ["apple", "apple", "banana"]);
        assert!(rows[0].id < rows[1].id);
    }

    #[test]
    fn subtitle_rules() {
        let rows = rows_for(vec![
            input("a", "ada", &["https://x.example.com"]),
            input("b", "", &["https://y.example.com"]),
            input("c", "", &[]),
        ]);
        assert_eq!(rows[0].subtitle.as_str(), "ada");
        assert_eq!(rows[1].subtitle.as_str(), "https://y.example.com");
        assert_eq!(rows[2].subtitle.as_str(), "");
    }

    fn other(title: &str, data: ItemData) -> ItemInput {
        ItemInput {
            title: Text::new(title.to_owned()),
            category: None,
            favourite: false,
            data,
        }
    }

    fn crypto(title: &str, chain: &str) -> ItemInput {
        other(
            title,
            ItemData::CryptoAddress {
                chain: Text::new(chain.to_owned()),
                address: SecretText::new("EXAMPLE-addr".to_owned()),
                memo: SecretText::new(String::new()),
                notes: SecretText::new(String::new()),
            },
        )
    }

    #[test]
    fn every_type_is_listed_with_its_subtitle() {
        let rows = rows_for(vec![
            input("a", "ada", &[]),
            crypto("b", "Test chain"),
            crypto("c", ""),
            other(
                "d",
                ItemData::RecoveryPhrase {
                    phrase: GatedSecret::new(SecretText::new("EXAMPLE words".to_owned())),
                    notes: SecretText::new(String::new()),
                },
            ),
            other(
                "e",
                ItemData::SecureNote {
                    body: SecretText::new("EXAMPLE body".to_owned()),
                },
            ),
        ]);
        let got: Vec<(ItemType, &str)> =
            rows.iter().map(|r| (r.kind, r.subtitle.as_str())).collect();
        assert_eq!(
            got,
            [
                (ItemType::Login, "ada"),
                (ItemType::CryptoAddress, "Test chain"),
                (ItemType::CryptoAddress, CRYPTO_SUBTITLE),
                (ItemType::RecoveryPhrase, PHRASE_SUBTITLE),
                (ItemType::SecureNote, NOTE_SUBTITLE),
            ]
        );
    }

    #[test]
    fn row_debug_has_no_text() {
        let rows = rows_for(vec![input("Example Mail", "ada@example.com", &[])]);
        let shown = format!("{:?}", rows[0]);
        assert!(!shown.contains("Example Mail"));
        assert!(!shown.contains("ada@example.com"));
    }
}
