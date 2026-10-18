//! The rows of the item list: built once from the session's items, then owned by the
//! vault view, so a frame never walks the vault.

use core::cmp::Ordering;
use core::fmt;

use holm_core::item::{Item, ItemData, ItemId};
use holm_core::text::Text;

/// One line of the item list. The title and subtitle are zeroizing text.
pub struct ItemRow {
    /// Which item the row stands for.
    pub id: ItemId,
    /// The item's title.
    pub title: Text,
    /// The username, or else the first web address, or empty.
    pub subtitle: Text,
}

impl fmt::Debug for ItemRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemRow")
            .field("id", &self.id)
            .field("title_len", &self.title.as_str().len())
            .field("subtitle_len", &self.subtitle.as_str().len())
            .finish()
    }
}

/// Builds the rows for the logins among `items`, sorted by title (ignoring case), then
/// by id. Other item types are not listed yet.
#[must_use]
pub fn build_rows<'a>(items: impl Iterator<Item = &'a Item>) -> Vec<ItemRow> {
    let mut rows: Vec<ItemRow> = items
        .filter_map(|item| {
            let ItemData::Login { username, urls, .. } = item.data() else {
                return None;
            };
            let subtitle = if !username.is_empty() {
                username.as_str()
            } else {
                urls.first().map_or("", Text::as_str)
            };
            Some(ItemRow {
                id: item.id(),
                title: Text::new(item.title().to_owned()),
                subtitle: Text::new(subtitle.to_owned()),
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        cmp_ignoring_case(a.title.as_str(), b.title.as_str()).then_with(|| a.id.cmp(&b.id))
    });
    rows
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
    use holm_core::item::ItemInput;
    use holm_core::session::Session;
    use holm_core::text::SecretText;
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
        build_rows(session.active_items().unwrap())
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

    #[test]
    fn row_debug_has_no_text() {
        let rows = rows_for(vec![input("Example Mail", "ada@example.com", &[])]);
        let shown = format!("{:?}", rows[0]);
        assert!(!shown.contains("Example Mail"));
        assert!(!shown.contains("ada@example.com"));
    }
}
