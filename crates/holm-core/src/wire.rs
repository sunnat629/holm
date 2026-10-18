//! Crate-private wire types for the vault body.
//!
//! The public item types have no `Serialize` or `Deserialize`, so no code outside this
//! crate can turn a secret into bytes or build one from bytes. The body codec (a later
//! task) goes through the types here. Output types borrow from the domain value. Input
//! types hold wiping strings, and every conversion back to a domain value re-runs the
//! field rules, so a stored vault cannot smuggle in a value the rules refuse.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "first used by the vault body codec")
)]

use crate::category::{Category, CategoryId, validate_category_name};
use crate::item::{Item, ItemData, ItemId, PhraseRule, Timestamp, validate_item};
use crate::rules::FieldError;
use crate::text::{GatedSecret, SecretText, Text};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

/// A string that wipes itself, for decoding.
struct WireStr(Zeroizing<String>);

impl<'de> Deserialize<'de> for WireStr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<WireStr, D::Error> {
        String::deserialize(d).map(|s| WireStr(Zeroizing::new(s)))
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
        }
    }
}

/// An item as read. Nothing here is trusted until [`ItemIn::into_item`] returns `Ok`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ItemIn {
    id: ItemId,
    title: WireStr,
    category: Option<CategoryId>,
    favourite: bool,
    created: Timestamp,
    updated: Timestamp,
    trashed: Option<Timestamp>,
    data: DataIn,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum DataIn {
    Login {
        username: WireStr,
        password: WireStr,
        urls: Vec<WireStr>,
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
                urls: urls.into_iter().map(WireStr::text).collect(),
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
        })
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
#[serde(deny_unknown_fields)]
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
