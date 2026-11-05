//! Search, filter and sort over the public fields of items.
//!
//! Only public fields are ever matched: title, a login's username and URLs,
//! a crypto item's chain, the category name, and custom field labels.
//! Secret fields (passwords, notes, addresses, memos, phrases, note bodies,
//! and custom secrets) are never read here. Custom text values and date
//! values are not matched either.

use std::cmp::Ordering;
use std::fmt;

use zeroize::Zeroizing;

use crate::category::CategoryId;
use crate::error::CoreError;
use crate::fields::{CalendarDate, from_unix_secs, is_expiring, soonest_expiry};
use crate::item::{Item, ItemData, ItemId, ItemType, Timestamp};
use crate::rules::EXPIRING_WITHIN_DAYS;
use crate::session::Session;
use crate::store::VaultStore;
use crate::text::fold;

/// Which category an item must belong to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CategoryFilter {
    /// Any category, or none.
    #[default]
    All,
    /// Items without a category.
    Uncategorised,
    /// Items in exactly this category.
    Only(CategoryId),
}

/// Which items to list: live ones or the trash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum View {
    /// Items that are not trashed.
    #[default]
    Active,
    /// Trashed items only.
    Trash,
}

/// Result ordering. Ties always break by item id.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sort {
    /// Case-insensitive title, ascending.
    #[default]
    TitleAsc,
    /// Most recently updated first.
    UpdatedDesc,
    /// Most recently created first.
    CreatedDesc,
}

/// A search request.
#[derive(Clone, Default)]
pub struct Query {
    /// Typed search text. Empty (after trimming) matches every item.
    pub text: Zeroizing<String>,
    /// Restrict to one item type.
    pub item_type: Option<ItemType>,
    /// Category restriction.
    pub category: CategoryFilter,
    /// Only favourites.
    pub favourites_only: bool,
    /// Active items or trash.
    pub view: View,
    /// Result ordering.
    pub sort: Sort,
    /// Keep only items whose soonest reminder falls inside the expiring window.
    pub expiring_only: bool,
}

impl fmt::Debug for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Query")
            .field("text_len", &self.text.len())
            .field("item_type", &self.item_type)
            .field("category", &self.category)
            .field("favourites_only", &self.favourites_only)
            .field("view", &self.view)
            .field("sort", &self.sort)
            .field("expiring_only", &self.expiring_only)
            .finish()
    }
}

/// A borrowed, display-ready view of one item. Holds no secrets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ItemSummary<'a> {
    /// Item id.
    pub id: ItemId,
    /// Item type.
    pub item_type: ItemType,
    /// Title, borrowed from the session.
    pub title: &'a str,
    /// Username, first URL or chain, when the type has one.
    pub subtitle: Option<&'a str>,
    /// Favourite flag.
    pub favourite: bool,
    /// Category, if any.
    pub category: Option<CategoryId>,
    /// Creation time.
    pub created: Timestamp,
    /// Last update time.
    pub updated: Timestamp,
    /// When it was trashed, if it was.
    pub trashed: Option<Timestamp>,
    /// Soonest custom-field reminder. Absent when no field has one.
    pub soonest_expiry: Option<CalendarDate>,
}

impl fmt::Debug for ItemSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemSummary")
            .field("id", &self.id)
            .field("item_type", &self.item_type)
            .field("title_len", &self.title.len())
            .field("subtitle_len", &self.subtitle.map(str::len))
            .field("favourite", &self.favourite)
            .field("category", &self.category)
            .field("created", &self.created)
            .field("updated", &self.updated)
            .field("trashed", &self.trashed)
            .field("soonest_expiry", &self.soonest_expiry)
            .finish()
    }
}

/// Folded title order, then id. Shared with other listings.
pub(crate) fn cmp_title_asc(a: &Item, b: &Item) -> Ordering {
    let (ta, tb) = (fold(a.title()), fold(b.title()));
    ta.as_str()
        .cmp(tb.as_str())
        .then_with(|| a.id().cmp(&b.id()))
}

fn subtitle(item: &Item) -> Option<&str> {
    match item.data() {
        ItemData::Login { username, urls, .. } => {
            if username.is_empty() {
                urls.first().map(|u| u.as_str())
            } else {
                Some(username.as_str())
            }
        }
        ItemData::CryptoAddress { chain, .. } => Some(chain.as_str()),
        _ => None,
    }
}

fn contains(needle: &str, field: &str) -> bool {
    fold(field).contains(needle)
}

fn text_matches(needle: &str, item: &Item, category_name: Option<&str>) -> bool {
    if contains(needle, item.title()) {
        return true;
    }
    if category_name.is_some_and(|n| contains(needle, n)) {
        return true;
    }
    // Labels only. This does not call `CustomField::value` or `SecretText::expose`.
    if item
        .fields()
        .iter()
        .any(|field| contains(needle, field.label()))
    {
        return true;
    }
    match item.data() {
        ItemData::Login { username, urls, .. } => {
            contains(needle, username.as_str()) || urls.iter().any(|u| contains(needle, u.as_str()))
        }
        ItemData::CryptoAddress { chain, .. } => contains(needle, chain.as_str()),
        _ => false,
    }
}

impl<S: VaultStore> Session<S> {
    /// Lists items matching `query`, filtered and sorted.
    ///
    /// Reads titles, usernames, URLs, chains, category names and custom field
    /// labels. It does not read passwords, notes, phrases, custom secrets,
    /// custom text values or date values.
    ///
    /// `expiring_only` keeps items whose soonest reminder is within
    /// [`EXPIRING_WITHIN_DAYS`] of the session clock's UTC date, including
    /// reminders that are already past. A clock outside years 1 through 9999
    /// matches nothing while that flag is set. Today is computed once, here.
    pub fn search(&self, query: &Query) -> Result<Vec<ItemSummary<'_>>, CoreError> {
        let data = &self.unlocked()?.data;
        let today = from_unix_secs(self.now_unix().0);
        let needle = fold(query.text.trim());
        let mut hits: Vec<&Item> = data
            .items
            .iter()
            .filter(|i| match query.view {
                View::Active => i.trashed().is_none(),
                View::Trash => i.trashed().is_some(),
            })
            .filter(|i| query.item_type.is_none_or(|t| i.item_type() == t))
            .filter(|i| !query.favourites_only || i.favourite())
            .filter(|i| match query.category {
                CategoryFilter::All => true,
                CategoryFilter::Uncategorised => i.category().is_none(),
                CategoryFilter::Only(c) => i.category() == Some(c),
            })
            .filter(|i| {
                if needle.is_empty() {
                    return true;
                }
                let name = i
                    .category()
                    .and_then(|c| data.categories.iter().find(|k| k.id() == c))
                    .map(|k| k.name());
                text_matches(&needle, i, name)
            })
            .filter(|i| {
                if query.expiring_only {
                    today.is_some_and(|day| is_expiring(i.fields(), day, EXPIRING_WITHIN_DAYS))
                } else {
                    true
                }
            })
            .collect();
        match query.sort {
            Sort::TitleAsc => hits.sort_by(|a, b| cmp_title_asc(a, b)),
            Sort::UpdatedDesc => hits.sort_by(|a, b| {
                b.updated()
                    .cmp(&a.updated())
                    .then_with(|| a.id().cmp(&b.id()))
            }),
            Sort::CreatedDesc => hits.sort_by(|a, b| {
                b.created()
                    .cmp(&a.created())
                    .then_with(|| a.id().cmp(&b.id()))
            }),
        }
        Ok(hits
            .into_iter()
            .map(|i| ItemSummary {
                id: i.id(),
                item_type: i.item_type(),
                title: i.title(),
                subtitle: subtitle(i),
                favourite: i.favourite(),
                category: i.category(),
                created: i.created(),
                updated: i.updated(),
                trashed: i.trashed(),
                soonest_expiry: soonest_expiry(i.fields()),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::CategoryId;
    use crate::clock::FakeClock;
    use crate::fields::{FieldValue, epoch_day, try_field};
    use crate::item::{ItemData, ItemId, ItemInput};
    use crate::store::MemStore;
    use crate::text::{GatedSecret, SecretText, Text};
    use holm_crypto::MasterPassword;
    use holm_crypto::kdf::KdfParams;

    const PW: &str = "correct-Horse-battery-staple-EXAMPLE-9";

    fn t(s: &str) -> Text {
        Text::new(s.to_owned())
    }

    fn st(s: &str) -> SecretText {
        SecretText::new(s.to_owned())
    }

    fn fresh() -> (Session<MemStore>, FakeClock) {
        let clock = FakeClock::default();
        clock.set_unix(1_700_000_000);
        let mut s = Session::new(MemStore::default(), Box::new(clock.clone()));
        s.create(&MasterPassword::new(PW.to_owned()), &KdfParams::FLOOR)
            .unwrap();
        (s, clock)
    }

    fn login(title: &str, user: &str, urls: &[&str]) -> ItemInput {
        ItemInput {
            fields: Vec::new(),
            title: t(title),
            category: None,
            favourite: false,
            data: ItemData::Login {
                username: t(user),
                password: st("pw-zebra"),
                urls: urls.iter().map(|u| t(u)).collect(),
                notes: st("notes-zebra"),
            },
        }
    }

    fn crypto(title: &str, chain: &str) -> ItemInput {
        ItemInput {
            fields: Vec::new(),
            title: t(title),
            category: None,
            favourite: false,
            data: ItemData::CryptoAddress {
                chain: t(chain),
                address: st("addr-zebra"),
                memo: st("memo-zebra"),
                notes: st("cn-zebra"),
            },
        }
    }

    fn note(title: &str) -> ItemInput {
        ItemInput {
            fields: Vec::new(),
            title: t(title),
            category: None,
            favourite: false,
            data: ItemData::SecureNote {
                body: st("body-zebra"),
            },
        }
    }

    fn phrase(title: &str) -> ItemInput {
        ItemInput {
            fields: Vec::new(),
            title: t(title),
            category: None,
            favourite: false,
            data: ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(st("phrase-zebra words")),
                notes: st("pn-zebra"),
            },
        }
    }

    fn q(text: &str) -> Query {
        Query {
            text: Zeroizing::new(text.to_owned()),
            ..Query::default()
        }
    }

    fn titles(s: &Session<MemStore>, query: &Query) -> Vec<String> {
        s.search(query)
            .unwrap()
            .iter()
            .map(|i| i.title.to_owned())
            .collect()
    }

    #[test]
    fn matches_each_public_field() {
        let (mut s, _) = fresh();
        let cat = s.add_category("Gadgets").unwrap();
        let mut a = login(
            "Alpha",
            "ada-user",
            &["https://one.example", "https://two.example"],
        );
        a.category = Some(cat);
        s.add_item(a).unwrap();
        s.add_item(crypto("Beta", "chain-x")).unwrap();
        assert_eq!(titles(&s, &q("alph")), ["Alpha"]);
        assert_eq!(titles(&s, &q("ada-us")), ["Alpha"]);
        assert_eq!(titles(&s, &q("one.exam")), ["Alpha"]);
        assert_eq!(titles(&s, &q("two.exam")), ["Alpha"]);
        assert_eq!(titles(&s, &q("chain-")), ["Beta"]);
        assert_eq!(titles(&s, &q("gadget")), ["Alpha"]);
        assert!(titles(&s, &q("nomatch")).is_empty());
    }

    #[test]
    fn never_matches_secret_fields() {
        let (mut s, _) = fresh();
        s.add_item(login("L", "u", &[])).unwrap();
        s.add_item(crypto("C", "ch")).unwrap();
        s.add_item(phrase("P")).unwrap();
        s.add_item(note("N")).unwrap();
        assert!(s.search(&q("zebra")).unwrap().is_empty());
    }

    #[test]
    fn case_and_composition_insensitive() {
        let (mut s, _) = fresh();
        s.add_item(login("Caf\u{e9} Login", "u", &[])).unwrap();
        assert_eq!(titles(&s, &q("cafe\u{301}")), ["Caf\u{e9} Login"]);
        assert_eq!(titles(&s, &q("CAF\u{c9}")), ["Caf\u{e9} Login"]);
    }

    #[test]
    fn empty_query_lists_active_only() {
        let (mut s, _) = fresh();
        s.add_item(note("A")).unwrap();
        let b = s.add_item(note("B")).unwrap();
        s.add_item(note("C")).unwrap();
        s.trash(b).unwrap();
        assert_eq!(titles(&s, &q("")), ["A", "C"]);
        assert_eq!(titles(&s, &q("   ")), ["A", "C"]);
    }

    #[test]
    fn trash_view_lists_trashed_only() {
        let (mut s, _) = fresh();
        s.add_item(note("A")).unwrap();
        let b = s.add_item(note("B")).unwrap();
        s.trash(b).unwrap();
        let query = Query {
            view: View::Trash,
            ..Query::default()
        };
        let found = s.search(&query).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].title, "B");
        assert!(found[0].trashed.is_some());
    }

    #[test]
    fn filters_combine() {
        let (mut s, _) = fresh();
        let cat = s.add_category("Hobbies").unwrap();
        let mut a = login("A", "u", &[]);
        a.favourite = true;
        s.add_item(a).unwrap();
        let mut b = login("B", "u", &[]);
        b.favourite = true;
        b.category = Some(cat);
        s.add_item(b).unwrap();
        s.add_item(login("C", "u", &[])).unwrap();
        let mut d = note("D");
        d.favourite = true;
        s.add_item(d).unwrap();
        let query = Query {
            item_type: Some(ItemType::Login),
            favourites_only: true,
            category: CategoryFilter::Uncategorised,
            ..Query::default()
        };
        assert_eq!(titles(&s, &query), ["A"]);
        let only = Query {
            category: CategoryFilter::Only(cat),
            ..Query::default()
        };
        assert_eq!(titles(&s, &only), ["B"]);
        let other = Query {
            category: CategoryFilter::Only(CategoryId(9999)),
            ..Query::default()
        };
        assert!(titles(&s, &other).is_empty());
    }

    #[test]
    fn sort_orders_with_id_ties() {
        let (mut s, clock) = fresh();
        clock.set_unix(1_700_000_100);
        s.add_item(note("bravo")).unwrap();
        clock.set_unix(1_700_000_200);
        let a = s.add_item(note("Alpha")).unwrap();
        clock.set_unix(1_700_000_300);
        s.add_item(note("charlie")).unwrap();
        assert_eq!(titles(&s, &q("")), ["Alpha", "bravo", "charlie"]);
        clock.set_unix(1_700_000_400);
        s.update_item(a, note("Alpha")).unwrap();
        let by = |sort| Query {
            sort,
            ..Query::default()
        };
        assert_eq!(
            titles(&s, &by(Sort::UpdatedDesc)),
            ["Alpha", "charlie", "bravo"]
        );
        assert_eq!(
            titles(&s, &by(Sort::CreatedDesc)),
            ["charlie", "Alpha", "bravo"]
        );
        // Equal titles and timestamps fall back to id order.
        let (mut s2, _) = fresh();
        for _ in 0..4 {
            s2.add_item(note("same")).unwrap();
        }
        for sort in [Sort::TitleAsc, Sort::UpdatedDesc, Sort::CreatedDesc] {
            let ids: Vec<ItemId> = s2.search(&by(sort)).unwrap().iter().map(|i| i.id).collect();
            let mut sorted = ids.clone();
            sorted.sort();
            assert_eq!(ids, sorted);
        }
    }

    #[test]
    fn subtitle_rules() {
        let (mut s, _) = fresh();
        s.add_item(login("A", "ada", &["https://u.example"]))
            .unwrap();
        s.add_item(login(
            "B",
            "",
            &["https://first.example", "https://second.example"],
        ))
        .unwrap();
        s.add_item(login("C", "", &[])).unwrap();
        s.add_item(crypto("D", "chain-x")).unwrap();
        s.add_item(note("E")).unwrap();
        s.add_item(phrase("F")).unwrap();
        let subs: Vec<Option<String>> = s
            .search(&q(""))
            .unwrap()
            .iter()
            .map(|i| i.subtitle.map(str::to_owned))
            .collect();
        assert_eq!(
            subs,
            [
                Some("ada".to_owned()),
                Some("https://first.example".to_owned()),
                None,
                Some("chain-x".to_owned()),
                None,
                None
            ]
        );
    }

    #[test]
    fn summary_and_query_debug_have_no_text() {
        let (mut s, _) = fresh();
        s.add_item(login("Example Mail", "ada@example.com", &[]))
            .unwrap();
        let query = q("secretquery");
        let found = s.search(&q("example")).unwrap();
        let shown = format!("{:?} {:?}", found, query);
        for needle in ["Example Mail", "ada@example.com", "secretquery"] {
            assert!(!shown.contains(needle), "{needle} leaked: {shown}");
        }
        assert!(shown.contains("11"), "query length shown: {shown}");
    }

    #[test]
    fn query_text_with_controls_matches_nothing_and_does_not_panic() {
        let (mut s, _) = fresh();
        s.add_item(note("A")).unwrap();
        assert!(s.search(&q("\u{202E}\u{0}")).unwrap().is_empty());
        assert!(s.search(&q(&"x".repeat(5_000))).unwrap().is_empty());
    }

    #[test]
    fn query_debug_never_shows_the_search_text() {
        let query = q("EXAMPLE-needle");
        let shown = format!("{query:?}");
        assert!(!shown.contains("needle"), "{shown}");
        assert!(shown.contains("text_len: 14"), "{shown}");
        assert!(shown.contains("expiring_only: false"), "{shown}");
    }

    #[test]
    fn search_when_locked_is_locked() {
        let (mut s, _) = fresh();
        s.lock();
        assert!(matches!(
            s.search(&Query::default()),
            Err(CoreError::Locked)
        ));
    }

    fn custom(label: &str, value: FieldValue) -> ItemInput {
        let mut item = note("Kept");
        item.fields = vec![try_field(t(label), value, None).unwrap()];
        item
    }

    #[test]
    fn search_matches_label_not_secret() {
        let (mut s, _) = fresh();
        s.add_item(custom(
            "recovery-email",
            FieldValue::Secret(st("EXAMPLE-field-secret")),
        ))
        .unwrap();
        assert_eq!(titles(&s, &q("recovery-email")), ["Kept"]);
        assert!(titles(&s, &q("EXAMPLE-field-secret")).is_empty());
    }

    #[test]
    fn search_skips_text_value() {
        let (mut s, _) = fresh();
        s.add_item(custom(
            "shown-label",
            FieldValue::Text(t("public-note-EXAMPLE")),
        ))
        .unwrap();
        assert!(titles(&s, &q("public-note-EXAMPLE")).is_empty());
        assert_eq!(titles(&s, &q("shown-label")), ["Kept"]);
    }

    #[test]
    fn search_still_skips_password() {
        let (mut s, _) = fresh();
        s.add_item(login("L", "u", &[])).unwrap();
        s.add_item(crypto("C", "ch")).unwrap();
        s.add_item(phrase("P")).unwrap();
        s.add_item(note("N")).unwrap();
        assert!(s.search(&q("zebra")).unwrap().is_empty());
        assert!(titles(&s, &q("pw-zebra")).is_empty());
    }

    #[test]
    fn expiring_uses_injected_clock() {
        let (mut s, clock) = fresh();
        let start = 1_700_000_000;
        clock.set_unix(start);
        let today = from_unix_secs(start).unwrap();
        let outside = i64::from(EXPIRING_WITHIN_DAYS) + 1;
        let expiry = from_unix_secs((i64::from(epoch_day(today)) + outside) * 86_400).unwrap();
        let mut item = note("Due");
        item.fields = vec![try_field(t("remind"), FieldValue::Text(t("")), Some(expiry)).unwrap()];
        s.add_item(item).unwrap();
        let expiring = Query {
            expiring_only: true,
            ..Query::default()
        };
        assert!(titles(&s, &expiring).is_empty());
        assert_eq!(
            s.search(&Query::default()).unwrap()[0].soonest_expiry,
            Some(expiry)
        );
        clock.set_unix(start + 86_400);
        assert_eq!(titles(&s, &expiring), ["Due"]);
    }
}
