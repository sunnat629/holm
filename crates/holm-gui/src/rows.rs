//! The rows of the item list: built once from the session's items, then owned by the
//! vault view, so a frame never walks the vault.

use core::cmp::Ordering;
use core::fmt;

use holm_core::category::Category;
use holm_core::fields::{CalendarDate, ExpiryStatus, expiry_status, format_date, from_unix_secs};
use holm_core::item::{ItemId, ItemType, Timestamp};
use holm_core::search::ItemSummary;
use holm_core::text::Text;

/// The subtitle of a crypto address with no chain name.
pub const CRYPTO_SUBTITLE: &str = "Crypto address";
/// The subtitle of every recovery phrase.
pub const PHRASE_SUBTITLE: &str = "Recovery phrase";
/// The subtitle of every secure note.
pub const NOTE_SUBTITLE: &str = "Secure note";

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The reminder badge of a row, copied from the core's [`ExpiryStatus`] so a row does
/// not borrow the session. It carries a day count only, never a field value or label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryBadge {
    /// The soonest reminder is this many UTC days away. Zero means today.
    InDays(u32),
    /// The soonest reminder is before today.
    Expired,
}

impl From<ExpiryStatus> for ExpiryBadge {
    fn from(status: ExpiryStatus) -> ExpiryBadge {
        match status {
            ExpiryStatus::InDays(n) => ExpiryBadge::InDays(n),
            ExpiryStatus::Expired => ExpiryBadge::Expired,
        }
    }
}

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
    /// The category's colour index (`CategoryId::colour_index`), which picks the avatar
    /// colour. `None` when the item has no category, or its category is not in the list.
    pub category_slot: Option<usize>,
    /// The soonest custom-field reminder as a badge. `None` when no field has one.
    pub expiry_badge: Option<ExpiryBadge>,
    /// When the item last changed, for the card's right edge. Never a secret.
    pub updated: String,
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
            .field("expiry_badge", &self.expiry_badge)
            .field("updated", &self.updated)
            .finish()
    }
}

/// Builds the rows for every item in `summaries` (from `Session::search`), sorted by
/// title (ignoring case), then by id. `categories` gives the names for the badges.
///
/// `today` is the UTC calendar day the expiry badges are counted from. The badge comes
/// from [`ItemSummary::soonest_expiry`] only, so no field value is read here.
///
/// `now` and `utc_offset_secs` give the local time the "updated" labels are worded
/// against; see [`updated_label`].
#[must_use]
pub fn build_rows(
    summaries: &[ItemSummary<'_>],
    categories: &[Category],
    today: CalendarDate,
    now: Timestamp,
    utc_offset_secs: i32,
) -> Vec<ItemRow> {
    let mut rows: Vec<ItemRow> = summaries
        .iter()
        .map(|s| {
            let found = s
                .category
                .and_then(|id| categories.iter().find(|c| c.id() == id));
            ItemRow {
                id: s.id,
                kind: s.item_type,
                title: Text::new(s.title.to_owned()),
                subtitle: Text::new(subtitle(s).to_owned()),
                category: found.map(|c| Text::new(c.name().to_owned())),
                category_slot: found.map(|c| c.id().colour_index()),
                expiry_badge: s
                    .soonest_expiry
                    .map(|expiry| ExpiryBadge::from(expiry_status(expiry, today))),
                updated: updated_label(s.updated, now, utc_offset_secs),
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

/// Year, month (1 to 12) and day of a checked date, read from its `YYYY-MM-DD` form.
fn date_parts(date: CalendarDate) -> (u16, u16, u16) {
    let text = format_date(date);
    let digits = |from: usize, to: usize| {
        text[from..to]
            .iter()
            .fold(0_u16, |acc, c| acc * 10 + u16::from(c.saturating_sub(b'0')))
    };
    (digits(0, 4), digits(5, 7), digits(8, 10))
}

/// The "updated" text of a card, in the local time given by `utc_offset_secs`.
///
/// The same local day as `now` gives "HH:MM". The same local year gives "D Mon". Any
/// other day gives "D Mon YYYY". A time after `now` is worded by the same rules from
/// its own date. A time outside years 1 through 9999 gives an empty string.
#[must_use]
pub fn updated_label(updated: Timestamp, now: Timestamp, utc_offset_secs: i32) -> String {
    let offset = i64::from(utc_offset_secs);
    let local = updated.0.saturating_add(offset);
    let local_now = now.0.saturating_add(offset);
    let Some(date) = from_unix_secs(local) else {
        return String::new();
    };
    let today = from_unix_secs(local_now);
    if today == Some(date) {
        let secs = local.rem_euclid(86_400);
        return format!("{:02}:{:02}", secs / 3_600, secs % 3_600 / 60);
    }
    let (year, month, day) = date_parts(date);
    let name = MONTHS
        .get(usize::from(month.saturating_sub(1)))
        .copied()
        .unwrap_or_default();
    if today.map(date_parts).is_some_and(|(y, _, _)| y == year) {
        format!("{day} {name}")
    } else {
        format!("{day} {name} {year}")
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
    use holm_core::fields::{
        CustomField, FieldValue, epoch_day, from_unix_secs, parse_date, try_field,
    };
    use holm_core::item::{ItemData, ItemInput};
    use holm_core::search::Query;
    use holm_core::session::Session;
    use holm_core::text::{GatedSecret, SecretText};
    use holm_crypto::MasterPassword;
    use holm_crypto::kdf::KdfParams;
    use holm_platform::fs_store::FsStore;

    fn input(title: &str, username: &str, urls: &[&str]) -> ItemInput {
        ItemInput {
            fields: Vec::new(),
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

    fn today() -> CalendarDate {
        parse_date("2026-11-05").unwrap()
    }

    fn now() -> Timestamp {
        Timestamp(i64::from(epoch_day(today())) * 86_400 + 43_200)
    }

    fn ts(date: &str, hour: i64, minute: i64) -> Timestamp {
        let day = i64::from(epoch_day(parse_date(date).unwrap()));
        Timestamp(day * 86_400 + hour * 3_600 + minute * 60)
    }

    fn reminder(days: i64) -> CustomField {
        let day = from_unix_secs((i64::from(epoch_day(today())) + days) * 86_400).unwrap();
        try_field(
            Text::new("remind".to_owned()),
            FieldValue::Secret(SecretText::new("EXAMPLE-field-secret".to_owned())),
            Some(day),
        )
        .unwrap()
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
            today(),
            now(),
            0,
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
            today(),
            now(),
            0,
        );
        assert_eq!(
            rows[0].category.as_ref().map(Text::as_str),
            Some("Projects")
        );
        assert!(rows[1].category.is_none());
        // The slot is the category's own colour index, not its place in the list.
        assert_eq!(rows[0].category_slot, Some(work.colour_index()));
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
            fields: Vec::new(),
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

    #[test]
    fn badge_comes_from_the_soonest_reminder() {
        let mut due = input("a", "", &[]);
        due.fields = vec![reminder(9), reminder(2)];
        let mut past = input("b", "", &[]);
        past.fields = vec![reminder(-1)];
        let rows = rows_for(vec![due, past, input("c", "", &[])]);
        assert_eq!(rows[0].expiry_badge, Some(ExpiryBadge::InDays(2)));
        assert_eq!(rows[1].expiry_badge, Some(ExpiryBadge::Expired));
        assert_eq!(rows[2].expiry_badge, None);
        let shown = format!("{:?}", rows[0]);
        assert!(!shown.contains("EXAMPLE-field-secret"), "{shown}");
        assert!(!shown.contains("remind"), "{shown}");
    }

    #[test]
    fn updated_today_is_a_local_time() {
        let now = ts("2026-11-05", 13, 30);
        assert_eq!(updated_label(ts("2026-11-05", 13, 5), now, 3_600), "14:05");
        assert_eq!(updated_label(ts("2026-11-05", 0, 0), now, 0), "00:00");
    }

    #[test]
    fn updated_earlier_this_year_has_day_and_month() {
        let now = ts("2026-11-05", 12, 0);
        assert_eq!(updated_label(ts("2026-11-03", 9, 0), now, 0), "3 Nov");
        assert_eq!(updated_label(ts("2026-01-31", 9, 0), now, 0), "31 Jan");
    }

    #[test]
    fn updated_in_an_older_year_has_the_year() {
        let now = ts("2026-11-05", 12, 0);
        assert_eq!(updated_label(ts("2025-11-03", 9, 0), now, 0), "3 Nov 2025");
    }

    #[test]
    fn updated_offset_can_cross_midnight() {
        let now = ts("2026-11-05", 12, 0);
        let updated = ts("2026-11-04", 23, 30);
        assert_eq!(updated_label(updated, now, 0), "4 Nov");
        assert_eq!(updated_label(updated, now, 3_600), "00:30");
        assert_eq!(updated_label(updated, now, -3_600), "4 Nov");
    }

    #[test]
    fn updated_in_the_future_uses_its_own_date() {
        let now = ts("2026-11-05", 12, 0);
        assert_eq!(updated_label(ts("2026-12-01", 8, 0), now, 0), "1 Dec");
        assert_eq!(updated_label(ts("2027-01-02", 8, 0), now, 0), "2 Jan 2027");
        assert_eq!(updated_label(ts("2026-11-05", 18, 45), now, 0), "18:45");
    }

    #[test]
    fn updated_out_of_range_is_empty() {
        let now = ts("2026-11-05", 12, 0);
        assert_eq!(updated_label(Timestamp(i64::MAX), now, 3_600), "");
        assert_eq!(updated_label(Timestamp(i64::MIN), now, -3_600), "");
    }

    #[test]
    fn badge_copies_the_core_status() {
        assert_eq!(
            ExpiryBadge::from(ExpiryStatus::InDays(0)),
            ExpiryBadge::InDays(0)
        );
        assert_eq!(
            ExpiryBadge::from(ExpiryStatus::Expired),
            ExpiryBadge::Expired
        );
    }
}
