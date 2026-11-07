//! A borrowed, secret-free view of one vault item.
//!
//! [`EntryView`] is what lists, search, badges and the detail view's public rows read.
//! It exposes the public fields and the presence flags of an item and never a secret.
//! A secret comes only from [`crate::session::Session::reveal`],
//! [`crate::session::Session::open_item`] or the phrase gate.
//!
//! The type is permanent: it wraps the stored index entry, so callers do not change when
//! the storage does. It reads the open index and never opens a record.

use crate::category::CategoryId;
use crate::fields::{CalendarDate, FieldKind, epoch_day};
use crate::index::{EntryPublic, FieldEntry, FieldEntryKind, ItemEntry};
use crate::item::{ItemId, ItemType, Timestamp};

/// The public part of an item, by kind, with presence flags in place of the secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicView<'a> {
    /// A website or app login.
    Login {
        /// Account name.
        username: &'a str,
        /// Sites this login is for.
        urls: Vec<&'a str>,
        /// Whether a password is stored.
        has_password: bool,
        /// Whether notes are stored.
        has_notes: bool,
    },
    /// A crypto address.
    CryptoAddress {
        /// Chain name.
        chain: &'a str,
        /// Whether an address is stored.
        has_address: bool,
        /// Whether a memo is stored.
        has_memo: bool,
        /// Whether notes are stored.
        has_notes: bool,
    },
    /// A recovery phrase. The phrase is always present.
    RecoveryPhrase {
        /// Whether notes are stored.
        has_notes: bool,
    },
    /// A secure note.
    SecureNote {
        /// Whether a body is stored.
        has_body: bool,
    },
}

/// What a custom field shows without a reveal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldDetail<'a> {
    /// A display line.
    Text(&'a str),
    /// A calendar day.
    Date(CalendarDate),
    /// A secret line; the value is behind a reveal.
    Secret,
    /// Secret text with newlines; the value is behind a reveal.
    MultilineSecret,
    /// Recovery codes; only the used flags are public, in code order.
    RecoveryCodes {
        /// One flag per code.
        used: Vec<bool>,
    },
}

/// One custom field as a list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldView<'a> {
    position: u8,
    label: &'a str,
    expiry: Option<CalendarDate>,
    detail: FieldDetail<'a>,
}

impl<'a> FieldView<'a> {
    fn of(field: &'a FieldEntry) -> FieldView<'a> {
        let detail = match field.kind() {
            FieldEntryKind::Text(t) => FieldDetail::Text(t.as_str()),
            FieldEntryKind::Date(d) => FieldDetail::Date(*d),
            FieldEntryKind::Secret => FieldDetail::Secret,
            FieldEntryKind::MultilineSecret => FieldDetail::MultilineSecret,
            FieldEntryKind::RecoveryCodes { used } => {
                FieldDetail::RecoveryCodes { used: used.clone() }
            }
        };
        FieldView {
            position: field.position(),
            label: field.label(),
            expiry: field.expiry(),
            detail,
        }
    }

    /// Position in the item's field list; the key `reveal` takes.
    #[must_use]
    pub fn position(&self) -> u8 {
        self.position
    }

    /// The display label.
    #[must_use]
    pub fn label(&self) -> &'a str {
        self.label
    }

    /// The optional reminder date.
    #[must_use]
    pub fn expiry(&self) -> Option<CalendarDate> {
        self.expiry
    }

    /// What can be shown without a reveal.
    #[must_use]
    pub fn detail(&self) -> &FieldDetail<'a> {
        &self.detail
    }

    /// The kind of the value.
    #[must_use]
    pub fn kind(&self) -> FieldKind {
        match self.detail {
            FieldDetail::Text(_) => FieldKind::Text,
            FieldDetail::Date(_) => FieldKind::Date,
            FieldDetail::Secret => FieldKind::Secret,
            FieldDetail::MultilineSecret => FieldKind::MultilineSecret,
            FieldDetail::RecoveryCodes { .. } => FieldKind::RecoveryCodes,
        }
    }

    /// Unused codes and total codes, for a recovery codes field.
    #[must_use]
    pub fn codes_left(&self) -> Option<(usize, usize)> {
        match &self.detail {
            FieldDetail::RecoveryCodes { used } => {
                Some((used.iter().filter(|u| !**u).count(), used.len()))
            }
            _ => None,
        }
    }
}

/// A borrowed view of one item: public fields and presence flags, no secret.
#[derive(Clone, Copy)]
pub struct EntryView<'a> {
    entry: &'a ItemEntry,
}

impl<'a> EntryView<'a> {
    pub(crate) fn new(entry: &'a ItemEntry) -> EntryView<'a> {
        EntryView { entry }
    }

    /// The item id.
    #[must_use]
    pub fn id(&self) -> ItemId {
        self.entry.id()
    }

    /// The title.
    #[must_use]
    pub fn title(&self) -> &'a str {
        self.entry.title()
    }

    /// The category, if any.
    #[must_use]
    pub fn category(&self) -> Option<CategoryId> {
        self.entry.category()
    }

    /// Whether the item is a favourite.
    #[must_use]
    pub fn favourite(&self) -> bool {
        self.entry.favourite()
    }

    /// When the item was created.
    #[must_use]
    pub fn created(&self) -> Timestamp {
        self.entry.created()
    }

    /// When the item was last changed.
    #[must_use]
    pub fn updated(&self) -> Timestamp {
        self.entry.updated()
    }

    /// When the item was moved to the trash, if it was.
    #[must_use]
    pub fn trashed(&self) -> Option<Timestamp> {
        self.entry.trashed()
    }

    /// The kind of this item.
    #[must_use]
    pub fn item_type(&self) -> ItemType {
        self.entry.item_type()
    }

    /// The public fields and presence flags, by kind.
    #[must_use]
    pub fn public(&self) -> PublicView<'a> {
        match self.entry.public() {
            EntryPublic::Login {
                username,
                urls,
                has_password,
                has_notes,
            } => PublicView::Login {
                username: username.as_str(),
                urls: urls.iter().map(|u| u.as_str()).collect(),
                has_password: *has_password,
                has_notes: *has_notes,
            },
            EntryPublic::CryptoAddress {
                chain,
                has_address,
                has_memo,
                has_notes,
            } => PublicView::CryptoAddress {
                chain: chain.as_str(),
                has_address: *has_address,
                has_memo: *has_memo,
                has_notes: *has_notes,
            },
            EntryPublic::RecoveryPhrase { has_notes } => PublicView::RecoveryPhrase {
                has_notes: *has_notes,
            },
            EntryPublic::SecureNote { has_body } => PublicView::SecureNote {
                has_body: *has_body,
            },
        }
    }

    /// The custom fields in their stored order.
    #[must_use]
    pub fn fields(&self) -> Vec<FieldView<'a>> {
        self.entry.fields().iter().map(FieldView::of).collect()
    }

    /// The soonest reminder date over all fields.
    #[must_use]
    pub fn soonest_expiry(&self) -> Option<CalendarDate> {
        self.entry
            .fields()
            .iter()
            .filter_map(FieldEntry::expiry)
            .min()
    }

    /// Whether the soonest reminder falls on or before `today` plus `within_days`.
    /// Days are UTC dates; `within_days` is widened to `i64` so a large window cannot wrap.
    #[must_use]
    pub fn is_expiring(&self, today: CalendarDate, within_days: u32) -> bool {
        let Some(soonest) = self.soonest_expiry() else {
            return false;
        };
        let limit = i64::from(epoch_day(today)) + i64::from(within_days);
        i64::from(epoch_day(soonest)) <= limit
    }

    /// The smallest count of unused codes over all recovery codes fields.
    #[must_use]
    pub fn fewest_codes_left(&self) -> Option<usize> {
        self.entry
            .fields()
            .iter()
            .filter_map(|f| match f.kind() {
                FieldEntryKind::RecoveryCodes { used } => {
                    Some(used.iter().filter(|u| !**u).count())
                }
                _ => None,
            })
            .min()
    }

    /// The line a list shows under the title: a login's username (or first URL when
    /// the username is empty) or a crypto item's chain.
    #[must_use]
    pub fn subtitle(&self) -> Option<&'a str> {
        match self.public() {
            PublicView::Login { username, urls, .. } => {
                if username.is_empty() {
                    urls.first().copied()
                } else {
                    Some(username)
                }
            }
            PublicView::CryptoAddress { chain, .. } => Some(chain),
            _ => None,
        }
    }
}

impl std::fmt::Debug for EntryView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryView")
            .field("type", &self.item_type())
            .finish_non_exhaustive()
    }
}
