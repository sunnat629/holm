//! A borrowed, secret-free view of one vault item.
//!
//! [`EntryView`] is what lists, search, badges and the detail view's public rows read.
//! It exposes the public fields and the presence flags of an item and never a secret.
//! A secret comes only from [`crate::session::Session::reveal`],
//! [`crate::session::Session::open_item`] or the phrase gate.
//!
//! The type is permanent: it wraps the stored item whatever shape the session keeps it
//! in, so callers do not change when the storage does.

use crate::category::CategoryId;
use crate::fields::{CalendarDate, CustomField, FieldKind, FieldValue, codes_left, is_expiring};
use crate::item::{Item, ItemData, ItemId, ItemType, Timestamp};

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
    fn of(position: u8, field: &'a CustomField) -> FieldView<'a> {
        let detail = match field.value() {
            FieldValue::Text(t) => FieldDetail::Text(t.as_str()),
            FieldValue::Date(d) => FieldDetail::Date(*d),
            FieldValue::Secret(_) => FieldDetail::Secret,
            FieldValue::MultilineSecret(_) => FieldDetail::MultilineSecret,
            FieldValue::RecoveryCodes(codes) => FieldDetail::RecoveryCodes {
                used: codes.iter().map(|c| c.used()).collect(),
            },
        };
        FieldView {
            position,
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
    item: &'a Item,
}

impl<'a> EntryView<'a> {
    pub(crate) fn new(item: &'a Item) -> EntryView<'a> {
        EntryView { item }
    }

    /// The item id.
    #[must_use]
    pub fn id(&self) -> ItemId {
        self.item.id()
    }

    /// The title.
    #[must_use]
    pub fn title(&self) -> &'a str {
        self.item.title()
    }

    /// The category, if any.
    #[must_use]
    pub fn category(&self) -> Option<CategoryId> {
        self.item.category()
    }

    /// Whether the item is a favourite.
    #[must_use]
    pub fn favourite(&self) -> bool {
        self.item.favourite()
    }

    /// When the item was created.
    #[must_use]
    pub fn created(&self) -> Timestamp {
        self.item.created()
    }

    /// When the item was last changed.
    #[must_use]
    pub fn updated(&self) -> Timestamp {
        self.item.updated()
    }

    /// When the item was moved to the trash, if it was.
    #[must_use]
    pub fn trashed(&self) -> Option<Timestamp> {
        self.item.trashed()
    }

    /// The kind of this item.
    #[must_use]
    pub fn item_type(&self) -> ItemType {
        self.item.item_type()
    }

    /// The public fields and presence flags, by kind.
    #[must_use]
    pub fn public(&self) -> PublicView<'a> {
        match self.item.data() {
            ItemData::Login {
                username,
                password,
                urls,
                notes,
            } => PublicView::Login {
                username: username.as_str(),
                urls: urls.iter().map(|u| u.as_str()).collect(),
                has_password: !password.is_empty(),
                has_notes: !notes.is_empty(),
            },
            ItemData::CryptoAddress {
                chain,
                address,
                memo,
                notes,
            } => PublicView::CryptoAddress {
                chain: chain.as_str(),
                has_address: !address.is_empty(),
                has_memo: !memo.is_empty(),
                has_notes: !notes.is_empty(),
            },
            ItemData::RecoveryPhrase { notes, .. } => PublicView::RecoveryPhrase {
                has_notes: !notes.is_empty(),
            },
            ItemData::SecureNote { body } => PublicView::SecureNote {
                has_body: !body.is_empty(),
            },
        }
    }

    /// The custom fields in their stored order.
    #[must_use]
    pub fn fields(&self) -> Vec<FieldView<'a>> {
        (0u8..)
            .zip(self.item.fields())
            .map(|(position, field)| FieldView::of(position, field))
            .collect()
    }

    /// The soonest reminder date over all fields.
    #[must_use]
    pub fn soonest_expiry(&self) -> Option<CalendarDate> {
        self.item
            .fields()
            .iter()
            .filter_map(CustomField::expiry)
            .min()
    }

    /// Whether the soonest reminder falls on or before `today` plus `within_days`.
    #[must_use]
    pub fn is_expiring(&self, today: CalendarDate, within_days: u32) -> bool {
        is_expiring(self.item.fields(), today, within_days)
    }

    /// The smallest count of unused codes over all recovery codes fields.
    #[must_use]
    pub fn fewest_codes_left(&self) -> Option<usize> {
        self.item
            .fields()
            .iter()
            .filter_map(|f| match f.value() {
                FieldValue::RecoveryCodes(codes) => Some(codes_left(codes).0),
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
