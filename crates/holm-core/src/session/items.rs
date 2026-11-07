//! Item, trash, settings and phrase-gate operations on an unlocked [`Session`].
//!
//! Every mutation validates, applies, then calls [`Session::commit_or_undo`] with a
//! closure that takes the change back if the vault has no room to save it.

use holm_crypto::MasterPassword;

use super::Session;
use crate::body::VaultData;
use crate::error::CoreError;
use crate::fields::{CustomField, FieldValue, RecoveryCode, validate_fields};
use crate::item::{Item, ItemData, ItemId, ItemInput, SecretSlot, Timestamp};
use crate::rules::MAX_ITEMS;
use crate::settings::Settings;
use crate::store::VaultStore;
use crate::text::SecretText;
use crate::view::EntryView;

/// Adds a new item to `data`: checks the item cap and the category, draws a fresh id
/// (redrawn on collision), sets `created = updated = now` and pushes it.
///
/// # Errors
/// [`CoreError::TooManyItems`], [`CoreError::UnknownCategory`], or
/// [`CoreError::Vault`] (`Crypto`) if the random id draw fails.
pub(crate) fn insert_new(
    data: &mut VaultData,
    input: ItemInput,
    now: Timestamp,
) -> Result<ItemId, CoreError> {
    if data.items.len() >= MAX_ITEMS {
        return Err(CoreError::TooManyItems);
    }
    check_category(data, &input)?;
    let mut id = ItemId::random()?;
    while data.items.iter().any(|i| i.id == id) {
        id = ItemId::random()?;
    }
    data.items.push(Item {
        fields: input.fields,
        id,
        title: input.title,
        category: input.category,
        favourite: input.favourite,
        created: now,
        updated: now,
        trashed: None,
        data: input.data,
    });
    Ok(id)
}

fn check_category(data: &VaultData, input: &ItemInput) -> Result<(), CoreError> {
    match input.category {
        Some(c) if !data.categories.iter().any(|k| k.id == c) => Err(CoreError::UnknownCategory),
        _ => Ok(()),
    }
}

fn position(data: &VaultData, id: ItemId) -> Result<usize, CoreError> {
    data.items
        .iter()
        .position(|i| i.id == id)
        .ok_or(CoreError::NotFound)
}

fn phrase_of(item: &mut Item) -> Option<&mut crate::text::GatedSecret> {
    match &mut item.data {
        ItemData::RecoveryPhrase { phrase, .. } => Some(phrase),
        _ => None,
    }
}

/// Swaps the phrases of two recovery-phrase items. Does nothing for other types.
fn swap_phrases(a: &mut Item, b: &mut Item) {
    if let (Some(x), Some(y)) = (phrase_of(a), phrase_of(b)) {
        std::mem::swap(x, y);
    }
}

impl<S: VaultStore> Session<S> {
    /// The item with this id, trashed or not.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`].
    pub fn item(&self, id: ItemId) -> Result<&Item, CoreError> {
        let data = &self.unlocked()?.data;
        let i = position(data, id)?;
        Ok(&data.items[i])
    }

    /// The items not in Trash, in stored order, with no filtering or sorting. The
    /// item list shows these; search and sort are separate (Phase 4).
    ///
    /// # Errors
    /// [`CoreError::Locked`].
    pub fn active_items(&self) -> Result<impl Iterator<Item = &Item> + '_, CoreError> {
        let data = &self.unlocked()?.data;
        Ok(data.items.iter().filter(|i| i.trashed.is_none()))
    }

    /// A view of the item with this id, trashed or not: public fields and presence
    /// flags, no secret.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`].
    pub fn entry(&self, id: ItemId) -> Result<EntryView<'_>, CoreError> {
        self.item(id).map(EntryView::new)
    }

    /// Views of the items not in Trash, in stored order.
    ///
    /// # Errors
    /// [`CoreError::Locked`].
    pub fn active_entries(&self) -> Result<impl Iterator<Item = EntryView<'_>> + '_, CoreError> {
        Ok(self.active_items()?.map(EntryView::new))
    }

    /// One secret value of an item, in a new wiping [`SecretText`]. The recovery phrase
    /// is not a slot; it has its own password gate ([`Session::reveal_phrase`]).
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::NoSuchSecret`] if
    /// the item has no value in that slot, or [`CoreError::DamagedItem`] if its record
    /// cannot be opened.
    pub fn reveal(&self, id: ItemId, slot: SecretSlot) -> Result<SecretText, CoreError> {
        let item = self.item(id)?;
        let found: Option<&SecretText> = match (slot, item.data()) {
            (SecretSlot::Field { position }, _) => {
                match item.fields().get(usize::from(position)).map(|f| f.value()) {
                    Some(FieldValue::Secret(v) | FieldValue::MultilineSecret(v)) => Some(v),
                    _ => None,
                }
            }
            (SecretSlot::Code { position, index }, _) => {
                match item.fields().get(usize::from(position)).map(|f| f.value()) {
                    Some(FieldValue::RecoveryCodes(codes)) => {
                        codes.get(usize::from(index)).map(RecoveryCode::code)
                    }
                    _ => None,
                }
            }
            (SecretSlot::Password, ItemData::Login { password, .. }) => Some(password),
            (
                SecretSlot::Notes,
                ItemData::Login { notes, .. }
                | ItemData::CryptoAddress { notes, .. }
                | ItemData::RecoveryPhrase { notes, .. },
            ) => Some(notes),
            (SecretSlot::Address, ItemData::CryptoAddress { address, .. }) => Some(address),
            (SecretSlot::Memo, ItemData::CryptoAddress { memo, .. }) => Some(memo),
            (SecretSlot::Body, ItemData::SecureNote { body }) => Some(body),
            _ => None,
        };
        found
            .map(|v| SecretText::new(v.expose().to_owned()))
            .ok_or(CoreError::NoSuchSecret)
    }

    /// The whole item, owned, in wiping types. For editing, CLI edit and export; the
    /// caller drops it as soon as the form has taken the values.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::DamagedItem`].
    pub fn open_item(&self, id: ItemId) -> Result<Item, CoreError> {
        self.item(id).map(Item::duplicate)
    }

    /// Marks one recovery code used or unused and saves. Changes `updated`.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::InTrash`],
    /// [`CoreError::NoSuchSecret`] if `position` is not a recovery codes field or
    /// `index` is past its last code, or the errors of a save.
    pub fn set_code_used(
        &mut self,
        id: ItemId,
        position: u8,
        index: u8,
        used: bool,
    ) -> Result<(), CoreError> {
        let now = self.now_unix();
        let data = &mut self.unlocked_mut()?.data;
        let pos = self::position(data, id)?;
        if data.items[pos].trashed.is_some() {
            return Err(CoreError::InTrash);
        }
        let item = &mut data.items[pos];
        let Some(code) = item
            .fields
            .get_mut(usize::from(position))
            .and_then(|f| f.codes_mut())
            .and_then(|codes| codes.get_mut(usize::from(index)))
        else {
            return Err(CoreError::NoSuchSecret);
        };
        let old_used = code.used();
        code.set_used(used);
        let old_updated = std::mem::replace(&mut item.updated, now);
        let (field, code_index) = (usize::from(position), usize::from(index));
        self.commit_or_undo(move |d| {
            d.items[pos].updated = old_updated;
            if let Some(code) = d.items[pos]
                .fields
                .get_mut(field)
                .and_then(|f| f.codes_mut())
                .and_then(|codes| codes.get_mut(code_index))
            {
                code.set_used(old_used);
            }
        })
    }

    /// Adds an item and saves.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Field`], [`CoreError::UnknownCategory`],
    /// [`CoreError::TooManyItems`], or the errors of a save.
    pub fn add_item(&mut self, input: ItemInput) -> Result<ItemId, CoreError> {
        self.unlocked()?;
        input.validate()?;
        let now = self.now_unix();
        let data = &mut self.unlocked_mut()?.data;
        let idx = data.items.len();
        let id = insert_new(data, input, now)?;
        self.commit_or_undo(move |d| d.items.truncate(idx))?;
        Ok(id)
    }

    /// Replaces an item's contents and saves. `created` stays; `updated` becomes now.
    /// An empty phrase on a recovery-phrase item keeps the stored phrase. The item's
    /// custom fields stay as they are (`input.fields` is ignored). Call
    /// [`Session::set_custom_fields`] to replace them.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Field`], [`CoreError::NotFound`],
    /// [`CoreError::InTrash`], [`CoreError::TypeChange`],
    /// [`CoreError::UnknownCategory`], or the errors of a save.
    pub fn update_item(&mut self, id: ItemId, input: ItemInput) -> Result<(), CoreError> {
        self.unlocked()?;
        input.validate_for_update()?;
        let now = self.now_unix();
        let data = &mut self.unlocked_mut()?.data;
        let pos = position(data, id)?;
        let old = &data.items[pos];
        if old.trashed.is_some() {
            return Err(CoreError::InTrash);
        }
        if old.data.item_type() != input.data.item_type() {
            return Err(CoreError::TypeChange);
        }
        check_category(data, &input)?;
        let keep = matches!(
            &input.data,
            ItemData::RecoveryPhrase { phrase, .. } if phrase.is_empty()
        );
        let created = data.items[pos].created;
        let new = Item {
            fields: Vec::new(),
            id,
            title: input.title,
            category: input.category,
            favourite: input.favourite,
            created,
            updated: now,
            trashed: None,
            data: input.data,
        };
        let mut old = std::mem::replace(&mut data.items[pos], new);
        if keep {
            swap_phrases(&mut data.items[pos], &mut old);
        }
        // The item keeps its custom fields: an edit form that does not show them must
        // not delete them. `input.fields` is ignored here.
        core::mem::swap(&mut data.items[pos].fields, &mut old.fields);
        self.commit_or_undo(move |d| {
            let mut cur = std::mem::replace(&mut d.items[pos], old);
            if keep {
                swap_phrases(&mut d.items[pos], &mut cur);
            }
            core::mem::swap(&mut d.items[pos].fields, &mut cur.fields);
        })
    }

    /// Replaces an item's custom fields and saves. `updated` becomes now.
    ///
    /// If the vault has no room for the save, the previous fields and `updated`
    /// are put back.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Field`], [`CoreError::NotFound`],
    /// [`CoreError::InTrash`], or the errors of a save.
    pub fn set_custom_fields(
        &mut self,
        id: ItemId,
        fields: Vec<CustomField>,
    ) -> Result<(), CoreError> {
        self.unlocked()?;
        validate_fields(&fields)?;
        let now = self.now_unix();
        let data = &mut self.unlocked_mut()?.data;
        let pos = position(data, id)?;
        if data.items[pos].trashed.is_some() {
            return Err(CoreError::InTrash);
        }
        let old_updated = data.items[pos].updated;
        let old_fields = std::mem::replace(&mut data.items[pos].fields, fields);
        data.items[pos].updated = now;
        self.commit_or_undo(move |d| {
            d.items[pos].fields = old_fields;
            d.items[pos].updated = old_updated;
        })
    }

    /// Sets or clears the favourite flag and saves. `updated` does not change.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], or the errors of a save.
    pub fn set_favourite(&mut self, id: ItemId, favourite: bool) -> Result<(), CoreError> {
        let data = &mut self.unlocked_mut()?.data;
        let pos = position(data, id)?;
        let old = std::mem::replace(&mut data.items[pos].favourite, favourite);
        self.commit_or_undo(move |d| d.items[pos].favourite = old)
    }

    /// Moves an item to the trash and saves.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::InTrash`], or the
    /// errors of a save.
    pub fn trash(&mut self, id: ItemId) -> Result<(), CoreError> {
        let now = self.now_unix();
        let data = &mut self.unlocked_mut()?.data;
        let pos = position(data, id)?;
        if data.items[pos].trashed.is_some() {
            return Err(CoreError::InTrash);
        }
        let old = data.items[pos].trashed.replace(now);
        self.commit_or_undo(move |d| d.items[pos].trashed = old)
    }

    /// Takes an item out of the trash and saves.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::NotInTrash`], or
    /// the errors of a save.
    pub fn restore(&mut self, id: ItemId) -> Result<(), CoreError> {
        let data = &mut self.unlocked_mut()?.data;
        let pos = position(data, id)?;
        let old = data.items[pos].trashed.take();
        if old.is_none() {
            return Err(CoreError::NotInTrash);
        }
        self.commit_or_undo(move |d| d.items[pos].trashed = old)
    }

    /// Removes a trashed item for good and saves.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::NotInTrash`], or
    /// the errors of a save.
    pub fn delete_forever(&mut self, id: ItemId) -> Result<(), CoreError> {
        let data = &mut self.unlocked_mut()?.data;
        let pos = position(data, id)?;
        if data.items[pos].trashed.is_none() {
            return Err(CoreError::NotInTrash);
        }
        let item = data.items.remove(pos);
        self.commit_or_undo(move |d| d.items.insert(pos, item))
    }

    /// Removes every trashed item for good and saves. Returns how many went. Saves
    /// nothing when the trash is empty.
    ///
    /// # Errors
    /// [`CoreError::Locked`], or the errors of a save.
    pub fn empty_trash(&mut self) -> Result<usize, CoreError> {
        let data = &mut self.unlocked_mut()?.data;
        if !data.items.iter().any(|i| i.trashed.is_some()) {
            return Ok(0);
        }
        let all = std::mem::take(&mut data.items);
        let mut removed: Vec<(usize, Item)> = Vec::new();
        for (idx, item) in all.into_iter().enumerate() {
            if item.trashed.is_some() {
                removed.push((idx, item));
            } else {
                data.items.push(item);
            }
        }
        let n = removed.len();
        self.commit_or_undo(move |d| {
            // Ascending original indices: each insert lands at its old place.
            for (idx, item) in removed {
                d.items.insert(idx, item);
            }
        })?;
        Ok(n)
    }

    /// The settings.
    ///
    /// # Errors
    /// [`CoreError::Locked`].
    pub fn settings(&self) -> Result<&Settings, CoreError> {
        Ok(&self.unlocked()?.data.settings)
    }

    /// Replaces the settings and saves. A weaker setting needs the master password.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Settings`], [`CoreError::PasswordRequired`],
    /// [`CoreError::WrongPassword`], [`CoreError::Throttled`], or the errors of a save.
    pub fn update_settings(
        &mut self,
        new: Settings,
        password: Option<&MasterPassword>,
    ) -> Result<(), CoreError> {
        let current = &self.unlocked()?.data.settings;
        new.validate()?;
        if new.is_weaker_than(current) {
            let pw = password.ok_or(CoreError::PasswordRequired)?;
            self.check_password(pw)?;
        }
        let data = &mut self.unlocked_mut()?.data;
        let old = std::mem::replace(&mut data.settings, new);
        self.commit_or_undo(move |d| d.settings = old)
    }

    /// Shows a recovery phrase after the master password is re-checked (throttled).
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::NotAPhrase`],
    /// [`CoreError::WrongPassword`], [`CoreError::Throttled`].
    pub fn reveal_phrase(
        &mut self,
        id: ItemId,
        password: &MasterPassword,
    ) -> Result<&str, CoreError> {
        match self.item(id)?.data() {
            ItemData::RecoveryPhrase { .. } => {}
            _ => return Err(CoreError::NotAPhrase),
        }
        self.check_password(password)?;
        match self.item(id)?.data() {
            ItemData::RecoveryPhrase { phrase, .. } => Ok(phrase.expose()),
            _ => Err(CoreError::NotAPhrase),
        }
    }
}

#[cfg(test)]
mod tests;
