//! Item, trash, settings and phrase-gate operations on an unlocked [`Session`].
//!
//! Every mutation validates, applies, then calls [`Session::commit_or_undo`] with a
//! closure that takes the change back if the vault has no room to save it.

use holm_crypto::MasterPassword;

use super::Session;
use crate::body::VaultData;
use crate::error::CoreError;
use crate::item::{Item, ItemData, ItemId, ItemInput, Timestamp};
use crate::rules::MAX_ITEMS;
use crate::settings::Settings;
use crate::store::VaultStore;

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
    /// An empty phrase on a recovery-phrase item keeps the stored phrase.
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
        self.commit_or_undo(move |d| {
            let mut cur = std::mem::replace(&mut d.items[pos], old);
            if keep {
                swap_phrases(&mut d.items[pos], &mut cur);
            }
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
