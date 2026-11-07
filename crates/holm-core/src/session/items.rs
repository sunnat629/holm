//! Item, trash, settings and phrase-gate operations on an unlocked [`Session`].
//!
//! Every mutation validates, applies, then calls [`Session::commit_or_undo`] with a
//! closure that takes the change back if the vault has no room to save it.
//!
//! The vault state is the index plus one sealed record per item. A change that touches
//! only public data (favourite, trash, category, settings, a code's used flag) edits the
//! index and leaves every record as it is. A change that touches secrets opens the one
//! record it needs, seals a new one with the next generation, and swaps entry and
//! record together.

use holm_crypto::MasterPassword;

use super::{Session, VaultState};
use crate::envelope_v2::{open_record, seal_record};
use crate::error::CoreError;
use crate::fields::{CustomField, validate_fields};
use crate::index::{FieldEntryKind, ItemEntry};
use crate::item::{Item, ItemData, ItemId, ItemInput, SecretSlot, Timestamp};
use crate::record::{join, split, take_phrase, take_slot};
use crate::rules::MAX_ITEMS;
use crate::settings::Settings;
use crate::store::VaultStore;
use crate::text::SecretText;
use crate::view::EntryView;

/// Seals `item` as generation `generation` under the state's keys. Returns the entry
/// (its record ref filled in) and the sealed record.
fn seal_item(
    state: &VaultState,
    item: Item,
    generation: u64,
) -> Result<(ItemEntry, crate::envelope_v2::SealedRecord), CoreError> {
    let (mut entry, secrets) = split(item);
    let sealed = seal_record(&state.keys, &entry.id, generation, &secrets)?;
    drop(secrets);
    entry.record = super::ref_of(&sealed)?;
    Ok((entry, sealed))
}

/// The next generation of the item at `pos`, or [`CoreError::GenerationExhausted`].
fn next_generation(state: &VaultState, pos: usize) -> Result<u64, CoreError> {
    let entry = &state.index.entries[pos];
    entry
        .record
        .generation
        .checked_add(1)
        .ok_or(CoreError::GenerationExhausted(entry.id))
}

/// Opens the record at `pos` into a whole item, in wiping types.
pub(crate) fn open_at(state: &VaultState, pos: usize) -> Result<Item, CoreError> {
    let entry = &state.index.entries[pos];
    let secrets = open_record(&state.keys, &state.records[pos], entry)?;
    join(entry, secrets).map_err(|_| CoreError::DamagedItem(entry.id))
}

/// Adds a new item to `state`: checks the item cap and the category, draws a fresh id
/// (redrawn on collision), sets `created = updated = now`, seals the record as
/// generation 1 and pushes entry and record.
///
/// # Errors
/// [`CoreError::TooManyItems`], [`CoreError::UnknownCategory`], or
/// [`CoreError::Vault`] (`Crypto`, `TooLargeToSave`) if the id draw or the seal fails.
pub(crate) fn insert_new(
    state: &mut VaultState,
    input: ItemInput,
    now: Timestamp,
) -> Result<ItemId, CoreError> {
    if state.index.entries.len() >= MAX_ITEMS {
        return Err(CoreError::TooManyItems);
    }
    check_category(state, &input)?;
    let mut id = ItemId::random()?;
    while state.index.entries.iter().any(|e| e.id == id) {
        id = ItemId::random()?;
    }
    let (entry, sealed) = seal_item(
        state,
        Item {
            fields: input.fields,
            id,
            title: input.title,
            category: input.category,
            favourite: input.favourite,
            created: now,
            updated: now,
            trashed: None,
            data: input.data,
        },
        1,
    )?;
    state.index.entries.push(entry);
    state.records.push(sealed);
    Ok(id)
}

fn check_category(state: &VaultState, input: &ItemInput) -> Result<(), CoreError> {
    match input.category {
        Some(c) if !state.index.categories.iter().any(|k| k.id == c) => {
            Err(CoreError::UnknownCategory)
        }
        _ => Ok(()),
    }
}

pub(crate) fn position(state: &VaultState, id: ItemId) -> Result<usize, CoreError> {
    state
        .index
        .entries
        .iter()
        .position(|e| e.id == id)
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

/// Puts back an entry and its record at `pos`.
fn put_back(
    state: &mut VaultState,
    pos: usize,
    entry: ItemEntry,
    record: crate::envelope_v2::SealedRecord,
) {
    state.index.entries[pos] = entry;
    state.records[pos] = record;
}

impl<S: VaultStore> Session<S> {
    /// A view of the item with this id, trashed or not: public fields and presence
    /// flags, no secret.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`].
    pub fn entry(&self, id: ItemId) -> Result<EntryView<'_>, CoreError> {
        let state = &self.unlocked()?.state;
        let pos = position(state, id)?;
        Ok(EntryView::new(&state.index.entries[pos]))
    }

    /// Views of the items not in Trash, in stored order, with no filtering or sorting.
    /// The item list shows these; search and sort are separate.
    ///
    /// # Errors
    /// [`CoreError::Locked`].
    pub fn active_entries(&self) -> Result<impl Iterator<Item = EntryView<'_>> + '_, CoreError> {
        let state = &self.unlocked()?.state;
        Ok(state
            .index
            .entries
            .iter()
            .filter(|e| e.trashed.is_none())
            .map(EntryView::new))
    }

    /// One secret value of an item, in a new wiping [`SecretText`]. The recovery phrase
    /// is not a slot; it has its own password gate ([`Session::reveal_phrase`]).
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::NoSuchSecret`] if
    /// the item has no value in that slot, or [`CoreError::DamagedItem`] if its record
    /// cannot be opened.
    pub fn reveal(&self, id: ItemId, slot: SecretSlot) -> Result<SecretText, CoreError> {
        let state = &self.unlocked()?.state;
        let pos = position(state, id)?;
        let secrets = open_record(&state.keys, &state.records[pos], &state.index.entries[pos])?;
        take_slot(secrets, slot)
    }

    /// The whole item, owned, in wiping types. For editing, CLI edit and export; the
    /// caller drops it as soon as the form has taken the values.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::DamagedItem`].
    pub fn open_item(&self, id: ItemId) -> Result<Item, CoreError> {
        let state = &self.unlocked()?.state;
        let pos = position(state, id)?;
        open_at(state, pos)
    }

    /// The whole item, owned. Tests only; the app uses [`Session::entry`], [`Session::reveal`]
    /// and [`Session::open_item`].
    #[cfg(test)]
    pub(crate) fn item(&self, id: ItemId) -> Result<Item, CoreError> {
        self.open_item(id)
    }

    /// Seals `item` as generation 1 and pushes it without saving. Tests only.
    #[cfg(test)]
    pub(crate) fn seed(&mut self, item: Item) {
        let state = &mut self.unlocked_mut().expect("unlocked").state;
        let (entry, sealed) = seal_item(state, item, 1).expect("seed seals");
        state.index.entries.push(entry);
        state.records.push(sealed);
    }

    /// How many items are stored, trashed ones included. Tests only.
    #[cfg(test)]
    pub(crate) fn stored_count(&self) -> usize {
        self.unlocked().expect("unlocked").state.index.entries.len()
    }

    /// Seeds items made by `make(i)` until the file is as full as it can be: one more
    /// of the same size would not fit. Nothing is saved. Returns the sealed size of
    /// one record and the seeded ids. Tests only.
    #[cfg(test)]
    pub(crate) fn seed_to_the_brim(
        &mut self,
        make: impl Fn(usize) -> Item,
    ) -> (usize, Vec<ItemId>) {
        self.seed(make(usize::MAX));
        let state = &mut self.unlocked_mut().expect("unlocked").state;
        let size = state.records[0].ct.len();
        state.index.entries.clear();
        state.records.clear();
        // Leave room for the header and the index, then add one at a time until the
        // file no longer assembles.
        let first = (crate::format::MAX_FILE_LEN - (1 << 20)) / size;
        for i in 0..first {
            self.seed(make(i));
        }
        let mut n = first;
        loop {
            self.seed(make(n));
            n += 1;
            let state = &mut self.unlocked_mut().expect("unlocked").state;
            if state.assemble().is_err() {
                state.index.entries.pop();
                state.records.pop();
                break;
            }
        }
        let state = &self.unlocked().expect("unlocked").state;
        (size, state.index.entries.iter().map(|e| e.id).collect())
    }

    /// Every item outside the Trash, owned, in stored order. Tests only.
    #[cfg(test)]
    pub(crate) fn active_items(&self) -> Result<impl Iterator<Item = Item> + '_, CoreError> {
        let state = &self.unlocked()?.state;
        Ok((0..state.index.entries.len())
            .filter(|p| state.index.entries[*p].trashed.is_none())
            .map(|p| open_at(state, p).expect("test record opens")))
    }

    /// Marks one recovery code used or unused and saves. Changes `updated`. Only the
    /// index changes; the record is not touched.
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
        let state = &mut self.unlocked_mut()?.state;
        let pos = self::position(state, id)?;
        let entry = &mut state.index.entries[pos];
        if entry.trashed.is_some() {
            return Err(CoreError::InTrash);
        }
        let (field, code) = (usize::from(position), usize::from(index));
        let Some(flag) = entry.fields.get_mut(field).and_then(|f| match &mut f.kind {
            FieldEntryKind::RecoveryCodes { used } => used.get_mut(code),
            _ => None,
        }) else {
            return Err(CoreError::NoSuchSecret);
        };
        let old_used = core::mem::replace(flag, used);
        let old_updated = core::mem::replace(&mut entry.updated, now);
        self.commit_or_undo(move |st| {
            let entry = &mut st.index.entries[pos];
            entry.updated = old_updated;
            if let Some(FieldEntryKind::RecoveryCodes { used }) =
                entry.fields.get_mut(field).map(|f| &mut f.kind)
                && let Some(flag) = used.get_mut(code)
            {
                *flag = old_used;
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
        let state = &mut self.unlocked_mut()?.state;
        let idx = state.index.entries.len();
        let id = insert_new(state, input, now)?;
        self.commit_or_undo(move |st| {
            st.index.entries.truncate(idx);
            st.records.truncate(idx);
        })?;
        Ok(id)
    }

    /// Replaces an item's contents and saves. `created` stays; `updated` becomes now.
    /// An empty phrase on a recovery-phrase item keeps the stored phrase. The item's
    /// custom fields stay as they are (`input.fields` is ignored). Call
    /// [`Session::set_custom_fields`] to replace them.
    ///
    /// The old record is opened only when something in it must be kept: the phrase or
    /// custom fields. The new record is sealed with the next generation and replaces
    /// the old one; no other record changes.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Field`], [`CoreError::NotFound`],
    /// [`CoreError::InTrash`], [`CoreError::TypeChange`],
    /// [`CoreError::UnknownCategory`], [`CoreError::GenerationExhausted`],
    /// [`CoreError::DamagedItem`], or the errors of a save.
    pub fn update_item(&mut self, id: ItemId, input: ItemInput) -> Result<(), CoreError> {
        self.unlocked()?;
        input.validate_for_update()?;
        let now = self.now_unix();
        let state = &mut self.unlocked_mut()?.state;
        let pos = position(state, id)?;
        let old_entry = &state.index.entries[pos];
        if old_entry.trashed.is_some() {
            return Err(CoreError::InTrash);
        }
        if old_entry.item_type() != input.data.item_type() {
            return Err(CoreError::TypeChange);
        }
        check_category(state, &input)?;
        let generation = next_generation(state, pos)?;
        let keep = matches!(
            &input.data,
            ItemData::RecoveryPhrase { phrase, .. } if phrase.is_empty()
        );
        let created = old_entry.created;
        // The item keeps its custom fields: an edit form that does not show them must
        // not delete them. `input.fields` is ignored here. Open the old record only if
        // it has something to keep.
        let mut old = if keep || !old_entry.fields.is_empty() {
            Some(open_at(state, pos)?)
        } else {
            None
        };
        let mut new = Item {
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
        if let Some(old) = old.as_mut() {
            if keep {
                swap_phrases(&mut new, old);
            }
            core::mem::swap(&mut new.fields, &mut old.fields);
        }
        drop(old);
        let (entry, sealed) = seal_item(state, new, generation)?;
        let old_entry = core::mem::replace(&mut state.index.entries[pos], entry);
        let old_record = core::mem::replace(&mut state.records[pos], sealed);
        self.commit_or_undo(move |st| put_back(st, pos, old_entry, old_record))
    }

    /// Replaces an item's custom fields and saves. `updated` becomes now.
    ///
    /// If the vault has no room for the save, the previous entry and record are put
    /// back.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Field`], [`CoreError::NotFound`],
    /// [`CoreError::InTrash`], [`CoreError::DamagedItem`], or the errors of a save.
    pub fn set_custom_fields(
        &mut self,
        id: ItemId,
        fields: Vec<CustomField>,
    ) -> Result<(), CoreError> {
        self.unlocked()?;
        validate_fields(&fields)?;
        let now = self.now_unix();
        let state = &mut self.unlocked_mut()?.state;
        let pos = position(state, id)?;
        if state.index.entries[pos].trashed.is_some() {
            return Err(CoreError::InTrash);
        }
        let generation = next_generation(state, pos)?;
        let mut item = open_at(state, pos)?;
        item.fields = fields;
        item.updated = now;
        let (entry, sealed) = seal_item(state, item, generation)?;
        let old_entry = core::mem::replace(&mut state.index.entries[pos], entry);
        let old_record = core::mem::replace(&mut state.records[pos], sealed);
        self.commit_or_undo(move |st| put_back(st, pos, old_entry, old_record))
    }

    /// Sets or clears the favourite flag and saves. `updated` does not change.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], or the errors of a save.
    pub fn set_favourite(&mut self, id: ItemId, favourite: bool) -> Result<(), CoreError> {
        let state = &mut self.unlocked_mut()?.state;
        let pos = position(state, id)?;
        let old = core::mem::replace(&mut state.index.entries[pos].favourite, favourite);
        self.commit_or_undo(move |st| st.index.entries[pos].favourite = old)
    }

    /// Moves an item to the trash and saves.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::InTrash`], or the
    /// errors of a save.
    pub fn trash(&mut self, id: ItemId) -> Result<(), CoreError> {
        let now = self.now_unix();
        let state = &mut self.unlocked_mut()?.state;
        let pos = position(state, id)?;
        if state.index.entries[pos].trashed.is_some() {
            return Err(CoreError::InTrash);
        }
        let old = state.index.entries[pos].trashed.replace(now);
        self.commit_or_undo(move |st| st.index.entries[pos].trashed = old)
    }

    /// Takes an item out of the trash and saves.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::NotInTrash`], or
    /// the errors of a save.
    pub fn restore(&mut self, id: ItemId) -> Result<(), CoreError> {
        let state = &mut self.unlocked_mut()?.state;
        let pos = position(state, id)?;
        let old = state.index.entries[pos].trashed.take();
        if old.is_none() {
            return Err(CoreError::NotInTrash);
        }
        self.commit_or_undo(move |st| st.index.entries[pos].trashed = old)
    }

    /// Removes a trashed item and its record for good and saves.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::NotInTrash`], or
    /// the errors of a save.
    pub fn delete_forever(&mut self, id: ItemId) -> Result<(), CoreError> {
        let state = &mut self.unlocked_mut()?.state;
        let pos = position(state, id)?;
        if state.index.entries[pos].trashed.is_none() {
            return Err(CoreError::NotInTrash);
        }
        let entry = state.index.entries.remove(pos);
        let record = state.records.remove(pos);
        self.commit_or_undo(move |st| {
            st.index.entries.insert(pos, entry);
            st.records.insert(pos, record);
        })
    }

    /// Removes every trashed item and its record for good and saves. Returns how many
    /// went. Saves nothing when the trash is empty.
    ///
    /// # Errors
    /// [`CoreError::Locked`], or the errors of a save.
    pub fn empty_trash(&mut self) -> Result<usize, CoreError> {
        let state = &mut self.unlocked_mut()?.state;
        if !state.index.entries.iter().any(|e| e.trashed.is_some()) {
            return Ok(0);
        }
        let all_entries = std::mem::take(&mut state.index.entries);
        let all_records = std::mem::take(&mut state.records);
        let mut removed: Vec<(usize, ItemEntry, crate::envelope_v2::SealedRecord)> = Vec::new();
        for (idx, (entry, record)) in all_entries.into_iter().zip(all_records).enumerate() {
            if entry.trashed.is_some() {
                removed.push((idx, entry, record));
            } else {
                state.index.entries.push(entry);
                state.records.push(record);
            }
        }
        let n = removed.len();
        self.commit_or_undo(move |st| {
            // Ascending original indices: each insert lands at its old place.
            for (idx, entry, record) in removed {
                st.index.entries.insert(idx, entry);
                st.records.insert(idx, record);
            }
        })?;
        Ok(n)
    }

    /// The settings.
    ///
    /// # Errors
    /// [`CoreError::Locked`].
    pub fn settings(&self) -> Result<&Settings, CoreError> {
        Ok(&self.unlocked()?.state.index.settings)
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
        let current = &self.unlocked()?.state.index.settings;
        new.validate()?;
        if new.is_weaker_than(current) {
            let pw = password.ok_or(CoreError::PasswordRequired)?;
            self.check_password(pw)?;
        }
        let state = &mut self.unlocked_mut()?.state;
        let old = core::mem::replace(&mut state.index.settings, new);
        self.commit_or_undo(move |st| st.index.settings = old)
    }

    /// Shows a recovery phrase after the master password is re-checked (throttled). The
    /// phrase comes back in a wiping [`SecretText`]; nothing stays resident.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::NotFound`], [`CoreError::NotAPhrase`],
    /// [`CoreError::WrongPassword`], [`CoreError::Throttled`], or
    /// [`CoreError::DamagedItem`].
    pub fn reveal_phrase(
        &mut self,
        id: ItemId,
        password: &MasterPassword,
    ) -> Result<SecretText, CoreError> {
        let state = &self.unlocked()?.state;
        let pos = position(state, id)?;
        if !matches!(
            state.index.entries[pos].public,
            crate::index::EntryPublic::RecoveryPhrase { .. }
        ) {
            return Err(CoreError::NotAPhrase);
        }
        self.check_password(password)?;
        let state = &self.unlocked()?.state;
        let pos = position(state, id)?;
        let secrets = open_record(&state.keys, &state.records[pos], &state.index.entries[pos])?;
        take_phrase(secrets)
    }
}

#[cfg(test)]
mod tests;
