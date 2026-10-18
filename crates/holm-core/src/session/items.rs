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
/// [`CoreError::Crypto`]-style failures from the random id draw.
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
mod tests {
    use super::super::Session;
    use super::super::tests::{
        FLOOR, NEW_PW, PW, WRONG, created, created_locked, failures, open_file, pw, secs, session,
        stored,
    };
    use crate::body::VaultData;
    use crate::category::CategoryId;
    use crate::envelope::{self, VaultError};
    use crate::error::CoreError;
    use crate::item::{Item, ItemData, ItemId, ItemInput, Timestamp};
    use crate::padding::MAX_BODY_LEN;
    use crate::rules::{Field, FieldError, MAX_ITEMS};
    use crate::settings::{Settings, SettingsError};
    use crate::store::{MemStore, StoreError};
    use crate::text::{GatedSecret, SecretText, Text};
    use crate::throttle::FREE_FAILURES;
    use std::io::ErrorKind;

    type S = Session<MemStore>;

    fn t(s: &str) -> Text {
        Text::new(s.to_owned())
    }

    fn st(s: &str) -> SecretText {
        SecretText::new(s.to_owned())
    }

    fn login(title: &str, password: &str) -> ItemInput {
        ItemInput {
            title: t(title),
            category: None,
            favourite: false,
            data: ItemData::Login {
                username: t("user"),
                password: st(password),
                urls: vec![t("https://example.com")],
                notes: st("n"),
            },
        }
    }

    fn big_login(title: &str) -> ItemInput {
        let mut i = login(title, "pw");
        if let ItemData::Login { notes, .. } = &mut i.data {
            *notes = st(&"a".repeat(65_536));
        }
        i
    }

    fn phrase(title: &str, words: &str) -> ItemInput {
        ItemInput {
            title: t(title),
            category: None,
            favourite: false,
            data: ItemData::RecoveryPhrase {
                phrase: GatedSecret::new(st(words)),
                notes: st("pn"),
            },
        }
    }

    fn note(title: &str, body: &str) -> ItemInput {
        ItemInput {
            title: t(title),
            category: None,
            favourite: false,
            data: ItemData::SecureNote { body: st(body) },
        }
    }

    fn crypto(title: &str) -> ItemInput {
        ItemInput {
            title: t(title),
            category: None,
            favourite: true,
            data: ItemData::CryptoAddress {
                chain: t("chain-x"),
                address: st("addr-EXAMPLE"),
                memo: st("memo-1"),
                notes: st("cn"),
            },
        }
    }

    fn seed_item(input: ItemInput) -> Item {
        Item {
            id: ItemId::random().unwrap(),
            title: input.title,
            category: input.category,
            favourite: input.favourite,
            created: Timestamp(1),
            updated: Timestamp(1),
            trashed: None,
            data: input.data,
        }
    }

    fn data_mut(s: &mut S) -> &mut VaultData {
        &mut s.unlocked_mut().unwrap().data
    }

    fn count(s: &S) -> usize {
        s.unlocked().unwrap().data.items.len()
    }

    fn login_password(s: &S, id: ItemId) -> String {
        match s.item(id).unwrap().data() {
            ItemData::Login { password, .. } => password.expose().to_owned(),
            _ => panic!("not a login"),
        }
    }

    #[test]
    fn every_type_survives_save_and_reopen() {
        let (mut s, _) = created();
        let cat = s.add_category("Misc").unwrap();
        let mut li = login("Login", "p@ss");
        li.category = Some(cat);
        li.favourite = true;
        let l = s.add_item(li).unwrap();
        let c = s.add_item(crypto("Crypto")).unwrap();
        let p = s.add_item(phrase("Phrase", "one two three")).unwrap();
        let n = s.add_item(note("Note", "secret body")).unwrap();
        s.lock();
        s.unlock(&pw(PW)).unwrap();

        let i = s.item(l).unwrap();
        assert_eq!(i.title(), "Login");
        assert_eq!(i.category(), Some(cat));
        assert!(i.favourite());
        assert_eq!(i.created(), i.updated());
        assert_eq!(i.trashed(), None);
        match i.data() {
            ItemData::Login {
                username,
                password,
                urls,
                notes,
            } => {
                assert_eq!(username.as_str(), "user");
                assert_eq!(password.expose(), "p@ss");
                assert_eq!(urls.len(), 1);
                assert_eq!(urls[0].as_str(), "https://example.com");
                assert_eq!(notes.expose(), "n");
            }
            _ => panic!("type changed"),
        }
        match s.item(c).unwrap().data() {
            ItemData::CryptoAddress {
                chain,
                address,
                memo,
                notes,
            } => {
                assert_eq!(chain.as_str(), "chain-x");
                assert_eq!(address.expose(), "addr-EXAMPLE");
                assert_eq!(memo.expose(), "memo-1");
                assert_eq!(notes.expose(), "cn");
            }
            _ => panic!("type changed"),
        }
        assert!(s.item(c).unwrap().favourite());
        match s.item(n).unwrap().data() {
            ItemData::SecureNote { body } => assert_eq!(body.expose(), "secret body"),
            _ => panic!("type changed"),
        }
        match s.item(p).unwrap().data() {
            ItemData::RecoveryPhrase { phrase, notes } => {
                assert!(!phrase.is_empty());
                assert_eq!(notes.expose(), "pn");
            }
            _ => panic!("type changed"),
        }
        assert_eq!(s.reveal_phrase(p, &pw(PW)).unwrap(), "one two three");
    }

    #[test]
    fn password_is_stored_byte_exact() {
        let odd = " pa\u{301}ss\tword ";
        let (mut s, _) = created();
        let id = s.add_item(login("odd", odd)).unwrap();
        s.lock();
        s.unlock(&pw(PW)).unwrap();
        assert_eq!(login_password(&s, id).as_bytes(), odd.as_bytes());
    }

    #[test]
    fn add_rejects_invalid_input() {
        let (mut s, _) = created();
        assert_eq!(
            s.add_item(login("  ", "x")),
            Err(CoreError::Field(FieldError::Empty(Field::Title)))
        );
        assert_eq!(count(&s), 0);
        assert!(!s.is_dirty());
        assert!(matches!(
            s.add_item(phrase("p", "")),
            Err(CoreError::Field(_))
        ));
    }

    #[test]
    fn update_rules() {
        let (mut s, _) = created();
        let l = s.add_item(login("a", "x")).unwrap();
        assert_eq!(s.update_item(l, note("a", "b")), Err(CoreError::TypeChange));
        let missing = ItemId::random().unwrap();
        assert_eq!(
            s.update_item(missing, login("a", "y")),
            Err(CoreError::NotFound)
        );
        s.trash(l).unwrap();
        assert_eq!(s.update_item(l, login("a", "y")), Err(CoreError::InTrash));
        s.restore(l).unwrap();
        s.update_item(l, login("renamed", "y")).unwrap();
        assert_eq!(s.item(l).unwrap().title(), "renamed");
        assert_eq!(login_password(&s, l), "y");
        assert!(matches!(
            s.update_item(l, login(" ", "y")),
            Err(CoreError::Field(_))
        ));
        assert_eq!(s.item(l).unwrap().title(), "renamed");
    }

    #[test]
    fn empty_phrase_on_update_keeps_phrase() {
        let (mut s, _) = created();
        let p = s.add_item(phrase("p", "alpha beta")).unwrap();
        s.update_item(p, phrase("p2", "")).unwrap();
        assert_eq!(s.item(p).unwrap().title(), "p2");
        assert_eq!(s.reveal_phrase(p, &pw(PW)).unwrap(), "alpha beta");
        s.update_item(p, phrase("p2", "gamma")).unwrap();
        assert_eq!(s.reveal_phrase(p, &pw(PW)).unwrap(), "gamma");
        s.lock();
        s.unlock(&pw(PW)).unwrap();
        assert_eq!(s.reveal_phrase(p, &pw(PW)).unwrap(), "gamma");
    }

    #[test]
    fn update_sets_updated_not_created() {
        let (mut s, clock) = created();
        let id = s.add_item(login("a", "x")).unwrap();
        let created_at = s.item(id).unwrap().created();
        clock.set_unix(1_700_000_010);
        s.update_item(id, login("b", "y")).unwrap();
        let i = s.item(id).unwrap();
        assert_eq!(i.created(), created_at);
        assert_eq!(i.updated(), Timestamp(created_at.0 + 10));
        assert_eq!(i.trashed(), None);
    }

    #[test]
    fn favourite_toggles_without_touching_updated() {
        let (mut s, clock) = created();
        let id = s.add_item(login("a", "x")).unwrap();
        let before = s.item(id).unwrap().updated();
        clock.set_unix(1_700_000_005);
        s.set_favourite(id, true).unwrap();
        assert!(s.item(id).unwrap().favourite());
        assert_eq!(s.item(id).unwrap().updated(), before);
        assert_eq!(
            s.set_favourite(ItemId::random().unwrap(), true),
            Err(CoreError::NotFound)
        );
    }

    #[test]
    fn trash_restore_delete_forever_flow() {
        let (mut s, clock) = created();
        let id = s.add_item(login("a", "x")).unwrap();
        clock.set_unix(1_700_000_003);
        s.trash(id).unwrap();
        let at = s.item(id).unwrap().trashed().unwrap();
        assert_eq!(at, Timestamp(1_700_000_003));
        assert_eq!(s.trash(id), Err(CoreError::InTrash));
        s.restore(id).unwrap();
        assert_eq!(s.item(id).unwrap().trashed(), None);
        s.trash(id).unwrap();
        s.delete_forever(id).unwrap();
        assert_eq!(s.item(id).err(), Some(CoreError::NotFound));
        assert_eq!(s.trash(id), Err(CoreError::NotFound));
        assert!(!s.is_dirty());
    }

    #[test]
    fn delete_forever_requires_trash() {
        let (mut s, _) = created();
        let id = s.add_item(login("a", "x")).unwrap();
        assert_eq!(s.delete_forever(id), Err(CoreError::NotInTrash));
        assert_eq!(s.restore(id), Err(CoreError::NotInTrash));
        assert_eq!(
            s.delete_forever(ItemId::random().unwrap()),
            Err(CoreError::NotFound)
        );
        assert_eq!(count(&s), 1);
    }

    #[test]
    fn empty_trash_counts() {
        let (mut s, _) = created();
        assert_eq!(s.empty_trash().unwrap(), 0);
        let a = s.add_item(login("a", "x")).unwrap();
        let b = s.add_item(login("b", "x")).unwrap();
        let keep = s.add_item(login("keep", "x")).unwrap();
        s.trash(a).unwrap();
        s.trash(b).unwrap();
        assert_eq!(s.empty_trash().unwrap(), 2);
        assert_eq!(count(&s), 1);
        assert!(s.item(keep).is_ok());
        assert_eq!(s.empty_trash().unwrap(), 0);
        s.lock();
        s.unlock(&pw(PW)).unwrap();
        assert_eq!(count(&s), 1);
    }

    #[test]
    fn deleted_forever_secret_absent_from_new_file() {
        let needle = b"EXAMPLE-zq9-unique";
        let (mut s, _) = created();
        let id = s.add_item(login("a", "EXAMPLE-zq9-unique")).unwrap();
        let (_, plain) = envelope::open(&stored(&s), &pw(PW)).unwrap();
        assert!(plain.expose().windows(needle.len()).any(|w| w == needle));
        drop(plain);
        s.trash(id).unwrap();
        s.delete_forever(id).unwrap();
        let (_, plain) = envelope::open(&stored(&s), &pw(PW)).unwrap();
        assert!(!plain.expose().windows(needle.len()).any(|w| w == needle));
        assert_eq!(open_file(&stored(&s), PW).item_count(), 0);
    }

    #[test]
    fn item_limit() {
        let (mut s, _) = created();
        for _ in 0..MAX_ITEMS {
            data_mut(&mut s).items.push(seed_item(note("n", "b")));
        }
        assert_eq!(
            s.add_item(note("one more", "b")),
            Err(CoreError::TooManyItems)
        );
        assert_eq!(count(&s), MAX_ITEMS);
        assert!(!s.is_dirty());
    }

    /// Seeds big logins until fewer than one more fits. Returns (the seeded session's
    /// size of one big login, ids of seeded items).
    fn fill_to_the_brim(s: &mut S) -> (usize, Vec<ItemId>) {
        let base = data_mut(s).encode().unwrap().expose().len();
        data_mut(s).items.push(seed_item(big_login("probe")));
        let with_one = data_mut(s).encode().unwrap().expose().len();
        data_mut(s).items.clear();
        let size = with_one - base;
        let n = (MAX_BODY_LEN - base) / size;
        let mut ids = Vec::new();
        for i in 0..n {
            let item = seed_item(big_login(&format!("big {i}")));
            ids.push(item.id);
            data_mut(s).items.push(item);
        }
        let len = data_mut(s).encode().unwrap().expose().len();
        assert!(len <= MAX_BODY_LEN);
        assert!(len + size > MAX_BODY_LEN);
        (size, ids)
    }

    #[test]
    fn oversize_change_rolled_back() {
        let (mut s, _) = created();
        let (_, _) = fill_to_the_brim(&mut s);
        let before_count = count(&s);
        let before_bytes = stored(&s);
        assert_eq!(
            s.add_item(big_login("too much")),
            Err(CoreError::Vault(VaultError::TooLargeToSave))
        );
        assert_eq!(count(&s), before_count);
        assert!(!s.is_dirty());
        assert_eq!(stored(&s), before_bytes);
    }

    #[test]
    fn undo_keeps_earlier_unsaved_edit() {
        let (mut s, _) = created();
        let (_, ids) = fill_to_the_brim(&mut s);
        let first = ids[0];
        s.store.fail_next_write = Some(StoreError::Io(ErrorKind::StorageFull));
        assert_eq!(
            s.set_favourite(first, true),
            Err(CoreError::Store(StoreError::Io(ErrorKind::StorageFull)))
        );
        assert!(s.is_dirty());
        let before_count = count(&s);
        assert_eq!(
            s.add_item(big_login("too much")),
            Err(CoreError::Vault(VaultError::TooLargeToSave))
        );
        assert_eq!(count(&s), before_count);
        assert!(s.item(first).unwrap().favourite());
        assert!(s.is_dirty());
        assert!(s.lock().discarded_unsaved);
    }

    #[test]
    fn weakening_settings_needs_password() {
        let (mut s, _) = created();
        let mut weaker = s.settings().unwrap().clone();
        weaker.auto_lock_secs = 600;
        assert_eq!(
            s.update_settings(weaker.clone(), None),
            Err(CoreError::PasswordRequired)
        );
        assert_eq!(s.settings().unwrap().auto_lock_secs, 300);
        assert_eq!(
            s.update_settings(weaker.clone(), Some(&pw(WRONG))),
            Err(CoreError::WrongPassword)
        );
        assert_eq!(failures(&s), 1);
        assert_eq!(s.settings().unwrap().auto_lock_secs, 300);
        s.update_settings(weaker, Some(&pw(PW))).unwrap();
        assert_eq!(s.settings().unwrap().auto_lock_secs, 600);
        s.lock();
        s.unlock(&pw(PW)).unwrap();
        assert_eq!(s.settings().unwrap().auto_lock_secs, 600);
    }

    #[test]
    fn strengthening_needs_no_password() {
        let (mut s, _) = created();
        let mut stronger: Settings = s.settings().unwrap().clone();
        stronger.auto_lock_secs = 120;
        stronger.clipboard_clear_secs = 10;
        s.update_settings(stronger, None).unwrap();
        assert_eq!(s.settings().unwrap().auto_lock_secs, 120);
        assert_eq!(s.settings().unwrap().clipboard_clear_secs, 10);
        assert!(!s.is_dirty());
    }

    #[test]
    fn invalid_settings_rejected() {
        let (mut s, _) = created();
        let mut bad = s.settings().unwrap().clone();
        bad.auto_lock_secs = 10;
        assert_eq!(
            s.update_settings(bad, None),
            Err(CoreError::Settings(SettingsError::AutoLockOutOfRange))
        );
        assert_eq!(s.settings().unwrap().auto_lock_secs, 300);
    }

    #[test]
    fn reveal_phrase_is_gated_and_throttled() {
        let (mut s, clock) = created();
        let p = s.add_item(phrase("p", "alpha beta")).unwrap();
        for _ in 0..FREE_FAILURES {
            assert_eq!(
                s.reveal_phrase(p, &pw(WRONG)).unwrap_err(),
                CoreError::WrongPassword
            );
        }
        assert!(matches!(
            s.reveal_phrase(p, &pw(PW)),
            Err(CoreError::Throttled { .. })
        ));
        clock.advance(secs(2));
        assert_eq!(s.reveal_phrase(p, &pw(PW)).unwrap(), "alpha beta");
    }

    #[test]
    fn reveal_on_login_is_not_a_phrase() {
        let (mut s, _) = created();
        let l = s.add_item(login("a", "x")).unwrap();
        assert_eq!(
            s.reveal_phrase(l, &pw(WRONG)).unwrap_err(),
            CoreError::NotAPhrase
        );
        assert_eq!(failures(&s), 0);
        assert_eq!(
            s.reveal_phrase(ItemId::random().unwrap(), &pw(PW))
                .unwrap_err(),
            CoreError::NotFound
        );
    }

    #[test]
    fn mutations_when_locked_return_locked() {
        let (mut s, _) = created_locked();
        let id = ItemId::random().unwrap();
        assert_eq!(s.add_item(login("a", "x")), Err(CoreError::Locked));
        assert_eq!(s.update_item(id, login("a", "x")), Err(CoreError::Locked));
        assert_eq!(s.set_favourite(id, true), Err(CoreError::Locked));
        assert_eq!(s.trash(id), Err(CoreError::Locked));
        assert_eq!(s.restore(id), Err(CoreError::Locked));
        assert_eq!(s.delete_forever(id), Err(CoreError::Locked));
        assert_eq!(s.empty_trash(), Err(CoreError::Locked));
        assert_eq!(s.item(id).err(), Some(CoreError::Locked));
        assert_eq!(s.settings().err(), Some(CoreError::Locked));
        assert_eq!(
            s.update_settings(Settings::default(), None),
            Err(CoreError::Locked)
        );
        assert_eq!(s.reveal_phrase(id, &pw(PW)).unwrap_err(), CoreError::Locked);
    }

    // Keep these names used so the shared helper imports stay honest.
    #[test]
    fn helpers_are_wired() {
        let _ = (NEW_PW, FLOOR, session as fn() -> _, None::<CategoryId>);
    }
}
