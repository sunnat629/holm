//! Category operations on an unlocked [`Session`]. Built-in categories are ordinary
//! categories here: they rename and delete like any other.

use super::Session;
use crate::category::{Category, CategoryId, MAX_CATEGORIES, name_key, validate_category_name};
use crate::error::CoreError;
use crate::store::VaultStore;
use crate::text::Text;

impl<S: VaultStore> Session<S> {
    /// All categories, in order.
    ///
    /// # Errors
    /// [`CoreError::Locked`].
    pub fn categories(&self) -> Result<&[Category], CoreError> {
        Ok(&self.unlocked()?.data.categories)
    }

    /// Adds a category and saves.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Field`], [`CoreError::CategoryNameTaken`],
    /// [`CoreError::TooManyCategories`], or the errors of a save.
    pub fn add_category(&mut self, name: &str) -> Result<CategoryId, CoreError> {
        self.unlocked()?;
        validate_category_name(name)?;
        let data = &mut self.unlocked_mut()?.data;
        if data.categories.len() >= MAX_CATEGORIES {
            return Err(CoreError::TooManyCategories);
        }
        let key = name_key(name);
        if data.categories.iter().any(|c| *name_key(c.name()) == *key) {
            return Err(CoreError::CategoryNameTaken);
        }
        let old_next = data.next_category_id;
        let next = old_next
            .checked_add(1)
            .ok_or(CoreError::TooManyCategories)?;
        let id = CategoryId(old_next);
        data.categories.push(Category {
            id,
            name: Text::new(name.trim().to_owned()),
        });
        data.next_category_id = next;
        self.commit_or_undo(move |d| {
            d.categories.pop();
            d.next_category_id = old_next;
        })?;
        Ok(id)
    }

    /// Renames a category and saves.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Field`], [`CoreError::UnknownCategory`],
    /// [`CoreError::CategoryNameTaken`], or the errors of a save.
    pub fn rename_category(&mut self, id: CategoryId, name: &str) -> Result<(), CoreError> {
        self.unlocked()?;
        validate_category_name(name)?;
        let data = &mut self.unlocked_mut()?.data;
        let pos = data
            .categories
            .iter()
            .position(|c| c.id == id)
            .ok_or(CoreError::UnknownCategory)?;
        let key = name_key(name);
        if data
            .categories
            .iter()
            .any(|c| c.id != id && *name_key(c.name()) == *key)
        {
            return Err(CoreError::CategoryNameTaken);
        }
        let old = std::mem::replace(
            &mut data.categories[pos].name,
            Text::new(name.trim().to_owned()),
        );
        self.commit_or_undo(move |d| d.categories[pos].name = old)
    }

    /// Deletes a category and saves. Its items (trashed ones too) become
    /// uncategorised. Returns how many items moved.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::UnknownCategory`], or the errors of a save.
    pub fn delete_category(&mut self, id: CategoryId) -> Result<usize, CoreError> {
        let data = &mut self.unlocked_mut()?.data;
        let pos = data
            .categories
            .iter()
            .position(|c| c.id == id)
            .ok_or(CoreError::UnknownCategory)?;
        let cat = data.categories.remove(pos);
        let mut moved: Vec<usize> = Vec::new();
        for (i, item) in data.items.iter_mut().enumerate() {
            if item.category == Some(id) {
                item.category = None;
                moved.push(i);
            }
        }
        let n = moved.len();
        self.commit_or_undo(move |d| {
            d.categories.insert(pos, cat);
            for i in moved {
                d.items[i].category = Some(id);
            }
        })?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{PW, created, created_locked, pw};
    use crate::category::{MAX_CATEGORIES, UNCATEGORISED};
    use crate::error::CoreError;
    use crate::item::{ItemData, ItemInput};
    use crate::rules::{Field, FieldError};
    use crate::text::{SecretText, Text};

    fn note_in(title: &str, category: Option<crate::category::CategoryId>) -> ItemInput {
        ItemInput {
            fields: Vec::new(),
            title: Text::new(title.to_owned()),
            category,
            favourite: false,
            data: ItemData::SecureNote {
                body: SecretText::new("body".to_owned()),
            },
        }
    }

    fn names(s: &super::super::Session<crate::store::MemStore>) -> Vec<String> {
        s.categories()
            .unwrap()
            .iter()
            .map(|c| c.name().to_owned())
            .collect()
    }

    fn id_of(
        s: &super::super::Session<crate::store::MemStore>,
        name: &str,
    ) -> crate::category::CategoryId {
        s.categories()
            .unwrap()
            .iter()
            .find(|c| c.name() == name)
            .unwrap()
            .id()
    }

    #[test]
    fn delete_category_moves_items_including_trashed() {
        let (mut s, _) = created();
        let cat = s.add_category("Trips").unwrap();
        let live = s.add_item(note_in("live", Some(cat))).unwrap();
        let gone = s.add_item(note_in("gone", Some(cat))).unwrap();
        s.trash(gone).unwrap();
        assert_eq!(s.delete_category(cat).unwrap(), 2);
        assert_eq!(s.item(live).unwrap().category(), None);
        assert_eq!(s.item(gone).unwrap().category(), None);
        s.restore(gone).unwrap();
        assert_eq!(s.item(gone).unwrap().category(), None);
        assert!(!names(&s).contains(&"Trips".to_owned()));
        assert_eq!(s.delete_category(cat), Err(CoreError::UnknownCategory));
    }

    #[test]
    fn built_in_categories_rename_and_delete() {
        let (mut s, _) = created();
        let work = id_of(&s, "Work");
        let personal = id_of(&s, "Personal");
        let item = s.add_item(note_in("p", Some(personal))).unwrap();
        s.rename_category(work, "Office").unwrap();
        assert_eq!(s.delete_category(personal).unwrap(), 1);
        assert_eq!(s.item(item).unwrap().category(), None);
        s.lock();
        s.unlock(&pw(PW)).unwrap();
        let n = names(&s);
        assert!(n.contains(&"Office".to_owned()));
        assert!(!n.contains(&"Work".to_owned()));
        assert!(!n.contains(&"Personal".to_owned()));
        assert_eq!(s.item(item).unwrap().category(), None);
    }

    #[test]
    fn category_names_unique() {
        let (mut s, _) = created();
        assert_eq!(s.add_category("work"), Err(CoreError::CategoryNameTaken));
        s.add_category("Caf\u{e9}").unwrap();
        assert_eq!(
            s.add_category("CAFE\u{301}"),
            Err(CoreError::CategoryNameTaken)
        );
        let work = id_of(&s, "Work");
        let community = id_of(&s, "Community");
        assert_eq!(
            s.rename_category(community, " WORK "),
            Err(CoreError::CategoryNameTaken)
        );
        // Renaming to a different case of its own name is allowed.
        s.rename_category(work, "WORK").unwrap();
        assert_eq!(id_of(&s, "WORK"), work);
    }

    #[test]
    fn uncategorised_is_reserved() {
        let (mut s, _) = created();
        let expect = || CoreError::Field(FieldError::Reserved(Field::CategoryName));
        assert_eq!(s.add_category(UNCATEGORISED), Err(expect()));
        assert_eq!(s.add_category(" uncategorised "), Err(expect()));
        let work = id_of(&s, "Work");
        assert_eq!(s.rename_category(work, UNCATEGORISED), Err(expect()));
        assert_eq!(
            s.add_category(" "),
            Err(CoreError::Field(FieldError::Empty(Field::CategoryName)))
        );
    }

    #[test]
    fn category_limit() {
        let (mut s, _) = created();
        let have = s.categories().unwrap().len();
        for i in have..MAX_CATEGORIES {
            s.add_category(&format!("cat {i}")).unwrap();
        }
        assert_eq!(s.categories().unwrap().len(), MAX_CATEGORIES);
        assert_eq!(
            s.add_category("one too many"),
            Err(CoreError::TooManyCategories)
        );
        assert_eq!(s.categories().unwrap().len(), MAX_CATEGORIES);
    }

    #[test]
    fn category_id_overflow_is_too_many() {
        let (mut s, _) = created();
        s.unlocked_mut().unwrap().data.next_category_id = u32::MAX;
        assert_eq!(s.add_category("late"), Err(CoreError::TooManyCategories));
        assert_eq!(s.categories().unwrap().len(), 3);
    }

    #[test]
    fn unknown_category_rejected() {
        let (mut s, _) = created();
        let cat = s.add_category("Temp").unwrap();
        s.delete_category(cat).unwrap();
        assert_eq!(
            s.add_item(note_in("x", Some(cat))),
            Err(CoreError::UnknownCategory)
        );
        assert_eq!(
            s.rename_category(cat, "Other"),
            Err(CoreError::UnknownCategory)
        );
        let ok = s.add_item(note_in("y", None)).unwrap();
        assert_eq!(
            s.update_item(ok, note_in("y", Some(cat))),
            Err(CoreError::UnknownCategory)
        );
    }

    #[test]
    fn category_calls_when_locked_return_locked() {
        let (mut s, _) = created_locked();
        assert_eq!(s.categories().map(|c| c.len()), Err(CoreError::Locked));
        assert_eq!(s.add_category("x"), Err(CoreError::Locked));
    }
}
