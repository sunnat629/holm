//! Categories and the category-name rules.

use crate::rules::{Field, FieldError, is_forbidden_display_char};
use crate::text::{Text, fold};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Names of the categories a new vault starts with. They can be edited and deleted.
pub const BUILT_IN_CATEGORIES: [&str; 3] = ["Personal", "Work", "Community"];
/// The label for items with no category. It is reserved and cannot name a category.
pub const UNCATEGORISED: &str = "Uncategorised";
/// Most categories one vault may hold.
pub const MAX_CATEGORIES: usize = 256;
/// Longest category name in characters.
pub const MAX_CATEGORY_NAME_CHARS: usize = 64;

/// Identifier of a category within one vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CategoryId(pub(crate) u32);

/// A named category.
pub struct Category {
    pub(crate) id: CategoryId,
    pub(crate) name: Text,
}

impl Category {
    /// The category id.
    #[must_use]
    pub fn id(&self) -> CategoryId {
        self.id
    }
    /// The category name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

/// The key two names are compared by: trimmed, NFC, lowercase.
pub(crate) fn name_key(name: &str) -> Zeroizing<String> {
    fold(name.trim())
}

/// Checks a category name: not blank, display-field characters only, at most
/// [`MAX_CATEGORY_NAME_CHARS`] characters as given, and not [`UNCATEGORISED`].
///
/// # Errors
/// Returns the [`FieldError`] for the first rule broken.
pub fn validate_category_name(name: &str) -> Result<(), FieldError> {
    if name.trim().is_empty() {
        return Err(FieldError::Empty(Field::CategoryName));
    }
    if name.chars().any(is_forbidden_display_char) {
        return Err(FieldError::ForbiddenChar(Field::CategoryName));
    }
    if name.chars().count() > MAX_CATEGORY_NAME_CHARS {
        return Err(FieldError::TooLong(Field::CategoryName));
    }
    if *name_key(name) == *name_key(UNCATEGORISED) {
        return Err(FieldError::Reserved(Field::CategoryName));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(Category: serde::Serialize, serde::de::DeserializeOwned);

    #[test]
    fn category_name_rules() {
        assert_eq!(
            validate_category_name(""),
            Err(FieldError::Empty(Field::CategoryName))
        );
        assert_eq!(
            validate_category_name("  "),
            Err(FieldError::Empty(Field::CategoryName))
        );
        assert_eq!(validate_category_name(&"a".repeat(64)), Ok(()));
        assert_eq!(
            validate_category_name(&"a".repeat(65)),
            Err(FieldError::TooLong(Field::CategoryName))
        );
        assert_eq!(
            validate_category_name("uncategorised"),
            Err(FieldError::Reserved(Field::CategoryName))
        );
        assert_eq!(
            validate_category_name(" UNCATEGORISED "),
            Err(FieldError::Reserved(Field::CategoryName))
        );
        assert_eq!(
            validate_category_name("Work\u{202E}"),
            Err(FieldError::ForbiddenChar(Field::CategoryName))
        );
        assert_eq!(validate_category_name("Family"), Ok(()));
    }

    #[test]
    fn name_key_folds_case_and_composition() {
        assert_eq!(*name_key("Café"), *name_key(" CAFE\u{301} "));
    }

    #[test]
    fn built_ins_are_valid() {
        for n in BUILT_IN_CATEGORIES {
            assert_eq!(validate_category_name(n), Ok(()));
        }
    }
}
