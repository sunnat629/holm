//! [`CoreError`]: the one error type of the vault session.
//!
//! Every session method returns it, so a UI matches on one enum. The lower-level
//! errors convert into it with `From`, which lets the session use `?` throughout. No
//! variant carries a password, a key or vault content.

use holm_crypto::CryptoError;

use crate::body::BodyError;
use crate::envelope::VaultError;
use crate::rules::FieldError;
use crate::settings::SettingsError;
use crate::store::StoreError;
use crate::strength::StrengthVerdict;

/// Everything that can go wrong in a vault session.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    /// The vault is locked; unlock it first.
    #[error("the vault is locked")]
    Locked,
    /// The vault is already unlocked.
    #[error("the vault is already unlocked")]
    AlreadyUnlocked,
    /// There is no vault file to unlock.
    #[error("no vault was found")]
    NoVault,
    /// A file already exists where a new vault or backup was to be written. It was
    /// not changed.
    #[error("a file already exists there, and it was not changed")]
    VaultExists,
    /// The vault file could not be opened or sealed.
    #[error("{}", vault_message(.0))]
    Vault(VaultError),
    /// Reading or writing the vault file failed.
    #[error("{0}")]
    Store(StoreError),
    /// Writing the vault under the new master password reported this error, but the
    /// new file may be in place anyway. The session now holds the new keys and is
    /// dirty, so the next save writes the vault under the new password again.
    #[error(
        "{0}; the password change may still have been saved, so the new master \
         password may now be required"
    )]
    PasswordChangeUncertain(StoreError),
    /// The decrypted body could not be decoded, or the data could not be encoded.
    #[error("{0}")]
    Body(BodyError),
    /// Too many failed attempts; the next one is allowed after this many seconds.
    #[error("too many failed attempts; try again in {retry_after_secs} s")]
    Throttled {
        /// Seconds to wait, rounded up.
        retry_after_secs: u64,
    },
    /// The master password given to confirm an action is wrong.
    #[error("that password is wrong")]
    WrongPassword,
    /// This change needs the master password.
    #[error("this change needs the master password")]
    PasswordRequired,
    /// The new master password is too easy to guess. The verdict holds numbers only
    /// (score, character count, verdict flag), never the password, so its `Debug` output is safe.
    #[error("this master password is too easy to guess")]
    WeakPassword(StrengthVerdict),
    /// No item has that id.
    #[error("no such item")]
    NotFound,
    /// No category has that id.
    #[error("no such category")]
    UnknownCategory,
    /// The item is in the trash.
    #[error("the item is in the trash")]
    InTrash,
    /// The item is not in the trash.
    #[error("the item is not in the trash")]
    NotInTrash,
    /// An item's type cannot be changed.
    #[error("an item's type cannot be changed")]
    TypeChange,
    /// The item is not a recovery phrase.
    #[error("the item is not a recovery phrase")]
    NotAPhrase,
    /// Another category already has that name.
    #[error("a category with that name already exists")]
    CategoryNameTaken,
    /// The vault has the most categories allowed.
    #[error("the vault has the most categories allowed")]
    TooManyCategories,
    /// The vault has the most items allowed.
    #[error("the vault has the most items allowed")]
    TooManyItems,
    /// A field breaks its rule.
    #[error("{0}")]
    Field(FieldError),
    /// A setting is out of range.
    #[error("{0}")]
    Settings(SettingsError),
}

/// The text for [`CoreError::Vault`]. The opaque open failure gets the full sentence
/// the unlock screen shows; every other vault error keeps its own message.
fn vault_message(e: &VaultError) -> String {
    match e {
        VaultError::WrongPasswordOrCorrupt => "That password didn't open this vault. Either \
             the password is wrong, or the file was changed or damaged."
            .to_owned(),
        other => other.to_string(),
    }
}

impl From<VaultError> for CoreError {
    fn from(e: VaultError) -> Self {
        CoreError::Vault(e)
    }
}

/// Through [`VaultError::from`], so a crypto failure gets the same mapping as in the
/// envelope: `ItemId::random()?` gives `Vault(Crypto)`, and a refused Argon2 work area
/// gives `Vault(OutOfMemory)`.
impl From<CryptoError> for CoreError {
    fn from(e: CryptoError) -> Self {
        CoreError::Vault(VaultError::from(e))
    }
}

impl From<StoreError> for CoreError {
    fn from(e: StoreError) -> Self {
        CoreError::Store(e)
    }
}

impl From<BodyError> for CoreError {
    fn from(e: BodyError) -> Self {
        CoreError::Body(e)
    }
}

impl From<FieldError> for CoreError {
    fn from(e: FieldError) -> Self {
        CoreError::Field(e)
    }
}

impl From<SettingsError> for CoreError {
    fn from(e: SettingsError) -> Self {
        CoreError::Settings(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Field;

    #[test]
    fn opaque_open_failure_has_the_unlock_screen_text() {
        assert_eq!(
            CoreError::Vault(VaultError::WrongPasswordOrCorrupt).to_string(),
            "That password didn't open this vault. Either the password is wrong, or the \
             file was changed or damaged."
        );
        assert_eq!(
            CoreError::Vault(VaultError::BadPadding).to_string(),
            VaultError::BadPadding.to_string()
        );
    }

    #[test]
    fn conversions_land_in_the_right_variant() {
        assert_eq!(
            CoreError::from(CryptoError::OutOfMemory),
            CoreError::Vault(VaultError::OutOfMemory)
        );
        assert_eq!(
            CoreError::from(CryptoError::Rng),
            CoreError::Vault(VaultError::Crypto)
        );
        assert_eq!(
            CoreError::from(CryptoError::Aead),
            CoreError::Vault(VaultError::WrongPasswordOrCorrupt)
        );
        assert_eq!(
            CoreError::from(StoreError::NotFound),
            CoreError::Store(StoreError::NotFound)
        );
        assert_eq!(
            CoreError::from(BodyError::Malformed),
            CoreError::Body(BodyError::Malformed)
        );
        assert_eq!(
            CoreError::from(FieldError::Empty(Field::Title)),
            CoreError::Field(FieldError::Empty(Field::Title))
        );
        assert_eq!(
            CoreError::from(SettingsError::AutoLockOutOfRange),
            CoreError::Settings(SettingsError::AutoLockOutOfRange)
        );
    }

    #[test]
    fn item_id_random_question_mark_gives_core_error() {
        fn make() -> Result<crate::item::ItemId, CoreError> {
            Ok(crate::item::ItemId::random()?)
        }
        assert!(make().is_ok());
    }
}
