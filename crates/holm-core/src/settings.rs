//! Security settings: auto-lock, clipboard clearing, lock on sleep and the generator
//! defaults.
//!
//! These live inside the encrypted body, so nobody can weaken them by editing a file.
//! The ranges are fixed by the spec (section 10): auto-lock at most 60 minutes with no
//! "Never", clipboard clearing at most 90 seconds. Making a setting weaker (see
//! [`Settings::is_weaker_than`]) needs the master password again.
//!
//! [`Settings`] has no `Serialize` or `Deserialize`. The body codec writes it through a
//! crate-private wire type, so the only way in from bytes is the checked decoder.

use crate::generator::{GeneratorError, PassphraseSpec, PasswordSpec, UsernameSpec};

/// Shortest auto-lock time in seconds.
pub const AUTO_LOCK_MIN_SECS: u32 = 60;
/// Longest auto-lock time in seconds (60 minutes). There is no "Never".
pub const AUTO_LOCK_MAX_SECS: u32 = 3600;
/// Auto-lock time for a new vault (5 minutes).
pub const AUTO_LOCK_DEFAULT_SECS: u32 = 300;
/// Shortest clipboard clear time in seconds.
pub const CLIPBOARD_MIN_SECS: u32 = 5;
/// Longest clipboard clear time in seconds.
pub const CLIPBOARD_MAX_SECS: u32 = 90;
/// Clipboard clear time for a new vault.
pub const CLIPBOARD_DEFAULT_SECS: u32 = 30;
/// A revealed password hides again after this many seconds. Fixed, not a setting.
pub const REHIDE_PASSWORD_SECS: u32 = 30;
/// A revealed recovery phrase hides again after this many seconds. Fixed, not a setting.
pub const REHIDE_PHRASE_SECS: u32 = 60;

/// Why a [`Settings`] value was refused. Carries no secret data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    /// Auto-lock is outside 60 to 3600 seconds.
    #[error("auto-lock must be between 60 and 3600 seconds")]
    AutoLockOutOfRange,
    /// Clipboard clearing is outside 5 to 90 seconds.
    #[error("clipboard clearing must be between 5 and 90 seconds")]
    ClipboardOutOfRange,
    /// A generator default is invalid.
    #[error("invalid generator setting: {0}")]
    Generator(GeneratorError),
}

/// The vault's security settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Lock after this many idle seconds, [`AUTO_LOCK_MIN_SECS`] to [`AUTO_LOCK_MAX_SECS`].
    pub auto_lock_secs: u32,
    /// Clear a copied value after this many seconds, [`CLIPBOARD_MIN_SECS`] to
    /// [`CLIPBOARD_MAX_SECS`].
    pub clipboard_clear_secs: u32,
    /// Lock when the computer sleeps.
    pub lock_on_sleep: bool,
    /// Default password generator spec.
    pub password: PasswordSpec,
    /// Default passphrase generator spec.
    pub passphrase: PassphraseSpec,
    /// Default username generator spec.
    pub username: UsernameSpec,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            auto_lock_secs: AUTO_LOCK_DEFAULT_SECS,
            clipboard_clear_secs: CLIPBOARD_DEFAULT_SECS,
            lock_on_sleep: true,
            password: PasswordSpec::DEFAULT,
            passphrase: PassphraseSpec::DEFAULT,
            username: UsernameSpec::DEFAULT,
        }
    }
}

impl Settings {
    /// Checks every setting against its range.
    ///
    /// # Errors
    /// Returns the first [`SettingsError`] found: auto-lock, then clipboard, then the
    /// password, passphrase and username specs.
    pub fn validate(&self) -> Result<(), SettingsError> {
        if !(AUTO_LOCK_MIN_SECS..=AUTO_LOCK_MAX_SECS).contains(&self.auto_lock_secs) {
            return Err(SettingsError::AutoLockOutOfRange);
        }
        if !(CLIPBOARD_MIN_SECS..=CLIPBOARD_MAX_SECS).contains(&self.clipboard_clear_secs) {
            return Err(SettingsError::ClipboardOutOfRange);
        }
        self.password.validate().map_err(SettingsError::Generator)?;
        self.passphrase
            .validate()
            .map_err(SettingsError::Generator)?;
        self.username.validate().map_err(SettingsError::Generator)?;
        Ok(())
    }

    /// True if moving from `current` to `self` weakens security, so it needs the
    /// master password: a longer auto-lock or clipboard time, lock on sleep turned off,
    /// or a lower password or passphrase entropy. Username changes never count.
    #[must_use]
    pub fn is_weaker_than(&self, current: &Settings) -> bool {
        self.auto_lock_secs > current.auto_lock_secs
            || self.clipboard_clear_secs > current.clipboard_clear_secs
            || (current.lock_on_sleep && !self.lock_on_sleep)
            || self.password.entropy_bits() < current.password.entropy_bits()
            || self.passphrase.entropy_bits() < current.passphrase.entropy_bits()
    }

    /// Brings every setting into its range: both times are clamped, and an invalid
    /// generator spec is replaced by its `DEFAULT`. Used on load, so a vault never
    /// becomes unopenable over a setting (`docs/DECISIONS.md`).
    pub(crate) fn clamp_to_policy(&mut self) {
        self.auto_lock_secs = self
            .auto_lock_secs
            .clamp(AUTO_LOCK_MIN_SECS, AUTO_LOCK_MAX_SECS);
        self.clipboard_clear_secs = self
            .clipboard_clear_secs
            .clamp(CLIPBOARD_MIN_SECS, CLIPBOARD_MAX_SECS);
        if self.password.validate().is_err() {
            self.password = PasswordSpec::DEFAULT;
        }
        if self.passphrase.validate().is_err() {
            self.passphrase = PassphraseSpec::DEFAULT;
        }
        if self.username.validate().is_err() {
            self.username = UsernameSpec::DEFAULT;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(Settings: serde::Serialize, serde::de::DeserializeOwned);

    #[test]
    fn defaults_exact() {
        let s = Settings::default();
        assert_eq!(s.auto_lock_secs, 300);
        assert_eq!(s.clipboard_clear_secs, 30);
        assert!(s.lock_on_sleep);
        assert_eq!(s.password, PasswordSpec::DEFAULT);
        assert_eq!(s.passphrase, PassphraseSpec::DEFAULT);
        assert_eq!(s.username, UsernameSpec::DEFAULT);
        assert_eq!(s.validate(), Ok(()));
        assert_eq!((REHIDE_PASSWORD_SECS, REHIDE_PHRASE_SECS), (30, 60));
    }

    #[test]
    fn validate_ranges() {
        let with = |auto, clip| Settings {
            auto_lock_secs: auto,
            clipboard_clear_secs: clip,
            ..Settings::default()
        };
        assert_eq!(
            with(59, 30).validate(),
            Err(SettingsError::AutoLockOutOfRange)
        );
        assert_eq!(
            with(3601, 30).validate(),
            Err(SettingsError::AutoLockOutOfRange)
        );
        assert_eq!(
            with(300, 4).validate(),
            Err(SettingsError::ClipboardOutOfRange)
        );
        assert_eq!(
            with(300, 91).validate(),
            Err(SettingsError::ClipboardOutOfRange)
        );
        for (auto, clip) in [(60, 5), (3600, 90), (60, 90), (3600, 5)] {
            assert_eq!(with(auto, clip).validate(), Ok(()));
        }
        let bad_gen = Settings {
            password: PasswordSpec {
                length: 3,
                ..PasswordSpec::DEFAULT
            },
            ..Settings::default()
        };
        assert_eq!(
            bad_gen.validate(),
            Err(SettingsError::Generator(GeneratorError::LengthOutOfRange))
        );
    }

    #[test]
    fn weaker_table() {
        let base = Settings::default();
        let auto = |n| Settings {
            auto_lock_secs: n,
            ..Settings::default()
        };
        assert!(auto(600).is_weaker_than(&auto(300)));
        assert!(!auto(300).is_weaker_than(&auto(600)));
        let clip = Settings {
            clipboard_clear_secs: 60,
            ..Settings::default()
        };
        assert!(clip.is_weaker_than(&base));
        let sleep_off = Settings {
            lock_on_sleep: false,
            ..Settings::default()
        };
        assert!(sleep_off.is_weaker_than(&base));
        assert!(!base.is_weaker_than(&sleep_off));
        let pw16 = Settings {
            password: PasswordSpec {
                length: 16,
                ..PasswordSpec::DEFAULT
            },
            ..Settings::default()
        };
        assert!(pw16.is_weaker_than(&base));
        let words7 = Settings {
            passphrase: PassphraseSpec {
                words: 7,
                ..PassphraseSpec::DEFAULT
            },
            ..Settings::default()
        };
        assert!(!words7.is_weaker_than(&base));
        assert!(base.is_weaker_than(&words7));
        let user = Settings {
            username: UsernameSpec {
                words: 1,
                digits: 0,
            },
            ..Settings::default()
        };
        assert!(!user.is_weaker_than(&base));
        assert!(!base.is_weaker_than(&user));
        assert!(!base.is_weaker_than(&base.clone()));
    }

    #[test]
    fn clamp_brings_everything_into_range() {
        let mut s = Settings {
            auto_lock_secs: 0,
            clipboard_clear_secs: 1000,
            lock_on_sleep: false,
            password: PasswordSpec {
                length: 3,
                ..PasswordSpec::DEFAULT
            },
            passphrase: PassphraseSpec {
                words: 1,
                ..PassphraseSpec::DEFAULT
            },
            username: UsernameSpec {
                words: 9,
                digits: 0,
            },
        };
        s.clamp_to_policy();
        assert_eq!(s.auto_lock_secs, AUTO_LOCK_MIN_SECS);
        assert_eq!(s.clipboard_clear_secs, CLIPBOARD_MAX_SECS);
        assert!(!s.lock_on_sleep, "a bool has no range and is kept");
        assert_eq!(s.password, PasswordSpec::DEFAULT);
        assert_eq!(s.passphrase, PassphraseSpec::DEFAULT);
        assert_eq!(s.username, UsernameSpec::DEFAULT);
        assert_eq!(s.validate(), Ok(()));

        let mut valid = Settings {
            auto_lock_secs: 3600,
            clipboard_clear_secs: 5,
            ..Settings::default()
        };
        let before = valid.clone();
        valid.clamp_to_policy();
        assert_eq!(valid, before, "a valid value is never changed");
    }
}
