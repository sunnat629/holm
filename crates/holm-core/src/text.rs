//! Text types that wipe their memory on drop and never print their contents.
//!
//! [`Text`] is for display fields (title, username, URL, chain). [`SecretText`] is for
//! secrets. [`GatedSecret`] is a secret with no public accessor: only code inside this
//! crate can read it, so the password gate cannot be bypassed from outside.

use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// A non-secret text field, wiped when dropped. `Debug` shows only the byte length.
#[derive(Clone)]
pub struct Text(Zeroizing<String>);

impl Text {
    /// Wraps `s`. The string is moved in, not copied.
    #[must_use]
    pub fn new(s: String) -> Text {
        Text(Zeroizing::new(s))
    }

    /// The text. Keep the borrow short.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when the text has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl PartialEq for Text {
    fn eq(&self, other: &Text) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Text {}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Text(len = {})", self.0.len())
    }
}

impl Serialize for Text {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Text, D::Error> {
        String::deserialize(deserializer).map(Text::new)
    }
}

/// A secret text field, wiped when dropped. No `Clone`, no `PartialEq`, and `Debug`
/// prints `[REDACTED]`.
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    /// Wraps `s`. The string is moved in, not copied.
    #[must_use]
    pub fn new(s: String) -> SecretText {
        SecretText(Zeroizing::new(s))
    }

    /// The secret. Keep the borrow short.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when the secret has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText([REDACTED])")
    }
}

impl Serialize for SecretText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<SecretText, D::Error> {
        String::deserialize(deserializer).map(SecretText::new)
    }
}

/// A secret that outside code can store and check for emptiness but never read.
/// Only this crate can call [`GatedSecret::expose`]; the session reveals it after a
/// password check.
pub struct GatedSecret(SecretText);

impl GatedSecret {
    /// Wraps a secret.
    #[must_use]
    pub fn new(secret: SecretText) -> GatedSecret {
        GatedSecret(secret)
    }

    /// True when the secret has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The secret, for the password-gated paths inside this crate only.
    #[allow(dead_code)] // first used by the session's reveal and export paths
    pub(crate) fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for GatedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatedSecret([REDACTED])")
    }
}

impl Serialize for GatedSecret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GatedSecret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<GatedSecret, D::Error> {
        SecretText::deserialize(deserializer).map(GatedSecret)
    }
}

/// Folds `s` for comparison and search: NFC, then lowercase, one character at a time.
/// The result is built in a buffer sized up front so it never reallocates (a
/// reallocation would leave an unwiped copy behind).
#[allow(dead_code)] // used by name_key now, and by search later
pub(crate) fn fold(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(3 * s.len()));
    for c in s.nfc() {
        out.extend(c.to_lowercase());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(SecretText: Clone, Copy);
    assert_not_impl_any!(GatedSecret: Clone, Copy);

    #[test]
    fn secret_text_debug_is_redacted() {
        let s = SecretText::new("EXAMPLE-secret".into());
        assert_eq!(format!("{s:?}"), "SecretText([REDACTED])");
    }

    #[test]
    fn text_debug_shows_len_only() {
        assert_eq!(format!("{:?}", Text::new("abcd".into())), "Text(len = 4)");
    }

    #[test]
    fn gated_debug_is_redacted() {
        let g = GatedSecret::new(SecretText::new("EXAMPLE-phrase".into()));
        assert_eq!(format!("{g:?}"), "GatedSecret([REDACTED])");
        assert!(!g.is_empty());
        assert_eq!(g.expose(), "EXAMPLE-phrase");
    }

    #[test]
    fn serde_is_a_plain_string() {
        let t = Text::new("EXAMPLE".into());
        assert_eq!(serde_json::to_string(&t).unwrap(), "\"EXAMPLE\"");
        let g: GatedSecret = serde_json::from_str("\"EXAMPLE\"").unwrap();
        assert_eq!(g.expose(), "EXAMPLE");
        let s: SecretText = serde_json::from_str("\"x\"").unwrap();
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"x\"");
    }

    #[test]
    fn fold_lowercases_and_composes() {
        assert_eq!(&*fold("CAFE\u{301}"), "caf\u{e9}");
    }
}
