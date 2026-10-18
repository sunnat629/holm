//! Password, passphrase and username generators.
//!
//! Randomness comes from the operating system through [`holm_crypto::fill_random`].
//! Every choice goes through [`uniform_below`], which uses rejection sampling so no
//! value is more likely than another. Generated secrets come back as [`SecretText`],
//! which wipes its memory when dropped. The spec types hold settings, not secrets.

use crate::text::{SecretText, Text};
use core::num::NonZeroU32;
use holm_crypto::CryptoError;
use std::sync::OnceLock;
use zeroize::Zeroizing;

/// Shortest allowed password.
pub const MIN_PASSWORD_LEN: u16 = 12;
/// Longest allowed password.
pub const MAX_PASSWORD_LEN: u16 = 128;
/// A password spec whose entropy is below this many bits is refused.
pub const MIN_ENTROPY_BITS: f64 = 64.0;
/// Fewest words in a passphrase.
pub const MIN_PASSPHRASE_WORDS: u8 = 6;
/// Most words in a passphrase.
pub const MAX_PASSPHRASE_WORDS: u8 = 20;
/// Characters that are easy to mix up when read by eye.
pub const LOOKALIKES: &str = "0Oo1lI|";
/// The 32 printable ASCII symbols.
pub const SYMBOLS: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
/// Number of words in the EFF large wordlist.
pub const WORDLIST_LEN: usize = 7776;
/// How many times the password generator retries to meet the minimums.
pub const MAX_ATTEMPTS: u32 = 10_000;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";

/// Why a spec was refused or a generator failed. Carries no secret data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GeneratorError {
    /// Password length is outside 12 to 128.
    #[error("password length must be between 12 and 128")]
    LengthOutOfRange,
    /// No character set is enabled.
    #[error("at least one character set must be enabled")]
    NoCharacterSets,
    /// A minimum was set for a character set that is turned off.
    #[error("a minimum is set for a disabled character set")]
    RequiredSetDisabled,
    /// The minimums add up to more than half the length.
    #[error("the required digits and symbols are more than half the length")]
    TooManyRequired,
    /// The spec would give fewer than 64 bits of entropy.
    #[error("the spec gives less than 64 bits of entropy")]
    BelowEntropyFloor,
    /// Word count is out of range.
    #[error("word count is out of range")]
    WordsOutOfRange,
    /// Digit count is out of range.
    #[error("digit count is out of range")]
    DigitsOutOfRange,
    /// The separator is not a space or ASCII punctuation.
    #[error("the separator must be a space or ASCII punctuation")]
    BadSeparator,
    /// No password met the minimums within the attempt limit.
    #[error("could not meet the minimums")]
    Unsatisfiable,
    /// The operating system could not provide random bytes.
    #[error("the system random number generator failed")]
    Rng,
}

/// Settings for [`generate_password`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordSpec {
    /// Number of characters, 12 to 128.
    pub length: u16,
    /// Use a-z.
    pub lowercase: bool,
    /// Use A-Z.
    pub uppercase: bool,
    /// Use 0-9.
    pub digits: bool,
    /// Use the 32 ASCII symbols.
    pub symbols: bool,
    /// Drop characters that look alike (see [`LOOKALIKES`]).
    pub avoid_lookalikes: bool,
    /// Fewest digits in the result.
    pub min_digits: u8,
    /// Fewest symbols in the result.
    pub min_symbols: u8,
}

impl PasswordSpec {
    /// 20 characters from all four sets, at least one digit and one symbol.
    pub const DEFAULT: PasswordSpec = PasswordSpec {
        length: 20,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
        avoid_lookalikes: false,
        min_digits: 1,
        min_symbols: 1,
    };

    /// Checks the spec.
    ///
    /// # Errors
    /// Returns the first rule the spec breaks.
    pub fn validate(&self) -> Result<(), GeneratorError> {
        if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&self.length) {
            return Err(GeneratorError::LengthOutOfRange);
        }
        if !(self.lowercase || self.uppercase || self.digits || self.symbols) {
            return Err(GeneratorError::NoCharacterSets);
        }
        if (self.min_digits > 0 && !self.digits) || (self.min_symbols > 0 && !self.symbols) {
            return Err(GeneratorError::RequiredSetDisabled);
        }
        if u16::from(self.min_digits) + u16::from(self.min_symbols) > self.length / 2 {
            return Err(GeneratorError::TooManyRequired);
        }
        if self.entropy_bits() < MIN_ENTROPY_BITS {
            return Err(GeneratorError::BelowEntropyFloor);
        }
        Ok(())
    }

    /// Entropy in bits: `length * log2(pool size)`. Ignores the minimums, so it is
    /// a slight over-estimate when they are set.
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        let pool = self.pool().len();
        if pool == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let pool = pool as f64;
        f64::from(self.length) * pool.log2()
    }

    /// The pool in fixed order: lower, upper, digits, symbols, minus look-alikes.
    fn pool(&self) -> Vec<char> {
        let mut pool = String::new();
        if self.lowercase {
            pool.push_str(LOWERCASE);
        }
        if self.uppercase {
            pool.push_str(UPPERCASE);
        }
        if self.digits {
            pool.push_str(DIGITS);
        }
        if self.symbols {
            pool.push_str(SYMBOLS);
        }
        pool.chars()
            .filter(|c| !(self.avoid_lookalikes && LOOKALIKES.contains(*c)))
            .collect()
    }
}

/// Settings for [`generate_passphrase`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassphraseSpec {
    /// Number of words, 6 to 20.
    pub words: u8,
    /// Put between words: a space or ASCII punctuation.
    pub separator: char,
    /// Upper-case the first letter of each word.
    pub capitalise: bool,
    /// Add one random digit to the end of one random word.
    pub add_number: bool,
}

impl PassphraseSpec {
    /// Six words joined by `-`.
    pub const DEFAULT: PassphraseSpec = PassphraseSpec {
        words: 6,
        separator: '-',
        capitalise: false,
        add_number: false,
    };

    /// Checks the spec.
    ///
    /// # Errors
    /// Returns the first rule the spec breaks.
    pub fn validate(&self) -> Result<(), GeneratorError> {
        if !(MIN_PASSPHRASE_WORDS..=MAX_PASSPHRASE_WORDS).contains(&self.words) {
            return Err(GeneratorError::WordsOutOfRange);
        }
        if self.separator != ' ' && !self.separator.is_ascii_punctuation() {
            return Err(GeneratorError::BadSeparator);
        }
        Ok(())
    }

    /// Entropy in bits: `words * log2(7776)`, plus `log2(10 * words)` with a number.
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let list = WORDLIST_LEN as f64;
        let words = f64::from(self.words);
        let base = words * list.log2();
        if self.add_number {
            base + (10.0 * words).log2()
        } else {
            base
        }
    }
}

/// Settings for [`generate_username`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsernameSpec {
    /// Number of words, 1 to 3.
    pub words: u8,
    /// Number of trailing digits, 0 to 6.
    pub digits: u8,
}

impl UsernameSpec {
    /// Two words and three digits.
    pub const DEFAULT: UsernameSpec = UsernameSpec {
        words: 2,
        digits: 3,
    };

    /// Checks the spec.
    ///
    /// # Errors
    /// Returns the first rule the spec breaks.
    pub fn validate(&self) -> Result<(), GeneratorError> {
        if !(1..=3).contains(&self.words) {
            return Err(GeneratorError::WordsOutOfRange);
        }
        if self.digits > 6 {
            return Err(GeneratorError::DigitsOutOfRange);
        }
        Ok(())
    }
}

/// A source of random bytes. A seam so tests can feed known values.
pub(crate) trait RandomSource {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError>;
}

/// The operating system's random source.
pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
        holm_crypto::fill_random(buf)
    }
}

/// A uniform number in `0..n`, by rejection sampling. Values in the uneven tail of the
/// 32-bit range are thrown away, so no remainder is more likely than another.
pub(crate) fn uniform_below(
    rng: &mut dyn RandomSource,
    n: NonZeroU32,
) -> Result<u32, GeneratorError> {
    let n = u64::from(n.get());
    let bound = (1u64 << 32) / n * n;
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b).map_err(|_| GeneratorError::Rng)?;
        let x = u64::from(u32::from_le_bytes(b));
        if x < bound {
            // x % n < n <= u32::MAX, so this cannot truncate.
            return u32::try_from(x % n).map_err(|_| GeneratorError::Rng);
        }
    }
}

/// A uniform index in `0..len`. `len` is never zero here.
fn index_below(rng: &mut dyn RandomSource, len: usize) -> Result<usize, GeneratorError> {
    let n = u32::try_from(len)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(GeneratorError::Unsatisfiable)?;
    Ok(uniform_below(rng, n)? as usize)
}

/// The EFF large wordlist, parsed once. Some entries contain `-` (for example `t-shirt`).
pub(crate) fn wordlist() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| {
        include_str!("eff_large_wordlist.txt")
            .lines()
            .filter_map(|l| l.split_once('\t').map(|(_, w)| w))
            .collect()
    })
}

/// Makes a password. See [`PasswordSpec`].
///
/// # Errors
/// Returns a [`GeneratorError`] if the spec is invalid, the OS RNG fails, or the
/// minimums cannot be met.
pub fn generate_password(spec: &PasswordSpec) -> Result<SecretText, GeneratorError> {
    spec.validate()?;
    password_with(&mut OsRandom, spec)
}

/// Makes a passphrase. See [`PassphraseSpec`].
///
/// # Errors
/// Returns a [`GeneratorError`] if the spec is invalid or the OS RNG fails.
pub fn generate_passphrase(spec: &PassphraseSpec) -> Result<SecretText, GeneratorError> {
    spec.validate()?;
    passphrase_with(&mut OsRandom, spec)
}

/// Makes a username. See [`UsernameSpec`].
///
/// # Errors
/// Returns a [`GeneratorError`] if the spec is invalid or the OS RNG fails.
pub fn generate_username(spec: &UsernameSpec) -> Result<Text, GeneratorError> {
    spec.validate()?;
    username_with(&mut OsRandom, spec)
}

pub(crate) fn password_with(
    rng: &mut dyn RandomSource,
    spec: &PasswordSpec,
) -> Result<SecretText, GeneratorError> {
    let pool = spec.pool();
    let len = usize::from(spec.length);
    // Pool characters are all ASCII, so the buffer never grows and never reallocates.
    let mut buf: Zeroizing<String> = Zeroizing::new(String::with_capacity(len));
    for _ in 0..MAX_ATTEMPTS {
        buf.clear();
        let (mut digits, mut symbols) = (0usize, 0usize);
        for _ in 0..len {
            let c = pool[index_below(rng, pool.len())?];
            if c.is_ascii_digit() {
                digits += 1;
            } else if SYMBOLS.contains(c) {
                symbols += 1;
            }
            buf.push(c);
        }
        if digits >= usize::from(spec.min_digits) && symbols >= usize::from(spec.min_symbols) {
            return Ok(SecretText::new(core::mem::take(&mut *buf)));
        }
    }
    Err(GeneratorError::Unsatisfiable)
}

pub(crate) fn passphrase_with(
    rng: &mut dyn RandomSource,
    spec: &PassphraseSpec,
) -> Result<SecretText, GeneratorError> {
    let words = usize::from(spec.words);
    let list = wordlist();
    // 9 letters + separator + digit per word is the longest possible, so no regrowth.
    let mut buf: Zeroizing<String> = Zeroizing::new(String::with_capacity(11 * words + 1));
    let number = if spec.add_number {
        let at = index_below(rng, words)?;
        let digit = index_below(rng, 10)?;
        Some((at, digit))
    } else {
        None
    };
    for i in 0..words {
        if i > 0 {
            buf.push(spec.separator);
        }
        let word = list[index_below(rng, list.len())?];
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            buf.push(if spec.capitalise {
                first.to_ascii_uppercase()
            } else {
                first
            });
            buf.push_str(chars.as_str());
        }
        if let Some((at, digit)) = number
            && at == i
        {
            buf.push(char::from(
                b'0' + u8::try_from(digit).map_err(|_| GeneratorError::Rng)?,
            ));
        }
    }
    Ok(SecretText::new(core::mem::take(&mut *buf)))
}

pub(crate) fn username_with(
    rng: &mut dyn RandomSource,
    spec: &UsernameSpec,
) -> Result<Text, GeneratorError> {
    let list = wordlist();
    let mut out = String::new();
    for _ in 0..spec.words {
        out.push_str(list[index_below(rng, list.len())?]);
    }
    for _ in 0..spec.digits {
        let d = u8::try_from(index_below(rng, 10)?).map_err(|_| GeneratorError::Rng)?;
        out.push(char::from(b'0' + d));
    }
    Ok(Text::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Returns the given `u32`s in order, then starts over.
    struct SeqSource {
        values: Vec<u32>,
        next: usize,
    }

    impl SeqSource {
        fn new(values: &[u32]) -> Self {
            SeqSource {
                values: values.to_vec(),
                next: 0,
            }
        }
    }

    impl RandomSource for SeqSource {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
            let v = self.values[self.next % self.values.len()];
            self.next += 1;
            buf.copy_from_slice(&v.to_le_bytes());
            Ok(())
        }
    }

    /// A small seeded generator for repeatable tests. Not for real use.
    struct SplitMix64Source(u64);

    impl SplitMix64Source {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    impl RandomSource for SplitMix64Source {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), CryptoError> {
            for chunk in buf.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    #[test]
    fn uniform_below_rejects_biased_tail() {
        // For n = 3 the accepted range is 0..=4_294_967_294, so u32::MAX is rejected.
        let mut rng = SeqSource::new(&[u32::MAX, 5]);
        assert_eq!(uniform_below(&mut rng, nz(3)), Ok(2));
        assert_eq!(rng.next, 2);
    }

    proptest! {
        #[test]
        fn uniform_below_in_range(seed: u64, n in 1u32..=u32::MAX) {
            let mut rng = SplitMix64Source(seed);
            let v = uniform_below(&mut rng, nz(n)).unwrap();
            prop_assert!(v < n);
        }
    }

    #[test]
    fn defaults_exact() {
        assert_eq!(
            PasswordSpec::DEFAULT,
            PasswordSpec {
                length: 20,
                lowercase: true,
                uppercase: true,
                digits: true,
                symbols: true,
                avoid_lookalikes: false,
                min_digits: 1,
                min_symbols: 1
            }
        );
        assert_eq!(
            PassphraseSpec::DEFAULT,
            PassphraseSpec {
                words: 6,
                separator: '-',
                capitalise: false,
                add_number: false
            }
        );
        assert_eq!(
            UsernameSpec::DEFAULT,
            UsernameSpec {
                words: 2,
                digits: 3
            }
        );
    }

    #[test]
    fn default_password_entropy() {
        let e = PasswordSpec::DEFAULT.entropy_bits();
        assert!((20.0 * 94f64.log2() - e).abs() < 1e-9);
        assert_eq!(SYMBOLS.len(), 32);
    }

    #[test]
    fn password_spec_rejections() {
        let d = PasswordSpec::DEFAULT;
        let digits_only = PasswordSpec {
            lowercase: false,
            uppercase: false,
            symbols: false,
            min_symbols: 0,
            ..d
        };
        let cases = [
            (
                PasswordSpec { length: 11, ..d },
                Err(GeneratorError::LengthOutOfRange),
            ),
            (
                PasswordSpec { length: 129, ..d },
                Err(GeneratorError::LengthOutOfRange),
            ),
            (
                PasswordSpec {
                    lowercase: false,
                    uppercase: false,
                    digits: false,
                    symbols: false,
                    min_digits: 0,
                    min_symbols: 0,
                    ..d
                },
                Err(GeneratorError::NoCharacterSets),
            ),
            (
                PasswordSpec {
                    digits: false,
                    min_digits: 1,
                    ..d
                },
                Err(GeneratorError::RequiredSetDisabled),
            ),
            (
                PasswordSpec {
                    length: 12,
                    min_digits: 4,
                    min_symbols: 3,
                    ..d
                },
                Err(GeneratorError::TooManyRequired),
            ),
            (
                PasswordSpec {
                    length: 12,
                    ..digits_only
                },
                Err(GeneratorError::BelowEntropyFloor),
            ),
            (
                PasswordSpec {
                    length: 20,
                    ..digits_only
                },
                Ok(()),
            ),
            (d, Ok(())),
        ];
        for (spec, want) in cases {
            assert_eq!(spec.validate(), want, "{spec:?}");
        }
    }

    #[test]
    fn password_meets_spec() {
        let mut rng = SplitMix64Source(1);
        for i in 0..200u64 {
            let spec = PasswordSpec {
                length: 12 + u16::try_from(i % 40).unwrap(),
                avoid_lookalikes: i % 2 == 0,
                min_digits: 2,
                min_symbols: 3,
                ..PasswordSpec::DEFAULT
            };
            spec.validate().unwrap();
            let pw = password_with(&mut rng, &spec).unwrap();
            let s = pw.expose();
            assert_eq!(s.chars().count(), usize::from(spec.length));
            let pool = spec.pool();
            assert!(s.chars().all(|c| pool.contains(&c)));
            assert!(s.chars().filter(char::is_ascii_digit).count() >= 2);
            assert!(s.chars().filter(|c| SYMBOLS.contains(*c)).count() >= 3);
            if spec.avoid_lookalikes {
                assert!(!s.chars().any(|c| LOOKALIKES.contains(c)));
            }
        }
    }

    #[test]
    fn password_unsatisfiable_after_max_attempts() {
        // Always picks pool[0] = 'a', so a digit is never produced.
        let mut rng = SeqSource::new(&[0]);
        let r = password_with(&mut rng, &PasswordSpec::DEFAULT);
        assert_eq!(r.err(), Some(GeneratorError::Unsatisfiable));
    }

    #[test]
    fn password_chars_uniform() {
        let spec = PasswordSpec {
            length: 128,
            min_digits: 0,
            min_symbols: 0,
            ..PasswordSpec::DEFAULT
        };
        let pool = spec.pool();
        assert_eq!(pool.len(), 94);
        let mut counts = [0u32; 94];
        let mut rng = SplitMix64Source(0xC0FFEE);
        let mut total = 0u32;
        while total < 200_000 {
            let pw = password_with(&mut rng, &spec).unwrap();
            for c in pw.expose().chars() {
                counts[pool.iter().position(|p| *p == c).unwrap()] += 1;
                total += 1;
            }
        }
        let expected = f64::from(total) / 94.0;
        let chi2: f64 = counts
            .iter()
            .map(|&o| {
                let d = f64::from(o) - expected;
                d * d / expected
            })
            .sum();
        assert!(chi2 < 140.0, "chi2 = {chi2}");
    }

    #[test]
    fn passphrase_shape() {
        let list = wordlist();
        let mut rng = SplitMix64Source(7);
        // A space separator, so hyphenated list words such as t-shirt cannot split.
        let spec = PassphraseSpec {
            separator: ' ',
            ..PassphraseSpec::DEFAULT
        };
        for _ in 0..200 {
            let p = passphrase_with(&mut rng, &spec).unwrap();
            let parts: Vec<&str> = p.expose().split(' ').collect();
            assert_eq!(parts.len(), 6);
            assert!(parts.iter().all(|w| list.contains(w)));
        }
        let p = passphrase_with(&mut rng, &PassphraseSpec::DEFAULT).unwrap();
        assert!(p.expose().matches('-').count() >= 5);

        let cap = PassphraseSpec {
            capitalise: true,
            ..spec
        };
        let p = passphrase_with(&mut rng, &cap).unwrap();
        assert!(
            p.expose()
                .split(' ')
                .all(|w| w.starts_with(|c: char| c.is_ascii_uppercase()))
        );

        let num = PassphraseSpec {
            add_number: true,
            ..spec
        };
        for _ in 0..200 {
            let p = passphrase_with(&mut rng, &num).unwrap();
            assert_eq!(p.expose().chars().filter(char::is_ascii_digit).count(), 1);
        }
    }

    #[test]
    fn passphrase_hyphenated_words_survive() {
        // Index 6639 is "t-shirt" (line 6640). With seed-free input, pick it directly.
        let idx = wordlist().iter().position(|w| *w == "t-shirt").unwrap();
        let v = u32::try_from(idx).unwrap();
        let mut rng = SeqSource::new(&[v]);
        let spec = PassphraseSpec {
            separator: ' ',
            ..PassphraseSpec::DEFAULT
        };
        let p = passphrase_with(&mut rng, &spec).unwrap();
        assert_eq!(p.expose(), ["t-shirt"; 6].join(" "));
    }

    #[test]
    fn passphrase_rejections() {
        let d = PassphraseSpec::DEFAULT;
        assert_eq!(
            PassphraseSpec { words: 5, ..d }.validate(),
            Err(GeneratorError::WordsOutOfRange)
        );
        assert_eq!(
            PassphraseSpec { words: 21, ..d }.validate(),
            Err(GeneratorError::WordsOutOfRange)
        );
        assert_eq!(
            PassphraseSpec {
                separator: 'a',
                ..d
            }
            .validate(),
            Err(GeneratorError::BadSeparator)
        );
        assert!(generate_passphrase(&PassphraseSpec { words: 5, ..d }).is_err());
        assert!((d.entropy_bits() - 6.0 * 7776f64.log2()).abs() < 1e-9);
        let n = PassphraseSpec {
            add_number: true,
            ..d
        };
        assert!((n.entropy_bits() - (6.0 * 7776f64.log2() + 60f64.log2())).abs() < 1e-9);
    }

    #[test]
    fn username_shape() {
        let mut rng = SplitMix64Source(3);
        for _ in 0..200 {
            let u = username_with(&mut rng, &UsernameSpec::DEFAULT).unwrap();
            let s = u.as_str();
            let (head, tail) = s.split_at(s.len() - 3);
            assert!(!head.is_empty() && head.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
            assert!(tail.chars().all(|c| c.is_ascii_digit()));
        }
        assert!(generate_username(&UsernameSpec::DEFAULT).is_ok());
    }

    #[test]
    fn username_rejections() {
        assert_eq!(
            UsernameSpec {
                words: 0,
                digits: 3
            }
            .validate(),
            Err(GeneratorError::WordsOutOfRange)
        );
        assert_eq!(
            UsernameSpec {
                words: 4,
                digits: 3
            }
            .validate(),
            Err(GeneratorError::WordsOutOfRange)
        );
        assert_eq!(
            UsernameSpec {
                words: 2,
                digits: 7
            }
            .validate(),
            Err(GeneratorError::DigitsOutOfRange)
        );
    }

    #[test]
    fn wordlist_integrity() {
        let list = wordlist();
        assert_eq!(list.len(), WORDLIST_LEN);
        assert_eq!(list[0], "abacus");
        assert_eq!(list[WORDLIST_LEN - 1], "zoom");
        let unique: std::collections::HashSet<_> = list.iter().collect();
        assert_eq!(unique.len(), WORDLIST_LEN);
        assert!(
            list.iter().all(|w| (3..=9).contains(&w.len())
                && w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        );
        // Dice numbers run 11111..66666 in order.
        let mut dice = Vec::new();
        for a in 1..=6u32 {
            for b in 1..=6 {
                for c in 1..=6 {
                    for d in 1..=6 {
                        for e in 1..=6 {
                            dice.push(format!("{a}{b}{c}{d}{e}"));
                        }
                    }
                }
            }
        }
        let src: Vec<&str> = include_str!("eff_large_wordlist.txt")
            .lines()
            .filter_map(|l| l.split_once('\t').map(|(n, _)| n))
            .collect();
        assert_eq!(src, dice);
        // The hyphenated entries the generator must tolerate.
        let hyphenated: Vec<&&str> = list.iter().filter(|w| w.contains('-')).collect();
        assert_eq!(
            hyphenated,
            [&"drop-down", &"felt-tip", &"t-shirt", &"yo-yo"]
        );
    }
}
