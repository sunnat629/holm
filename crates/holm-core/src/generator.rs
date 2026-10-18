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

/// A spec is refused when all `MAX_ATTEMPTS` tries would fail with more than this chance.
const MAX_FAIL_CHANCE: f64 = 1e-9;

#[allow(clippy::cast_precision_loss)]
fn as_f64(n: usize) -> f64 {
    n as f64
}

fn powi(base: f64, exp: usize) -> f64 {
    i32::try_from(exp).map_or(f64::INFINITY, |e| base.powi(e))
}

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
    /// The minimums are too high for this length: more than half of it, or so high that
    /// a random draw would almost never meet them.
    #[error("the minimum counts are too high for this length")]
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
        let (valid, total) = self.counts();
        if valid.log2() < MIN_ENTROPY_BITS {
            return Err(GeneratorError::BelowEntropyFloor);
        }
        // Chance that all MAX_ATTEMPTS tries fail: (1 - p)^MAX_ATTEMPTS.
        let p = valid / total;
        if f64::from(MAX_ATTEMPTS) * (-p).ln_1p() > MAX_FAIL_CHANCE.ln() {
            return Err(GeneratorError::TooManyRequired);
        }
        Ok(())
    }

    /// Entropy in bits: `log2` of the number of strings that meet the minimums.
    /// The generator is uniform over exactly that set, so this is the real figure.
    ///
    /// Returns 0.0 for a spec that cannot be valid: a length outside 12 to 128, minimums
    /// that add up to more than the length, no character sets, or a minimum for a class
    /// that is switched off (nothing can meet it). The input is checked before any
    /// counting, so a huge `length` is cheap.
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&self.length)
            || u16::from(self.min_digits) + u16::from(self.min_symbols) > self.length
            || self.pool().is_empty()
            || (self.min_digits > 0 && !self.digits)
            || (self.min_symbols > 0 && !self.symbols)
        {
            return 0.0;
        }
        self.counts().0.log2()
    }

    /// `(valid, total)` as f64: the number of strings of this length that meet the
    /// minimums, and the number of all strings from the pool. The largest total is
    /// 94^128, about 2^839, well inside the f64 range.
    fn counts(&self) -> (f64, f64) {
        let pool = self.pool();
        let digits = pool.iter().filter(|c| c.is_ascii_digit()).count();
        let symbols = pool.iter().filter(|c| SYMBOLS.contains(**c)).count();
        let others = pool.len() - digits - symbols;
        let (d, s, o) = (as_f64(digits), as_f64(symbols), as_f64(others));
        let len = usize::from(self.length);
        // Pascal's triangle row by row: choose[n][k] = C(n, k).
        let mut choose = vec![vec![0.0f64; len + 1]; len + 1];
        for n in 0..=len {
            choose[n][0] = 1.0;
            for k in 1..=n {
                let above = if k < n { choose[n - 1][k] } else { 0.0 };
                choose[n][k] = choose[n - 1][k - 1] + above;
            }
        }
        let (min_d, min_s) = (usize::from(self.min_digits), usize::from(self.min_symbols));
        let mut valid = 0.0f64;
        for i in min_d..=len {
            for j in min_s..=(len - i) {
                valid += choose[len][i]
                    * choose[len - i][j]
                    * powi(d, i)
                    * powi(s, j)
                    * powi(o, len - i - j);
            }
        }
        (valid, powi(as_f64(pool.len()), len))
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
///
/// Four list words contain a hyphen (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`). They
/// are kept. With a `-` separator they cause 0 split collisions, because no left half
/// (`drop`, `felt`, `t`, `yo`) is a list word, so a phrase decodes uniquely.
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

/// The EFF large wordlist, parsed once. Four entries contain `-`: `drop-down`,
/// `felt-tip`, `t-shirt` and `yo-yo`. With a `-` separator this costs no entropy and
/// causes 0 split collisions: no left half (`drop`, `felt`, `t`, `yo`) is itself a list
/// word, so a joined phrase always decodes back to one word sequence. That holds only
/// for this exact file, which `scripts/ci-local.sh` checks against its pinned SHA-256.
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
        // u32::MAX - 1 is the largest accepted value: (2^32 - 2) % 3 = 2, in one draw.
        let mut rng = SeqSource::new(&[u32::MAX - 1]);
        assert_eq!(uniform_below(&mut rng, nz(3)), Ok(2));
        assert_eq!(rng.next, 1);
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
        // Below 20 * log2(94) = 131.09 because one digit and one symbol are required.
        let e = PasswordSpec::DEFAULT.entropy_bits();
        assert!((e - 130.93).abs() < 0.01, "e = {e}");
        // No minimums: the exact count is pool^length.
        let free = PasswordSpec {
            min_digits: 0,
            min_symbols: 0,
            ..PasswordSpec::DEFAULT
        };
        assert!((free.entropy_bits() - 20.0 * 94f64.log2()).abs() < 1e-6);
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
    fn minimums_cannot_bypass_entropy_floor() {
        // Digits and symbols only, 6 digits of 12: the naive figure is 64.71 bits, the
        // real one is 60.19.
        let spec = PasswordSpec {
            length: 12,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: true,
            avoid_lookalikes: false,
            min_digits: 6,
            min_symbols: 0,
        };
        assert!(12.0 * 42f64.log2() >= MIN_ENTROPY_BITS);
        assert!(spec.entropy_bits() < MIN_ENTROPY_BITS);
        assert_eq!(spec.validate(), Err(GeneratorError::BelowEntropyFloor));
    }

    #[test]
    fn hopeless_minimums_rejected_up_front() {
        let spec = PasswordSpec {
            length: 128,
            min_digits: 64,
            min_symbols: 0,
            ..PasswordSpec::DEFAULT
        };
        assert_eq!(spec.validate(), Err(GeneratorError::TooManyRequired));
        assert_eq!(
            generate_password(&spec).err(),
            Some(GeneratorError::TooManyRequired)
        );
    }

    #[test]
    fn entropy_bits_is_zero_for_huge_length() {
        let spec = PasswordSpec {
            length: u16::MAX,
            ..PasswordSpec::DEFAULT
        };
        assert!(spec.entropy_bits().abs() < f64::EPSILON);
    }

    #[test]
    fn entropy_bits_is_zero_when_minimums_exceed_length() {
        let spec = PasswordSpec {
            length: 12,
            min_digits: 10,
            min_symbols: 10,
            ..PasswordSpec::DEFAULT
        };
        assert!(spec.entropy_bits().abs() < f64::EPSILON);
    }

    #[test]
    fn entropy_bits_is_zero_when_a_minimum_needs_a_disabled_class() {
        let no_digits = PasswordSpec {
            digits: false,
            min_digits: 1,
            ..PasswordSpec::DEFAULT
        };
        assert!(no_digits.entropy_bits().abs() < f64::EPSILON);
        let no_symbols = PasswordSpec {
            symbols: false,
            min_symbols: 1,
            ..PasswordSpec::DEFAULT
        };
        assert!(no_symbols.entropy_bits().abs() < f64::EPSILON);
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
        // Hyphenated list words only add hyphens, so at least 5 and at most 5 + 6.
        assert!(p.expose().matches('-').count() >= 5);
        // Decode: a token that is not a list word must be the left half of a hyphenated
        // one and join the next token. Then there are exactly 6 words.
        let mut words = 0;
        let mut pending: Option<String> = None;
        for tok in p.expose().split('-') {
            let cand = match pending.take() {
                Some(left) => format!("{left}-{tok}"),
                None => tok.to_string(),
            };
            if list.contains(&cand.as_str()) {
                words += 1;
            } else {
                pending = Some(cand);
            }
        }
        assert!(pending.is_none());
        assert_eq!(words, 6);

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
            // The digit ends a word: strip it and every part is a list word.
            let stripped: Vec<String> = p
                .expose()
                .split(' ')
                .map(|w| w.trim_end_matches(|c: char| c.is_ascii_digit()).to_string())
                .collect();
            assert!(stripped.iter().all(|w| list.contains(&w.as_str())));
            assert_eq!(
                p.expose()
                    .split(' ')
                    .filter(|w| w.ends_with(|c: char| c.is_ascii_digit()))
                    .count(),
                1
            );
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

    #[test]
    fn defaults_pass_the_master_password_check() {
        // What the generator offers by default must be accepted as a master password.
        let mut rng = SplitMix64Source(0x5EED);
        for _ in 0..300 {
            let p = passphrase_with(&mut rng, &PassphraseSpec::DEFAULT).unwrap();
            let master = holm_crypto::MasterPassword::new(p.expose().to_owned());
            let verdict = crate::strength::check(&master).verdict;
            assert!(
                verdict.acceptable,
                "default passphrase refused (score {})",
                verdict.score
            );
            let p = password_with(&mut rng, &PasswordSpec::DEFAULT).unwrap();
            let master = holm_crypto::MasterPassword::new(p.expose().to_owned());
            let verdict = crate::strength::check(&master).verdict;
            assert!(
                verdict.acceptable,
                "default password refused (score {})",
                verdict.score
            );
        }
    }
}
