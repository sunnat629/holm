//! Master password strength check.
//!
//! [`check`] estimates how many guesses an attacker needs for a candidate master password
//! and applies Holm's two rules: at least [`MIN_MASTER_CHARS`] characters, and a score of
//! at least [`MIN_MASTER_SCORE`], which means at least 10^8 guesses.
//!
//! The estimate is Holm's own, in the spirit of zxcvbn and kept at least as strict on weak
//! passwords (a test checks this against the `zxcvbn` crate, which is a dev-dependency
//! only). It works on the NFC form of the whole password, with no length cut-off:
//!
//! 1. Find guessable pieces: words from an embedded list of 93,855 common passwords,
//!    words and names (also upper-cased, reversed, or with look-alike symbols such as `@`
//!    for `a`), the word `holm`, keyboard walks, repeats, letter and digit sequences,
//!    years and dates.
//! 2. Find the cheapest way to build the whole password from those pieces, pricing any
//!    gap as random characters.
//! 3. Turn the guess count into zxcvbn's 0 to 4 score.
//!
//! Every buffer derived from the password (characters, lower-cased and reversed copies,
//! matches, tables) is wiped when dropped. The report holds only fixed advice text from
//! this module, never any part of the password.

mod keyboard;
mod lists;
mod matching;
mod scoring;

use holm_crypto::MasterPassword;

use lists::Source;
use matching::{ALL_CAPS, CAPS, Hint, L33T, Match, REVERSED, Text, wiped_chars};
use scoring::Budget;

/// The fewest characters (Unicode scalar values after NFC) a master password may have.
pub const MIN_MASTER_CHARS: usize = 12;

/// The lowest score (0 to 4) a master password may have. Score 3 starts at 10^8 guesses.
pub const MIN_MASTER_SCORE: u8 = 3;

/// The numbers behind a strength decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StrengthVerdict {
    /// Score, 0 (trivially guessed) to 4 (very hard to guess), on zxcvbn's scale:
    /// below 10^3, 10^6, 10^8, 10^10 guesses, and above.
    pub score: u8,
    /// Length in `char`s of the NFC form.
    pub chars: usize,
    /// True when `score >= MIN_MASTER_SCORE` and `chars >= MIN_MASTER_CHARS`.
    pub acceptable: bool,
}

/// A verdict plus advice. The text is fixed wording from this module and never contains
/// the password.
#[derive(Debug)]
pub struct StrengthReport {
    /// The decision.
    pub verdict: StrengthVerdict,
    /// What is wrong, if anything.
    pub warning: Option<String>,
    /// How to improve, if needed.
    pub suggestions: Vec<String>,
}

const WARN_COMMON: &str = "This is similar to a commonly used password.";
const WARN_WORD: &str = "A single common word is easy to guess.";
const WARN_NAME: &str = "Names and surnames are easy to guess.";
const WARN_CONTEXT: &str = "The app's own name is easy to guess.";
const WARN_KEYBOARD: &str = "Keyboard patterns are easy to guess.";
const WARN_REPEAT: &str = "Repeated characters or words are easy to guess.";
const WARN_SEQUENCE: &str = "Runs of letters or numbers are easy to guess.";
const WARN_YEAR: &str = "Years are easy to guess.";
const WARN_DATE: &str = "Dates are easy to guess.";
const WARN_SHORT: &str = "This is too short for a master password.";
const SUGGEST_WORDS: &str = "Use four or more unrelated words, or let Holm make a passphrase.";
const SUGGEST_CAPS: &str = "Capital letters in the usual places add little.";
const SUGGEST_ALL_CAPS: &str = "All capitals are almost as easy to guess as none.";
const SUGGEST_REVERSED: &str = "Spelling a word backwards adds little.";
const SUGGEST_L33T: &str = "Swapping letters for look-alike symbols adds little.";
const SUGGEST_LONGER: &str = "Use at least 12 characters.";

/// Every text a report can hold.
#[cfg(test)]
const ALL_FEEDBACK: &[&str] = &[
    WARN_COMMON,
    WARN_WORD,
    WARN_NAME,
    WARN_CONTEXT,
    WARN_KEYBOARD,
    WARN_REPEAT,
    WARN_SEQUENCE,
    WARN_YEAR,
    WARN_DATE,
    WARN_SHORT,
    SUGGEST_WORDS,
    SUGGEST_CAPS,
    SUGGEST_ALL_CAPS,
    SUGGEST_REVERSED,
    SUGGEST_L33T,
    SUGGEST_LONGER,
];

/// Scores `password` and decides whether Holm accepts it as a master password.
///
/// The whole NFC form is judged, however long. The work grows linearly with length.
#[must_use]
pub fn check(password: &MasterPassword) -> StrengthReport {
    let bytes = password.to_kdf_bytes();
    // `to_kdf_bytes` builds the bytes from a `String`, so they are valid UTF-8. If that
    // ever stopped being true, refuse the password rather than guess.
    let Ok(text) = core::str::from_utf8(bytes.expose()) else {
        return report(0, 0, &[]);
    };
    let count = text.chars().count();
    let chars = wiped_chars(text.chars(), count);
    let lower = wiped_chars(chars.iter().map(char::to_ascii_lowercase), count);
    let estimate = scoring::estimate(
        Text {
            chars: &chars,
            lower: &lower,
        },
        &mut Budget::default(),
    );
    let score = if count == 0 {
        0
    } else {
        scoring::score(estimate.guesses)
    };
    report(score, count, &estimate.pieces)
}

fn report(score: u8, chars: usize, pieces: &[Match]) -> StrengthReport {
    let acceptable = score >= MIN_MASTER_SCORE && chars >= MIN_MASTER_CHARS;
    let mut warning = None;
    let mut suggestions = Vec::new();
    if score < MIN_MASTER_SCORE {
        // Advise on the longest piece, as zxcvbn does.
        let longest = pieces
            .iter()
            .copied()
            .reduce(|a, b| if b.j - b.i > a.j - a.i { b } else { a });
        if let Some(m) = longest {
            warning = warning_for(m.hint);
            for (flag, text) in [
                (CAPS, SUGGEST_CAPS),
                (ALL_CAPS, SUGGEST_ALL_CAPS),
                (REVERSED, SUGGEST_REVERSED),
                (L33T, SUGGEST_L33T),
            ] {
                if m.flags & flag != 0 {
                    suggestions.push(text);
                }
            }
        }
        suggestions.insert(0, SUGGEST_WORDS);
    }
    if chars < MIN_MASTER_CHARS {
        warning = warning.or(Some(WARN_SHORT));
        suggestions.push(SUGGEST_LONGER);
    }
    StrengthReport {
        verdict: StrengthVerdict {
            score,
            chars,
            acceptable,
        },
        warning: warning.map(str::to_owned),
        suggestions: suggestions.into_iter().map(str::to_owned).collect(),
    }
}

fn warning_for(hint: Hint) -> Option<&'static str> {
    Some(match hint {
        Hint::Bruteforce => return None,
        Hint::Word(Source::Passwords) => WARN_COMMON,
        Hint::Word(Source::Words) => WARN_WORD,
        Hint::Word(Source::Names) => WARN_NAME,
        Hint::Word(Source::Context) => WARN_CONTEXT,
        Hint::Keyboard => WARN_KEYBOARD,
        Hint::Repeat => WARN_REPEAT,
        Hint::Sequence => WARN_SEQUENCE,
        Hint::Year => WARN_YEAR,
        Hint::Date => WARN_DATE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> MasterPassword {
        MasterPassword::new(s.to_owned())
    }

    #[test]
    fn empty_refused() {
        let r = check(&pw(""));
        assert_eq!(
            r.verdict,
            StrengthVerdict {
                score: 0,
                chars: 0,
                acceptable: false
            }
        );
    }

    #[test]
    fn common_password_refused() {
        let r = check(&pw("password1234"));
        assert!(!r.verdict.acceptable);
        assert!(r.verdict.score <= 2, "score {}", r.verdict.score);
        assert!(r.warning.is_some() || !r.suggestions.is_empty());
    }

    #[test]
    fn eleven_strong_chars_refused_for_length() {
        let r = check(&pw("Xk#9vQ!2mLp"));
        assert_eq!(r.verdict.chars, 11);
        assert!(!r.verdict.acceptable);
    }

    #[test]
    fn long_random_accepted() {
        let r = check(&pw("q7#Vt9!mZ2@rL5$w"));
        assert_eq!(r.verdict.score, 4);
        assert!(r.verdict.acceptable);
    }

    #[test]
    fn chars_counted_after_nfc() {
        let r = check(&pw(&"e\u{301}".repeat(12)));
        assert_eq!(r.verdict.chars, 12);
    }

    #[test]
    fn report_debug_has_no_password() {
        let secret = "q7#Vt9!mZ2@rL5$w";
        let r = check(&pw(secret));
        assert!(!format!("{r:?}").contains(secret));
    }

    #[test]
    fn feedback_never_echoes_weak_password() {
        let secret = "zebra-quartz-harbor";
        let r = check(&pw(secret));
        let all = format!("{:?}", r);
        for part in ["zebra", "quartz", "harbor"] {
            assert!(!all.contains(part), "feedback echoed {part}");
        }
    }
    #[test]
    fn padded_strong_password_judged_whole() {
        let strong = "q7#Vt9!mZ2@rL5$w";
        let pad = "a".repeat(100);
        for text in [format!("{pad}{strong}"), format!("{strong}{pad}")] {
            let r = check(&pw(&text));
            assert_eq!(r.verdict.chars, 116);
            assert!(r.verdict.acceptable, "padding hid the strong part");
        }
    }

    #[test]
    fn long_repeat_refused() {
        let r = check(&pw(&"a".repeat(10_000)));
        assert_eq!(r.verdict.chars, 10_000);
        assert!(!r.verdict.acceptable);
    }

    #[test]
    fn year_and_date_refused() {
        for text in ["holmholm2026!", "04/12/1990holm", "summer2024summer2024"] {
            assert!(
                !check(&pw(text)).verdict.acceptable,
                "accepted a guessable password"
            );
        }
    }
    #[test]
    fn report_text_comes_from_fixed_table() {
        for text in [
            "",
            "password1234",
            "P@ssw0rd",
            "drowssap",
            "PASSWORD",
            "qwertyuiop",
            "aaaaaaaa",
            "abcdefgh",
            "1990",
            "11/04/1990",
            "holm",
            "maria",
            "the",
            "Xk#9vQ!2mLp",
        ] {
            let r = check(&pw(text));
            for line in r.warning.iter().chain(&r.suggestions) {
                assert!(
                    ALL_FEEDBACK.contains(&line.as_str()),
                    "unexpected text: {line}"
                );
            }
        }
    }

    #[test]
    fn long_random_input_judged_in_full() {
        // 10,000 fixed pseudo-random printable characters: no cut-off, bounded work.
        let mut state: u32 = 12_345;
        let text: String = (0..10_000)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                char::from(b'!' + u8::try_from((state >> 16) % 94).unwrap_or(0))
            })
            .collect();
        let r = check(&pw(&text));
        assert_eq!(r.verdict.chars, 10_000);
        assert_eq!(r.verdict.score, 4);
        assert!(r.verdict.acceptable);
    }
}
