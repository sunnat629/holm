//! Master password strength check.
//!
//! [`check`] scores a candidate master password with zxcvbn and applies Holm's two rules:
//! a zxcvbn score of at least [`MIN_MASTER_SCORE`] and at least [`MIN_MASTER_CHARS`]
//! characters. The report holds only zxcvbn's fixed advice text, never the password.
//!
//! zxcvbn copies the candidate into memory Holm cannot wipe; see `docs/CRYPTO.md`.

use holm_crypto::MasterPassword;

/// The fewest characters (Unicode scalar values after NFC) a master password may have.
pub const MIN_MASTER_CHARS: usize = 12;

/// The lowest zxcvbn score (0 to 4) a master password may have.
pub const MIN_MASTER_SCORE: u8 = 3;

/// Words zxcvbn treats as guessable context for every check.
const USER_INPUTS: &[&str] = &["holm"];

/// The numbers behind a strength decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StrengthVerdict {
    /// zxcvbn score, 0 (trivially guessed) to 4 (very hard to guess).
    pub score: u8,
    /// Length in `char`s of the NFC form.
    pub chars: usize,
    /// True when `score >= MIN_MASTER_SCORE` and `chars >= MIN_MASTER_CHARS`.
    pub acceptable: bool,
}

/// A verdict plus zxcvbn's advice. The text is fixed library wording and never contains
/// the password.
#[derive(Debug)]
pub struct StrengthReport {
    /// The decision.
    pub verdict: StrengthVerdict,
    /// What is wrong, if zxcvbn says.
    pub warning: Option<String>,
    /// How to improve, if zxcvbn says.
    pub suggestions: Vec<String>,
}

/// Scores `password` and decides whether Holm accepts it as a master password.
///
/// An empty password scores 0 without calling zxcvbn. zxcvbn only looks at the first 100
/// characters. Its internal copies of the password are freed but not wiped.
#[must_use]
pub fn check(password: &MasterPassword) -> StrengthReport {
    let bytes = password.to_kdf_bytes();
    // `to_kdf_bytes` builds the bytes from a `String`, so they are valid UTF-8. If that
    // ever stopped being true, refuse the password rather than guess.
    let Ok(text) = core::str::from_utf8(bytes.expose()) else {
        return refused();
    };
    let chars = text.chars().count();
    if chars == 0 {
        return refused();
    }
    let entropy = zxcvbn::zxcvbn(text, USER_INPUTS);
    let score = u8::from(entropy.score());
    let (warning, suggestions) = match entropy.feedback() {
        Some(f) => (
            f.warning().map(|w| w.to_string()),
            f.suggestions().iter().map(ToString::to_string).collect(),
        ),
        None => (None, Vec::new()),
    };
    StrengthReport {
        verdict: StrengthVerdict {
            score,
            chars,
            acceptable: score >= MIN_MASTER_SCORE && chars >= MIN_MASTER_CHARS,
        },
        warning,
        suggestions,
    }
}

/// Score 0, not acceptable, no advice: used for an empty or undecodable password.
fn refused() -> StrengthReport {
    StrengthReport {
        verdict: StrengthVerdict {
            score: 0,
            chars: 0,
            acceptable: false,
        },
        warning: None,
        suggestions: Vec::new(),
    }
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
}
