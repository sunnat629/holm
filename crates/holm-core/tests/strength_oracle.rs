//! Holm's strength check against zxcvbn, used here as a test oracle only.
//!
//! The rule: every password in the corpus that zxcvbn scores below 3 must be refused by
//! Holm too. Holm's score is also never above zxcvbn's on the corpus. A strong set must be
//! accepted, so the check cannot pass by refusing
//! everything. The corpus is fixed in this file; the combinations are generated from it
//! the same way on every run.

use holm_core::strength::{MIN_MASTER_SCORE, check};
use holm_crypto::MasterPassword;

/// Common passwords, words and names to build weak candidates from.
const BASES: &[&str] = &[
    "password",
    "123456",
    "qwerty",
    "iloveyou",
    "dragon",
    "monkey",
    "letmein",
    "football",
    "baseball",
    "sunshine",
    "princess",
    "shadow",
    "superman",
    "michael",
    "jennifer",
    "charlie",
    "trustno1",
    "welcome",
    "master",
    "freedom",
    "whatever",
    "starwars",
    "summer",
    "winter",
    "holm",
    "harbor",
    "computer",
    "internet",
    "chocolate",
    "butterfly",
    "smith",
    "johnson",
    "elizabeth",
    "london",
    "secret",
    "abc123",
    "passw0rd",
    "admin",
    "login",
    "hello",
    "batman",
    "pokemon",
    "liverpool",
    "arsenal",
    "mustang",
    "jordan",
    "maggie",
];

const SUFFIXES: &[&str] = &[
    "", "1", "12", "123", "1234", "12345", "!", "!!", "1!", "2024", "1990", "1987", "2026", "01",
    "007", "69", "99", "@", "#1", "_", "abc", "xyz", "qwe", "11/04", "!@#",
];

/// Hand-picked weak shapes the generator does not make.
const WEAK: &[&str] = &[
    "password1234",
    "Password1234",
    "P@ssw0rd1234",
    "p4ssw0rd2024!",
    "qwertyuiop123",
    "1qaz2wsx3edc",
    "zxcvbnmasdfgh",
    "asdfghjkl;'",
    "qazwsxedcrfv",
    "1234567890-=",
    "aaaaaaaaaaaaaaaa",
    "abcabcabcabc",
    "passwordpassword",
    "123123123123",
    "abcdefghijklmn",
    "zyxwvutsrqpon",
    "13579135791357",
    "0987654321098",
    "11/04/1990abc",
    "1990-11-04-holm",
    "19901104199011",
    "04.11.1990.0411",
    "summer2024summer",
    "iloveyou12345",
    "HOLMHOLMHOLM",
    "holm2026holm!",
    "Holm2026!!",
    "drowssapdrowssap",
    "monkeymonkey1",
    "letmeinletmein",
    "welcome123456",
    "Jennifer1987!",
    "michael19901104",
    "7894561230789",
    "9632587410123",
    "!@#$%^&*()_+",
    "qwerty123456!",
    "trustno1trustno1",
    "Sunshine2026",
    "LONDON2024!!",
    "c0mput3r1234",
    "ch0c0l4t3123",
    "b4tm4nb4tm4n",
    "abc123abc123",
    "a1b2c3d4e5f6",
    "aaaa1111bbbb",
    "elizabeth1990",
    "smithjohnson12",
    "liverpool2024",
    "freedom!freedom",
    "Passw0rd!2026",
];

/// Strong passphrases of five or six unrelated words, and one random string.
const STRONG: &[&str] = &[
    "q7#Vt9!mZ2@rL5$w",
    "unbent-gravy-mumble-oxidize-plaza",
    "gopher tannery wreath unlisted sprain",
    "blurt.cubicle.pellet.scorch.deem",
    "Fanciness6-Overlying-Squall-Rebate",
    "dislodge_exile_mortuary_trance_jot",
    "smock-yodel-ferment-bovine-quiver-amid",
];

fn variants(base: &str) -> Vec<String> {
    let mut out = vec![base.to_owned()];
    let mut caps = base.to_owned();
    if let Some(first) = caps.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    out.push(caps);
    out.push(base.to_ascii_uppercase());
    out.push(
        base.chars()
            .map(|c| match c {
                'a' => '@',
                'e' => '3',
                'i' => '1',
                'o' => '0',
                's' => '$',
                _ => c,
            })
            .collect(),
    );
    out.push(base.chars().rev().collect());
    out
}

fn corpus() -> Vec<String> {
    let mut out: Vec<String> = WEAK.iter().map(|s| (*s).to_owned()).collect();
    for base in BASES {
        for v in variants(base) {
            for suffix in SUFFIXES {
                out.push(format!("{v}{suffix}"));
                out.push(format!("{suffix}{v}"));
            }
            out.push(format!("{v}{v}"));
        }
    }
    for pair in BASES.windows(2) {
        out.push(format!("{}{}", pair[0], pair[1]));
        out.push(format!("{}{}2024", pair[0], pair[1]));
    }
    out
}

/// Fixed pseudo-random printable strings (a linear congruential generator with a fixed
/// seed), so the strong set is the same on every run.
fn random_strings() -> Vec<String> {
    let mut state: u64 = 0x5eed_1234_abcd_0042;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        // 94 printable ASCII characters from '!' to '~'.
        char::from(b'!' + u8::try_from((state >> 33) % 94).unwrap_or(0))
    };
    (0..40).map(|_| (0..16).map(|_| next()).collect()).collect()
}

fn holm(s: &str) -> holm_core::strength::StrengthReport {
    check(&MasterPassword::new(s.to_owned()))
}

#[test]
fn holm_refuses_everything_zxcvbn_finds_weak() {
    let mut weak_by_zxcvbn = 0;
    let mut missed = Vec::new();
    let mut laxer = Vec::new();
    for p in corpus() {
        let z = u8::from(zxcvbn::zxcvbn(&p, &["holm"]).score());
        let h = holm(&p).verdict;
        if z < MIN_MASTER_SCORE {
            weak_by_zxcvbn += 1;
            if h.acceptable {
                missed.push(p.clone());
            }
        }
        if h.score > z {
            laxer.push(p);
        }
    }
    assert!(
        weak_by_zxcvbn > 10_000,
        "corpus too small: {weak_by_zxcvbn}"
    );
    assert!(
        missed.is_empty(),
        "Holm accepted {} that zxcvbn scores below 3: {missed:?}",
        missed.len()
    );
    assert!(
        laxer.is_empty(),
        "Holm scored {} above zxcvbn: {laxer:?}",
        laxer.len()
    );
}

#[test]
fn holm_accepts_strong_passwords() {
    let mut all: Vec<String> = STRONG.iter().map(|s| (*s).to_owned()).collect();
    all.extend(random_strings());
    for p in &all {
        let z = u8::from(zxcvbn::zxcvbn(p, &["holm"]).score());
        let h = holm(p).verdict;
        assert!(z >= MIN_MASTER_SCORE, "oracle doubts the strong set: {p}");
        assert!(
            h.acceptable,
            "Holm refused a strong password: {p} (score {})",
            h.score
        );
    }
}
