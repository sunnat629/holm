//! Holm's strength check against zxcvbn, used here as a test oracle only.
//!
//! The rule: every password that zxcvbn scores below 4 (under 10^10 guesses) must be
//! refused by Holm too. Holm's score is also never above zxcvbn's. Two corpora are
//! checked: a fixed one built from word lists, suffixes and variants, and a generated one
//! of compositions (doubled words, prefix + repeat, walks and dates in the middle, l33t +
//! year, capitalised word + digits + symbols, three-piece mixes) from a fixed seed. Every
//! candidate is under 100 characters, where zxcvbn scores the whole string. A strong set
//! must be accepted, including passwords just over zxcvbn's score-4 boundary, so the
//! check cannot pass by refusing everything or by a threshold set too high.
//!
//! zxcvbn 3.1.1's guess counts can vary between runs for l33t input (its substitution
//! search iterates a `HashMap`). Its scores were stable in practice, and Holm tries every
//! substitution, so the variation should only make zxcvbn rate a candidate higher, which
//! drops it from the weak set. If this test ever flakes, look there first.

use holm_core::strength::{MIN_MASTER_CHARS, MIN_MASTER_SCORE, check};
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

/// Extra words for the generator: names and words that double well, plus the words from
/// the repeat cases review found.
const MORE_WORDS: &[&str] = &[
    "hello", "steven", "orange", "bryce", "darn", "justine", "shoe", "close", "ragsdale", "yoyo",
    "tiger", "angel", "lover", "music", "silver", "ginger", "pepper", "cookie", "soccer", "hockey",
    "killer", "george", "andrew", "thomas", "robert", "daniel", "ashley", "nicole", "jessica",
    "amanda", "blue", "red", "green", "black", "happy", "sunny", "money", "love", "baby", "girl",
    "boy", "king", "queen", "star", "moon", "sky", "fire", "rock",
];

const WALKS: &[&str] = &[
    "qwerty", "asdf", "zxcvbn", "1qaz2wsx", "qazwsx", "poiuy", "7410", "8520", "!@#$", "123456",
    "09876", "asdfgh", "qwe", "zxc", "147258", "963", "wasd", "mnbvc",
];

const SEQUENCES: &[&str] = &[
    "abcd", "1234", "9876", "xyz", "abc", "4321", "2468", "13579",
];

const SYMBOLS: &[u8] = b"!@#$%&*?._-+";

/// A fixed-seed generator (SplitMix64), so the corpus is the same on every run.
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    fn word(&mut self) -> String {
        let w = if self.chance(50) {
            self.pick(BASES)
        } else {
            self.pick(MORE_WORDS)
        };
        self.styled(w)
    }

    /// The word plain, capitalised, all capitals, reversed or in l33t.
    fn styled(&mut self, w: &str) -> String {
        match self.below(6) {
            0 | 1 => w.to_owned(),
            2 => capitalised(w),
            3 => w.to_ascii_uppercase(),
            4 => w.chars().rev().collect(),
            _ => self.l33t(w),
        }
    }

    /// Each substitutable letter swapped for a look-alike with even odds.
    fn l33t(&mut self, w: &str) -> String {
        w.chars()
            .map(|c| {
                let options: &[char] = match c {
                    'a' => &['@', '4'],
                    'e' => &['3'],
                    'i' => &['1', '!'],
                    'o' => &['0'],
                    's' => &['$', '5'],
                    't' => &['7', '+'],
                    'l' => &['1', '|'],
                    'g' => &['9'],
                    _ => &[],
                };
                if options.is_empty() || self.chance(50) {
                    c
                } else {
                    options[self.below(options.len())]
                }
            })
            .collect()
    }

    fn year(&mut self) -> String {
        (1950 + self.below(81)).to_string()
    }

    fn date(&mut self) -> String {
        let d = 1 + self.below(28);
        let m = 1 + self.below(12);
        let y = 1950 + self.below(76);
        let yy = y % 100;
        match self.below(5) {
            0 => format!("{d:02}/{m:02}/{y}"),
            1 => format!("{y}-{m:02}-{d:02}"),
            2 => format!("{d:02}{m:02}{yy:02}"),
            3 => format!("{m:02}{d:02}{y}"),
            _ => format!("{d}.{m}.{y}"),
        }
    }

    fn digits(&mut self) -> String {
        let len = 1 + self.below(6);
        (0..len)
            .map(|_| char::from(b'0' + u8::try_from(self.below(10)).unwrap()))
            .collect()
    }

    fn symbols(&mut self) -> String {
        let len = 1 + self.below(3);
        (0..len)
            .map(|_| char::from(SYMBOLS[self.below(SYMBOLS.len())]))
            .collect()
    }

    fn middle(&mut self) -> String {
        match self.below(4) {
            0 => self.pick(WALKS).to_owned(),
            1 => self.date(),
            2 => self.pick(SEQUENCES).to_owned(),
            _ => self.year(),
        }
    }

    /// Any one piece.
    fn piece(&mut self) -> String {
        match self.below(6) {
            0 | 1 => self.word(),
            2 => self.middle(),
            3 => self.digits(),
            4 => self.symbols(),
            _ => self.year(),
        }
    }

    /// One candidate of the given shape.
    fn candidate(&mut self, shape: usize) -> String {
        match shape {
            // Two-word doubles, sometimes after a doubled short piece or a character that
            // shifts the repeat run (`yoyohellohello`).
            0 => {
                let (a, b) = (self.word(), self.word());
                match self.below(3) {
                    0 => format!("{a}{a}{b}{b}"),
                    1 => {
                        let last = a.chars().last().unwrap_or('x');
                        format!("{last}{a}{a}{b}{b}")
                    }
                    _ => {
                        let short = &a[..a.len().min(2)];
                        format!("{short}{short}{b}{b}")
                    }
                }
            }
            // A prefix, then a word two or three times.
            1 => {
                let w = self.word();
                let prefix = match self.below(4) {
                    0 => w.chars().last().map(String::from).unwrap_or_default(),
                    1 => self.digits(),
                    2 => self.symbols(),
                    _ => self.word(),
                };
                let copies = 2 + self.below(2);
                format!("{prefix}{}", w.repeat(copies))
            }
            // A walk, date, sequence or year between two words.
            2 => {
                let (a, m, b) = (self.word(), self.middle(), self.word());
                format!("{a}{m}{b}")
            }
            // A l33t word with a year, either order, maybe a symbol.
            3 => {
                let w = if self.chance(50) {
                    self.pick(BASES)
                } else {
                    self.pick(MORE_WORDS)
                };
                let (l, y) = (self.l33t(w), self.year());
                let sym = if self.chance(50) {
                    self.symbols()
                } else {
                    String::new()
                };
                if self.chance(70) {
                    format!("{l}{y}{sym}")
                } else {
                    format!("{y}{l}{sym}")
                }
            }
            // A capitalised word, digits and symbols.
            4 => {
                let w = if self.chance(50) {
                    self.pick(BASES)
                } else {
                    self.pick(MORE_WORDS)
                };
                let (c, d, s) = (capitalised(w), self.digits(), self.symbols());
                match self.below(3) {
                    0 => format!("{c}{d}{s}"),
                    1 => format!("{s}{c}{d}"),
                    _ => format!("{c}{s}{d}"),
                }
            }
            // Three pieces, any of them maybe doubled.
            _ => {
                let mut out = String::new();
                for _ in 0..3 {
                    let p = self.piece();
                    out.push_str(&p);
                    if self.chance(25) {
                        out.push_str(&p);
                    }
                }
                out
            }
        }
    }
}

fn capitalised(w: &str) -> String {
    let mut c = w.to_owned();
    if let Some(first) = c.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    c
}

/// The generated corpus: a fixed number of candidates of each shape, under 100 chars.
fn generated() -> Vec<String> {
    const PER_SHAPE: usize = 1_000;
    let mut g = Gen(0x0516_0bac_e5ee_d001);
    let mut out = Vec::new();
    for shape in 0..6 {
        let mut made = 0;
        while made < PER_SHAPE {
            let c = g.candidate(shape);
            if !c.is_empty() && c.chars().count() < 100 {
                out.push(c);
                made += 1;
            }
        }
    }
    out
}

/// Passwords zxcvbn puts just over its score-4 boundary (10^10.0 to 10^10.4 guesses, no
/// l33t, so zxcvbn's count is stable). Holm must accept them, so a threshold set above
/// 10^10 fails. They are not good passwords; they show where the line is.
const BORDERLINE_STRONG: &[&str] = &[
    "Red1990-12-04hockey",
    "moon2014-07-01music",
    "sky04101969london",
    "master24.3.1964queen",
    "Summer14/02/1965Hello",
    "happywasdsunny",
    "lover091201BRYCE",
    "rats1993-04-10123456",
];

fn holm(s: &str) -> holm_core::strength::StrengthReport {
    check(&MasterPassword::new(s.to_owned()))
}

struct Tally {
    weak_by_zxcvbn: usize,
    strong_by_zxcvbn: usize,
    over_refused: usize,
    missed: Vec<String>,
    laxer: Vec<String>,
}

fn compare(corpus: &[String]) -> Tally {
    let mut t = Tally {
        weak_by_zxcvbn: 0,
        strong_by_zxcvbn: 0,
        over_refused: 0,
        missed: Vec::new(),
        laxer: Vec::new(),
    };
    for p in corpus {
        let z = u8::from(zxcvbn::zxcvbn(p, &["holm"]).score());
        let h = holm(p).verdict;
        if z < MIN_MASTER_SCORE {
            t.weak_by_zxcvbn += 1;
            if h.acceptable {
                t.missed.push(p.clone());
            }
        } else if h.chars >= MIN_MASTER_CHARS {
            t.strong_by_zxcvbn += 1;
            if !h.acceptable {
                t.over_refused += 1;
            }
        }
        if h.score > z {
            t.laxer.push(p.clone());
        }
    }
    t
}

fn assert_no_misses(name: &str, t: &Tally) {
    assert!(
        t.missed.is_empty(),
        "{name}: Holm accepted {} that zxcvbn scores below 4: {:?}",
        t.missed.len(),
        t.missed
    );
    assert!(
        t.laxer.is_empty(),
        "{name}: Holm scored {} above zxcvbn: {:?}",
        t.laxer.len(),
        t.laxer
    );
}

#[test]
fn holm_refuses_everything_zxcvbn_finds_weak() {
    let t = compare(&corpus());
    eprintln!(
        "fixed corpus: {} weak by zxcvbn, {} strong, {} of those refused by Holm",
        t.weak_by_zxcvbn, t.strong_by_zxcvbn, t.over_refused
    );
    assert!(
        t.weak_by_zxcvbn > 10_000,
        "corpus too small: {}",
        t.weak_by_zxcvbn
    );
    assert_no_misses("fixed corpus", &t);
}

#[test]
fn holm_refuses_generated_weak_compositions() {
    let corpus = generated();
    assert!(corpus.len() >= 6_000);
    assert!(corpus.iter().all(|p| p.chars().count() < 100));
    let t = compare(&corpus);
    eprintln!(
        "generated corpus: {} weak by zxcvbn, {} strong, {} of those refused by Holm",
        t.weak_by_zxcvbn, t.strong_by_zxcvbn, t.over_refused
    );
    assert!(
        t.weak_by_zxcvbn >= 3_000,
        "too few weak: {}",
        t.weak_by_zxcvbn
    );
    assert_no_misses("generated corpus", &t);
    // Holm refuses some passwords zxcvbn rates 4, where it finds a cheaper reading
    // (an aligned repeat, an independent l33t swap, an overlapping year). On this seed
    // that is 173 of 546. The bound is a tripwire for a threshold or matcher that
    // suddenly refuses far more.
    assert!(
        t.over_refused * 100 <= t.strong_by_zxcvbn * 35,
        "Holm refused {} of {} that zxcvbn scores 4",
        t.over_refused,
        t.strong_by_zxcvbn
    );
}

#[test]
fn holm_accepts_strong_passwords() {
    let mut all: Vec<String> = STRONG.iter().map(|s| (*s).to_owned()).collect();
    all.extend(BORDERLINE_STRONG.iter().map(|s| (*s).to_owned()));
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
