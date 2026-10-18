//! The embedded common-word lists.
//!
//! `frequency_lists.coffee` is Dropbox zxcvbn v4.4.2's `src/frequency_lists.coffee`, byte for
//! byte (MIT; provenance and SHA-256 in `NOTICE`, hash gate in `scripts/ci-local.sh`). Each
//! list line looks like `  passwords: "123456,password,...".split(",")`; a word's rank is its
//! 1-based position in its list, most common first. Holm adds one context word, `holm`, at
//! rank 1, the way zxcvbn treats a user input.

use std::sync::OnceLock;

/// Which list a word came from. Only used to pick feedback text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Source {
    /// Leaked passwords.
    #[default]
    Passwords,
    /// English Wikipedia, or US TV and film subtitles.
    Words,
    /// Census first names and surnames.
    Names,
    /// Words tied to this app (`holm`).
    Context,
}

/// One word of the merged list.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry {
    /// Lower-case ASCII word.
    pub(crate) word: &'static str,
    /// 1-based rank in its list; lower is more common.
    pub(crate) rank: u32,
    /// The list it came from.
    pub(crate) source: Source,
}

/// Words Holm treats as guessable context, each at rank 1.
const CONTEXT_WORDS: &[&str] = &["holm"];

/// The longest word in the lists, in bytes. Bounds the dictionary walk.
pub(crate) const MAX_WORD_LEN: usize = 23;

const RAW: &str = include_str!("frequency_lists.coffee");

/// The merged list, sorted by word bytes, one entry per word (lowest rank wins).
pub(crate) fn entries() -> &'static [Entry] {
    static LIST: OnceLock<Vec<Entry>> = OnceLock::new();
    LIST.get_or_init(build)
}

fn build() -> Vec<Entry> {
    let mut out = Vec::with_capacity(94_000);
    for (name, words) in RAW.lines().filter_map(parse_line) {
        let source = match name {
            "passwords" => Source::Passwords,
            "female_names" | "male_names" | "surnames" => Source::Names,
            _ => Source::Words,
        };
        for (rank, word) in (1u32..).zip(words.split(',')) {
            out.push(Entry { word, rank, source });
        }
    }
    for &word in CONTEXT_WORDS {
        out.push(Entry {
            word,
            rank: 1,
            source: Source::Context,
        });
    }
    // Sort by word, then rank, then keep the first (lowest rank) of each word.
    out.sort_unstable_by(|a, b| a.word.cmp(b.word).then(a.rank.cmp(&b.rank)));
    out.dedup_by(|later, kept| later.word == kept.word);
    out
}

/// `  name: "a,b,c".split(",")` gives `("name", "a,b,c")`. Other lines give `None`.
fn parse_line(line: &'static str) -> Option<(&'static str, &'static str)> {
    let rest = line.strip_prefix("  ")?;
    let (name, rest) = rest.split_once(": \"")?;
    let words = rest.strip_suffix("\".split(\",\")")?;
    Some((name, words))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_integrity() {
        let counts: Vec<(&str, usize)> = RAW
            .lines()
            .filter_map(parse_line)
            .map(|(name, words)| (name, words.split(',').count()))
            .collect();
        assert_eq!(
            counts,
            [
                ("passwords", 30_000),
                ("english_wikipedia", 30_000),
                ("female_names", 3_712),
                ("surnames", 10_000),
                ("us_tv_and_film", 19_160),
                ("male_names", 983),
            ]
        );
        let list = entries();
        assert!(list.windows(2).all(|w| w[0].word < w[1].word));
        assert!(list.iter().all(|e| {
            !e.word.is_empty()
                && e.word.len() <= MAX_WORD_LEN
                && e.word
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase())
        }));
        let find = |w: &str| list.binary_search_by(|e| e.word.cmp(w)).map(|i| list[i]);
        let password = find("password").expect("password listed");
        assert_eq!((password.rank, password.source), (2, Source::Passwords));
        let holm = find("holm").expect("holm listed");
        assert_eq!((holm.rank, holm.source), (1, Source::Context));
    }
}
