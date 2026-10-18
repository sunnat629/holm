//! Pattern matchers: each finds guessable pieces of the password and prices them.
//!
//! The matchers and their guess formulas follow zxcvbn (Dropbox's CoffeeScript v4.4.2 and
//! the Rust `zxcvbn` 3.1.1 port). Where the two differ, or where a zxcvbn rule depends on
//! the clock or truncates input, Holm picks the stricter choice, so a piece Holm prices is
//! never priced higher than zxcvbn would price it. Notes on each matcher say where Holm
//! differs.
//!
//! A [`Match`] holds only a span, a guess count and a feedback hint, never characters.
//! Every heap buffer here is a [`Zeroizing`] vector that grows through [`push_wiped`], so no
//! copy of password-derived data is freed unwiped.

use zeroize::{DefaultIsZeroes, Zeroizing};

use super::keyboard;
use super::lists::{self, Entry, MAX_WORD_LEN, Source};
use super::scoring::{self, Budget, CAP};

/// What kind of piece a match is. Used only to pick fixed feedback text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Hint {
    /// No pattern: priced as random characters.
    #[default]
    Bruteforce,
    /// A listed word, from this list.
    Word(Source),
    /// A keyboard walk.
    Keyboard,
    /// The same characters again and again.
    Repeat,
    /// Steps through letters or digits, such as `abc` or `975`.
    Sequence,
    /// A year from 1900 to 2099.
    Year,
    /// A calendar date.
    Date,
}

/// Match flag: some letters are upper case.
pub(crate) const CAPS: u8 = 1;
/// Match flag: all letters are upper case.
pub(crate) const ALL_CAPS: u8 = 2;
/// Match flag: the word is spelled backwards.
pub(crate) const REVERSED: u8 = 4;
/// Match flag: look-alike symbols stand in for letters.
pub(crate) const L33T: u8 = 8;

/// One guessable piece: characters `i..=j` cost about `guesses` guesses.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Match {
    pub(crate) i: usize,
    pub(crate) j: usize,
    pub(crate) guesses: f64,
    pub(crate) hint: Hint,
    pub(crate) flags: u8,
}

impl DefaultIsZeroes for Match {}

/// A password under analysis: its characters, and the same characters with ASCII letters
/// lower-cased. Both slices have the same length, so indices line up.
#[derive(Clone, Copy)]
pub(crate) struct Text<'a> {
    pub(crate) chars: &'a [char],
    pub(crate) lower: &'a [char],
}

/// Pushes onto a wiping vector. When it is full, the contents move to a vector twice the
/// size and the old one is wiped as it drops, so growth leaves no stale copy behind.
pub(crate) fn push_wiped<T: DefaultIsZeroes>(v: &mut Zeroizing<Vec<T>>, x: T) {
    if v.len() == v.capacity() {
        let mut bigger = Zeroizing::new(Vec::with_capacity(v.capacity().saturating_mul(2).max(16)));
        bigger.extend_from_slice(v);
        *v = bigger;
    }
    v.push(x);
}

/// Copies characters into a new wiping vector sized for `len` of them.
pub(crate) fn wiped_chars(chars: impl Iterator<Item = char>, len: usize) -> Zeroizing<Vec<char>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    for c in chars {
        push_wiped(&mut out, c);
    }
    out
}

/// Runs every matcher over `text`.
pub(crate) fn all_matches(text: Text<'_>, budget: &mut Budget) -> Zeroizing<Vec<Match>> {
    let mut out = Zeroizing::new(Vec::new());
    dictionary(text, &mut out);
    reversed_dictionary(text, &mut out);
    keyboard_walks(text, &mut out);
    repeats(text, budget, &mut out);
    sequences(text, &mut out);
    years(text, &mut out);
    dates(text, &mut out);
    out
}

// ---- Dictionary -------------------------------------------------------------------------

/// Letters a look-alike symbol may stand for (zxcvbn's l33t table, inverted).
fn l33t_letters(c: char) -> &'static [u8] {
    match c {
        '4' | '@' => b"a",
        '8' => b"b",
        '(' | '{' | '[' | '<' => b"c",
        '3' => b"e",
        '6' | '9' => b"g",
        '!' => b"i",
        '1' | '|' => b"il",
        '7' => b"lt",
        '0' => b"o",
        '$' | '5' => b"s",
        '+' => b"t",
        '%' => b"x",
        '2' => b"z",
        _ => b"",
    }
}

/// A point in the dictionary walk: `depth` characters matched, and `lo..hi` is the range of
/// list entries that start with them.
#[derive(Clone, Copy, Default)]
struct Step {
    depth: usize,
    lo: usize,
    hi: usize,
    subbed: bool,
}

impl DefaultIsZeroes for Step {}

/// The most walk steps tried from one start position. A real word list never gets near
/// it; it only stops a crafted input from making the walk slow.
const MAX_STEPS_PER_START: usize = 4_096;

/// Finds every listed word in `text` starting at each position. With `l33t`, a look-alike
/// symbol may also stand for its letter. `found(start, end, entry, subbed)` gets each hit.
///
/// zxcvbn tries one substitution map for the whole password at a time; Holm lets each
/// symbol stand for any of its letters independently. That finds every word zxcvbn finds,
/// and more.
fn walk_words(text: Text<'_>, l33t: bool, mut found: impl FnMut(usize, usize, &Entry, bool)) {
    let list = lists::entries();
    let n = text.chars.len();
    let mut stack: Zeroizing<Vec<Step>> = Zeroizing::new(Vec::with_capacity(64));
    for start in 0..n {
        stack.clear();
        push_wiped(
            &mut stack,
            Step {
                depth: 0,
                lo: 0,
                hi: list.len(),
                subbed: false,
            },
        );
        let mut steps = 0;
        while let Some(step) = stack.pop() {
            steps += 1;
            if steps > MAX_STEPS_PER_START {
                break;
            }
            let Step {
                depth, lo, subbed, ..
            } = step;
            // Sorting puts a word before every longer word it is a prefix of.
            if depth > 0 && list[lo].word.len() == depth {
                found(start, start + depth - 1, &list[lo], subbed);
            }
            let pos = start + depth;
            if pos >= n || depth >= MAX_WORD_LEN {
                continue;
            }
            let literal = text.lower[pos];
            if literal.is_ascii() {
                narrow(&mut stack, list, step, literal as u8, subbed);
            }
            if l33t {
                for &letter in l33t_letters(text.chars[pos]) {
                    narrow(&mut stack, list, step, letter, true);
                }
            }
        }
    }
}

/// Pushes the sub-range of `step` whose next byte is `b`, if it is not empty.
fn narrow(stack: &mut Zeroizing<Vec<Step>>, list: &[Entry], step: Step, b: u8, subbed: bool) {
    let d = step.depth;
    let range = &list[step.lo..step.hi];
    let next = |e: &Entry| e.word.as_bytes().get(d).copied();
    let lo = range.partition_point(|e| next(e) < Some(b));
    let hi = range.partition_point(|e| next(e) <= Some(b));
    if lo < hi {
        push_wiped(
            stack,
            Step {
                depth: d + 1,
                lo: step.lo + lo,
                hi: step.lo + hi,
                subbed,
            },
        );
    }
}

/// Listed words, plain or with look-alike symbols: rank x case variations x l33t
/// variations.
fn dictionary(text: Text<'_>, out: &mut Zeroizing<Vec<Match>>) {
    walk_words(text, true, |i, j, entry, subbed| {
        let token = &text.chars[i..=j];
        let (case, mut flags) = uppercase_variations(token);
        let mut guesses = f64::from(entry.rank) * case;
        if subbed {
            guesses *= l33t_variations(token, &text.lower[i..=j], entry.word);
            flags |= L33T;
        }
        push_wiped(
            out,
            Match {
                i,
                j,
                guesses: guesses.min(CAP),
                hint: Hint::Word(entry.source),
                flags,
            },
        );
    });
}

/// Listed words spelled backwards: twice the plain price. No look-alikes, as in zxcvbn.
fn reversed_dictionary(text: Text<'_>, out: &mut Zeroizing<Vec<Match>>) {
    let n = text.chars.len();
    let chars = wiped_chars(text.chars.iter().rev().copied(), n);
    let lower = wiped_chars(text.lower.iter().rev().copied(), n);
    let reversed = Text {
        chars: &chars,
        lower: &lower,
    };
    walk_words(reversed, false, |ri, rj, entry, _| {
        let (i, j) = (n - 1 - rj, n - 1 - ri);
        let (case, flags) = uppercase_variations(&text.chars[i..=j]);
        let guesses = f64::from(entry.rank) * case * 2.0;
        push_wiped(
            out,
            Match {
                i,
                j,
                guesses: guesses.min(CAP),
                hint: Hint::Word(entry.source),
                flags: flags | REVERSED,
            },
        );
    });
}

/// How many ways the word's letters could have been capitalised (zxcvbn's formula,
/// including its zero when every letter is upper case but the token also has a digit;
/// the caller's floor turns that zero into the minimum price).
fn uppercase_variations(token: &[char]) -> (f64, u8) {
    let upper = token.iter().filter(|c| c.is_uppercase()).count();
    let lower = token.iter().filter(|c| c.is_lowercase()).count();
    if upper == 0 {
        return (1.0, 0);
    }
    let flags = if lower == 0 { ALL_CAPS } else { CAPS };
    let first = token.first().is_some_and(|c| c.is_uppercase());
    let last = token.last().is_some_and(|c| c.is_uppercase());
    if ((first || last) && upper == 1) || upper == token.len() {
        return (2.0, flags);
    }
    let ways: f64 = (1..=upper.min(lower))
        .map(|k| n_choose_k(upper + lower, k))
        .sum();
    (ways, flags)
}

/// How many ways the substitutions could have been made (zxcvbn's formula).
fn l33t_variations(token: &[char], lower: &[char], word: &str) -> f64 {
    // Distinct (symbol, letter) pairs used. A word has at most MAX_WORD_LEN of them.
    let mut pairs = [('\0', '\0'); MAX_WORD_LEN];
    let mut used = 0;
    for (p, w) in word.bytes().enumerate() {
        let w = char::from(w);
        if lower[p] != w {
            let pair = (token[p], w);
            if !pairs[..used].contains(&pair) && used < pairs.len() {
                pairs[used] = pair;
                used += 1;
            }
        }
    }
    let mut variations = 1.0;
    for &(symbol, letter) in &pairs[..used] {
        let s = lower.iter().filter(|&&c| c == symbol).count();
        let u = lower.iter().filter(|&&c| c == letter).count();
        if s == 0 || u == 0 {
            variations *= 2.0;
        } else {
            variations *= (1..=s.min(u)).map(|k| n_choose_k(s + u, k)).sum::<f64>();
        }
    }
    variations
}

/// Binomial coefficient, as a float (exact while it is below 2^53).
pub(crate) fn n_choose_k(n: usize, k: usize) -> f64 {
    if k > n {
        return 0.0;
    }
    let mut r = 1.0;
    for d in 1..=k {
        r = r * (n + 1 - d) as f64 / d as f64;
    }
    r
}

// ---- Keyboard walks ---------------------------------------------------------------------

/// Runs of three or more adjacent keys on qwerty, dvorak and two keypads. The price grows
/// with length, turns and shifted keys (zxcvbn's formula). Holm's shifted set leaves out
/// `[` and `]`, which zxcvbn 3.1.1 counts by mistake; fewer shifts is a lower price.
fn keyboard_walks(text: Text<'_>, out: &mut Zeroizing<Vec<Match>>) {
    let chars = text.chars;
    let n = chars.len();
    if n <= 2 {
        return;
    }
    for graph in keyboard::graphs() {
        let mut i = 0;
        while i < n - 1 {
            let mut j = i + 1;
            let mut last_direction = None;
            let mut turns = 0;
            let mut shifted = usize::from(graph.counts_shift && keyboard::is_shifted(chars[i]));
            loop {
                let step = chars
                    .get(j)
                    .and_then(|&cur| adjacent_direction(graph, chars[j - 1], cur));
                if let Some((direction, position)) = step {
                    if position == 1 {
                        shifted += 1;
                    }
                    if last_direction != Some(direction) {
                        turns += 1;
                        last_direction = Some(direction);
                    }
                    j += 1;
                    continue;
                }
                if j - i > 2 {
                    let guesses = walk_guesses(j - i, turns, shifted, graph);
                    push_wiped(
                        out,
                        Match {
                            i,
                            j: j - 1,
                            guesses,
                            hint: Hint::Keyboard,
                            flags: 0,
                        },
                    );
                }
                i = j;
                break;
            }
        }
    }
}

/// The direction from `prev` to `cur` on `graph`, and `cur`'s place on its key (1 means
/// shifted), if the keys are neighbours.
fn adjacent_direction(graph: &keyboard::Graph, prev: char, cur: char) -> Option<(usize, usize)> {
    graph
        .adjacent
        .get(&prev)?
        .iter()
        .enumerate()
        .find_map(|(direction, key)| Some((direction, key.and_then(|k| k.find(cur))?)))
}

fn walk_guesses(len: usize, turns: usize, shifted: usize, graph: &keyboard::Graph) -> f64 {
    let mut guesses = 0.0;
    'outer: for i in 2..=len {
        for t in 1..=turns.min(i - 1) {
            guesses += n_choose_k(i - 1, t - 1) * graph.starts * graph.degree.powi(to_i32(t));
            if guesses >= CAP {
                break 'outer;
            }
        }
    }
    if shifted > 0 {
        let unshifted = len - shifted;
        if unshifted == 0 {
            guesses *= 2.0;
        } else {
            let mut ways = 0.0;
            for k in 1..=shifted.min(unshifted) {
                ways += n_choose_k(shifted + unshifted, k);
                if ways >= CAP {
                    break;
                }
            }
            guesses *= ways;
        }
    }
    guesses.min(CAP)
}

fn to_i32(n: usize) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

// ---- Repeats ----------------------------------------------------------------------------

/// The longest repeated unit Holm looks for. Longer units are not searched for, so their
/// copies are priced as whatever else they match. This bounds the work at about
/// `MAX_REPEAT_UNIT` steps per character, however long the password is.
pub(crate) const MAX_REPEAT_UNIT: usize = 512;

/// Two or more back-to-back copies of a unit: the unit's own price times the copy count.
///
/// zxcvbn finds one repeat at a time, left to right, with a regex. Holm finds every
/// maximal run for every unit length up to [`MAX_REPEAT_UNIT`], which includes zxcvbn's
/// matches. The unit is priced by a full estimate of its own (as zxcvbn does), drawn from a
/// shared [`Budget`].
fn repeats(text: Text<'_>, budget: &mut Budget, out: &mut Zeroizing<Vec<Match>>) {
    let chars = text.chars;
    let n = chars.len();
    for unit in 1..=MAX_REPEAT_UNIT.min(n / 2) {
        let mut k = 0;
        while k + unit < n {
            if chars[k] != chars[k + unit] {
                k += 1;
                continue;
            }
            let start = k;
            while k + unit < n && chars[k] == chars[k + unit] {
                k += 1;
            }
            let copies = (k - start + unit) / unit;
            if copies >= 2 && is_primitive(&chars[start..start + unit]) {
                let base = Text {
                    chars: &chars[start..start + unit],
                    lower: &text.lower[start..start + unit],
                };
                let guesses = (scoring::unit_guesses(base, budget) * copies as f64).min(CAP);
                push_wiped(
                    out,
                    Match {
                        i: start,
                        j: start + copies * unit - 1,
                        guesses,
                        hint: Hint::Repeat,
                        flags: 0,
                    },
                );
            }
        }
    }
}

/// True when `unit` is not itself a repeat of a shorter unit. A non-primitive unit's run
/// is already found, with more copies, at the shorter length.
fn is_primitive(unit: &[char]) -> bool {
    let len = unit.len();
    !(1..len).any(|p| len.is_multiple_of(p) && (p..len).all(|x| unit[x] == unit[x - p]))
}

// ---- Sequences --------------------------------------------------------------------------

/// The largest step between code points that still counts as a sequence.
const MAX_SEQUENCE_STEP: i64 = 5;

/// Runs with a constant step of 1 to 5 code points, up or down, such as `abcd`, `9753` or
/// `zyx` (zxcvbn's scan and formula, kept exactly, including its habit of counting a
/// leading repeated character into the run).
fn sequences(text: Text<'_>, out: &mut Zeroizing<Vec<Match>>) {
    let chars = text.chars;
    let n = chars.len();
    if n <= 1 {
        return;
    }
    let mut i = 0;
    let mut last_step = 0i64;
    for k in 1..n {
        let step = i64::from(u32::from(chars[k])) - i64::from(u32::from(chars[k - 1]));
        if last_step == 0 {
            last_step = step;
        }
        if last_step == step {
            continue;
        }
        sequence_match(chars, i, k - 1, last_step, out);
        i = k - 1;
        last_step = step;
    }
    sequence_match(chars, i, n - 1, last_step, out);
}

fn sequence_match(chars: &[char], i: usize, j: usize, step: i64, out: &mut Zeroizing<Vec<Match>>) {
    let size = step.abs();
    if !((j - i > 1 || size == 1) && 0 < size && size <= MAX_SEQUENCE_STEP) {
        return;
    }
    let first = chars[i];
    let mut base = if "aAzZ019".contains(first) {
        4.0
    } else if first.is_ascii_digit() {
        10.0
    } else {
        26.0
    };
    if step < 0 {
        base *= 2.0;
    }
    let guesses = base * (j - i + 1) as f64;
    push_wiped(
        out,
        Match {
            i,
            j,
            guesses,
            hint: Hint::Sequence,
            flags: 0,
        },
    );
}

// ---- Years and dates --------------------------------------------------------------------

/// The year Holm prices years against. zxcvbn reads the clock; Holm does not. Years from
/// this one on all get the minimum price, and earlier years cost their distance from it.
/// As the real year moves on, zxcvbn's price for any year only stays the same or grows,
/// so Holm never prices a year above zxcvbn.
pub(crate) const REFERENCE_YEAR: i32 = 2026;

/// The fewest years an attacker is assumed to try (zxcvbn's `MIN_YEAR_SPACE`).
const MIN_YEAR_SPACE: i32 = 20;

fn year_space(year: i32) -> f64 {
    f64::from((REFERENCE_YEAR - year).max(MIN_YEAR_SPACE))
}

/// Every `19xx` or `20xx`, overlapping ones included (zxcvbn takes them left to right
/// without overlap).
fn years(text: Text<'_>, out: &mut Zeroizing<Vec<Match>>) {
    let chars = text.chars;
    for i in 0..chars.len().saturating_sub(3) {
        let w = &chars[i..i + 4];
        if matches!((w[0], w[1]), ('1', '9') | ('2', '0'))
            && w[2].is_ascii_digit()
            && w[3].is_ascii_digit()
        {
            let guesses = year_space(i32::from(number(w)));
            push_wiped(
                out,
                Match {
                    i,
                    j: i + 3,
                    guesses,
                    hint: Hint::Year,
                    flags: 0,
                },
            );
        }
    }
}

/// zxcvbn's date range.
const DATE_MIN_YEAR: u16 = 1000;
const DATE_MAX_YEAR: u16 = 2050;

/// Ways to split a run of 4 to 8 digits into day, month and year (zxcvbn's table).
fn date_splits(len: usize) -> &'static [(usize, usize)] {
    match len {
        4 => &[(1, 2), (2, 3)],
        5 => &[(1, 3), (2, 3)],
        6 => &[(1, 2), (2, 4), (4, 5)],
        7 => &[(1, 3), (2, 3), (4, 5), (4, 6)],
        8 => &[(2, 4), (4, 6)],
        _ => &[],
    }
}

/// Dates as 4 to 8 digits (`1121`, `19901104`) or with one repeated separator
/// (`11/4/1990`, `1990.11.04`): years from the reference x 365 days, x 4 with a separator.
///
/// zxcvbn then drops dates that sit inside a longer date; Holm keeps them, which can only
/// lower the price.
fn dates(text: Text<'_>, out: &mut Zeroizing<Vec<Match>>) {
    let chars = text.chars;
    let n = chars.len();
    for i in 0..n.saturating_sub(3) {
        for j in i + 3..(i + 8).min(n) {
            let token = &chars[i..=j];
            if !token.iter().all(char::is_ascii_digit) {
                break;
            }
            let best = date_splits(token.len())
                .iter()
                .filter_map(|&(k, l)| {
                    ymd(
                        number(&token[..k]),
                        number(&token[k..l]),
                        number(&token[l..]),
                    )
                })
                .map(year_space)
                .reduce(f64::min);
            if let Some(space) = best {
                push_wiped(
                    out,
                    Match {
                        i,
                        j,
                        guesses: space * 365.0,
                        hint: Hint::Date,
                        flags: 0,
                    },
                );
            }
        }
    }
    for i in 0..n.saturating_sub(5) {
        for j in i + 5..(i + 10).min(n) {
            if let Some(year) = separated_date(&chars[i..=j]) {
                let guesses = year_space(year) * 365.0 * 4.0;
                push_wiped(
                    out,
                    Match {
                        i,
                        j,
                        guesses,
                        hint: Hint::Date,
                        flags: 0,
                    },
                );
            }
        }
    }
}

/// Parses `d{1,4} sep d{1,2} sep d{1,4}` with the same separator twice, and returns the
/// date's year.
fn separated_date(token: &[char]) -> Option<i32> {
    let is_sep = |c: char| c.is_whitespace() || "/\\_.-".contains(c);
    let digits = |from: usize| {
        token[from..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count()
    };
    let a = digits(0);
    let sep = *token.get(a)?;
    let b = digits(a + 1);
    let second = *token.get(a + 1 + b)?;
    let c_from = a + 2 + b;
    let c = token.get(c_from..).map_or(0, |rest| {
        rest.iter().take_while(|c| c.is_ascii_digit()).count()
    });
    let shape_ok = (1..=4).contains(&a)
        && (1..=2).contains(&b)
        && (1..=4).contains(&c)
        && c_from + c == token.len()
        && is_sep(sep)
        && second == sep;
    if !shape_ok {
        return None;
    }
    ymd(
        number(&token[..a]),
        number(&token[a + 1..a + 1 + b]),
        number(&token[c_from..]),
    )
}

/// The value of 1 to 4 ASCII digits.
fn number(digits: &[char]) -> u16 {
    digits.iter().fold(0u16, |acc, c| {
        acc.saturating_mul(10)
            .saturating_add(c.to_digit(10).map_or(0, |d| d as u16))
    })
}

/// zxcvbn's `map_ints_to_ymd`: the year of a plausible day-month-year reading, if any.
fn ymd(first: u16, second: u16, third: u16) -> Option<i32> {
    if second > 31 || second == 0 {
        return None;
    }
    let all = [first, second, third];
    if all
        .iter()
        .any(|&x| (99 < x && x < DATE_MIN_YEAR) || x > DATE_MAX_YEAR)
    {
        return None;
    }
    let over_31 = all.iter().filter(|&&x| x > 31).count();
    let over_12 = all.iter().filter(|&&x| x > 12).count();
    let zero = all.iter().filter(|&&x| x == 0).count();
    if over_31 >= 2 || over_12 == 3 || zero >= 2 {
        return None;
    }
    let splits = [(third, first, second), (first, second, third)];
    for &(year, a, b) in &splits {
        if (DATE_MIN_YEAR..=DATE_MAX_YEAR).contains(&year) {
            return is_day_month(a, b).then_some(i32::from(year));
        }
    }
    for &(year, a, b) in &splits {
        if is_day_month(a, b) {
            let year = match year {
                0..=50 => year + 2000,
                51..=99 => year + 1900,
                _ => year,
            };
            return Some(i32::from(year));
        }
    }
    None
}

fn is_day_month(a: u16, b: u16) -> bool {
    let ok = |d: u16, m: u16| (1..=31).contains(&d) && (1..=12).contains(&m);
    ok(a, b) || ok(b, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches_of(s: &str) -> Vec<Match> {
        let chars: Vec<char> = s.chars().collect();
        let lower: Vec<char> = chars.iter().map(char::to_ascii_lowercase).collect();
        let mut budget = Budget::default();
        all_matches(
            Text {
                chars: &chars,
                lower: &lower,
            },
            &mut budget,
        )
        .to_vec()
    }

    fn has(s: &str, hint: Hint, i: usize, j: usize) -> bool {
        matches_of(s)
            .iter()
            .any(|m| m.hint == hint && m.i == i && m.j == j)
    }

    #[test]
    fn finds_each_pattern() {
        assert!(has("xpasswordx", Hint::Word(Source::Passwords), 1, 8));
        assert!(has("p@55w0rd", Hint::Word(Source::Passwords), 0, 7));
        assert!(has("drowssap", Hint::Word(Source::Passwords), 0, 7));
        assert!(has("Holm", Hint::Word(Source::Context), 0, 3));
        assert!(has("zxcvbnm", Hint::Keyboard, 0, 6));
        assert!(has("78963", Hint::Keyboard, 0, 4));
        assert!(has("abcabcabc", Hint::Repeat, 0, 8));
        assert!(has("xyz9753", Hint::Sequence, 3, 6));
        assert!(has("me1987", Hint::Year, 2, 5));
        assert!(has("11/04/1990", Hint::Date, 0, 9));
        assert!(has("19901104", Hint::Date, 0, 7));
    }

    #[test]
    fn prices_follow_zxcvbn_formulas() {
        let price = |s: &str, hint: Hint| {
            matches_of(s)
                .iter()
                .filter(|m| m.hint == hint && m.i == 0 && m.j + 1 == s.chars().count())
                .map(|m| m.guesses)
                .reduce(f64::min)
        };
        // Rank 2, plain.
        assert_eq!(price("password", Hint::Word(Source::Passwords)), Some(2.0));
        // First letter capitalised: x2. Reversed: x2.
        assert_eq!(price("Password", Hint::Word(Source::Passwords)), Some(4.0));
        assert_eq!(price("drowssap", Hint::Word(Source::Passwords)), Some(4.0));
        // `@` for `a` once: x2.
        assert_eq!(price("p@ssword", Hint::Word(Source::Passwords)), Some(4.0));
        // Sequence from `a`: 4 x length.
        assert_eq!(price("abcdef", Hint::Sequence), Some(24.0));
        // Year at the reference gets the minimum space.
        assert_eq!(price("2026", Hint::Year), Some(20.0));
        assert_eq!(price("1990", Hint::Year), Some(36.0));
    }

    #[test]
    fn date_rules() {
        assert_eq!(ymd(11, 4, 1990), Some(1990));
        assert_eq!(ymd(90, 11, 4), Some(1990));
        assert_eq!(ymd(4, 11, 12), Some(2012));
        assert_eq!(ymd(40, 40, 40), None);
        assert_eq!(
            separated_date(&"11/4/1990".chars().collect::<Vec<_>>()),
            Some(1990)
        );
        assert_eq!(
            separated_date(&"11/4.1990".chars().collect::<Vec<_>>()),
            None
        );
    }

    #[test]
    fn primitive_units() {
        let chars = |s: &str| s.chars().collect::<Vec<_>>();
        assert!(is_primitive(&chars("abc")));
        assert!(!is_primitive(&chars("abab")));
        assert!(!is_primitive(&chars("aaa")));
    }

    #[test]
    fn push_wiped_keeps_order() {
        let mut v = Zeroizing::new(Vec::new());
        for x in 0..100u32 {
            push_wiped(&mut v, x);
        }
        assert!(v.iter().copied().eq(0..100));
    }
}
