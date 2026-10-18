//! The guess estimate: the cheapest way to build the whole password from matches.
//!
//! As in zxcvbn, a password split into `l` pieces costs `l! x (product of piece prices) +
//! 10000^(l-1)` guesses (the additive term is 1 for a single piece). Gaps between matches
//! are priced as random characters, `10^length`. Holm finds the cheapest split of the
//! matches it found, exactly, with dynamic programming. It is the true minimum only for
//! that set of matches: if Holm misses a piece that zxcvbn finds, Holm's estimate can be
//! higher than zxcvbn's. `tests/strength_oracle.rs` measures that; nothing proves it away.
//!
//! Two bounds keep the work linear in the password length without changing the score:
//! - At most [`MAX_PIECES`] pieces. Five or more pieces cost over `10000^4 = 1e16` from the
//!   additive term alone, far above the top score boundary.
//! - Random gaps of at most [`MAX_GAP`] characters, plus a random prefix of any length. A
//!   longer gap costs at least `1e11`, also above the top boundary, and the prefix keeps
//!   every split possible.
//!
//! Prices saturate at [`CAP`], which is far above every boundary.

use zeroize::{DefaultIsZeroes, Zeroizing};

use super::matching::{self, Hint, Match, Text, push_wiped};

/// Prices stop growing here. Every score boundary is far below it.
pub(crate) const CAP: f64 = 1e20;

/// The most pieces a split may have.
const MAX_PIECES: usize = 4;

/// The longest random gap between two matches.
const MAX_GAP: usize = 10;

/// zxcvbn's lowest price for a piece shorter than the whole password.
const MIN_SINGLE_CHAR_GUESSES: f64 = 10.0;
const MIN_MULTI_CHAR_GUESSES: f64 = 50.0;

/// Characters that repeat units may still be priced with a full estimate of their own.
/// After that a unit is priced at one guess, the strictest choice. Ordinary passwords use a
/// tiny fraction of it; only a crafted input of many long repeats can run it out.
pub(crate) const UNIT_BUDGET: usize = 1 << 14;

/// The shared allowance for pricing repeat units.
pub(crate) struct Budget {
    remaining: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            remaining: UNIT_BUDGET,
        }
    }
}

impl Budget {
    /// Characters left to price in depth.
    #[cfg(test)]
    pub(crate) fn remaining(&self) -> usize {
        self.remaining
    }
}

/// The estimate for a whole text.
pub(crate) struct Estimate {
    /// Guesses an attacker following zxcvbn's model needs.
    pub(crate) guesses: f64,
    /// The pieces of the cheapest split, in order.
    pub(crate) pieces: Zeroizing<Vec<Match>>,
}

/// Estimates `text` from scratch.
pub(crate) fn estimate(text: Text<'_>, budget: &mut Budget) -> Estimate {
    let found = matching::all_matches(text, budget);
    cheapest_split(text.chars.len(), &found)
}

/// Prices a repeat unit by estimating it on its own, as zxcvbn does.
pub(crate) fn unit_guesses(unit: Text<'_>, budget: &mut Budget) -> f64 {
    let len = unit.chars.len();
    if budget.remaining < len {
        return 1.0;
    }
    budget.remaining -= len;
    estimate(unit, budget).guesses
}

/// zxcvbn's score from a guess count: 0 to 4, with boundaries at 1e3, 1e6, 1e8 and 1e10
/// (each plus 5).
pub(crate) fn score(guesses: f64) -> u8 {
    const DELTA: f64 = 5.0;
    match guesses {
        g if g < 1e3 + DELTA => 0,
        g if g < 1e6 + DELTA => 1,
        g if g < 1e8 + DELTA => 2,
        g if g < 1e10 + DELTA => 3,
        _ => 4,
    }
}

/// One cell of the table: the cheapest split of the text up to some position into some
/// number of pieces, ending in a random gap or not.
#[derive(Clone, Copy, Default)]
struct Cell {
    /// Product of piece prices, or 0 when no such split exists.
    product: f64,
    /// The last piece.
    last: Match,
    /// Whether the split before `last` ended in a random gap.
    before_was_gap: bool,
}

impl DefaultIsZeroes for Cell {}

fn cell(end: usize, pieces: usize, gap: bool) -> usize {
    (end * MAX_PIECES + (pieces - 1)) * 2 + usize::from(gap)
}

fn cheapest_split(n: usize, found: &[Match]) -> Estimate {
    let mut pieces = Zeroizing::new(Vec::with_capacity(MAX_PIECES));
    if n == 0 {
        return Estimate {
            guesses: 1.0,
            pieces,
        };
    }
    let mut by_end = Zeroizing::new(Vec::with_capacity(found.len()));
    by_end.extend_from_slice(found);
    by_end.sort_unstable_by_key(|m| m.j);

    let mut table = Zeroizing::new(vec![Cell::default(); n * MAX_PIECES * 2]);
    let mut next = 0;
    for end in 0..n {
        while next < by_end.len() && by_end[next].j == end {
            let mut m = by_end[next];
            m.guesses = m.guesses.max(floor(m.j - m.i + 1, n));
            add(&mut table, m, false);
            next += 1;
        }
        let first_gap = end.saturating_sub(MAX_GAP - 1);
        for start in first_gap..=end {
            add(&mut table, gap(start, end), true);
        }
        if first_gap > 0 {
            add(&mut table, gap(0, end), true);
        }
    }

    // Pick the cheapest split of the whole text, then walk it back.
    let mut best = (f64::INFINITY, 1, false);
    for count in 1..=MAX_PIECES {
        for ends_in_gap in [false, true] {
            let c = table[cell(n - 1, count, ends_in_gap)];
            if c.product > 0.0 {
                let g = (factorial(count) * c.product + additive(count)).min(CAP);
                if g < best.0 {
                    best = (g, count, ends_in_gap);
                }
            }
        }
    }
    let (guesses, mut count, mut ends_in_gap) = best;
    let mut end = n - 1;
    loop {
        let c = table[cell(end, count, ends_in_gap)];
        push_wiped(&mut pieces, c.last);
        if c.last.i == 0 || count == 1 {
            break;
        }
        end = c.last.i - 1;
        ends_in_gap = c.before_was_gap;
        count -= 1;
    }
    pieces.reverse();
    Estimate { guesses, pieces }
}

/// Extends every split that ends just before `m` with `m`. A random gap never follows
/// another random gap.
fn add(table: &mut [Cell], m: Match, is_gap: bool) {
    if m.i == 0 {
        offer(table, m, is_gap, 1, m.guesses, false);
        return;
    }
    for count in 1..MAX_PIECES {
        for before_was_gap in [false, true] {
            if is_gap && before_was_gap {
                continue;
            }
            let prev = table[cell(m.i - 1, count, before_was_gap)];
            if prev.product > 0.0 {
                offer(
                    table,
                    m,
                    is_gap,
                    count + 1,
                    prev.product * m.guesses,
                    before_was_gap,
                );
            }
        }
    }
}

/// Keeps the split if it is the cheapest so far for its cell.
fn offer(
    table: &mut [Cell],
    m: Match,
    is_gap: bool,
    count: usize,
    product: f64,
    before_was_gap: bool,
) {
    let slot = &mut table[cell(m.j, count, is_gap)];
    let product = product.min(CAP);
    if slot.product == 0.0 || product < slot.product {
        *slot = Cell {
            product,
            last: m,
            before_was_gap,
        };
    }
}

/// Characters `start..=end` priced as random: `10^length`, and never below the submatch
/// floor plus one (11 for one character, 51 for more), as in zxcvbn.
fn gap(start: usize, end: usize) -> Match {
    let len = end - start + 1;
    let random = 10f64.powi(i32::try_from(len).unwrap_or(i32::MAX)).min(CAP);
    let least = if len == 1 {
        MIN_SINGLE_CHAR_GUESSES
    } else {
        MIN_MULTI_CHAR_GUESSES
    } + 1.0;
    Match {
        i: start,
        j: end,
        guesses: random.max(least),
        hint: Hint::Bruteforce,
        flags: 0,
    }
}

/// The lowest price of a piece of `len` characters in a text of `n`.
fn floor(len: usize, n: usize) -> f64 {
    match (len < n, len) {
        (false, _) => 1.0,
        (true, 1) => MIN_SINGLE_CHAR_GUESSES,
        (true, _) => MIN_MULTI_CHAR_GUESSES,
    }
}

fn factorial(n: usize) -> f64 {
    (1..=n).map(|k| k as f64).product()
}

fn additive(pieces: usize) -> f64 {
    if pieces == 1 {
        1.0
    } else {
        10_000f64.powi(i32::try_from(pieces - 1).unwrap_or(i32::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guesses(s: &str) -> f64 {
        let chars: Vec<char> = s.chars().collect();
        let lower: Vec<char> = chars.iter().map(char::to_ascii_lowercase).collect();
        estimate(
            Text {
                chars: &chars,
                lower: &lower,
            },
            &mut Budget::default(),
        )
        .guesses
    }

    #[test]
    fn score_boundaries() {
        assert_eq!(score(1e3 + 4.0), 0);
        assert_eq!(score(1e3 + 5.0), 1);
        assert_eq!(score(1e8 + 4.0), 2);
        assert_eq!(score(1e8 + 5.0), 3);
        assert_eq!(score(1e10 + 5.0), 4);
    }

    #[test]
    fn whole_word_and_split() {
        // A single listed word costs its rank, plus the additive 1 for one piece.
        assert_eq!(guesses("password"), 3.0);
        // One random character costs 11 (the floor plus one), plus 1.
        assert_eq!(guesses("#"), 12.0);
        // Two pieces: 2! x 50 x 11 + 10000. "password" is now a part, so it costs at least
        // the multi-character floor of 50; the lone symbol costs 11.
        assert_eq!(guesses("password#"), 2.0 * 50.0 * 11.0 + 10_000.0);
    }

    #[test]
    fn repeat_units_draw_from_budget() {
        let chars: Vec<char> = "ab".chars().collect();
        let mut budget = Budget { remaining: 1 };
        assert_eq!(
            unit_guesses(
                Text {
                    chars: &chars,
                    lower: &chars
                },
                &mut budget
            ),
            1.0
        );
        assert_eq!(budget.remaining, 1);
    }
}
