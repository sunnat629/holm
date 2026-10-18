//! Keyboard adjacency graphs for spotting key walks like `qwerty` or `zxcvbn`.
//!
//! A port of zxcvbn's `build_keyboard_adjacency_graphs.py`. Each layout lists keys as
//! tokens (unshifted then shifted character). On the slanted keyboards each row is indented
//! one more space than the one above. A character's neighbours are stored in a fixed
//! direction order, so a change of index along a walk counts as a turn.

use std::collections::HashMap;
use std::sync::OnceLock;

const QWERTY: &str = r#"
`~ 1! 2@ 3# 4$ 5% 6^ 7& 8* 9( 0) -_ =+
    qQ wW eE rR tT yY uU iI oO pP [{ ]} \|
     aA sS dD fF gG hH jJ kK lL ;: '"
      zZ xX cC vV bB nN mM ,< .> /?
"#;

const DVORAK: &str = r#"
`~ 1! 2@ 3# 4$ 5% 6^ 7& 8* 9( 0) [{ ]}
    '" ,< .> pP yY fF gG cC rR lL /? =+ \|
     aA oO eE uU iI dD hH tT nN sS -_
      ;: qQ jJ kK xX bB mM wW vV zZ
"#;

const KEYPAD: &str = "
  / * -
7 8 9 +
4 5 6
1 2 3
  0 .
";

const MAC_KEYPAD: &str = "
  = / *
7 8 9 -
4 5 6 +
1 2 3
  0 .
";

/// One graph: each character maps to its neighbouring key tokens, by direction.
pub(crate) struct Graph {
    /// Neighbours by direction; `None` where there is no key.
    pub(crate) adjacent: HashMap<char, Vec<Option<&'static str>>>,
    /// Keyboards: a leading shifted character counts as one shift.
    pub(crate) counts_shift: bool,
    /// Distinct starting characters, used by the guess estimate.
    pub(crate) starts: f64,
    /// Average neighbour count, rounded down as zxcvbn does.
    pub(crate) degree: f64,
}

/// The four graphs zxcvbn uses.
pub(crate) fn graphs() -> &'static [Graph; 4] {
    static GRAPHS: OnceLock<[Graph; 4]> = OnceLock::new();
    GRAPHS.get_or_init(|| {
        let qwerty = build(QWERTY, true);
        let keypad = build(KEYPAD, false);
        // zxcvbn scores dvorak walks with qwerty's numbers and mac keypad walks with the
        // keypad's.
        let (kb_starts, kb_degree) = stats(&qwerty);
        let (kp_starts, kp_degree) = stats(&keypad);
        [
            Graph {
                adjacent: qwerty,
                counts_shift: true,
                starts: kb_starts,
                degree: kb_degree,
            },
            Graph {
                adjacent: build(DVORAK, true),
                counts_shift: true,
                starts: kb_starts,
                degree: kb_degree,
            },
            Graph {
                adjacent: keypad,
                counts_shift: false,
                starts: kp_starts,
                degree: kp_degree,
            },
            Graph {
                adjacent: build(MAC_KEYPAD, false),
                counts_shift: false,
                starts: kp_starts,
                degree: kp_degree,
            },
        ]
    })
}

/// Characters typed with shift on a US keyboard (as in zxcvbn's JavaScript `SHIFTED_RX`).
pub(crate) fn is_shifted(c: char) -> bool {
    c.is_ascii_uppercase() || "~!@#$%^&*()_+{}|:\"<>?".contains(c)
}

fn build(layout: &'static str, slanted: bool) -> HashMap<char, Vec<Option<&'static str>>> {
    let token_len = layout.split_whitespace().next().map_or(1, str::len);
    let x_unit = token_len + 1;
    let mut positions: HashMap<(i64, i64), &'static str> = HashMap::new();
    for (y, line) in (0i64..).zip(layout.split('\n')) {
        let slant = if slanted { y - 1 } else { 0 };
        let mut offset = 0usize;
        for token in line.split_whitespace() {
            // Tokens are unique within a line, so the first match from `offset` is this one.
            let at = offset + line[offset..].find(token).unwrap_or(0);
            offset = at + token.len();
            let x = (to_i64(at) - slant) / to_i64(x_unit);
            positions.insert((x, y), token);
        }
    }
    let mut graph = HashMap::new();
    for (&(x, y), token) in &positions {
        let around: &[(i64, i64)] = if slanted {
            &[(-1, 0), (0, -1), (1, -1), (1, 0), (0, 1), (-1, 1)]
        } else {
            &[
                (-1, 0),
                (-1, -1),
                (0, -1),
                (1, -1),
                (1, 0),
                (1, 1),
                (0, 1),
                (-1, 1),
            ]
        };
        let adjacent: Vec<Option<&'static str>> = around
            .iter()
            .map(|(dx, dy)| positions.get(&(x + dx, y + dy)).copied())
            .collect();
        for c in token.chars() {
            graph.insert(c, adjacent.clone());
        }
    }
    graph
}

/// Layout offsets are tiny, so this never saturates.
fn to_i64(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn stats(graph: &HashMap<char, Vec<Option<&'static str>>>) -> (f64, f64) {
    let keys = graph.len();
    let links: usize = graph.values().map(|v| v.iter().flatten().count()).sum();
    // Both counts are tiny, so the float conversion is exact.
    (keys as f64, (links / keys.max(1)) as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphs_match_zxcvbn_shape() {
        let [qwerty, dvorak, keypad, mac] = graphs();
        assert_eq!(qwerty.adjacent.len(), 94);
        assert_eq!(dvorak.adjacent.len(), 94);
        assert_eq!(keypad.adjacent.len(), 15);
        assert_eq!(mac.adjacent.len(), 16);
        assert_eq!((qwerty.starts, qwerty.degree), (94.0, 4.0));
        assert_eq!((keypad.starts, keypad.degree), (15.0, 5.0));
        // Spot checks against zxcvbn's generated adjacency_graphs.
        assert_eq!(
            qwerty.adjacent[&'1'],
            [Some("`~"), None, None, Some("2@"), Some("qQ"), None]
        );
        assert_eq!(
            qwerty.adjacent[&'"'],
            [Some(";:"), Some("[{"), Some("]}"), None, None, Some("/?")]
        );
        assert_eq!(
            keypad.adjacent[&'5'],
            [
                Some("4"),
                Some("7"),
                Some("8"),
                Some("9"),
                Some("6"),
                Some("3"),
                Some("2"),
                Some("1")
            ]
        );
    }
}
