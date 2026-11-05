//! The narrow JSON import shape: one array of flat objects whose values are strings
//! or `null`.

use core::fmt;

use super::{Cell, PlainError};

/// One JSON object: its keys and values in file order.
pub(crate) struct JsonObject {
    /// 1-based physical line of the object's `{`.
    pub(crate) line: u64,
    /// `(key, value)` pairs; `None` is JSON `null`.
    pub(crate) fields: Vec<(Cell, Option<Cell>)>,
}

/// Shows the line and the number of fields, never a key or a value.
impl fmt::Debug for JsonObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonObject")
            .field("line", &self.line)
            .field("fields", &self.fields.len())
            .finish()
    }
}

/// Parses `src` as an array of flat objects.
///
/// The accepted shape is: whitespace, `[`, zero or more objects separated by `,`, `]`,
/// whitespace, end. An object holds `"key": value` pairs where the value is a string
/// or `null`. Everything else JSON allows (numbers, `true`, `false`, nested arrays or
/// objects) is refused, as are trailing commas, an exact duplicate key in one object,
/// raw control characters in a string, invalid escapes and lone surrogates. The
/// nesting depth is fixed at two, so the parser is a loop and never recurses.
///
/// # Errors
///
/// [`PlainError::Malformed`] with the line where parsing stopped;
/// [`PlainError::TooManyRows`] for more than `max_rows` objects;
/// [`PlainError::TooManyColumns`] for more than `max_fields` keys in one object.
pub(crate) fn parse_json_rows(
    src: &str,
    max_rows: usize,
    max_fields: usize,
) -> Result<Vec<JsonObject>, PlainError> {
    let mut p = Parser {
        src,
        pos: 0,
        line: 1,
    };
    let mut rows = Vec::new();
    p.skip_ws();
    p.expect(b'[')?;
    p.skip_ws();
    if p.peek() == Some(b']') {
        p.pos += 1;
    } else {
        loop {
            if p.peek() != Some(b'{') {
                return Err(p.bad());
            }
            if rows.len() >= max_rows {
                return Err(PlainError::TooManyRows);
            }
            rows.push(p.object(max_fields)?);
            p.skip_ws();
            match p.peek() {
                Some(b',') => {
                    p.pos += 1;
                    p.skip_ws();
                }
                Some(b']') => {
                    p.pos += 1;
                    break;
                }
                _ => return Err(p.bad()),
            }
        }
    }
    p.skip_ws();
    if p.pos != src.len() {
        return Err(p.bad());
    }
    Ok(rows)
}

/// Bytes [`push_json_string`] writes for `s`, including the surrounding quotes.
///
/// The count and the writer share [`escaped_len`], so a measured buffer is never
/// grown. Escapes only add bytes. They do not allocate a second copy of `s`.
pub(crate) fn json_string_len(s: &str) -> usize {
    let mut n = 2usize;
    for c in s.chars() {
        n = n.saturating_add(escaped_len(c));
    }
    n
}

/// How many bytes one character takes inside a JSON string.
fn escaped_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

/// Appends `s` as a JSON string. `out` must already have room for [`json_string_len`]
/// bytes, so this never reallocates (and leaves no unwiped copy).
pub(crate) fn push_json_string(out: &mut String, s: &str) {
    let need = json_string_len(s);
    let start_len = out.len();
    assert!(
        out.capacity() - start_len >= need,
        "no room for the json string"
    );
    let cap = out.capacity();
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => push_u00(out, c),
            c => out.push(c),
        }
    }
    out.push('"');
    assert_eq!(out.capacity(), cap, "json string grew");
    assert_eq!(out.len(), start_len + need, "json string length disagrees");
}

/// Writes `\u00XX` for a control character below U+0020 that has no short escape.
fn push_u00(out: &mut String, c: char) {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let n = u32::from(c);
    out.push('\\');
    out.push('u');
    out.push('0');
    out.push('0');
    out.push(char::from(HEX[((n >> 4) & 0xf) as usize]));
    out.push(char::from(HEX[(n & 0xf) as usize]));
}

/// A cursor over the source. All positions are byte offsets; the parser only
/// stops on ASCII bytes, so every slice it takes is on a `char` boundary.
struct Parser<'a> {
    src: &'a str,
    /// Byte offset of the next unread byte.
    pos: usize,
    /// 1-based physical line of `pos`.
    line: u64,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.src.as_bytes().get(self.pos).copied()
    }

    fn bad(&self) -> PlainError {
        PlainError::Malformed { line: self.line }
    }

    fn expect(&mut self, b: u8) -> Result<(), PlainError> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.bad())
        }
    }

    /// Skips JSON whitespace, counting `\r\n`, `\n` and a lone `\r` as one line each.
    fn skip_ws(&mut self) {
        let bytes = self.src.as_bytes();
        loop {
            match bytes.get(self.pos) {
                Some(b' ' | b'\t') => self.pos += 1,
                Some(b'\r') if bytes.get(self.pos + 1) == Some(&b'\n') => {
                    self.pos += 2;
                    self.line += 1;
                }
                Some(b'\r' | b'\n') => {
                    self.pos += 1;
                    self.line += 1;
                }
                _ => return,
            }
        }
    }

    /// Parses one flat object starting at its `{`.
    fn object(&mut self, max_fields: usize) -> Result<JsonObject, PlainError> {
        let line = self.line;
        self.expect(b'{')?;
        self.skip_ws();
        let mut fields: Vec<(Cell, Option<Cell>)> = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonObject { line, fields });
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(self.bad());
            }
            if fields.len() >= max_fields {
                return Err(PlainError::TooManyColumns);
            }
            let key = self.string()?;
            if fields.iter().any(|(k, _)| k.as_str() == key.as_str()) {
                return Err(self.bad());
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = match self.peek() {
                Some(b'"') => Some(self.string()?),
                Some(b'n') if self.src.as_bytes()[self.pos..].starts_with(b"null") => {
                    self.pos += 4;
                    None
                }
                _ => return Err(self.bad()),
            };
            fields.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonObject { line, fields });
                }
                _ => return Err(self.bad()),
            }
        }
    }

    /// Parses one string starting at its opening `"`. First finds the closing quote
    /// without allocating, then decodes into one buffer of the raw length (escapes
    /// only shrink, so that is enough) that is never grown.
    fn string(&mut self) -> Result<Cell, PlainError> {
        self.expect(b'"')?;
        let bytes = self.src.as_bytes();
        let start = self.pos;
        let mut i = start;
        loop {
            match bytes.get(i) {
                None => return Err(self.bad()),
                Some(b'"') => break,
                // Skip the escaped byte so `\"` does not end the string; the decode
                // step checks the escape itself.
                Some(b'\\') => i += 2,
                Some(&b) if b < 0x20 => return Err(self.bad()),
                Some(_) => i += 1,
            }
        }
        let raw = &self.src[start..i];
        // The partial cell is wiped on drop if decoding fails.
        let mut cell = Cell::new(String::with_capacity(raw.len()));
        fill_string(&mut cell, raw).map_err(|()| self.bad())?;
        self.pos = i + 1;
        Ok(cell)
    }
}

/// Appends the decoded text of a string's raw span (between the quotes, with no raw
/// control characters and no unescaped `"`). `out` must already have room for
/// `raw.len()` bytes; it is never grown. Fails on an invalid escape or a lone
/// surrogate.
fn fill_string(out: &mut String, raw: &str) -> Result<(), ()> {
    let cap = out.capacity();
    debug_assert!(cap - out.len() >= raw.len());
    let b = raw.as_bytes();
    let mut run = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            i += 1;
            continue;
        }
        out.push_str(&raw[run..i]);
        let ch = match b.get(i + 1) {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let (ch, used) = unicode_escape(b, i)?;
                out.push(ch);
                i += used;
                run = i;
                continue;
            }
            _ => return Err(()),
        };
        out.push(ch);
        i += 2;
        run = i;
    }
    out.push_str(&raw[run..]);
    debug_assert_eq!(out.capacity(), cap);
    Ok(())
}

/// Decodes `\uXXXX` at `b[i..]`, joining a surrogate pair. Returns the character and
/// the bytes used (6 or 12).
fn unicode_escape(b: &[u8], i: usize) -> Result<(char, usize), ()> {
    let hi = hex4(b, i + 2)?;
    match hi {
        0xD800..=0xDBFF => {
            if b.get(i + 6) != Some(&b'\\') || b.get(i + 7) != Some(&b'u') {
                return Err(());
            }
            let lo = hex4(b, i + 8)?;
            if !(0xDC00..=0xDFFF).contains(&lo) {
                return Err(());
            }
            let c = 0x1_0000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
            char::from_u32(c).map(|ch| (ch, 12)).ok_or(())
        }
        0xDC00..=0xDFFF => Err(()),
        _ => char::from_u32(hi).map(|ch| (ch, 6)).ok_or(()),
    }
}

/// Reads four hex digits at `b[at..]`.
fn hex4(b: &[u8], at: usize) -> Result<u32, ()> {
    let digits = b.get(at..at + 4).ok_or(())?;
    let mut v = 0u32;
    for &d in digits {
        let n = match d {
            b'0'..=b'9' => d - b'0',
            b'a'..=b'f' => d - b'a' + 10,
            b'A'..=b'F' => d - b'A' + 10,
            _ => return Err(()),
        };
        v = (v << 4) | u32::from(n);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use crate::plain::{JsonObject, PlainError, parse_json_rows};
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    type Pairs = Vec<(String, Option<String>)>;

    fn pairs(o: &JsonObject) -> Pairs {
        o.fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_ref().map(|v| v.to_string())))
            .collect()
    }

    fn parse(src: &str) -> Result<Vec<(u64, Pairs)>, PlainError> {
        parse_json_rows(src, 1000, 64).map(|rows| rows.iter().map(|o| (o.line, pairs(o))).collect())
    }

    fn p(k: &str, v: Option<&str>) -> (String, Option<String>) {
        (k.to_string(), v.map(str::to_string))
    }

    #[test]
    fn json_flat_objects() {
        assert_eq!(parse("[]"), Ok(vec![]));
        assert_eq!(parse(" \r\n\t[ \n ] \n"), Ok(vec![]));
        assert_eq!(parse("[{}]"), Ok(vec![(1, vec![])]));
        let src = "[\n  {\"title\": \"Mail\", \"notes\": null},\n  {\n    \"t\": \"a\\\"b\\\\c\\/d\\b\\f\\n\\r\\t\",\n    \"u\": \"\\u00e9\\u20AC\\ud83d\\ude00\\u0000\", \"\": \"\"\n  }\n]";
        assert_eq!(
            parse(src),
            Ok(vec![
                (2, vec![p("title", Some("Mail")), p("notes", None)]),
                (
                    3,
                    vec![
                        p("t", Some("a\"b\\c/d\u{8}\u{c}\n\r\t")),
                        p("u", Some("é€😀\u{0}")),
                        p("", Some("")),
                    ]
                ),
            ])
        );
        // Raw non-ASCII text passes through unchanged.
        assert_eq!(
            parse("[{\"ü\":\"日本😀\"}]"),
            Ok(vec![(1, vec![p("ü", Some("日本😀"))])])
        );
        // Debug shows the line and field count only.
        let rows = parse_json_rows("[{\"k\":\"EXAMPLE-secret\"}]", 10, 10).unwrap();
        let dbg = format!("{rows:?}");
        assert!(!dbg.contains("EXAMPLE"), "{dbg}");
        assert!(
            dbg.contains("line: 1") && dbg.contains("fields: 1"),
            "{dbg}"
        );
    }

    #[test]
    fn writer_length_matches_fill() {
        let samples = [
            "",
            "a",
            "say \"hi\"",
            "a\\b",
            "line\nnext",
            "\r\n\t\u{8}\u{c}\u{1}",
            "日本😀",
        ];
        for sample in samples {
            let need = super::json_string_len(sample);
            let mut out = String::with_capacity(need);
            super::push_json_string(&mut out, sample);
            assert_eq!(out.len(), need, "{sample:?}");
            let wrapped = format!("[{{\"k\":{out}}}]");
            let rows = parse_json_rows(&wrapped, 4, 4).unwrap();
            let value = rows[0].fields[0].1.as_ref().unwrap();
            assert_eq!(value.as_str(), sample);
        }
    }

    #[test]
    fn json_rejections() {
        let bad = |src: &str| match parse(src) {
            Err(PlainError::Malformed { line }) => line,
            other => panic!("{src:?} gave {other:?}"),
        };
        assert_eq!(bad("[{\"a\": 1}]"), 1);
        assert_eq!(bad("[{\"a\": true}]"), 1);
        assert_eq!(bad("[{\"a\": false}]"), 1);
        assert_eq!(bad("[{\"a\": nul}]"), 1);
        assert_eq!(bad("[{\"a\": nullx}]"), 1);
        assert_eq!(bad("[\n{\"a\": {\"b\": \"c\"}}]"), 2);
        assert_eq!(bad("[{\"a\": [\"b\"]}]"), 1);
        assert_eq!(bad("[{\"a\": \"b\"},]"), 1);
        assert_eq!(bad("[{\"a\": \"b\",}]"), 1);
        assert_eq!(bad("{\"a\": \"b\"}"), 1);
        assert_eq!(bad("[{\"a\": \"b\", \"a\": \"c\"}]"), 1);
        // A raw control character is refused; the same character escaped is fine.
        assert_eq!(bad("[{\"a\": \"b\u{1}\"}]"), 1);
        assert_eq!(
            parse("[{\"a\": \"b\\u0001\"}]"),
            Ok(vec![(1, vec![p("a", Some("b\u{1}"))])])
        );
        assert_eq!(bad("[{\"a\": \"\n\"}]"), 1);
        assert_eq!(bad("[{\"a\": \"\\ud800\"}]"), 1);
        assert_eq!(bad("[{\"a\": \"\\ud800\\u0041\"}]"), 1);
        assert_eq!(bad("[{\"a\": \"\\udc00\"}]"), 1);
        assert_eq!(bad("[{\"a\": \"\\x\"}]"), 1);
        assert_eq!(bad("[{\"a\": \"\\u12G4\"}]"), 1);
        assert_eq!(bad("[{\"a\": \"\\u12\"}]"), 1);
        assert_eq!(bad("[{\"a\": \"unclosed}]"), 1);
        assert_eq!(bad("[{\"a\" \"b\"}]"), 1);
        assert_eq!(bad("[{a: \"b\"}]"), 1);
        assert_eq!(bad("[{\"a\": \"b\"} {\"c\": \"d\"}]"), 1);
        assert_eq!(bad("[{\"a\": \"b\"}] x"), 1);
        assert_eq!(bad("[{\"a\": \"b\"}][]"), 1);
        assert_eq!(bad("[\n\n{\"a\": \"b\"}\n"), 4);
        assert_eq!(bad(""), 1);
        assert_eq!(bad("[\"a\"]"), 1);
        assert_eq!(bad("\u{feff}[]"), 1);
        // A duplicate is an exact key match; a different key is fine.
        assert!(parse("[{\"a\": \"b\", \"A\": \"c\"}]").is_ok());
        // Errors never carry the text.
        let e = parse("[{\"k\": \"EXAMPLE-leak\" 1}]").unwrap_err();
        assert!(!format!("{e:?}").contains("EXAMPLE"));

        let mut wide = String::from("[{");
        for i in 0..65 {
            if i > 0 {
                wide.push(',');
            }
            wide.push_str(&format!("\"k{i}\":\"v\""));
        }
        wide.push_str("}]");
        assert_eq!(
            parse_json_rows(&wide, 10, 64).unwrap_err(),
            PlainError::TooManyColumns
        );
        assert!(parse_json_rows(&wide, 10, 65).is_ok());
        assert_eq!(
            parse_json_rows("[{},{},{}]", 2, 64).unwrap_err(),
            PlainError::TooManyRows
        );
        assert!(parse_json_rows("[{},{},{}]", 3, 64).is_ok());
    }

    #[test]
    fn deep_nesting_is_malformed_without_recursion() {
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let a = "[".repeat(100_000);
                let b = format!("[{{\"a\":{}", "[".repeat(100_000));
                (
                    parse_json_rows(&a, 10, 10).unwrap_err(),
                    parse_json_rows(&b, 10, 10).unwrap_err(),
                )
            })
            .unwrap();
        let (a, b) = handle.join().unwrap();
        assert_eq!(a, PlainError::Malformed { line: 1 });
        assert_eq!(b, PlainError::Malformed { line: 1 });
    }

    #[test]
    fn cells_allocated_once_at_final_size() {
        // The raw span is an upper bound; the fill never moves or grows the buffer.
        for raw in ["x\u{e9}\\n", "\\ud83d\\ude00", "plain", "\\\"\\\\", ""] {
            let mut s = String::with_capacity(raw.len());
            let (ptr, cap) = (s.as_ptr(), s.capacity());
            super::fill_string(&mut s, raw).unwrap();
            assert_eq!((s.as_ptr(), s.capacity()), (ptr, cap));
            assert!(s.capacity() >= s.len());
        }
        let rows = parse_json_rows("[{\"xé\\n\": \"xé\\n\"}]", 10, 10).unwrap();
        let (k, v) = &rows[0].fields[0];
        let v = v.as_ref().unwrap();
        assert_eq!((k.as_str(), v.as_str()), ("xé\n", "xé\n"));
        assert!(k.capacity() >= k.len() && v.capacity() >= v.len());
    }

    fn text_strategy() -> impl Strategy<Value = String> {
        prop_oneof![any::<String>(), "[\"\\\\/\u{0}-\u{1f}\u{7f}a-zé😀 ]{0,12}"]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn json_agrees_with_serde_json(
            rows in prop::collection::vec(
                prop::collection::btree_map(text_strategy(), prop::option::of(text_strategy()), 0..6),
                0..6,
            ),
            pretty in any::<bool>(),
        ) {
            let src = if pretty {
                serde_json::to_string_pretty(&rows).unwrap()
            } else {
                serde_json::to_string(&rows).unwrap()
            };
            let parsed = parse_json_rows(&src, 6, 6).unwrap();
            prop_assert_eq!(parsed.len(), rows.len());
            for (got, want) in parsed.iter().zip(&rows) {
                let want: Pairs = want.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                prop_assert_eq!(pairs(got), want);
            }
        }

        #[test]
        fn json_reader_never_panics(src in any::<String>()) {
            let _ = parse_json_rows(&src, 4, 4);
        }

        #[test]
        fn json_rejects_what_serde_json_rejects(src in "[\\[\\]{}\":, a-z0-9\\\\\n]{0,24}") {
            // Holm accepts a strict subset of JSON: anything it accepts, serde_json must too.
            if parse_json_rows(&src, 64, 64).is_ok() {
                let v: Result<Vec<BTreeMap<String, Option<String>>>, _> = serde_json::from_str(&src);
                prop_assert!(v.is_ok(), "{:?}", src);
            }
        }
    }
}
