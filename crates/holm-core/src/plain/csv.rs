//! Strict RFC 4180 CSV: a reader that yields wiping cells and a quoting writer.

use super::{Cell, PlainError};

/// The line end the writer puts after every row.
pub(crate) const ROW_END: &str = "\r\n";

/// Where a record started and how many cells it really had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    /// 1-based physical line of the record's first byte.
    pub(crate) line: u64,
    /// Every cell in the record, including any past `max_cells` that were not kept.
    pub(crate) cells_seen: usize,
}

/// Reads records from CSV text one at a time.
///
/// Rules (RFC 4180, strict): `,` separates cells; a record ends at `\r\n`, `\n` or a
/// lone `\r`; a cell is quoted only if its first byte is `"`; inside quotes `""` is
/// one `"` and line ends are kept verbatim; after a closing quote only `,`, a line end
/// or the end of input may follow. A `"` inside an unquoted cell, or an unclosed
/// quote, is [`PlainError::Malformed`]. A record that is one empty line is skipped.
/// Cells are never trimmed.
///
/// All positions are byte offsets into the `&str`. The reader only stops on ASCII
/// bytes (`"`, `,`, `\r`, `\n`), which are never inside a multi-byte UTF-8 sequence,
/// so every slice it takes starts and ends on a `char` boundary.
///
/// It has no `Debug`: it holds the source text.
pub(crate) struct CsvReader<'a> {
    src: &'a str,
    /// Byte offset of the next unread byte.
    pos: usize,
    /// 1-based physical line of `pos`.
    line: u64,
}

/// How a scanned cell is laid out in the source.
enum Span {
    /// Unquoted: the cell is `src[start..end]` as is.
    Plain { start: usize, end: usize },
    /// Quoted: `src[start..end]` is the text between the outer quotes, with `""` pairs.
    Quoted { start: usize, end: usize },
}

impl<'a> CsvReader<'a> {
    /// A reader at the start of `src`.
    pub(crate) fn new(src: &'a str) -> CsvReader<'a> {
        CsvReader {
            src,
            pos: 0,
            line: 1,
        }
    }

    /// Reads the next record into `out`, which is cleared first. At most `max_cells`
    /// cells are allocated; the rest of the record is still scanned (quotes are still
    /// checked) and only counted in [`Record::cells_seen`]. Returns `Ok(None)` at the
    /// end of input.
    ///
    /// # Errors
    ///
    /// [`PlainError::Malformed`] with the line where the bad cell starts. The reader
    /// should not be used after an error.
    pub(crate) fn next_record(
        &mut self,
        out: &mut Vec<Cell>,
        max_cells: usize,
    ) -> Result<Option<Record>, PlainError> {
        out.clear();
        // Skip records that are a single empty line.
        while self.at_line_end() {
            self.eat_line_end();
        }
        if self.pos >= self.src.len() {
            return Ok(None);
        }
        let line = self.line;
        let mut cells_seen = 0usize;
        loop {
            let span = self.scan_cell()?;
            cells_seen = cells_seen.saturating_add(1);
            if out.len() < max_cells {
                out.push(self.decode(span));
            }
            match self.byte_at(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'\r' | b'\n') => {
                    self.eat_line_end();
                    break;
                }
                // End of input. `scan_cell` stops only at `,`, a line end or the end.
                _ => break,
            }
        }
        Ok(Some(Record { line, cells_seen }))
    }

    fn byte_at(&self, i: usize) -> Option<u8> {
        self.src.as_bytes().get(i).copied()
    }

    fn at_line_end(&self) -> bool {
        matches!(self.byte_at(self.pos), Some(b'\r' | b'\n'))
    }

    /// Consumes one `\r\n`, `\n` or lone `\r` at `pos` and counts the line.
    fn eat_line_end(&mut self) {
        match self.byte_at(self.pos) {
            Some(b'\r') if self.byte_at(self.pos + 1) == Some(b'\n') => self.pos += 2,
            Some(b'\r' | b'\n') => self.pos += 1,
            _ => return,
        }
        self.line += 1;
    }

    /// Scans one cell starting at `pos` and leaves `pos` on the byte after it
    /// (`,`, a line end, or the end of input). Allocates nothing.
    fn scan_cell(&mut self) -> Result<Span, PlainError> {
        let start_line = self.line;
        let bad = PlainError::Malformed { line: start_line };
        let bytes = self.src.as_bytes();
        if bytes.get(self.pos) != Some(&b'"') {
            let start = self.pos;
            let mut i = start;
            while let Some(&b) = bytes.get(i) {
                match b {
                    b',' | b'\r' | b'\n' => break,
                    b'"' => return Err(bad),
                    _ => i += 1,
                }
            }
            self.pos = i;
            return Ok(Span::Plain { start, end: i });
        }
        let start = self.pos + 1;
        let mut i = start;
        loop {
            match bytes.get(i) {
                None => return Err(bad),
                Some(b'"') if bytes.get(i + 1) == Some(&b'"') => i += 2,
                Some(b'"') => break,
                Some(b'\r') if bytes.get(i + 1) == Some(&b'\n') => {
                    i += 2;
                    self.line += 1;
                }
                Some(b'\r' | b'\n') => {
                    i += 1;
                    self.line += 1;
                }
                Some(_) => i += 1,
            }
        }
        let end = i;
        self.pos = end + 1;
        match self.byte_at(self.pos) {
            None | Some(b',' | b'\r' | b'\n') => Ok(Span::Quoted { start, end }),
            Some(_) => Err(bad),
        }
    }

    /// Copies a scanned cell into one allocation of exactly its decoded length.
    fn decode(&self, span: Span) -> Cell {
        match span {
            Span::Plain { start, end } => {
                let raw = &self.src[start..end];
                let mut cell = Cell::new(String::with_capacity(raw.len()));
                cell.push_str(raw);
                cell
            }
            Span::Quoted { start, end } => {
                let raw = &self.src[start..end];
                let mut cell = Cell::new(String::with_capacity(quoted_decoded_len(raw)));
                fill_quoted(&mut cell, raw);
                cell
            }
        }
    }
}

/// Decoded length of the text between a quoted cell's outer quotes: each `""` is one
/// byte. `raw` comes from the scanner, so every `"` in it is half of a pair.
fn quoted_decoded_len(raw: &str) -> usize {
    raw.len() - raw.bytes().filter(|&b| b == b'"').count() / 2
}

/// Appends `raw` with each `""` turned into `"`. `out` must already have room for
/// [`quoted_decoded_len`] bytes; it is never grown.
fn fill_quoted(out: &mut String, raw: &str) {
    let cap = out.capacity();
    debug_assert!(cap - out.len() >= quoted_decoded_len(raw));
    let mut rest = raw;
    while let Some(i) = rest.find('"') {
        // `rest[..=i]` ends with the first quote of a pair; skip the second.
        out.push_str(&rest[..=i]);
        rest = rest.get(i + 2..).unwrap_or("");
    }
    out.push_str(rest);
    debug_assert_eq!(out.capacity(), cap);
}

/// The bytes [`push_quoted`] writes for `cell`: 2 + `cell.len()` + the number of `"`.
pub(crate) fn quoted_len(cell: &str) -> usize {
    let quotes = cell.bytes().filter(|&b| b == b'"').count();
    cell.len().saturating_add(quotes).saturating_add(2)
}

/// Appends `cell` quoted, with each `"` doubled. `out` must already have room for
/// [`quoted_len`] bytes, so this never reallocates (and leaves no unwiped copy).
/// The caller separates cells with `,` and ends each row with [`ROW_END`].
pub(crate) fn push_quoted(out: &mut String, cell: &str) {
    let cap = out.capacity();
    debug_assert!(cap - out.len() >= quoted_len(cell));
    out.push('"');
    let mut rest = cell;
    while let Some(i) = rest.find('"') {
        out.push_str(&rest[..=i]);
        out.push('"');
        rest = &rest[i + 1..];
    }
    out.push_str(rest);
    out.push('"');
    debug_assert_eq!(out.capacity(), cap);
}

#[cfg(test)]
mod tests {
    use crate::plain::{Cell, CsvReader, PlainError, ROW_END, Record, push_quoted, quoted_len};
    use proptest::prelude::*;

    /// Reads all records with a generous cap; panics on error.
    fn read_all(src: &str) -> Vec<(u64, Vec<String>)> {
        let mut r = CsvReader::new(src);
        let mut out: Vec<Cell> = Vec::new();
        let mut rows = Vec::new();
        while let Some(rec) = r.next_record(&mut out, 64).expect("valid csv") {
            assert_eq!(rec.cells_seen, out.len());
            rows.push((rec.line, out.iter().map(|c| c.to_string()).collect()));
        }
        rows
    }

    fn first_error(src: &str) -> PlainError {
        let mut r = CsvReader::new(src);
        let mut out: Vec<Cell> = Vec::new();
        loop {
            match r.next_record(&mut out, 64) {
                Ok(Some(_)) => {}
                Ok(None) => panic!("expected an error"),
                Err(e) => return e,
            }
        }
    }

    fn row(cells: &[&str]) -> Vec<String> {
        cells.iter().map(|c| (*c).to_string()).collect()
    }

    #[test]
    fn csv_rfc4180_basics() {
        let rows = read_all("a,\"b,c\",\"d\"\"e\"\r\nf,,\"g\nh\"\n");
        assert_eq!(
            rows,
            vec![
                (1, row(&["a", "b,c", "d\"e"])),
                (2, row(&["f", "", "g\nh"])),
            ]
        );
        // Cells are never trimmed, and a trailing comma is one more empty cell.
        assert_eq!(read_all(" a , b ,"), vec![(1, row(&[" a ", " b ", ""]))]);
        // The quoted line end counts as a physical line for the next record.
        assert_eq!(
            read_all("\"x\r\ny\",z\nnext"),
            vec![(1, row(&["x\r\ny", "z"])), (3, row(&["next"]))]
        );
        assert_eq!(read_all(""), Vec::new());
        assert_eq!(read_all("\"\""), vec![(1, row(&[""]))]);
        assert_eq!(read_all("é,\"ü😀\""), vec![(1, row(&["é", "ü😀"]))]);
    }

    #[test]
    fn csv_line_ends_and_blank_lines() {
        assert_eq!(
            read_all("a\r\nb\nc\rd"),
            vec![
                (1, row(&["a"])),
                (2, row(&["b"])),
                (3, row(&["c"])),
                (4, row(&["d"])),
            ]
        );
        // A trailing blank line and blank lines between records are skipped, but
        // still counted for line numbers.
        assert_eq!(
            read_all("a\n\nb\r\n\r\n\rc\n\n"),
            vec![(1, row(&["a"])), (3, row(&["b"])), (6, row(&["c"]))]
        );
        assert_eq!(read_all("\n\r\n\r"), Vec::new());
        // A quoted empty cell is a record, not a blank line.
        assert_eq!(read_all("\"\"\n"), vec![(1, row(&[""]))]);
        // A lone comma is two empty cells.
        assert_eq!(read_all(",\n"), vec![(1, row(&["", ""]))]);
    }

    #[test]
    fn csv_strictness() {
        assert_eq!(first_error("a\"b"), PlainError::Malformed { line: 1 });
        assert_eq!(first_error("\"a\"b"), PlainError::Malformed { line: 1 });
        assert_eq!(first_error("\"abc"), PlainError::Malformed { line: 1 });
        assert_eq!(first_error("ok\nx,a\"b"), PlainError::Malformed { line: 2 });
        assert_eq!(
            first_error("ok\r\n\r\n\"a\" ,b"),
            PlainError::Malformed { line: 3 }
        );
        // The line is where the bad cell starts, not where the reader gave up.
        assert_eq!(
            first_error("ok\n\"abc\n\n\n"),
            PlainError::Malformed { line: 2 }
        );
        assert_eq!(
            first_error("\"a\",\"b\nc\"d"),
            PlainError::Malformed { line: 1 }
        );
        let e = first_error("\"x\nEXAMPLE-leak");
        assert_eq!(e, PlainError::Malformed { line: 1 });
        assert!(!format!("{e:?}").contains("EXAMPLE"));
        // A bad cell past `max_cells` is still checked.
        let mut r = CsvReader::new("a,b,c\"d");
        let mut out: Vec<Cell> = Vec::new();
        assert_eq!(
            r.next_record(&mut out, 1),
            Err(PlainError::Malformed { line: 1 })
        );
    }

    #[test]
    fn wide_row_allocates_no_cells_past_cap() {
        let src = ",".repeat(1_000_000);
        let mut r = CsvReader::new(&src);
        let mut out: Vec<Cell> = Vec::new();
        let rec = r.next_record(&mut out, 64).unwrap().unwrap();
        assert_eq!(out.len(), 64);
        assert_eq!(
            rec,
            Record {
                line: 1,
                cells_seen: 1_000_001
            }
        );
        assert_eq!(r.next_record(&mut out, 64), Ok(None));
        // `out` is cleared first, and a cap of 0 keeps no cells.
        let mut r = CsvReader::new("a,b\nc");
        let rec = r.next_record(&mut out, 0).unwrap().unwrap();
        assert!(out.is_empty());
        assert_eq!(rec.cells_seen, 2);
    }

    #[test]
    fn cells_allocated_once_at_final_size() {
        let mut r = CsvReader::new("\"a\"\"b\",plain,\"x\ny\",,\"\"");
        let mut out: Vec<Cell> = Vec::new();
        r.next_record(&mut out, 8).unwrap().unwrap();
        let cells: Vec<&str> = out.iter().map(|c| c.as_str()).collect();
        assert_eq!(cells, ["a\"b", "plain", "x\ny", "", ""]);
        for c in &out {
            assert_eq!(c.capacity(), c.len());
        }
        // The fill step itself never moves or grows the buffer.
        for raw in ["a\"\"b", "plain", "\"\"\"\"", "é\"\"ü"] {
            let mut s = String::with_capacity(super::quoted_decoded_len(raw));
            let (ptr, cap) = (s.as_ptr(), s.capacity());
            super::fill_quoted(&mut s, raw);
            assert_eq!((s.as_ptr(), s.capacity()), (ptr, cap));
            assert_eq!(s.len(), cap);
        }
    }

    #[test]
    fn writer_quotes_and_measures() {
        for (cell, quoted) in [
            ("", "\"\""),
            ("a\"b", "\"a\"\"b\""),
            (",\n", "\",\n\""),
            ("=SUM(A1)", "\"=SUM(A1)\""),
        ] {
            let mut out = String::with_capacity(quoted_len(cell));
            let (ptr, cap) = (out.as_ptr(), out.capacity());
            push_quoted(&mut out, cell);
            assert_eq!(out, quoted);
            assert_eq!(out.len(), quoted_len(cell));
            assert_eq!((out.as_ptr(), out.capacity()), (ptr, cap));
        }
        assert_eq!(quoted_len("\"\""), 6);
        assert_eq!(ROW_END, "\r\n");
    }

    fn cell_strategy() -> impl Strategy<Value = String> {
        prop_oneof![any::<String>(), "[\",\r\na-zé😀 ]{0,12}",]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn csv_roundtrip_any_fields(
            rows in prop::collection::vec(prop::collection::vec(cell_strategy(), 1..=8), 0..12)
        ) {
            let total: usize = rows
                .iter()
                .map(|r| {
                    r.iter().map(|c| quoted_len(c)).sum::<usize>() + (r.len() - 1) + ROW_END.len()
                })
                .sum();
            let mut text = String::with_capacity(total);
            let (ptr, cap) = (text.as_ptr(), text.capacity());
            for r in &rows {
                for (i, c) in r.iter().enumerate() {
                    if i > 0 {
                        text.push(',');
                    }
                    push_quoted(&mut text, c);
                }
                text.push_str(ROW_END);
            }
            prop_assert_eq!(text.len(), total);
            prop_assert_eq!((text.as_ptr(), text.capacity()), (ptr, cap));

            let mut reader = CsvReader::new(&text);
            let mut out: Vec<Cell> = Vec::new();
            for r in &rows {
                let rec = reader.next_record(&mut out, 8).unwrap().unwrap();
                prop_assert_eq!(rec.cells_seen, r.len());
                let got: Vec<&str> = out.iter().map(|c| c.as_str()).collect();
                let want: Vec<&str> = r.iter().map(String::as_str).collect();
                prop_assert_eq!(got, want);
            }
            prop_assert_eq!(reader.next_record(&mut out, 8), Ok(None));
        }

        #[test]
        fn csv_reader_never_panics(src in any::<String>(), cap in 0usize..4) {
            let mut reader = CsvReader::new(&src);
            let mut out: Vec<Cell> = Vec::new();
            let mut guard = 0usize;
            while let Ok(Some(rec)) = reader.next_record(&mut out, cap) {
                prop_assert!(out.len() <= cap);
                prop_assert!(out.len() <= rec.cells_seen);
                guard += 1;
                prop_assert!(guard <= src.len() + 1);
            }
        }
    }
}
