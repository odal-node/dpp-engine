//! XLSX parser for bulk import uploads.
//! Includes zip-bomb, dimension-bomb, and pathological-attribute pre-scan
//! guards before delegating to calamine.

use std::collections::HashMap;
use std::io::{BufRead, Cursor, Read};

use calamine::{DataType, Reader, Xlsx};
use quick_xml::Reader as XmlReader;
use quick_xml::events::Event;
use zip::ZipArchive;

use crate::domain::csv_parser::{MAX_ROWS, ParseError, normalize_header};

/// Maximum implied dense-range size (cols × rows) for any worksheet. calamine
/// materialises a dense `vec![_; rows*cols]` from the *actual* min/max cell
/// positions, so a few-byte file with a cell at e.g. `XFD1048576` would force a
/// ~500 GB allocation (a "dimension bomb"). We scan the raw cell references and
/// reject *before* calamine allocates. (~160 MB worst case at this cap.)
const MAX_DENSE_CELLS: u64 = 5_000_000;

/// Maximum total *decompressed* bytes read from the archive, enforced by
/// streaming so a zip-bomb (a tiny archive that inflates to gigabytes) is
/// rejected before calamine reads anything.
const MAX_DECOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;

/// Maximum attributes accepted on a single XML start/empty tag anywhere in the
/// archive. Guards RUSTSEC-2026-0194: quick-xml's default checked attribute
/// iteration (`.attributes()`, `try_get_attribute`) does an `O(N²)` scan for
/// duplicate names with no bound on `N`, and calamine (transitively pinned to
/// a pre-0.41 quick-xml with no fixed release published yet) parses every XML
/// part of an XLSX this way. A single crafted tag with tens of thousands of
/// attributes can pin a CPU core for minutes. A legitimate XLSX tag never
/// carries more than a handful of attributes (a `<c>` cell tops out around 6;
/// the root `<worksheet>`/`<workbook>` tag's xmlns declarations top out
/// around a dozen) — this cap rejects the file before calamine, or our own
/// scan below, ever runs the vulnerable check against a pathological tag.
const MAX_ATTRS_PER_TAG: usize = 64;

/// Parse XLSX bytes into a list of rows.
///
/// Reads the first worksheet. The first row is treated as the header.
/// Column headers are normalised identically to [`super::csv_parser::parse_csv`].
/// Empty rows are silently skipped.
pub fn parse_xlsx(bytes: &[u8]) -> Result<Vec<HashMap<String, String>>, ParseError> {
    // Reject zip-bombs and dimension-bombs BEFORE calamine decompresses the
    // archive or allocates the dense worksheet range.
    precheck_xlsx(bytes)?;

    let cursor = Cursor::new(bytes.to_vec());
    let mut wb: Xlsx<_> =
        Xlsx::new(cursor).map_err(|e| ParseError::Csv(format!("XLSX open error: {e}")))?;

    let sheet_names = wb.sheet_names().to_vec();
    let first_sheet = sheet_names.first().ok_or(ParseError::Empty)?.clone();

    let range = wb
        .worksheet_range(&first_sheet)
        .ok_or(ParseError::Empty)?
        .map_err(|e| ParseError::Csv(format!("XLSX range error: {e}")))?;

    let mut rows_iter = range.rows();

    // First row → headers
    let header_row = rows_iter.next().ok_or(ParseError::Empty)?;
    let headers: Vec<String> = header_row.iter().map(cell_to_header).collect();

    if headers.iter().all(|h| h.is_empty()) {
        return Err(ParseError::Empty);
    }

    let header_count = headers.len();
    let mut result: Vec<HashMap<String, String>> = Vec::new();

    for row in rows_iter {
        let mut map = HashMap::new();
        for (i, cell) in row.iter().enumerate().take(header_count) {
            let key = &headers[i];
            if key.is_empty() {
                continue;
            }
            let value = cell_to_string(cell);
            if !value.is_empty() {
                map.insert(key.clone(), value);
            }
        }
        if !map.is_empty() {
            result.push(map);
            if result.len() > MAX_ROWS {
                return Err(ParseError::Csv(format!(
                    "file contains too many rows; maximum is {MAX_ROWS}"
                )));
            }
        }
    }

    Ok(result)
}

fn cell_to_string(cell: &DataType) -> String {
    match cell {
        DataType::Empty => String::new(),
        DataType::Error(_) => String::new(),
        DataType::Bool(b) => b.to_string(),
        DataType::Int(i) => i.to_string(),
        DataType::Float(f) => {
            // Avoid scientific notation for whole numbers (e.g. GTINs stored as floats)
            if f.fract() == 0.0 && f.abs() < 1e15_f64 {
                format!("{:.0}", f)
            } else {
                f.to_string()
            }
        }
        DataType::String(s) => s.trim().to_owned(),
        other => other.to_string(),
    }
}

fn cell_to_header(cell: &DataType) -> String {
    normalize_header(&cell_to_string(cell))
}

// ─── Bomb pre-scan ──────────────────────────────────────────────────────────────

/// A `Read` adapter that errors once a shared decompressed-byte budget is
/// exhausted, so a zip-bomb cannot be inflated without bound.
struct LimitedReader<'a, R> {
    inner: R,
    remaining: &'a mut u64,
}

impl<R: Read> Read for LimitedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if *self.remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed size limit exceeded",
            ));
        }
        let cap = (buf.len() as u64).min(*self.remaining) as usize;
        let n = self.inner.read(&mut buf[..cap])?;
        *self.remaining -= n as u64;
        Ok(n)
    }
}

/// Reject malicious workbooks before calamine reads them:
/// - **zip-bomb**: total decompressed bytes are capped (`MAX_DECOMPRESSED_BYTES`),
///   enforced by streaming so a lying central-directory size can't bypass it.
/// - **dimension-bomb**: each worksheet's cell references are scanned and the
///   implied dense range (max-col × max-row) is capped (`MAX_DENSE_CELLS`).
/// - **pathological attributes**: every XML part (not just worksheets) is
///   scanned for tags exceeding `MAX_ATTRS_PER_TAG` (see RUSTSEC-2026-0194).
fn precheck_xlsx(bytes: &[u8]) -> Result<(), ParseError> {
    let mut zip = ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ParseError::Csv(format!("XLSX is not a valid zip: {e}")))?;

    let mut budget = MAX_DECOMPRESSED_BYTES;
    for i in 0..zip.len() {
        let entry = zip
            .by_index(i)
            .map_err(|e| ParseError::Csv(format!("XLSX entry error: {e}")))?;
        let name = entry.name();
        let is_worksheet = name.starts_with("xl/worksheets/") && name.ends_with(".xml");
        let is_xml = name.ends_with(".xml") || name.ends_with(".rels");
        let mut limited = LimitedReader {
            inner: entry,
            remaining: &mut budget,
        };
        if is_xml {
            scan_xml_entry(std::io::BufReader::new(limited), is_worksheet)?;
        } else {
            // Non-XML entries (rare in an XLSX; e.g. embedded media): decompress
            // to a sink only to enforce the byte budget against zip-bombs.
            std::io::copy(&mut limited, &mut std::io::sink())
                .map_err(|e| ParseError::Csv(format!("XLSX decompression too large: {e}")))?;
        }
    }
    Ok(())
}

/// Stream an XML part and reject it if any tag exceeds `MAX_ATTRS_PER_TAG`
/// attributes, or (when `track_dimensions` is set, i.e. this is a worksheet)
/// its cells reference an oversized dense range. Returns early as soon as
/// either cap is exceeded, so a bomb is rejected without reading the whole
/// file.
///
/// Deliberately uses `.attributes().with_checks(false)` rather than
/// `.attributes()`/`try_get_attribute` — the checked variants are exactly the
/// RUSTSEC-2026-0194 code path this scan exists to guard against, so using
/// them here would make the guard itself exploitable.
fn scan_xml_entry<R: BufRead>(reader: R, track_dimensions: bool) -> Result<(), ParseError> {
    let mut xml = XmlReader::from_reader(reader);
    let mut buf = Vec::new();
    let (mut max_col, mut max_row): (u64, u64) = (0, 0);
    loop {
        match xml.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let is_cell = track_dimensions && e.name().as_ref() == b"c";
                let mut attr_count = 0usize;
                let mut r_value: Option<Vec<u8>> = None;
                for attr in e.attributes().with_checks(false) {
                    attr_count += 1;
                    if attr_count > MAX_ATTRS_PER_TAG {
                        return Err(ParseError::Csv(format!(
                            "XLSX contains a tag with too many attributes; \
                                 maximum is {MAX_ATTRS_PER_TAG}"
                        )));
                    }
                    if is_cell
                        && let Ok(attr) = attr
                        && attr.key.as_ref() == b"r"
                    {
                        r_value = Some(attr.value.into_owned());
                    }
                }
                if let Some(r) = r_value
                    && let Some((col, row)) = parse_cell_ref(&r)
                {
                    max_col = max_col.max(col);
                    max_row = max_row.max(row);
                    if max_col.saturating_mul(max_row) > MAX_DENSE_CELLS {
                        return Err(ParseError::Csv(format!(
                            "XLSX worksheet implies an oversized dense range \
                                 ({max_col} cols × {max_row} rows); maximum is {MAX_DENSE_CELLS} cells"
                        )));
                    }
                }
            }
            Ok(_) => {}
            Err(e) => return Err(ParseError::Csv(format!("XLSX XML scan error: {e}"))),
        }
        buf.clear();
    }
    Ok(())
}

/// Parse an A1-style cell reference (`b"XFD1048576"`) into a 1-based `(col, row)`.
/// An absurdly long reference (overflow) yields `(u64::MAX, u64::MAX)` so the
/// caller's span check rejects it; a malformed reference yields `None`.
fn parse_cell_ref(r: &[u8]) -> Option<(u64, u64)> {
    let split = r.iter().position(|b| b.is_ascii_digit())?;
    let (letters, digits) = r.split_at(split);
    if letters.is_empty() || digits.is_empty() || !letters.iter().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let mut col: u64 = 0;
    for &b in letters {
        match col
            .checked_mul(26)
            .and_then(|v| v.checked_add((b - b'A' + 1) as u64))
        {
            Some(v) => col = v,
            None => return Some((u64::MAX, u64::MAX)),
        }
    }
    let mut row: u64 = 0;
    for &b in digits {
        match row
            .checked_mul(10)
            .and_then(|v| v.checked_add((b - b'0') as u64))
        {
            Some(v) => row = v,
            None => return Some((u64::MAX, u64::MAX)),
        }
    }
    Some((col, row))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_returns_error() {
        let result = parse_xlsx(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_cell_ref_handles_a1_notation() {
        assert_eq!(parse_cell_ref(b"A1"), Some((1, 1)));
        assert_eq!(parse_cell_ref(b"Z9"), Some((26, 9)));
        assert_eq!(parse_cell_ref(b"AA1"), Some((27, 1)));
        assert_eq!(parse_cell_ref(b"XFD1048576"), Some((16384, 1048576)));
        assert_eq!(parse_cell_ref(b"notaref"), None);
        assert_eq!(parse_cell_ref(b"123"), None);
    }

    /// RT2-1: a worksheet with cells far apart implies a huge dense allocation
    /// and must be rejected by the scan before calamine ever sees it.
    #[test]
    fn scan_rejects_dimension_bomb() {
        let xml = br#"<worksheet><sheetData>
            <row r="1"><c r="A1"><v>1</v></c></row>
            <row r="1048576"><c r="XFD1048576"><v>1</v></c></row>
        </sheetData></worksheet>"#;
        let res = scan_xml_entry(Cursor::new(&xml[..]), true);
        assert!(
            res.is_err(),
            "far-apart cells (dimension bomb) must be rejected"
        );
    }

    #[test]
    fn scan_accepts_small_sheet() {
        let xml = br#"<worksheet><sheetData>
            <row r="1"><c r="A1"><v>1</v></c><c r="B1"><v>2</v></c></row>
            <row r="2"><c r="A2"><v>3</v></c></row>
        </sheetData></worksheet>"#;
        let res = scan_xml_entry(Cursor::new(&xml[..]), true);
        assert!(res.is_ok(), "a small contiguous sheet must be accepted");
    }

    /// Build a minimal zip (the worksheet entry is all `precheck_xlsx` needs) so
    /// we exercise the full archive → scan path, not just `scan_worksheet`.
    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            let opts = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, data) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(data).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    /// RT2-1, full path: an archive whose worksheet is a dimension bomb must be
    /// rejected by `precheck_xlsx` before calamine opens it.
    #[test]
    fn precheck_rejects_dimension_bomb_archive() {
        let bomb =
            br#"<worksheet><sheetData><c r="A1"/><c r="XFD1048576"/></sheetData></worksheet>"#;
        let zip = zip_with(&[("xl/worksheets/sheet1.xml", bomb)]);
        assert!(
            precheck_xlsx(&zip).is_err(),
            "dimension-bomb archive must be rejected"
        );
    }

    /// RUSTSEC-2026-0194 guard: a tag with far more attributes than any real
    /// XLSX part uses must be rejected before calamine's checked attribute
    /// iteration (the vulnerable `O(N²)` duplicate-name scan) ever sees it.
    fn attr_bomb_xml(count: usize) -> Vec<u8> {
        let mut attrs = String::new();
        for i in 0..count {
            attrs.push_str(&format!(" a{i}=\"x\""));
        }
        format!("<c{attrs}/>").into_bytes()
    }

    #[test]
    fn scan_rejects_attribute_bomb_in_worksheet() {
        let xml = attr_bomb_xml(MAX_ATTRS_PER_TAG + 1);
        let res = scan_xml_entry(Cursor::new(&xml[..]), true);
        assert!(
            res.is_err(),
            "a tag exceeding MAX_ATTRS_PER_TAG must be rejected"
        );
    }

    #[test]
    fn scan_accepts_tag_at_attribute_cap() {
        let xml = attr_bomb_xml(MAX_ATTRS_PER_TAG);
        let res = scan_xml_entry(Cursor::new(&xml[..]), true);
        assert!(res.is_ok(), "a tag exactly at the cap must be accepted");
    }

    /// The attribute-count guard must also cover non-worksheet XML parts
    /// (sharedStrings, styles, workbook.xml, …), since calamine parses all of
    /// them with the same vulnerable checked-attribute pattern.
    #[test]
    fn precheck_rejects_attribute_bomb_in_shared_strings() {
        let bomb = attr_bomb_xml(MAX_ATTRS_PER_TAG + 1);
        let sheet = br#"<worksheet><sheetData><c r="A1"/></sheetData></worksheet>"#;
        let zip = zip_with(&[
            ("xl/worksheets/sheet1.xml", sheet),
            ("xl/sharedStrings.xml", &bomb),
        ]);
        assert!(
            precheck_xlsx(&zip).is_err(),
            "an attribute bomb in a non-worksheet XML part must be rejected"
        );
    }

    /// A small, well-formed archive (worksheet + a non-worksheet entry exercising
    /// the zip-bomb sink branch) must pass the pre-scan.
    #[test]
    fn precheck_accepts_small_archive() {
        let sheet = br#"<worksheet><sheetData><c r="A1"/><c r="B2"/></sheetData></worksheet>"#;
        let shared = br#"<sst><si><t>hello</t></si></sst>"#;
        let zip = zip_with(&[
            ("xl/worksheets/sheet1.xml", sheet),
            ("xl/sharedStrings.xml", shared),
        ]);
        assert!(
            precheck_xlsx(&zip).is_ok(),
            "a small archive must be accepted"
        );
    }
}
