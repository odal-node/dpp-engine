//! XLSX parser for bulk import uploads.
//! Includes zip-bomb, dimension-bomb, and pathological-attribute pre-scan
//! guards before delegating to calamine.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{BufRead, Cursor, Read};

use calamine::{Data, DataRef, Reader, ReaderRef, Xlsx};
use quick_xml::Reader as XmlReader;
use quick_xml::events::Event;
use zip::ZipArchive;

use crate::domain::csv_parser::{MAX_RETAINED_BYTES, MAX_ROWS, ParseError, normalize_header};

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
/// archive. Defence in depth, not a patch: the quadratic duplicate-attribute
/// scan this originally guarded (RUSTSEC-2026-0194) is fixed upstream, and
/// both calamine and our own pre-scan now run quick-xml >= 0.41. The cap stays
/// because it bounds the input rather than trusting the parser — a crafted tag
/// with tens of thousands of attributes is still pathological work for any
/// implementation, and this rejects it before calamine, or the scan below,
/// touches it. A legitimate XLSX tag never carries more than a handful (a `<c>`
/// cell tops out around 6; a root `<worksheet>`/`<workbook>` tag's xmlns
/// declarations top out around a dozen).
const MAX_ATTRS_PER_TAG: usize = 64;

/// Most unique shared strings a workbook may declare. The reader reserves room
/// for the declared `uniqueCount` before it reads a single string, so that count
/// is capped first. `count`, the total number of references, sizes nothing.
const MAX_SHARED_STRINGS: u64 = 1_000_000;

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

    // The borrowed range, not `worksheet_range`: that one gives every cell its own
    // `String`, so a shared string named by 100,000 cells was copied 100,000 times
    // before the retained-bytes budget below was looked at, and 32 KiB of text
    // became 3 GiB. Here a shared string is a `&str` into the workbook's own
    // table, and is copied only once the budget has accepted it.
    let range = wb
        .worksheet_range_ref(&first_sheet)
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
    let mut retained = 0usize;

    for row in rows_iter {
        let mut map = HashMap::new();
        for (i, cell) in row.iter().enumerate().take(header_count) {
            let key = &headers[i];
            if key.is_empty() {
                continue;
            }
            let value = cell_to_string(cell);
            if !value.is_empty() {
                retained = retained.saturating_add(key.len() + value.len());
                if retained > MAX_RETAINED_BYTES {
                    return Err(ParseError::Csv(format!(
                        "the workbook's parsed content exceeds {MAX_RETAINED_BYTES} bytes"
                    )));
                }
                map.insert(key.clone(), value.into_owned());
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

/// A cell's text. A string cell is **borrowed** (trimmed), not copied, so its
/// length can be counted against the retained-bytes budget before any copy of it
/// is made.
fn cell_to_string<'a>(cell: &'a DataRef<'_>) -> Cow<'a, str> {
    match cell {
        DataRef::Empty | DataRef::Error(_) => Cow::Borrowed(""),
        DataRef::Bool(b) => Cow::Owned(b.to_string()),
        DataRef::Int(i) => Cow::Owned(i.to_string()),
        DataRef::Float(f) => {
            // Avoid scientific notation for whole numbers (e.g. GTINs stored as floats)
            if f.fract() == 0.0 && f.abs() < 1e15_f64 {
                Cow::Owned(format!("{:.0}", f))
            } else {
                Cow::Owned(f.to_string())
            }
        }
        DataRef::SharedString(s) => Cow::Borrowed(s.trim()),
        DataRef::String(s) => Cow::Borrowed(s.trim()),
        // Dates and durations: a few bytes each, formatted as they always were.
        other => Cow::Owned(Data::from(other.clone()).to_string()),
    }
}

fn cell_to_header(cell: &DataRef<'_>) -> String {
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
///   scanned for tags exceeding `MAX_ATTRS_PER_TAG`.
fn precheck_xlsx(bytes: &[u8]) -> Result<(), ParseError> {
    let mut zip = ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ParseError::Csv(format!("XLSX is not a valid zip: {e}")))?;

    let mut budget = MAX_DECOMPRESSED_BYTES;
    for i in 0..zip.len() {
        let entry = zip
            .by_index(i)
            .map_err(|e| ParseError::Csv(format!("XLSX entry error: {e}")))?;
        // A name that cannot be read is refused, not skipped: skipping would
        // leave that entry's XML unscanned.
        let name = entry
            .name()
            .map_err(|e| ParseError::Csv(format!("XLSX entry name error: {e}")))?;
        // The reader finds a part by its name case-insensitively and with `\` read
        // as `/`, so the checks name parts the same way: otherwise a part named
        // `xl/SharedStrings.xml` is read as the shared strings and escapes their cap.
        let name = name.replace('\\', "/").to_ascii_lowercase();
        let is_worksheet = name.starts_with("xl/worksheets/") && name.ends_with(".xml");
        let is_shared_strings = name == "sharedstrings.xml" || name.ends_with("/sharedstrings.xml");
        let is_xml = name.ends_with(".xml") || name.ends_with(".rels");
        let mut limited = LimitedReader {
            inner: entry,
            remaining: &mut budget,
        };
        if is_xml {
            scan_xml_entry(
                std::io::BufReader::new(limited),
                is_worksheet,
                is_shared_strings,
            )?;
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
/// `.attributes()`/`try_get_attribute`: the checked variants do a duplicate-name
/// scan over every attribute, so counting attributes with them would do the
/// very work this guard exists to bound. Keep it unchecked here regardless of
/// what the parser costs — a guard that scales with its input is not a guard.
fn scan_xml_entry<R: BufRead>(
    reader: R,
    track_dimensions: bool,
    track_shared_strings: bool,
) -> Result<(), ParseError> {
    let mut xml = XmlReader::from_reader(reader);
    let mut buf = Vec::new();
    let (mut max_col, mut max_row): (u64, u64) = (0, 0);
    loop {
        match xml.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                // The reader resolves a prefixed element (`x:c`) to the same cell as
                // an unprefixed one, so the check matches local names, as it does.
                let is_cell = track_dimensions && e.local_name().as_ref() == "c";
                let is_shared_strings_root =
                    track_shared_strings && e.local_name().as_ref() == "sst";
                let mut attr_count = 0usize;
                let mut r_value: Option<String> = None;
                for attr in e.attributes().with_checks(false) {
                    attr_count += 1;
                    if attr_count > MAX_ATTRS_PER_TAG {
                        return Err(ParseError::Csv(format!(
                            "XLSX contains a tag with too many attributes; \
                                 maximum is {MAX_ATTRS_PER_TAG}"
                        )));
                    }
                    if let Ok(attr) = attr {
                        if is_cell && attr.key.local_name().as_ref() == "r" {
                            r_value = Some(attr.value.into_owned());
                        } else if is_shared_strings_root
                            && attr.key.local_name().as_ref() == "uniqueCount"
                        {
                            // The reader reserves room for this many strings before
                            // reading any, so the declared `uniqueCount` is bounded
                            // here. `count` totals the references to them and sizes
                            // nothing; an ordinary large workbook exceeds the cap by it.
                            let declared = attr.value.trim().parse::<u64>().unwrap_or(0);
                            if declared > MAX_SHARED_STRINGS {
                                return Err(ParseError::Csv(format!(
                                    "XLSX declares {declared} shared strings; \
                                     maximum is {MAX_SHARED_STRINGS}"
                                )));
                            }
                        }
                    }
                }
                if let Some(r) = r_value
                    && let Some((col, row)) = parse_cell_ref(r.as_bytes())
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
        let res = scan_xml_entry(Cursor::new(&xml[..]), true, false);
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
        let res = scan_xml_entry(Cursor::new(&xml[..]), true, false);
        assert!(res.is_ok(), "a small contiguous sheet must be accepted");
    }

    /// Build a minimal zip (the worksheet entry is all `precheck_xlsx` needs) so
    /// we exercise the full archive → scan path, not just `scan_worksheet`.
    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            // `SimpleFileOptions`, not `FileOptions`: zip 8 made the latter
            // generic over its extended-data type, so a bare `default()` no
            // longer infers. This alias is the no-extra-data case these
            // fixtures want.
            let opts = zip::write::SimpleFileOptions::default()
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

    /// An entry name that is not valid UTF-8 is decoded (zip falls back to
    /// CP437) and the entry is still classified and scanned by it. The guard
    /// keys on the name, so a name it could not read would be a way to dodge the
    /// scan; this pins that it is not.
    #[test]
    fn a_non_utf8_entry_name_does_not_dodge_the_scan() {
        let bomb =
            br#"<worksheet><sheetData><c r="A1"/><c r="XFD1048576"/></sheetData></worksheet>"#;
        let mut zip = zip_with(&[("xl/worksheets/s1.xml", bomb)]);
        // Corrupt the byte after `xl/worksheets/` in the local header (name
        // starts at +30) and in the central directory entry (name at +46), so
        // the two agree. 0xFF is never valid UTF-8.
        const NAME_OFFSET: usize = "xl/worksheets/".len();
        assert_eq!(&zip[..4], b"PK\x03\x04", "first bytes are a local header");
        zip[30 + NAME_OFFSET] = 0xFF;
        let central = zip
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("a central directory entry");
        zip[central + 46 + NAME_OFFSET] = 0xFF;

        let err = precheck_xlsx(&zip).expect_err("the dimension bomb must still be caught");
        assert!(
            matches!(&err, ParseError::Csv(m) if m.contains("oversized dense range")),
            "rejected by the worksheet scan, not for some other reason: {err:?}"
        );
    }

    /// Attribute-bomb guard: a tag with far more attributes than any real XLSX
    /// part uses must be rejected before calamine's checked attribute iteration
    /// (a duplicate-name scan over every attribute) ever sees it.
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
        let res = scan_xml_entry(Cursor::new(&xml[..]), true, false);
        assert!(
            res.is_err(),
            "a tag exceeding MAX_ATTRS_PER_TAG must be rejected"
        );
    }

    #[test]
    fn scan_accepts_tag_at_attribute_cap() {
        let xml = attr_bomb_xml(MAX_ATTRS_PER_TAG);
        let res = scan_xml_entry(Cursor::new(&xml[..]), true, false);
        assert!(res.is_ok(), "a tag exactly at the cap must be accepted");
    }

    /// A prefixed cell is measured like an unprefixed one. The reader resolves
    /// `x:c` to the same cell, so a guard that matched only the bare name let a
    /// far-away cell past the dense-range check.
    #[test]
    fn a_namespace_prefixed_cell_is_measured_too() {
        let xml = br#"<worksheet><sheetData>
            <x:row xmlns:x="urn:x"><x:c r="A1"/><x:c r="XFD1048576"/></x:row>
        </sheetData></worksheet>"#;
        assert!(scan_xml_entry(Cursor::new(&xml[..]), true, false).is_err());
    }

    /// The reader reserves room for a declared shared-string count before reading
    /// any strings, so a count past the cap is refused before that reservation.
    #[test]
    fn a_shared_string_count_past_the_cap_is_refused() {
        let declared = format!(
            r#"<sst xmlns="urn:s" count="1" uniqueCount="{}"/>"#,
            MAX_SHARED_STRINGS + 1
        );
        assert!(scan_xml_entry(Cursor::new(declared.as_bytes()), false, true).is_err());
        let small = br#"<sst xmlns="urn:s" count="1" uniqueCount="1"/>"#;
        assert!(scan_xml_entry(Cursor::new(&small[..]), false, true).is_ok());
    }

    /// `count` totals the references to shared strings, and 100,000 rows of eleven
    /// text columns already pass the cap by it. Only `uniqueCount` sizes the
    /// reader's reservation, so only it is capped.
    #[test]
    fn a_large_total_reference_count_is_accepted() {
        let declared = format!(
            r#"<sst xmlns="urn:s" count="{}" uniqueCount="1"/>"#,
            MAX_SHARED_STRINGS + 1
        );
        assert!(scan_xml_entry(Cursor::new(declared.as_bytes()), false, true).is_ok());
    }

    /// The reader finds the shared strings under any letter case, so a part named
    /// with other case is capped like the usual one.
    #[test]
    fn a_shared_strings_part_named_in_other_case_is_still_capped() {
        let declared = format!(
            r#"<sst xmlns="urn:s" count="1" uniqueCount="{}"/>"#,
            MAX_SHARED_STRINGS + 1
        );
        let sheet = br#"<worksheet><sheetData><c r="A1"/></sheetData></worksheet>"#;
        let zip = zip_with(&[
            ("xl/worksheets/sheet1.xml", sheet),
            ("xl/SharedStrings.xml", declared.as_bytes()),
        ]);
        assert!(precheck_xlsx(&zip).is_err());
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

    /// A workbook calamine opens: one sheet, one column of text cells, each cell
    /// naming an entry of the shared-string table by index (`column[0]` is the
    /// header row).
    fn workbook(shared: &[&str], column: &[usize]) -> Vec<u8> {
        const MAIN: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
        const REL: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
        const DOC: &str = "http://schemas.openxmlformats.org/officeDocument/2006";

        let content_types = r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>"#;
        let root_rels = format!(
            r#"<Relationships xmlns="{REL}"><Relationship Id="rId1" Type="{DOC}/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#
        );
        let workbook = format!(
            r#"<workbook xmlns="{MAIN}" xmlns:r="{DOC}/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>"#
        );
        let workbook_rels = format!(
            r#"<Relationships xmlns="{REL}"><Relationship Id="rId1" Type="{DOC}/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="{DOC}/relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>"#
        );
        let strings: String = shared
            .iter()
            .map(|s| format!("<si><t>{s}</t></si>"))
            .collect();
        let shared_strings = format!(
            r#"<sst xmlns="{MAIN}" count="{}" uniqueCount="{}">{strings}</sst>"#,
            column.len(),
            shared.len()
        );
        let rows: String = column
            .iter()
            .enumerate()
            .map(|(i, index)| {
                let r = i + 1;
                format!(r#"<row r="{r}"><c r="A{r}" t="s"><v>{index}</v></c></row>"#)
            })
            .collect();
        let sheet =
            format!(r#"<worksheet xmlns="{MAIN}"><sheetData>{rows}</sheetData></worksheet>"#);

        zip_with(&[
            ("[Content_Types].xml", content_types.as_bytes()),
            ("_rels/.rels", root_rels.as_bytes()),
            ("xl/workbook.xml", workbook.as_bytes()),
            ("xl/_rels/workbook.xml.rels", workbook_rels.as_bytes()),
            ("xl/sharedStrings.xml", shared_strings.as_bytes()),
            ("xl/worksheets/sheet1.xml", sheet.as_bytes()),
        ])
    }

    /// A workbook of the size the import supports still parses: many rows naming
    /// a few shared strings, which is what a real catalogue export looks like.
    #[test]
    fn a_workbook_of_many_rows_naming_few_strings_still_parses() {
        const ROWS: usize = 20_000;
        let names: Vec<String> = (0..50).map(|i| format!("Product {i:02}")).collect();
        let mut shared: Vec<&str> = vec!["productName"];
        shared.extend(names.iter().map(String::as_str));
        let mut column = vec![0];
        column.extend((0..ROWS).map(|row| 1 + row % names.len()));
        let bytes = workbook(&shared, &column);

        let rows = parse_xlsx(&bytes).expect("a workbook of the supported size parses");

        assert_eq!(rows.len(), ROWS);
        assert_eq!(rows[0]["productName"], "Product 00");
        assert_eq!(rows[ROWS - 1]["productName"], "Product 49");
    }

    /// A workbook of the size the import supports still parses, text trimmed as
    /// before and a string shared by two cells read for each of them.
    #[test]
    fn an_ordinary_workbook_still_parses() {
        let bytes = workbook(
            &["productName", "Cotton Tee", "  Wool Hat  "],
            &[0, 1, 2, 1],
        );

        let rows = parse_xlsx(&bytes).expect("an ordinary workbook parses");

        let names: Vec<&str> = rows.iter().map(|r| r["productName"].as_str()).collect();
        assert_eq!(names, ["Cotton Tee", "Wool Hat", "Cotton Tee"]);
    }

    /// The process's peak resident memory, in KiB. `VmHWM` is a high-water mark,
    /// so a test sees growth past what the process had already reached: it can
    /// miss an allocation a sibling test made first, and cannot invent one. Each
    /// test runs in its own process under nextest, which is what `just test`
    /// uses.
    #[cfg(target_os = "linux")]
    fn peak_resident_kib() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .expect("procfs is readable")
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
            .expect("VmHWM is reported")
    }

    /// One shared string repeated down a column was copied into every cell before
    /// the retained-bytes budget was looked at: `worksheet_range` gives each cell
    /// its own `String`, and the whole range is built first. A workbook can pass
    /// every pre-scan check and still ask for gigabytes: 100,000 cells naming one
    /// 32 KiB string is about 3 GiB. This is the same shape at a size a test can
    /// afford, about 1 GiB if each cell is copied.
    ///
    /// What is asserted is the refusal, and that it was reached without the
    /// copies: the process grew by a fraction of what they would take.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_large_shared_string_repeated_down_a_column_is_refused_before_it_is_copied() {
        const CELLS: usize = 30_000;
        let big = "x".repeat(32 * 1024);
        let mut column = vec![0];
        column.extend(std::iter::repeat_n(1, CELLS));
        let bytes = workbook(&["productName", &big], &column);
        drop(big);

        let before = peak_resident_kib();
        let refused = parse_xlsx(&bytes).expect_err("past the retained-bytes budget");
        let grown_mib = peak_resident_kib().saturating_sub(before) / 1024;

        assert!(
            matches!(&refused, ParseError::Csv(m) if m.contains("exceeds")),
            "refused for the budget: {refused:?}"
        );
        assert!(
            grown_mib < 256,
            "refusing it took {grown_mib} MiB more than the process had used: the cells were \
             copied before the budget was checked"
        );
    }
}
