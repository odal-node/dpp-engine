#![no_main]
//! Fuzz the bulk-import XLSX parser — an uploaded workbook is a ZIP archive of
//! XML parts, and every byte of it is the uploader's.
//! Property: `parse_xlsx` returns `Ok`/`Err` for any bytes, never panics, and
//! its zip-bomb, dimension-bomb and attribute-bomb guards hold — an input that
//! inflates past them is an out-of-memory or timeout finding here.
//!
//! Each input is tried twice. As raw bytes it reaches the archive reader and the
//! pre-scan. A ZIP entry carries a CRC-32, though, so almost every mutation of a
//! real archive fails there and never reaches the XML. The second run writes the
//! input as the worksheet of an otherwise valid workbook, the five parts the
//! integrator's own tests build, so the fuzzer works on the sheet XML that the
//! dimension scan and calamine read.

use std::io::{Cursor, Write};

use dpp_integrator::domain::xlsx_parser::parse_xlsx;
use libfuzzer_sys::fuzz_target;

const CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#;

const ROOT_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#;

const WORKBOOK: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>"#;

const WORKBOOK_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#;

/// A workbook whose only worksheet is `sheet`, with every entry stored rather
/// than compressed.
fn workbook_with_sheet(sheet: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, body) in [
        ("[Content_Types].xml", CONTENT_TYPES.as_bytes()),
        ("_rels/.rels", ROOT_RELS.as_bytes()),
        ("xl/workbook.xml", WORKBOOK.as_bytes()),
        ("xl/_rels/workbook.xml.rels", WORKBOOK_RELS.as_bytes()),
        ("xl/worksheets/sheet1.xml", sheet),
    ] {
        zw.start_file(name, opts)
            .expect("an in-memory archive accepts an entry");
        zw.write_all(body)
            .expect("an in-memory archive accepts its bytes");
    }
    zw.finish().expect("an in-memory archive finishes");
    buf
}

fuzz_target!(|data: &[u8]| {
    let _ = parse_xlsx(data);
    let _ = parse_xlsx(&workbook_with_sheet(data));
});
