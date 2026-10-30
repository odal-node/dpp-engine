//! Bulk import, the part that runs on the node: reading an operator's spreadsheet
//! and validating each row. These take untrusted uploads, so they are the work an
//! import costs before a single request goes to the vault.
//!
//! The CSV header is the one the downloadable template generates, annotations and
//! all, and the rows are textile ones that pass validation.
//!
//! Run with:
//! ```sh
//! cargo bench -p dpp-integrator
//! ```

use std::collections::HashMap;
use std::io::{Cursor, Write};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use dpp_integrator::domain::csv_parser::parse_csv;
use dpp_integrator::domain::validate::{columns_for, template_header, validate_row};
use dpp_integrator::domain::xlsx_parser::parse_xlsx;

const PRODUCT_GROUP: &str = "textile";

/// A value for a textile column, or empty for the optional ones this fixture leaves
/// out. Row `n` differs from row `n + 1` in its batch, so no two rows are equal.
fn cell(column: &str, n: usize) -> String {
    match column {
        "productName" => format!("Organic Cotton T-Shirt {n}"),
        "gtin" => "09506000134352".into(),
        "batchId" => format!("LOT-{n:06}"),
        "manufacturerName" => "Sample Textiles Co.".into(),
        "manufacturerCountry" => "DE".into(),
        "countryOfOrigin" => "BD".into(),
        "careInstructions" => "30\u{00B0}C machine wash".into(),
        "chemicalComplianceStandard" => "OEKO-TEX 100".into(),
        "fibreComposition" => {
            r#"[{"fibre":"cotton","pct":60.0},{"fibre":"polyester","pct":40.0}]"#.into()
        }
        "recycledContentPct" => "12.5".into(),
        _ => String::new(),
    }
}

fn column_names() -> Vec<&'static str> {
    columns_for(PRODUCT_GROUP)
        .expect("textile is importable")
        .iter()
        .map(|c| c.name)
        .collect()
}

fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn csv_bytes(rows: usize) -> Vec<u8> {
    let columns = column_names();
    let mut out = template_header(&columns_for(PRODUCT_GROUP).expect("importable"));
    out.push('\n');
    for n in 0..rows {
        let line: Vec<String> = columns.iter().map(|c| csv_field(&cell(c, n))).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out.into_bytes()
}

/// Spreadsheet column letters: A..Z, AA..
fn letters(mut index: usize) -> String {
    let mut out = Vec::new();
    loop {
        out.push(b'A' + (index % 26) as u8);
        if index < 26 {
            break;
        }
        index = index / 26 - 1;
    }
    out.reverse();
    String::from_utf8(out).expect("ASCII")
}

fn xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A minimal workbook: one sheet of inline strings, deflated as a real file is.
fn xlsx_bytes(rows: usize) -> Vec<u8> {
    let columns = column_names();
    let header = columns_for(PRODUCT_GROUP).expect("importable");

    let mut sheet = String::from(
        r#"<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>"#,
    );
    let mut push_row = |r: usize, values: Vec<String>| {
        sheet.push_str(&format!(r#"<row r="{r}">"#));
        for (i, value) in values.iter().enumerate().filter(|(_, v)| !v.is_empty()) {
            sheet.push_str(&format!(
                r#"<c r="{}{r}" t="inlineStr"><is><t>{}</t></is></c>"#,
                letters(i),
                xml_text(value)
            ));
        }
        sheet.push_str("</row>");
    };
    push_row(1, header.iter().map(|c| c.header_cell()).collect());
    for n in 0..rows {
        push_row(n + 2, columns.iter().map(|c| cell(c, n)).collect());
    }
    sheet.push_str("</sheetData></worksheet>");

    let parts: [(&str, &str); 5] = [
        (
            "[Content_Types].xml",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#,
        ),
        (
            "_rels/.rels",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#,
        ),
        (
            "xl/workbook.xml",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>"#,
        ),
        (
            "xl/_rels/workbook.xml.rels",
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#,
        ),
        ("xl/worksheets/sheet1.xml", &sheet),
    ];

    let mut buf = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(Cursor::new(&mut buf));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in parts {
            zip.start_file(name, options).expect("start zip entry");
            zip.write_all(data.as_bytes()).expect("write zip entry");
        }
        zip.finish().expect("finish zip");
    }
    buf
}

fn sample_row(n: usize) -> HashMap<String, String> {
    column_names()
        .into_iter()
        .map(|c| (c.to_owned(), cell(c, n)))
        .filter(|(_, v)| !v.is_empty())
        .collect()
}

fn parsing(c: &mut Criterion) {
    let mut csv = c.benchmark_group("csv_parse");
    for rows in [10_usize, 1_000, 10_000] {
        let bytes = csv_bytes(rows);
        assert_eq!(
            parse_csv(&bytes).expect("the fixture parses").len(),
            rows,
            "every CSV fixture row should survive parsing"
        );
        csv.throughput(Throughput::Elements(rows as u64));
        csv.bench_with_input(BenchmarkId::from_parameter(rows), &bytes, |b, bytes| {
            b.iter(|| parse_csv(bytes).unwrap());
        });
    }
    csv.finish();

    // The XLSX path also pre-scans the archive for zip and dimension bombs, so this
    // is the whole cost of accepting a workbook, not just reading its cells.
    let mut xlsx = c.benchmark_group("xlsx_parse");
    for rows in [10_usize, 1_000] {
        let bytes = xlsx_bytes(rows);
        assert_eq!(
            parse_xlsx(&bytes).expect("the fixture parses").len(),
            rows,
            "every XLSX fixture row should survive parsing"
        );
        xlsx.throughput(Throughput::Elements(rows as u64));
        xlsx.bench_with_input(BenchmarkId::from_parameter(rows), &bytes, |b, bytes| {
            b.iter(|| parse_xlsx(bytes).unwrap());
        });
    }
    xlsx.finish();
}

fn validation(c: &mut Criterion) {
    let valid = sample_row(0);
    assert!(
        validate_row(PRODUCT_GROUP, &valid, 1).is_ok(),
        "the fixture row should validate, or this times the failure path"
    );
    // A row with nothing in it fails on every required column at once.
    let empty = HashMap::new();
    assert!(
        validate_row(PRODUCT_GROUP, &empty, 1).is_err(),
        "an empty row should be refused"
    );

    let mut group = c.benchmark_group("validate_row");
    group.bench_function("textile_valid", |b| {
        b.iter(|| validate_row(PRODUCT_GROUP, &valid, 1).is_ok());
    });
    group.bench_function("textile_empty", |b| {
        b.iter(|| validate_row(PRODUCT_GROUP, &empty, 1).is_err());
    });
    group.finish();

    // Everything an import does before the first request to the vault.
    let bytes = csv_bytes(1_000);
    let import = || {
        parse_csv(&bytes)
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(i, row)| validate_row(PRODUCT_GROUP, row, i + 1).is_ok())
            .count()
    };
    assert_eq!(
        import(),
        1_000,
        "every row of the pipeline fixture should pass"
    );
    c.bench_function("import_cpu_1000_rows", |b| b.iter(import));
}

criterion_group!(benches, parsing, validation);
criterion_main!(benches);
