//! CSV parser for bulk import uploads.
//! Strips Odal template annotations from column headers and enforces the row cap.

use std::collections::HashMap;

use thiserror::Error;

/// Hard cap on the number of data rows produced from a single upload. Bounds the
/// memory a caller can force the parser/validator to allocate (shared by the CSV
/// and XLSX paths).
pub(crate) const MAX_ROWS: usize = 200_000;

/// Errors produced while parsing a CSV or XLSX file structure (not row-level
/// validation — those are handled by the validator).
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("CSV error: {0}")]
    Csv(String),
    #[error("file is empty or has no header row")]
    Empty,
}

/// Parse CSV bytes into a list of rows.
///
/// Column headers are normalised: the `[REQUIRED]` and `[OPTIONAL]` suffixes
/// used in Odal's downloadable templates are stripped and values are trimmed.
///
/// Empty rows (all cells blank) are silently skipped.
pub fn parse_csv(bytes: &[u8]) -> Result<Vec<HashMap<String, String>>, ParseError> {
    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .flexible(true)
        .delimiter(detect_delimiter(bytes))
        .from_reader(bytes);

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| ParseError::Csv(e.to_string()))?
        .iter()
        .map(normalize_header)
        .collect();

    if headers.iter().all(|h| h.is_empty()) {
        return Err(ParseError::Empty);
    }

    let mut rows: Vec<HashMap<String, String>> = Vec::new();

    for result in reader.records() {
        let record = result.map_err(|e| ParseError::Csv(e.to_string()))?;
        let row: HashMap<String, String> = headers
            .iter()
            .zip(record.iter())
            .filter(|(k, v)| !k.is_empty() && !v.trim().is_empty())
            .map(|(k, v)| (k.clone(), v.trim().to_owned()))
            .collect();
        if !row.is_empty() {
            rows.push(row);
            if rows.len() > MAX_ROWS {
                return Err(ParseError::Csv(format!(
                    "file contains too many rows; maximum is {MAX_ROWS}"
                )));
            }
        }
    }

    Ok(rows)
}

/// Detect the field delimiter from the first line: tab (TSV), semicolon
/// (European CSV, only when no comma is present), else comma. Mirrors the
/// delimiter handling the CLI used to do client-side.
fn detect_delimiter(bytes: &[u8]) -> u8 {
    let first_line = bytes.split(|&b| b == b'\n').next().unwrap_or(bytes);
    let has = |c: u8| first_line.contains(&c);
    if has(b'\t') {
        b'\t'
    } else if has(b';') && !has(b',') {
        b';'
    } else {
        b','
    }
}

/// Strip `[REQUIRED]` / `[OPTIONAL]` annotation suffixes and trim whitespace.
pub(crate) fn normalize_header(header: &str) -> String {
    header
        .replace(" [REQUIRED]", "")
        .replace(" [OPTIONAL]", "")
        .trim()
        .to_owned()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header_annotations() {
        assert_eq!(normalize_header("productName [REQUIRED]"), "productName");
        assert_eq!(
            normalize_header("recycledContentPct [OPTIONAL]"),
            "recycledContentPct"
        );
        assert_eq!(normalize_header("plain"), "plain");
    }

    #[test]
    fn detects_delimiters() {
        assert_eq!(detect_delimiter(b"a\tb\tc\n"), b'\t');
        assert_eq!(detect_delimiter(b"a;b;c\n"), b';');
        assert_eq!(detect_delimiter(b"a,b,c\n"), b',');
        // Comma present alongside semicolons (quoted address) → comma wins.
        assert_eq!(detect_delimiter(b"a,b;c\n"), b',');
    }

    #[test]
    fn parses_semicolon_separated() {
        let csv = b"productName [REQUIRED];batchId [REQUIRED]\nWidget A;BATCH-001\n";
        let rows = parse_csv(csv).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("productName").unwrap(), "Widget A");
        assert_eq!(rows[0].get("batchId").unwrap(), "BATCH-001");
    }

    #[test]
    fn parses_simple_csv() {
        let csv =
            b"productName [REQUIRED],batchId [REQUIRED]\nWidget A,BATCH-001\nWidget B,BATCH-002\n";
        let rows = parse_csv(csv).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get("productName").unwrap(), "Widget A");
        assert_eq!(rows[0].get("batchId").unwrap(), "BATCH-001");
    }

    #[test]
    fn skips_empty_rows() {
        let csv = b"productName [REQUIRED],batchId [REQUIRED]\nWidget A,BATCH-001\n,,\n\nWidget B,BATCH-002\n";
        let rows = parse_csv(csv).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn error_on_empty_file() {
        let csv = b"";
        assert!(parse_csv(csv).is_err());
    }

    /// Regression (red-team RT2-1): the CSV path must reject inputs that exceed
    /// the row cap so a single upload can't force an unbounded allocation.
    #[test]
    fn rejects_too_many_rows() {
        let mut csv = String::from("productName [REQUIRED]\n");
        for _ in 0..(MAX_ROWS + 1) {
            csv.push_str("Widget\n");
        }
        let err = parse_csv(csv.as_bytes()).unwrap_err();
        assert!(matches!(err, ParseError::Csv(_)), "got: {err:?}");
    }
}
