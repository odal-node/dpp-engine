//! The completeness half of the public page.
//!
//! # Why this exists
//!
//! Each sector section in [`super::sections`] is a hand-written table of named
//! fields, chosen for a readable summary. Battery renders seven. Battery v2.6.0
//! declares **53** fields `x-disclosure: public`, each citing an Annex XIII basis
//! in its own schema `description` — so 46 fields that `public_view` deliberately
//! passes into the signed public payload never reached the page.
//!
//! That is not a leak; nothing over-discloses. It is the opposite, and it matters
//! because of *which* surface is short: the carrier this node mints points at the
//! resolver, `/dpp/{id}` is content-negotiated, and a phone camera sends
//! `Accept: text/html`. So the JSON-LD representation served every public field
//! and the representation a consumer actually reaches served seven of them —
//! including none of `hazardousSubstances`, `hazardSymbol`,
//! `usableExtinguishingAgent` or `wasteBatteryInformation`.
//!
//! # Why "everything else" rather than "everything"
//!
//! The curated sections are worth keeping: they format units (`3.2 V`,
//! `100.0 Ah`), order fields by what a reader wants first, and draw the fibre
//! composition bar. Replacing them with a generic key/value dump would trade a
//! completeness defect for a legibility one.
//!
//! So the page is a curated summary **plus** this table of everything the summary
//! did not show. Each section declares the keys it consumes
//! ([`super::sections::rendered_keys`]) and this renders the remainder.
//!
//! # The drift property this buys
//!
//! The remainder is computed from the *data*, not from a list. A field added to
//! a sector in `dpp-core` appears on the public page with no change here — which
//! is the failure mode that produced the original gap, since a hand-written
//! table has no way to notice a field it was never told about.
//!
//! # What it does not do
//!
//! It performs no filtering. Its input is `sectorData` from the already-redacted
//! public view, so a key present here is a key `public_view` decided was public,
//! at the schema version the passport's signature was frozen under. Re-deciding
//! that here would be a second disclosure policy, which is the defect
//! `public_view`'s own doc comment exists to prevent.

use serde_json::Value;

use crate::esc::esc;

/// Keys that are structural rather than data, and belong on no table.
const SKIP: &[&str] = &["sector"];

/// Render every `sectorData` key not already shown by the curated section.
///
/// Returns an empty string when nothing remains, so a sector whose section
/// happens to cover everything gets no empty table.
pub(crate) fn build_remainder_section(p: &Value, already_rendered: &[&str]) -> String {
    let Some(obj) = p.get("sectorData").and_then(Value::as_object) else {
        return String::new();
    };

    let rows: String = obj
        .iter()
        .filter(|(k, _)| !SKIP.contains(&k.as_str()))
        .filter(|(k, _)| !already_rendered.contains(&k.as_str()))
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| {
            format!(
                r#"<tr><th scope="row">{}</th><td>{}</td></tr>"#,
                esc(&humanise(k)),
                render_value(v)
            )
        })
        .collect();

    if rows.is_empty() {
        return String::new();
    }

    format!(
        r#"<h2>Further Public Data</h2>
    <table aria-label="Further public data">{rows}</table>"#
    )
}

/// `batteryChemistry` → `Battery Chemistry`, `co2ePerUnitKg` → `Co2e Per Unit Kg`.
///
/// Deliberately mechanical. A curated label table would be a second place to
/// forget a field — the exact failure this module exists to close — so an
/// imperfect but automatic label beats a good but omittable one. Fields worth a
/// hand-written label belong in the curated section, which is where they get one.
fn humanise(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 8);
    for (i, c) in key.char_indices() {
        if i == 0 {
            out.extend(c.to_uppercase());
            continue;
        }
        // A word boundary is an uppercase letter, or the first digit of a run
        // (`co2ePerUnitKg` → `Co2e Per Unit Kg`, not `Co 2 e …`).
        let starts_word =
            c.is_uppercase() || (c.is_ascii_digit() && !key[..i].ends_with(char::is_numeric));
        if starts_word {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// Render one JSON value as escaped HTML.
///
/// Objects and arrays are summarised rather than expanded: a nested structure
/// rendered inline is unreadable, and the JSON-LD representation is the right
/// place for a consumer who wants the full shape. What matters is that the field
/// is *visible* — a reader can see it exists and how much is there.
fn render_value(v: &Value) -> String {
    match v {
        Value::String(s) => esc(s),
        Value::Number(n) => esc(&n.to_string()),
        Value::Bool(b) => (if *b { "Yes" } else { "No" }).to_owned(),
        Value::Array(a) if a.is_empty() => "None".to_owned(),
        Value::Array(a) => {
            // A list of scalars reads fine inline; anything else gets a count.
            if a.iter().all(|e| e.is_string() || e.is_number()) {
                a.iter().map(render_value).collect::<Vec<_>>().join(", ")
            } else {
                format!("{} entries", a.len())
            }
        }
        Value::Object(o) => {
            // One level of nesting inline, which covers the common
            // `{ value, unit }` and `{ pct, basis }` shapes without turning the
            // table into a tree.
            o.iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| format!("{}: {}", esc(&humanise(k)), render_value(v)))
                .collect::<Vec<_>>()
                .join("; ")
        }
        Value::Null => String::new(),
    }
}

/// [`humanise`], for the cross-module completeness test in [`super::sections`].
#[cfg(test)]
pub(crate) fn humanise_for_test(key: &str) -> String {
    humanise(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn renders_only_what_the_curated_section_did_not() {
        let p = json!({ "sectorData": {
            "sector": "battery",
            "batteryChemistry": "LFP",
            "hazardSymbol": "GHS07",
        }});
        let html = build_remainder_section(&p, &["batteryChemistry"]);
        assert!(html.contains("Hazard Symbol"), "{html}");
        assert!(html.contains("GHS07"));
        assert!(
            !html.contains("Battery Chemistry"),
            "the curated section already showed it: {html}"
        );
        assert!(!html.contains(">sector<"), "the tag is not data");
    }

    #[test]
    fn nothing_left_renders_nothing() {
        let p = json!({ "sectorData": { "sector": "battery", "batteryChemistry": "LFP" }});
        assert_eq!(build_remainder_section(&p, &["batteryChemistry"]), "");
    }

    #[test]
    fn absent_sector_data_renders_nothing() {
        assert_eq!(build_remainder_section(&json!({}), &[]), "");
    }

    /// Nulls are absence, not data. `Passport`'s optional fields serialise as
    /// absent, but a stored document can carry an explicit null.
    #[test]
    fn null_values_are_omitted() {
        let p = json!({ "sectorData": { "sector": "x", "a": serde_json::Value::Null }});
        assert_eq!(build_remainder_section(&p, &[]), "");
    }

    /// Every value on this table is caller-influenced free text from the
    /// passport, so the same escaping rule the curated sections follow applies —
    /// in the label as well as the value, since a key can be arbitrary in a
    /// stored document.
    #[test]
    fn values_and_labels_are_escaped() {
        let p = json!({ "sectorData": {
            "sector": "x",
            "note": "<script>alert(1)</script>",
        }});
        let html = build_remainder_section(&p, &[]);
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn humanise_splits_camel_case_and_digits() {
        assert_eq!(humanise("batteryChemistry"), "Battery Chemistry");
        assert_eq!(humanise("gtin"), "Gtin");
        assert_eq!(
            humanise("recycledContentCobaltPct"),
            "Recycled Content Cobalt Pct"
        );
    }

    #[test]
    fn scalars_arrays_and_objects_all_render() {
        assert_eq!(render_value(&json!("x")), "x");
        assert_eq!(render_value(&json!(1.5)), "1.5");
        assert_eq!(render_value(&json!(true)), "Yes");
        assert_eq!(render_value(&json!([])), "None");
        assert_eq!(render_value(&json!(["a", "b"])), "a, b");
        assert_eq!(render_value(&json!([{"a":1},{"a":2}])), "2 entries");
        assert_eq!(render_value(&json!({"pct": 12.5})), "Pct: 12.5");
    }
}
