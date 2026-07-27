//! Textile sector HTML section, including the fibre-composition bar chart.

use crate::esc::esc;
use crate::fields::{f64_field, str_field};

pub(super) fn build_textile_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };

    let country = str_field(sd, "countryOfManufacturing", "-");
    let care = str_field(sd, "careInstructions", "-");
    let chemical = str_field(sd, "chemicalComplianceStandard", "-");
    let recycled = f64_field(sd, "recycledContentPct", "-", |v| format!("{v:.1}%"));

    // Fibre composition bar
    let fibres: Vec<(&str, f64)> = sd
        .get("fibreComposition")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    let name = e.get("fibre")?.as_str()?;
                    let pct = e.get("pct")?.as_f64()?;
                    Some((name, pct))
                })
                .collect()
        })
        .unwrap_or_default();

    let fibre_bar = build_fibre_bar(&fibres);
    let fibre_legend = build_fibre_legend(&fibres);

    format!(
        r#"<h2>Textile Information</h2>
    <table aria-label="Textile data">
      <tr><th scope="row">Country of Manufacturing</th><td>{country}</td></tr>
      <tr><th scope="row">Care Instructions</th><td>{care}</td></tr>
      <tr><th scope="row">Chemical Compliance</th><td>{chemical}</td></tr>
      <tr><th scope="row">Recycled Content</th><td>{recycled}</td></tr>
      <tr>
        <th scope="row">Fibre Composition</th>
        <td>
          {fibre_bar}
          {fibre_legend}
        </td>
      </tr>
    </table>"#
    )
}

/// Palette of accessible colours for fibre composition segments.
const FIBRE_COLOURS: &[&str] = &[
    "#2563eb", "#16a34a", "#d97706", "#dc2626", "#7c3aed", "#0891b2", "#059669", "#b45309",
    "#9333ea", "#0284c7",
];

fn build_fibre_bar(fibres: &[(&str, f64)]) -> String {
    if fibres.is_empty() {
        return String::new();
    }
    let segs: String = fibres
        .iter()
        .enumerate()
        .map(|(i, (name, pct))| {
            let colour = FIBRE_COLOURS[i % FIBRE_COLOURS.len()];
            let name = esc(name);
            let label = if *pct >= 10.0 {
                format!("{pct:.0}%")
            } else {
                String::new()
            };
            format!(
                r#"<div class="fibre-seg" style="width:{pct:.1}%;background:{colour}" title="{name}: {pct:.1}%" aria-label="{name} {pct:.1} percent">{label}</div>"#
            )
        })
        .collect();
    format!(
        r#"<div class="fibre-bar" role="img" aria-label="Fibre composition bar chart">{segs}</div>"#
    )
}

fn build_fibre_legend(fibres: &[(&str, f64)]) -> String {
    if fibres.is_empty() {
        return String::new();
    }
    let items: String = fibres
        .iter()
        .enumerate()
        .map(|(i, (name, pct))| {
            let colour = FIBRE_COLOURS[i % FIBRE_COLOURS.len()];
            let name = esc(name);
            format!(
                r#"<span style="display:inline-flex;align-items:center;gap:.25rem;margin:.2rem .4rem 0 0;font-size:.75rem"><span style="display:inline-block;width:10px;height:10px;background:{colour};border-radius:2px;flex-shrink:0" aria-hidden="true"></span>{name} {pct:.1}%</span>"#
            )
        })
        .collect();
    format!(r#"<div style="margin-top:.4rem">{items}</div>"#)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_data_populates_all_fields() {
        let p = serde_json::json!({"sectorData": {
            "countryOfManufacturing": "Germany",
            "careInstructions": "Machine wash cold",
            "chemicalComplianceStandard": "OEKO-TEX Standard 100",
            "recycledContentPct": 32.5,
            "fibreComposition": [
                { "fibre": "Organic Cotton", "pct": 80.0 },
                { "fibre": "Elastane", "pct": 20.0 },
            ],
        }});
        let html = build_textile_section(&p);
        assert!(html.contains("Germany"));
        assert!(html.contains("Machine wash cold"));
        assert!(html.contains("OEKO-TEX Standard 100"));
        assert!(html.contains("32.5%"));
        assert!(html.contains("Organic Cotton"));
        assert!(html.contains("Elastane"));
    }

    #[test]
    fn missing_fields_fall_back_to_dashes() {
        let p = serde_json::json!({"sectorData": {}});
        let html = build_textile_section(&p);
        assert!(html.contains("Textile Information"));
        assert!(html.contains(">-<"));
    }

    #[test]
    fn absent_sector_data_returns_empty_string() {
        let p = serde_json::json!({});
        assert_eq!(build_textile_section(&p), "");
    }

    /// The textile sector catalog (`dpp-core/crates/dpp-domain/sectors/textile.json`)
    /// marks `svhcSubstances`, `disassemblyInstructions` and `sparePartsAvailable` as
    /// professional-tier, not public. This section is expected to receive an
    /// already-redacted Public-tier view and performs no filtering of its own — but
    /// it also never names these fields, so even an unredacted passport renders
    /// none of them. Guards that property against a future edit that starts
    /// serializing `sectorData` wholesale instead of field-by-field.
    #[test]
    fn professional_tier_fields_are_never_rendered() {
        let p = serde_json::json!({"sectorData": {
            "countryOfManufacturing": "Germany",
            "svhcSubstances": "MARKER_SVHC_SUBSTANCE",
            "disassemblyInstructions": "MARKER_DISASSEMBLY_INSTRUCTIONS",
            "sparePartsAvailable": "MARKER_SPARE_PARTS",
        }});
        let html = build_textile_section(&p);
        assert!(!html.contains("MARKER_SVHC_SUBSTANCE"), "leaked: {html}");
        assert!(
            !html.contains("MARKER_DISASSEMBLY_INSTRUCTIONS"),
            "leaked: {html}"
        );
        assert!(!html.contains("MARKER_SPARE_PARTS"), "leaked: {html}");
    }
}
