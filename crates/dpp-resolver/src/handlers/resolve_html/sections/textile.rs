//! Textile sector HTML section, including the fibre-composition bar chart.

use super::super::esc::esc;

pub(super) fn build_textile_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };

    let country = esc(sd
        .get("countryOfManufacturing")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let care = esc(sd
        .get("careInstructions")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let chemical = esc(sd
        .get("chemicalComplianceStandard")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let recycled = sd
        .get("recycledContentPct")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".into());

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
