//! Steel sector HTML section.

use super::super::esc::esc;

pub(super) fn build_steel_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let route = esc(sd
        .get("productionRoute")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let category = esc(sd
        .get("productCategory")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let country = esc(sd
        .get("countryOfProduction")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let co2e = sd
        .get("co2ePerTonneSteel")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.3} t CO\u{2082}e / t steel"))
        .unwrap_or_else(|| "-".into());
    let recycled = sd
        .get("recycledScrapContentPct")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".into());
    format!(
        r#"<h2>Steel Product Information</h2>
    <table aria-label="Steel data">
      <tr><th scope="row">Product Category</th><td>{category}</td></tr>
      <tr><th scope="row">Production Route</th><td>{route}</td></tr>
      <tr><th scope="row">Country of Production</th><td>{country}</td></tr>
      <tr><th scope="row">Carbon Intensity</th><td>{co2e}</td></tr>
      <tr><th scope="row">Recycled Scrap Content</th><td>{recycled}</td></tr>
    </table>"#
    )
}
