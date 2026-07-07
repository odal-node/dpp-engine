//! Construction products sector HTML section.

use super::super::esc::esc;

pub(super) fn build_construction_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let family = esc(sd
        .get("productFamily")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let country = esc(sd
        .get("countryOfManufacture")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let unit = esc(sd
        .get("functionalUnit")
        .and_then(|v| v.as_str())
        .unwrap_or("unit"));
    let co2e = sd
        .get("co2ePerFunctionalUnitKg")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.2} kg CO\u{2082}e / {unit}"))
        .unwrap_or_else(|| "-".into());
    let ce = sd
        .get("ceMarking")
        .and_then(|v| v.as_bool())
        .map(|v| if v { "Yes" } else { "No" })
        .unwrap_or("-");
    format!(
        r#"<h2>Construction Product Information</h2>
    <table aria-label="Construction product data">
      <tr><th scope="row">Product Family</th><td>{family}</td></tr>
      <tr><th scope="row">Country of Manufacture</th><td>{country}</td></tr>
      <tr><th scope="row">Carbon Footprint</th><td>{co2e}</td></tr>
      <tr><th scope="row">CE Marking</th><td>{ce}</td></tr>
    </table>"#
    )
}
