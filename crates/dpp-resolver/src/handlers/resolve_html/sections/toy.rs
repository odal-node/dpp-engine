//! Toy safety sector HTML section.

use super::super::esc::esc;

pub(super) fn build_toy_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let age = esc(sd.get("ageGroup").and_then(|v| v.as_str()).unwrap_or("-"));
    let material = esc(sd
        .get("primaryMaterial")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let country = esc(sd
        .get("countryOfManufacture")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let ce = sd
        .get("ceMarking")
        .and_then(|v| v.as_bool())
        .map(|v| if v { "Yes" } else { "No" })
        .unwrap_or("-");
    format!(
        r#"<h2>Toy Safety Information</h2>
    <table aria-label="Toy data">
      <tr><th scope="row">Age Group</th><td>{age}</td></tr>
      <tr><th scope="row">Primary Material</th><td>{material}</td></tr>
      <tr><th scope="row">Country of Manufacture</th><td>{country}</td></tr>
      <tr><th scope="row">CE Marking</th><td>{ce}</td></tr>
    </table>"#
    )
}
