//! Detergent sector HTML section.

use super::super::esc::esc;

pub(super) fn build_detergent_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let product_type = esc(sd
        .get("productType")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let format = esc(sd.get("format").and_then(|v| v.as_str()).unwrap_or("-"));
    let country = esc(sd
        .get("countryOfManufacture")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let biodegradable = sd
        .get("biodegradable")
        .and_then(|v| v.as_bool())
        .map(|v| {
            if v {
                "All surfactants biodegradable"
            } else {
                "Not fully biodegradable"
            }
        })
        .unwrap_or("-");
    let surfactant_count = sd
        .get("surfactants")
        .and_then(|v| v.as_array())
        .map(|a| a.len().to_string())
        .unwrap_or_else(|| "-".into());
    format!(
        r#"<h2>Detergent Information</h2>
    <table aria-label="Detergent data">
      <tr><th scope="row">Product Type</th><td>{product_type}</td></tr>
      <tr><th scope="row">Format</th><td>{format}</td></tr>
      <tr><th scope="row">Country of Manufacture</th><td>{country}</td></tr>
      <tr><th scope="row">Biodegradability</th><td>{biodegradable}</td></tr>
      <tr><th scope="row">Surfactants Declared</th><td>{surfactant_count}</td></tr>
    </table>"#
    )
}
