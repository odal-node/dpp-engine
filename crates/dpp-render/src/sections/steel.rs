//! Steel sector HTML section.

use crate::fields::{f64_field, str_field};

pub(super) fn build_steel_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let route = str_field(sd, "productionRoute", "-");
    let category = str_field(sd, "productCategory", "-");
    let country = str_field(sd, "countryOfProduction", "-");
    let co2e = f64_field(sd, "co2ePerTonneSteel", "-", |v| {
        format!("{v:.3} t CO\u{2082}e / t steel")
    });
    let recycled = f64_field(sd, "recycledScrapContentPct", "-", |v| format!("{v:.1}%"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_data_populates_all_fields() {
        let p = serde_json::json!({"sectorData": {
            "productionRoute": "EAF",
            "productCategory": "Flat Steel",
            "countryOfProduction": "IT",
            "co2ePerTonneSteel": 0.850,
            "recycledScrapContentPct": 65.0,
        }});
        let html = build_steel_section(&p);
        assert!(html.contains("EAF"));
        assert!(html.contains("Flat Steel"));
        assert!(html.contains("IT"));
        assert!(html.contains("0.850 t CO\u{2082}e / t steel"));
        assert!(html.contains("65.0%"));
    }

    #[test]
    fn missing_fields_fall_back_to_dashes() {
        let p = serde_json::json!({"sectorData": {}});
        let html = build_steel_section(&p);
        assert!(html.contains("Steel Product Information"));
        assert!(html.contains(">-<"));
    }

    #[test]
    fn absent_sector_data_returns_empty_string() {
        let p = serde_json::json!({});
        assert_eq!(build_steel_section(&p), "");
    }
}
