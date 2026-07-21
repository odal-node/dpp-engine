//! Detergent sector HTML section.

use crate::fields::{array_len_field, bool_field, str_field};

pub(super) fn build_detergent_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };
    let product_type = str_field(sd, "productType", "-");
    let format = str_field(sd, "format", "-");
    let country = str_field(sd, "countryOfManufacture", "-");
    let biodegradable = bool_field(
        sd,
        "biodegradable",
        "-",
        "All surfactants biodegradable",
        "Not fully biodegradable",
    );
    let surfactant_count = array_len_field(sd, "surfactants", "-");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_data_populates_all_fields() {
        let p = serde_json::json!({"sectorData": {
            "productType": "Laundry Detergent",
            "format": "Liquid",
            "countryOfManufacture": "NL",
            "biodegradable": true,
            "surfactants": ["anionic", "nonionic"],
        }});
        let html = build_detergent_section(&p);
        assert!(html.contains("Laundry Detergent"));
        assert!(html.contains("Liquid"));
        assert!(html.contains("NL"));
        assert!(html.contains("All surfactants biodegradable"));
        assert!(html.contains(">2<"));
    }

    #[test]
    fn not_biodegradable_renders_the_negative_message() {
        let p = serde_json::json!({"sectorData": {"biodegradable": false}});
        let html = build_detergent_section(&p);
        assert!(html.contains("Not fully biodegradable"));
    }

    #[test]
    fn missing_fields_fall_back_to_dashes() {
        let p = serde_json::json!({"sectorData": {}});
        let html = build_detergent_section(&p);
        assert!(html.contains("Detergent Information"));
        assert!(html.contains(">-<"));
    }

    #[test]
    fn absent_sector_data_returns_empty_string() {
        let p = serde_json::json!({});
        assert_eq!(build_detergent_section(&p), "");
    }
}
