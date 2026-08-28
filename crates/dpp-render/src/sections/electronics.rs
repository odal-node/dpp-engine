//! Electronics product group HTML section.

use crate::fields::{f64_field, str_field, u64_field};

/// Human label for a `DeviceType` wire value.
///
/// The field became a closed enum with kebab-case wire values, so what used to
/// be operator-written prose is now a machine token. Rendering it raw would put
/// `other-mobile-phone` in front of a consumer on the public page.
///
/// The four values are the ones Regulation (EU) 2023/1670 Art. 1(1) enumerates.
/// Anything else is passed through untouched rather than mangled: a value this
/// function does not recognise is one it cannot honestly relabel, and an
/// unexpected token is more useful to a reader than a wrong word.
fn device_type_label(raw: &str) -> String {
    match raw {
        "smartphone" => "Smartphone".to_owned(),
        "other-mobile-phone" => "Mobile phone (other than a smartphone)".to_owned(),
        "cordless-phone" => "Cordless phone".to_owned(),
        "tablet" => "Slate tablet".to_owned(),
        other => other.to_owned(),
    }
}

pub(super) fn build_electronics_section(p: &serde_json::Value) -> String {
    let sd = match p.get("productGroupData") {
        Some(v) => v,
        None => return String::new(),
    };
    let category = device_type_label(str_field(sd, "productCategory", "-").as_str());
    let efficiency = str_field(sd, "energyEfficiencyClass", "-");
    let co2e = f64_field(sd, "co2ePerUnitKg", "Not disclosed", |v| {
        format!("{v:.2} kg CO\u{2082}e")
    });
    // `ElectronicsData::repairability_score` is a `RepairabilityScore` struct
    // (`{ overall, criteria }`), not a scalar — unlike furniture's, which really
    // is an `f64`. Reading it as a scalar always missed and rendered the dash, so
    // the public electronics page never showed a repairability score. The section
    // fixture asserted against a bare float, which is why no test caught it.
    let repair = sd
        .get("repairabilityScore")
        .and_then(|v| v.get("overall"))
        .and_then(serde_json::Value::as_f64)
        .map(|v| format!("{v:.1} / 10"))
        .unwrap_or_else(|| "-".to_owned());
    let lifetime = u64_field(sd, "expectedLifetimeYears", "-", |v| format!("{v} years"));
    format!(
        r#"<h2>Electronics Information</h2>
    <table aria-label="Electronics data">
      <tr><th scope="row">Product Category</th><td>{category}</td></tr>
      <tr><th scope="row">Energy Efficiency</th><td>{efficiency}</td></tr>
      <tr><th scope="row">Carbon Footprint</th><td>{co2e}</td></tr>
      <tr><th scope="row">Repairability Score</th><td>{repair}</td></tr>
      <tr><th scope="row">Expected Lifetime</th><td>{lifetime}</td></tr>
    </table>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_data_populates_all_fields() {
        let p = crate::sections::typed_fixture(serde_json::json!({
            "productGroup": "electronics",
            "gtin": "09506000134352",
            "productCategory": "smartphone",
            "energyEfficiencyClass": "A",
            "co2ePerUnitKg": 42.1,
            "repairabilityScore": { "overall": 7.5 },
            "expectedLifetimeYears": 5,
        }));
        let html = build_electronics_section(&p);
        assert!(html.contains("Smartphone"));
        assert!(html.contains(">A<"));
        assert!(html.contains("42.10 kg CO\u{2082}e"));
        assert!(html.contains("7.5 / 10"));
        assert!(html.contains("5 years"));
    }

    #[test]
    fn missing_co2e_reports_not_disclosed() {
        let p = serde_json::json!({"productGroupData": {}});
        let html = build_electronics_section(&p);
        assert!(html.contains("Not disclosed"));
        assert!(html.contains(">-<"));
    }

    #[test]
    fn absent_product_group_data_returns_empty_string() {
        let p = serde_json::json!({});
        assert_eq!(build_electronics_section(&p), "");
    }
}
