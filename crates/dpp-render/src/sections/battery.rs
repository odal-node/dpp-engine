//! Battery sector HTML section.

use crate::fields::{f64_field, str_field, u64_field};

pub(super) fn build_battery_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };

    let chemistry = str_field(sd, "batteryChemistry", "-");
    let voltage = f64_field(sd, "nominalVoltageV", "-", |v| format!("{v:.1} V"));
    let capacity = f64_field(sd, "nominalCapacityAh", "-", |v| format!("{v:.1} Ah"));
    let cycles = u64_field(sd, "expectedLifetimeCycles", "-", |v| format!("{v}"));
    let co2e = f64_field(sd, "co2ePerUnitKg", "Not disclosed", |v| {
        format!("{v:.2} kg CO\u{2082}e")
    });
    let recycled_co = f64_field(sd, "recycledContentCobaltPct", "-", |v| format!("{v:.1}%"));
    let recycled_li = f64_field(sd, "recycledContentLithiumPct", "-", |v| format!("{v:.1}%"));

    format!(
        r#"<h2>Battery Information</h2>
    <table aria-label="Battery data">
      <tr><th scope="row">Chemistry</th><td>{chemistry}</td></tr>
      <tr><th scope="row">Nominal Voltage</th><td>{voltage}</td></tr>
      <tr><th scope="row">Nominal Capacity</th><td>{capacity}</td></tr>
      <tr><th scope="row">Expected Lifetime</th><td>{cycles} cycles</td></tr>
      <tr><th scope="row">Carbon Footprint</th><td>{co2e}</td></tr>
      <tr><th scope="row">Recycled Cobalt</th><td>{recycled_co}</td></tr>
      <tr><th scope="row">Recycled Lithium</th><td>{recycled_li}</td></tr>
    </table>"#
    )
}
