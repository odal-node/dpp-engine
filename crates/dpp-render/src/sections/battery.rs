//! Battery sector HTML section.

use crate::esc::esc;

pub(super) fn build_battery_section(p: &serde_json::Value) -> String {
    let sd = match p.get("sectorData") {
        Some(v) => v,
        None => return String::new(),
    };

    let chemistry = esc(sd
        .get("batteryChemistry")
        .and_then(|v| v.as_str())
        .unwrap_or("-"));
    let voltage = sd
        .get("nominalVoltageV")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1} V"))
        .unwrap_or_else(|| "-".into());
    let capacity = sd
        .get("nominalCapacityAh")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1} Ah"))
        .unwrap_or_else(|| "-".into());
    let cycles = sd
        .get("expectedLifetimeCycles")
        .and_then(|v| v.as_u64())
        .map(|v| format!("{v}"))
        .unwrap_or_else(|| "-".into());
    let co2e = sd
        .get("co2ePerUnitKg")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.2} kg CO\u{2082}e"))
        .unwrap_or_else(|| "Not disclosed".into());
    let recycled_co = sd
        .get("recycledContentCobaltPct")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".into());
    let recycled_li = sd
        .get("recycledContentLithiumPct")
        .and_then(|v| v.as_f64())
        .map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "-".into());

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
