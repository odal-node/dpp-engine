//! End-to-end checks for the Art. 8 determination, host-side.
//!
//! These are the first tests in this repository that exercise a `dpp-calc`
//! calculator at all. Until this strategy existed, `calcReceipts` in the
//! evidence dossier was documented as "always empty in v1" and there was nothing
//! that could have filled it.

use chrono::NaiveDate;

use dpp_domain::Gtin;
use dpp_domain::domain::product_group::{
    BatteryChemistry, BatteryData, BatteryType, ProductGroupData, TextileData,
};
use dpp_domain::ports::compliance::{ComplianceErrorKind, ComplianceStatus, ComplianceStrategy};

use super::CalcBatteryStrategy;

fn day(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).expect("valid date")
}

/// An EV battery whose declared shares clear Art. 8(2) and fail Art. 8(3).
fn ev_battery() -> ProductGroupData {
    ProductGroupData::Battery(Box::new(BatteryData {
        gtin: Gtin::parse("09506000134352").expect("valid gtin"),
        battery_chemistry: BatteryChemistry::Nmc,
        battery_type: BatteryType::Ev,
        nominal_voltage_v: 400.0,
        nominal_capacity_ah: 200.0,
        co2e_per_unit_kg: 5100.0,
        rated_capacity_kwh: Some(80.0),
        recycled_content_cobalt_pct: Some(16.0),
        recycled_content_lithium_pct: Some(6.0),
        recycled_content_nickel_pct: Some(6.0),
        ..battery_defaults()
    }))
}

/// Everything else on `BatteryData`, which is `Default` for none of it.
fn battery_defaults() -> BatteryData {
    serde_json::from_value(serde_json::json!({
        "gtin": "09506000134352",
        "batteryChemistry": "NMC",
        "batteryType": "ev",
        "nominalVoltageV": 400.0,
        "nominalCapacityAh": 200.0,
        "co2ePerUnitKg": 5100.0
    }))
    .expect("a minimal battery deserialises")
}

fn shortfall_codes(r: &dpp_domain::ports::compliance::ComplianceResult) -> Vec<&str> {
    r.warnings.iter().map(|w| w.code.as_str()).collect()
}

/// The headline: a determination that carries a receipt.
///
/// Every field here was structurally unreachable before — `ruleset_version`,
/// `assessed_at` and `receipt` on `ComplianceResult` existed and nothing ever
/// populated them.
#[test]
fn a_2036_battery_gets_a_determination_with_a_receipt() {
    let result = CalcBatteryStrategy
        .compute(&ev_battery(), Some(day(2036, 8, 18)))
        .expect("battery data");

    assert_eq!(
        result.ruleset_version.as_deref(),
        Some("battery-recycled-content-art8-3@1.0.0"),
        "the determination must name the ruleset that produced it"
    );
    assert!(result.assessed_at.is_some());

    let receipt = result.receipt.as_ref().expect("a receipt must be attached");
    assert_eq!(receipt["rulesetId"], "battery-recycled-content-art8-3");
    assert_eq!(receipt["assessedAsOf"], "2036-08-18");
    assert!(
        receipt["inputHash"].as_str().is_some_and(|h| !h.is_empty()),
        "the receipt must bind the inputs it was computed from"
    );

    let codes = shortfall_codes(&result);
    assert!(
        codes.contains(&"battery.recycled_content.cobalt_below_minimum"),
        "16% cobalt is below the 26% Art. 8(3) minimum: {codes:?}"
    );

    // Still not a pass/fail claim: Art. 8 shortfalls are advisory here, and the
    // overall status stays what passthrough set.
    assert_eq!(
        result.compliance_status,
        ComplianceStatus::PassthroughNoValidation
    );
}

/// The same battery, placed on the market five years earlier, is compliant —
/// and the receipt cites the earlier phase.
#[test]
fn the_governing_phase_follows_the_market_date_not_the_clock() {
    let result = CalcBatteryStrategy
        .compute(&ev_battery(), Some(day(2032, 1, 1)))
        .expect("battery data");

    assert_eq!(
        result.ruleset_version.as_deref(),
        Some("battery-recycled-content-art8-2@1.0.0")
    );
    assert!(
        shortfall_codes(&result).is_empty(),
        "these shares meet the Art. 8(2) minima: {:?}",
        shortfall_codes(&result)
    );
}

/// Placed on the market before any phase binds: told the next deadline, not
/// reported as short.
#[test]
fn a_battery_placed_before_2031_is_told_when_the_duty_starts() {
    let result = CalcBatteryStrategy
        .compute(&ev_battery(), Some(day(2026, 6, 1)))
        .expect("battery data");

    let codes = shortfall_codes(&result);
    assert!(
        codes.contains(&"battery.recycled_content.not_yet_binding"),
        "{codes:?}"
    );
    assert!(
        result.receipt.is_none(),
        "no determination ran, so there is no receipt to show for one"
    );
}

/// No market date means no phase, and the node declines to pick one.
///
/// This is the case that produces retroactively wrong findings if it defaults
/// to "today" — from 18 Aug 2031 every undated battery would silently acquire
/// the Art. 8(2) minima.
#[test]
fn a_missing_market_date_is_reported_rather_than_guessed() {
    let result = CalcBatteryStrategy
        .compute(&ev_battery(), None)
        .expect("battery data");

    assert!(
        shortfall_codes(&result).contains(&"battery.recycled_content.market_date_missing"),
        "{:?}",
        shortfall_codes(&result)
    );
    assert!(result.receipt.is_none());
}

/// An LFP cell contains no cobalt or nickel, so a declared share for either is
/// not measured against a minimum it cannot have.
#[test]
fn shares_are_scoped_to_the_metals_the_chemistry_contains() {
    let ProductGroupData::Battery(mut b) = ev_battery() else {
        unreachable!()
    };
    b.battery_chemistry = BatteryChemistry::Lfp;
    // Deliberately contradictory declarations, well below the 2036 minima.
    b.recycled_content_cobalt_pct = Some(1.0);
    b.recycled_content_nickel_pct = Some(1.0);
    b.recycled_content_lithium_pct = Some(12.0);

    let result = CalcBatteryStrategy
        .compute(&ProductGroupData::Battery(b), Some(day(2036, 8, 18)))
        .expect("battery data");

    let codes = shortfall_codes(&result);
    assert!(
        !codes.contains(&"battery.recycled_content.cobalt_below_minimum")
            && !codes.contains(&"battery.recycled_content.nickel_below_minimum"),
        "an LFP cell has neither metal: {codes:?}"
    );
}

/// Portable batteries are outside Art. 8 entirely — no finding, no receipt.
#[test]
fn a_portable_battery_is_outside_art8() {
    let ProductGroupData::Battery(mut b) = ev_battery() else {
        unreachable!()
    };
    b.battery_type = BatteryType::Portable;

    let result = CalcBatteryStrategy
        .compute(&ProductGroupData::Battery(b), Some(day(2036, 8, 18)))
        .expect("battery data");

    assert!(shortfall_codes(&result).is_empty(), "{result:?}");
    assert!(result.receipt.is_none());
}

/// The declared CO₂e still comes through — this strategy adds to the
/// passthrough's answer rather than replacing it.
#[test]
fn the_declared_metrics_are_still_lifted() {
    let result = CalcBatteryStrategy
        .compute(&ev_battery(), Some(day(2036, 8, 18)))
        .expect("battery data");
    assert_eq!(result.co2e_score, Some(5100.0));
    assert!(
        result.recycled_content_pct.is_none(),
        "four per-metal shares still do not become one number"
    );
}

/// A routing mistake is reportable, not fatal.
#[test]
fn another_product_groups_data_is_refused() {
    let textile = ProductGroupData::Textile(Box::new(
        serde_json::from_value::<TextileData>(serde_json::json!({
            "gtin": "09506000134352",
            "fibreComposition": [{"fibre": "cotton", "pct": 100.0}],
            "countryOfOrigin": "PT",
            "careInstructions": "cold wash",
            "chemicalComplianceStandard": "OEKO-TEX 100"
        }))
        .expect("a minimal textile deserialises"),
    ));

    let err = CalcBatteryStrategy
        .compute(&textile, Some(day(2036, 8, 18)))
        .expect_err("must refuse textile data");
    assert_eq!(err.kind, ComplianceErrorKind::InvalidInput);
}
