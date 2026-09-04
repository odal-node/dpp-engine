//! Parsers for the structured battery columns a flat CSV has to express.
//!
//! `fields.rs` holds the generic helpers every product group uses. These are
//! battery-specific and there are enough of them to be worth their own module:
//! four shapes, all following the `material_N_*` convention the bill of
//! materials already established, so an operator meets one idea rather than
//! four.
//!
//! - **Repeating groups** — `cathode_1_name`, `cathode_1_weightPct`, … A blank
//!   name ends the group, which is what lets a template ship empty trailing
//!   slots without them becoming empty entries.
//! - **Nested blocks** — `dynamicPerformance_ratedCapacityAh`, … one column per
//!   member, with the block omitted entirely when every member is blank.
//! - **A range** — `notInUseTemperatureMinC` / `…MaxC`, present only when both
//!   halves are.
//! - **A delimited list** — `componentPartNumbers`, semicolon-separated because
//!   the separator has to survive a spreadsheet writing the file back out as
//!   comma-delimited CSV.
//!
//! # Absence is not zero
//!
//! Every parser here returns `None` for a blank column rather than a default.
//! A `0.0` where the operator wrote nothing is a measurement they did not make,
//! and for these fields — recycled cobalt content, remaining capacity — an
//! invented zero is a false declaration rather than a harmless placeholder.

use std::collections::HashMap;

use dpp_domain::product_group::{
    BatteryStatus, CriticalRawMaterial, DynamicPerformance, HazardousSubstance,
    MaterialComposition, StateOfHealth, TemperatureRange,
};

use super::fields::{optional_f64, optional_str};
use super::request::RowError;

/// Maximum indexed slots read for any repeating group.
///
/// Ten matches `MAX_MATERIAL_COLUMNS` for the bill of materials, so the two
/// conventions do not differ in a way an operator has to remember.
const MAX_GROUP_SLOTS: usize = 10;

/// Build a `#[non_exhaustive]` core type from its own wire shape.
///
/// `TemperatureRange` and `HazardousSubstance` are marked `#[non_exhaustive]`
/// and carry neither a constructor nor `Default`, so a struct expression is
/// refused outside `dpp-domain` and this crate has no other way to make one.
/// Deserialization is the construction path the attribute leaves open, and it
/// is the same one every stored passport already travels.
///
/// The cost is that the field names become strings, so each caller is covered
/// by a test that would fail loudly on a typo rather than silently dropping the
/// value. A constructor in core would remove the need for this entirely, and is
/// the better fix — filed separately rather than blocking this behind a core
/// release and a repin.
fn non_exhaustive<T: serde::de::DeserializeOwned>(wire: &serde_json::Value) -> Option<T> {
    serde_json::from_value(wire.clone()).ok()
}

/// A blank-or-absent cell, treated identically. A spreadsheet writes an empty
/// string where a hand-made file omits the column, and neither is a value.
fn cell(row: &HashMap<String, String>, name: &str) -> Option<String> {
    optional_str(row, name).filter(|v| !v.trim().is_empty())
}

/// `u32` from a column, ignoring a blank or unparseable one.
pub(super) fn optional_u32(row: &HashMap<String, String>, name: &str) -> Option<u32> {
    cell(row, name).and_then(|v| v.trim().parse::<u32>().ok())
}

/// Parse `<prefix>_N_name` / `_weightPct` / `_casNumber` into a composition.
///
/// `weightPct` is required by the type, so a slot whose weight is missing or
/// unparseable is skipped rather than defaulted to zero — a component declared
/// to be 0% of the cell is a claim, and a silent one.
pub(super) fn parse_composition(
    row: &HashMap<String, String>,
    prefix: &str,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<Vec<MaterialComposition>> {
    let mut out = Vec::new();
    for i in 1..=MAX_GROUP_SLOTS {
        let Some(name) = cell(row, &format!("{prefix}_{i}_name")) else {
            continue;
        };
        let Some(weight_pct) =
            optional_f64(row, &format!("{prefix}_{i}_weightPct"), row_num, errors)
        else {
            continue;
        };
        out.push(MaterialComposition {
            name,
            weight_pct,
            cas_number: cell(row, &format!("{prefix}_{i}_casNumber")),
        });
    }
    (!out.is_empty()).then_some(out)
}

/// Parse `criticalRaw_N_*` into the critical raw materials list.
pub(super) fn parse_critical_raw_materials(
    row: &HashMap<String, String>,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<Vec<CriticalRawMaterial>> {
    let mut out = Vec::new();
    for i in 1..=MAX_GROUP_SLOTS {
        let Some(name) = cell(row, &format!("criticalRaw_{i}_name")) else {
            continue;
        };
        out.push(CriticalRawMaterial {
            name,
            cas_number: cell(row, &format!("criticalRaw_{i}_casNumber")),
            weight_grams: optional_f64(
                row,
                &format!("criticalRaw_{i}_weightGrams"),
                row_num,
                errors,
            ),
            country_of_origin: cell(row, &format!("criticalRaw_{i}_countryOfOrigin")),
        });
    }
    (!out.is_empty()).then_some(out)
}

/// Parse `hazardous_N_*` into the hazardous substances list.
pub(super) fn parse_hazardous_substances(
    row: &HashMap<String, String>,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<Vec<HazardousSubstance>> {
    let mut out = Vec::new();
    for i in 1..=MAX_GROUP_SLOTS {
        let Some(name) = cell(row, &format!("hazardous_{i}_name")) else {
            continue;
        };
        let concentration_pct = optional_f64(
            row,
            &format!("hazardous_{i}_concentrationPct"),
            row_num,
            errors,
        );
        out.push(non_exhaustive(&serde_json::json!({
            "name": name,
            "casNumber": cell(row, &format!("hazardous_{i}_casNumber")),
            "concentrationPct": concentration_pct,
        }))?);
    }
    (!out.is_empty()).then_some(out)
}

/// Parse the not-in-use temperature range.
///
/// Both halves or neither: a range with one bound is not a range, and guessing
/// the other end would invent an operating limit.
pub(super) fn parse_temperature_range(
    row: &HashMap<String, String>,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<TemperatureRange> {
    let min_c = optional_f64(row, "notInUseTemperatureMinC", row_num, errors)?;
    let max_c = optional_f64(row, "notInUseTemperatureMaxC", row_num, errors)?;
    non_exhaustive(&serde_json::json!({ "minC": min_c, "maxC": max_c }))
}

/// Parse the semicolon-separated component part numbers.
pub(super) fn parse_component_part_numbers(row: &HashMap<String, String>) -> Option<Vec<String>> {
    let raw = cell(row, "componentPartNumbers")?;
    let parts: Vec<String> = raw
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    (!parts.is_empty()).then_some(parts)
}

/// Parse the `dynamicPerformance_*` block.
///
/// Omitted entirely when every member is blank, rather than emitted as a block
/// of `None`s: a present-but-empty `dynamicPerformance` would satisfy the
/// publish gate's presence check while carrying no data, which is worse than
/// its absence because the gate would stop asking.
pub(super) fn parse_dynamic_performance(
    row: &HashMap<String, String>,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Option<Box<DynamicPerformance>> {
    // A closure would borrow `errors` mutably for the whole block, so each
    // member reads through this instead.
    macro_rules! f {
        ($name:literal) => {
            optional_f64(row, concat!("dynamicPerformance_", $name), row_num, errors)
        };
    }
    // `Default` then assignment, because the struct is `#[non_exhaustive]` and a
    // struct expression — including one ending `..Default::default()` — is
    // refused outside `dpp-domain`. The fields are public, so this is the same
    // result by the route the attribute leaves open.
    let mut block = DynamicPerformance::default();
    block.rated_capacity_ah = f!("ratedCapacityAh");
    block.capacity_fade_pct = f!("capacityFadePct");
    block.power_w = f!("powerW");
    block.power_fade_pct = f!("powerFadePct");
    block.internal_resistance_mohm = f!("internalResistanceMohm");
    block.internal_resistance_increase_pct = f!("internalResistanceIncreasePct");
    block.round_trip_efficiency_pct = f!("roundTripEfficiencyPct");
    block.round_trip_efficiency_fade_pct = f!("roundTripEfficiencyFadePct");
    block.expected_lifetime_cycles = optional_u32(row, "dynamicPerformance_expectedLifetimeCycles");
    block.expected_lifetime_years = f!("expectedLifetimeYears");

    let empty = block.rated_capacity_ah.is_none()
        && block.capacity_fade_pct.is_none()
        && block.power_w.is_none()
        && block.power_fade_pct.is_none()
        && block.internal_resistance_mohm.is_none()
        && block.internal_resistance_increase_pct.is_none()
        && block.round_trip_efficiency_pct.is_none()
        && block.round_trip_efficiency_fade_pct.is_none()
        && block.expected_lifetime_cycles.is_none()
        && block.expected_lifetime_years.is_none();
    (!empty).then(|| Box::new(block))
}

/// Parse the `stateOfHealth_*` block into whichever Annex VII Part A list the
/// row carries.
///
/// The two lists are disjoint in the annex — an EV battery reports state of
/// certified energy and nothing else, a stationary or LMT one reports a
/// five-parameter list — and `StateOfHealth` is a sum type for exactly that
/// reason. So the column that is present decides the variant, and a row
/// carrying columns from both is refused rather than silently resolved: it
/// describes a battery the annex does not permit, and picking one for the
/// operator would hide that.
pub(super) fn parse_state_of_health(
    row: &HashMap<String, String>,
    row_num: usize,
    errors: &mut Vec<RowError>,
) -> Result<Option<Box<StateOfHealth>>, &'static str> {
    let soce = optional_f64(row, "stateOfHealth_socePct", row_num, errors);
    let remaining_capacity =
        optional_f64(row, "stateOfHealth_remainingCapacityPct", row_num, errors);
    let self_discharge = optional_f64(
        row,
        "stateOfHealth_selfDischargeRatePctPerMonth",
        row_num,
        errors,
    );

    match (soce, remaining_capacity.or(self_discharge)) {
        (Some(_), Some(_)) => Err(
            "stateOfHealth carries both the electric-vehicle parameter (socePct) and the \
             stationary/LMT ones. Annex VII Part A lists these as alternatives, so a battery \
             reports one set or the other — fill only the columns for this battery's category.",
        ),
        (Some(soce_pct), None) => Ok(Some(Box::new(StateOfHealth::ElectricVehicle { soce_pct }))),
        (None, Some(_)) => {
            // Items 1 and 4 are unconditional in the annex; without them the
            // list is not the list, so the block is refused rather than filled
            // with a guess.
            let (Some(remaining_capacity_pct), Some(self_discharge_rate_pct_per_month)) =
                (remaining_capacity, self_discharge)
            else {
                return Err("stateOfHealth for a stationary or LMT battery needs both \
                     remainingCapacityPct and selfDischargeRatePctPerMonth — Annex VII Part A \
                     lists items 1 and 4 unconditionally, unlike items 2, 3 and 5.");
            };
            Ok(Some(Box::new(StateOfHealth::StationaryOrLmt {
                remaining_capacity_pct,
                remaining_power_capability_pct: optional_f64(
                    row,
                    "stateOfHealth_remainingPowerCapabilityPct",
                    row_num,
                    errors,
                ),
                remaining_round_trip_efficiency_pct: optional_f64(
                    row,
                    "stateOfHealth_remainingRoundTripEfficiencyPct",
                    row_num,
                    errors,
                ),
                self_discharge_rate_pct_per_month,
                ohmic_resistance_mohm: optional_f64(
                    row,
                    "stateOfHealth_ohmicResistanceMohm",
                    row_num,
                    errors,
                ),
            })))
        }
        (None, None) => Ok(None),
    }
}

/// Parse the battery status, defaulting to nothing rather than to `original`.
///
/// A repurposed battery imported with a blank status would be published as
/// original, which is a claim about the product's history that the operator did
/// not make.
pub(super) fn parse_battery_status(row: &HashMap<String, String>) -> Option<BatteryStatus> {
    let raw = cell(row, "batteryStatus")?;
    let normalised = raw.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalised.as_str() {
        "original" => Some(BatteryStatus::Original),
        "repurposed" => Some(BatteryStatus::Repurposed),
        "re_used" | "reused" => Some(BatteryStatus::ReUsed),
        "remanufactured" => Some(BatteryStatus::Remanufactured),
        "waste" => Some(BatteryStatus::Waste),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Most of these tests do not care about parse errors, only about the value
    /// that comes back. `errs` gives them a sink to pass without repeating it.
    fn errs() -> Vec<RowError> {
        Vec::new()
    }

    fn row(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn a_repeating_group_stops_at_the_first_blank_name_but_reads_later_slots() {
        let r = row(&[
            ("cathode_1_name", "LFP"),
            ("cathode_1_weightPct", "94.0"),
            ("cathode_1_casNumber", "15365-14-7"),
            ("cathode_3_name", "Binder"),
            ("cathode_3_weightPct", "6.0"),
        ]);
        let out = parse_composition(&r, "cathode", 1, &mut errs()).expect("two entries");
        assert_eq!(
            out.len(),
            2,
            "a gap in the numbering does not end the group"
        );
        assert_eq!(out[0].name, "LFP");
        assert_eq!(out[1].weight_pct, 6.0);
        assert_eq!(out[1].cas_number, None);
    }

    /// A component with no weight is skipped, not defaulted to zero — the type
    /// requires the number, and inventing one declares a composition.
    #[test]
    fn a_component_without_a_weight_is_skipped_rather_than_zeroed() {
        let r = row(&[("cathode_1_name", "LFP")]);
        assert!(parse_composition(&r, "cathode", 1, &mut errs()).is_none());
    }

    #[test]
    fn a_temperature_range_needs_both_bounds() {
        assert!(
            parse_temperature_range(&row(&[("notInUseTemperatureMinC", "-20")]), 1, &mut errs())
                .is_none()
        );
        let both = parse_temperature_range(
            &row(&[
                ("notInUseTemperatureMinC", "-20"),
                ("notInUseTemperatureMaxC", "45"),
            ]),
            1,
            &mut errs(),
        )
        .expect("range");
        assert_eq!((both.min_c, both.max_c), (-20.0, 45.0));
    }

    #[test]
    fn component_part_numbers_split_on_semicolons_and_drop_blanks() {
        let out = parse_component_part_numbers(&row(&[("componentPartNumbers", "A-1; B-2 ;;C-3")]))
            .expect("parts");
        assert_eq!(out, vec!["A-1", "B-2", "C-3"]);
        assert!(parse_component_part_numbers(&row(&[("componentPartNumbers", " ; ")])).is_none());
    }

    #[test]
    fn an_all_blank_dynamic_performance_block_is_absent_rather_than_empty() {
        assert!(parse_dynamic_performance(&row(&[]), 1, &mut errs()).is_none());
        let some = parse_dynamic_performance(
            &row(&[("dynamicPerformance_powerW", "4800")]),
            1,
            &mut errs(),
        )
        .expect("block");
        assert_eq!(some.power_w, Some(4800.0));
        assert_eq!(some.capacity_fade_pct, None);
    }

    /// The two Annex VII Part A lists are alternatives, and a row carrying both
    /// describes a battery the annex does not permit.
    #[test]
    fn state_of_health_refuses_both_parameter_sets_at_once() {
        let r = row(&[
            ("stateOfHealth_socePct", "98.5"),
            ("stateOfHealth_remainingCapacityPct", "98.0"),
            ("stateOfHealth_selfDischargeRatePctPerMonth", "1.5"),
        ]);
        assert!(parse_state_of_health(&r, 1, &mut errs()).is_err());
    }

    #[test]
    fn state_of_health_picks_the_variant_the_row_carries() {
        let ev = parse_state_of_health(&row(&[("stateOfHealth_socePct", "98.5")]), 1, &mut errs())
            .expect("ok")
            .expect("present");
        assert!(matches!(*ev, StateOfHealth::ElectricVehicle { soce_pct } if soce_pct == 98.5));

        let stationary = parse_state_of_health(
            &row(&[
                ("stateOfHealth_remainingCapacityPct", "98.0"),
                ("stateOfHealth_selfDischargeRatePctPerMonth", "1.5"),
                ("stateOfHealth_ohmicResistanceMohm", "14.0"),
            ]),
            1,
            &mut errs(),
        )
        .expect("ok")
        .expect("present");
        match *stationary {
            StateOfHealth::StationaryOrLmt {
                remaining_capacity_pct,
                ohmic_resistance_mohm,
                remaining_power_capability_pct,
                ..
            } => {
                assert_eq!(remaining_capacity_pct, 98.0);
                assert_eq!(ohmic_resistance_mohm, Some(14.0));
                assert_eq!(
                    remaining_power_capability_pct, None,
                    "an item the annex qualifies `where possible` stays absent"
                );
            }
            StateOfHealth::ElectricVehicle { .. } => panic!("wrong variant"),
        }
    }

    /// Items 1 and 4 are unconditional; a partial list is refused rather than
    /// completed with a guess.
    #[test]
    fn a_stationary_state_of_health_missing_an_unconditional_item_is_refused() {
        let r = row(&[("stateOfHealth_remainingCapacityPct", "98.0")]);
        assert!(parse_state_of_health(&r, 1, &mut errs()).is_err());
    }

    #[test]
    fn a_blank_battery_status_is_absent_rather_than_original() {
        assert!(parse_battery_status(&row(&[("batteryStatus", "  ")])).is_none());
        assert_eq!(
            parse_battery_status(&row(&[("batteryStatus", "Re-Used")])),
            Some(BatteryStatus::ReUsed)
        );
    }
}
