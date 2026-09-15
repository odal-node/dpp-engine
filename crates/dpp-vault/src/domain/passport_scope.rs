//! Which batteries Art. 77(1) actually requires a passport for.
//!
//! **The rule is `dpp_rules::batteries::passport_scope` and is not restated
//! here.** This module used to carry its own copy — the categories, the 2 kWh
//! threshold, the fail-closed reading of an undeclared capacity — under a note
//! saying it was a core candidate parked here "so the two repositories are not
//! edited in the same breath". Core now owns it, so the copy is gone.
//!
//! Two copies of a regulatory rule is the hazard, not the duplication itself.
//! They had already drifted: core answers five outcomes where this answered
//! three, and core reads the **date** the article turns on where this did not —
//! so a battery placed on the market before the article binds was reported as in
//! scope by this node and out of scope by the rule it was supposed to mirror.
//!
//! # What this module still decides
//!
//! Three things core's function cannot, because it takes a battery type, a
//! capacity and a date:
//!
//! 1. **Whether the record is a battery at all.** `None` is not an exemption —
//!    Art. 77(1) is a battery article and says nothing about anything else.
//! 2. **Which date to hand it**, including what an absent `placedOnMarketDate`
//!    means. See [`scope_of`].
//! 3. **Whether this node's content gate runs** ([`gate_applies`]) and **what to
//!    tell an operator** ([`scope_note`]). Both are deployment decisions rather
//!    than readings of the article, which is why they live on this side.
//!
//! # Not `dpp_domain::instrument::PassportObligation`
//!
//! Core has a type with a similar name, and they answer different questions at
//! different granularities. Keeping them apart is the point of the name here.
//!
//! - [`PassportObligation`](dpp_domain::instrument::PassportObligation) is about
//!   an **act and a product group**: does Reg. (EU) 2023/1542 require a passport
//!   for batteries at all, and from when. Its answers are `Required`,
//!   `NotRequired` and `DisplacedBy`.
//! - [`PassportScope`] is about **one record**: given that the obligation
//!   exists, does Art. 77(1) reach *this* battery, whose type, capacity and
//!   placing date decide it.
//!
//! They compose rather than compete — core says the duty exists for batteries
//! from 18 February 2027, and this says a portable one is not inside it. Naming
//! both "obligation" would have made a reader assume one was the other, which is
//! the same two-names-one-concept mistake the `sector`/`productGroup` rename was
//! paid for.
//!
//! # The node is stricter than the article, and says so
//!
//! A passport outside Art. 77(1) is still held to the category content gate:
//! `check_mandatory_content` runs inside `Passport::transition_to` on first
//! publish, and this node calls that and cannot skip it. So an industrial
//! battery at or below 2 kWh is asked for content the article exempts.
//!
//! That is reported rather than hidden — [`scope_note`] admits it — and it is
//! the half of engine issue #238 that stays open, because narrowing the gate to
//! the article's scope is core's change to make.

use chrono::Datelike as _;
use dpp_domain::passport::Passport;
use dpp_domain::product_group::{BatteryType, ProductGroupData};
use dpp_rules::batteries::passport_scope::{PASSPORT_REQUIRED_FROM, PassportScope};
use dpp_rules::common::date::CalendarDate;

/// Apply Art. 77(1) to a passport. `None` when the record is not a battery.
///
/// The rule itself is `dpp_rules::batteries::passport_scope` and is **not**
/// restated here. This function decides only the two things core cannot: whether
/// the record is a battery at all, and which date to hand it.
///
/// # The date, and what an absent one means
///
/// Art. 77(1) binds batteries placed on the market **from 18 February 2027**, so
/// the answer depends on a date, and `placedOnMarketDate` is optional on the
/// record. An absent date is read as *inside* the binding period rather than
/// before it.
///
/// That is the same fail-closed direction the capacity question takes, and for
/// the same reason. Reading an absent date as "before 2027" would report
/// `notYetBinding` for a draft being prepared today for a product that will be
/// placed on the market after the date — telling an operator they owe nothing,
/// on the strength of a field they simply have not filled in yet. Reading it as
/// inside the period asks for content they may not owe, which is friction they
/// can end by stating the date.
#[must_use]
pub fn scope_of(passport: &Passport) -> Option<PassportScope> {
    let Some(ProductGroupData::Battery(battery)) = passport.product_group_data.as_ref() else {
        return None;
    };
    let placed = passport
        .placed_on_market_date
        .map_or(PASSPORT_REQUIRED_FROM, |d| {
            CalendarDate::new(d.year(), d.month() as u8, d.day() as u8)
        });
    Some(dpp_rules::batteries::passport_scope::passport_scope(
        battery.battery_type.wire_str(),
        battery.rated_capacity_kwh,
        placed,
    ))
}

/// Whether this node should hold the record to the passport-content gate.
///
/// Wider than core's [`PassportScope::is_required`], deliberately. That answers
/// "is a passport owed **now**, on this answer alone", which is `Required` and
/// nothing else. This answers a different question — should the gate run — and
/// an undetermined answer must not switch it off: the obligation turns on a
/// capacity the record did not state, and exempting on a missing field is the
/// one error that silently stops asking for content the law requires.
#[must_use]
pub fn gate_applies(scope: Option<PassportScope>) -> bool {
    match scope {
        None => false,
        Some(s) => s.is_required() || s.is_undetermined(),
    }
}

/// Every wire value [`wire_status`] can return.
///
/// Exists because `status` crosses the API as a plain string, so neither the
/// Rust type system nor the OpenAPI enum gate — which can only enumerate a Rust
/// enum — connects the two. A stale value survived exactly that gap once: the
/// contract fixture went on emitting `"voluntary"` after this module stopped
/// producing it, and every check passed.
///
/// `every_passport_scope_status_is_in_the_schema` in the contract suite asserts
/// this list against the published enum.
pub const ALL_WIRE_STATUSES: &[&str] = &[
    "required",
    "notCovered",
    "belowThreshold",
    "capacityUnknown",
    "notYetBinding",
    "notApplicable",
];

/// The wire value for [`PassportScopeReport`](crate::handlers::lint::PassportScopeReport).
///
/// Core's vocabulary, one-for-one, plus `notApplicable` for a record that is not
/// a battery — which core's function cannot answer because it takes a battery
/// type. Collapsing core's five into fewer would put a translation layer back
/// between the rule and the answer, which is the thing this module stopped
/// doing.
#[must_use]
pub fn wire_status(scope: Option<PassportScope>) -> &'static str {
    let Some(scope) = scope else {
        return "notApplicable";
    };
    match scope {
        PassportScope::Required => "required",
        PassportScope::NotCovered => "notCovered",
        PassportScope::BelowThreshold => "belowThreshold",
        PassportScope::CapacityUnknown => "capacityUnknown",
        PassportScope::NotYetBinding => "notYetBinding",
        // `PassportScope` is `#[non_exhaustive]`, so a newer `dpp-rules` can add
        // an outcome this build has never heard of. Reported as in scope and
        // said out loud, for the same reason an undeclared capacity is: a
        // variant this build cannot name is not evidence of an exemption, and
        // absorbing it silently is how a statutory gate switches itself off.
        other => {
            tracing::warn!(
                scope = ?other,
                "Art. 77(1) outcome not recognised by this build; reporting it as in scope"
            );
            "required"
        }
    }
}

/// A sentence for a caller who is about to be asked for mandatory content, or
/// who is publishing something the law does not require.
///
/// Returned alongside the readiness gates rather than instead of them: this node
/// applies core's content gate whatever this says, and pretending otherwise
/// would be the more confusing answer.
#[must_use]
pub fn scope_note(scope: Option<PassportScope>, data: Option<&ProductGroupData>) -> Option<String> {
    let Some(ProductGroupData::Battery(battery)) = data else {
        return None;
    };
    let kind = match &battery.battery_type {
        BatteryType::Portable => "portable",
        BatteryType::Sli => "starting, lighting and ignition",
        _ => "battery",
    };
    match scope? {
        PassportScope::Required => None,
        PassportScope::CapacityUnknown => Some(
            "Art. 77(1) requires a battery passport for an industrial battery with a capacity \
             greater than 2 kWh. This record does not declare `ratedCapacityKwh`, so it is \
             treated as in scope: an undeclared capacity is not evidence of a small one. \
             Declaring a capacity of 2 kWh or less would put it outside the article."
                .to_owned(),
        ),
        PassportScope::NotCovered => Some(format!(
            "Art. 77(1) requires a battery passport for LMT, electric-vehicle and industrial \
             batteries above 2 kWh. A {kind} battery is outside it, so this passport is \
             voluntary — publishing one is allowed and discharges no duty under that article."
        )),
        PassportScope::BelowThreshold => Some(
            "Art. 77(1) reaches industrial batteries with a capacity greater than 2 kWh. This \
             one declares 2 kWh or less, so its passport is voluntary. Note that this node \
             still applies the category content gate, which is stricter than the article \
             requires here."
                .to_owned(),
        ),
        PassportScope::NotYetBinding => Some(
            "Art. 77(1) applies to batteries placed on the market from 18 February 2027. This \
             record declares an earlier `placedOnMarketDate`, so the article does not reach it \
             and its passport is voluntary. A record that states no date at all is treated as \
             inside the period instead, because an unstated date is not evidence of an earlier \
             one."
                .to_owned(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpp_domain::product_group::{BatteryChemistry, BatteryData};

    /// Comfortably inside the binding period, so a case about type or capacity
    /// is not silently also a case about the date.
    fn in_period() -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(2030, 1, 1).expect("a real date")
    }

    fn passport_of(data: Option<ProductGroupData>, placed: Option<chrono::NaiveDate>) -> Passport {
        let mut p = crate::public_view::tests::stub_passport();
        p.product_group_data = data;
        p.placed_on_market_date = placed;
        p
    }

    fn battery_data(
        battery_type: BatteryType,
        rated_capacity_kwh: Option<f64>,
    ) -> ProductGroupData {
        let mut data = minimal_battery();
        data.battery_type = battery_type;
        data.rated_capacity_kwh = rated_capacity_kwh;
        ProductGroupData::Battery(Box::new(data))
    }

    fn scope(battery_type: BatteryType, rated_capacity_kwh: Option<f64>) -> Option<PassportScope> {
        scope_of(&passport_of(
            Some(battery_data(battery_type, rated_capacity_kwh)),
            Some(in_period()),
        ))
    }

    /// A `BatteryData` with only the fields this rule reads. Every other field
    /// is irrelevant to Art. 77(1) and is left at its empty value.
    fn minimal_battery() -> BatteryData {
        serde_json::from_value(serde_json::json!({
            "productGroup": "battery",
            "gtin": "09506000134352",
            "batteryChemistry": "LFP",
            "batteryType": "ev",
            "nominalVoltageV": 48.0,
            "nominalCapacityAh": 100.0,
            "co2ePerUnitKg": 85.4,
        }))
        .expect("a minimal battery deserialises")
    }

    /// The two categories the article names without qualification.
    #[test]
    fn lmt_and_electric_vehicle_batteries_always_carry_the_obligation() {
        for t in [BatteryType::Lmt, BatteryType::Ev] {
            for capacity in [None, Some(0.5), Some(2.0), Some(100.0)] {
                assert_eq!(
                    scope(t.clone(), capacity),
                    Some(PassportScope::Required),
                    "{t:?} at {capacity:?} kWh is named by Art. 77(1) with no threshold"
                );
            }
        }
    }

    /// The two the article does not reach at all — and `NotCovered` rather than
    /// a shared "voluntary", because "this category never owes one" is a
    /// different sentence from "this unit is under the threshold".
    #[test]
    fn portable_and_sli_batteries_never_carry_the_obligation() {
        for t in [BatteryType::Portable, BatteryType::Sli] {
            for capacity in [None, Some(0.5), Some(500.0)] {
                assert_eq!(
                    scope(t.clone(), capacity),
                    Some(PassportScope::NotCovered),
                    "{t:?} is outside Art. 77(1) at any capacity"
                );
            }
        }
    }

    /// "Greater than 2 kWh" — so exactly 2 kWh is out, and the boundary is the
    /// one thing a threshold gets wrong.
    #[test]
    fn the_industrial_threshold_is_strictly_greater_than_two_kwh() {
        let at = |kwh: f64| scope(BatteryType::Industrial, Some(kwh));
        assert_eq!(at(1.999), Some(PassportScope::BelowThreshold));
        assert_eq!(
            at(2.0),
            Some(PassportScope::BelowThreshold),
            "the article says *greater than* 2 kWh, so 2.0 is outside it"
        );
        assert_eq!(at(2.001), Some(PassportScope::Required));
        assert_eq!(at(64.0), Some(PassportScope::Required));
    }

    /// An undeclared capacity does not exempt, and the note says how to leave
    /// scope. `CapacityUnknown` is its own answer rather than folded into
    /// `Required`: the operator can end it by stating a number, which is not
    /// true of the others.
    #[test]
    fn an_industrial_battery_with_no_declared_capacity_stays_in_scope() {
        let data = battery_data(BatteryType::Industrial, None);
        let scope = scope_of(&passport_of(Some(data.clone()), Some(in_period())));
        assert_eq!(scope, Some(PassportScope::CapacityUnknown));
        assert!(
            gate_applies(scope),
            "an unknown capacity must not switch off a statutory gate"
        );
        let note = scope_note(scope, Some(&data)).expect("a note explains the default");
        assert!(note.contains("ratedCapacityKwh"), "{note}");
    }

    /// The date is part of the article, and the record carries it.
    ///
    /// This is what the rule could not express while it lived here: `scope_of`
    /// took only the product-group data, so a battery placed on the market
    /// before the article binds was reported as in scope. It is not — Art. 77(1)
    /// reaches batteries placed on the market **from 18 February 2027**.
    #[test]
    fn a_battery_placed_before_the_article_binds_is_not_yet_in_scope() {
        let data = battery_data(BatteryType::Ev, Some(64.0));
        let before = chrono::NaiveDate::from_ymd_opt(2026, 12, 31).expect("a real date");
        let scope = scope_of(&passport_of(Some(data.clone()), Some(before)));
        assert_eq!(scope, Some(PassportScope::NotYetBinding));
        assert!(!gate_applies(scope));
        let note = scope_note(scope, Some(&data)).expect("note");
        assert!(note.contains("18 February 2027"), "{note}");
    }

    /// The boundary, which is the half of a date rule that gets written wrong.
    #[test]
    fn the_article_binds_on_the_eighteenth_and_not_before() {
        let at = |y, m, d| {
            scope_of(&passport_of(
                Some(battery_data(BatteryType::Ev, Some(64.0))),
                Some(chrono::NaiveDate::from_ymd_opt(y, m, d).expect("a real date")),
            ))
        };
        assert_eq!(at(2027, 2, 17), Some(PassportScope::NotYetBinding));
        assert_eq!(
            at(2027, 2, 18),
            Some(PassportScope::Required),
            "the article says *from* 18 February 2027, so the day itself is inside it"
        );
    }

    /// An unstated date is read as inside the period, not before it.
    ///
    /// The fail-closed direction, and the same choice an undeclared capacity
    /// gets: a draft being prepared today for a product not yet placed on the
    /// market has no date, and answering `notYetBinding` would tell its operator
    /// they owe nothing on the strength of an unfilled field.
    #[test]
    fn an_unstated_placing_date_is_treated_as_inside_the_period() {
        let scope = scope_of(&passport_of(
            Some(battery_data(BatteryType::Ev, Some(64.0))),
            None,
        ));
        assert_eq!(scope, Some(PassportScope::Required));
        assert!(gate_applies(scope));
    }

    /// A non-battery gets no answer from this article rather than a wrong one.
    #[test]
    fn a_non_battery_is_not_applicable_rather_than_out_of_scope() {
        let scope = scope_of(&passport_of(None, Some(in_period())));
        assert_eq!(
            scope, None,
            "Art. 77(1) is a battery article; absence of a battery is not exemption"
        );
        assert_eq!(wire_status(scope), "notApplicable");
        assert!(!gate_applies(scope));
        assert!(scope_note(scope, None).is_none());
    }

    /// Every answer this node can emit has a distinct wire value, and none is
    /// the collapsed "voluntary" this module used to report. Three different
    /// reasons a passport is not owed are three different things to tell an
    /// operator.
    #[test]
    fn each_outcome_has_its_own_wire_value() {
        let seen = [
            wire_status(None),
            wire_status(Some(PassportScope::Required)),
            wire_status(Some(PassportScope::NotCovered)),
            wire_status(Some(PassportScope::BelowThreshold)),
            wire_status(Some(PassportScope::CapacityUnknown)),
            wire_status(Some(PassportScope::NotYetBinding)),
        ];
        let mut unique = seen.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            seen.len(),
            "two outcomes share a wire value: {seen:?}"
        );

        let mut declared = ALL_WIRE_STATUSES.to_vec();
        declared.sort_unstable();
        assert_eq!(
            unique, declared,
            "ALL_WIRE_STATUSES is what the contract suite checks the schema against, so a              value this function can return and that list cannot is invisible to it"
        );
    }

    /// The node still gates a voluntary passport, and the note admits it rather
    /// than leaving an operator to wonder why they are asked for content they do
    /// not owe.
    #[test]
    fn a_voluntary_passport_is_named_and_the_stricter_gate_is_admitted() {
        let portable = battery_data(BatteryType::Portable, None);
        let note = scope_note(Some(PassportScope::NotCovered), Some(&portable)).expect("note");
        assert!(note.contains("voluntary"), "{note}");
        assert!(note.contains("portable"), "{note}");

        let small = battery_data(BatteryType::Industrial, Some(1.0));
        let note = scope_note(Some(PassportScope::BelowThreshold), Some(&small)).expect("note");
        assert!(
            note.contains("stricter"),
            "the over-demand has to be admitted, not hidden: {note}"
        );
    }

    /// The chemistry is irrelevant to the article, asserted so nobody adds it.
    #[test]
    fn chemistry_does_not_affect_the_obligation() {
        let mut data = minimal_battery();
        data.battery_type = BatteryType::Portable;
        data.battery_chemistry = BatteryChemistry::LeadAcid;
        let scope = scope_of(&passport_of(
            Some(ProductGroupData::Battery(Box::new(data))),
            Some(in_period()),
        ));
        assert_eq!(scope, Some(PassportScope::NotCovered));
    }
}
