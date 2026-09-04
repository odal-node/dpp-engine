//! Which batteries Art. 77(1) actually requires a passport for.
//!
//! ⬅️ **Core-candidate.** This is a rule that changes when the Regulation
//! changes, which by the golden rule belongs in `dpp-core` beside
//! `dpp_rules::batteries::passport_content`. It is here for now so the two
//! repositories are not edited in the same breath; the shape is deliberately one
//! pure function over values core already owns, so moving it is a lift rather
//! than a rewrite.
//!
//! # The article
//!
//! > **Art. 77(1)** — "From 18 February 2027 each LMT battery, each industrial
//! > battery with a capacity greater than 2 kWh and each electric vehicle
//! > battery placed on the market or put into service shall have an electronic
//! > record ('battery passport')."
//!
//! Reg. (EU) 2023/1542 defines five battery categories — portable (Art. 3(9)),
//! LMT (11), SLI (12), industrial (13), electric-vehicle (14) — and this article
//! reaches three of them. Portable and SLI batteries bear no passport obligation
//! at all.
//!
//! That is also why `mandatory_fields` answers `Requirement::Unknown` for those
//! two rather than listing nothing: the Commission's data-point guidance does
//! not cover them because there is no passport to carry the data points. Silence
//! there is an absence of obligation, not a gap in the source.
//!
//! # Two qualifiers worth not losing
//!
//! **The threshold is energy, not charge.** Art. 77(1) says *kWh*. The
//! Regulation's only definition of "rated capacity" — ampere-hours — is scoped
//! *"for the purposes of this Annex"* and does not govern this article, so the
//! comparison is against `ratedCapacityKwh` and never against
//! `nominalCapacityAh`.
//!
//! **No `rechargeable` qualifier.** Arts. 7 and 8 both read "*rechargeable*
//! industrial batteries with a capacity greater than 2 kWh"; Art. 77(1) does
//! not. The word is absent here on purpose and is not reintroduced.
//!
//! # Why an undeclared capacity is in scope rather than out
//!
//! The obligation attaches to industrial batteries **above** 2 kWh, so deciding
//! an unknown capacity means choosing which way to be wrong.
//!
//! Wrongly exempting means the node stops asking for content the law requires,
//! and an operator publishes a deficient passport believing it complete.
//! Wrongly including means an operator is asked for data they do not owe, which
//! is friction and nothing worse — and it is friction they can end by declaring
//! the capacity.
//!
//! So a battery leaves the obligation only by **saying** it is small enough.
//! `ratedCapacityKwh` is optional on the record, and its absence is read as "not
//! established", never as "small".
//!
//! Deriving the energy from `nominalVoltageV × nominalCapacityAh` — both
//! required — was considered and rejected for the exempting direction: a
//! nameplate product is an inference about the battery, and an inference is not
//! the ground on which to switch off a statutory gate.

use dpp_domain::product_group::{BatteryType, ProductGroupData};

/// Whether this node's passport-content gate is something the law asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassportObligation {
    /// Art. 77(1) requires a battery passport for this record.
    Required,
    /// Art. 77(1) does not reach this record. A passport may still be published
    /// — nothing forbids one — but it is the operator's own artefact rather than
    /// the discharge of a duty.
    Voluntary,
    /// Not a battery, so Art. 77(1) has nothing to say. Other instruments may
    /// still require a passport; this type answers one article only.
    NotApplicable,
}

impl PassportObligation {
    /// Whether the article requires the passport.
    #[must_use]
    pub fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }
}

/// The Art. 77(1) threshold, in kilowatt-hours. Strictly greater than.
pub const INDUSTRIAL_THRESHOLD_KWH: f64 = 2.0;

/// Apply Art. 77(1) to a passport's product-group data.
#[must_use]
pub fn passport_obligation(data: Option<&ProductGroupData>) -> PassportObligation {
    let Some(ProductGroupData::Battery(battery)) = data else {
        return PassportObligation::NotApplicable;
    };
    match &battery.battery_type {
        // Named by the article without qualification.
        BatteryType::Lmt | BatteryType::Ev => PassportObligation::Required,
        // Named with a threshold. Undeclared capacity is not "small" — see the
        // module header on which way to be wrong.
        BatteryType::Industrial => match battery.rated_capacity_kwh {
            Some(kwh) if kwh <= INDUSTRIAL_THRESHOLD_KWH => PassportObligation::Voluntary,
            _ => PassportObligation::Required,
        },
        // Outside the article entirely.
        BatteryType::Portable | BatteryType::Sli => PassportObligation::Voluntary,
        // `BatteryType` is `#[non_exhaustive]`, so a newer `dpp-domain` can add a
        // category this build has never heard of. It is treated as in scope, for
        // the same reason an undeclared capacity is: exempting on an unknown is
        // the one error that silently switches off a statutory gate. An
        // unrecognised type is also worth saying out loud rather than absorbing.
        other => {
            tracing::warn!(
                battery_type = ?other,
                "battery category not recognised by this build; applying the Art. 77(1) \
                 obligation rather than assuming it is out of scope"
            );
            PassportObligation::Required
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
pub fn obligation_note(
    obligation: PassportObligation,
    data: Option<&ProductGroupData>,
) -> Option<String> {
    let Some(ProductGroupData::Battery(battery)) = data else {
        return None;
    };
    match obligation {
        PassportObligation::NotApplicable => None,
        PassportObligation::Required => match &battery.battery_type {
            BatteryType::Industrial if battery.rated_capacity_kwh.is_none() => Some(
                "Art. 77(1) requires a battery passport for an industrial battery with a \
                 capacity greater than 2 kWh. This record does not declare \
                 `ratedCapacityKwh`, so it is treated as in scope: an undeclared capacity is \
                 not evidence of a small one. Declaring a capacity of 2 kWh or less would put \
                 it outside the article."
                    .to_owned(),
            ),
            _ => None,
        },
        PassportObligation::Voluntary => Some(match &battery.battery_type {
            BatteryType::Portable | BatteryType::Sli => format!(
                "Art. 77(1) requires a battery passport for LMT, electric-vehicle and \
                 industrial batteries above 2 kWh. A {} battery is outside it, so this \
                 passport is voluntary — publishing one is allowed and discharges no duty \
                 under that article.",
                match &battery.battery_type {
                    BatteryType::Portable => "portable",
                    _ => "starting, lighting and ignition",
                }
            ),
            _ => "Art. 77(1) reaches industrial batteries with a capacity greater than \
                  2 kWh. This one declares 2 kWh or less, so its passport is voluntary. \
                  Note that this node still applies the category content gate, which is \
                  stricter than the article requires here."
                .to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpp_domain::product_group::{BatteryChemistry, BatteryData};

    fn battery(battery_type: BatteryType, rated_capacity_kwh: Option<f64>) -> ProductGroupData {
        let mut data = crate::domain::passport_scope::tests::minimal_battery();
        data.battery_type = battery_type.clone();
        data.rated_capacity_kwh = rated_capacity_kwh;
        ProductGroupData::Battery(Box::new(data))
    }

    /// A `BatteryData` with only the fields this rule reads. Every other field
    /// is irrelevant to Art. 77(1) and is left at its empty value.
    pub(super) fn minimal_battery() -> BatteryData {
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
                    passport_obligation(Some(&battery(t.clone(), capacity))),
                    PassportObligation::Required,
                    "{t:?} at {capacity:?} kWh is named by Art. 77(1) with no threshold"
                );
            }
        }
    }

    /// The two the article does not reach at all.
    #[test]
    fn portable_and_sli_batteries_never_carry_the_obligation() {
        for t in [BatteryType::Portable, BatteryType::Sli] {
            for capacity in [None, Some(0.5), Some(500.0)] {
                assert_eq!(
                    passport_obligation(Some(&battery(t.clone(), capacity))),
                    PassportObligation::Voluntary,
                    "{t:?} is outside Art. 77(1) at any capacity"
                );
            }
        }
    }

    /// "Greater than 2 kWh" — so exactly 2 kWh is out, and the boundary is the
    /// one thing a threshold gets wrong.
    #[test]
    fn the_industrial_threshold_is_strictly_greater_than_two_kwh() {
        let at = |kwh: f64| passport_obligation(Some(&battery(BatteryType::Industrial, Some(kwh))));
        assert_eq!(at(1.999), PassportObligation::Voluntary);
        assert_eq!(
            at(2.0),
            PassportObligation::Voluntary,
            "the article says *greater than* 2 kWh, so 2.0 is outside it"
        );
        assert_eq!(at(2.001), PassportObligation::Required);
        assert_eq!(at(64.0), PassportObligation::Required);
    }

    /// An undeclared capacity is in scope, and the note says how to leave it.
    #[test]
    fn an_industrial_battery_with_no_declared_capacity_stays_in_scope() {
        let data = battery(BatteryType::Industrial, None);
        let obligation = passport_obligation(Some(&data));
        assert_eq!(
            obligation,
            PassportObligation::Required,
            "an unknown capacity must not exempt a battery from a statutory gate"
        );
        let note = obligation_note(obligation, Some(&data)).expect("a note explains the default");
        assert!(note.contains("ratedCapacityKwh"), "{note}");
    }

    /// A non-battery gets no answer from this article rather than a wrong one.
    #[test]
    fn a_non_battery_is_not_applicable_rather_than_voluntary() {
        assert_eq!(
            passport_obligation(None),
            PassportObligation::NotApplicable,
            "Art. 77(1) is a battery article; absence of a battery is not exemption"
        );
        assert!(obligation_note(PassportObligation::NotApplicable, None).is_none());
    }

    /// A voluntary passport is named as such, and the industrial case says the
    /// node is stricter than the article — the operator is otherwise left to
    /// wonder why they are being asked for content they do not owe.
    #[test]
    fn a_voluntary_passport_is_named_and_the_stricter_gate_is_admitted() {
        let portable = battery(BatteryType::Portable, None);
        let note = obligation_note(PassportObligation::Voluntary, Some(&portable)).expect("note");
        assert!(note.contains("voluntary"), "{note}");
        assert!(note.contains("portable"), "{note}");

        let small = battery(BatteryType::Industrial, Some(1.0));
        let note = obligation_note(PassportObligation::Voluntary, Some(&small)).expect("note");
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
        assert_eq!(
            passport_obligation(Some(&ProductGroupData::Battery(Box::new(data)))),
            PassportObligation::Voluntary
        );
    }
}
