//! What the published `TSA/QTST` entries actually are.
//!
//! The matcher behind `qualify_timestamp` accepts two shapes of listed entry — a
//! timestamping unit's **own** certificate (matched by equality) and a **CA** above
//! it (matched through a verified path) — because that is what the standard's
//! description of a service's digital identity suggests. That is reading, not
//! measuring, and this workspace has been wrong in exactly this way before: the
//! seal side's equivalent survey, `ca_key_survey.rs`, found that the lists carry
//! anchors and not chains, that Italy publishes self-signed roots, and that the
//! algorithms in play were not the ones already supported.
//!
//! So this measures the same things for the timestamp side: **what kind of
//! certificate each entry names**, and **whether this build can check a signature
//! made under its key**. Over the lists committed beside it; larger ones held
//! locally are used when present and skipped loudly when not.

use base64::Engine as _;
use der::{Decode as _, Encode as _};
use dpp_domain::trusted_list::TrustServiceType;
use dpp_seal::trustlist::{VerifiedTrustedList, verify_lotl, verify_trusted_list};

const EU_LOTL: &str = include_str!("fixtures/eu-lotl.xml");
const FI_LIST: &str = include_str!("fixtures/fi-trusted-list.xml");

/// `id-kp-timeStamping` — RFC 5280 §4.2.1.12.
const ID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";

/// What kind of certificate a listed entry names.
#[derive(Debug, Default)]
struct Shape {
    /// An end-entity certificate with the timestamping usage: the unit itself.
    timestamping_unit: usize,
    /// A certificate authority.
    ca: usize,
    /// An end-entity certificate that is not marked for timestamping.
    other_end_entity: usize,
    /// Of the above, those that issued themselves.
    self_signed: usize,
    /// Of the above, those whose key this build can verify a signature under.
    verifiable: usize,
    /// Public-key algorithm → count, with the curve for EC keys.
    keys: std::collections::BTreeMap<String, usize>,
    /// Certificates that would not decode, so the totals say what was *not* seen.
    unreadable: usize,
    /// The entries that fit neither the unit nor the CA description, named so they
    /// can be looked at rather than counted.
    odd: Vec<String>,
}

impl Shape {
    fn total(&self) -> usize {
        self.timestamping_unit + self.ca + self.other_end_entity
    }
}

fn verified(xml: &str, territory: &str) -> VerifiedTrustedList {
    let lotl = verify_lotl(EU_LOTL).expect("the LOTL verifies");
    let pointer = lotl
        .pointers()
        .iter()
        .find(|p| p.territory.as_deref() == Some(territory))
        .expect("the LOTL points at this territory")
        .clone();
    verify_trusted_list(xml, &pointer).expect("the list verifies")
}

/// Everything this measures, for one list.
///
/// Returns the shape of the entries **and** how many `TSA/QTST` services there are,
/// because a list with none proves nothing and must say so rather than pass.
fn survey(list: &VerifiedTrustedList) -> (usize, Shape) {
    let mut shape = Shape::default();
    let mut services_seen = 0;

    for (_, services) in list.providers_offering(TrustServiceType::QUALIFIED_TIMESTAMP_AUTHORITY) {
        for service in services {
            services_seen += 1;
            for c in &service.certificates {
                let Ok(der) = base64::engine::general_purpose::STANDARD.decode(c.trim()) else {
                    shape.unreadable += 1;
                    continue;
                };
                let Ok(cert) = x509_cert::Certificate::from_der(&der) else {
                    shape.unreadable += 1;
                    continue;
                };
                let tbs = &cert.tbs_certificate;

                let is_ca = tbs
                    .get::<x509_cert::ext::pkix::BasicConstraints>()
                    .ok()
                    .flatten()
                    .is_some_and(|(_, bc)| bc.ca);
                let is_timestamping = tbs
                    .get::<x509_cert::ext::pkix::ExtendedKeyUsage>()
                    .ok()
                    .flatten()
                    .is_some_and(|(_, eku)| {
                        eku.0.iter().any(|o| o.to_string() == ID_KP_TIME_STAMPING)
                    });

                if is_ca {
                    shape.ca += 1;
                } else if is_timestamping {
                    shape.timestamping_unit += 1;
                } else {
                    shape.other_end_entity += 1;
                    let usages = tbs
                        .get::<x509_cert::ext::pkix::ExtendedKeyUsage>()
                        .ok()
                        .flatten()
                        .map_or_else(
                            || "no extended key usage".to_owned(),
                            |(_, eku)| {
                                eku.0
                                    .iter()
                                    .map(ToString::to_string)
                                    .collect::<Vec<_>>()
                                    .join(",")
                            },
                        );
                    shape.odd.push(format!("{} [{usages}]", tbs.subject));
                }
                if tbs.issuer == tbs.subject {
                    shape.self_signed += 1;
                    if !is_ca {
                        shape
                            .odd
                            .push(format!("self-signed non-CA: {}", tbs.subject));
                    }
                }
                if dpp_seal::cades::can_verify_signatures_of(&der) {
                    shape.verifiable += 1;
                }

                let spki = &tbs.subject_public_key_info;
                let curve = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.to_der().ok())
                    .and_then(|d| der::asn1::ObjectIdentifier::from_der(&d).ok())
                    .map(|o| format!(" curve {o}"))
                    .unwrap_or_default();
                *shape
                    .keys
                    .entry(format!("{}{curve}", spki.algorithm.oid))
                    .or_default() += 1;
            }
        }
    }
    (services_seen, shape)
}

/// The lists to measure: the committed one, plus any held locally.
fn available_lists() -> Vec<(&'static str, VerifiedTrustedList)> {
    let mut lists = vec![("FI", verified(FI_LIST, "FI"))];

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/local");
    for (territory, file) in [("IT", "it-trusted-list.xml"), ("FR", "fr-trusted-list.xml")] {
        match std::fs::read_to_string(dir.join(file)) {
            Ok(xml) => lists.push((territory, verified(&xml, territory))),
            Err(_) => eprintln!("SKIPPED {territory}: {file} is absent"),
        }
    }
    lists
}

/// Every service type a list publishes, with how many services carry it.
///
/// A diagnostic, kept: a survey that finds *nothing* has to be able to say whether
/// the list has no timestamp services at all or files them under a type the matcher
/// does not look for — those are different findings.
#[test]
fn the_service_types_a_list_publishes() {
    for (territory, list) in available_lists() {
        let mut types: std::collections::BTreeMap<String, usize> = Default::default();
        for provider in list.providers() {
            for service in &provider.services {
                *types
                    .entry(service.service_type.as_str().to_owned())
                    .or_default() += 1;
            }
        }
        println!("{territory}: {} distinct service type(s)", types.len());
        for (uri, n) in &types {
            let short = uri.rsplit("/Svctype/").next().unwrap_or(uri);
            println!("    {n:>3}  {short}");
        }
        assert!(!types.is_empty(), "{territory}: a list with no services");
    }
}

/// **What the published qualified-timestamp entries are, and whether this build
/// can check a signature under their keys.**
///
/// Printed rather than only asserted, because the numbers are the finding. The
/// assertions pin the two things a change would invalidate: that every entry is a
/// shape the matcher accepts, and that every listed key is one this build can
/// verify.
#[test]
fn the_published_timestamp_entries_are_shapes_the_matcher_accepts_and_keys_it_can_check() {
    let mut measured = 0;
    let mut unverifiable_anywhere = 0;

    for (territory, list) in available_lists() {
        let (services, shape) = survey(&list);
        println!(
            "{territory}: {services} qualified timestamp service(s), {} certificate(s): \
             {} timestamping unit(s), {} CA(s), {} other end-entity, {} self-signed, \
             {} this build can verify, {} unreadable",
            shape.total(),
            shape.timestamping_unit,
            shape.ca,
            shape.other_end_entity,
            shape.self_signed,
            shape.verifiable,
            shape.unreadable
        );
        for (key, n) in &shape.keys {
            println!("    key {key}: {n}");
        }
        for odd in &shape.odd {
            println!("    unusual: {odd}");
        }

        if services == 0 {
            eprintln!("{territory} publishes no TSA/QTST service, so it measured nothing");
            continue;
        }
        measured += 1;
        unverifiable_anywhere += shape.total() - shape.verifiable;

        assert_eq!(
            shape.unreadable, 0,
            "{territory}: a listed certificate that will not decode is one the matcher silently \
             skips, so the entry it belongs to can never match"
        );

        // The two shapes the matcher accepts are each **load-bearing somewhere**, and
        // that is what is pinned: not the exact counts, which move whenever a Member
        // State republishes, but which kind of entry each one actually publishes.
        // If either flips, the matcher's two-way description should be read again.
        match territory {
            "FR" => assert!(
                shape.timestamping_unit > 0,
                "France is measured to list timestamping UNITS directly (140 of 160 when this was \
                 written), which is what makes matching by certificate equality necessary; if it \
                 stopped, that leg would be dead code"
            ),
            "IT" => assert!(
                shape.ca > 0 && shape.timestamping_unit == 0,
                "Italy is measured to list only self-signed ROOT CAs for qualified timestamps \
                 (34 of 34 when this was written), so an Italian token can match only through a \
                 verified path and must carry its intermediates; if that changed, the \
                 incomplete-chain handling for timestamps was sized against the wrong shape"
            ),
            _ => {}
        }
    }

    // Finland's committed list publishes no timestamp service at all, so a checkout
    // without the larger lists measures nothing — and says so, loudly, rather than
    // failing or passing. The same pattern the other local-list tests use: absent
    // fixtures read as "not measured here", never as a pass. See
    // `tests/fixtures/local/README.md` for how to fetch them.
    if measured == 0 {
        eprintln!(
            "SKIPPED: no list present here carries a TSA/QTST service (Finland's committed list \
             has none), so this measured nothing. Fetch the Italian and French lists to run it."
        );
        return;
    }
    assert_eq!(
        unverifiable_anywhere, 0,
        "a listed timestamp key this build cannot check is an authority whose tokens would be \
         refused as unverifiable, qualified or not"
    );
}
