//! What the vendored `xml-sec` fork is for, demonstrated on real documents.
//!
//! An integration test rather than a unit one, for two reasons that both point
//! the same way: it reads its documents from disk at run time rather than
//! compiling them in, and it reports a skip on stdout — which the
//! `debug-check` gate forbids inside a service crate's `src`, correctly.
//!
//! # Why the documents are not committed
//!
//! Italy's and France's published lists are roughly 2.8 MB and 2.5 MB. Holding
//! ~5 MB of XML in the repository to demonstrate one claim is a poor trade, so
//! they live under `tests/fixtures/local/`, which is git-ignored.
//! `tests/fixtures/local/README.md` says how to fetch them.
//!
//! **The regression guard does not depend on them.** The failure that actually
//! bites is `[patch.crates-io]` silently ceasing to apply — Cargo reports that
//! as a warning, not an error — and
//! `the_patched_xml_sec_is_the_one_that_resolved` catches it by reading
//! `Cargo.lock`, with no documents involved. What is here is a one-time
//! demonstration that the fork does what it claims on a real published list.

use dpp_seal::trustlist::{TrustedListPointer, verify_lotl, verify_trusted_list};

const EU_LOTL: &str = include_str!("fixtures/eu-lotl.xml");

/// The pointer the verified LOTL carries for `territory`.
///
/// Filters out the PDF pointer some Member States publish beside their XML: a
/// territory can carry more than one, and fetching the human-readable one looks
/// exactly like a broken trusted list.
fn pointer_for(territory: &str) -> TrustedListPointer {
    let lotl = verify_lotl(EU_LOTL).expect("the LOTL verifies");
    lotl.pointers()
        .iter()
        .find(|p| {
            p.territory.as_deref() == Some(territory)
                && p.mime_type.as_deref() != Some("application/pdf")
        })
        .unwrap_or_else(|| panic!("the LOTL points at {territory}"))
        .clone()
}

/// A document from `tests/fixtures/local`, or `None` with a loud reason.
///
/// A skipped test that says nothing is worse than no test. The message names the
/// file and the README, so a green run without the documents reads as "this
/// machine did not have it", never as "this passed".
fn local_list(name: &str) -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/local")
        .join(name);
    std::fs::read_to_string(&path).ok().or_else(|| {
        eprintln!(
            "SKIPPED: {} is not present, so the xml-sec fork is not demonstrated on this run. \
             It is deliberately not committed — see tests/fixtures/local/README.md.",
            path.display()
        );
        None
    })
}

/// A real published list that exceeds the unpatched node-set ceiling verifies.
///
/// The published `xml-sec` caps XML node-sets at 65 536 entries. Italy carries
/// 65 540 and France 65 541, so without the fork both fail as a canonicaliser
/// that stops before the end of the document — not as a bad signature. Confirmed
/// by removing the `[patch.crates-io]` stanza and watching this fail with
/// `node-set entries exceeds policy maximum 65536: got 65540`.
///
/// **These are not the only two affected**, despite being the two the fork was
/// vendored for. Measured across every list the LOTL points at on 2026-09-15,
/// four are over the ceiling — France 65 541, Czechia 65 543, Italy 65 540,
/// Spain 65 543 — and byte size does not predict the count. The set grows; this
/// test demonstrates the mechanism rather than enumerating its members.
#[test]
fn a_list_over_the_unpatched_ceiling_verifies_with_the_fork() {
    for (territory, file) in [("IT", "it-trusted-list.xml"), ("FR", "fr-trusted-list.xml")] {
        let Some(xml) = local_list(file) else {
            continue;
        };
        let pointer = pointer_for(territory);
        assert!(
            !pointer.certificates.is_empty(),
            "the LOTL names {territory}'s signing certificates"
        );

        let verified = verify_trusted_list(&xml, &pointer)
            .unwrap_or_else(|e| panic!("{territory}'s list must verify: {e}"));
        assert_eq!(verified.territory(), Some(territory));
        assert!(
            !verified.providers().is_empty(),
            "{territory} lists providers"
        );
    }
}
