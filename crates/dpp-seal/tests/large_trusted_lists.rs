//! The largest published trusted lists verify, demonstrated on real documents.
//!
//! `xml-sec` releases before 0.1.17 stopped canonicalising at 65 536 node-set
//! entries, and several published lists are over it. This workspace carried a
//! fork with that constant raised until upstream shipped the fix
//! (`structured-world/xml-sec#158`); this file is what showed the fork worked,
//! and now shows the released crate does.
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
//! **The regression guard does not depend on them.** The failure that would
//! bite is a manifest or lock edit taking `xml-sec` below 0.1.17, and
//! `xml_sec_is_a_release_with_the_raised_node_set_ceiling` catches it by reading
//! `Cargo.lock`, with no documents involved, so CI runs it. What is here is the
//! end-to-end demonstration on real published lists, to re-run on every
//! `xml-sec` bump.

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
            "SKIPPED: {} is not present, so verifying an over-ceiling list is not demonstrated \
             on this run. \
             It is deliberately not committed — see tests/fixtures/local/README.md.",
            path.display()
        );
        None
    })
}

/// A real published list that exceeds the old node-set ceiling verifies.
///
/// `xml-sec` before 0.1.17 capped XML node-sets at 65 536 entries. Italy and
/// France are over it, so on those releases both fail as a canonicaliser that
/// stops before the end of the document, not as a bad signature. That failure
/// was confirmed with the fork's patch removed:
/// `node-set entries exceeds policy maximum 65536: got 65540`. On 0.1.20, with
/// no fork, this passes.
///
/// **These are not the only two affected.** Measured across every list the
/// LOTL points at on 2026-09-15, four were over the old ceiling (France,
/// Czechia, Italy, Spain), and byte size does not predict the count. The set
/// grows; this test demonstrates the mechanism rather than enumerating its
/// members. Upstream counted roughly 149k (IT) and 144k (FR) entries before
/// text nodes; the default policy limit since 0.1.17 is 262 144, and both pass
/// under it.
#[test]
fn a_list_over_the_old_node_set_ceiling_verifies() {
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
