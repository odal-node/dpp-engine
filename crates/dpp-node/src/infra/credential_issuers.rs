//! Trusted-issuer configuration for access credentials.
//!
//! Answers one question: may this issuer DID attest this audience? The policy
//! itself lives in `dpp_vc::StaticTrustedIssuers`; this module is the
//! engine-side binding to configuration, plus the trust tier the node reports.
//!
//! # Why zero-config is Ghost, not deny-all
//!
//! A node with no trusted issuers configured cannot grant credentialed access.
//! It could report that by denying every credential, which is *behaviourally*
//! correct and *diagnostically* useless — indistinguishable from a node that
//! rejects a specific issuer, or from a broken credential. Under the
//! ghost-honesty invariant the node instead reports the port as `ghost`, so
//! `/health` says the capability is absent rather than the request being wrong.
//!
//! The port is **not** `required`: a node serving only public passport views is
//! completely functional. ESPR Art. 11(b) and the toy and detergent regulations
//! require public access free of charge and without registration, so the
//! unauthenticated path is the product's baseline, not a degraded mode.
//!
//! # The operator as its own issuer
//!
//! `CREDENTIAL_ISSUERS_SELF` trusts the node's own operator DID for a
//! **legitimate interest**, and for nothing above it. That is the first trust
//! anchor that exists in practice: no EU register of authorised repairers has
//! been established, and the DPP registry registers operators and passports
//! rather than repairer credentials. An operator vouching for its own
//! authorised repair network is a real and defensible model, and it is
//! deliberately opt-in rather than implied.
//!
//! It used to grant `authority` as well, which nothing above argues for and
//! which is not the operator's to grant. Authority status under Art. 77(2)(b)
//! is conferred by a member state; an operator that adds its own DID to the
//! authority bucket has written itself a market-surveillance credential, and the
//! credential-verified read path would honour it. Trusting an authority is what
//! `CREDENTIAL_ISSUERS_AUTHORITY` is for, where naming the issuer is an explicit
//! act rather than a side effect of a switch about repairers.
//!
//! `dpp-vc` reaches the same split from the other side: it says a node signing
//! its own access credentials "has attested nothing to anyone", which is true of
//! the claim no operator can make about itself and not of the one only the
//! operator can make.

use dpp_types::trust::TrustMode;
use dpp_vc::StaticTrustedIssuers;

/// Comma-separated issuer DIDs trusted to attest a legitimate interest.
const ENV_LEGITIMATE_INTEREST: &str = "CREDENTIAL_ISSUERS_LEGITIMATE_INTEREST";
/// Comma-separated issuer DIDs trusted to attest an authority.
const ENV_AUTHORITY: &str = "CREDENTIAL_ISSUERS_AUTHORITY";
/// When `true`, the node's own operator DID is trusted to attest a legitimate
/// interest — and nothing above it. See the module header.
const ENV_SELF: &str = "CREDENTIAL_ISSUERS_SELF";

/// Trust is matched against `credential.issuer` by exact string equality, so an
/// entry that is not a DID can never match anything. Admitting one would be
/// worse than dropping it: a non-empty list reports the port `Live`, so the node
/// would advertise credentialed access while denying every credential — the
/// exact indistinguishable-denial failure this module exists to avoid. Refuse it
/// loudly instead.
fn is_did(candidate: &str) -> bool {
    candidate.starts_with("did:")
}

fn keep_dids(source: &str, candidates: Vec<String>) -> Vec<String> {
    candidates
        .into_iter()
        .filter(|c| {
            if is_did(c) {
                return true;
            }
            tracing::warn!(
                source,
                value = c.as_str(),
                "ignoring trusted-issuer entry: not a DID. Trust is matched against \
                 the credential's `issuer` by exact string equality, so this entry \
                 could never match. Expected e.g. did:web:issuer.example"
            );
            false
        })
        .collect()
}

fn dids_from(var: &str) -> Vec<String> {
    let raw: Vec<String> = std::env::var(var)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    keep_dids(var, raw)
}

/// Build the trusted-issuer registry from env, alongside the tier to report.
///
/// `operator_did` is the node's own **DID** — not its base URL. Pass the `id` of
/// the node's published DID document; that is the string a self-issued
/// credential carries as `issuer`, and the two must be byte-identical for
/// `CREDENTIAL_ISSUERS_SELF` to grant anything.
pub fn from_env(operator_did: Option<&str>) -> (StaticTrustedIssuers, TrustMode) {
    let mut legitimate_interest = dids_from(ENV_LEGITIMATE_INTEREST);
    let authority = dids_from(ENV_AUTHORITY);

    let trust_self = std::env::var(ENV_SELF)
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if trust_self && let Some(did) = operator_did.filter(|d| !d.is_empty()) {
        // Legitimate interest only — see the module header. An operator that
        // genuinely needs to trust an authority names it in `ENV_AUTHORITY`,
        // where it is a decision rather than a consequence.
        legitimate_interest.extend(keep_dids(ENV_SELF, vec![did.to_owned()]));
    }

    if legitimate_interest.is_empty() && authority.is_empty() {
        tracing::info!(
            "credential issuers: none configured — credentialed access unavailable. \
             Set {ENV_LEGITIMATE_INTEREST} / {ENV_AUTHORITY}, or {ENV_SELF}=true to \
             trust this operator's own DID."
        );
        return (
            StaticTrustedIssuers::new(Vec::<String>::new(), Vec::<String>::new()),
            TrustMode::Ghost,
        );
    }

    tracing::info!(
        legitimate_interest = legitimate_interest.len(),
        authority = authority.len(),
        "credential issuers configured"
    );
    (
        StaticTrustedIssuers::new(legitimate_interest, authority),
        TrustMode::Live,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpp_domain::Audience;
    use dpp_vc::TrustedIssuerRegistry;
    use serial_test::serial;

    fn clear() {
        for v in [ENV_LEGITIMATE_INTEREST, ENV_AUTHORITY, ENV_SELF] {
            unsafe { std::env::remove_var(v) };
        }
    }

    #[test]
    #[serial]
    fn no_configuration_reports_ghost_rather_than_denying() {
        clear();
        let (_registry, mode) = from_env(Some("did:web:operator.example"));
        assert_eq!(
            mode,
            TrustMode::Ghost,
            "an unconfigured node must report the capability absent"
        );
    }

    #[test]
    #[serial]
    fn a_configured_issuer_is_trusted_and_others_are_not() {
        clear();
        unsafe { std::env::set_var(ENV_LEGITIMATE_INTEREST, "did:web:trusted.example") };
        let (registry, mode) = from_env(None);
        assert_eq!(mode, TrustMode::Live);
        assert!(
            registry
                .is_trusted_for_audience("did:web:trusted.example", Audience::LegitimateInterest)
        );
        assert!(
            !registry
                .is_trusted_for_audience("did:web:stranger.example", Audience::LegitimateInterest)
        );
        clear();
    }

    /// Issuer trust is hierarchical even though data visibility is not: an
    /// issuer trusted to attest an authority may also attest a legitimate
    /// interest, because the harder attestation implies the easier one. This
    /// says nothing about what either credential can *see*.
    #[test]
    #[serial]
    fn authority_trust_implies_legitimate_interest_trust_but_not_the_reverse() {
        clear();
        unsafe { std::env::set_var(ENV_AUTHORITY, "did:web:authority.example") };
        unsafe { std::env::set_var(ENV_LEGITIMATE_INTEREST, "did:web:repairer.example") };
        let (registry, _) = from_env(None);

        assert!(registry.is_trusted_for_audience("did:web:authority.example", Audience::Authority));
        assert!(
            registry
                .is_trusted_for_audience("did:web:authority.example", Audience::LegitimateInterest)
        );

        assert!(
            registry
                .is_trusted_for_audience("did:web:repairer.example", Audience::LegitimateInterest)
        );
        assert!(
            !registry.is_trusted_for_audience("did:web:repairer.example", Audience::Authority),
            "trust for a lower audience must not confer a higher one"
        );
        clear();
    }

    #[test]
    #[serial]
    fn the_operator_can_be_its_own_issuer_but_only_when_opted_in() {
        clear();
        let did = "did:web:operator.example";

        let (registry, mode) = from_env(Some(did));
        assert_eq!(mode, TrustMode::Ghost, "self-trust must not be implied");
        assert!(!registry.is_trusted_for_audience(did, Audience::LegitimateInterest));

        unsafe { std::env::set_var(ENV_SELF, "true") };
        let (registry, mode) = from_env(Some(did));
        assert_eq!(mode, TrustMode::Live);
        assert!(registry.is_trusted_for_audience(did, Audience::LegitimateInterest));
        clear();
    }

    /// Self-trust stops at a legitimate interest.
    ///
    /// The switch used to push the operator's DID into the authority bucket
    /// too, which let an operator write itself a market-surveillance credential
    /// that the credential-verified read path would honour. Authority status is
    /// a member state's to confer; `ENV_AUTHORITY` is where an operator names
    /// one, deliberately.
    #[test]
    #[serial]
    fn self_trust_never_reaches_the_authority_audience() {
        clear();
        let did = "did:web:operator.example";
        unsafe { std::env::set_var(ENV_SELF, "true") };
        let (registry, _) = from_env(Some(did));

        assert!(
            registry.is_trusted_for_audience(did, Audience::LegitimateInterest),
            "the repair-network model is the whole point of the switch"
        );
        assert!(
            !registry.is_trusted_for_audience(did, Audience::Authority),
            "an operator cannot make itself a market surveillance authority"
        );
        clear();
    }

    /// And the switch composes with an explicitly named authority rather than
    /// replacing it: an operator that has a real authority to trust still gets
    /// it, and still does not become one itself.
    #[test]
    #[serial]
    fn a_named_authority_is_unaffected_by_self_trust() {
        clear();
        let did = "did:web:operator.example";
        unsafe { std::env::set_var(ENV_SELF, "true") };
        unsafe { std::env::set_var(ENV_AUTHORITY, "did:web:bundesnetzagentur.example") };
        let (registry, _) = from_env(Some(did));

        assert!(
            registry
                .is_trusted_for_audience("did:web:bundesnetzagentur.example", Audience::Authority)
        );
        assert!(!registry.is_trusted_for_audience(did, Audience::Authority));
        clear();
    }

    /// A base URL is not a DID. Passing one (the node's `DID_WEB_BASE_URL`
    /// rather than its DID document's `id`) must not produce a `Live` node whose
    /// every credential is denied as untrusted — the operator would see a
    /// healthy trust report and an endpoint that grants nothing.
    #[test]
    #[serial]
    fn a_base_url_is_refused_rather_than_trusted_as_a_did() {
        clear();
        unsafe { std::env::set_var(ENV_SELF, "true") };
        let (registry, mode) = from_env(Some("http://localhost:8001"));
        assert_eq!(
            mode,
            TrustMode::Ghost,
            "a non-DID self entry must leave the node Ghost, not falsely Live"
        );
        assert!(
            !registry
                .is_trusted_for_audience("http://localhost:8001", Audience::LegitimateInterest)
        );
        // The DID that credential subjects actually carry is likewise untrusted,
        // because the base URL never became one.
        assert!(
            !registry
                .is_trusted_for_audience("did:web:localhost%3A8001", Audience::LegitimateInterest)
        );
        clear();
    }

    /// The same rule for operator-configured issuers: a typo'd https URL in the
    /// env var is dropped, not admitted as an unmatchable entry.
    #[test]
    #[serial]
    fn a_non_did_env_entry_is_dropped() {
        clear();
        unsafe {
            std::env::set_var(
                ENV_AUTHORITY,
                "https://authority.example,did:web:authority.example",
            );
        }
        let (registry, mode) = from_env(None);
        assert_eq!(mode, TrustMode::Live, "the one real DID still configures");
        assert!(registry.is_trusted_for_audience("did:web:authority.example", Audience::Authority));
        assert!(
            !registry.is_trusted_for_audience("https://authority.example", Audience::Authority)
        );
        clear();
    }

    /// The DID this node publishes is the string a self-issued credential
    /// carries as `issuer`, so self-trust must match it exactly.
    #[test]
    #[serial]
    fn self_trust_matches_the_published_did_exactly() {
        clear();
        let did = "did:web:localhost%3A8001";
        unsafe { std::env::set_var(ENV_SELF, "true") };
        let (registry, mode) = from_env(Some(did));
        assert_eq!(mode, TrustMode::Live);
        assert!(registry.is_trusted_for_audience(did, Audience::LegitimateInterest));
        clear();
    }

    /// The public audience needs no issuer at all — anyone may read the public
    /// view, so trust is vacuously true and must stay true on an unconfigured
    /// node. Regressing this would gate the unauthenticated path behind
    /// credential configuration, which the toy and detergent regulations forbid.
    #[test]
    #[serial]
    fn the_public_audience_needs_no_trusted_issuer() {
        clear();
        let (registry, _) = from_env(None);
        assert!(registry.is_trusted_for_audience("did:web:anyone.example", Audience::Public));
    }
}
