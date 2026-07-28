//! Trusted-issuer configuration for access credentials.
//!
//! Answers one question: may this issuer DID attest this audience? The policy
//! itself lives in `dpp_crypto::StaticTrustedIssuers`; this module is the
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
//! `CREDENTIAL_ISSUERS_SELF` trusts the node's own operator DID for every
//! audience. That is the first trust anchor that exists in practice: no EU
//! register of authorised repairers has been established, and the DPP registry
//! registers operators and passports rather than repairer credentials. An
//! operator vouching for its own authorised repair network is a real and
//! defensible model, and it is deliberately opt-in rather than implied.

use dpp_crypto::StaticTrustedIssuers;
use dpp_types::trust::TrustMode;

/// Comma-separated issuer DIDs trusted to attest a legitimate interest.
const ENV_LEGITIMATE_INTEREST: &str = "CREDENTIAL_ISSUERS_LEGITIMATE_INTEREST";
/// Comma-separated issuer DIDs trusted to attest an authority.
const ENV_AUTHORITY: &str = "CREDENTIAL_ISSUERS_AUTHORITY";
/// When `true`, the node's own operator DID is trusted for every audience.
const ENV_SELF: &str = "CREDENTIAL_ISSUERS_SELF";

fn dids_from(var: &str) -> Vec<String> {
    std::env::var(var)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Build the trusted-issuer registry from env, alongside the tier to report.
///
/// `operator_did` is the node's own DID, trusted for every audience when
/// `CREDENTIAL_ISSUERS_SELF=true`.
pub fn from_env(operator_did: Option<&str>) -> (StaticTrustedIssuers, TrustMode) {
    let mut legitimate_interest = dids_from(ENV_LEGITIMATE_INTEREST);
    let mut authority = dids_from(ENV_AUTHORITY);

    let trust_self = std::env::var(ENV_SELF)
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if trust_self && let Some(did) = operator_did.filter(|d| !d.is_empty()) {
        legitimate_interest.push(did.to_owned());
        authority.push(did.to_owned());
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
    use dpp_crypto::TrustedIssuerRegistry;
    use dpp_domain::Audience;
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
        assert!(registry.is_trusted_for_audience(did, Audience::Authority));
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
