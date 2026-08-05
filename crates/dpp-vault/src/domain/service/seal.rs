//! The eIDAS qualified-seal step in `publish`.
//!
//! # What gets sealed, and why it is the JWS
//!
//! The digest handed to the QTSP is `SHA-256(passport.jwsSignature)` — the bytes
//! of the compact JWS string, exactly as stored. Three properties make that the
//! right preimage, and each rules out an alternative that was considered:
//!
//! - **It is frozen.** The JWS is produced once per publish and never rewritten
//!   afterwards. Sealing the canonicalized passport document instead would sweep
//!   in `lintResult`, `status` and `qrCodeUrl`, all of which stay mutable after
//!   publish — a later re-lint would silently invalidate the seal, which is the
//!   drift `publicJwsSignature` already had to be fixed for.
//! - **It is reconstructible by anyone.** A verifier reads `jwsSignature` off the
//!   passport, hashes those bytes, and has the preimage. No canonicalization
//!   step, no agreement on a field ordering, nothing to get wrong. Sealing the
//!   pre-signing payload would be reconstructible only from our audit trail.
//! - **It makes the seal a countersignature.** The JWS commits to the whole
//!   passport payload, so a QTSP attesting to the JWS transitively attests to
//!   the content *and* to the fact that the operator signed it at that time —
//!   which is what a qualified seal over a signed document normally means.
//!
//! # Why this is queued rather than called here
//!
//! Sealing is a paid call to a third-party QTSP aggregator. See
//! `dpp_types::seal` for why publish must not depend on that provider being up.

use dpp_domain::domain::passport::Passport;

use super::PassportService;

/// The digest a qualified seal is applied over, for this passport.
///
/// The rule itself is `dpp_types::seal::digest_for_jws` — one definition, shared
/// with the DAL's repair sweep, so what a seal covers cannot drift between the
/// two places that derive it. This only adds "which JWS".
///
/// `None` when the passport carries no `jwsSignature` — an unpublished passport
/// has no operator signature to countersign, and there is nothing honest to seal.
pub fn seal_digest(passport: &Passport) -> Option<String> {
    passport
        .jws_signature
        .as_deref()
        .map(dpp_types::seal::digest_for_jws)
}

impl PassportService {
    /// Queue a qualified seal for a freshly published passport.
    ///
    /// After-commit and best-effort, the same posture as the snapshot and
    /// webhook outboxes: once the row exists the node's drain owns retry and
    /// backoff, so a QTSP that is slow or down never sits on the publish
    /// response. A no-op when no outbox is wired (test doubles), and when the
    /// passport somehow reached here unsigned.
    pub(super) async fn enqueue_seal(&self, passport: &Passport) {
        let Some(outbox) = &self.seal_outbox else {
            return;
        };
        let Some(digest) = seal_digest(passport) else {
            tracing::warn!(
                passport_id = %passport.id,
                "published passport has no jwsSignature — nothing to seal"
            );
            return;
        };
        if let Err(e) = outbox.enqueue(passport.id, &digest).await {
            tracing::warn!(
                passport_id = %passport.id,
                error = %e,
                "failed to enqueue qualified seal (non-fatal)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passport_with_jws(jws: Option<&str>) -> Passport {
        let mut p = crate::public_view::tests::stub_passport();
        p.jws_signature = jws.map(ToOwned::to_owned);
        p
    }

    #[test]
    fn the_digest_is_sha256_of_the_compact_jws() {
        use sha2::{Digest, Sha256};
        let p = passport_with_jws(Some("header.payload.signature"));
        assert_eq!(
            seal_digest(&p).unwrap(),
            hex::encode(Sha256::digest(b"header.payload.signature"))
        );
    }

    /// The vault and the DAL's repair sweep must derive the same digest, or the
    /// sweep buys a seal over something the passport does not recognise.
    #[test]
    fn the_vault_and_the_shared_rule_agree() {
        let jws = "header.payload.signature";
        assert_eq!(
            seal_digest(&passport_with_jws(Some(jws))).unwrap(),
            dpp_types::seal::digest_for_jws(jws)
        );
    }

    #[test]
    fn the_digest_is_a_64_char_hex_sha256() {
        // The `seal_outbox.payload_hash` CHECK constraint enforces exactly this.
        let d = seal_digest(&passport_with_jws(Some("a.b.c"))).unwrap();
        assert_eq!(d.len(), 64);
        assert!(
            d.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }

    #[test]
    fn an_unsigned_passport_has_nothing_to_seal() {
        assert!(seal_digest(&passport_with_jws(None)).is_none());
    }

    /// A re-publish re-signs, so it must produce a distinct digest — that is what
    /// makes the outbox's `(passport_id, payload_hash)` key buy a second seal for
    /// a genuinely new attestation while a retried enqueue of the same signature
    /// stays free.
    #[test]
    fn a_different_signature_is_a_different_digest() {
        let first = seal_digest(&passport_with_jws(Some("a.b.first"))).unwrap();
        let second = seal_digest(&passport_with_jws(Some("a.b.second"))).unwrap();
        assert_ne!(first, second);
    }

    /// The digest must not move when a field that is mutable after publish
    /// changes. This is the property that ruled out sealing the canonicalized
    /// document: `lintResult` is re-stamped by every relint, and a seal taken
    /// over the document would silently stop covering the row.
    #[test]
    fn a_post_publish_mutation_does_not_move_the_digest() {
        let before = passport_with_jws(Some("a.b.c"));
        let mut after = passport_with_jws(Some("a.b.c"));
        after.lint_result = None;
        after.status = dpp_domain::domain::status::PassportStatus::Suspended;
        after.qr_code_url = Some("https://example.test/dpp/x".into());
        after.updated_at = chrono::Utc::now();

        assert_eq!(seal_digest(&before), seal_digest(&after));
    }
}
