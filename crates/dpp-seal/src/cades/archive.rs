//! Whether the archival protection is still live, and renewing it.

use chrono::{DateTime, Utc};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode as _, Encode as _};

use super::signature::digest_matches;
use super::signature::signature_holds;
use super::signed::ID_AA_ETS_ARCHIVE_TIMESTAMP_V2;
use super::signed::ID_AA_ETS_ARCHIVE_TIMESTAMP_V3;
use super::signed::Signed;
use super::signed::parse;
use super::timestamp::stamped_within_its_certificate;
use super::timestamp::to_utc;
use super::timestamp::{TimestampToken, TstInfo};
use crate::error::SealError;

/// How much life is left in a seal's archival timestamp.
///
/// # Why a seal can stop being long-term without anything changing
///
/// An archival timestamp is what keeps a `B-LTA` seal verifiable after its
/// signing certificate expires — which for a retention-locked passport is the
/// whole point, because the document outlives every certificate involved.
///
/// **The archival timestamp expires too.** Its own timestamping authority's
/// certificate has a validity period, and once that passes the token can no
/// longer be validated on its own terms. ETSI's long-term profiles handle this
/// by **re-timestamping** before it happens, a new archive timestamp over the
/// old one — which [`crate::timestamp::renewal`] does, where a node has an authority to ask.
/// Where it does not, nothing would notice: `evidenced_level` reports
/// `BaselineLta` from the *presence* of the attribute, so a seal whose archival
/// timestamp lapsed years ago reports exactly as it did on the day it was bought.
///
/// # A signal, never a verdict
///
/// Deliberately the same posture the trust anchor's freshness takes, and for the
/// same reason: a seal whose archival timestamp is nearing expiry still verifies,
/// and that window is the only chance to renew without an outage. Folding this
/// into a failure would refuse documents that are fine and destroy the early
/// warning it exists to give.
///
/// No threshold is applied here. [`Self::Current`] carries the date, and how
/// much notice is enough is a policy question belonging to whoever reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchivalFreshness {
    /// No archival timestamp at all — a seal below `B-LTA`.
    ///
    /// Nothing to renew, which is different from a renewal that has lapsed.
    NotArchived,
    /// The archival timestamp's authority certificate is still valid.
    Current {
        /// When that certificate expires — the date by which re-timestamping
        /// has to have happened.
        expires: DateTime<Utc>,
    },
    /// It has expired. The archival protection has lapsed.
    ///
    /// The seal may still verify today; what is gone is the thing that was
    /// meant to keep it verifying once its signing certificate goes.
    Lapsed {
        /// When the authority's certificate expired. The same value
        /// [`Self::Current`] carries, read from the other side of it.
        expires: DateTime<Utc>,
    },
    /// An archival timestamp is present and could not be read.
    ///
    /// **Not [`Self::Current`].** A token that cannot be checked is not a fresh
    /// one, and reporting it as current is how a staleness signal goes quiet at
    /// the moment it matters.
    Unknown,
}

/// Read how much life is left in a seal's archival timestamp.
///
/// # What is checked
///
/// The token's own signature, that it was stamped inside its authority's
/// certificate window, and — see [`archives`] — that it is a timestamp of **this
/// signature**, by recomputing the EN 319 122-1 clause 5.5.3 concatenation
/// against the `ats-hash-index-v3` the token carries.
///
/// That last one is the difference between *"is there archival protection here?"*
/// and *"is this seal archived?"*, and it used not to be checked: an unsigned
/// attribute is covered by nothing in the enclosing signature, so a genuine
/// token from another seal could be pasted in and this passport would report
/// protection until somebody else's authority certificate expired.
///
/// A token that cannot be tied to this signature contributes no date, so a seal
/// carrying only such tokens reports [`ArchivalFreshness::Unknown`] rather than
/// `Current` — present, and unreadable *as this seal's*.
///
/// The **latest** timestamp decides, by `genTime`. A renewal chain is a sequence
/// of archive timestamps each covering the one before it, and it is the newest
/// that carries the protection forward — reading an older one would report a
/// renewed seal as lapsed.
///
/// # Errors
///
/// [`SealError::Backend`] when the seal itself cannot be read.
pub fn archival_freshness(
    seal_der: &[u8],
    now: DateTime<Utc>,
) -> Result<ArchivalFreshness, SealError> {
    let signed = parse(seal_der)?;
    let Some(attrs) = signed.signer.unsigned_attrs.as_ref() else {
        return Ok(ArchivalFreshness::NotArchived);
    };

    let archival: Vec<_> = attrs
        .iter()
        .filter(|a| {
            a.oid == ID_AA_ETS_ARCHIVE_TIMESTAMP_V3 || a.oid == ID_AA_ETS_ARCHIVE_TIMESTAMP_V2
        })
        .collect();
    if archival.is_empty() {
        return Ok(ArchivalFreshness::NotArchived);
    }

    // The newest readable token wins. An unreadable one among several is not
    // fatal — but if *none* reads, the answer is unknown rather than absent.
    let Some(newest) = newest_of(archival_tokens(&signed, archival)) else {
        return Ok(ArchivalFreshness::Unknown);
    };
    let expires = newest.expires;
    Ok(if expires > now {
        ArchivalFreshness::Current { expires }
    } else {
        ArchivalFreshness::Lapsed { expires }
    })
}

/// Every archive timestamp among `attrs` that survives its checks, as tokens.
pub(super) fn archival_tokens(
    signed: &Signed,
    attrs: Vec<&x509_cert::attr::Attribute>,
) -> Vec<ArchiveToken> {
    let mut found = Vec::new();
    for attr in attrs {
        for value in attr.values.as_slice() {
            if let Some(token) = archival_token(
                value,
                crate::cades::ats::Enclosing::of(&signed.data),
                &signed.signer,
            ) {
                found.push(token);
            }
        }
    }
    found
}

/// The newest of several archive timestamps.
///
/// By `genTime`, with the authority certificate's expiry as the tie-break: a
/// renewal chain is a sequence of stamps each covering the one before, so the
/// newest carries the protection forward, and two stamped in the same second —
/// the old authority's and its replacement's, in a deployment that rotated — are
/// ordered by which outlasts the other rather than by whichever the `SET`
/// happened to encode first.
pub(super) fn newest_of(tokens: Vec<ArchiveToken>) -> Option<ArchiveToken> {
    tokens
        .into_iter()
        .max_by_key(|t| (t.stamp.gen_time, t.expires))
}

/// A verified archive timestamp, and when its authority's certificate ends.
pub(super) struct ArchiveToken {
    stamp: TimestampToken,
    expires: DateTime<Utc>,
}

/// The newest archive timestamp this seal carries that is **verifiably of this
/// seal** — the one a renewal would extend, and the one whose authority is
/// answerable for the protection `B-LTA` promises.
///
/// `Ok(None)` for a seal with no archive timestamp, and for one whose every
/// archive timestamp fails its checks: neither has anything to renew from, and
/// the distinction is [`archival_freshness`]'s to draw.
///
/// # Errors
///
/// [`SealError::Backend`] when the seal itself cannot be read.
pub fn newest_archive_timestamp(seal_der: &[u8]) -> Result<Option<TimestampToken>, SealError> {
    let signed = parse(seal_der)?;
    let Some(attrs) = signed.signer.unsigned_attrs.as_ref() else {
        return Ok(None);
    };
    let archival: Vec<_> = attrs
        .iter()
        .filter(|a| {
            a.oid == ID_AA_ETS_ARCHIVE_TIMESTAMP_V3 || a.oid == ID_AA_ETS_ARCHIVE_TIMESTAMP_V2
        })
        .collect();
    Ok(newest_of(archival_tokens(&signed, archival)).map(|t| t.stamp))
}

// ─── Renewing the archive timestamp ──────────────────────────────────────────

/// What an authority has to be asked to stamp, to renew a seal's archive
/// timestamp — and what that renewal has to beat.
///
/// Built by [`prepare_archive_renewal`]. Opaque outside this module for the same
/// reason [`TimestampToken`] is: the imprint and the index belong together, and a
/// caller that held them separately could stamp one and attach the other.
pub(crate) struct RenewalRequest {
    /// SHA-256, EN 319 122-1 clause 5.5.3, over the seal **as it stands now** —
    /// which is what makes the new stamp cover the old one.
    pub(crate) imprint: [u8; 32],
    index: crate::cades::ats::AtsHashIndexV3,
    /// When the newest archive timestamp's authority certificate ends — the date
    /// to beat.
    pub(crate) previous_expires: DateTime<Utc>,
    /// When that stamp says it was made. A renewal that claims an earlier moment
    /// has gone backwards in time.
    pub(crate) previous_gen_time: DateTime<Utc>,
}

pub(super) fn not_renewable(why: impl std::fmt::Display) -> SealError {
    SealError::Backend(format!("this seal cannot be renewed: {why}"))
}

/// The unsigned attributes of `signed`'s signer that are archive timestamps.
pub(super) fn archival_attrs(signed: &Signed) -> Vec<&x509_cert::attr::Attribute> {
    signed
        .signer
        .unsigned_attrs
        .as_ref()
        .map(|attrs| {
            attrs
                .iter()
                .filter(|a| {
                    a.oid == ID_AA_ETS_ARCHIVE_TIMESTAMP_V3
                        || a.oid == ID_AA_ETS_ARCHIVE_TIMESTAMP_V2
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Work out what to ask an authority to stamp so as to renew this seal.
///
/// # What a renewal is
///
/// ETSI's long-term profiles handle an expiring archive timestamp by
/// **re-timestamping**: a new `archive-time-stamp-v3` whose `ats-hash-index-v3`
/// names everything the seal carries *including the previous archive timestamp*,
/// so the new stamp covers the old one and the chain is unbroken. Nothing about
/// the signature changes and nothing is re-signed — this is why a renewal costs a
/// timestamp and not a seal, and why it needs no sealing key.
///
/// The index is built over the seal as it stands, which is the whole contract:
/// the clause asks for a hash of every instance present when the timestamp is
/// requested, and no others — so it must run after every other attribute is in
/// and before the new stamp is.
///
/// # What is refused
///
/// A seal with **no archive timestamp that verifies as this seal's** has nothing
/// to renew from. That is `B-LT` and below, which never promised long-term
/// protection, and it is also a seal whose only archive timestamp is a token lifted
/// from elsewhere — renewing that would carry forward protection that was never
/// there. And a seal signed under any digest but SHA-256: the clause ties the
/// imprint's algorithm to the signature's, and building one under a digest this
/// node does not hash with would be asking an authority to stamp a value nobody
/// here can recompute.
///
/// # Errors
///
/// [`SealError::Backend`] when the seal cannot be read or is not renewable.
pub(crate) fn prepare_archive_renewal(seal_der: &[u8]) -> Result<RenewalRequest, SealError> {
    let signed = parse(seal_der)?;
    if signed.signer.digest_alg.oid != const_oid::db::rfc5912::ID_SHA_256 {
        return Err(not_renewable(
            "it was signed under a digest other than SHA-256, and a renewal's imprint is built \
             under the signature's own digest",
        ));
    }
    let Some(newest) = newest_of(archival_tokens(&signed, archival_attrs(&signed))) else {
        return Err(not_renewable(
            "it carries no archive timestamp that verifies as a timestamp of this seal, so \
             there is no protection to carry forward",
        ));
    };

    let enclosing = crate::cades::ats::Enclosing::of(&signed.data);
    let index = crate::cades::ats::hash_index(enclosing, &signed.signer)?;
    let signed_data_hash =
        crate::cades::ats::signed_data_hash(&signed.signer, &index.hash_ind_algorithm)
            .ok_or_else(|| not_renewable("its signed-data hash cannot be recovered"))?;
    let imprint: [u8; 32] =
        crate::cades::ats::imprint(enclosing, &signed.signer, &signed_data_hash, &index)?
            .try_into()
            .map_err(|_| not_renewable("the imprint it asks for is not a SHA-256 value"))?;

    Ok(RenewalRequest {
        imprint,
        index,
        previous_expires: newest.expires,
        previous_gen_time: newest.stamp.gen_time(),
    })
}

/// A renewed seal, with the archive timestamp that renewed it.
pub(crate) struct Attached {
    pub(crate) seal_der: Vec<u8>,
    pub(crate) stamp: TimestampToken,
    /// When the new stamp's authority certificate ends.
    pub(crate) expires: DateTime<Utc>,
}

/// Attach an authority's token to the seal as its newest archive timestamp.
///
/// # The token is checked as an archive timestamp **of this seal** first
///
/// Before the seal is touched, the token — with the index added as its unsigned
/// attribute, which is where the clause puts it — is put through the very check
/// the audit applies to every stored seal: its own signature, its authority's
/// window, and that its imprint is the one clause 5.5.3 produces for *this*
/// signature. A token that fails any of them is an error and the seal is returned
/// unchanged, so a bad answer from an authority can never become what is stored.
///
/// It is the same function that reads a stored seal's archival state, not a copy
/// of it: a renewal and the audit that finds it due cannot come to disagree about
/// what a valid archive timestamp is.
///
/// # Errors
///
/// [`SealError::Backend`] when either structure cannot be read or the token does
/// not verify as an archive timestamp of this seal.
pub(crate) fn attach_archive_timestamp(
    seal_der: &[u8],
    request: &RenewalRequest,
    token_der: &[u8],
) -> Result<Attached, SealError> {
    use der::asn1::SetOfVec;

    let unusable = |what: &str, e: &dyn std::fmt::Display| {
        SealError::Backend(format!("cannot attach the archive timestamp: {what}: {e}"))
    };

    // The token, carrying the index the authority was not asked to stamp.
    let token_info =
        ContentInfo::from_der(token_der).map_err(|e| unusable("the token is not CMS", &e))?;
    let mut token_sd: SignedData = token_info
        .content
        .decode_as()
        .map_err(|e| unusable("the token is not SignedData", &e))?;
    let [token_signer] = token_sd.signer_infos.0.as_slice() else {
        return Err(unusable("the token has", &"other than one signer"));
    };
    let mut token_signer = token_signer.clone();
    let mut token_attrs = token_signer.unsigned_attrs.take().unwrap_or_default();
    let mut index_values = SetOfVec::new();
    index_values
        .insert(
            der::Any::encode_from(&request.index)
                .map_err(|e| unusable("the hash index does not encode", &e))?,
        )
        .map_err(|e| unusable("the hash index cannot be carried", &e))?;
    token_attrs
        .insert(x509_cert::attr::Attribute {
            oid: crate::cades::ats::ID_AA_ATS_HASH_INDEX_V3,
            values: index_values,
        })
        .map_err(|e| unusable("the hash index cannot be attached", &e))?;
    token_signer.unsigned_attrs = Some(token_attrs);
    let mut token_signers = SetOfVec::new();
    token_signers
        .insert(token_signer)
        .map_err(|e| unusable("the token's signer cannot be re-attached", &e))?;
    token_sd.signer_infos = cms::signed_data::SignerInfos::from(token_signers);
    let token = der::Any::encode_from(&ContentInfo {
        content_type: token_info.content_type,
        content: der::Any::encode_from(&token_sd)
            .map_err(|e| unusable("the token does not re-encode", &e))?,
    })
    .map_err(|e| unusable("the token does not re-encode", &e))?;

    // Checked against the seal exactly as it was stamped, before any change.
    let signed = parse(seal_der)?;
    let Some(verified) = archival_token(
        &token,
        crate::cades::ats::Enclosing::of(&signed.data),
        &signed.signer,
    ) else {
        return Err(SealError::Backend(
            "the authority's token does not verify as an archive timestamp of this seal — its \
             signature, its authority's validity window, or its imprint did not hold"
                .to_owned(),
        ));
    };

    // Now the seal: one more attribute, and nothing else touched. Every earlier
    // unsigned attribute stays exactly as it was, which is what the new index
    // vouches for.
    let info = ContentInfo::from_der(seal_der).map_err(|e| unusable("the seal is not CMS", &e))?;
    let mut sd: SignedData = info
        .content
        .decode_as()
        .map_err(|e| unusable("the seal is not SignedData", &e))?;
    let mut signer = signed.signer.clone();
    let mut attrs = signer.unsigned_attrs.take().unwrap_or_default();
    let mut values = SetOfVec::new();
    values
        .insert(token)
        .map_err(|e| unusable("the token cannot be carried", &e))?;
    attrs
        .insert(x509_cert::attr::Attribute {
            oid: ID_AA_ETS_ARCHIVE_TIMESTAMP_V3,
            values,
        })
        .map_err(|e| unusable("the archive timestamp cannot be attached", &e))?;
    signer.unsigned_attrs = Some(attrs);
    let mut signers = SetOfVec::new();
    signers
        .insert(signer)
        .map_err(|e| unusable("the seal's signer cannot be re-attached", &e))?;
    sd.signer_infos = cms::signed_data::SignerInfos::from(signers);

    let renewed = ContentInfo {
        content_type: info.content_type,
        content: der::Any::encode_from(&sd)
            .map_err(|e| unusable("the seal does not re-encode", &e))?,
    }
    .to_der()
    .map_err(|e| unusable("the seal does not re-encode", &e))?;

    Ok(Attached {
        seal_der: renewed,
        stamp: verified.stamp,
        expires: verified.expires,
    })
}

/// What a time-stamp token says about itself, once its own signature holds.
pub(crate) struct TokenFacts {
    pub(crate) hash_algorithm: const_oid::ObjectIdentifier,
    pub(crate) imprint: Vec<u8>,
    /// The `nonce`, as minimal unsigned big-endian bytes.
    pub(crate) nonce: Option<Vec<u8>>,
}

/// Read a bare RFC 3161 token — checking only that it is what it says it is.
///
/// For the layer that talks to an authority and has to confirm it was answered:
/// the token's own signature, and the digest binding that signature to its
/// `TSTInfo`, are verified before anything is read out of it. What this does
/// **not** check is whether the token is a timestamp of anything in particular, or
/// when, or by whom — those belong to whoever knows what was asked.
///
/// `None` for anything that is not a well-formed, self-consistent token.
pub(crate) fn token_facts(token_der: &[u8]) -> Option<TokenFacts> {
    let token = parse(token_der).ok()?;
    if !signature_holds(&token).unwrap_or(false) {
        return None;
    }
    let content = token.econtent.as_ref()?;
    if !digest_matches(&token, content) {
        return None;
    }
    let info = TstInfo::from_der(content).ok()?;
    Some(TokenFacts {
        hash_algorithm: info.message_imprint.hash_algorithm.oid,
        imprint: info.message_imprint.hashed_message.as_bytes().to_vec(),
        nonce: info.nonce.map(|n| n.as_bytes().to_vec()),
    })
}

/// One archive timestamp that survived its checks.
///
/// `None` when the token cannot be read or its signature does not hold — a
/// token that failed its check must not contribute a date.
pub(super) fn archival_token(
    value: &der::Any,
    enclosing: crate::cades::ats::Enclosing<'_>,
    archived: &cms::signed_data::SignerInfo,
) -> Option<ArchiveToken> {
    let token_der = value.to_der().ok()?;
    let token = parse(&token_der).ok()?;
    if !signature_holds(&token).unwrap_or(false) {
        return None;
    }
    if !archives(&token, enclosing, archived) {
        return None;
    }
    let content = token.econtent.as_ref()?;
    if !digest_matches(&token, content) {
        return None;
    }
    let info = TstInfo::from_der(content).ok()?;

    let made_at = info.gen_time.0;
    // The same rule the signature timestamp uses. Here it also keeps the two
    // halves of this answer consistent: `expires` below is read off the very
    // certificate being checked, so a token stamped outside that window would
    // have this seal reported as archived until a date its own authority could
    // not have vouched for.
    if !stamped_within_its_certificate(&token, made_at) {
        return None;
    }
    let expires = to_utc(
        token
            .certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
    )?;
    Some(ArchiveToken {
        stamp: TimestampToken {
            token,
            gen_time: made_at,
        },
        expires,
    })
}

/// Whether this token is an archive timestamp **of this signature**.
///
/// ✅ COMPLIANCE-PIN: ETSI EN 319 122-1 V1.3.1, clauses 5.5.2 and 5.5.3.
///
/// A token's own signature holding proves it is a genuine timestamp. It proves
/// nothing about *what* it timestamps — and an unsigned attribute is exactly
/// where a token lifted from another seal can be pasted, since nothing in the
/// enclosing signature covers it. Without this, a well-formed foreign token
/// reports this passport as archived until that other seal's authority
/// certificate expires.
///
/// Three things have to hold, and each closes a different substitution:
///
/// 1. **the token carries an `ats-hash-index-v3`** — without it there is nothing
///    to recompute the imprint from, so the binding cannot be checked at all and
///    the honest answer is no;
/// 2. **everything the index claims is actually here** — `claimed ⊆ present`.
///    An index naming a value the signature does not carry is invalid by the
///    clause's own words, which is what stops one claiming to protect material
///    that was removed after stamping. The reverse is deliberately allowed: an
///    unindexed value is simply unprotected, and the clause exists so that later
///    additions — this archive timestamp among them — do not invalidate it;
/// 3. **the imprint is the one the concatenation produces** — which is what ties
///    the index, the signature's own fields and the signed data together.
///
/// Returns `false` rather than an error throughout: a token that cannot be tied
/// to this seal is not a malformed seal, it is a token that does not belong, and
/// the caller's job is to ignore it rather than to fail.
pub(super) fn archives(
    token: &Signed,
    enclosing: crate::cades::ats::Enclosing<'_>,
    archived: &cms::signed_data::SignerInfo,
) -> bool {
    let Some(attrs) = token.signer.unsigned_attrs.as_ref() else {
        return false;
    };
    let Some(attr) = attrs
        .iter()
        .find(|a| a.oid == crate::cades::ats::ID_AA_ATS_HASH_INDEX_V3)
    else {
        return false;
    };
    let Some(value) = attr.values.as_slice().first() else {
        return false;
    };
    let Ok(der) = value.to_der() else {
        return false;
    };
    let Ok(index) = crate::cades::ats::AtsHashIndexV3::from_der(der.as_slice()) else {
        return false;
    };

    if !crate::cades::ats::index_is_satisfied(enclosing, archived, &index) {
        return false;
    }

    // Step 2 of the concatenation. Detached, so this comes from the
    // `message-digest` signed attribute — which is only the same value when the
    // archive timestamp hashed with the algorithm the signature did.
    let Some(signed_data_hash) =
        crate::cades::ats::signed_data_hash(archived, &index.hash_ind_algorithm)
    else {
        return false;
    };
    let Ok(expected) = crate::cades::ats::imprint(enclosing, archived, &signed_data_hash, &index)
    else {
        return false;
    };

    token
        .econtent
        .as_ref()
        .and_then(|c| TstInfo::from_der(c).ok())
        .is_some_and(|info| {
            // The clause ties the two together: the index's algorithm is the one
            // the timestamp's imprint was computed under. Comparing the digest
            // bytes without checking that would accept a token whose own
            // metadata says it hashed with something else — the bytes would
            // match and the token would be describing a different computation.
            info.message_imprint.hash_algorithm.oid == index.hash_ind_algorithm.oid
                && info.message_imprint.hashed_message.as_bytes() == expected
        })
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
