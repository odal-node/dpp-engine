//! `archive-time-stamp-v3`, built and checked the way the standard specifies.
//!
//! ✅ COMPLIANCE-PIN: ETSI EN 319 122-1 V1.3.1, clauses 5.5.2 and 5.5.3.
//!
//! # What this closes
//!
//! An archive timestamp's own signature holding says the token is genuine. It
//! says **nothing about which signature it archives**. Without the computation
//! below, a well-formed token lifted from another seal — internally consistent,
//! signed by a real authority, protecting something else entirely — is accepted,
//! and the seal it was pasted into reports archival protection it does not have.
//!
//! The imprint is what binds the two, and it is not a single field: clause 5.5.3
//! builds it from a concatenation over the `SignedData`, and clause 5.5.2 adds an
//! index naming exactly which certificates, CRLs and unsigned attribute values
//! were covered — so that material added later does not invalidate the stamp.
//! Both have to exist for either to mean anything.
//!
//! # The concatenation, in order
//!
//! Clause 5.5.3 takes the signed-data hash as **raw octets** and every other
//! component in its binary encoded form **including tag, length and value**:
//!
//! 1. `SignedData.encapContentInfo.eContentType`;
//! 2. the hash of the signed data — the same content the `message-digest` signed
//!    attribute hashed, under the archive timestamp's own hash algorithm;
//! 3. `version`, `sid`, `digestAlgorithm`, `signedAttrs`, `signatureAlgorithm`
//!    and `signature` from the `SignerInfo` being archived, in that order;
//! 4. one `ATSHashIndexV3`.
//!
//! # Detached signatures, which is all this workspace produces
//!
//! Step 2 wants the hash of content a detached signature does not carry. The
//! clause anticipates this and allows the hash to come from an external trusted
//! source — but it does not have to here, because the `message-digest` signed
//! attribute already *is* that hash, and it is inside the signature.
//!
//! That holds **only while the archive timestamp and the signature use the same
//! hash algorithm**, which is what the clause requires of step 2 and of the
//! index. When they differ the value cannot be recomputed from the signature
//! alone, and [`signed_data_hash`] says so rather than substituting the one it
//! has.

use cms::signed_data::{SignedData, SignerInfo};
use const_oid::ObjectIdentifier;
use der::{Decode as _, Encode, asn1::OctetString};
use sha2::{Digest as _, Sha256};
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::error::SealError;

/// `id-aa-ATSHashIndex-v3`, from the standard's annex D.
pub(crate) const ID_AA_ATS_HASH_INDEX_V3: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.19122.1.5");

/// `ATSHashIndexV3`, clause 5.5.2.
///
/// ```text
/// ATSHashIndexV3 ::= SEQUENCE {
///     hashIndAlgorithm            AlgorithmIdentifier,
///     certificatesHashIndex       SEQUENCE OF OCTET STRING,
///     crlsHashIndex               SEQUENCE OF OCTET STRING,
///     unsignedAttrValuesHashIndex SEQUENCE OF OCTET STRING }
/// ```
///
/// The last field is per **attribute value**, not per attribute: one entry for
/// every `AttributeValue` in every `Attribute`. That is the v3 change, and it is
/// what lets a later attribute — another archive timestamp, a counter signature
/// — be added without invalidating this one.
#[derive(der::Sequence, Debug, Clone, PartialEq, Eq)]
pub(crate) struct AtsHashIndexV3 {
    pub hash_ind_algorithm: AlgorithmIdentifierOwned,
    pub certificates_hash_index: Vec<OctetString>,
    pub crls_hash_index: Vec<OctetString>,
    pub unsigned_attr_values_hash_index: Vec<OctetString>,
}

fn sha256_of(bytes: &[u8]) -> Result<OctetString, SealError> {
    OctetString::new(Sha256::digest(bytes).as_slice())
        .map_err(|e| SealError::Config(format!("cannot encode a hash index entry: {e}")))
}

fn der_of<T: Encode>(what: &str, value: &T) -> Result<Vec<u8>, SealError> {
    value
        .to_der()
        .map_err(|e| SealError::Config(format!("cannot encode {what}: {e}")))
}

/// SHA-256, the only algorithm this module builds indexes with.
pub(crate) fn sha256_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    }
}

/// The parts of a `SignedData` an archive timestamp is computed over.
///
/// Taken as pieces rather than as an assembled `SignedData` because the two
/// callers hold it at opposite moments: a reader has parsed one, and the sealer
/// is still building it — the signer's unsigned attributes cannot be finished
/// until the index exists, and the index cannot be built until the certificates
/// and revocation material are. Threading the pieces keeps one implementation
/// for both instead of one for each, which is the only way they stay in
/// agreement.
#[derive(Clone, Copy)]
pub(crate) struct Enclosing<'a> {
    pub econtent_type: &'a ObjectIdentifier,
    pub certificates: Option<&'a cms::signed_data::CertificateSet>,
    pub crls: Option<&'a cms::revocation::RevocationInfoChoices>,
}

impl<'a> Enclosing<'a> {
    /// The pieces, read off a parsed signature.
    pub(crate) fn of(signed_data: &'a SignedData) -> Self {
        Self {
            econtent_type: &signed_data.encap_content_info.econtent_type,
            certificates: signed_data.certificates.as_ref(),
            crls: signed_data.crls.as_ref(),
        }
    }
}

/// Build the index over a signature as it stands right now.
///
/// "As it stands" is the whole contract: the clause asks for a hash for **every**
/// instance present when the archive timestamp is requested, and no others. So
/// this must run after every other unsigned attribute has been attached and
/// before the archive timestamp itself is — an archive timestamp cannot index
/// itself.
pub(crate) fn hash_index(
    enclosing: Enclosing<'_>,
    signer: &SignerInfo,
) -> Result<AtsHashIndexV3, SealError> {
    let mut certificates_hash_index = Vec::new();
    if let Some(certs) = enclosing.certificates {
        for choice in certs.0.iter() {
            certificates_hash_index.push(sha256_of(&der_of("a certificate", choice)?)?);
        }
    }

    let mut crls_hash_index = Vec::new();
    if let Some(crls) = enclosing.crls {
        for choice in crls.0.iter() {
            crls_hash_index.push(sha256_of(&der_of("a revocation entry", choice)?)?);
        }
    }

    // One entry per attribute *value*, each over the concatenation of the
    // attribute's type and that one value — both as full DER, tag and length
    // included.
    let mut unsigned_attr_values_hash_index = Vec::new();
    if let Some(attrs) = signer.unsigned_attrs.as_ref() {
        for attr in attrs.iter() {
            let oid = der_of("an unsigned attribute's type", &attr.oid)?;
            for value in attr.values.as_slice() {
                let mut input = oid.clone();
                input.extend_from_slice(&der_of("an unsigned attribute's value", value)?);
                unsigned_attr_values_hash_index.push(sha256_of(&input)?);
            }
        }
    }

    Ok(AtsHashIndexV3 {
        hash_ind_algorithm: sha256_alg(),
        certificates_hash_index,
        crls_hash_index,
        unsigned_attr_values_hash_index,
    })
}

/// Whether every entry in `index` corresponds to something that is actually here.
///
/// 🚨 **Containment, not equality**, and the difference is the whole design of
/// the attribute. Recomputing the index and comparing wholesale looks stricter
/// and is simply wrong: the index lists what was present *when the timestamp was
/// requested*, and the clause exists precisely so that material added afterwards
/// — another archive timestamp, a counter signature, later revocation data —
/// does not invalidate it. The archive timestamp is itself such an addition, so
/// an equality check fails on the very signature it was built for. That is not a
/// hypothesis: it is what the round-trip test reported first.
///
/// What the clause does forbid is an entry with **no** corresponding value: an
/// index may not refer to something that is not here, because that is how an
/// index would claim to protect material that was removed after stamping.
///
/// So: everything indexed must be present. Not everything present need be
/// indexed — and what is not indexed is simply not protected, which is what the
/// caller's imprint check then settles.
pub(crate) fn index_is_satisfied(
    enclosing: Enclosing<'_>,
    signer: &SignerInfo,
    index: &AtsHashIndexV3,
) -> bool {
    let Ok(present) = hash_index(enclosing, signer) else {
        return false;
    };
    let covered = |claimed: &Vec<OctetString>, here: &Vec<OctetString>| {
        claimed.iter().all(|c| here.contains(c))
    };
    covered(
        &index.certificates_hash_index,
        &present.certificates_hash_index,
    ) && covered(&index.crls_hash_index, &present.crls_hash_index)
        && covered(
            &index.unsigned_attr_values_hash_index,
            &present.unsigned_attr_values_hash_index,
        )
}

/// `signedAttrs` as it appears **inside** `SignerInfo`.
///
/// 🚨 Not the same bytes the signature was computed over. RFC 5652 §5.4 signs
/// the `SET OF` encoding, while the field inside `SignerInfo` is `[0] IMPLICIT`
/// — and the clause asks for the field "without any modification".
///
/// Implicit tagging changes the tag octet and nothing else, so the conversion is
/// exactly that one byte. It is done by rewriting rather than re-encoding
/// because re-encoding is what the clause forbids, and it is asserted rather
/// than assumed: a `SET OF` that did not start with `0x31` would mean this
/// understanding is wrong, and silently shipping the wrong bytes would produce
/// an imprint that agrees with nothing.
fn signed_attrs_as_in_signer_info(signer: &SignerInfo) -> Result<Vec<u8>, SealError> {
    let attrs = signer.signed_attrs.as_ref().ok_or_else(|| {
        SealError::Config("the signature carries no signed attributes".to_owned())
    })?;
    let mut der = der_of("the signed attributes", attrs)?;
    match der.first() {
        Some(0x31) => {
            der[0] = 0xA0;
            Ok(der)
        }
        other => Err(SealError::Config(format!(
            "the signed attributes encode with tag {other:?} rather than SET OF, so the \
             [0] IMPLICIT form the clause asks for cannot be derived from them"
        ))),
    }
}

/// The hash of the signed data for step 2, read out of the signature.
///
/// The `message-digest` signed attribute already holds the hash of the content,
/// so a detached signature needs no external source — **provided** the archive
/// timestamp hashes with the same algorithm the signature did. `archive_hash` is
/// that algorithm; when it is not the signature's, this returns `None` rather
/// than handing back a digest computed under a different one.
pub(crate) fn signed_data_hash(
    signer: &SignerInfo,
    archive_hash: &AlgorithmIdentifierOwned,
) -> Option<Vec<u8>> {
    if archive_hash.oid != signer.digest_alg.oid {
        return None;
    }
    let attrs = signer.signed_attrs.as_ref()?;
    let attr = attrs
        .iter()
        .find(|a| a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST)?;
    let value = attr.values.as_slice().first()?;
    OctetString::from_der(&value.to_der().ok()?)
        .ok()
        .map(|o| o.as_bytes().to_vec())
}

/// The clause 5.5.3 message imprint input, in order.
pub(crate) fn imprint_input(
    enclosing: Enclosing<'_>,
    signer: &SignerInfo,
    signed_data_hash: &[u8],
    index: &AtsHashIndexV3,
) -> Result<Vec<u8>, SealError> {
    let mut out = Vec::new();
    // 1
    out.extend_from_slice(&der_of("the content type", enclosing.econtent_type)?);
    // 2 — raw octets, the one component not in TLV form.
    out.extend_from_slice(signed_data_hash);
    // 3 — in the order the clause lists, which is their order of appearance.
    out.extend_from_slice(&der_of("the signer version", &signer.version)?);
    out.extend_from_slice(&der_of("the signer identifier", &signer.sid)?);
    out.extend_from_slice(&der_of("the digest algorithm", &signer.digest_alg)?);
    out.extend_from_slice(&signed_attrs_as_in_signer_info(signer)?);
    out.extend_from_slice(&der_of(
        "the signature algorithm",
        &signer.signature_algorithm,
    )?);
    out.extend_from_slice(&der_of("the signature", &signer.signature)?);
    // 4
    out.extend_from_slice(&der_of("the hash index", index)?);
    Ok(out)
}

/// The imprint an archive timestamp over this signature must carry.
pub(crate) fn imprint(
    enclosing: Enclosing<'_>,
    signer: &SignerInfo,
    signed_data_hash: &[u8],
    index: &AtsHashIndexV3,
) -> Result<Vec<u8>, SealError> {
    Ok(Sha256::digest(imprint_input(enclosing, signer, signed_data_hash, index)?).to_vec())
}
