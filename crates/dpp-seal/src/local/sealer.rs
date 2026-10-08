//! A real detached CMS `SignedData` over the payload digest, signed locally.
//!
//! # What this is, and what it is not
//!
//! It **is** a genuine CMS signature: the bytes verify against the certificate,
//! the structure is what a provider returns, and every stage of the pipeline
//! that handles a seal handles this one identically. The digest travels in
//! `signedAttrs`, as CAdES requires, so the envelope is self-checking — a holder
//! of the bytes alone can confirm the signature, which is what lets this backend
//! answer `verify()` when the hosted one cannot.
//!
//! It is **not** qualified, and cannot become so. The certificate is
//! self-signed and on no EU Trusted List, which is a property of the
//! certificate rather than of this code — nothing in the signing or
//! verification path differs between a self-signed key and a QTSP-held one.
//! What differs is the legal weight, which is none. The node reflects that by
//! resolving this backend's trust tier to `Ghost`, so a production profile
//! refuses to boot on it.
//!
//! A second, narrower limit worth stating: the OpenID4VC High Assurance
//! Interoperability Profile requires that an issuer's signing certificate
//! **not** be self-signed. So this backend can never stand in for a real issuer
//! in a conformant credential flow, however complete the pipeline around it is.

use std::path::Path;

use async_trait::async_trait;
use base64::Engine as _;
use chrono::Utc;
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedAttributes,
    SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::db::rfc5911::ID_DATA;
use der::{Any, Decode as _, Encode};
use dpp_domain::seal::{
    SealCapabilities, SealChecks, SealConformanceLevel, SealEnvelope, SealFormat, SealMode,
    SealRequest, SealVerification, SealedEnvelope,
};
use p256::ecdsa::{DerSignature, SigningKey};
use x509_cert::Certificate;
use x509_cert::attr::Attribute;

use cms::revocation::{RevocationInfoChoice, RevocationInfoChoices};

use crate::backend::SealBackend;
use crate::error::SealError;

/// A locally generated signing identity: one key, one self-signed certificate.
pub struct LocalIdentity {
    key: SigningKey,
    cert: Certificate,
    cert_der: Vec<u8>,
    /// The authority that timestamps this node's own seals.
    ///
    /// Held here rather than built per seal because its certificate has to stay
    /// the same across restarts: a token issued yesterday refers to it.
    tsa: super::timestamp::LocalTsa,
}

impl LocalIdentity {
    /// Load the identity at `dir`, generating it on first use.
    ///
    /// Persisted rather than regenerated per boot: a seal produced yesterday
    /// must still verify against the same certificate today. A restart that
    /// silently invalidated every seal it had produced would teach the wrong
    /// thing about how seals behave.
    pub fn load_or_create(dir: &Path) -> Result<Self, SealError> {
        let key_path = dir.join("seal-key.pkcs8.der");
        let cert_path = dir.join("seal-cert.der");

        if key_path.exists() && cert_path.exists() {
            let key_der = std::fs::read(&key_path).map_err(io_err("read the local seal key"))?;
            let cert_der =
                std::fs::read(&cert_path).map_err(io_err("read the local seal certificate"))?;
            return Self::from_der(
                &key_der,
                cert_der,
                super::timestamp::LocalTsa::load_or_create(dir)?,
            );
        }

        let (key_der, cert_der) = generate()?;
        std::fs::create_dir_all(dir).map_err(io_err("create the local seal directory"))?;
        std::fs::write(&key_path, &key_der).map_err(io_err("write the local seal key"))?;
        std::fs::write(&cert_path, &cert_der)
            .map_err(io_err("write the local seal certificate"))?;
        let tsa = super::timestamp::LocalTsa::load_or_create(dir)?;
        Self::from_der(&key_der, cert_der, tsa)
    }

    fn from_der(
        key_der: &[u8],
        cert_der: Vec<u8>,
        tsa: super::timestamp::LocalTsa,
    ) -> Result<Self, SealError> {
        use p256::pkcs8::DecodePrivateKey as _;
        let key = SigningKey::from_pkcs8_der(key_der)
            .map_err(|e| SealError::Config(format!("local seal key is not a P-256 PKCS#8: {e}")))?;
        let cert = Certificate::from_der(cert_der.as_slice()).map_err(|e| {
            SealError::Config(format!("local seal certificate is not valid DER: {e}"))
        })?;
        Ok(Self {
            key,
            cert,
            cert_der,
            tsa,
        })
    }

    /// SHA-256 of the certificate, as the envelope's `signing_cert_ref`.
    pub fn cert_thumbprint(&self) -> String {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(&self.cert_der))
    }

    /// Produce a **detached** CMS `SignedData` over `digest`.
    ///
    /// Detached is the point: `eContent` is absent, so the signature travels
    /// separately from what it covers — the same arrangement a provider returns
    /// and the same one the passport's `jwsSignature` expects.
    pub fn sign_detached(&self, digest: &[u8]) -> Result<Vec<u8>, SealError> {
        self.sign_detached_at(digest, SealConformanceLevel::BaselineB)
    }

    /// Produce a detached CMS `SignedData` over `digest`, at `level`.
    ///
    /// # What each level adds, and where the requirement comes from
    ///
    /// ETSI EN 319 122-1 V1.3.1 Table 1, read directly:
    ///
    /// - **B-B** — `SignedData.certificates` shall be present. Nothing else.
    /// - **B-T** — a `signature-time-stamp` unsigned attribute *shall* be
    ///   present, computed over the signature (clause 5.3).
    /// - **B-LT** — revocation material for long-term validation *shall be
    ///   provided*, in `SignedData.crls`. Note the table also says the older
    ///   `certificate-values` and `revocation-values` attributes **shall not be
    ///   present** at this level, so this deliberately does not emit them.
    /// - **B-LTA** — an `archive-time-stamp-v3` *shall be provided*
    ///   (clause 5.5.3).
    ///
    /// Cumulative, because the table is: an `B-LTA` signature carries
    /// everything the levels below it carry.
    ///
    /// # This is a faithful shape, not a conformant signature
    ///
    /// The attributes are real, well-formed and really signed, which is what
    /// lets every path in this workspace that reads a seal be exercised against
    /// something other than a stub.
    ///
    /// The `archive-time-stamp-v3` **is** built the way clause 5.5.3 specifies —
    /// the full concatenation, with an `ats-hash-index-v3` inside the token — and
    /// it did not used to be. Two departures were documented here instead: the
    /// imprint taken over the signer's encoded form, and no index at all. They
    /// were reasonable while nothing read them, on the argument that conformance
    /// is wasted on a validator that rejects this self-signed certificate on its
    /// first check.
    ///
    /// What changed the argument is that **the reader in this workspace is that
    /// validator**. `cades::archival_freshness` now checks the binding, and a
    /// token that is not built to the clause cannot be told from one lifted out
    /// of a different seal. Left as it was, this backend would have produced
    /// seals its own node correctly reported as unarchived — so the departure
    /// stopped being a shortcut and became the thing under test.
    ///
    /// What remains not conformant is the certificate, which is the part that
    /// cannot be fixed from here: self-signed, on no Trusted List, of no legal
    /// weight whatsoever.
    pub fn sign_detached_at(
        &self,
        digest: &[u8],
        level: SealConformanceLevel,
    ) -> Result<Vec<u8>, SealError> {
        use der::asn1::{OctetString, SetOfVec};
        use p256::ecdsa::signature::Signer as _;

        // Assembled from `cms`'s own types rather than its `builder` feature.
        // That feature depends unconditionally on `rsa`, which carries
        // RUSTSEC-2023-0071 with no fixed upgrade; we sign with P-256 and have
        // no use for RSA, so the dependency would be pure advisory surface on
        // the one crate that produces seals.
        //
        // Detached: `eContent` is absent, so what was signed travels separately
        // from the signature — the arrangement a provider returns. The *digest*
        // does travel, in `signedAttrs` below; that is what detached CAdES does,
        // and it is the difference between a seal that can be checked and one
        // that cannot.
        let econtent = EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: None,
        };

        let digest_algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };

        // Signed attributes carry the digest *inside* the signature, which is
        // what makes the seal checkable at all. With `signedAttrs` absent the
        // signature covers the digest directly, and a verifier holding only the
        // envelope — which is all `SealPort::verify` is given — has no way to
        // reconstruct what was signed. Attaching `messageDigest` is also what
        // CAdES requires, so this is the faithful shape rather than a
        // concession.
        let signed_attrs = signed_attributes(ID_DATA, digest)?;

        // RFC 5652 §5.4: the signature is computed over the DER **SET OF**
        // encoding of the signed attributes, not over the `[0] IMPLICIT` form
        // they take inside `SignerInfo`. Encoding the wrong one produces a
        // signature that verifies nowhere, including here.
        let to_sign = signed_attrs
            .to_der()
            .map_err(|e| SealError::Config(format!("cannot encode the signed attributes: {e}")))?;
        let signature: DerSignature = self.key.sign(&to_sign);

        let signer_info = SignerInfo {
            version: cms::content_info::CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: self.cert.tbs_certificate.issuer.clone(),
                serial_number: self.cert.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: digest_algorithm.clone(),
            signed_attrs: Some(signed_attrs),
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                parameters: None,
            },
            signature: OctetString::new(signature.to_bytes().as_ref())
                .map_err(|e| SealError::Config(format!("cannot encode the signature: {e}")))?,
            unsigned_attrs: None,
        };
        let mut digest_algorithms = SetOfVec::new();
        digest_algorithms
            .insert(digest_algorithm)
            .map_err(|e| SealError::Config(format!("cannot record the digest algorithm: {e}")))?;

        let mut certs = SetOfVec::new();
        certs
            .insert(CertificateChoices::Certificate(self.cert.clone()))
            .map_err(|e| SealError::Config(format!("cannot attach the certificate: {e}")))?;
        // From B-T upward the seal carries a timestamp, and EN 319 122-1
        // requires a verifier to be able to build a path for every timestamp in
        // it. A token whose signing certificate travels nowhere is unverifiable
        // by anyone but the node that made it.
        if level.survives_certificate_expiry() || level == SealConformanceLevel::BaselineT {
            certs
                .insert(CertificateChoices::Certificate(
                    self.tsa.certificate().clone(),
                ))
                .map_err(|e| {
                    SealError::Config(format!("cannot attach the TSA certificate: {e}"))
                })?;
        }

        // The certificates and revocation material are settled before the
        // unsigned attributes are attached, because an `archive-time-stamp-v3`
        // indexes them: its `ats-hash-index-v3` carries a hash of every
        // `CertificateChoices` and `RevocationInfoChoice` present when the
        // timestamp is requested. Attaching the timestamp first would index a
        // `SignedData` that does not exist yet.
        let certificates = CertificateSet::from(certs);
        let crls = self.revocation_material(level)?;
        let signer_info = self.at_level(
            signer_info,
            level,
            crate::cades::ats::Enclosing {
                econtent_type: &econtent.econtent_type,
                certificates: Some(&certificates),
                crls: crls.as_ref(),
            },
        )?;

        let mut signer_infos = SetOfVec::new();
        signer_infos
            .insert(signer_info)
            .map_err(|e| SealError::Config(format!("cannot attach the signer info: {e}")))?;

        let signed_data = SignedData {
            version: cms::content_info::CmsVersion::V1,
            digest_algorithms: DigestAlgorithmIdentifiers::from(digest_algorithms),
            encap_content_info: econtent,
            certificates: Some(certificates),
            crls,
            signer_infos: SignerInfos::from(signer_infos),
        };

        let info = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::encode_from(&signed_data)
                .map_err(|e| SealError::Config(format!("cannot encode the SignedData: {e}")))?,
        };
        info.to_der()
            .map_err(|e| SealError::Config(format!("cannot DER-encode the seal: {e}")))
    }
}

impl LocalIdentity {
    /// `id-aa-signatureTimeStampToken` — RFC 5126 §6.1.1, EN 319 122-1 cl. 5.3.
    const ID_AA_SIGNATURE_TIME_STAMP_TOKEN: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

    /// `id-aa-ets-archiveTimestampV3` — EN 319 122-1 cl. 5.5.3, annex D.
    const ID_AA_ETS_ARCHIVE_TIMESTAMP_V3: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("0.4.0.1733.2.4");

    /// Attach the unsigned attributes `level` requires to `signer`.
    ///
    /// The archive timestamp is applied **after** the signature timestamp and
    /// over a signer that already carries it, which is the ordering EN 319 122-1
    /// clause 5.5.3 describes: the archive timestamp protects the signature
    /// *including* the material added to it, so applying it first would leave
    /// the timestamp it is supposed to cover outside its imprint.
    fn at_level(
        &self,
        signer: SignerInfo,
        level: SealConformanceLevel,
        enclosing: crate::cades::ats::Enclosing<'_>,
    ) -> Result<SignerInfo, SealError> {
        use sha2::{Digest as _, Sha256};

        if level == SealConformanceLevel::BaselineB {
            return Ok(signer);
        }

        // Clause 5.3: computed on the signature field *without* its ASN.1 tag
        // and length — the value octets alone. Taken before the signer is moved,
        // because the imprint is over the signature as it stands *now*: an
        // attribute added first would not change it, but reading it afterwards
        // would invite exactly that mistake.
        let imprint = Sha256::digest(signer_signature_value(&signer));
        let mut signer =
            self.with_attribute(signer, Self::ID_AA_SIGNATURE_TIME_STAMP_TOKEN, &imprint, 1)?;

        if level == SealConformanceLevel::BaselineLta {
            // The index is built here, over a signer that already carries the
            // signature timestamp and before the archive timestamp is attached.
            // That ordering is the clause's: the index covers every unsigned
            // attribute value *present when the archive timestamp is requested*,
            // and an archive timestamp cannot index itself.
            let index = crate::cades::ats::hash_index(enclosing, &signer)?;

            // Step 2 of the concatenation. Detached, so the hash of the signed
            // data is not in the envelope — but the `message-digest` signed
            // attribute is that hash, and the archive timestamp uses the same
            // algorithm the signature did, which is the condition that makes
            // reading it sound.
            let signed_data_hash =
                crate::cades::ats::signed_data_hash(&signer, &crate::cades::ats::sha256_alg())
                    .ok_or_else(|| {
                        SealError::Config(
                            "cannot read the signed-data hash for the archive timestamp: the \
                         message-digest attribute is absent or was computed under a different \
                         algorithm"
                                .to_owned(),
                        )
                    })?;

            let imprint =
                crate::cades::ats::imprint(enclosing, &signer, &signed_data_hash, &index)?;
            signer = self.with_archive_timestamp(signer, &imprint, 2, &index)?;
        }

        Ok(signer)
    }

    /// `signer` with one more unsigned attribute carrying a time-stamp token.
    fn with_attribute(
        &self,
        signer: SignerInfo,
        oid: const_oid::ObjectIdentifier,
        imprint: &[u8],
        serial: u64,
    ) -> Result<SignerInfo, SealError> {
        use der::asn1::SetOfVec;

        let mut values = SetOfVec::new();
        values
            .insert(self.tsa.token(imprint, serial, None)?)
            .map_err(|e| SealError::Config(format!("cannot build the timestamp attribute: {e}")))?;

        Self::attach(signer, oid, values)
    }

    /// `signer` with an `archive-time-stamp-v3` carrying its `ats-hash-index-v3`.
    ///
    /// The index goes **inside the token**, as an unsigned attribute of the
    /// token's own CMS signature — which is where the clause puts it, and it is
    /// the placement that makes it useful: a verifier needs the index to
    /// recompute the imprint, and an index outside the token could be swapped
    /// without disturbing anything the timestamp authority signed.
    fn with_archive_timestamp(
        &self,
        signer: SignerInfo,
        imprint: &[u8],
        serial: u64,
        index: &crate::cades::ats::AtsHashIndexV3,
    ) -> Result<SignerInfo, SealError> {
        use der::asn1::SetOfVec;

        let mut values = SetOfVec::new();
        values
            .insert(self.tsa.token(imprint, serial, Some(index))?)
            .map_err(|e| SealError::Config(format!("cannot build the archive timestamp: {e}")))?;

        Self::attach(signer, Self::ID_AA_ETS_ARCHIVE_TIMESTAMP_V3, values)
    }

    /// `signer` with one more unsigned attribute.
    fn attach(
        mut signer: SignerInfo,
        oid: const_oid::ObjectIdentifier,
        values: der::asn1::SetOfVec<Any>,
    ) -> Result<SignerInfo, SealError> {
        use der::asn1::SetOfVec;

        let mut attrs = signer
            .unsigned_attrs
            .take()
            .map(|a| a.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        attrs.push(Attribute { oid, values });

        let mut set = SetOfVec::new();
        for a in attrs {
            set.insert(a).map_err(|e| {
                SealError::Config(format!("cannot collect unsigned attributes: {e}"))
            })?;
        }
        signer.unsigned_attrs = Some(set);
        Ok(signer)
    }

    /// The revocation material `level` requires, in the home EN 319 122-1 names.
    ///
    /// `SignedData.crls`, and **not** the `revocation-values` unsigned
    /// attribute: Table 1 marks that older home "shall not be present" at B-LT
    /// and B-LTA. `cades::evidenced_level` accepts either because a seal bought
    /// under the superseded profile is still lawful; a seal *produced* here has
    /// no such excuse.
    ///
    /// The list is empty, which is the truthful statement — this node has
    /// revoked nothing — rather than a placeholder entry that would claim a
    /// revocation that never happened.
    fn revocation_material(
        &self,
        level: SealConformanceLevel,
    ) -> Result<Option<RevocationInfoChoices>, SealError> {
        use der::asn1::{BitString, SetOfVec};
        use p256::ecdsa::signature::Signer as _;

        if !level.survives_certificate_expiry() {
            return Ok(None);
        }

        let algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| SealError::Config(format!("the clock is before 1970: {e}")))?;

        let tbs = x509_cert::crl::TbsCertList {
            version: x509_cert::Version::V2,
            signature: algorithm.clone(),
            // Self-signed, so the sealing certificate is its own issuer and this
            // node is the only authority that could speak to its revocation.
            issuer: self.cert.tbs_certificate.subject.clone(),
            this_update: x509_cert::time::Time::GeneralTime(
                der::asn1::GeneralizedTime::from_unix_duration(now)
                    .map_err(|e| SealError::Config(format!("cannot encode thisUpdate: {e}")))?,
            ),
            next_update: None,
            revoked_certificates: None,
            crl_extensions: None,
        };
        let signature: DerSignature = self.key.sign(
            &tbs.to_der()
                .map_err(|e| SealError::Config(format!("cannot encode the CRL body: {e}")))?,
        );

        let crl = x509_cert::crl::CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(signature.to_bytes().as_ref())
                .map_err(|e| SealError::Config(format!("cannot encode the CRL signature: {e}")))?,
        };

        let mut set = SetOfVec::new();
        set.insert(RevocationInfoChoice::Crl(crl))
            .map_err(|e| SealError::Config(format!("cannot attach the CRL: {e}")))?;
        Ok(Some(RevocationInfoChoices(set)))
    }
}

/// The value octets of a `SignerInfo`'s signature, without tag or length.
///
/// EN 319 122-1 clause 5.3 is explicit that the signature timestamp covers the
/// signature field "without the ASN.1 tag and length". Timestamping the encoded
/// OCTET STRING instead would produce a token that no other implementation
/// could reproduce.
fn signer_signature_value(signer: &SignerInfo) -> &[u8] {
    signer.signature.as_bytes()
}

#[async_trait]
impl SealBackend for LocalIdentity {
    async fn seal(&self, req: SealRequest) -> Result<SealedEnvelope, SealError> {
        let digest = hex::decode(&req.payload_hash)
            .map_err(|e| SealError::Config(format!("payload hash is not hex: {e}")))?;
        let der = self.sign_detached_at(&digest, req.conformance_level)?;

        Ok(SealedEnvelope {
            format: SealFormat::Cades,
            seal_value: base64::engine::general_purpose::STANDARD.encode(&der),
            signing_cert_ref: Some(self.cert_thumbprint()),
            // The **requested** level, which is what this field records. Core's
            // own kit fails an envelope whose stored level disagrees with the
            // request (`seal.misrecorded_level`), and the field's doc is explicit
            // that it is a record of what was asked for rather than proof of what
            // arrived.
            //
            // That is not the same as trusting it. `capabilities()` advertises
            // `BaselineB` alone and the adapter checks `can_produce` first, so the
            // only request that reaches here asked for `BaselineB` — which is also
            // what these bytes carry. If that guard ever stopped working, echoing
            // the request would record a level the bytes do not have; what catches
            // that is `cades::evidenced_level`, read independently by the drain,
            // which alarms on the disagreement rather than letting either side
            // vouch for itself.
            conformance_level: Some(req.conformance_level),
            sealed_at: Utc::now(),
            // Not a placeholder: these bytes verify. Legal standing is the trust
            // tier's business, not the envelope's.
            placeholder: false,
        })
    }

    fn capabilities(&self) -> SealCapabilities {
        // Real detached CAdES bytes. `OperatorSeal` because the certificate is
        // generated per node rather than held centrally on operators' behalf —
        // this backend rehearses the shape the hosted arrangement takes.
        SealCapabilities {
            supported_formats: vec![SealFormat::Cades],
            supported_modes: vec![SealMode::OperatorSeal],
            // Every baseline level, read off what `sign_detached_at` actually
            // emits: the signature (B), a signature timestamp (T), revocation
            // material in `SignedData.crls` (LT) and an archive timestamp
            // (LTA), each required by ETSI EN 319 122-1 Table 1 at that level.
            //
            // **Advertising a level is a claim about structure, never about
            // trust.** Every one of these is signed by a key this node generated
            // and timestamped by an authority it generated, so an `LTA` seal
            // from here is a faithfully shaped envelope with no legal weight
            // whatsoever — which is exactly what makes it useful for exercising
            // the paths that read a seal, and useless for anything else. The
            // node says so separately and structurally by resolving this backend
            // to the `Ghost` trust tier.
            supported_levels: SealConformanceLevel::ALL.to_vec(),
            // Detached: the signature travels beside the digest it covers and
            // never wraps it.
            supported_envelopes: vec![SealEnvelope::Detached],
        }
    }

    /// Overrides the refusing default, because this backend can answer honestly.
    ///
    /// The default exists so that no backend claims a verdict it did not
    /// compute, and the reason a hosted QTSP's seal cannot be answered here is
    /// independence: a verdict from the node that bought the seal attests
    /// nothing. Neither objection applies to this backend. Its seals make no
    /// trust claim at all beyond "this key signed this digest", so a
    /// cryptographic check *is* the whole truth about them, and there is no
    /// authority whose independence could be borrowed or faked.
    ///
    /// So a pass here is founded on [`SealChecks::SignatureOnly`] and says
    /// exactly what that documents — the signature was checked against the
    /// certificate carried inside the seal, and nothing else. No certificate
    /// path, no revocation, no timestamp, no Trusted List. It carries no legal
    /// weight, because the certificate is self-signed, and
    /// [`SealVerification::is_qualified_pass`] is false on it for that reason.
    /// The node says the same thing separately and structurally, by resolving
    /// this backend to the `Ghost` trust tier so a production profile refuses to
    /// boot on it.
    async fn verify(&self, env: &SealedEnvelope) -> Result<SealVerification, SealError> {
        use base64::engine::general_purpose::STANDARD as BASE64;

        // A placeholder envelope was never validated by anyone, so there is no
        // verdict to reach — reporting one either way would invent it.
        if env.placeholder {
            return Ok(SealVerification::placeholder(
                "placeholder envelope: no seal to validate",
            ));
        }

        let der = BASE64
            .decode(&env.seal_value)
            .map_err(|e| SealError::Backend(format!("seal value is not base64: {e}")))?;

        Ok(
            if crate::cades::verify_against_embedded_certificate(&der)? {
                SealVerification::passed(SealChecks::SignatureOnly)
            } else {
                SealVerification::failed(
                    SealChecks::SignatureOnly,
                    "signature does not verify against the certificate embedded in the seal",
                )
            },
        )
    }
}

/// The attributes the signature covers: what was signed, and its digest.
///
/// Two, both mandatory under RFC 5652 §11 for a signature carrying signed
/// attributes: `contentType`, and `messageDigest` holding the digest the caller
/// asked to seal. The second is the one that matters here — it is what puts the
/// sealed value inside the signature, so a holder of the bytes alone can check
/// them.
pub(super) fn signed_attributes(
    content_type: const_oid::ObjectIdentifier,
    digest: &[u8],
) -> Result<SignedAttributes, SealError> {
    use der::asn1::{OctetString, SetOfVec};

    let attr = |oid, value: Any| -> Result<Attribute, SealError> {
        let mut values = SetOfVec::new();
        values
            .insert(value)
            .map_err(|e| SealError::Config(format!("cannot build a signed attribute: {e}")))?;
        Ok(Attribute { oid, values })
    };

    let content_type = attr(
        const_oid::db::rfc5911::ID_CONTENT_TYPE,
        Any::encode_from(&content_type)
            .map_err(|e| SealError::Config(format!("cannot encode the content type: {e}")))?,
    )?;
    let message_digest = attr(
        const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
        Any::encode_from(
            &OctetString::new(digest)
                .map_err(|e| SealError::Config(format!("cannot encode the digest: {e}")))?,
        )
        .map_err(|e| SealError::Config(format!("cannot encode the digest attribute: {e}")))?,
    )?;

    let mut attrs = SetOfVec::new();
    for a in [content_type, message_digest] {
        attrs
            .insert(a)
            .map_err(|e| SealError::Config(format!("cannot collect signed attributes: {e}")))?;
    }
    Ok(attrs)
}

/// Generate a P-256 key and a self-signed certificate for it.
fn generate() -> Result<(Vec<u8>, Vec<u8>), SealError> {
    let mut params = rcgen::CertificateParams::new(vec!["odal-local-seal".to_owned()])
        .map_err(|e| SealError::Config(format!("cannot build certificate params: {e}")))?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "Odal Node local development seal",
    );
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "NOT A QUALIFIED SEAL");

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| SealError::Config(format!("cannot generate a P-256 key: {e}")))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| SealError::Config(format!("cannot self-sign the certificate: {e}")))?;

    Ok((key.serialize_der(), cert.der().to_vec()))
}

fn io_err(what: &'static str) -> impl Fn(std::io::Error) -> SealError {
    move |e| SealError::Config(format!("cannot {what}: {e}"))
}

#[cfg(test)]
#[path = "sealer_tests.rs"]
mod tests;
