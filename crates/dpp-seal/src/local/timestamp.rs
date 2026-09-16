//! A local timestamping authority, so the development backend can produce the
//! shape of a `B-T`, `B-LT` and `B-LTA` seal.
//!
//! # What this is for
//!
//! ETSI EN 319 122-1 Table 1 requires a `signature-time-stamp` from `B-T`
//! upward and an `archive-time-stamp-v3` at `B-LTA`, and both are RFC 3161
//! time-stamp tokens. Without a timestamping authority the local backend can
//! only ever emit `B-B`, which means every path in this workspace that depends
//! on a higher level — the drain's downgrade check, the evidence dossier, the
//! conformance probe at boot — can only be exercised against a provider nobody
//! can currently buy from.
//!
//! So this stands one up locally. The node generates a TSA key and certificate
//! beside its sealing identity and timestamps its own seals.
//!
//! # What this is emphatically not
//!
//! **Not a qualified timestamp, and not a trusted one.** Regulation (EU)
//! No 910/2014 Art. 42 makes a qualified electronic time stamp a service of a
//! qualified trust service provider, and Art. 41(2) attaches the presumption of
//! accuracy to that. This TSA is a key this node generated for itself: its token
//! attests that a machine's own clock said something, which is worth exactly
//! nothing to anybody else.
//!
//! Three things make that unmistakable rather than a matter of reading the docs:
//!
//! - the TSA certificate is **self-signed** and names itself `NOT A QUALIFIED
//!   TIMESTAMP`, so it appears on no Trusted List and never will;
//! - its policy identifier is **deliberately unregistered** — see
//!   [`DEVELOPMENT_TSA_POLICY`] — so a validator checking TSA policy sees at once
//!   that this is not a real one;
//! - the whole backend already resolves to the `Ghost` trust tier, which a
//!   production profile refuses at boot.
//!
//! The tokens are therefore **structurally faithful and legally void**, which is
//! precisely what a development stand-in should be: enough to exercise every
//! path that reads a seal, never enough to be mistaken for one.

use std::path::Path;

use der::{Decode as _, Encode as _, asn1::Any};
use p256::ecdsa::{DerSignature, SigningKey};
use x509_cert::Certificate;

use crate::error::SealError;

use crate::cades::ID_CT_TST_INFO;

/// The policy this development authority stamps under, deliberately unregistered.
///
/// RFC 3161 §2.4.2 requires `TSTInfo.policy`, and a real authority names a
/// policy it has published and been audited against. `1.2.3.4.x` is the
/// conventional example arc, allocated to nobody — so this value cannot collide
/// with a real policy and cannot be mistaken for one. A validator that checks
/// the policy identifier learns immediately what it is looking at, which is the
/// intent: the fastest way to be honest about a simulated authority is to make
/// the simulation legible in the bytes.
pub const DEVELOPMENT_TSA_POLICY: &str = "1.2.3.4.1";

/// A locally generated timestamping identity: one key, one self-signed
/// certificate carrying the timestamping extended key usage.
pub(super) struct LocalTsa {
    key: SigningKey,
    cert: Certificate,
}

impl LocalTsa {
    /// Load the authority at `dir`, generating it on first use.
    ///
    /// Persisted for the same reason the sealing identity is: a token issued
    /// yesterday has to keep referring to a certificate that still exists.
    pub(super) fn load_or_create(dir: &Path) -> Result<Self, SealError> {
        let key_path = dir.join("tsa-key.pkcs8.der");
        let cert_path = dir.join("tsa-cert.der");

        let (key_der, cert_der) = if key_path.exists() && cert_path.exists() {
            (
                std::fs::read(&key_path).map_err(io_err("read the local TSA key"))?,
                std::fs::read(&cert_path).map_err(io_err("read the local TSA certificate"))?,
            )
        } else {
            let generated = generate()?;
            std::fs::create_dir_all(dir).map_err(io_err("create the local TSA directory"))?;
            std::fs::write(&key_path, &generated.0).map_err(io_err("write the local TSA key"))?;
            std::fs::write(&cert_path, &generated.1)
                .map_err(io_err("write the local TSA certificate"))?;
            generated
        };

        use p256::pkcs8::DecodePrivateKey as _;
        Ok(Self {
            key: SigningKey::from_pkcs8_der(&key_der).map_err(|e| {
                SealError::Config(format!("local TSA key is not a P-256 PKCS#8: {e}"))
            })?,
            cert: Certificate::from_der(&cert_der).map_err(|e| {
                SealError::Config(format!("local TSA certificate is not valid DER: {e}"))
            })?,
        })
    }

    /// An RFC 3161 `TimeStampToken` over `imprint`, as an attribute value.
    ///
    /// `imprint` is the SHA-256 of whatever is being timestamped — the caller
    /// decides what that is, because the two levels that need a token compute it
    /// over different things (EN 319 122-1 clauses 5.3 and 5.5.3).
    ///
    /// The token is an **attached** `SignedData`: its `eContent` carries the
    /// `TSTInfo`, which is what makes a token self-contained and checkable.
    ///
    /// `index` is the `ats-hash-index-v3` an `archive-time-stamp-v3` must carry,
    /// and `None` for a signature timestamp, which has none. It rides as an
    /// **unsigned** attribute of the token, which is where the clause puts it —
    /// inside the token so that a verifier recomputing the imprint has it, and
    /// unsigned because the authority stamps an imprint it is handed rather than
    /// a structure it inspects.
    pub(super) fn token(
        &self,
        imprint: &[u8],
        serial: u64,
        index: Option<&crate::ats::AtsHashIndexV3>,
    ) -> Result<Any, SealError> {
        use der::asn1::{OctetString, SetOfVec};
        use p256::ecdsa::signature::Signer as _;

        let sha256 = x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };

        let info = crate::cades::TstInfo {
            version: 1,
            policy: const_oid::ObjectIdentifier::new(DEVELOPMENT_TSA_POLICY)
                .map_err(|e| SealError::Config(format!("the TSA policy OID is malformed: {e}")))?,
            message_imprint: crate::cades::MessageImprint {
                hash_algorithm: sha256.clone(),
                hashed_message: OctetString::new(imprint)
                    .map_err(|e| SealError::Config(format!("cannot encode the imprint: {e}")))?,
            },
            serial_number: serial,
            gen_time: der::asn1::GeneralizedTime::from_unix_duration(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| SealError::Config(format!("the clock is before 1970: {e}")))?,
            )
            .map_err(|e| SealError::Config(format!("cannot encode the timestamp: {e}")))?,
        };
        let tst_der = info
            .to_der()
            .map_err(|e| SealError::Config(format!("cannot encode the TSTInfo: {e}")))?;

        // The token signs its own payload, so the signed attributes carry the
        // TSTInfo's content type and digest — not the sealed document's.
        let signed_attrs = {
            use sha2::{Digest as _, Sha256};
            super::sealer::signed_attributes(ID_CT_TST_INFO, &Sha256::digest(&tst_der))?
        };
        let to_sign = signed_attrs.to_der().map_err(|e| {
            SealError::Config(format!("cannot encode the token's signed attributes: {e}"))
        })?;
        let signature: DerSignature = self.key.sign(&to_sign);

        let signer_info = cms::signed_data::SignerInfo {
            version: cms::content_info::CmsVersion::V1,
            sid: cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(
                cms::cert::IssuerAndSerialNumber {
                    issuer: self.cert.tbs_certificate.issuer.clone(),
                    serial_number: self.cert.tbs_certificate.serial_number.clone(),
                },
            ),
            digest_alg: sha256.clone(),
            signed_attrs: Some(signed_attrs),
            signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                parameters: None,
            },
            signature: OctetString::new(signature.to_bytes().as_ref()).map_err(|e| {
                SealError::Config(format!("cannot encode the token's signature: {e}"))
            })?,
            unsigned_attrs: match index {
                None => None,
                Some(index) => {
                    let mut values = SetOfVec::new();
                    values
                        .insert(Any::encode_from(index).map_err(|e| {
                            SealError::Config(format!("cannot encode the hash index: {e}"))
                        })?)
                        .map_err(|e| {
                            SealError::Config(format!("cannot carry the hash index: {e}"))
                        })?;
                    let mut set = SetOfVec::new();
                    set.insert(x509_cert::attr::Attribute {
                        oid: crate::ats::ID_AA_ATS_HASH_INDEX_V3,
                        values,
                    })
                    .map_err(|e| SealError::Config(format!("cannot attach the hash index: {e}")))?;
                    Some(set)
                }
            },
        };

        let mut digest_algorithms = SetOfVec::new();
        digest_algorithms
            .insert(sha256)
            .map_err(|e| SealError::Config(format!("cannot record the digest algorithm: {e}")))?;
        let mut certs = SetOfVec::new();
        certs
            .insert(cms::cert::CertificateChoices::Certificate(
                self.cert.clone(),
            ))
            .map_err(|e| SealError::Config(format!("cannot attach the TSA certificate: {e}")))?;
        let mut signer_infos = SetOfVec::new();
        signer_infos
            .insert(signer_info)
            .map_err(|e| SealError::Config(format!("cannot attach the token's signer: {e}")))?;

        let signed_data = cms::signed_data::SignedData {
            version: cms::content_info::CmsVersion::V3,
            digest_algorithms: cms::signed_data::DigestAlgorithmIdentifiers::from(
                digest_algorithms,
            ),
            encap_content_info: cms::signed_data::EncapsulatedContentInfo {
                econtent_type: ID_CT_TST_INFO,
                econtent: Some(
                    Any::new(der::Tag::OctetString, tst_der.as_slice())
                        .map_err(|e| SealError::Config(format!("cannot wrap the TSTInfo: {e}")))?,
                ),
            },
            certificates: Some(cms::signed_data::CertificateSet::from(certs)),
            crls: None,
            signer_infos: cms::signed_data::SignerInfos::from(signer_infos),
        };

        Any::encode_from(&cms::content_info::ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: Any::encode_from(&signed_data).map_err(|e| {
                SealError::Config(format!("cannot encode the token's SignedData: {e}"))
            })?,
        })
        .map_err(|e| SealError::Config(format!("cannot encode the time-stamp token: {e}")))
    }

    /// The authority's certificate, so a seal can carry it.
    ///
    /// EN 319 122-1 requires a verifier to be able to build a path for every
    /// timestamp in the signature, and a token whose signing certificate travels
    /// nowhere cannot be checked by anyone.
    pub(super) fn certificate(&self) -> &Certificate {
        &self.cert
    }
}

/// Generate a P-256 key and a self-signed TSA certificate for it.
///
/// RFC 3161 §2.3 requires the timestamping extended key usage, **critical and
/// sole**: a certificate that may also do other things is not a TSA
/// certificate. `rcgen` emits `extendedKeyUsage` as critical when it is the only
/// purpose set, which is the shape wanted here.
fn generate() -> Result<(Vec<u8>, Vec<u8>), SealError> {
    let mut params = rcgen::CertificateParams::new(vec!["odal-local-tsa".to_owned()])
        .map_err(|e| SealError::Config(format!("cannot build TSA certificate params: {e}")))?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "Odal Node local development timestamp",
    );
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "NOT A QUALIFIED TIMESTAMP");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::TimeStamping];

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| SealError::Config(format!("cannot generate a TSA P-256 key: {e}")))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| SealError::Config(format!("cannot self-sign the TSA certificate: {e}")))?;

    Ok((key.serialize_der(), cert.der().to_vec()))
}

fn io_err(what: &'static str) -> impl Fn(std::io::Error) -> SealError {
    move |e| SealError::Config(format!("cannot {what}: {e}"))
}
