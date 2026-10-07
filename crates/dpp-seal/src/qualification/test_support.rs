//! Fixtures both halves of the qualification tests use.
//!
//! The issuer and timestamp tests reach the same real Finnish list and the same
//! seal surgery from here, rather than one file copying the other's helpers.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::Encode as _;

use crate::trustlist::{VerifiedTrustedList, verify_lotl, verify_trusted_list};

pub(super) const EU_LOTL: &str = include_str!("../../tests/fixtures/eu-lotl.xml");
pub(super) const FI_LIST: &str = include_str!("../../tests/fixtures/fi-trusted-list.xml");

/// Finland's list, verified through the verified list of lists.
///
/// The real document rather than a fixture assembled here: a hand-built list
/// would prove the matcher agrees with the builder, and the names in a published
/// list are exactly the thing whose encoding this module bets on.
pub(super) fn finnish_list() -> VerifiedTrustedList {
    let lotl = verify_lotl(EU_LOTL).expect("the LOTL verifies");
    let pointer = lotl
        .pointers()
        .iter()
        .find(|p| p.territory.as_deref() == Some("FI"))
        .expect("the LOTL points at Finland")
        .clone();
    verify_trusted_list(FI_LIST, &pointer).expect("Finland's list verifies")
}

/// A seal from the local backend, and the directory holding its key.
///
/// The directory is returned because dropping it removes the key store.
pub(super) fn local_seal() -> (Vec<u8>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let id = crate::local::LocalIdentity::load_or_create(dir.path()).expect("identity");
    let seal = id.sign_detached(&[0x11; 32]).expect("sign");
    (seal, dir)
}

/// Point the seal's single `SignerInfo` at `certificate`.
pub(super) fn name_signer(sd: &mut SignedData, certificate: &x509_cert::Certificate) {
    let mut signers = sd.signer_infos.0.as_slice().to_vec();
    signers[0].sid = cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(
        cms::cert::IssuerAndSerialNumber {
            issuer: certificate.tbs_certificate.issuer.clone(),
            serial_number: certificate.tbs_certificate.serial_number.clone(),
        },
    );
    let mut set = der::asn1::SetOfVec::new();
    set.insert(signers.remove(0)).expect("signer");
    sd.signer_infos = cms::signed_data::SignerInfos::from(set);
}

/// Re-encode a modified `SignedData` as a detached CAdES seal.
pub(super) fn reencode(sd: SignedData) -> Vec<u8> {
    ContentInfo {
        content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
        content: der::Any::encode_from(&sd).expect("encode"),
    }
    .to_der()
    .expect("re-encode")
}
