//! Reading what a detached CAdES says about itself.
//!
//! Shared by the backends because the parsing is plain CMS and belongs to
//! neither: a backend module may not reach into another's, and duplicating
//! ASN.1 handling across two of them is how the two quietly stop agreeing about
//! what a seal contains.
//!
//! # What is *reported* and what is *verified*, kept apart by name
//!
//! Most of this module reads a structure and reports what it found. A
//! certificate it names is the one the seal **claims** signed it, on the seal's
//! own word — [`signer_certificate`], [`evidenced_level`] and
//! [`signer_certificate_thumbprint`] all work that way, and are named so the
//! distinction survives a skim.
//!
//! [`check_path_to`] is the exception, and the only one. It verifies signatures:
//! given a trust anchor established elsewhere, it walks from the seal's signer up
//! through the certificates the seal carries and checks that each link was really
//! signed by the one above it. That is a genuine cryptographic result, not a
//! report.
//!
//! It still does **not** make a seal qualified. No validity window is read and no
//! revocation is consulted, so a certificate that had expired or been revoked at
//! the moment of sealing passes this check. Establishing *that* remains an
//! independent AdES validator's job.
//!
//! The distinction is the whole reason this is a separate module with its own
//! vocabulary. A convenience field that reads as verification while verifying
//! nothing is worse than an absent one, because an absent field prompts the
//! question and a populated one settles it wrongly.

mod archive;
pub(crate) mod ats;
mod certificate;
mod path;
mod signature;
mod signed;
#[cfg(test)]
mod test_support;
mod timestamp;

pub use archive::{ArchivalFreshness, archival_freshness, newest_archive_timestamp};
pub(crate) use archive::{attach_archive_timestamp, prepare_archive_renewal, token_facts};
pub use certificate::{SignerCertificate, certificate_standing, signer_certificate};
pub use path::{ChainTerminus, IssuerCheck, chain_issuer_names, chain_terminus, check_path_to};
pub use signature::{
    can_verify_signatures_of, covered_digest, evidenced_level, signer_certificate_thumbprint,
    verify_against_embedded_certificate,
};
pub(crate) use timestamp::{GenTime, ID_CT_TST_INFO, MessageImprint, TstInfo};
pub use timestamp::{TimestampToken, attested_sealing_time, signature_timestamp_token};
