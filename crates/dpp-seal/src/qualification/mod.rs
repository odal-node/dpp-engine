//! Whether a seal was made under a qualified provider, or signed here.
//!
//! The question this answers is the one an operator, an auditor and a market
//! surveillance authority all ask first, and which nothing in this crate could
//! answer before: **did a qualified trust service provider issue the certificate
//! behind this seal, or did the node sign it itself?** A node running the local
//! development backend produces seals that verify perfectly and mean nothing
//! legally, and until now the two were distinguishable only by knowing which
//! backend was configured.
//!
//! Everything here is read out of the seal. Configuration is not consulted,
//! deliberately: a node knows which backend it was *told* to use, which attests
//! the operator's intent rather than the bytes that came back.
//!
//! # What this reaches, and what it does not
//!
//! Regulation (EU) No 910/2014 Art. 40 applies Art. 32 to seals *mutatis
//! mutandis*, and Art. 32(1) has two legs that an ordinary AdES validation does
//! not reach:
//!
//! - **Art. 32(1)(a)–(b)** — the certificate was a qualified certificate issued
//!   by a QTSP. A Trusted List question (Art. 22), answered here by
//!   [`IssuerStanding`].
//! - **Art. 32(1)(f)** — the seal was created by a qualified electronic seal
//!   creation device, which **Annex III(j)** requires the certificate to declare
//!   in machine-processable form. Answered here by
//!   [`CreationDevice`](dpp_types::CreationDevice).
//!
//! Two legs, so two fields rather than one ladder: they are independent, and a
//! seal can hold either without the other.
//!
//! ## The issuer is verified, not merely named
//!
//! Matching starts from the name — the seal certificate's issuer distinguished
//! name against the subject of a CA certificate the list carries — and **does
//! not stop there**. Every listed certificate under that name is then tried as a
//! verifier of the CA's signature over this certificate's `tbsCertificate`, and
//! only a certificate that actually verifies reaches
//! [`IssuerStanding::QualifiedAtSealing`].
//!
//! Every listed certificate, because a certificate authority rotating its key
//! publishes the old and the new together under one subject name. Stopping at
//! the first would report a genuine seal as unsigned, intermittently, and only
//! for providers mid-rotation.
//!
//! Before that check existed, a self-signed certificate relabelled with a listed
//! CA's name reached the top verdict — and **still verified as a seal**, because
//! a CMS signature covers the signed attributes rather than the certificate
//! travelling beside them. What the relabelling breaks is the certificate's own
//! signature, which is exactly what this now checks.
//!
//! ## A chain that runs out is not a finding about the lists
//!
//! Matching considers every issuer name the seal's embedded certificates refer
//! to, so a seal carrying its intermediates reaches a listed root two or more
//! links up. A seal that does **not** carry them is a different state, and
//! [`IssuerStanding::ChainIncomplete`] reports it as one: the walk ran out of
//! links, so a listed CA may sit above the gap and "no list names this issuer"
//! would be an accusation drawn from a certificate nobody shipped.
//!
//! Which state a seal is in is decided by where its chain ends —
//! [`crate::cades::chain_terminus`] — not by whether the lookup happened to
//! fail. Nothing is fetched to fill the gap: the material a verifier is expected
//! to have is what the seal carries and what the lists publish, and an AIA URL
//! inside an untrusted certificate is not something a node should be dialling.
//!
//! ## The certificate's own standing is a different question, asked elsewhere
//!
//! Art. 32(1)(b), reached for seals by Art. 40, has two limbs: the certificate
//! must have been **issued by a qualified trust service provider**, and it must
//! have been **valid at the time of signing**. This module answers the first —
//! it is the trusted list question, and the list is the only thing that can
//! answer it.
//!
//! The second is answerable from the seal alone, so it lives with the rest of
//! the certificate reading in [`crate::cades::certificate_standing`]: the
//! validity window judged against an attested sealing time, and revocation read
//! from the CRLs the seal carries. This module deliberately does not fold that
//! in. A caller wanting the whole of (b) asks both, which keeps each answer
//! traceable to the evidence it came from — a trusted list, or the bytes.
//!
//! ## Still not `SealChecks::QualifiedValidation`
//!
//! Conditions of Art. 32(1) remain unchecked, and none is a matter of degree:
//!
//! - **(f), the creation device.** [`CreationDevice`] reports what Annex III(j)
//!   *declares*, which is the certificate's word for it. Nothing confirms it,
//!   and nothing could from bytes alone.
//! - **(c) and (d)** — that the validation data corresponds to what the relying
//!   party was given, and that the data representing the seal creator is
//!   correctly provided — are about the presentation, not the envelope.
//! - **(h)**, the Art. 26 requirements for an advanced seal.
//!
//! So nothing in this module returns a
//! [`SealChecks`](dpp_domain::seal::SealChecks). A rung would be claimed by
//! whoever wired it up next, and the missing conditions would go with it.

mod issuer;
mod listed;
#[cfg(test)]
mod test_support;
mod timestamp;

/// The verdict's **shape** lives in `dpp-types`; the reading of it lives here.
///
/// Re-exported rather than referenced through `dpp_types::` throughout, so this
/// module reads as it did and every existing caller — `dpp_seal::qualification::
/// IssuerStanding` — keeps resolving. `dpp-vault` serves these and reaches this
/// crate through one trait in `dpp-types`, so the types had to sit below both;
/// they moved to join `SealOrigin`, `SealBinding`, `CertificateStanding` and
/// `ArchivalFreshness`, which were already declared there and computed here.
pub use dpp_types::qualification::{
    IssuerStanding, SealQualification, TimestampStanding, UncheckedTerritory,
};

pub use issuer::qualify;
pub use timestamp::qualify_timestamp;
pub(crate) use timestamp::timestamp_standing;
