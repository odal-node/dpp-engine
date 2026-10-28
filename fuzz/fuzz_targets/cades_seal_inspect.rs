#![no_main]
//! Fuzz the CAdES seal readers — a seal is DER from outside the node: the bytes
//! a QTSP returned, a seal stored by an earlier version, or the one inside an
//! uploaded evidence dossier. Every read of one parses CMS, X.509 and RFC 3161
//! structures out of it.
//! Property: every public reader in `dpp_seal::cades`, and every
//! `SealInspector` answer over an envelope carrying the bytes, returns for any
//! input, never panics.
//!
//! `verify_dossier_json` reaches the same code, but only through JSON and then
//! base64, so few of its inputs get as far as the DER. Here the input is the DER.

use base64::Engine as _;
use chrono::{DateTime, TimeZone, Utc};
use dpp_domain::seal::{SealFormat, SealedEnvelope};
use dpp_seal::cades::{self, TimestampToken};
use dpp_seal::CadesInspector;
use dpp_types::SealInspector;
use libfuzzer_sys::fuzz_target;

/// A self-signed P-256 certificate, subject `CN=dpp-engine fuzz anchor`, DER in
/// base64. Generated for this target with `openssl req -x509 -newkey ec
/// -keyout /dev/null`, so its private key was never written anywhere.
///
/// `check_path_to` parses its anchor before it walks anything, and gives up on
/// one that is not a certificate. A real one is what lets the walk up the
/// seal's embedded chain run; the fuzzer reaches it by naming this subject as
/// an issuer.
const ANCHOR: &str = "MIIBmDCCAT+gAwIBAgIUes/2oSnPWUiIiQK83c9e7zQnkg4wCgYIKoZIzj0EAwIwITEfMB0GA1UEAwwWZHBwLWVuZ2luZSBmdXp6IGFuY2hvcjAgFw0yNjEwMjgyMzQyMTdaGA8yMTI2MTAwNDIzNDIxN1owITEfMB0GA1UEAwwWZHBwLWVuZ2luZSBmdXp6IGFuY2hvcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNpX4zE0tWjzLSekYgwslG2W3E34tJekbqdV/Txscz5K0ZeoDRumK5FZoXEY7XR5JQ8TsO/XjafLGVfxnHuTjpqjUzBRMB0GA1UdDgQWBBRuMuCym8mMMKaQkIIgTV1Z+KSsUzAfBgNVHSMEGDAWgBRuMuCym8mMMKaQkIIgTV1Z+KSsUzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIGRpl5tWyc92FMPGqWIEgFkqONLrXPOAQF3XVFxzCq7WAiB90lmBXFgOT5y/m8GgkJL5JY0sKN52e+ecws7SvD8k9g==";

fn anchor() -> &'static [u8] {
    static DER: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    DER.get_or_init(|| {
        base64::engine::general_purpose::STANDARD
            .decode(ANCHOR)
            .expect("the anchor is valid base64")
    })
}

/// A fixed instant, so a finding reproduces whatever day it is replayed.
fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 19, 12, 0, 0)
        .single()
        .expect("a valid instant")
}

/// Every reader a timestamp token offers, including a path check against its
/// own signer.
fn read_token(token: &TimestampToken) {
    let _ = token.gen_time();
    let _ = token.authority_expires();
    let _ = token.subject();
    let _ = token.issuer();
    let _ = token.is_self_issued();
    let _ = token.chain_issuer_names();
    let _ = token.chain_terminus();
    if let Ok(signer) = token.signer_der() {
        let _ = token.check_path_to(&signer);
    }
}

fuzz_target!(|der: &[u8]| {
    let _ = cades::evidenced_level(der);
    let _ = cades::signer_certificate_thumbprint(der);
    let _ = cades::covered_digest(der);
    let _ = cades::can_verify_signatures_of(der);
    let _ = cades::verify_against_embedded_certificate(der);
    if let Ok(certificate) = cades::signer_certificate(der) {
        let _ = certificate.origin();
    }
    let attested = cades::attested_sealing_time(der).ok().flatten();
    if let Ok(Some(token)) = cades::signature_timestamp_token(der) {
        read_token(&token);
    }
    if let Ok(Some(token)) = cades::newest_archive_timestamp(der) {
        read_token(&token);
    }
    let _ = cades::archival_freshness(der, now());
    let _ = cades::certificate_standing(der, now(), attested);
    let _ = cades::chain_issuer_names(der);
    let _ = cades::chain_terminus(der);
    let _ = cades::check_path_to(der, anchor());

    let envelope = SealedEnvelope {
        format: SealFormat::Cades,
        seal_value: base64::engine::general_purpose::STANDARD.encode(der),
        signing_cert_ref: None,
        conformance_level: None,
        sealed_at: now(),
        placeholder: false,
    };
    static INSPECTOR: std::sync::OnceLock<CadesInspector> = std::sync::OnceLock::new();
    let inspector = INSPECTOR.get_or_init(CadesInspector::new);
    let _ = inspector.origin(&envelope);
    let _ = inspector.binding(&envelope, &"0".repeat(64));
    let _ = inspector.evidenced_level(&envelope);
    let _ = inspector.attested_sealing_time(&envelope);
    let _ = inspector.timestamp_authority(&envelope);
    let _ = inspector.archival_freshness(&envelope, now());
    let _ = inspector.certificate_standing(&envelope, now());
    let _ = inspector.qualification(&envelope);
});
