#![no_main]
//! Fuzz the evidence-dossier JSON verifier — parses attacker-supplied uploads.
//! Property: `verify_dossier_json` returns `Ok`/`Err` for any bytes, never panics.
//!
//! Handed a real inspector rather than `None`, because `None` returns `Absent`
//! from the `qualified_seal` check before the dossier's seal member is touched —
//! it would fuzz a narrower function than the verify endpoint calls, and the
//! base64 + CMS + X.509 parse behind that member is the byte frontier here most
//! worth fuzzing. Built exactly as the node builds it at boot: no trusted lists,
//! no credential, no network.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Hoisted out of the iteration: the inspector is stateless for this call
    // and rebuilding it per input would allocate on every run.
    static INSPECTOR: std::sync::OnceLock<dpp_seal::CadesInspector> = std::sync::OnceLock::new();
    let inspector = INSPECTOR.get_or_init(dpp_seal::CadesInspector::new);

    let _ = dpp_vault::domain::verify::verify_dossier_json(data, Some(inspector));
});
