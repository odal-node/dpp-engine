#![no_main]
//! Fuzz the evidence-dossier JSON verifier — parses attacker-supplied uploads.
//! Property: `verify_dossier_json` returns `Ok`/`Err` for any bytes, never panics.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dpp_vault::domain::verify::verify_dossier_json(data);
});
