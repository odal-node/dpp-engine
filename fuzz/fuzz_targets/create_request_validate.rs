#![no_main]
//! Fuzz the checks a passport create body meets — `POST /api/v1/dpp`, its
//! dry-run twin `POST /api/v1/dpp/validate`, and every row an import forwards
//! send a JSON body that is read into a `CreatePassportRequest` and handed to
//! `validate_create_request` before anything is stored.
//! Property: reading any JSON as a create request, and validating whatever
//! reads as one, never panics.

use dpp_types::CreatePassportRequest;
use dpp_vault::handlers::create::validate_create_request;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(body) = serde_json::from_slice::<CreatePassportRequest>(data) {
        let _ = validate_create_request(&body);
    }
});
