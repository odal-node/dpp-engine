#![no_main]
//! Fuzz the bulk-import CSV parser — a hostile-upload byte frontier.
//! Property: `parse_csv` returns `Ok`/`Err` for any bytes, never panics.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dpp_integrator::domain::csv_parser::parse_csv(data);
});
