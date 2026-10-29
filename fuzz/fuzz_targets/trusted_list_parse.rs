#![no_main]
//! Fuzz the eIDAS trusted list readers — the list of trusted lists and every
//! national list are XML fetched over the network, and each is parsed, and its
//! signing certificate picked out, before its signature has been checked.
//! Property: `parse_lotl`, `parse_trusted_list`, `verify_lotl` and
//! `verify_trusted_list` return `Ok`/`Err` for any document, never panic.
//!
//! `verify_lotl` stops at the pinned Commission certificate, which the fuzzer
//! does not have, so it never reaches the signature. `verify_trusted_list` is
//! handed every pointer the same document names, the way the list of trusted
//! lists names its own signing certificates: a document that carries the
//! certificate it points to gets as far as canonicalisation and the signature
//! check.

use dpp_seal::trustlist::{parse_lotl, parse_trusted_list, verify_lotl, verify_trusted_list};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_trusted_list(xml);
    let _ = verify_lotl(xml);
    if let Ok(pointers) = parse_lotl(xml) {
        for pointer in &pointers {
            let _ = verify_trusted_list(xml, pointer);
        }
    }
});
