//! Unit tests for `config.rs`.

use super::*;

/// A lookup over a fixed set of variables — no process environment, so these
/// are pure and parallel-safe.
fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let owned: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name: &str| {
        owned
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }
}

#[test]
fn unset_is_none() {
    assert_eq!(SealProvider::resolve(env(&[])).unwrap(), SealProvider::None);
}

#[test]
fn explicit_none_is_none() {
    assert_eq!(
        SealProvider::resolve(env(&[(SEAL_PROVIDER, "none")])).unwrap(),
        SealProvider::None
    );
}

#[test]
fn an_unknown_provider_names_the_supported_ones() {
    let msg = SealProvider::resolve(env(&[(SEAL_PROVIDER, "acme")]))
        .unwrap_err()
        .to_string();
    assert!(msg.contains("acme"), "{msg}");
    assert!(msg.contains(crate::local::config::PROVIDER), "{msg}");
}

/// Credentials without a selection is refused rather than ghosted.
///
/// The failure this guards is a typo in `SEAL_PROVIDER` on a node that is
/// otherwise fully configured to seal: falling back would publish passports
/// with no qualified seal and no error.
#[test]
fn backend_vars_without_a_selection_are_refused() {
    let msg = SealProvider::resolve(env(&[("SEAL_LOCAL_KEY_PATH", "/tmp/k.pem")]))
        .unwrap_err()
        .to_string();
    assert!(msg.contains(SEAL_PROVIDER), "{msg}");
}
