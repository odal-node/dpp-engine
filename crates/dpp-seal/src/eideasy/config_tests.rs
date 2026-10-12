//! Unit tests for `config.rs`.

use super::*;

/// Resolve against a fixed set of variables — no process environment, so
/// these are pure, parallel-safe, and cannot be perturbed by the developer's
/// shell.
fn resolve(vars: &[(&str, &str)]) -> Result<EideasyConfig, SealError> {
    let owned: Vec<(String, String)> = vars
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    EideasyConfig::resolve(|name| {
        owned
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    })
}

const FULL: [(&str, &str); 3] = [
    (ENV_BASE_URL, SANDBOX_BASE_URL),
    (ENV_CLIENT_ID, "client-id"),
    (ENV_HMAC_KEY, "hmac-key"),
];

#[test]
fn a_full_configuration_resolves() {
    let cfg = resolve(&FULL).expect("configured");
    assert_eq!(cfg.environment, EideasyEnvironment::Sandbox);
    assert_eq!(cfg.client_id, "client-id");
    // Defaulted, not required.
    assert_eq!(cfg.signature_profile, "CAdES_BASELINE_T");
}

#[test]
fn a_partial_configuration_names_what_is_missing() {
    let err = resolve(&FULL[..1]).expect_err("partial must fail");
    let msg = err.to_string();
    assert!(msg.contains("SEAL_EIDEASY_CLIENT_ID"), "{msg}");
    assert!(msg.contains("SEAL_EIDEASY_HMAC_KEY"), "{msg}");
}

#[test]
fn known_hosts_map_to_their_environments() {
    assert_eq!(
        environment_for(SANDBOX_BASE_URL).unwrap(),
        EideasyEnvironment::Sandbox
    );
    assert_eq!(
        environment_for(PRODUCTION_BASE_URL).unwrap(),
        EideasyEnvironment::Production
    );
}

#[test]
fn an_unknown_host_is_refused() {
    // A typo must not become "some seal from somewhere" — it must not boot.
    for url in [
        "https://id.eideasy.com.evil.test",
        "https://eideasy.com",
        "https://localhost:8080",
    ] {
        assert!(
            environment_for(url).is_err(),
            "{url} was accepted as an eID Easy host"
        );
    }
}

#[test]
fn plaintext_http_is_refused() {
    assert!(environment_for("http://test.eideasy.com").is_err());
}

#[test]
fn debug_does_not_print_the_hmac_key() {
    let mut cfg = test_config(SANDBOX_BASE_URL);
    cfg.hmac_key = Zeroizing::new("super-secret-key-material".into());
    let rendered = format!("{cfg:?}");
    assert!(
        !rendered.contains("super-secret-key-material"),
        "Debug leaked the HMAC key: {rendered}"
    );
    assert!(rendered.contains("[redacted]"));
}
