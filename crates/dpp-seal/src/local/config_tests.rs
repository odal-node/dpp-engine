//! Unit tests for `config.rs`.

use super::*;

#[test]
fn key_path_defaults_when_unset() {
    let cfg = LocalConfig::resolve(|_| None).unwrap();
    assert_eq!(cfg.key_path, PathBuf::from("./.seal-local"));
}

#[test]
fn key_path_is_read_from_the_environment() {
    let cfg =
        LocalConfig::resolve(|n| (n == ENV_KEY_PATH).then(|| "/var/lib/odal/seal".to_owned()))
            .unwrap();
    assert_eq!(cfg.key_path, PathBuf::from("/var/lib/odal/seal"));
}

#[test]
fn a_blank_value_is_not_a_path() {
    let cfg = LocalConfig::resolve(|n| (n == ENV_KEY_PATH).then(|| "   ".to_owned())).unwrap();
    assert_eq!(cfg.key_path, PathBuf::from("./.seal-local"));
}
