//! Configuration for the local development sealing backend.

use std::path::PathBuf;

use crate::error::SealError;

/// The `SEAL_PROVIDER` value that selects this backend.
pub const PROVIDER: &str = "local";

/// Human-readable name of this backend's variable group, for the message the
/// selector emits when these are set without the provider being chosen.
pub const ENV_GROUP: &str = "SEAL_LOCAL_*";

const ENV_KEY_PATH: &str = "SEAL_LOCAL_KEY_PATH";

/// Whether any variable of this backend's group is set.
pub fn any_env_set(get: &impl Fn(&str) -> Option<String>) -> bool {
    [ENV_KEY_PATH]
        .iter()
        .any(|n| get(n).is_some_and(|v| !v.trim().is_empty()))
}

/// Resolved configuration for the local backend.
#[derive(Debug, Clone)]
pub struct LocalConfig {
    /// Where the generated key and certificate are persisted between runs.
    ///
    /// Persisted rather than regenerated per boot so a seal produced yesterday
    /// still verifies against the same certificate today — a restart that
    /// silently invalidated every seal it had produced would teach a developer
    /// the wrong thing about how seals behave.
    pub key_path: PathBuf,
}

impl LocalConfig {
    /// Read configuration from the process environment.
    pub fn from_env() -> Result<Self, SealError> {
        Self::resolve(|name| std::env::var(name).ok())
    }

    /// The whole of [`Self::from_env`]'s logic over an arbitrary lookup, for the
    /// same reason the other backends split it: process-global state is `unsafe`
    /// to mutate under Rust 2024 and makes tests serialise against each other.
    pub fn resolve(get: impl Fn(&str) -> Option<String>) -> Result<Self, SealError> {
        let key_path = get(ENV_KEY_PATH)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from("./.seal-local"), PathBuf::from);

        Ok(Self { key_path })
    }
}

#[cfg(test)]
mod tests {
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
}
