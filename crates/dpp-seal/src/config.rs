//! Which sealing backend this node runs, resolved from the environment.
//!
//! This module knows the *selection* rule and nothing about any particular
//! backend. Each backend owns its own variables, its own validation and its own
//! failure messages, inside its own module — so adding one is additive here and
//! removing one leaves nothing behind.

use crate::error::SealError;

/// Selects the sealing backend. Unset means no seal provider.
///
/// Deliberately explicit rather than inferred from whichever credentials happen
/// to be present: a node that cannot name its trust provider must not quietly
/// become one that has none.
pub const SEAL_PROVIDER: &str = "SEAL_PROVIDER";

const PROVIDER_NONE: &str = "none";

/// The backend a node is configured to seal with.
///
/// Deliberately **not** `#[non_exhaustive]`: adding a backend should break every
/// wiring site until it is handled. A `_` arm here is a node that silently seals
/// with something other than what it was asked for, which is the downgrade the
/// trust report exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealProvider {
    /// The hosted QTSP backend.
    Qtsp,
    /// In-process signing with a locally generated key. Development only — the
    /// certificate is not on an EU Trusted List, so the envelope is structurally
    /// a seal and legally nothing.
    Local,
    /// No provider. The node wires `GhostSeal`, which a development profile
    /// permits and a production profile refuses at boot.
    None,
}

impl SealProvider {
    /// Read the selection from the process environment.
    pub fn from_env() -> Result<Self, SealError> {
        Self::resolve(|name| std::env::var(name).ok())
    }

    /// The whole of [`Self::from_env`]'s logic over an arbitrary lookup.
    ///
    /// Split out so the rule is testable as a pure function. Exercising it
    /// through the real environment would mean mutating process-global state
    /// from tests, which is `unsafe` under Rust 2024, forces them to serialise
    /// against one another, and lets a stray variable in the developer's shell
    /// change the result.
    pub fn resolve(get: impl Fn(&str) -> Option<String>) -> Result<Self, SealError> {
        let selected = get(SEAL_PROVIDER)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());

        match selected.as_deref() {
            None | Some(PROVIDER_NONE) => {
                // A backend's credentials present without its provider selected
                // is a misconfiguration, not a fallback: silently ghosting on a
                // misspelled variable would downgrade a node from qualified
                // sealing to no sealing, which is exactly what the trust report
                // exists to make impossible.
                if let Some(stray) = stray_backend_vars(&get) {
                    return Err(SealError::Config(format!(
                        "{stray} is set but {SEAL_PROVIDER} is not — set it, or unset those \
                         variables to run with GhostSeal"
                    )));
                }
                Ok(Self::None)
            }
            Some(crate::eideasy::config::PROVIDER) => Ok(Self::Qtsp),
            Some(crate::local::config::PROVIDER) => Ok(Self::Local),
            Some(other) => Err(SealError::Config(format!(
                "unknown {SEAL_PROVIDER} `{other}` — supported: `{}`, `{}`, `{PROVIDER_NONE}`",
                crate::eideasy::config::PROVIDER,
                crate::local::config::PROVIDER
            ))),
        }
    }
}

/// The name of a backend's variable group that is set while no provider is
/// selected, if any. Each backend answers for its own prefix.
fn stray_backend_vars(get: &impl Fn(&str) -> Option<String>) -> Option<&'static str> {
    [
        (
            crate::eideasy::config::ENV_GROUP,
            crate::eideasy::config::any_env_set(get),
        ),
        (
            crate::local::config::ENV_GROUP,
            crate::local::config::any_env_set(get),
        ),
    ]
    .into_iter()
    .find_map(|(group, set)| set.then_some(group))
}

#[cfg(test)]
mod tests {
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
}
