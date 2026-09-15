//! Which fields `patch_fields` refuses to modify — the one answer both backends
//! give.
//!
//! Passport identity, lifecycle state, retention lock, signatures, seal,
//! registry identity and upward lineage. Each is governed by the publish
//! pipeline / `update_status` / a dedicated transition method, and several back
//! a scalar column that the JSONB-merge path does not rewrite — allowing them
//! would both bypass the state machine and desync the doc from its enforcing
//! column (e.g. flipping `retentionLocked` in the doc while the
//! `retention_locked` column stays `false`). Serialized (camelCase) names.
//!
//! # Derived from core, never restated
//!
//! A backend that overrides `patch_fields` does not inherit core's default
//! guard, but it still owes callers that guard's contract. So this reads
//! `dpp_domain::PROTECTED_PATCH_FIELDS` and applies exactly the divergences
//! declared below, rather than keeping a second list.
//!
//! The Postgres backend used to keep one, and that list fell **three entries
//! short** of core's: `operatorIdentifier`, `facility` and the lineage edge then
//! called `parentPassportRef` were protected by core and not there, which made
//! them writable through `PUT /dpp/{id}` and carried them into the signed
//! publish payload. A second list is a second thing to keep right, and nothing
//! was keeping it right: the one test covering that path asserted two keys, both
//! of which were in both lists the whole time.
//!
//! # Why it lives here rather than beside one backend
//!
//! It was private to `pg::repo_passport`, so it governed the Postgres backend
//! and nothing else. `InMemoryPassportRepo` does not override `patch_fields`, so
//! it inherited core's *undiverged* default — and the two backends therefore
//! disagreed about whether a `componentRefs` patch succeeds: Postgres allowed
//! it, the in-memory repo refused it.
//!
//! That is worse than either answer on its own. A suite running against the
//! in-memory repo proved the opposite of what production does, so the divergence
//! below was simultaneously deliberate and untested. One home, both backends.
//!
//! # The one divergence, and why it is deliberate
//!
//! **`componentRefs` is removed here.** Core protects the lineage edges because
//! patching them on a *published* passport would leave the served body no longer
//! verifying against its own signature. The update path accepts drafts only
//! (`update` refuses any non-`Draft` status), and a draft has no signature to
//! break — a bill of materials is editable while it is still being assembled,
//! which is the point of a draft. Its *upward* sibling `derivedFrom` stays
//! protected, because nothing applies it: it is stamped at create and read at
//! verify.
//!
//! **`productGroup` used to be added here** and is not any more: core 0.20.0
//! protects it directly. The local reason still holds — it backs a real scalar
//! column the JSONB merge does not rewrite — it is simply no longer a
//! *divergence*, and a declared exception that no longer excepts anything reads
//! as a deliberate difference while being none.
//!
//! [`tests`] holds both halves honest: the guard must equal core's value
//! plus/minus these entries, and an entry that no longer diverges from core must
//! be deleted rather than left as a stale exception. That is exactly how the
//! `productGroup` entry came to be removed.

/// Keys this build protects that core does not.
pub const ADDED_HERE: [&str; 0] = [];

/// Keys core protects that this build deliberately allows. See the module doc.
pub const REMOVED_HERE: [&str; 1] = ["componentRefs"];

/// Whether `patch_fields` must refuse a delta carrying `key`.
///
/// Every backend consults this. A backend that answers differently is a backend
/// whose tests prove something about itself rather than about the system.
#[must_use]
pub fn is_protected_patch_field(key: &str) -> bool {
    if REMOVED_HERE.contains(&key) {
        return false;
    }
    ADDED_HERE.contains(&key) || dpp_domain::PROTECTED_PATCH_FIELDS.contains(&key)
}

/// The refusal a backend returns for a delta naming protected keys.
///
/// Shared so the two backends cannot disagree about the message either — a
/// caller branching on the text would otherwise see a different sentence
/// depending on which repository answered.
pub fn refuse_protected(delta: &serde_json::Value) -> Result<(), dpp_domain::error::DppError> {
    let Some(obj) = delta.as_object() else {
        return Ok(());
    };
    let mut forbidden: Vec<&str> = obj
        .keys()
        .map(String::as_str)
        .filter(|k| is_protected_patch_field(k))
        .collect();
    if forbidden.is_empty() {
        return Ok(());
    }
    forbidden.sort_unstable();
    Err(dpp_domain::error::DppError::Validation(
        format!(
            "patch_fields cannot modify protected field(s): {}",
            forbidden.join(", ")
        )
        .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{ADDED_HERE, REMOVED_HERE, is_protected_patch_field, refuse_protected};

    /// The guard must equal core's, plus/minus the declared divergences — and it
    /// is checked against core's live value, not a copy.
    ///
    /// This is the test the hand-typed list never had. Its predecessor asserted
    /// two keys (`retentionLocked`, `status`), both of which were present in both
    /// lists the whole time, so the three entries that actually drifted were
    /// covered by nothing.
    #[test]
    fn guard_equals_core_plus_declared_divergences() {
        for key in dpp_domain::PROTECTED_PATCH_FIELDS {
            let expected = !REMOVED_HERE.contains(key);
            assert_eq!(
                is_protected_patch_field(key),
                expected,
                "core protects `{key}`; every backend must too unless it is in REMOVED_HERE"
            );
        }
        for key in ADDED_HERE {
            assert!(
                is_protected_patch_field(key),
                "`{key}` is declared as added here but is not protected"
            );
        }
    }

    /// A divergence that no longer diverges is a stale exception — it reads as a
    /// deliberate difference while being none, and hides the next real one.
    #[test]
    fn declared_divergences_are_real() {
        for key in ADDED_HERE {
            assert!(
                !dpp_domain::PROTECTED_PATCH_FIELDS.contains(&key),
                "`{key}` is in ADDED_HERE but core already protects it — drop the entry"
            );
        }
        for key in REMOVED_HERE {
            assert!(
                dpp_domain::PROTECTED_PATCH_FIELDS.contains(&key),
                "`{key}` is in REMOVED_HERE but core does not protect it — drop the entry"
            );
        }
    }

    #[test]
    fn refusal_names_every_protected_key_in_the_delta_and_sorts_them() {
        let err = refuse_protected(&serde_json::json!({
            "status": "active",
            "productName": "fine",
            "retentionLocked": true
        }))
        .expect_err("protected keys must be refused");
        let msg = err.to_string();
        assert!(msg.contains("retentionLocked"), "{msg}");
        assert!(msg.contains("status"), "{msg}");
        assert!(
            !msg.contains("productName"),
            "an allowed key must not be named as the reason: {msg}"
        );
        assert!(
            msg.find("retentionLocked") < msg.find("status"),
            "keys are sorted so the message is stable: {msg}"
        );
    }

    #[test]
    fn a_delta_of_only_allowed_keys_passes() {
        assert!(
            refuse_protected(&serde_json::json!({ "productName": "fine" })).is_ok(),
            "an unprotected key must not be refused"
        );
        assert!(
            refuse_protected(&serde_json::json!({ "componentRefs": [] })).is_ok(),
            "the declared divergence must actually diverge"
        );
    }
}
