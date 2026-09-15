//! An in-memory [`PassportRepository`], for suites that need the port without a
//! database.
//!
//! # Why it lives beside `PgPassportRepo`
//!
//! It is an alternative implementation of the same port, so it belongs with the
//! other one rather than in a test-support crate. Both consumers —
//! `dpp-node`'s suites and `dpp-vault`'s — already depend on `dpp-dal`.
//!
//! It was copied into three suites first. The `impl` blocks were byte-for-byte
//! identical; the structs had already diverged, one having grown
//! `Arc` + `Clone` that the other two lacked. That is the same drift the
//! Postgres harness went through on its way to eight copies and six
//! implementations, caught earlier.
//!
//! Gated behind `test-harness` with the container harness, and `dpp-dal` is
//! `publish = false`, so it ships nowhere.
//!
//! # What it is not
//!
//! Not a substitute for the Postgres suites. It stores passports in a map and
//! enforces none of the things the database does — no retention trigger, no
//! append-only audit, no app-role privilege boundary, no `LIKE` escaping. A test
//! asserting any of those must use [`start_pg`](crate::test_harness::start_pg).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dpp_domain::error::DppError;
use dpp_domain::passport::{Passport, PassportId};
use dpp_domain::ports::passport_repo::PassportRepository;
use dpp_domain::status::PassportStatus;

/// A [`PassportRepository`] backed by a `HashMap`.
///
/// `Default` is the only constructor; it starts empty.
///
/// `Clone` shares the same map rather than copying it — two clones see each
/// other's writes. That is what a suite handing the repo to a component while
/// keeping a handle to assert against needs, and it is why the store is behind
/// an `Arc`: of the three copies this replaces, one had already grown that
/// requirement and the other two had not.
#[derive(Default, Clone)]
pub struct InMemoryPassportRepo {
    store: Arc<Mutex<HashMap<PassportId, Passport>>>,
}

#[async_trait::async_trait]
impl PassportRepository for InMemoryPassportRepo {
    async fn create(&self, passport: Passport) -> Result<Passport, DppError> {
        self.store
            .lock()
            .unwrap()
            .insert(passport.id, passport.clone());
        Ok(passport)
    }

    async fn find_by_id(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        Ok(self.store.lock().unwrap().get(&id).cloned())
    }

    /// Returns any stored passport regardless of status.
    ///
    /// Deliberately not filtered: a suite using this double is exercising a
    /// caller, not the publication policy, and a double that silently hid
    /// non-published rows would make those callers look correct when they are
    /// not. A test that needs the real filter needs the real repository.
    async fn find_published_by_id(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        self.find_by_id(id).await
    }

    /// Always `None` — GTIN lookup is not modelled here.
    ///
    /// The real query matches a GS1 Digital Link path segment inside
    /// `qrCodeUrl` and refuses non-numeric input so a `LIKE` metacharacter
    /// cannot widen the match. Approximating that in a map would make a test
    /// pass against behaviour the database does not have, so this answers
    /// nothing rather than answering wrongly.
    async fn find_published_by_gtin(&self, _gtin: &str) -> Result<Option<Passport>, DppError> {
        Ok(None)
    }

    /// Answers nothing, for the same reason as `find_published_by_gtin` above:
    /// the real lookup is a `LIKE` over `qrCodeUrl` with a numeric-only guard,
    /// and approximating that here would make a test pass against behaviour the
    /// database does not have.
    async fn find_by_gtin_any_status(&self, _gtin: &str) -> Result<Option<Passport>, DppError> {
        Ok(None)
    }

    async fn find_by_id_any_status(&self, id: PassportId) -> Result<Option<Passport>, DppError> {
        self.find_by_id(id).await
    }

    async fn update(&self, passport: Passport) -> Result<Passport, DppError> {
        self.store
            .lock()
            .unwrap()
            .insert(passport.id, passport.clone());
        Ok(passport)
    }

    /// Merge a delta, refusing the same fields the Postgres backend refuses.
    ///
    /// Overridden rather than inherited. Core's default guard reads
    /// `PROTECTED_PATCH_FIELDS` undiverged, and this build deliberately diverges
    /// from it — so inheriting meant this double refused a `componentRefs` patch
    /// that production accepts. A suite asserting the refusal proved something
    /// true only of the double, which is the one thing a double must never do.
    ///
    /// Null-removal is matched too: the database path deletes a key whose value
    /// is `null`, while core's default `extend`s it in as `Value::Null`. The two
    /// agree for an `Option` field and part company for a `Vec`, so the cheaper
    /// behaviour is not the same behaviour.
    async fn patch_fields(
        &self,
        id: PassportId,
        delta: serde_json::Value,
    ) -> Result<Passport, DppError> {
        crate::protected_fields::refuse_protected(&delta)?;

        let mut g = self.store.lock().unwrap();
        let passport = g
            .get(&id)
            .ok_or_else(|| DppError::NotFound(id.to_string()))?;

        let mut doc = serde_json::to_value(passport)
            .map_err(|e| DppError::Internal(format!("serialize: {e}")))?;
        if let (serde_json::Value::Object(dm), serde_json::Value::Object(pm)) = (&delta, &mut doc) {
            for (k, v) in dm {
                if v.is_null() {
                    pm.remove(k);
                } else {
                    pm.insert(k.clone(), v.clone());
                }
            }
        }
        let patched: Passport = serde_json::from_value(doc)
            .map_err(|e| DppError::Internal(format!("deserialize: {e}")))?;
        g.insert(id, patched.clone());
        Ok(patched)
    }

    async fn update_status(
        &self,
        id: PassportId,
        status: PassportStatus,
    ) -> Result<Passport, DppError> {
        let mut g = self.store.lock().unwrap();
        let mut p = g
            .get(&id)
            .cloned()
            .ok_or_else(|| DppError::NotFound(id.to_string()))?;
        p.status = status;
        g.insert(id, p.clone());
        Ok(p)
    }

    /// Every stored passport. Filters and paging are ignored.
    async fn list(
        &self,
        _status: Option<PassportStatus>,
        _q: Option<&str>,
        _facility_id: Option<&str>,
        _limit: u32,
        _offset: u32,
    ) -> Result<Vec<Passport>, DppError> {
        Ok(self.store.lock().unwrap().values().cloned().collect())
    }

    async fn count(
        &self,
        _status: Option<PassportStatus>,
        _facility_id: Option<&str>,
    ) -> Result<u64, DppError> {
        Ok(self.store.lock().unwrap().len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryPassportRepo;
    use dpp_domain::error::DppError;
    use dpp_domain::passport::PassportId;
    use dpp_domain::ports::passport_repo::PassportRepository;

    /// This double must refuse exactly what the database refuses.
    ///
    /// It inherited core's undiverged default before, so it rejected a
    /// `componentRefs` patch that Postgres accepts — and every suite built on it
    /// proved that rejection. Asserted here without storing a passport: the
    /// guard runs *before* the lookup, so a protected key answers `Validation`
    /// on an empty repository while an allowed one gets as far as `NotFound`.
    /// That difference is the whole question, and it needs no fixture.
    #[tokio::test]
    async fn the_double_applies_the_same_patch_guard_as_the_database() {
        let repo = InMemoryPassportRepo::default();
        let id = PassportId::new();

        assert!(
            matches!(
                repo.patch_fields(id, serde_json::json!({ "status": "active" }))
                    .await,
                Err(DppError::Validation(_))
            ),
            "a protected key must be refused before the lookup"
        );

        assert!(
            matches!(
                repo.patch_fields(id, serde_json::json!({ "componentRefs": [] }))
                    .await,
                Err(DppError::NotFound(_))
            ),
            "the declared divergence must reach the lookup, not be refused — this is \
             the case that used to disagree with Postgres"
        );

        assert!(
            matches!(
                repo.patch_fields(id, serde_json::json!({ "productName": "x" }))
                    .await,
                Err(DppError::NotFound(_))
            ),
            "an ordinary patchable field must reach the lookup"
        );
    }
}
