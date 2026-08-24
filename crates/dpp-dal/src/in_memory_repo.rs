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

use dpp_domain::domain::error::DppError;
use dpp_domain::domain::passport::{Passport, PassportId};
use dpp_domain::domain::status::PassportStatus;
use dpp_domain::ports::passport_repo::PassportRepository;

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
