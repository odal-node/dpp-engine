//! Infrastructure adapters: NATS event bus, PostgreSQL job store, EU registry sync, S3 archive.

pub mod credential_issuers;
pub mod drain;
pub mod nats_event_bus;
pub mod pg_job_store;
pub mod registry;
pub mod registry_drain;
pub mod ruleset;
pub mod s3_archive;
#[cfg(feature = "s3")]
pub mod s3_snapshot;
pub mod seal_drain;
pub mod snapshot_drain;
pub mod snapshot_store;
pub mod transfer_drain;
pub mod webhook_drain;
