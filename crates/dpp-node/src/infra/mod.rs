//! Infrastructure adapters: NATS event bus, PostgreSQL job store, EU registry sync, S3 archive.

pub mod drain;
pub mod nats_event_bus;
pub mod pg_job_store;
pub mod registry;
pub mod registry_drain;
pub mod ruleset;
pub mod s3_archive;
pub mod s3_snapshot;
pub mod snapshot_drain;
pub mod webhook_drain;
