//! Infrastructure adapters: NATS event bus, PostgreSQL job store, EU registry sync, S3 archive.

pub mod eu_registry_sync;
pub mod nats_event_bus;
pub mod pg_job_store;
pub mod s3_archive;
