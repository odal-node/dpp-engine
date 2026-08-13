//! Local development sealing backend.
//!
//! Signs in-process with a locally generated key instead of calling a trust
//! service provider. The point is to exercise the whole pipeline — port
//! contract, digest handling, envelope, storage, verification path — without a
//! provider account, a contract, or a sandbox credential.
//!
//! **The certificate is not on an EU Trusted List.** That is a property of the
//! certificate, not of this code: nothing in the signing or verification path
//! differs between a self-signed key and a qualified one. What differs is the
//! legal weight, which is none.

pub mod config;

pub use config::LocalConfig;
