//! The shapes this service publishes, as distinct from the shapes it stores.
//!
//! A response type here is the API's own contract. It is built from the core
//! aggregate rather than being it, so a change inside `dpp-domain` reaches the
//! wire only by way of an edit somebody wrote in this module.

pub mod passport_response;

pub use passport_response::PassportResponse;
