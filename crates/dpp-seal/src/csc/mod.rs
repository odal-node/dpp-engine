//! Cloud Signature Consortium (CSC) API — wire types and (future) HTTP client.

pub mod client;
pub mod probe;
pub mod types;

pub use types::{
    CscCredentialInfo, CscCredentialStatus, CscKeyInfo, CscSignHashRequest, CscSignHashResponse,
};
