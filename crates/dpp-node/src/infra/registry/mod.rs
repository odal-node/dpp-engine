//! EU Central DPP Registry sync adapter (ESPR Art. 13).

mod client;
mod config;
mod mapping;
mod token;

pub use client::EuRegistrySync;
pub use config::EuRegistrySyncConfig;

#[cfg(test)]
mod tests;
