//! Sector plugin loader — compile, verify signature, and cache a `LoadedPlugin`.

mod discover;
mod plugin;
mod signing;

pub use discover::discover_plugins;
pub use plugin::LoadedPlugin;
