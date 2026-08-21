//! Connection config and named profiles (`config.toml`): load, save, and resolution.

mod model;
mod paths;
mod profiles;
mod secrets;

pub use model::{Config, EnvKind, Profile, resolver_is_unstated_default, vault_url_from_node};
pub use paths::{config_dir, export_target};
pub use profiles::{
    NO_PROFILE_HINT, active_profile_name, create_profile, has_profiles, list_profiles,
    remove_profile, rename_profile, set_active_profile_override, use_profile,
};
pub use secrets::mask_secret;
