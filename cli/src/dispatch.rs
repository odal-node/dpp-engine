//! Command dispatch: maps a parsed `Commands` tree to its `commands::run_*` handler.

use crate::cli_args::{
    Commands, FacilityCommands, KeyCommands, OperatorCommands, OperatorIdCommands,
    PassportCommands, ProfileCommands, SchemaCommands,
};
use crate::commands::{
    bootstrap::run_bootstrap,
    down::run_down,
    evidence::run_evidence,
    export::run_export,
    facility::{
        run_facility_add, run_facility_list, run_facility_remove, run_facility_set_default,
    },
    import::run_import,
    init::run_init,
    key::{run_key_create, run_key_list, run_key_revoke, run_key_use},
    lifecycle::{run_archive, run_history, run_suspend},
    list::run_passport_list,
    operator::{run_operator_set, run_operator_show},
    operator_id::{
        run_operator_id_add, run_operator_id_list, run_operator_id_remove,
        run_operator_id_set_primary,
    },
    profile::{
        run_profile_create, run_profile_list, run_profile_remove, run_profile_rename,
        run_profile_show, run_profile_use,
    },
    publish::run_publish,
    schema::run_schema,
    status::run_status,
    up::run_up,
    update::run_update,
    validate::run_validate,
    verify::run_verify,
};

pub fn should_enter_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::env::var("CI").is_err()
}

pub async fn dispatch(cmd: Commands) -> anyhow::Result<()> {
    match cmd {
        Commands::Init { vault_url, api_key } => run_init(vault_url, api_key).await,
        Commands::Up => run_up().await,
        Commands::Down => run_down().await,
        Commands::Status => run_status().await,
        Commands::Update => run_update().await,
        Commands::Bootstrap {
            legal_name,
            country,
            address,
            contact_email,
            did_web_url,
            admin_user,
            admin_pass,
            force,
        } => {
            run_bootstrap(
                legal_name,
                country,
                address,
                contact_email,
                did_web_url,
                admin_user,
                admin_pass,
                force,
            )
            .await
        }
        Commands::Operator {
            command: OperatorCommands::Show,
        } => run_operator_show().await,
        Commands::Operator {
            command:
                OperatorCommands::Set {
                    legal_name,
                    trade_name,
                    address,
                    country,
                    contact_email,
                    did_web_url,
                    retention_policy_days,
                },
        } => {
            run_operator_set(
                legal_name,
                trade_name,
                address,
                country,
                contact_email,
                did_web_url,
                retention_policy_days,
            )
            .await
        }
        Commands::Key {
            command: KeyCommands::Create { name, use_key },
        } => run_key_create(&name, use_key).await,
        Commands::Key {
            command: KeyCommands::List,
        } => run_key_list().await,
        Commands::Key {
            command: KeyCommands::Revoke { id },
        } => run_key_revoke(&id).await,
        Commands::Key {
            command: KeyCommands::Use { secret },
        } => run_key_use(&secret).await,
        Commands::Facility {
            command: FacilityCommands::List,
        } => run_facility_list().await,
        Commands::Facility {
            command:
                FacilityCommands::Add {
                    name,
                    scheme,
                    value,
                    country,
                    address,
                    default,
                },
        } => run_facility_add(name, scheme, value, country, address, default).await,
        Commands::Facility {
            command: FacilityCommands::SetDefault { id },
        } => run_facility_set_default(&id).await,
        Commands::Facility {
            command: FacilityCommands::Remove { id },
        } => run_facility_remove(&id).await,
        Commands::OperatorId {
            command: OperatorIdCommands::List,
        } => run_operator_id_list().await,
        Commands::OperatorId {
            command:
                OperatorIdCommands::Add {
                    scheme,
                    value,
                    label,
                    primary,
                },
        } => run_operator_id_add(scheme, value, label, primary).await,
        Commands::OperatorId {
            command: OperatorIdCommands::SetPrimary { id },
        } => run_operator_id_set_primary(&id).await,
        Commands::OperatorId {
            command: OperatorIdCommands::Remove { id },
        } => run_operator_id_remove(&id).await,
        Commands::Profile {
            command: ProfileCommands::List,
        } => run_profile_list(),
        Commands::Profile {
            command: ProfileCommands::Show { name },
        } => run_profile_show(name),
        Commands::Profile {
            command: ProfileCommands::Use { name },
        } => run_profile_use(&name),
        Commands::Profile {
            command:
                ProfileCommands::Create {
                    name,
                    vault_url,
                    kind,
                    force,
                },
        } => run_profile_create(&name, vault_url, kind, force),
        Commands::Profile {
            command: ProfileCommands::Remove { name },
        } => run_profile_remove(&name),
        Commands::Profile {
            command: ProfileCommands::Rename { old, new },
        } => run_profile_rename(&old, &new),
        Commands::Passport {
            command:
                PassportCommands::List {
                    status,
                    q,
                    facility_id,
                    limit,
                    json,
                },
        } => {
            run_passport_list(
                status.as_deref(),
                q.as_deref(),
                facility_id.as_deref(),
                limit,
                json,
            )
            .await
        }
        Commands::Passport {
            command: PassportCommands::Import { file },
        } => run_import(&file).await,
        Commands::Passport {
            command: PassportCommands::Validate,
        } => run_validate().await,
        Commands::Passport {
            command: PassportCommands::Publish { id },
        } => run_publish(id.as_deref()).await,
        Commands::Passport {
            command: PassportCommands::Suspend { id },
        } => run_suspend(&id).await,
        Commands::Passport {
            command: PassportCommands::Archive { id },
        } => run_archive(&id).await,
        Commands::Passport {
            command: PassportCommands::History { id },
        } => run_history(&id).await,
        Commands::Passport {
            command: PassportCommands::Evidence { id, output },
        } => run_evidence(&id, output.as_deref()).await,
        Commands::Passport {
            command:
                PassportCommands::Export {
                    format,
                    status,
                    output,
                },
        } => run_export(&format, status.as_deref(), output.as_deref()).await,
        Commands::Schema {
            command: SchemaCommands::Check,
        } => run_schema().await,
        Commands::Verify { file } => run_verify(&file),
    }
}
