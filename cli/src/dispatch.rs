//! Command dispatch: maps a parsed `Commands` tree to its `commands::run_*` handler.

use crate::cli_args::{
    Commands, CredentialCommands, FacilityCommands, KeyCommands, OperatorCommands,
    OperatorIdCommands, PassportCommands, PluginCommands, ProductGroupCommands, ProfileCommands,
    RulesetCommands, SchemaCommands, SealCommands, TransferCommands, WebhookCommands,
};
use crate::commands::{
    bootstrap::run_bootstrap,
    catalog::{
        run_product_group_list, run_product_group_show, run_schema_list, run_schema_show,
        run_template,
    },
    credential::run_credential_issue,
    down::run_down,
    evidence::run_evidence,
    export::run_export,
    facility::{
        run_facility_add, run_facility_list, run_facility_remove, run_facility_set_default,
    },
    import::run_import,
    init::run_init,
    inspect::{run_eol, run_find, run_lint, run_tree},
    key::{run_key_create, run_key_list, run_key_revoke, run_key_use},
    lifecycle::{run_archive, run_history, run_suspend},
    list::run_passport_list,
    operator::{run_operator_set, run_operator_show},
    operator_id::{
        run_operator_id_add, run_operator_id_list, run_operator_id_remove,
        run_operator_id_set_primary,
    },
    plugin::run_plugin_install,
    profile::{
        run_profile_create, run_profile_list, run_profile_remove, run_profile_rename,
        run_profile_show, run_profile_use,
    },
    publish::run_publish,
    registry::{run_facility_audit, run_operator_id_audit, run_registry},
    ruleset::run_ruleset_reload,
    schema::run_schema,
    seal::run_seal_status,
    stats::{run_operator_stats, run_passport_stats},
    status::run_status,
    transfer::{run_transfer_initiate, run_transfer_resolve},
    up::run_up,
    update::run_update,
    validate::run_validate,
    verify::run_verify,
    webhook::{run_webhook_add, run_webhook_list, run_webhook_remove, run_webhook_test},
    whoami::run_whoami,
};

/// Resolve an API-key secret without requiring it as a shell argument (which
/// would land in shell history and `ps`/`/proc/<pid>/cmdline`): use the flag if
/// given, else the `ODAL_API_SECRET` env var, else a hidden interactive prompt.
fn resolve_api_secret(arg: Option<String>) -> anyhow::Result<String> {
    if let Some(s) = crate::credentials::resolve_secret_arg(arg, "set `ODAL_API_SECRET`")? {
        return Ok(s);
    }
    if let Ok(s) = std::env::var("ODAL_API_SECRET")
        && !s.is_empty()
    {
        return Ok(s);
    }
    Ok(inquire::Password::new("API key secret:")
        .without_confirmation()
        .prompt()?)
}

pub fn should_enter_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::env::var("CI").is_err()
}

pub async fn dispatch(cmd: Commands) -> anyhow::Result<()> {
    match cmd {
        Commands::Init {
            node_url,
            vault_url,
            resolver_url,
            api_key,
        } => run_init(node_url, vault_url, resolver_url, api_key).await,
        Commands::Up => run_up().await,
        Commands::Down => run_down().await,
        Commands::Status => run_status().await,
        Commands::Whoami => run_whoami().await,
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
        } => run_key_use(&resolve_api_secret(secret)?).await,
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
        Commands::Facility {
            command: FacilityCommands::Audit { id },
        } => run_facility_audit(&id).await,
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
        Commands::OperatorId {
            command: OperatorIdCommands::Audit { id },
        } => run_operator_id_audit(&id).await,
        Commands::Credential {
            command:
                CredentialCommands::Issue {
                    holder_did,
                    name,
                    role,
                    country,
                    product_groups,
                    valid_for_days,
                },
        } => {
            run_credential_issue(crate::core::credential::IssueRequest {
                holder_did,
                name,
                role,
                country,
                product_groups,
                valid_for_days,
            })
            .await
        }
        Commands::Webhook {
            command: WebhookCommands::List,
        } => run_webhook_list().await,
        Commands::Webhook {
            command:
                WebhookCommands::Add {
                    url,
                    events,
                    description,
                },
        } => run_webhook_add(url, events, description).await,
        Commands::Webhook {
            command: WebhookCommands::Test { id },
        } => run_webhook_test(&id).await,
        Commands::Webhook {
            command: WebhookCommands::Remove { id },
        } => run_webhook_remove(&id).await,
        Commands::Plugin {
            command: PluginCommands::Install { file },
        } => run_plugin_install(&file).await,
        Commands::Ruleset {
            command: RulesetCommands::Reload,
        } => run_ruleset_reload().await,
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
                    node_url,
                    vault_url,
                    resolver_url,
                    kind,
                    force,
                },
        } => run_profile_create(&name, node_url, vault_url, resolver_url, kind, force),
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
            command: PassportCommands::Validate { file },
        } => run_validate(file).await,
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
            command: PassportCommands::Stats { id, days, json },
        } => run_passport_stats(&id, days, json).await,
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
        Commands::Passport {
            command: PassportCommands::Lint { id, json },
        } => run_lint(&id, json).await,
        Commands::Passport {
            command:
                PassportCommands::Eol {
                    id,
                    reason,
                    derogation,
                    derogation_citation,
                    notes,
                },
        } => {
            run_eol(
                &id,
                &reason,
                derogation.as_deref(),
                derogation_citation.as_deref(),
                notes.as_deref(),
            )
            .await
        }
        Commands::Passport {
            command: PassportCommands::Tree { id, json },
        } => run_tree(&id, json).await,
        Commands::Passport {
            command:
                PassportCommands::Find {
                    product_group,
                    gtin,
                    batch,
                    json,
                },
        } => run_find(&product_group, &gtin, batch.as_deref(), json).await,
        Commands::Passport {
            command: PassportCommands::Transfer { command },
        } => match command {
            TransferCommands::Initiate(args) => run_transfer_initiate(&args).await,
            TransferCommands::Accept { id } => run_transfer_resolve(&id, "accept").await,
            TransferCommands::Reject { id } => run_transfer_resolve(&id, "reject").await,
            TransferCommands::Cancel { id } => run_transfer_resolve(&id, "cancel").await,
        },
        Commands::Schema {
            command: SchemaCommands::Check,
        } => run_schema().await,
        Commands::Schema {
            command: SchemaCommands::List { json },
        } => run_schema_list(json).await,
        Commands::Schema {
            command:
                SchemaCommands::Show {
                    product_group,
                    version,
                    output,
                },
        } => run_schema_show(&product_group, version.as_deref(), output.as_deref()).await,
        Commands::ProductGroup {
            command: ProductGroupCommands::List { required, json },
        } => run_product_group_list(required, json).await,
        Commands::ProductGroup {
            command:
                ProductGroupCommands::Show {
                    product_group,
                    json,
                },
        } => run_product_group_show(&product_group, json).await,
        Commands::Template {
            product_group,
            output,
        } => run_template(&product_group, output.as_deref()).await,
        Commands::Registry { id, json } => run_registry(id.as_deref(), json).await,
        Commands::Verify { target } => run_verify(&target).await,
        Commands::Seal {
            command: SealCommands::Status { id, json },
        } => run_seal_status(id.as_deref(), json).await,
        Commands::Stats { days, json } => run_operator_stats(days, json).await,
    }
}
