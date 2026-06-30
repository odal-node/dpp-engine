//! `odal` — Odal Node management CLI: argument parsing and command dispatch.

use clap::{CommandFactory, Parser, Subcommand};

mod commands;
mod config;
mod console;
mod core;
mod credentials;
mod http;
mod stateless;

use commands::{
    bootstrap::run_bootstrap,
    down::run_down,
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
};
use console::setup::run_setup;

/// Odal Node — self-hosted installation manager
#[derive(Parser)]
#[command(name = "odal", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    /// Operate against a named profile (dev / prod / …). Overrides $ODAL_PROFILE
    /// and the saved current profile. See `odal profile --help`.
    #[arg(long, global = true)]
    profile: Option<String>,
    /// Re-run guided setup (connect · start · onboard). Bypasses the TTY guard.
    #[arg(long)]
    reconfigure: bool,
}

#[derive(Subcommand)]
enum Commands {
    // ── Infrastructure ───────────────────────────────────────────────────────
    /// Save connection config and scaffold docker/docker-compose.yml (for scripting/CI).
    /// Interactive operators: just run `odal` with no arguments.
    Init {
        /// Vault URL to save (default: http://localhost:8001/vault)
        #[arg(long)]
        vault_url: Option<String>,
        /// API key to save to config
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Start all services with Docker Compose
    Up,
    /// Stop all services
    Down,
    /// Show health status of all services
    Status,
    /// Pull latest container images
    Update,
    // ── Onboarding & auth ────────────────────────────────────────────────────
    /// Onboard the operator and mint the first API key
    Bootstrap {
        #[arg(long)]
        legal_name: Option<String>,
        #[arg(long)]
        country: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        contact_email: Option<String>,
        #[arg(long)]
        did_web_url: Option<String>,
        #[arg(long)]
        admin_user: Option<String>,
        #[arg(long)]
        admin_pass: Option<String>,
        /// Mint an additional key even if the node is already bootstrapped
        #[arg(long)]
        force: bool,
    },
    /// View or update the operator configuration
    Operator {
        #[command(subcommand)]
        command: OperatorCommands,
    },
    /// Manage API keys
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    // ── Registry identity ────────────────────────────────────────────────────
    /// Manage facilities (ESPR Annex III) stamped onto new passports
    Facility {
        #[command(subcommand)]
        command: FacilityCommands,
    },
    /// Manage economic-operator identifiers (ESPR Art. 13)
    #[command(name = "operator-id")]
    OperatorId {
        #[command(subcommand)]
        command: OperatorIdCommands,
    },
    // ── Profiles / environments ──────────────────────────────────────────────
    /// Manage named connection profiles (dev / prod / …)
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    // ── Passport lifecycle ───────────────────────────────────────────────────
    /// Digital product passport commands (import, validate, publish, lifecycle, export)
    Passport {
        #[command(subcommand)]
        command: PassportCommands,
    },
    // ── Schema ───────────────────────────────────────────────────────────────
    /// Schema management commands
    Schema {
        #[command(subcommand)]
        command: SchemaCommands,
    },
}

#[derive(Subcommand)]
enum PassportCommands {
    /// List or search passports (id, name, status) — no ID needed
    List {
        /// Filter by status (draft, active, suspended, archived)
        #[arg(long)]
        status: Option<String>,
        /// Free-text search across product name, batch, and manufacturer
        #[arg(long)]
        q: Option<String>,
        /// Filter to passports stamped with this exact facility identifier
        /// (see `odal facility list`)
        #[arg(long = "facility-id")]
        facility_id: Option<String>,
        /// Maximum results (server caps at 100)
        #[arg(long, default_value = "50")]
        limit: u32,
        /// Output raw JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Import passports from a CSV/TSV or JSON file (created as drafts)
    Import {
        /// Path to the CSV/TSV/JSON file
        file: String,
    },
    /// Validate draft passports against sector schemas
    Validate,
    /// Sign and publish draft passports (all drafts, or a specific ID)
    Publish {
        /// Specific passport ID to publish (publishes all drafts if omitted)
        id: Option<String>,
    },
    /// Suspend a published passport (serves 410 Gone)
    Suspend {
        /// Passport ID
        id: String,
    },
    /// Archive a passport (terminal state)
    Archive {
        /// Passport ID
        id: String,
    },
    /// Show a passport's audit trail
    History {
        /// Passport ID
        id: String,
    },
    /// Export passports to JSON or CSV
    Export {
        /// Output format
        #[arg(long, default_value = "json")]
        format: String,
        /// Filter by status (draft, active, suspended, archived)
        #[arg(long)]
        status: Option<String>,
        /// Output file (stdout if omitted)
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
enum SchemaCommands {
    /// Check if a schema update is available
    Check,
}

#[derive(Subcommand)]
enum OperatorCommands {
    /// Print the current operator configuration
    Show,
    /// Update operator fields (pass one or more)
    Set {
        #[arg(long)]
        legal_name: Option<String>,
        #[arg(long)]
        trade_name: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        country: Option<String>,
        #[arg(long)]
        contact_email: Option<String>,
        #[arg(long)]
        did_web_url: Option<String>,
        #[arg(long)]
        retention_policy_days: Option<i64>,
    },
}

#[derive(Subcommand)]
enum ProfileCommands {
    /// List all profiles (the active one is marked with `*`)
    List,
    /// Show one profile's settings (active profile if no name given)
    Show {
        /// Profile name (defaults to the active profile)
        name: Option<String>,
    },
    /// Switch the active profile
    Use {
        /// Profile name
        name: String,
    },
    /// Create a new profile
    Create {
        /// Profile name
        name: String,
        /// Vault URL for the new profile
        #[arg(long)]
        vault_url: Option<String>,
        /// Environment kind: dev or prod (inferred from the URL if omitted)
        #[arg(long)]
        kind: Option<String>,
        /// Overwrite an existing profile of the same name
        #[arg(long)]
        force: bool,
    },
    /// Remove a profile
    Remove {
        /// Profile name
        name: String,
    },
    /// Rename a profile
    Rename {
        /// Current name
        old: String,
        /// New name
        new: String,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Create a new API key (prints the secret once)
    Create {
        /// A label for the key
        name: String,
        /// Adopt the new key as this profile's active credential
        #[arg(long = "use")]
        use_key: bool,
    },
    /// List API keys (prefix only)
    List,
    /// Revoke an API key by id
    Revoke {
        /// API key id
        id: String,
    },
    /// Adopt an existing API key secret as this profile's active credential
    Use {
        /// The `odal_sk_…` secret to save
        secret: String,
    },
}

#[derive(Subcommand)]
enum FacilityCommands {
    /// List configured facilities (the default is marked with `*`)
    List,
    /// Add a facility (e.g. a GLN). Use --default to make it the default.
    Add {
        /// Human-readable facility name
        #[arg(long)]
        name: String,
        /// Identifier scheme (e.g. `gln`, `national`)
        #[arg(long, default_value = "gln")]
        scheme: String,
        /// Identifier value (e.g. the 13-digit GLN)
        #[arg(long)]
        value: String,
        /// ISO 3166-1 alpha-2 country code
        #[arg(long)]
        country: String,
        /// Optional street address
        #[arg(long)]
        address: Option<String>,
        /// Make this the default facility (stamped on new passports)
        #[arg(long)]
        default: bool,
    },
    /// Make a facility the default (stamped on new passports)
    SetDefault {
        /// Facility id
        id: String,
    },
    /// Remove a facility by id
    Remove {
        /// Facility id
        id: String,
    },
}

#[derive(Subcommand)]
enum OperatorIdCommands {
    /// List configured operator identifiers (the primary is marked with `*`)
    List,
    /// Add an operator identifier. Use --primary to make it the primary.
    Add {
        /// Identifier scheme (e.g. `vat`, `lei`, `eori`, `duns`)
        #[arg(long)]
        scheme: String,
        /// Identifier value (e.g. the VAT or LEI string)
        #[arg(long)]
        value: String,
        /// Optional human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Make this the primary identifier (stamped on new passports)
        #[arg(long)]
        primary: bool,
    },
    /// Make an operator identifier the primary (stamped on new passports)
    SetPrimary {
        /// Operator identifier id
        id: String,
    },
    /// Remove an operator identifier by id
    Remove {
        /// Operator identifier id
        id: String,
    },
}

fn should_enter_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::env::var("CI").is_err()
}

async fn dispatch(cmd: Commands) -> anyhow::Result<()> {
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
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    config::set_active_profile_override(cli.profile.clone());
    match cli.command {
        Some(cmd) => dispatch(cmd).await,
        None => {
            if cli.reconfigure {
                return run_setup().await;
            }
            if !should_enter_interactive() {
                Cli::command().print_help()?;
                std::process::exit(2);
            }
            console::run().await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_no_subcommand_gives_none() {
        let cli = Cli::parse_from(["odal"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn tty_guard_suppressed_in_test_runner() {
        // cargo test pipes stdin — not a TTY — so the guard returns false,
        // preventing interactive mode from launching in CI.
        assert!(!should_enter_interactive());
    }

    #[test]
    fn parse_reconfigure() {
        let cli = Cli::parse_from(["odal", "--reconfigure"]);
        assert!(cli.reconfigure);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parse_global_profile_flag() {
        let cli = Cli::parse_from(["odal", "--profile", "prod", "status"]);
        assert_eq!(cli.profile.as_deref(), Some("prod"));
        assert!(matches!(cli.command, Some(Commands::Status)));
    }

    #[test]
    fn parse_global_profile_flag_after_subcommand() {
        // `global = true` lets --profile appear after the subcommand too.
        let cli = Cli::parse_from(["odal", "status", "--profile", "dev"]);
        assert_eq!(cli.profile.as_deref(), Some("dev"));
    }

    #[test]
    fn parse_profile_use() {
        let cli = Cli::parse_from(["odal", "profile", "use", "prod"]);
        if let Some(Commands::Profile {
            command: ProfileCommands::Use { name },
        }) = cli.command
        {
            assert_eq!(name, "prod");
        } else {
            panic!("expected Profile::Use");
        }
    }

    #[test]
    fn parse_profile_create_with_flags() {
        let cli = Cli::parse_from([
            "odal",
            "profile",
            "create",
            "prod",
            "--vault-url",
            "https://n.example/vault",
            "--kind",
            "prod",
            "--force",
        ]);
        if let Some(Commands::Profile {
            command:
                ProfileCommands::Create {
                    name,
                    vault_url,
                    kind,
                    force,
                },
        }) = cli.command
        {
            assert_eq!(name, "prod");
            assert_eq!(vault_url.as_deref(), Some("https://n.example/vault"));
            assert_eq!(kind.as_deref(), Some("prod"));
            assert!(force);
        } else {
            panic!("expected Profile::Create");
        }
    }

    #[test]
    fn parse_init() {
        let cli = Cli::parse_from(["odal", "init"]);
        assert!(matches!(cli.command, Some(Commands::Init { .. })));
    }

    #[test]
    fn parse_up() {
        let cli = Cli::parse_from(["odal", "up"]);
        assert!(matches!(cli.command, Some(Commands::Up)));
    }

    #[test]
    fn parse_down() {
        let cli = Cli::parse_from(["odal", "down"]);
        assert!(matches!(cli.command, Some(Commands::Down)));
    }

    #[test]
    fn parse_status() {
        let cli = Cli::parse_from(["odal", "status"]);
        assert!(matches!(cli.command, Some(Commands::Status)));
    }

    #[test]
    fn parse_passport_publish_all() {
        let cli = Cli::parse_from(["odal", "passport", "publish"]);
        if let Some(Commands::Passport {
            command: PassportCommands::Publish { id },
        }) = cli.command
        {
            assert!(id.is_none());
        } else {
            panic!("expected Passport::Publish");
        }
    }

    #[test]
    fn parse_passport_publish_by_id() {
        let cli = Cli::parse_from(["odal", "passport", "publish", "abc-123"]);
        if let Some(Commands::Passport {
            command: PassportCommands::Publish { id },
        }) = cli.command
        {
            assert_eq!(id.as_deref(), Some("abc-123"));
        } else {
            panic!("expected Passport::Publish");
        }
    }

    #[test]
    fn parse_passport_list_with_filters() {
        let cli = Cli::parse_from([
            "odal",
            "passport",
            "list",
            "--status",
            "draft",
            "--q",
            "linen",
            "--facility-id",
            "4012345000009",
            "--json",
        ]);
        if let Some(Commands::Passport {
            command:
                PassportCommands::List {
                    status,
                    q,
                    facility_id,
                    limit,
                    json,
                },
        }) = cli.command
        {
            assert_eq!(status.as_deref(), Some("draft"));
            assert_eq!(q.as_deref(), Some("linen"));
            assert_eq!(facility_id.as_deref(), Some("4012345000009"));
            assert_eq!(limit, 50);
            assert!(json);
        } else {
            panic!("expected Passport::List");
        }
    }

    #[test]
    fn parse_passport_import() {
        let cli = Cli::parse_from(["odal", "passport", "import", "data.csv"]);
        if let Some(Commands::Passport {
            command: PassportCommands::Import { file },
        }) = cli.command
        {
            assert_eq!(file, "data.csv");
        } else {
            panic!("expected Passport::Import");
        }
    }

    #[test]
    fn parse_passport_export_defaults() {
        let cli = Cli::parse_from(["odal", "passport", "export"]);
        if let Some(Commands::Passport {
            command:
                PassportCommands::Export {
                    format,
                    status,
                    output,
                },
        }) = cli.command
        {
            assert_eq!(format, "json");
            assert!(status.is_none());
            assert!(output.is_none());
        } else {
            panic!("expected Passport::Export");
        }
    }

    #[test]
    fn parse_passport_export_with_options() {
        let cli = Cli::parse_from([
            "odal", "passport", "export", "--format", "csv", "--status", "active", "-o", "out.csv",
        ]);
        if let Some(Commands::Passport {
            command:
                PassportCommands::Export {
                    format,
                    status,
                    output,
                },
        }) = cli.command
        {
            assert_eq!(format, "csv");
            assert_eq!(status.as_deref(), Some("active"));
            assert_eq!(output.as_deref(), Some("out.csv"));
        } else {
            panic!("expected Passport::Export");
        }
    }

    #[test]
    fn parse_schema_check() {
        let cli = Cli::parse_from(["odal", "schema", "check"]);
        assert!(matches!(
            cli.command,
            Some(Commands::Schema {
                command: SchemaCommands::Check
            })
        ));
    }

    #[test]
    fn parse_passport_suspend() {
        let cli = Cli::parse_from(["odal", "passport", "suspend", "id-xyz"]);
        if let Some(Commands::Passport {
            command: PassportCommands::Suspend { id },
        }) = cli.command
        {
            assert_eq!(id, "id-xyz");
        } else {
            panic!("expected Passport::Suspend");
        }
    }

    #[test]
    fn parse_passport_history() {
        let cli = Cli::parse_from(["odal", "passport", "history", "id-xyz"]);
        if let Some(Commands::Passport {
            command: PassportCommands::History { id },
        }) = cli.command
        {
            assert_eq!(id, "id-xyz");
        } else {
            panic!("expected Passport::History");
        }
    }
}
