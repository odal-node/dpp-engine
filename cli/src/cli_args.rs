//! Argument parsing: the `Cli` entrypoint and every `clap` subcommand tree.

use clap::{Parser, Subcommand};

/// Odal Node — self-hosted installation manager
#[derive(Parser)]
#[command(name = "odal", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
    /// Operate against a named profile (dev / prod / …). Overrides $ODAL_PROFILE
    /// and the saved current profile. See `odal profile --help`.
    #[arg(long, global = true)]
    pub profile: Option<String>,
    /// Re-run guided setup (connect · start · onboard). Bypasses the TTY guard.
    #[arg(long)]
    pub reconfigure: bool,
}

#[derive(Subcommand)]
pub enum Commands {
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
    /// Manage signed outbound webhooks (delivery of passport events)
    Webhook {
        #[command(subcommand)]
        command: WebhookCommands,
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
    // ── Evidence verification ────────────────────────────────────────────────
    /// Verify an evidence dossier against the node (see `odal passport
    /// evidence` to generate one)
    Verify {
        /// Stored dossier id, or path to a dossier JSON file
        target: String,
    },
}

#[derive(Subcommand)]
pub enum PassportCommands {
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
    /// Generate and store a signed evidence dossier (`odal verify` checks
    /// it) — proof + audit chain + transfer chain in one document.
    Evidence {
        /// Passport ID
        id: String,
        /// Output file (stdout if omitted)
        #[arg(short, long)]
        output: Option<String>,
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
pub enum SchemaCommands {
    /// Check if a schema update is available
    Check,
}

#[derive(Subcommand)]
pub enum OperatorCommands {
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
pub enum ProfileCommands {
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
pub enum KeyCommands {
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
    /// Adopt an existing API key secret as this profile's active credential.
    ///
    /// Prefer supplying the secret via the `ODAL_API_SECRET` environment
    /// variable or the interactive prompt (omit the argument) so it does not
    /// land in shell history or `ps`/`/proc/<pid>/cmdline`.
    Use {
        /// The `odal_sk_…` secret to save. If omitted, it is read from
        /// `ODAL_API_SECRET` or prompted for without echoing to the terminal —
        /// keeping the secret out of shell history and the process table.
        secret: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum FacilityCommands {
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
pub enum OperatorIdCommands {
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

#[derive(Subcommand)]
pub enum WebhookCommands {
    /// List configured webhook subscriptions
    List,
    /// Add a subscription. Omit --events to receive all events.
    Add {
        /// Receiver URL (must be https)
        url: String,
        /// Event filter — comma-separated subjects, e.g.
        /// `dpp.passport.published,dpp.passport.suspended`. Omit for all events.
        #[arg(long, value_delimiter = ',')]
        events: Vec<String>,
        /// Optional human-readable label
        #[arg(long)]
        description: Option<String>,
    },
    /// Send a test delivery to a subscription
    Test {
        /// Webhook subscription id
        id: String,
    },
    /// Remove a subscription by id
    Remove {
        /// Webhook subscription id
        id: String,
    },
}
