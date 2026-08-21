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
        /// Node origin, e.g. https://node.example.com. Sets both the vault and
        /// identity URLs, which the single-binary node serves on one origin.
        #[arg(long, conflicts_with = "vault_url")]
        node_url: Option<String>,
        /// Vault URL to save (default: http://localhost:8001/vault)
        #[arg(long)]
        vault_url: Option<String>,
        /// Resolver URL, e.g. https://dpp.example.com. Deployed separately from
        /// the node, so --node-url cannot derive it.
        #[arg(long)]
        resolver_url: Option<String>,
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
        /// Admin password. Pass `-` to read it from stdin, or set
        /// `ADMIN_PASSWORD`. A literal value here lands in shell history and is
        /// readable by other local users via `ps`/`/proc/<pid>/cmdline` for the
        /// process lifetime, so it warns. `bootstrap` is the scripting/CI
        /// entrypoint (no interactive prompt); interactive operators should run
        /// `odal` instead.
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
    /// Install signed sector plugins (verified, persisted, hot-swapped)
    Plugin {
        #[command(subcommand)]
        command: PluginCommands,
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
    // ── Qualified seals ──────────────────────────────────────────────────────
    /// eIDAS qualified seal inspection
    Seal {
        #[command(subcommand)]
        command: SealCommands,
    },
    // ── Insight ──────────────────────────────────────────────────────────────
    /// Operator-wide scan telemetry — how often your passports were resolved
    /// (per-passport detail: `odal passport stats <id>`)
    Stats {
        /// Trailing window in days (default 30)
        #[arg(long, default_value = "30")]
        days: u32,
        /// Output raw JSON instead of a summary
        #[arg(long)]
        json: bool,
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
    /// Show a passport's scan telemetry — resolutions and QR renders (aggregate)
    Stats {
        /// Passport ID
        id: String,
        /// Trailing window in days (default 30)
        #[arg(long, default_value = "30")]
        days: u32,
        /// Output raw JSON instead of a summary
        #[arg(long)]
        json: bool,
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
        /// Node origin, e.g. https://node.example.com. The single-binary node
        /// serves the vault and identity sub-routers on one origin, so this
        /// sets both. It cannot set the resolver, which deploys separately.
        #[arg(long, conflicts_with = "vault_url")]
        node_url: Option<String>,
        /// Vault URL for the new profile
        #[arg(long)]
        vault_url: Option<String>,
        /// Resolver URL, e.g. https://dpp.example.com. The resolver is a
        /// separate deployment on its own host, so it is never derived from
        /// --node-url; a prod profile that omits it keeps the localhost
        /// default and `odal status` will report the resolver unreachable.
        #[arg(long)]
        resolver_url: Option<String>,
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
    /// Prefer `-` (read from stdin), the `ODAL_API_SECRET` environment
    /// variable, or the interactive prompt (omit the argument) so the secret
    /// does not land in shell history or `ps`/`/proc/<pid>/cmdline`.
    Use {
        /// The `odal_sk_…` secret to save. Pass `-` to read it from stdin. If
        /// omitted, it is read from `ODAL_API_SECRET` or prompted for without
        /// echoing to the terminal. A literal value warns, because it is
        /// visible in shell history and the process table.
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
pub enum PluginCommands {
    /// Install a signed sector plugin. Uploads the `.wasm` and its sibling
    /// `<file>.sig`; the node verifies the signature against its pinned publisher
    /// key, gates the ABI, persists it, and hot-swaps it into service — no restart.
    Install {
        /// Path to the `.wasm` plugin file (its detached signature must sit
        /// alongside it as `<file>.sig`)
        file: String,
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

#[derive(Subcommand)]
pub enum SealCommands {
    /// Show sealing state. With no ID: how many published passports are
    /// unsealed, operator-wide. With an ID: that passport's seal, its signing
    /// certificate, and whether it still covers the current signature
    Status {
        /// Passport ID. Omit for the operator-wide summary.
        id: Option<String>,
        /// Output the raw route response instead of a summary
        #[arg(long)]
        json: bool,
    },
}
