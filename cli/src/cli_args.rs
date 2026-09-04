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
    /// Make this invocation safe to re-run. Sent as `Idempotency-Key` on the
    /// commands that create something; re-running with the same key returns the
    /// first outcome instead of creating a second resource.
    ///
    /// Intended for scripts: on a network error you cannot tell whether the
    /// write landed, and re-running blind is how duplicates happen. Pass the
    /// same value on the retry — and only on a retry of the *same* command, as
    /// a changed argument is a different request and is refused.
    ///
    /// Ignored by commands that create nothing; those are already safe to
    /// repeat.
    #[arg(long, global = true, value_name = "KEY")]
    pub idempotency_key: Option<String>,
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
    /// Report what the configured API key actually is (identity and scope)
    Whoami,
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
    /// Install signed product group plugins (verified, persisted, hot-swapped)
    Plugin {
        #[command(subcommand)]
        command: PluginCommands,
    },
    /// Manage the signed compliance-ruleset channel (Compliance Current)
    Ruleset {
        #[command(subcommand)]
        command: RulesetCommands,
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
    // ── Regulatory catalog ───────────────────────────────────────────────────
    /// Which product groups need a passport, from when, and under which acts
    #[command(name = "product-group")]
    ProductGroup {
        #[command(subcommand)]
        command: ProductGroupCommands,
    },
    /// Download the CSV import template for a product group (the header row
    /// `odal passport import` expects)
    Template {
        /// Product group key (battery, textile, steel, aluminium, tyre)
        product_group: String,
        /// Output file (stdout if omitted)
        #[arg(short, long)]
        output: Option<String>,
    },
    // ── EU registry ──────────────────────────────────────────────────────────
    /// EU registry sync status — the rollup, or one passport's record
    Registry {
        /// Passport ID (operator-wide rollup if omitted)
        id: Option<String>,
        /// Output raw JSON instead of a summary
        #[arg(long)]
        json: bool,
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
    /// Validate draft passports, or dry-run a passport body from a file
    Validate {
        /// Path to a passport JSON body to dry-run against the node. Nothing is
        /// created. Omit to validate the passports already stored as drafts.
        file: Option<String>,
    },
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
    /// Re-run the plausibility lint pack and store the refreshed findings.
    /// Findings are advisory — they never gate publish.
    Lint {
        /// Passport ID
        id: String,
        /// Output raw JSON instead of a summary
        #[arg(long)]
        json: bool,
    },
    /// Declare a passport end-of-life (terminal). The record is retained,
    /// never deleted — the passport outlives the product.
    Eol {
        /// Passport ID
        id: String,
        /// Why the product reached end-of-life
        #[arg(long, value_parser = ["recycled", "destroyed", "exported", "lost"])]
        reason: String,
        /// Derogation category permitting destruction — required for
        /// `--reason destroyed`, which is otherwise barred by the ESPR
        /// Art. 25 unsold-goods destruction ban
        #[arg(long)]
        derogation: Option<String>,
        /// The act or article the derogation is grounded in (OJ/CELEX ref)
        #[arg(long = "derogation-citation")]
        derogation_citation: Option<String>,
        /// Free-text note recorded with the declaration
        #[arg(long)]
        notes: Option<String>,
    },
    /// Walk and verify the component (BOM) tree — checks each node's signed
    /// public view against the hash pinned by its parent
    Tree {
        /// Passport ID of the tree root
        id: String,
        /// Output raw JSON instead of a summary
        #[arg(long)]
        json: bool,
    },
    /// Find a passport by its business identity rather than its ID
    Find {
        /// Product group key (battery, textile, …)
        #[arg(long = "product-group")]
        product_group: String,
        /// GTIN
        #[arg(long)]
        gtin: String,
        /// Batch identifier
        #[arg(long)]
        batch: Option<String>,
        /// Output raw JSON instead of a summary
        #[arg(long)]
        json: bool,
    },
    /// Transfer responsibility for a passport to another economic operator
    Transfer {
        #[command(subcommand)]
        command: TransferCommands,
    },
}

#[derive(Subcommand)]
pub enum TransferCommands {
    /// Sign a pending handover onto the passport's transfer chain. Only a
    /// published passport can be transferred.
    ///
    /// Boxed, and its eleven arguments held in their own struct: two full
    /// economic operators inline would make every variant of this enum — and
    /// so every variant of `Commands` above it — as large as this one.
    Initiate(Box<TransferInitiateArgs>),
    /// Countersign a pending handover and complete it
    Accept {
        /// Passport ID
        id: String,
    },
    /// End a pending handover as refused (terminal — frees the chain)
    Reject {
        /// Passport ID
        id: String,
    },
    /// End a pending handover as withdrawn (terminal — frees the chain)
    Cancel {
        /// Passport ID
        id: String,
    },
}

/// Both sides of a handover: who is giving responsibility up and who is taking
/// it on. The API needs a complete `ResponsibleOperator` for each, so all four
/// fields of each are required.
#[derive(clap::Args)]
pub struct TransferInitiateArgs {
    /// Passport ID
    pub id: String,
    /// DID of the outgoing operator — must match the chain head
    #[arg(long = "from-did")]
    pub from_did: String,
    /// Legal name of the outgoing operator
    #[arg(long = "from-name")]
    pub from_name: String,
    /// Supply-chain role of the outgoing operator
    #[arg(long = "from-role", value_parser = OPERATOR_ROLES)]
    pub from_role: String,
    /// ISO 3166-1 alpha-2 country of the outgoing operator
    #[arg(long = "from-country")]
    pub from_country: String,
    /// DID of the incoming operator
    #[arg(long = "to-did")]
    pub to_did: String,
    /// Legal name of the incoming operator
    #[arg(long = "to-name")]
    pub to_name: String,
    /// Supply-chain role of the incoming operator
    #[arg(long = "to-role", value_parser = OPERATOR_ROLES)]
    pub to_role: String,
    /// ISO 3166-1 alpha-2 country of the incoming operator
    #[arg(long = "to-country")]
    pub to_country: String,
    /// Why responsibility is moving
    #[arg(long, value_parser = TRANSFER_REASONS)]
    pub reason: String,
    /// Free-text note recorded on the transfer
    #[arg(long)]
    pub notes: Option<String>,
}

/// The `OperatorRole` enum as the API spells it. Listed here so `--from-role`
/// rejects a typo at parse time with the valid set, rather than costing a
/// round-trip to be told the same thing.
const OPERATOR_ROLES: [&str; 9] = [
    "manufacturer",
    "importer",
    "distributor",
    "authorisedRepresentative",
    "remanufacturer",
    "repurposer",
    "preparerForReuse",
    "repairer",
    "recycler",
];

/// The `TransferReason` enum as the API spells it — same reasoning as
/// [`OPERATOR_ROLES`].
const TRANSFER_REASONS: [&str; 7] = [
    "sale",
    "return",
    "remanufacturing",
    "repurposing",
    "preparationForReuse",
    "import",
    "insolvencySuccession",
];

#[derive(Subcommand)]
pub enum ProductGroupCommands {
    /// List every product group this node knows of, with whether a passport is
    /// required and from when
    List {
        /// Show only groups a passport is already required for
        #[arg(long)]
        required: bool,
        /// Output raw JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Show one product group's obligation in full, including the acts behind it
    Show {
        /// Product group key (battery, textile, toy, …)
        product_group: String,
        /// Output raw JSON instead of a summary
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum SchemaCommands {
    /// Check if a schema update is available
    Check,
    /// List every product group with a schema, and the version this node serves
    List {
        /// Output raw JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Print a product group's JSON Schema
    Show {
        /// Product group key (battery, textile, …)
        product_group: String,
        /// Schema version (the node's current one if omitted)
        version: Option<String>,
        /// Output file (stdout if omitted)
        #[arg(short, long)]
        output: Option<String>,
    },
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
    /// Show a facility's append-only provenance trail (retire, restore,
    /// default changes)
    Audit {
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
    /// Show an identifier's append-only provenance trail (retire, restore,
    /// primary changes)
    Audit {
        /// Operator identifier id
        id: String,
    },
}

#[derive(Subcommand)]
pub enum PluginCommands {
    /// Install a signed product group plugin. Uploads the `.wasm` and its sibling
    /// `<file>.sig`; the node verifies the signature against its pinned publisher
    /// key, gates the ABI, persists it, and hot-swaps it into service — no restart.
    Install {
        /// Path to the `.wasm` plugin file (its detached signature must sit
        /// alongside it as `<file>.sig`)
        file: String,
    },
}

#[derive(Subcommand)]
pub enum RulesetCommands {
    /// Re-read the signed ruleset channel now and hot-swap a verified bundle.
    /// The node verifies the manifest against its pinned publisher key, refuses
    /// a bundle that is not yet effective or older than the one in force, and
    /// swaps atomically — no restart. The node also polls on its own; this is
    /// how you say "take it now".
    Reload,
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
