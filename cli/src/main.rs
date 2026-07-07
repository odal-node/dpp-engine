//! `odal` — Odal Node management CLI: argument parsing and command dispatch.

use clap::{CommandFactory, Parser};

mod cli_args;
mod commands;
mod config;
mod console;
mod core;
mod credentials;
mod dispatch;
mod http;
mod stateless;

use cli_args::Cli;
use console::setup::run_setup;
use dispatch::{dispatch, should_enter_interactive};

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
    use cli_args::{Commands, PassportCommands, ProfileCommands, SchemaCommands};

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
