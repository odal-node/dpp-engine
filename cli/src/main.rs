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

/// Whether a panic message is `println!` reporting that the pipe it writes to
/// has been closed, as `head` does once it has its lines.
///
/// Matched on the message because that is all a panic carries: the I/O error
/// inside it is formatted away before the hook sees it. Unix says "Broken pipe"
/// (error 32); Windows says the pipe is closing (232) or ended (109).
fn is_closed_pipe_message(message: &str) -> bool {
    message.starts_with("failed printing to std")
        && ["os error 32", "os error 232", "os error 109"]
            .iter()
            .any(|code| message.contains(code))
}

/// End quietly when whatever reads our output goes away.
///
/// `println!` panics when stdout is a pipe that has been closed, so
/// `odal passport list | head -n 1` ended in a panic message and exit code 101.
/// A reader that has all it wanted is not a failure of ours. Any other panic,
/// including a failed write to a file or a full disk, still goes to the default
/// hook.
fn exit_quietly_when_the_reader_goes_away() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        if is_closed_pipe_message(message) {
            std::process::exit(0);
        }
        default_hook(info);
    }));
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    exit_quietly_when_the_reader_goes_away();
    let cli = Cli::parse();
    config::set_active_profile_override(cli.profile.clone());
    http::set_idempotency_key(cli.idempotency_key.clone());
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

    /// A variant's `///` doc comment is its help text, so a note written for
    /// the next reader of the code is printed to an operator. The note on why
    /// `Initiate` is boxed was.
    #[test]
    fn transfer_initiate_help_says_what_the_command_does_and_nothing_else() {
        let mut cli = Cli::command();
        let help = cli
            .find_subcommand_mut("passport")
            .and_then(|c| c.find_subcommand_mut("transfer"))
            .and_then(|c| c.find_subcommand_mut("initiate"))
            .expect("`odal passport transfer initiate` exists")
            .render_long_help()
            .to_string();
        assert!(help.contains("Sign a pending handover"), "{help}");
        assert!(
            !help.contains("Boxed"),
            "an implementation note is in the help:\n{help}"
        );
    }

    fn long_help(path: &[&str]) -> String {
        let mut command = Cli::command();
        let mut current = &mut command;
        for name in path {
            current = current
                .find_subcommand_mut(name)
                .unwrap_or_else(|| panic!("`odal {}` has no `{name}`", path.join(" ")));
        }
        current.render_long_help().to_string()
    }

    /// The help named four statuses and the node accepts six. Each one listed is
    /// also one the node's own status type reads, so the list cannot name a status
    /// that does not exist.
    #[test]
    fn the_status_filters_list_every_status_the_node_accepts() {
        let statuses = [
            "draft",
            "active",
            "suspended",
            "superseded",
            "retired",
            "deactivated",
        ];
        for status in statuses {
            assert!(
                serde_json::from_value::<dpp_domain::PassportStatus>(serde_json::json!(status))
                    .is_ok(),
                "the node does not read `{status}` as a status"
            );
        }
        for path in [["passport", "list"], ["passport", "export"]] {
            let help = long_help(&path);
            for status in statuses {
                assert!(help.contains(status), "`{status}` missing from:\n{help}");
            }
        }
    }

    /// Behaviour a command's name does not say, and its help once did not: each
    /// of these was learned by running it.
    #[test]
    fn help_states_what_the_command_does_beyond_what_its_name_says() {
        let publish = long_help(&["passport", "publish"]);
        assert!(publish.contains("suspended"), "{publish}");

        let retire = long_help(&["passport", "retire"]);
        assert!(retire.contains("retention period"), "{retire}");

        let remove = long_help(&["webhook", "remove"]);
        assert!(remove.contains("inactive"), "{remove}");

        let verify = long_help(&["verify"]);
        assert!(verify.contains("embedded"), "{verify}");
        assert!(verify.contains("current DID document"), "{verify}");
    }

    /// A field's `///` doc comment is its help text, so a 🚨 note written for
    /// the next reader of the code is printed to an operator. The note on
    /// `snapshot verify --key` was. Walks every command, so the next one fails
    /// here rather than in front of someone.
    #[test]
    fn no_help_text_carries_a_note_for_maintainers() {
        fn walk(cmd: &mut clap::Command, path: &str, leaks: &mut Vec<String>) {
            let help = cmd.render_long_help().to_string();
            if help.contains('🚨') {
                leaks.push(format!("{path}:\n{help}"));
            }
            for sub in cmd.get_subcommands_mut() {
                let path = format!("{path} {}", sub.get_name());
                walk(sub, &path, leaks);
            }
        }

        let mut leaks = Vec::new();
        walk(&mut Cli::command(), "odal", &mut leaks);
        assert!(
            leaks.is_empty(),
            "help text carries a maintainers' note:\n{}",
            leaks.join("\n\n")
        );
    }

    #[test]
    fn only_a_write_to_a_closed_pipe_is_treated_as_the_reader_leaving() {
        assert!(is_closed_pipe_message(
            "failed printing to stdout: Broken pipe (os error 32)"
        ));
        assert!(is_closed_pipe_message(
            "failed printing to stdout: The pipe is being closed. (os error 232)"
        ));
        // A full disk is a real failure of ours and must still be reported.
        assert!(!is_closed_pipe_message(
            "failed printing to stdout: No space left on device (os error 28)"
        ));
        assert!(!is_closed_pipe_message(
            "called `Option::unwrap()` on a `None` value"
        ));
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
            "--resolver-url",
            "https://dpp.n.example",
            "--kind",
            "prod",
            "--force",
        ]);
        if let Some(Commands::Profile {
            command:
                ProfileCommands::Create {
                    name,
                    node_url,
                    vault_url,
                    resolver_url,
                    kind,
                    force,
                },
        }) = cli.command
        {
            assert_eq!(name, "prod");
            assert!(node_url.is_none());
            assert_eq!(vault_url.as_deref(), Some("https://n.example/vault"));
            assert_eq!(resolver_url.as_deref(), Some("https://dpp.n.example"));
            assert_eq!(kind.as_deref(), Some("prod"));
            assert!(force);
        } else {
            panic!("expected Profile::Create");
        }
    }

    /// The two-flag shape a normal remote install uses: one origin for the node,
    /// one URL for the separately deployed resolver.
    #[test]
    fn parse_profile_create_with_node_origin() {
        let cli = Cli::parse_from([
            "odal",
            "profile",
            "create",
            "prod",
            "--node-url",
            "https://node.example.com",
            "--resolver-url",
            "https://dpp.example.com",
        ]);
        if let Some(Commands::Profile {
            command:
                ProfileCommands::Create {
                    node_url,
                    vault_url,
                    resolver_url,
                    ..
                },
        }) = cli.command
        {
            assert_eq!(node_url.as_deref(), Some("https://node.example.com"));
            assert!(vault_url.is_none());
            assert_eq!(resolver_url.as_deref(), Some("https://dpp.example.com"));
        } else {
            panic!("expected Profile::Create");
        }
    }

    /// `--node-url` and `--vault-url` describe the same thing at different
    /// depths. Rejecting the pair at the parser is what keeps the handlers free
    /// of a silent precedence rule no help text could explain.
    #[test]
    fn node_url_and_vault_url_are_mutually_exclusive() {
        for argv in [
            vec![
                "odal",
                "profile",
                "create",
                "prod",
                "--node-url",
                "https://node.example.com",
                "--vault-url",
                "https://node.example.com/vault",
            ],
            vec![
                "odal",
                "init",
                "--node-url",
                "https://node.example.com",
                "--vault-url",
                "https://node.example.com/vault",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "expected a conflict for {argv:?}"
            );
        }
    }

    #[test]
    fn parse_init_with_node_origin() {
        let cli = Cli::parse_from([
            "odal",
            "init",
            "--node-url",
            "https://node.example.com",
            "--resolver-url",
            "https://dpp.example.com",
        ]);
        if let Some(Commands::Init {
            node_url,
            resolver_url,
            ..
        }) = cli.command
        {
            assert_eq!(node_url.as_deref(), Some("https://node.example.com"));
            assert_eq!(resolver_url.as_deref(), Some("https://dpp.example.com"));
        } else {
            panic!("expected Init");
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
    fn parse_whoami() {
        let cli = Cli::parse_from(["odal", "whoami"]);
        assert!(matches!(cli.command, Some(Commands::Whoami)));
    }

    /// The file argument is optional: without it `validate` keeps checking the
    /// stored drafts, with it the same command dry-runs a body.
    #[test]
    fn parse_passport_validate_with_and_without_a_file() {
        let stored = Cli::parse_from(["odal", "passport", "validate"]);
        if let Some(Commands::Passport {
            command: PassportCommands::Validate { file },
        }) = stored.command
        {
            assert!(file.is_none());
        } else {
            panic!("expected Passport::Validate");
        }

        let dry_run = Cli::parse_from(["odal", "passport", "validate", "body.json"]);
        if let Some(Commands::Passport {
            command: PassportCommands::Validate { file },
        }) = dry_run.command
        {
            assert_eq!(file.as_deref(), Some("body.json"));
        } else {
            panic!("expected Passport::Validate");
        }
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
            command:
                PassportCommands::Import {
                    file,
                    product_group,
                },
        }) = cli.command
        {
            assert_eq!(file, "data.csv");
            assert!(product_group.is_none());
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
    fn parse_verify() {
        let cli = Cli::parse_from(["odal", "verify", "dossier.json"]);
        if let Some(Commands::Verify { target }) = cli.command {
            assert_eq!(target, "dossier.json");
        } else {
            panic!("expected Verify");
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

    #[test]
    fn parse_passport_stats() {
        let cli = Cli::parse_from(["odal", "passport", "stats", "id-xyz", "--days", "7"]);
        if let Some(Commands::Passport {
            command: PassportCommands::Stats { id, days, json },
        }) = cli.command
        {
            assert_eq!(id, "id-xyz");
            assert_eq!(days, 7);
            assert!(!json);
        } else {
            panic!("expected Passport::Stats");
        }
    }

    /// `odal registry [id]` predates `odal registry handle`, and adding the
    /// subcommand must not change what it means: runbooks and the node's own row
    /// messages name the old form.
    #[test]
    fn parse_registry_status_keeps_its_old_form() {
        let cli = Cli::parse_from(["odal", "registry"]);
        assert!(matches!(
            cli.command,
            Some(Commands::Registry {
                id: None,
                json: false,
                command: None
            })
        ));

        let cli = Cli::parse_from(["odal", "registry", "id-xyz", "--json"]);
        if let Some(Commands::Registry { id, json, command }) = cli.command {
            assert_eq!(id.as_deref(), Some("id-xyz"));
            assert!(json);
            assert!(command.is_none());
        } else {
            panic!("expected Registry");
        }
    }

    #[test]
    fn parse_registry_handle() {
        use cli_args::RegistryCommands;
        let cli = Cli::parse_from(["odal", "registry", "handle", "id-xyz", "CORR-1", "--json"]);
        if let Some(Commands::Registry {
            command:
                Some(RegistryCommands::Handle {
                    id,
                    correlation_id,
                    json,
                }),
            ..
        }) = cli.command
        {
            assert_eq!(id, "id-xyz");
            assert_eq!(correlation_id, "CORR-1");
            assert!(json);
        } else {
            panic!("expected Registry::Handle");
        }
    }

    #[test]
    fn parse_registry_abandon() {
        use cli_args::RegistryCommands;
        let cli = Cli::parse_from([
            "odal",
            "registry",
            "abandon",
            "id-xyz",
            "--reason",
            "withdrawn before it was registered",
        ]);
        if let Some(Commands::Registry {
            command: Some(RegistryCommands::Abandon { id, reason, json }),
            ..
        }) = cli.command
        {
            assert_eq!(id, "id-xyz");
            assert_eq!(reason, "withdrawn before it was registered");
            assert!(!json);
        } else {
            panic!("expected Registry::Abandon");
        }
    }

    /// A registration is not given up on without saying why: the write ends an
    /// obligation the node was tracking, and the reason is the trail's only account.
    #[test]
    fn abandoning_a_registration_requires_a_reason() {
        assert!(Cli::try_parse_from(["odal", "registry", "abandon", "id-xyz"]).is_err());
    }

    #[test]
    fn a_registry_handle_needs_both_identifiers() {
        assert!(Cli::try_parse_from(["odal", "registry", "handle", "id-xyz"]).is_err());
        assert!(Cli::try_parse_from(["odal", "registry", "handle"]).is_err());
    }

    #[test]
    fn parse_operator_stats() {
        let cli = Cli::parse_from(["odal", "stats", "--json"]);
        if let Some(Commands::Stats { days, json }) = cli.command {
            assert_eq!(days, 30, "default window");
            assert!(json);
        } else {
            panic!("expected Stats");
        }
    }
}
