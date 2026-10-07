use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};

/// Parses and executes an xtask command.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let workspace = workspace_root()?;

    match cli.command {
        Task::CheckProfiles => check_profiles(&workspace),
        Task::Build { profile } => run_spec(build_spec(profile), &workspace),
        Task::Test { profile } => run_spec(test_spec(profile), &workspace),
        Task::Lint => run_specs(lint_specs(), &workspace),
        Task::Compose { profile } => run_spec(compose_spec(profile), &workspace),
        Task::Ci => run_spec(ci_spec(), &workspace),
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "cargo xtask",
    bin_name = "cargo xtask",
    about = "Development workflows for status-list-server"
)]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
enum Task {
    /// Check every supported feature profile.
    CheckProfiles,
    /// Build the server.
    Build {
        /// Cargo feature profile to build.
        #[arg(long, value_enum, default_value_t = FeatureProfile::Postgres)]
        profile: FeatureProfile,
    },
    /// Test the workspace.
    Test {
        /// Cargo feature profile to test.
        #[arg(long, value_enum, default_value_t = FeatureProfile::Postgres)]
        profile: FeatureProfile,
    },
    /// Run formatting, Clippy, cargo-audit, and cargo-machete.
    Lint,
    /// Build and start the matching Docker Compose services.
    Compose {
        /// Cargo feature and service profile to start.
        #[arg(long, value_enum, default_value_t = FeatureProfile::Postgres)]
        profile: FeatureProfile,
    },
    /// Run the complete local CI pipeline.
    Ci,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum FeatureProfile {
    Minimal,
    Postgres,
    #[value(name = "mysql")]
    MySql,
    Sqlite,
    Aws,
    Vault,
    Gcp,
    Azure,
    Redis,
}

impl FeatureProfile {
    const ALL: [Self; 9] = [
        Self::Minimal,
        Self::Postgres,
        Self::MySql,
        Self::Sqlite,
        Self::Aws,
        Self::Vault,
        Self::Gcp,
        Self::Azure,
        Self::Redis,
    ];

    fn cargo_args(self) -> &'static [&'static str] {
        match self {
            Self::Minimal => &["--no-default-features", "--features", "memory"],
            Self::Postgres => &["--features", "postgres"],
            Self::MySql => &["--features", "mysql"],
            Self::Sqlite => &["--features", "sqlite"],
            Self::Aws => &["--features", "postgres,aws"],
            Self::Vault => &["--features", "postgres,vault"],
            Self::Gcp => &["--features", "postgres,gcp"],
            Self::Azure => &["--features", "postgres,azure"],
            Self::Redis => &["--features", "postgres,redis"],
        }
    }

    fn docker_features(self) -> &'static str {
        match self {
            Self::Minimal => "memory",
            Self::Postgres => "postgres",
            Self::MySql => "mysql",
            Self::Sqlite => "sqlite",
            Self::Aws => "postgres,aws",
            Self::Vault => "postgres,vault",
            Self::Gcp => "postgres,gcp",
            Self::Azure => "postgres,azure",
            Self::Redis => "postgres,redis",
        }
    }

    fn compose_profiles(self) -> &'static [&'static str] {
        match self {
            Self::Minimal | Self::Sqlite => &[],
            Self::Postgres | Self::Vault | Self::Gcp | Self::Azure => &["postgres"],
            Self::MySql => &["mysql"],
            Self::Aws => &["postgres", "aws"],
            Self::Redis => &["postgres", "redis"],
        }
    }
}

impl fmt::Display for FeatureProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Minimal => "minimal",
            Self::Postgres => "postgres",
            Self::MySql => "mysql",
            Self::Sqlite => "sqlite",
            Self::Aws => "aws",
            Self::Vault => "vault",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
            Self::Redis => "redis",
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CommandSpec {
    program: &'static str,
    args: Vec<&'static str>,
    env: Vec<(&'static str, &'static str)>,
}

impl CommandSpec {
    fn new(program: &'static str, args: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            program,
            args: args.into_iter().collect(),
            env: Vec::new(),
        }
    }

    fn with_env(mut self, key: &'static str, value: &'static str) -> Self {
        self.env.push((key, value));
        self
    }

    fn to_command(&self, workspace: &Path) -> Command {
        let mut command = Command::new(self.program);
        command
            .args(&self.args)
            .envs(self.env.iter().copied())
            .current_dir(workspace);
        command
    }
}

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("xtask manifest directory has no workspace parent")
}

fn check_profiles(workspace: &Path) -> Result<()> {
    for profile in FeatureProfile::ALL {
        println!("Checking feature profile '{profile}'...");
        run_spec(check_spec(profile), workspace)
            .with_context(|| format!("feature profile '{profile}' failed"))?;
    }
    Ok(())
}

fn check_spec(profile: FeatureProfile) -> CommandSpec {
    let args = ["check", "--package", "status-list-server", "--all-targets"]
        .into_iter()
        .chain(profile.cargo_args().iter().copied());
    CommandSpec::new("cargo", args)
}

fn build_spec(profile: FeatureProfile) -> CommandSpec {
    let args = [
        "build",
        "--package",
        "status-list-server",
        "--bin",
        "status-list-server",
    ]
    .into_iter()
    .chain(profile.cargo_args().iter().copied());
    CommandSpec::new("cargo", args)
}

fn test_spec(profile: FeatureProfile) -> CommandSpec {
    let args = ["test", "--workspace"]
        .into_iter()
        .chain(profile.cargo_args().iter().copied());
    CommandSpec::new("cargo", args)
}

fn lint_specs() -> [CommandSpec; 4] {
    [
        CommandSpec::new("cargo", ["fmt", "--all", "--check"]),
        CommandSpec::new(
            "cargo",
            [
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
        CommandSpec::new("cargo", ["audit"]),
        // Invoke the plugin binary directly. Older cargo-machete releases parse
        // nested `cargo machete` arguments as paths when xtask itself is run by Cargo.
        CommandSpec::new("cargo-machete", ["--with-metadata"]),
    ]
}

fn compose_spec(profile: FeatureProfile) -> CommandSpec {
    let mut args = vec!["compose"];
    for compose_profile in profile.compose_profiles() {
        args.extend(["--profile", compose_profile]);
    }
    args.extend(["up", "--detach", "--build"]);

    let mut spec = CommandSpec::new("docker", args).with_env("FEATURES", profile.docker_features());
    if profile == FeatureProfile::MySql {
        spec = spec
            .with_env("APP_DATABASE__HOST", "mysql")
            .with_env("APP_DATABASE__PORT", "3306")
            .with_env("APP_DATABASE__USERNAME", "mysql")
            .with_env("APP_DATABASE__PASSWORD", "mysql")
            .with_env("APP_DATABASE__NAME", "status-list");
    }
    if profile == FeatureProfile::Sqlite {
        spec = spec
            .with_env("APP_DATABASE__URL", "sqlite::memory:?cache=shared")
            .with_env("APP_DATABASE__HOST", "")
            .with_env("APP_DATABASE__USERNAME", "")
            .with_env("APP_DATABASE__PASSWORD", "")
            .with_env("APP_DATABASE__NAME", "");
    }
    if profile == FeatureProfile::Redis {
        spec = spec.with_env("APP_CACHE__BACKEND", "redis");
    }
    spec
}

fn ci_spec() -> CommandSpec {
    CommandSpec::new("sh", ["local-ci.sh", "--full"])
}

fn run_specs<const N: usize>(specs: [CommandSpec; N], workspace: &Path) -> Result<()> {
    for spec in specs {
        run_spec(spec, workspace)?;
    }
    Ok(())
}

fn run_spec(spec: CommandSpec, workspace: &Path) -> Result<()> {
    let mut command = spec.to_command(workspace);
    println!("Running {command:?}");
    let display = format!("{command:?}");
    let status = command
        .status()
        .with_context(|| format!("failed to start {display}"))?;
    ensure!(status.success(), "{display} exited with {status}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("cargo xtask").chain(args.iter().copied()))
    }

    #[test]
    fn build_defaults_to_postgres_profile() {
        assert_eq!(
            parse(&["build"]).expect("build parses").command,
            Task::Build {
                profile: FeatureProfile::Postgres
            }
        );
    }

    #[test]
    fn profile_option_accepts_separate_and_equals_forms() {
        assert_eq!(
            parse(&["test", "--profile", "redis"])
                .expect("separate profile parses")
                .command,
            Task::Test {
                profile: FeatureProfile::Redis
            }
        );
        assert_eq!(
            parse(&["compose", "--profile=mysql"])
                .expect("equals profile parses")
                .command,
            Task::Compose {
                profile: FeatureProfile::MySql
            }
        );
    }

    #[test]
    fn parser_rejects_unknown_profile_and_extra_arguments() {
        let unknown = parse(&["build", "--profile", "oracle"])
            .expect_err("unknown profile must be rejected")
            .to_string();
        assert!(unknown.contains("invalid value 'oracle'"));

        let extra = parse(&["lint", "extra"])
            .expect_err("extra lint argument must be rejected")
            .to_string();
        assert!(extra.contains("unexpected argument 'extra'"));
    }

    #[test]
    fn cargo_feature_arguments_match_the_ticket_matrix() {
        let expected = [
            (
                FeatureProfile::Minimal,
                &["--no-default-features", "--features", "memory"][..],
            ),
            (FeatureProfile::Postgres, &["--features", "postgres"][..]),
            (FeatureProfile::MySql, &["--features", "mysql"][..]),
            (FeatureProfile::Sqlite, &["--features", "sqlite"][..]),
            (FeatureProfile::Aws, &["--features", "postgres,aws"][..]),
            (FeatureProfile::Vault, &["--features", "postgres,vault"][..]),
            (FeatureProfile::Gcp, &["--features", "postgres,gcp"][..]),
            (FeatureProfile::Azure, &["--features", "postgres,azure"][..]),
            (FeatureProfile::Redis, &["--features", "postgres,redis"][..]),
        ];

        for (profile, args) in expected {
            assert_eq!(profile.cargo_args(), args, "profile {profile}");
        }
    }

    #[test]
    fn compose_profiles_never_start_postgres_and_mysql_together() {
        for profile in FeatureProfile::ALL {
            let services = profile.compose_profiles();
            assert!(
                !(services.contains(&"postgres") && services.contains(&"mysql")),
                "profile {profile} starts two database services"
            );
        }
        assert_eq!(FeatureProfile::MySql.compose_profiles(), &["mysql"]);
    }

    #[test]
    fn compose_sets_backend_specific_runtime_environment() {
        let mysql = compose_spec(FeatureProfile::MySql);
        assert!(mysql.env.contains(&("APP_DATABASE__HOST", "mysql")));
        assert!(mysql.env.contains(&("APP_DATABASE__PORT", "3306")));

        let sqlite = compose_spec(FeatureProfile::Sqlite);
        assert!(
            sqlite
                .env
                .contains(&("APP_DATABASE__URL", "sqlite::memory:?cache=shared"))
        );
        assert!(sqlite.env.contains(&("APP_DATABASE__HOST", "")));

        let redis = compose_spec(FeatureProfile::Redis);
        assert!(redis.env.contains(&("APP_CACHE__BACKEND", "redis")));
    }

    #[test]
    fn ci_delegates_to_the_authoritative_full_local_pipeline() {
        assert_eq!(
            ci_spec(),
            CommandSpec::new("bash", ["local-ci.sh", "--full"])
        );
    }
}
