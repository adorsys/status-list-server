use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, Subcommand, ValueEnum};
use color_eyre::eyre::{OptionExt, Result, WrapErr, ensure};

/// Parses and executes an xtask command.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let workspace = workspace_root()?;

    match cli.command {
        Task::CheckProfiles => check_profiles(&workspace),
        Task::Build { profile, release } => run_spec(build_spec(profile, release), &workspace),
        Task::Test { profile, args } => {
            let runner = detect_test_runner()?;
            for spec in test_specs(profile, runner, &args) {
                run_spec(spec, &workspace)?;
            }
            Ok(())
        }
        Task::Lint => run_checks(
            lint_specs().map(|(name, spec)| (name.to_owned(), spec)),
            |spec| run_spec(spec, &workspace),
        ),
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

#[derive(Debug, Eq, PartialEq, Subcommand)]
enum Task {
    /// Check every supported feature profile.
    CheckProfiles,
    /// Build the server.
    Build {
        /// Cargo feature profile to build.
        #[arg(long, value_enum, default_value_t = FeatureProfile::Postgres)]
        profile: FeatureProfile,
        /// Build with Cargo's release configuration.
        #[arg(long)]
        release: bool,
    },
    /// Test the workspace.
    Test {
        /// Cargo feature profile to test.
        #[arg(long, value_enum, default_value_t = FeatureProfile::Postgres)]
        profile: FeatureProfile,
        /// Test name filters and runner options following `--`.
        #[arg(last = true)]
        args: Vec<OsString>,
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

struct ProfileDefinition {
    features: &'static str,
    test_features: &'static str,
    compose_profiles: &'static [&'static str],
    compose_file: Option<&'static str>,
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

    const fn definition(self) -> ProfileDefinition {
        match self {
            Self::Minimal => ProfileDefinition {
                features: "memory",
                test_features: "",
                compose_profiles: &[],
                compose_file: None,
            },
            Self::Postgres => ProfileDefinition {
                features: "postgres",
                test_features: "postgres-tests",
                compose_profiles: &["postgres"],
                compose_file: None,
            },
            Self::MySql => ProfileDefinition {
                features: "mysql",
                test_features: "",
                compose_profiles: &["mysql"],
                compose_file: Some("compose/mysql.yml"),
            },
            Self::Sqlite => ProfileDefinition {
                features: "sqlite",
                test_features: "",
                compose_profiles: &[],
                compose_file: Some("compose/sqlite.yml"),
            },
            Self::Aws => ProfileDefinition {
                features: "postgres,aws",
                test_features: "postgres-tests",
                compose_profiles: &["postgres", "aws"],
                compose_file: None,
            },
            Self::Vault => ProfileDefinition {
                features: "postgres,vault",
                test_features: "postgres-tests",
                compose_profiles: &["postgres"],
                compose_file: None,
            },
            Self::Gcp => ProfileDefinition {
                features: "postgres,gcp",
                test_features: "postgres-tests",
                compose_profiles: &["postgres"],
                compose_file: None,
            },
            Self::Azure => ProfileDefinition {
                features: "postgres,azure",
                test_features: "postgres-tests",
                compose_profiles: &["postgres"],
                compose_file: None,
            },
            Self::Redis => ProfileDefinition {
                features: "postgres,redis",
                test_features: "postgres-tests,redis-tests",
                compose_profiles: &["postgres", "redis"],
                compose_file: Some("compose/redis.yml"),
            },
        }
    }

    fn cargo_args(self) -> Vec<&'static str> {
        let mut args = Vec::new();
        if self == Self::Minimal {
            args.push("--no-default-features");
        }
        args.extend(["--features", self.definition().features]);
        args
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
    args: Vec<OsString>,
    env: Vec<(&'static str, &'static str)>,
}

impl CommandSpec {
    fn new(program: &'static str, args: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
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
        .ok_or_eyre("xtask manifest directory has no workspace parent")
}

fn check_profiles(workspace: &Path) -> Result<()> {
    let checks = FeatureProfile::ALL.into_iter().flat_map(|profile| {
        [
            (
                format!("{profile}: isolated library"),
                isolated_check_spec(profile),
            ),
            (format!("{profile}: supported targets"), check_spec(profile)),
        ]
    });
    run_checks(checks, |spec| run_spec(spec, workspace))
}

fn isolated_check_spec(profile: FeatureProfile) -> CommandSpec {
    CommandSpec::new(
        "cargo",
        [
            "check",
            "--package",
            "status-list-server",
            "--lib",
            "--no-default-features",
            "--features",
            profile.definition().features,
        ],
    )
}

fn check_spec(profile: FeatureProfile) -> CommandSpec {
    let args = ["check", "--package", "status-list-server", "--all-targets"]
        .into_iter()
        .chain(profile.cargo_args());
    CommandSpec::new("cargo", args)
}

fn build_spec(profile: FeatureProfile, release: bool) -> CommandSpec {
    let mut args: Vec<_> = [
        "build",
        "--package",
        "status-list-server",
        "--bin",
        "status-list-server",
    ]
    .into_iter()
    .chain(profile.cargo_args())
    .collect();
    if release {
        args.push("--release");
    }
    CommandSpec::new("cargo", args)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestRunner {
    Cargo,
    Nextest,
}

fn detect_test_runner() -> Result<TestRunner> {
    match Command::new("cargo-nextest")
        .args(["nextest", "--version"])
        .output()
    {
        Ok(output) => {
            ensure!(
                output.status.success(),
                "cargo-nextest version probe failed: {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(TestRunner::Nextest)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            println!(
                "cargo-nextest is not installed; using cargo test without nextest's timeouts and test groups."
            );
            Ok(TestRunner::Cargo)
        }
        Err(error) => Err(error).wrap_err("failed to probe cargo-nextest"),
    }
}

fn test_specs(
    profile: FeatureProfile,
    runner: TestRunner,
    test_args: &[OsString],
) -> Vec<CommandSpec> {
    let mut specs = match runner {
        TestRunner::Cargo => vec![CommandSpec::new("cargo", ["test", "--workspace"])],
        TestRunner::Nextest => vec![
            CommandSpec::new("cargo", ["nextest", "run", "--workspace", "--all-targets"]),
            CommandSpec::new("cargo", ["test", "--doc", "--workspace"]),
        ],
    };
    let test_features = profile.definition().test_features;
    for spec in &mut specs {
        spec.args
            .extend(profile.cargo_args().into_iter().map(OsString::from));
        if !test_features.is_empty() {
            spec.args
                .extend(["--features", test_features].map(OsString::from));
        }
        if !test_args.is_empty() {
            spec.args.push("--".into());
            spec.args.extend_from_slice(test_args);
        }
    }
    specs
}

fn lint_specs() -> [(&'static str, CommandSpec); 4] {
    [
        (
            "formatting",
            CommandSpec::new("cargo", ["fmt", "--all", "--check"]),
        ),
        (
            "Clippy",
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
        ),
        ("audit", CommandSpec::new("cargo", ["audit"])),
        // Invoke the plugin binary directly. Older cargo-machete releases parse
        // nested `cargo machete` arguments as paths when xtask itself is run by Cargo.
        (
            "machete",
            CommandSpec::new("cargo-machete", ["--with-metadata"]),
        ),
    ]
}

fn compose_spec(profile: FeatureProfile) -> CommandSpec {
    let definition = profile.definition();
    let mut args = vec!["compose", "-f", "docker-compose.yml"];
    if let Some(file) = definition.compose_file {
        args.extend(["-f", file]);
    }
    for compose_profile in definition.compose_profiles {
        args.extend(["--profile", compose_profile]);
    }
    args.extend(["up", "--detach", "--build"]);

    CommandSpec::new("docker", args).with_env("FEATURES", definition.features)
}

fn ci_spec() -> CommandSpec {
    CommandSpec::new("bash", ["local-ci.sh", "--full"])
}

fn run_checks(
    checks: impl IntoIterator<Item = (String, CommandSpec)>,
    mut execute: impl FnMut(CommandSpec) -> Result<()>,
) -> Result<()> {
    let mut results = Vec::new();
    for (name, spec) in checks {
        println!("Checking {name}...");
        results.push((name, execute(spec)));
    }
    println!("\nCheck results:");
    let mut failures = Vec::new();
    for (name, result) in results {
        match result {
            Ok(()) => println!("PASS {name}"),
            Err(error) => {
                eprintln!("FAIL {name}: {error:#}");
                failures.push(name);
            }
        }
    }
    ensure!(
        failures.is_empty(),
        "failed checks: {}",
        failures.join(", ")
    );
    Ok(())
}

fn run_spec(spec: CommandSpec, workspace: &Path) -> Result<()> {
    let mut command = spec.to_command(workspace);
    println!("Running {command:?}");
    let display = format!("{command:?}");
    let status = command
        .status()
        .wrap_err_with(|| format!("failed to start {display}"))?;
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
                profile: FeatureProfile::Postgres,
                release: false,
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
                profile: FeatureProfile::Redis,
                args: vec![],
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
    fn build_release_and_test_arguments_preserve_the_selected_profile() {
        assert_eq!(
            parse(&["build", "--profile", "sqlite", "--release"])
                .unwrap()
                .command,
            Task::Build {
                profile: FeatureProfile::Sqlite,
                release: true
            }
        );
        assert!(
            build_spec(FeatureProfile::Sqlite, true)
                .args
                .contains(&OsString::from("--release"))
        );
        assert!(
            !build_spec(FeatureProfile::Sqlite, false)
                .args
                .contains(&OsString::from("--release"))
        );
        let args = vec![OsString::from("my test"), OsString::from("--exact")];
        assert_eq!(
            parse(&["test", "--profile", "sqlite", "--", "my test", "--exact"])
                .unwrap()
                .command,
            Task::Test {
                profile: FeatureProfile::Sqlite,
                args: args.clone()
            }
        );
        for runner in [TestRunner::Cargo, TestRunner::Nextest] {
            for spec in test_specs(FeatureProfile::Sqlite, runner, &args) {
                assert_eq!(
                    &spec.args[spec.args.len() - 3..],
                    &[OsString::from("--"), args[0].clone(), args[1].clone()]
                );
            }
        }
        assert!(parse(&["build", "--", "--features", "mysql"]).is_err());
    }

    #[test]
    fn nextest_runs_all_targets_and_preserves_doctests() {
        let specs = test_specs(FeatureProfile::Minimal, TestRunner::Nextest, &[]);
        assert_eq!(specs.len(), 2);
        assert_eq!(
            specs[0].args,
            [
                "nextest",
                "run",
                "--workspace",
                "--all-targets",
                "--no-default-features",
                "--features",
                "memory"
            ]
        );
        assert_eq!(
            specs[1].args,
            [
                "test",
                "--doc",
                "--workspace",
                "--no-default-features",
                "--features",
                "memory"
            ]
        );
        assert_eq!(
            test_specs(FeatureProfile::Minimal, TestRunner::Cargo, &[]).len(),
            1
        );
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
            let services = profile.definition().compose_profiles;
            assert!(
                !(services.contains(&"postgres") && services.contains(&"mysql")),
                "profile {profile} starts two database services"
            );
        }
        assert_eq!(
            FeatureProfile::MySql.definition().compose_profiles,
            &["mysql"]
        );
    }

    #[test]
    fn compose_uses_the_profile_matrix_and_never_passes_credentials() {
        let expected = [
            (FeatureProfile::Minimal, "memory", &[][..], None),
            (
                FeatureProfile::Postgres,
                "postgres",
                &["postgres"][..],
                None,
            ),
            (
                FeatureProfile::MySql,
                "mysql",
                &["mysql"][..],
                Some("compose/mysql.yml"),
            ),
            (
                FeatureProfile::Sqlite,
                "sqlite",
                &[][..],
                Some("compose/sqlite.yml"),
            ),
            (
                FeatureProfile::Aws,
                "postgres,aws",
                &["postgres", "aws"][..],
                None,
            ),
            (
                FeatureProfile::Vault,
                "postgres,vault",
                &["postgres"][..],
                None,
            ),
            (FeatureProfile::Gcp, "postgres,gcp", &["postgres"][..], None),
            (
                FeatureProfile::Azure,
                "postgres,azure",
                &["postgres"][..],
                None,
            ),
            (
                FeatureProfile::Redis,
                "postgres,redis",
                &["postgres", "redis"][..],
                Some("compose/redis.yml"),
            ),
        ];
        for (profile, features, services, file) in expected {
            let spec = compose_spec(profile);
            let mut args = vec!["compose", "-f", "docker-compose.yml"];
            if let Some(file) = file {
                args.extend(["-f", file]);
            }
            for service in services {
                args.extend(["--profile", service]);
            }
            args.extend(["up", "--detach", "--build"]);
            assert_eq!(spec.args, args, "profile {profile}");
            assert_eq!(spec.env, [("FEATURES", features)], "profile {profile}");
        }
    }

    #[test]
    fn test_profiles_enable_integration_tests_without_changing_build_features() {
        let expected = [
            (FeatureProfile::Minimal, ""),
            (FeatureProfile::Postgres, "postgres-tests"),
            (FeatureProfile::MySql, ""),
            (FeatureProfile::Sqlite, ""),
            (FeatureProfile::Aws, "postgres-tests"),
            (FeatureProfile::Vault, "postgres-tests"),
            (FeatureProfile::Gcp, "postgres-tests"),
            (FeatureProfile::Azure, "postgres-tests"),
            (FeatureProfile::Redis, "postgres-tests,redis-tests"),
        ];
        for (profile, test_features) in expected {
            let mut args = vec!["test", "--workspace"];
            args.extend(profile.cargo_args());
            if !test_features.is_empty() {
                args.extend(["--features", test_features]);
            }
            assert_eq!(
                test_specs(profile, TestRunner::Cargo, &[])[0].args,
                args,
                "profile {profile}"
            );
            for spec in test_specs(profile, TestRunner::Nextest, &[]) {
                if !test_features.is_empty() {
                    assert!(
                        spec.args.contains(&OsString::from(test_features)),
                        "profile {profile}"
                    );
                }
            }
            assert!(
                !build_spec(profile, false)
                    .args
                    .iter()
                    .any(|arg| arg.to_string_lossy().contains("-tests"))
            );
        }
    }

    #[test]
    fn isolated_checks_disable_defaults_and_leave_test_helpers_to_supported_checks() {
        for profile in FeatureProfile::ALL {
            let isolated = isolated_check_spec(profile);
            assert!(
                isolated
                    .args
                    .contains(&OsString::from("--no-default-features"))
            );
            assert!(isolated.args.contains(&OsString::from("--lib")));
            assert!(!isolated.args.contains(&OsString::from("--all-targets")));
            assert_eq!(
                isolated.args.last(),
                Some(&OsString::from(profile.definition().features))
            );
            assert!(
                check_spec(profile)
                    .args
                    .contains(&OsString::from("--all-targets"))
            );
            assert_eq!(
                check_spec(profile)
                    .args
                    .contains(&OsString::from("--no-default-features")),
                profile == FeatureProfile::Minimal
            );
        }
    }

    #[test]
    fn checks_continue_after_failures_and_report_every_failed_step() {
        let checks = ["first", "second", "third", "fourth"].map(|name| {
            (
                name.to_owned(),
                CommandSpec::new(name, std::iter::empty::<&str>()),
            )
        });
        let mut executed = Vec::new();
        let error = run_checks(checks, |spec| {
            executed.push(spec.program);
            if matches!(spec.program, "first" | "third") {
                color_eyre::eyre::bail!("simulated failure");
            }
            Ok(())
        })
        .expect_err("any failed step must fail the task");
        assert_eq!(executed, ["first", "second", "third", "fourth"]);
        assert_eq!(error.to_string(), "failed checks: first, third");
    }

    #[test]
    fn ci_delegates_to_the_authoritative_full_local_pipeline() {
        assert_eq!(
            ci_spec(),
            CommandSpec::new("bash", ["local-ci.sh", "--full"])
        );
    }
}
