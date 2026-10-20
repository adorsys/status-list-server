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
        Task::Issuer { command } => issuer_command(command),
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
    /// Validate and maintain the operator-managed issuer registry.
    Issuer {
        #[command(subcommand)]
        command: IssuerTask,
    },
}

#[derive(Debug, Eq, PartialEq, Subcommand)]
enum IssuerTask {
    /// Add a new issuer using a public JWK; the issuer id and kid are generated.
    Add {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        jwk: String,
        #[arg(long, default_value = "ES256")]
        alg: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long, default_value = "standard")]
        tier: String,
    },
    /// Add a rotation key to an existing issuer; kid is derived from the JWK thumbprint.
    AddKey {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        issuer: String,
        #[arg(long)]
        jwk: String,
        #[arg(long, default_value = "ES256")]
        alg: String,
    },
}

fn issuer_command(command: IssuerTask) -> Result<()> {
    match command {
        IssuerTask::Add {
            file,
            jwk,
            alg,
            display_name,
            tier,
        } => {
            let mut root = load_registry_yaml(&file)?;
            let key = registry_key(&jwk, &alg)?;
            let mut issuer = serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "aggregation_id": uuid::Uuid::new_v4().to_string(),
                "tier": tier,
                "keys": [key],
            });
            if let Some(display_name) = display_name {
                issuer["display_name"] = serde_json::Value::String(display_name);
            }
            let item = issuer;
            root.get_mut("issuers")
                .and_then(serde_json::Value::as_array_mut)
                .ok_or_eyre("registry issuers must be a sequence")?
                .push(item.clone());
            write_registry_yaml(&file, root, RegistryInsertion::Issuer(item))
        }
        IssuerTask::AddKey {
            file,
            issuer,
            jwk,
            alg,
        } => {
            let mut root = load_registry_yaml(&file)?;
            let key = registry_key(&jwk, &alg)?;
            let issuers = root
                .get_mut("issuers")
                .and_then(serde_json::Value::as_array_mut)
                .ok_or_eyre("registry issuers must be a sequence")?;
            let issuer_index = issuers
                .iter()
                .position(|entry| {
                    entry.get("id").and_then(serde_json::Value::as_str) == Some(issuer.as_str())
                })
                .ok_or_eyre("issuer not found")?;
            let entry = issuers
                .get_mut(issuer_index)
                .ok_or_eyre("issuer not found")?;
            entry
                .get_mut("keys")
                .and_then(serde_json::Value::as_array_mut)
                .ok_or_eyre("issuer keys must be a sequence")?
                .push(key.clone());
            write_registry_yaml(&file, root, RegistryInsertion::Key { issuer_index, key })
        }
    }
}

fn load_registry_yaml(file: &Path) -> Result<serde_json::Value> {
    let text = std::fs::read_to_string(file).wrap_err("read issuer registry")?;
    serde_saphyr::from_str(&text).wrap_err("parse issuer registry")
}

fn registry_key(raw_jwk: &str, alg: &str) -> Result<serde_json::Value> {
    let json: serde_json::Value =
        serde_json::from_str(raw_jwk).wrap_err("parse public JWK JSON")?;
    let jwk: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(json.clone()).wrap_err("validate public JWK")?;
    let kid = jwk
        .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
        .wrap_err("compute JWK thumbprint")?;
    Ok(serde_json::json!({"kid": kid, "alg": alg, "jwk": json}))
}

enum RegistryInsertion {
    Issuer(serde_json::Value),
    Key {
        issuer_index: usize,
        key: serde_json::Value,
    },
}

fn sequence_item(value: &serde_json::Value, indent: usize) -> Result<String> {
    let yaml = serde_saphyr::to_string(value)?;
    let mut lines = yaml.lines();
    let first = lines.next().ok_or_eyre("empty YAML item")?;
    let mut rendered = format!("{}- {first}\n", " ".repeat(indent));
    for line in lines {
        rendered.push_str(&format!("{}  {line}\n", " ".repeat(indent)));
    }
    Ok(rendered)
}

fn insert_registry_item(original: &str, insertion: RegistryInsertion) -> Result<String> {
    let mut lines: Vec<String> = original.lines().map(|line| format!("{line}\n")).collect();
    let issuers = lines
        .iter()
        .position(|line| line.starts_with("issuers:"))
        .ok_or_eyre("expected block-style issuers section; paste the generated entry manually")?;
    let section_end = (issuers + 1..lines.len())
        .find(|&i| {
            let line = lines[i].as_str();
            !line.trim().is_empty() && !line.starts_with([' ', '#'])
        })
        .unwrap_or(lines.len());
    match insertion {
        RegistryInsertion::Issuer(item) => {
            let snippet = sequence_item(&item, 2)?;
            if lines[issuers].trim_end() == "issuers: []" {
                lines[issuers] = format!("issuers:\n{snippet}");
            } else {
                ensure!(
                    lines[issuers].trim_end() == "issuers:",
                    "expected block-style issuers section; paste the generated entry manually"
                );
                lines.insert(section_end, snippet);
            }
        }
        RegistryInsertion::Key { issuer_index, key } => {
            ensure!(
                lines[issuers].trim_end() == "issuers:",
                "expected block-style issuers section; paste the generated entry manually"
            );
            let issuer_starts: Vec<usize> = (issuers + 1..section_end)
                .filter(|&i| lines[i].starts_with("  - "))
                .collect();
            let start = *issuer_starts
                .get(issuer_index)
                .ok_or_eyre("could not locate issuer in block-style YAML")?;
            let end = issuer_starts
                .get(issuer_index + 1)
                .copied()
                .unwrap_or(section_end);
            let keys = (start..end)
                .find(|&i| lines[i].starts_with("    keys:"))
                .ok_or_eyre("could not locate issuer keys in block-style YAML")?;
            let key_indent = (keys + 1..end)
                .find(|&i| lines[i].trim_start().starts_with("- "))
                .map(|i| lines[i].len() - lines[i].trim_start().len())
                .unwrap_or(6);
            let snippet = sequence_item(&key, key_indent)?;
            if lines[keys].trim() == "keys: []" {
                lines[keys] = format!("    keys:\n{snippet}");
            } else {
                ensure!(
                    lines[keys].trim() == "keys:",
                    "expected block-style issuer keys; paste the generated key manually"
                );
                let key_end = (keys + 1..end)
                    .find(|&i| {
                        lines[i].starts_with("    ")
                            && !lines[i].starts_with("      ")
                            && !lines[i].trim_start().starts_with('#')
                            && !lines[i].trim_start().starts_with("- ")
                    })
                    .unwrap_or(end);
                lines.insert(key_end, snippet);
            }
        }
    }
    Ok(lines.concat())
}

fn write_registry_yaml(
    file: &Path,
    value: serde_json::Value,
    insertion: RegistryInsertion,
) -> Result<()> {
    let original = std::fs::read_to_string(file).wrap_err("read issuer registry")?;
    let content = insert_registry_item(&original, insertion)?;
    let actual: serde_json::Value =
        serde_saphyr::from_str(&content).wrap_err("parse edited issuer registry")?;
    ensure!(
        actual == value,
        "edited registry differs from validated candidate"
    );
    let parent = file.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).wrap_err("create temporary issuer registry")?;
    std::io::Write::write_all(&mut temporary, content.as_bytes())
        .wrap_err("write temporary issuer registry")?;
    validate_registry_file(temporary.path())?;
    temporary
        .as_file()
        .set_permissions(std::fs::metadata(file)?.permissions())?;
    temporary
        .persist(file)
        .map_err(|error| error.error)
        .wrap_err("replace issuer registry atomically")?;
    println!("updated {}", file.display());
    Ok(())
}

fn validate_registry_file(file: &Path) -> Result<()> {
    let workspace = workspace_root()?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.args([
        "run",
        "--quiet",
        "--package",
        "status-list-server",
        "--bin",
        "status-list-server",
        "--",
    ]);
    let status = command
        .arg("issuer-registry")
        .current_dir(workspace)
        .env("APP_MANAGEMENT_AUTH__ISSUERS_FILE", file)
        .status()
        .wrap_err("run status-list-server issuer-registry validator")?;
    ensure!(
        status.success(),
        "updated issuer registry failed validation"
    );
    Ok(())
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
    compose_files: &'static [&'static str],
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
                compose_files: &[],
            },
            Self::Postgres => ProfileDefinition {
                features: "postgres",
                test_features: "postgres-tests",
                compose_profiles: &["postgres"],
                compose_files: &["compose/postgres.yml"],
            },
            Self::MySql => ProfileDefinition {
                features: "mysql",
                test_features: "",
                compose_profiles: &["mysql"],
                compose_files: &["compose/mysql.yml"],
            },
            Self::Sqlite => ProfileDefinition {
                features: "sqlite",
                test_features: "",
                compose_profiles: &[],
                compose_files: &["compose/sqlite.yml"],
            },
            Self::Aws => ProfileDefinition {
                features: "postgres,aws",
                test_features: "postgres-tests",
                compose_profiles: &["postgres", "aws"],
                compose_files: &["compose/postgres.yml"],
            },
            Self::Vault => ProfileDefinition {
                features: "postgres,vault",
                test_features: "postgres-tests",
                compose_profiles: &["postgres"],
                compose_files: &["compose/postgres.yml"],
            },
            Self::Gcp => ProfileDefinition {
                features: "postgres,gcp",
                test_features: "postgres-tests",
                compose_profiles: &["postgres"],
                compose_files: &["compose/postgres.yml"],
            },
            Self::Azure => ProfileDefinition {
                features: "postgres,azure",
                test_features: "postgres-tests",
                compose_profiles: &["postgres"],
                compose_files: &["compose/postgres.yml"],
            },
            Self::Redis => ProfileDefinition {
                features: "postgres,redis",
                test_features: "postgres-tests,redis-tests",
                compose_profiles: &["postgres", "redis"],
                compose_files: &["compose/postgres.yml", "compose/redis.yml"],
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
    for file in definition.compose_files {
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
            (FeatureProfile::Minimal, "memory", &[][..], &[][..]),
            (
                FeatureProfile::Postgres,
                "postgres",
                &["postgres"][..],
                &["compose/postgres.yml"][..],
            ),
            (
                FeatureProfile::MySql,
                "mysql",
                &["mysql"][..],
                &["compose/mysql.yml"][..],
            ),
            (
                FeatureProfile::Sqlite,
                "sqlite",
                &[][..],
                &["compose/sqlite.yml"][..],
            ),
            (
                FeatureProfile::Aws,
                "postgres,aws",
                &["postgres", "aws"][..],
                &["compose/postgres.yml"][..],
            ),
            (
                FeatureProfile::Vault,
                "postgres,vault",
                &["postgres"][..],
                &["compose/postgres.yml"][..],
            ),
            (
                FeatureProfile::Gcp,
                "postgres,gcp",
                &["postgres"][..],
                &["compose/postgres.yml"][..],
            ),
            (
                FeatureProfile::Azure,
                "postgres,azure",
                &["postgres"][..],
                &["compose/postgres.yml"][..],
            ),
            (
                FeatureProfile::Redis,
                "postgres,redis",
                &["postgres", "redis"][..],
                &["compose/postgres.yml", "compose/redis.yml"][..],
            ),
        ];
        for (profile, features, services, files) in expected {
            let spec = compose_spec(profile);
            let mut args = vec!["compose", "-f", "docker-compose.yml"];
            for file in files {
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

    #[test]
    fn issuer_commands_generate_ids_and_validate_before_writing() {
        let file = std::env::temp_dir().join(format!(
            "issuer-registry-xtask-{}.yaml",
            uuid::Uuid::new_v4()
        ));
        let initial =
            "# Operator notes must survive CLI edits.\nversion: 1\nissuers: []\nadmins: []\n";
        std::fs::write(&file, initial).unwrap();
        let public_jwk = r#"{"kty":"EC","crv":"P-256","x":"chypcSL_5pNDkx4dzv1dppYLpI_bYISWR_aw4JARneY","y":"YwrO4sum6xF2PMUqSshAKVzLPJ-Ul87HgD7NGTo-oMA"}"#;

        issuer_command(IssuerTask::Add {
            file: file.clone(),
            jwk: public_jwk.to_string(),
            alg: "ES256".into(),
            display_name: None,
            tier: "standard".into(),
        })
        .unwrap();
        let validated: serde_json::Value =
            serde_saphyr::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(validated["issuers"][0]["keys"].as_array().unwrap().len(), 1);
        assert!(
            std::fs::read_to_string(&file)
                .unwrap()
                .starts_with("# Operator notes must survive CLI edits.")
        );
        let rotated_jwk = r#"{"kty":"EC","crv":"P-256","x":"qaCUinBNo9IgFyzWGAu6KfXt3F7eO96BcnzXj5CzedY","y":"BWYxfxFdS_axRuHChV_3uQ1DQFccSMXFqNrBqdBobks"}"#;
        issuer_command(IssuerTask::AddKey {
            file: file.clone(),
            issuer: validated["issuers"][0]["id"].as_str().unwrap().to_owned(),
            jwk: rotated_jwk.into(),
            alg: "ES256".into(),
        })
        .unwrap();
        let rotated: serde_json::Value =
            serde_saphyr::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(rotated["issuers"][0]["keys"].as_array().unwrap().len(), 2);
        assert!(
            std::fs::read_to_string(&file)
                .unwrap()
                .starts_with("# Operator notes must survive CLI edits.")
        );
        let issuer_id = validated["issuers"][0]["id"]
            .as_str()
            .unwrap()
            .parse::<uuid::Uuid>()
            .unwrap();
        assert_eq!(issuer_id.get_version(), Some(uuid::Version::Random));
        let bytes_before_invalid_update = std::fs::read(&file).unwrap();

        let private_jwk = public_jwk.replace("\"y\":", "\"d\":\"private\",\"y\":");
        assert!(
            issuer_command(IssuerTask::AddKey {
                file: file.clone(),
                issuer: validated["issuers"][0]["id"].as_str().unwrap().to_owned(),
                jwk: private_jwk,
                alg: "ES256".into(),
            })
            .is_err()
        );
        assert_eq!(std::fs::read(&file).unwrap(), bytes_before_invalid_update);

        let mut private_registry: serde_json::Value =
            serde_saphyr::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        private_registry["issuers"][0]["keys"][0]["jwk"]["d"] =
            serde_json::Value::String("private-material".into());
        std::fs::write(&file, serde_json::to_vec(&private_registry).unwrap()).unwrap();
        assert!(
            validate_registry_file(&file).is_err(),
            "the server validator must reject private JWK material"
        );
        let _ = std::fs::remove_file(file);
    }
}
