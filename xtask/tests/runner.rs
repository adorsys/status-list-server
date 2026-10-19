#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture {
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "xtask-runner-{}-{nonce}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let fixture = Self { directory };
        fixture.executable(
            "cargo",
            "printf '%s\\n' 'COMMAND' \"$@\" >> \"$COMMAND_LOG\"",
        );
        fixture
    }

    fn executable(&self, name: &str, body: &str) {
        let path = self.directory.join(name);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(args)
            .env("PATH", &self.directory)
            .env("COMMAND_LOG", self.directory.join("commands"))
            .output()
            .unwrap()
    }

    fn commands(&self) -> String {
        fs::read_to_string(self.directory.join("commands")).unwrap_or_default()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn missing_nextest_falls_back_to_cargo_and_preserves_test_arguments() {
    let fixture = Fixture::new();
    let result = fixture.run(&[
        "test",
        "--profile",
        "sqlite",
        "--",
        "test name; literal",
        "--exact",
    ]);
    assert!(result.status.success(), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("using cargo test"));
    assert_eq!(
        fixture.commands(),
        "COMMAND\ntest\n--workspace\n--features\nsqlite\n--\ntest name; literal\n--exact\n"
    );
}

#[test]
fn installed_nextest_is_followed_by_doctests_with_the_same_profile_and_filters() {
    let fixture = Fixture::new();
    fixture.executable("cargo-nextest", "exit 0");
    let result = fixture.run(&["test", "--profile", "redis", "--", "my_test", "--exact"]);
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        fixture.commands(),
        "COMMAND\nnextest\nrun\n--workspace\n--all-targets\n--features\npostgres,redis\n--features\npostgres-tests,redis-tests\n--\nmy_test\n--exact\nCOMMAND\ntest\n--doc\n--workspace\n--features\npostgres,redis\n--features\npostgres-tests,redis-tests\n--\nmy_test\n--exact\n"
    );
}

#[test]
fn failed_nextest_run_never_falls_back_to_cargo_test() {
    let fixture = Fixture::new();
    fixture.executable("cargo-nextest", "exit 0");
    fixture.executable(
        "cargo",
        "printf '%s\\n' 'COMMAND' \"$@\" >> \"$COMMAND_LOG\"\nexit 100",
    );
    let result = fixture.run(&["test", "--profile", "minimal"]);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("100"));
    assert!(!fixture.commands().contains("\ntest\n"));
    assert_eq!(fixture.commands().matches("COMMAND").count(), 1);
}

#[test]
fn broken_nextest_probe_fails_before_running_tests() {
    let fixture = Fixture::new();
    fixture.executable("cargo-nextest", "echo broken-install >&2\nexit 42");
    let result = fixture.run(&["test"]);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("broken-install"));
    assert!(fixture.commands().is_empty());
}

#[test]
fn release_build_only_adds_the_requested_build_mode() {
    let fixture = Fixture::new();
    let result = fixture.run(&["build", "--profile", "minimal", "--release"]);
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        fixture.commands(),
        "COMMAND\nbuild\n--package\nstatus-list-server\n--bin\nstatus-list-server\n--no-default-features\n--features\nmemory\n--release\n"
    );
}

#[test]
fn ci_uses_bash_for_the_full_local_pipeline() {
    let fixture = Fixture::new();
    fixture.executable("sh", "echo unexpected-posix-shell >&2\nexit 90");
    fixture.executable(
        "bash",
        // Exercise the actual Bash script's help path without bootstrapping tools.
        "test \"$1\" = local-ci.sh\ntest \"$2\" = --full\nPATH=/usr/bin:/bin exec /bin/bash \"$1\" --help",
    );
    let result = fixture.run(&["ci"]);
    assert!(result.status.success(), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("Usage: ./local-ci.sh"));
}

#[test]
fn issuer_export_reads_legacy_database_and_never_overwrites_registry() {
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};

    let fixture = Fixture::new();
    let database_url = format!(
        "sqlite://{}?mode=rwc",
        fixture.directory.join("legacy.db").display()
    );
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let db = Database::connect(&database_url).await.unwrap();
        db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite,
            "CREATE TABLE credentials (issuer TEXT PRIMARY KEY, public_key JSON NOT NULL, aggregation_id TEXT)"))
            .await.unwrap();
        db.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "INSERT INTO credentials VALUES (?, ?, ?)", vec![
                "existing-issuer".into(),
                serde_json::json!({"kty":"EC", "crv":"P-256", "kid":"old-kid", "alg":"ES256",
                    "x":"NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
                    "y":"eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"}).into(),
                "11111111-1111-4111-8111-111111111111".into(),
            ])).await.unwrap();
        db.close().await.unwrap();
    });
    let file = fixture.directory.join("issuers.yaml");
    let args = [
        "issuer",
        "export",
        "--database-url",
        &database_url,
        "--file",
        file.to_str().unwrap(),
    ];
    let result = fixture.run(&args);
    assert!(result.status.success(), "{result:?}");
    let exported = fs::read_to_string(&file).unwrap();
    let registry =
        status_list_server::server::auth::issuer_registry::IssuerRegistry::from_yaml(&exported)
            .unwrap();
    let issuer = registry.issuer("existing-issuer").unwrap();
    assert_eq!(
        issuer.aggregation_id.to_string(),
        "11111111-1111-4111-8111-111111111111"
    );
    assert_ne!(issuer.keys[0].kid, "old-kid");
    assert!(!fixture.run(&args).status.success());
    assert_eq!(fs::read_to_string(&file).unwrap(), exported);
}
