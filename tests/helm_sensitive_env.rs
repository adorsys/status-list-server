use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("failed to create test chart directory");
    for entry in fs::read_dir(src).expect("failed to read chart directory") {
        let entry = entry.expect("failed to read chart entry");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir(&src_path, &dst_path);
        } else {
            fs::copy(&src_path, &dst_path).expect("failed to copy chart file");
        }
    }
}

fn dependency_free_chart() -> PathBuf {
    let chart_dir = PathBuf::from(format!(
        "target/helm-sensitive-env-chart-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));

    if chart_dir.exists() {
        fs::remove_dir_all(&chart_dir).expect("failed to remove stale test chart directory");
    }
    fs::create_dir_all(&chart_dir).expect("failed to create test chart directory");
    fs::copy(
        "deploy/helm/chart/values.yaml",
        chart_dir.join("values.yaml"),
    )
    .expect("failed to copy chart values");
    fs::copy(
        "deploy/helm/chart/values.schema.json",
        chart_dir.join("values.schema.json"),
    )
    .expect("failed to copy chart values schema");
    copy_dir(
        Path::new("deploy/helm/chart/templates"),
        &chart_dir.join("templates"),
    );
    fs::write(
        chart_dir.join("Chart.yaml"),
        r#"apiVersion: v2
name: status-list-server
description: Test chart copy without remote dependencies
type: application
version: 0.1.0
appVersion: "1.0.0"
"#,
    )
    .expect("failed to write dependency-free Chart.yaml");

    chart_dir
}

fn helm_available() -> bool {
    Command::new("helm")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn helm_template_with_postgres_default(args: &[&str], disable_postgres: bool) -> Option<Output> {
    if !helm_available() {
        if env::var_os("CI").is_some() {
            panic!("helm is required for helm_sensitive_env tests in CI");
        }
        eprintln!("skipping Helm render assertions because helm is not installed");
        return None;
    }

    let chart_dir = dependency_free_chart();
    let mut command = Command::new("helm");
    command
        .arg("template")
        .arg("status-list-server")
        .arg(&chart_dir)
        .arg("-f")
        .arg(chart_dir.join("values.yaml"))
        .args(["--namespace", "statuslist"])
        .args(["--set", "opentelemetry-collector.enabled=false"]);
    if disable_postgres {
        command.args(["--set", "postgres.enabled=false"]);
    }
    Some(
        command
            .args(args)
            .output()
            .expect("failed to execute helm template"),
    )
}

fn helm_template(args: &[&str]) -> Option<Output> {
    helm_template_with_postgres_default(args, true)
}

fn helm_template_chart_defaults(args: &[&str]) -> Option<Output> {
    helm_template_with_postgres_default(args, false)
}

fn render_helm(args: &[&str]) -> Option<String> {
    let output = helm_template(args)?;

    assert!(
        output.status.success(),
        "helm template failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Some(String::from_utf8(output.stdout).expect("helm template output should be valid UTF-8"))
}

fn render_helm_failure(args: &[&str]) -> Option<Output> {
    let output = helm_template(args)?;

    assert!(
        !output.status.success(),
        "helm template should have failed, stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    Some(output)
}

fn render_helm_chart_defaults_failure(args: &[&str]) -> Option<Output> {
    let output = helm_template_chart_defaults(args)?;

    assert!(
        !output.status.success(),
        "helm template should have failed, stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    Some(output)
}

#[test]
fn rendered_chart_uses_split_database_credentials() {
    let Some(rendered) = render_helm(&[]) else {
        return;
    };

    assert!(
        !rendered.contains("APP_DATABASE__URL"),
        "rendered Helm output must not contain a fully assembled database URL env var"
    );
    assert!(
        !rendered.contains("postgres://"),
        "rendered Helm output must not contain an assembled Postgres URL"
    );
    assert!(
        !rendered.contains("$(POSTGRES_PASSWORD)"),
        "rendered Helm output must not assemble credentials with env expansion"
    );

    for expected in [
        "name: APP_DATABASE__BACKEND",
        "value: \"postgres\"",
        "name: APP_DATABASE__HOST",
        "name: APP_DATABASE__PORT",
        "name: APP_DATABASE__USERNAME",
        "name: APP_DATABASE__PASSWORD_FILE",
        "value: \"/var/run/status-list-server/database/password\"",
        "name: database-credentials",
        "secretName: statuslist-secret",
        "key: postgres-password",
        "name: APP_DATABASE__NAME",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered Helm output is missing safer split credential field {expected}"
        );
    }
}

#[test]
fn rendered_chart_templates_mysql_backend_defaults() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.env.APP_DATABASE__BACKEND=mysql",
        "--set",
        "statuslist.env.APP_DATABASE__HOST=mysql.example.internal",
        "--set",
        "statuslist.networkPolicy.enabled=true",
        "--set",
        "statuslist.networkPolicy.databaseEgress[0].ipBlock.cidr=10.10.0.0/24",
        "--set",
        "statuslist.image.repository=example.com/status-list-server",
        "--set",
        "statuslist.image.tag=mysql",
    ]) else {
        return;
    };

    for expected in [
        "name: wait-for-db",
        "until nc -z mysql.example.internal 3306; do",
        "name: APP_DATABASE__BACKEND\n              value: \"mysql\"",
        "name: APP_DATABASE__HOST\n              value: \"mysql.example.internal\"",
        "name: APP_DATABASE__PORT\n              value: \"3306\"",
        "name: APP_DATABASE__USERNAME\n              value: \"mysql\"",
        "name: APP_DATABASE__NAME\n              value: \"status-list\"",
        "image: \"example.com/status-list-server:mysql\"",
        "key: postgres-password",
        "cidr: 10.10.0.0/24",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered Helm output is missing MySQL backend field {expected}"
        );
    }
}

#[test]
fn rendered_chart_preserves_secret_item_mode() {
    let Some(rendered) = render_helm(&[
        "--set-json",
        r#"statuslist.secretMounts=[{"name":"database-credentials","secretName":"statuslist-secret","mountPath":"/var/run/status-list-server/database","items":[{"key":"postgres-password","path":"password","mode":256}],"fileEnv":{"APP_DATABASE__PASSWORD_FILE":"password"}}]"#,
    ]) else {
        return;
    };

    for expected in ["key: postgres-password", "path: password", "mode: 256"] {
        assert!(
            rendered.contains(expected),
            "rendered Secret volume item should preserve configured field {expected}"
        );
    }
}

#[test]
fn rendered_chart_preserves_custom_secret_mount_key_for_mysql() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.env.APP_DATABASE__BACKEND=mysql",
        "--set",
        "statuslist.env.APP_DATABASE__HOST=mysql.example.internal",
        "--set",
        "statuslist.image.repository=example.com/status-list-server",
        "--set",
        "statuslist.image.tag=mysql",
        "--set-json",
        r#"statuslist.secretMounts=[{"name":"database-credentials","secretName":"customer-db-secret","mountPath":"/var/run/status-list-server/database","items":[{"key":"postgres-password","path":"password"}],"fileEnv":{"APP_DATABASE__PASSWORD_FILE":"password"}}]"#,
    ]) else {
        return;
    };

    assert!(
        rendered.contains("secretName: customer-db-secret")
            && rendered.contains("key: postgres-password")
            && rendered.contains("path: password"),
        "custom MySQL secret mounts must keep their configured Secret key"
    );
}

#[test]
fn rendered_chart_rejects_mysql_backend_when_postgres_subchart_is_still_enabled() {
    let Some(output) = render_helm_chart_defaults_failure(&[
        "--set",
        "statuslist.env.APP_DATABASE__BACKEND=mysql",
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr).contains("set postgres.enabled=false"),
        "helm template should name the required fix when MySQL backend is selected with PostgreSQL still enabled"
    );
}

#[test]
fn rendered_chart_rejects_mysql_enabled_as_a_subchart_switch() {
    let Some(output) = render_helm_failure(&[
        "--set",
        "mysql.enabled=true",
        "--set",
        "statuslist.env.APP_DATABASE__BACKEND=mysql",
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "mysql.enabled is not supported because this chart does not vendor a MySQL database"
        ),
        "helm template should reject mysql.enabled instead of implying this chart deploys MySQL"
    );
}

#[test]
fn rendered_chart_rejects_enabled_postgres_with_mysql_backend() {
    let Some(output) = render_helm_failure(&[
        "--set",
        "postgres.enabled=true",
        "--set",
        "statuslist.env.APP_DATABASE__BACKEND=mysql",
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "postgres.enabled=true requires statuslist.env.APP_DATABASE__BACKEND=postgres"
        ),
        "helm template should reject an enabled PostgreSQL backend with MySQL app config"
    );
}

#[test]
fn rendered_chart_preserves_default_secret_mount_key_for_externally_managed_mysql_secret() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.fallbackSecret.enabled=false",
        "--set",
        "externalSecret.enabled=false",
        "--set",
        "statuslist.env.APP_DATABASE__BACKEND=mysql",
        "--set",
        "statuslist.env.APP_DATABASE__HOST=mysql.example.internal",
        "--set",
        "statuslist.image.repository=example.com/status-list-server",
        "--set",
        "statuslist.image.tag=mysql",
    ]) else {
        return;
    };

    assert!(
        !rendered.contains("kind: Secret\nmetadata:\n  # Single supported fallback secret name"),
        "fallback Secret should not render in externally managed Secret mode"
    );
    assert!(
        rendered.contains("secretName: statuslist-secret")
            && rendered.contains("key: postgres-password")
            && rendered.contains("path: password")
            && !rendered.contains("key: database-password"),
        "MySQL must preserve the configured default mount key for externally managed Secrets"
    );
}

#[test]
fn rendered_chart_rejects_mysql_backend_without_explicit_image_tag_or_digest() {
    let Some(output) = render_helm_failure(&[
        "--set",
        "statuslist.env.APP_DATABASE__BACKEND=mysql",
        "--set",
        "statuslist.env.APP_DATABASE__HOST=mysql.example.internal",
        "--set",
        "statuslist.image.repository=example.com/status-list-server",
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("set statuslist.image.tag or statuslist.image.digest"),
        "helm template should reject MySQL backend without an explicit image tag or digest"
    );
}

#[test]
fn rendered_chart_accepts_mysql_enabled_false_overlay() {
    let Some(rendered) = render_helm(&[
        "--set",
        "mysql.enabled=false",
        "--set",
        "statuslist.image.tag=explicit-postgres-tag",
    ]) else {
        return;
    };

    assert!(
        rendered.contains("image: \"ghcr.io/adorsys/status-list-server:explicit-postgres-tag\""),
        "mysql.enabled=false should not be treated as enabling an unsupported MySQL subchart"
    );
}

#[test]
fn rendered_chart_accepts_fscert_redis_variant() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.image.variant=fscert-redis",
        "--set",
        "statuslist.secretEnv.APP_CACHE__REDIS_URL.name=redis-url",
        "--set",
        "statuslist.secretEnv.APP_CACHE__REDIS_URL.key=url",
    ]) else {
        return;
    };

    for expected in [
        "image: \"ghcr.io/adorsys/status-list-server:1.0.0-fscert-redis\"",
        "name: APP_CACHE__REDIS_URL",
        "name: \"redis-url\"",
        "key: \"url\"",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered Helm output is missing Redis variant field {expected}"
        );
    }
}

#[test]
fn rendered_chart_rejects_mysql_backend_without_explicit_host() {
    let Some(output) = render_helm_failure(&[
        "--set",
        "statuslist.env.APP_DATABASE__BACKEND=mysql",
        "--set",
        "statuslist.image.tag=mysql",
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr).contains("APP_DATABASE__HOST must be set"),
        "helm template should reject external MySQL without an explicit host"
    );
}

#[test]
fn rendered_chart_rejects_mysql_network_policy_without_database_egress() {
    let Some(output) = render_helm_failure(&[
        "--set",
        "statuslist.env.APP_DATABASE__BACKEND=mysql",
        "--set",
        "statuslist.env.APP_DATABASE__HOST=mysql.example.internal",
        "--set",
        "statuslist.image.tag=mysql",
        "--set",
        "statuslist.networkPolicy.enabled=true",
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("statuslist.networkPolicy.databaseEgress must be set"),
        "helm template should reject MySQL NetworkPolicy without an explicit database egress peer"
    );
}

#[test]
fn rendered_chart_allows_cache_egress_network_policy() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.networkPolicy.enabled=true",
        "--set",
        "statuslist.networkPolicy.cachePort=6380",
        "--set",
        "statuslist.networkPolicy.cacheEgress[0].ipBlock.cidr=10.20.0.0/24",
    ]) else {
        return;
    };

    for expected in ["port: 6380", "cidr: 10.20.0.0/24"] {
        assert!(
            rendered.contains(expected),
            "rendered Helm output is missing cache egress field {expected}"
        );
    }
}

#[test]
fn rendered_chart_rejects_redis_network_policy_without_cache_egress() {
    let Some(output) = render_helm_failure(&[
        "--set",
        "statuslist.image.variant=fscert-redis",
        "--set",
        "statuslist.networkPolicy.enabled=true",
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("statuslist.networkPolicy.cacheEgress must be set"),
        "helm template should reject Redis cache NetworkPolicy without an explicit cache egress peer"
    );
}

#[test]
fn rendered_chart_rejects_out_of_range_string_cache_port() {
    let Some(output) = render_helm_failure(&[
        "--set",
        "statuslist.networkPolicy.enabled=true",
        "--set-string",
        "statuslist.networkPolicy.cachePort=99999",
        "--set",
        "statuslist.networkPolicy.cacheEgress[0].ipBlock.cidr=10.20.0.0/24",
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr).contains("statuslist.networkPolicy.cachePort"),
        "helm schema should reject quoted cachePort values outside the Kubernetes port range"
    );
}

#[test]
fn rendered_chart_resolves_empty_database_env_values_to_helper_defaults() {
    let Some(rendered) = helm_template_chart_defaults(&[
        "--set-string",
        "statuslist.env.APP_DATABASE__BACKEND=",
        "--set-string",
        "statuslist.env.APP_DATABASE__HOST=",
    ]) else {
        return;
    };

    assert!(
        rendered.status.success(),
        "helm template failed: {}",
        String::from_utf8_lossy(&rendered.stderr)
    );
    let rendered =
        String::from_utf8(rendered.stdout).expect("helm template output should be valid UTF-8");

    for expected in [
        "until nc -z status-list-server-postgres.statuslist.svc.cluster.local 5432; do",
        "name: APP_DATABASE__BACKEND\n              value: \"postgres\"",
        "name: APP_DATABASE__HOST\n              value: \"status-list-server-postgres.statuslist.svc.cluster.local\"",
    ] {
        assert!(
            rendered.contains(expected),
            "empty database env value should resolve consistently to {expected}"
        );
    }
}

#[test]
fn rendered_chart_supports_database_password_mount_after_secret_migration() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.secretMounts[0].items[0].key=database-password",
    ]) else {
        return;
    };

    assert!(
        rendered.contains("key: database-password"),
        "operators must be able to switch the mounted password key after their Secret contains database-password"
    );
}

#[test]
fn rendered_chart_supports_database_password_secret_key_default() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.database.passwordSecretKey=database-password",
    ]) else {
        return;
    };

    assert!(
        rendered.contains("key: database-password"),
        "statuslist.database.passwordSecretKey should control the default database password mount"
    );
}

#[test]
fn rendered_chart_default_mount_is_safe_for_legacy_external_secret() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.fallbackSecret.enabled=false",
        "--set",
        "externalSecret.enabled=false",
    ]) else {
        return;
    };

    assert!(
        !rendered.contains("kind: Secret\nmetadata:\n  # Single supported fallback secret name"),
        "fallback Secret should not render in externally managed Secret mode"
    );
    assert!(
        rendered.contains("secretName: statuslist-secret")
            && rendered.contains("key: postgres-password")
            && rendered.contains("path: password"),
        "default mount must remain compatible with externally managed Secrets that only contain postgres-password"
    );
}

#[test]
fn rendered_chart_rejects_external_secret_missing_mounted_database_key() {
    let Some(output) = render_helm_failure(&[
        "--set",
        "externalSecret.enabled=true",
        "--set",
        "statuslist.fallbackSecret.enabled=false",
        "--set",
        "secretStore.enabled=true",
        "--set",
        "secretStore.provider=gcp",
        "--set",
        "secretStore.gcp.projectID=my-project-id",
        "--set-json",
        "externalSecret.spec.target.template=null",
        "--set-json",
        r#"externalSecret.spec.data=[{"secretKey":"database-password","remoteRef":{"key":"statuslist-database-password"}}]"#,
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must emit key \"postgres-password\""),
        "helm template should reject ESO mappings that do not emit the mounted password key"
    );
}

#[test]
fn rendered_chart_accepts_external_secret_empty_template_overlay_with_data_keys() {
    let Some(rendered) = render_helm(&[
        "--set",
        "externalSecret.enabled=true",
        "--set",
        "statuslist.fallbackSecret.enabled=false",
        "--set",
        "secretStore.enabled=true",
        "--set",
        "secretStore.provider=gcp",
        "--set",
        "secretStore.gcp.projectID=my-project-id",
        "--set-json",
        r#"externalSecret.spec.target={"name":"statuslist-secret","creationPolicy":"Owner","template":{}}"#,
        "--set-json",
        r#"externalSecret.spec.data=[{"secretKey":"postgres-password","remoteRef":{"key":"statuslist-database-password"}}]"#,
    ]) else {
        return;
    };

    assert!(
        rendered.contains("secretKey: postgres-password"),
        "an empty ESO target.template overlay should not hide spec.data keys during validation"
    );
}

#[test]
fn rendered_chart_skips_external_secret_key_check_for_template_from() {
    let Some(rendered) = render_helm(&[
        "--set",
        "externalSecret.enabled=true",
        "--set",
        "statuslist.fallbackSecret.enabled=false",
        "--set",
        "secretStore.enabled=true",
        "--set",
        "secretStore.provider=gcp",
        "--set",
        "secretStore.gcp.projectID=my-project-id",
        "--set-json",
        r#"externalSecret.spec.target={"name":"statuslist-secret","creationPolicy":"Owner","template":{"templateFrom":[{"configMap":{"name":"statuslist-secret-template","items":[{"key":"secret-template"}]}}]}}"#,
        "--set-json",
        r#"externalSecret.spec.data=[{"secretKey":"raw-password","remoteRef":{"key":"statuslist-database-password"}}]"#,
    ]) else {
        return;
    };

    assert!(
        rendered.contains("templateFrom:") && rendered.contains("secretKey: raw-password"),
        "templateFrom can emit the mounted key, so the chart should not reject it as missing"
    );
}

#[test]
fn rendered_chart_rejects_external_secret_replace_template_missing_mounted_key() {
    let Some(output) = render_helm_failure(&[
        "--set",
        "externalSecret.enabled=true",
        "--set",
        "statuslist.fallbackSecret.enabled=false",
        "--set",
        "secretStore.enabled=true",
        "--set",
        "secretStore.provider=gcp",
        "--set",
        "secretStore.gcp.projectID=my-project-id",
        "--set-string",
        "statuslist.secretMounts[0].items[0].key=other-password",
        "--set-string",
        "externalSecret.spec.target.template.data.unrelated=value",
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must emit key \"other-password\""),
        "ESO template mergePolicy=Replace should validate the final Secret keys, not fetched input keys"
    );
}

#[test]
fn rendered_chart_rejects_uppercase_database_backend() {
    let Some(output) =
        render_helm_failure(&["--set", "statuslist.env.APP_DATABASE__BACKEND=MYSQL"])
    else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("statuslist.env.APP_DATABASE__BACKEND must be either postgres or mysql"),
        "helm template should reject backend values that the application enum would reject"
    );
}

#[test]
fn rendered_chart_rejects_non_chart_database_backends() {
    for backend in ["sqlite", "memory"] {
        let arg = format!("statuslist.env.APP_DATABASE__BACKEND={backend}");
        let Some(output) = render_helm_failure(&["--set", &arg]) else {
            return;
        };

        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("statuslist.env.APP_DATABASE__BACKEND must be either postgres or mysql"),
            "helm template should reject {backend} because the chart only supports postgres/mysql wiring"
        );
    }
}

#[test]
fn rendered_chart_fallback_secret_publishes_database_and_legacy_password_keys() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.fallbackSecret.stringData.database-password=fixed-password",
    ]) else {
        return;
    };

    for expected in [
        "database-password: \"fixed-password\"",
        "postgres-password: \"fixed-password\"",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered fallback Secret is missing compatible password key {expected}"
        );
    }
}

#[test]
fn rendered_chart_fallback_secret_accepts_legacy_postgres_password_key() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.fallbackSecret.stringData.postgres-password=legacy-password",
    ]) else {
        return;
    };

    for expected in [
        "database-password: \"legacy-password\"",
        "postgres-password: \"legacy-password\"",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered fallback Secret did not preserve legacy password compatibility for {expected}"
        );
    }
}

#[test]
fn rendered_chart_renders_database_query() {
    let Some(rendered) = render_helm(&[
        "--set-string",
        "statuslist.env.APP_DATABASE__PORT=5432",
        "--set-string",
        "statuslist.env.APP_DATABASE__QUERY=sslmode=verify-full&sslrootcert=/var/run/postgres/ca.crt",
    ]) else {
        return;
    };

    assert!(
        rendered.contains(
            "name: APP_DATABASE__QUERY\n              value: \"sslmode=verify-full&sslrootcert=/var/run/postgres/ca.crt\""
        ),
        "rendered Helm output must preserve operator-provided database query"
    );
}

#[test]
fn rendered_chart_rejects_assembled_database_url_env() {
    let Some(output) = render_helm_failure(&[
        "--set-string",
        "statuslist.env.APP_DATABASE__PORT=5432",
        "--set-string",
        "statuslist.env.APP_DATABASE__URL=postgres://user:pass@db:5432/status-list",
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("statuslist.env.APP_DATABASE__URL is not supported"),
        "helm template should explain that assembled database URLs are not supported"
    );
}

#[test]
fn rendered_chart_rejects_plain_database_password_env() {
    let Some(output) = render_helm_failure(&[
        "--set-string",
        "statuslist.env.APP_DATABASE__PORT=5432",
        "--set-string",
        "statuslist.env.APP_DATABASE__PASSWORD=plain-secret",
    ]) else {
        return;
    };

    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("statuslist.env.APP_DATABASE__PASSWORD must not be set as a plain env value"),
        "helm template should explain that plain database passwords are not supported"
    );
}

#[test]
fn rendered_chart_uses_default_database_port() {
    // With APP_DATABASE__BACKEND defaulting to "postgres", the chart derives 5432
    // without requiring APP_DATABASE__PORT in values.yaml.
    let Some(rendered) = render_helm(&[]) else {
        return;
    };

    assert!(
        rendered.contains("name: APP_DATABASE__PORT\n              value: \"5432\""),
        "rendered Helm output must use default database port 5432 from values.yaml"
    );
}

#[test]
fn rendered_chart_does_not_duplicate_watcher_poll_interval() {
    let Some(rendered) = render_helm(&[
        "--set-string",
        "statuslist.env.APP_WATCHER__POLL_INTERVAL_SECS=45",
        "--set",
        "statuslist.watcher.pollIntervalSecs=60",
    ]) else {
        return;
    };

    assert_eq!(
        rendered
            .matches("name: APP_WATCHER__POLL_INTERVAL_SECS")
            .count(),
        1,
        "rendered Helm output must not duplicate watcher poll interval env vars"
    );
    assert!(
        rendered.contains("name: APP_WATCHER__POLL_INTERVAL_SECS\n              value: \"45\""),
        "explicit statuslist.env watcher poll interval should take precedence"
    );
}

#[test]
fn rendered_chart_supports_gke_workload_identity_dns_example() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.image.tag=1.2.0-gcp",
        "--set",
        "statuslist.env.APP_SERVER__CERT__DNS__PROVIDER=gcloud",
        "--set",
        "statuslist.env.APP_SERVER__CERT__DNS__GCLOUD__PROJECT_ID=dns-project-id",
        "--set",
        "serviceAccount.annotations.iam\\.gke\\.io/gcp-service-account=status-list-server@dns-project-id.iam.gserviceaccount.com",
    ]) else {
        return;
    };

    for expected in [
        "image: \"ghcr.io/adorsys/status-list-server:1.2.0-gcp\"",
        "iam.gke.io/gcp-service-account: status-list-server@dns-project-id.iam.gserviceaccount.com",
        "name: APP_SERVER__CERT__DNS__PROVIDER\n              value: \"gcloud\"",
        "name: APP_SERVER__CERT__DNS__GCLOUD__PROJECT_ID\n              value: \"dns-project-id\"",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered Helm output is missing GKE Workload Identity field {expected}"
        );
    }
}

#[test]
fn rendered_chart_supports_aks_workload_identity_dns_example() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.image.tag=1.2.0-azure",
        "--set-string",
        "statuslist.podLabels.azure\\.workload\\.identity/use=true",
        "--set",
        "statuslist.env.APP_SERVER__CERT__DNS__PROVIDER=azure",
        "--set",
        "statuslist.env.APP_SERVER__CERT__DNS__AZURE__SUBSCRIPTION_ID=subscription-id",
        "--set",
        "statuslist.env.APP_SERVER__CERT__DNS__AZURE__RESOURCE_GROUP=dns-resource-group",
        "--set",
        "serviceAccount.annotations.azure\\.workload\\.identity/client-id=00000000-0000-0000-0000-000000000000",
    ]) else {
        return;
    };

    for expected in [
        "image: \"ghcr.io/adorsys/status-list-server:1.2.0-azure\"",
        "azure.workload.identity/use: \"true\"",
        "azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000000",
        "name: APP_SERVER__CERT__DNS__PROVIDER\n              value: \"azure\"",
        "name: APP_SERVER__CERT__DNS__AZURE__SUBSCRIPTION_ID\n              value: \"subscription-id\"",
        "name: APP_SERVER__CERT__DNS__AZURE__RESOURCE_GROUP\n              value: \"dns-resource-group\"",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered Helm output is missing AKS Workload Identity field {expected}"
        );
    }
}
