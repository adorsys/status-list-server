use std::{
    fs,
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
    fs::copy("helm/chart/values.yaml", chart_dir.join("values.yaml"))
        .expect("failed to copy chart values");
    copy_dir(
        Path::new("helm/chart/templates"),
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
        .args(["version", "--client"])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn helm_template(args: &[&str]) -> Option<Output> {
    if !helm_available() {
        eprintln!("skipping Helm render assertions because helm is not installed");
        return None;
    }

    let chart_dir = dependency_free_chart();
    Some(
        Command::new("helm")
            .arg("template")
            .arg("status-list-server")
            .arg(&chart_dir)
            .arg("-f")
            .arg(chart_dir.join("values.yaml"))
            .args(["--namespace", "statuslist"])
            .args([
                "--set",
                "postgres.enabled=false",
                "--set",
                "opentelemetry-collector.enabled=false",
            ])
            .args(args)
            .output()
            .expect("failed to execute helm template"),
    )
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

#[test]
fn rendered_chart_uses_split_database_credentials() {
    let Some(rendered) = render_helm(&["--set", "statuslist.env.APP_DATABASE__PORT=5432"]) else {
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
        "name: APP_DATABASE__NAME",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered Helm output is missing safer split credential field {expected}"
        );
    }
}

#[test]
fn rendered_chart_respects_database_backend_override() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.env.APP_DATABASE__BACKEND=mysql",
        "--set",
        "statuslist.env.APP_DATABASE__PORT=3306",
    ]) else {
        return;
    };

    assert!(
        rendered.contains("name: APP_DATABASE__BACKEND\n              value: \"mysql\""),
        "rendered Helm output must preserve operator-provided database backend"
    );
}

#[test]
fn rendered_chart_renders_database_query() {
    let Some(rendered) = render_helm(&[
        "--set",
        "statuslist.env.APP_DATABASE__PORT=5432",
        "--set",
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
        "--set",
        "statuslist.env.APP_DATABASE__PORT=5432",
        "--set",
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
        "--set",
        "statuslist.env.APP_DATABASE__PORT=5432",
        "--set",
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
    // With APP_DATABASE__PORT now defaulting to "5432" in values.yaml,
    // the chart should render successfully without explicit --set
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
        "--set",
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
        "statuslist.env.APP_SERVER__CERT__DNS__GCLOUD__AUTH_MODE=ambient",
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
        "name: APP_SERVER__CERT__DNS__GCLOUD__AUTH_MODE\n              value: \"ambient\"",
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
        "statuslist.env.APP_SERVER__CERT__DNS__AZURE__AUTH_MODE=ambient",
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
        "name: APP_SERVER__CERT__DNS__AZURE__AUTH_MODE\n              value: \"ambient\"",
        "name: APP_SERVER__CERT__DNS__AZURE__SUBSCRIPTION_ID\n              value: \"subscription-id\"",
        "name: APP_SERVER__CERT__DNS__AZURE__RESOURCE_GROUP\n              value: \"dns-resource-group\"",
    ] {
        assert!(
            rendered.contains(expected),
            "rendered Helm output is missing AKS Workload Identity field {expected}"
        );
    }
}
