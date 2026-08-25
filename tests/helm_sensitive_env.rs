use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
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

fn render_helm(args: &[&str]) -> String {
    let chart_dir = dependency_free_chart();
    let output = Command::new("helm")
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
        .expect("failed to execute helm template");

    assert!(
        output.status.success(),
        "helm template failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("helm template output should be valid UTF-8")
}

#[test]
fn rendered_chart_uses_split_database_credentials() {
    let rendered = render_helm(&["--set", "statuslist.env.APP_DATABASE__PORT=5432"]);

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
    assert!(
        !rendered.contains("APP_REDIS__URI") && !rendered.contains("rediss://"),
        "rendered Helm output must not contain Redis credential URI metadata after Redis chart removal"
    );

    for expected in [
        "name: APP_DATABASE__BACKEND",
        "value: \"postgres\"",
        "name: APP_DATABASE__HOST",
        "name: APP_DATABASE__PORT",
        "name: APP_DATABASE__USERNAME",
        "name: APP_DATABASE__PASSWORD",
        "secretKeyRef:",
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
fn rendered_chart_respects_database_backend_override() {
    let rendered = render_helm(&[
        "--set",
        "statuslist.env.APP_DATABASE__BACKEND=mysql",
        "--set",
        "statuslist.env.APP_DATABASE__PORT=3306",
    ]);

    assert!(
        rendered.contains("name: APP_DATABASE__BACKEND\n              value: \"mysql\""),
        "rendered Helm output must preserve operator-provided database backend"
    );
}

#[test]
fn rendered_chart_rejects_assembled_database_url_env() {
    let chart_dir = dependency_free_chart();
    let output = Command::new("helm")
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
        .args([
            "--set",
            "statuslist.env.APP_DATABASE__URL=postgres://user:pass@db:5432/status-list",
        ])
        .output()
        .expect("failed to execute helm template");

    assert!(
        !output.status.success(),
        "helm template should reject APP_DATABASE__URL in statuslist.env"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("statuslist.env.APP_DATABASE__URL is not supported"),
        "helm template should explain that assembled database URLs are not supported"
    );
}

#[test]
fn rendered_chart_requires_database_port_env() {
    let chart_dir = dependency_free_chart();
    let output = Command::new("helm")
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
        .output()
        .expect("failed to execute helm template");

    assert!(
        !output.status.success(),
        "helm template should reject a missing APP_DATABASE__PORT"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("statuslist.env.APP_DATABASE__PORT is required"),
        "helm template should tell users to input APP_DATABASE__PORT"
    );
}
