use std::process::Command;

fn render_helm(args: &[&str]) -> String {
    let output = Command::new("helm")
        .args(["template", "status-list-server", "helm/chart"])
        .args(["-f", "helm/chart/values.yaml"])
        .args(["--namespace", "statuslist"])
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
    let rendered = render_helm(&[]);

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
    let rendered = render_helm(&["--set", "statuslist.env.APP_DATABASE__BACKEND=mysql"]);

    assert!(
        rendered.contains("name: APP_DATABASE__BACKEND\n              value: \"mysql\""),
        "rendered Helm output must preserve operator-provided database backend"
    );
}

#[test]
fn rendered_chart_rejects_assembled_database_url_env() {
    let output = Command::new("helm")
        .args(["template", "status-list-server", "helm/chart"])
        .args(["-f", "helm/chart/values.yaml"])
        .args(["--namespace", "statuslist"])
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
