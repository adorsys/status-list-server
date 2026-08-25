#[test]
fn deployment_template_uses_split_database_credentials() {
    let deployment = include_str!("../helm/chart/templates/deployment.yaml");
    let helpers = include_str!("../helm/chart/templates/_helpers.tpl");

    assert!(
        !deployment.contains("APP_DATABASE__URL"),
        "Helm deployment must not render a fully assembled database URL in pod metadata"
    );
    assert!(
        !deployment.contains("APP_REDIS__URI"),
        "Helm deployment must not render Redis URI metadata after Redis chart removal"
    );
    assert!(
        !deployment.contains("$(POSTGRES_PASSWORD)") && !deployment.contains("$(REDIS_PASSWORD)"),
        "Helm deployment must not assemble credential URLs with secret env expansion"
    );
    assert!(
        !helpers.contains("$(REDIS_PASSWORD)"),
        "Helm helpers must not assemble Redis URIs with secret env expansion"
    );

    for expected in [
        "APP_DATABASE__HOST",
        "APP_DATABASE__PORT",
        "APP_DATABASE__USERNAME",
        "APP_DATABASE__PASSWORD",
        "APP_DATABASE__NAME",
        "secretKeyRef:",
        "postgres-password",
    ] {
        assert!(
            deployment.contains(expected),
            "Helm deployment is missing safer split credential field {expected}"
        );
    }
}
