//! Structural checks on `docs/openapi.yaml` that the linter cannot express.

use serde_json::Value;

const METHODS: [&str; 8] = [
    "get", "put", "post", "patch", "delete", "head", "options", "trace",
];
const ADMIN_SERVER: &str = "http://{admin_host}";

fn contract() -> Value {
    serde_saphyr::from_str(include_str!("../docs/openapi.yaml")).unwrap()
}

fn server_urls(servers: &Value) -> Vec<&str> {
    servers
        .as_array()
        .unwrap()
        .iter()
        .map(|server| server["url"].as_str().unwrap())
        .collect()
}

fn uses_admin_bearer(security: &Value) -> bool {
    security
        .as_array()
        .unwrap()
        .iter()
        .any(|requirement| requirement.get("AdminBearer").is_some())
}

/// Admin operations are documented one by one in a file whose defaults are the
/// public listener and `BearerAuth`. An admin operation that forgets to opt in
/// would document an admin token on the public listener, so check every one.
#[test]
fn admin_operations_use_admin_bearer_and_the_admin_listener() {
    let openapi = contract();
    let root_security = &openapi["security"];
    let root_servers = &openapi["servers"];
    assert!(!uses_admin_bearer(root_security));
    assert!(!server_urls(root_servers).contains(&ADMIN_SERVER));

    // OpenAPI 3.1 cannot `$ref` a server, so every admin operation repeats the
    // block. Compare whole objects so a copy with a wrong default also fails.
    let admin_servers = &openapi["paths"]["/health/ready"]["get"]["servers"];
    assert_eq!(server_urls(admin_servers), [ADMIN_SERVER]);

    let mut admin_operations = 0;
    for (path, item) in openapi["paths"].as_object().unwrap() {
        for method in METHODS {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let id = operation["operationId"].as_str().unwrap_or(path);
            let security = operation.get("security").unwrap_or(root_security);
            let servers = operation
                .get("servers")
                .or_else(|| item.get("servers"))
                .unwrap_or(root_servers);

            if path.starts_with("/admin/") {
                admin_operations += 1;
                assert_eq!(
                    security,
                    &serde_json::json!([{ "AdminBearer": [] }]),
                    "{id} must require AdminBearer"
                );
                assert_eq!(
                    servers, admin_servers,
                    "{id} must be served on the admin listener"
                );
            } else {
                assert!(
                    !uses_admin_bearer(security),
                    "{id} is not an admin operation but uses AdminBearer"
                );
            }
        }
    }
    assert!(admin_operations > 0, "no /admin/ operations found");
}
