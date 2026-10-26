# Issuer registry migration

`POST /api/v1/credentials` has been removed. Issuers must be trusted through the operator-managed registry before they can publish lists.

1. Export the registry draft from the running database: `cargo xtask issuer export --database-url <database-url>`. The command writes `issuers.yaml` in the current directory. Review every issuer, key, and aggregation ID, then commit the file to the deployment repository.
2. Agree one management-token audience with every issuer and configure it in `APP_MANAGEMENT_AUTH__AUDIENCES`. Issuers must send `typ: statuslist-management+jwt`, the registered `kid`, and the agreed `aud` claim. The `kid` in the exported draft is the RFC 7638 SHA-256 JWK thumbprint.
3. Upgrade the server and Helm chart together, mounting the reviewed registry through `statuslist.issuerRegistry.volume`. The registry keeps each issuer ID and aggregation ID from the database.
4. Have each issuer call `GET /api/v1/credentials` on the management listener. Confirm that the returned `aggregation_uri` matches the value previously published in its tokens.

The export fails if a stored issuer has no aggregation ID or a key cannot be represented. Resolve those records before retrying. Keep the database in place: it continues to hold list ownership and published status lists.
