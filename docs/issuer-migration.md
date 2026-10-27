# Issuer registry migration

`POST /api/v1/credentials` has been removed. Issuers must be trusted through the operator-managed registry before they can publish lists.

1. Set `DATABASE_URL` through your secret manager or secure shell input, then export the draft with either `cargo xtask issuer export --output ./issuers.yaml` from a source checkout or `status-list-server issuer-export --output /out/issuers.yaml` from the server image. For example, a one-off container can receive the already-set variable and write to a mounted directory:

   ```bash
   docker run --rm --env DATABASE_URL --volume "$PWD:/out" \
     ghcr.io/adorsys/status-list-server:TAG issuer-export --output /out/issuers.yaml
   ```

   Replace `TAG` with the server image tag used by your deployment. Export refuses to replace an existing file; pass `--force` only when replacement is intended. Review the issuer IDs, keys, and aggregation IDs, then store the private registry draft wherever you manage the source for the registry mount.
2. Agree one management-token audience with every issuer and configure it in `APP_MANAGEMENT_AUTH__AUDIENCES`. Give each issuer the exact `kid` for its key from the exported draft. Issuers should send `typ: statuslist-management+jwt`, that `kid`, and the agreed `aud` claim before the upgrade. The current server ignores these fields, so they can be added before cutover. Exported `kid` values are RFC 7638 SHA-256 JWK thumbprints.
3. Upgrade the server and Helm chart together, mounting the reviewed registry through `statuslist.issuerRegistry.volume`. The registry keeps each issuer ID and aggregation ID from the database.
4. Have each issuer call `GET /api/v1/credentials` on the management listener. Confirm that the returned `aggregation_uri` matches the value previously published in its tokens.

The exporter preserves aggregation IDs already stored in the database. For v1.2.0 databases, which have no aggregation ID column or mapping table, it assigns an ID in the draft; these issuers have no scoped aggregation URI to preserve. Invalid keys are reported together so they can be corrected in one pass. Keep the database in place: it continues to hold list ownership and published status lists.
