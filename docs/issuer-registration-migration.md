# Issuer registration migration

`POST /api/v1/credentials` has been removed from every server environment. The
database still holds existing issuer keys and aggregation IDs; keep the same
database through the upgrade so their lists remain owned by the same issuers.

## Migration order

1. Export a review draft from the running server's credential database:

   ```bash
   cargo xtask issuer export --database-url "$DATABASE_URL" --output issuers.yaml
   ```

   Review every issuer ID, public key thumbprint, and `aggregation_id`. Commit
   the reviewed `issuers.yaml` to the deployment repository. Existing
   `aggregation_id` values must remain unchanged because status-list tokens
   embed them in `aggregation_uri`.

2. Agree on an audience with each issuer and configure it in
   `management_auth.audiences` (production environment variable:
   `APP_MANAGEMENT_AUTH__AUDIENCES`). Configure each issuer to send management
   tokens with `typ: statuslist-management+jwt`, the exported `kid`, and the
   agreed `aud` value. The server validates these fields as part of management
   token authentication.

3. Upgrade the server and Helm chart together. Keep the existing credential
   database and its data during the rollout.

4. For each issuer, use its management token to call `GET /api/v1/credentials`
   on the management listener. Confirm the returned issuer and
   `aggregation_id` match the reviewed registry draft and that
   `aggregation_uri` is unchanged. Then have the issuer publish to its existing
   status list.

## Export format

The exporter writes the v1 issuer registry shape from
[`docs/schemas/issuers.v1.schema.json`](schemas/issuers.v1.schema.json). It
includes public signing keys only. Each `kid` is the RFC 7638 SHA-256 JWK
thumbprint. Missing legacy aggregation IDs are assigned once and stored in the
database during export, so repeated exports keep the same value.

## Local demo

The demo uses the checked-in public fixture at `demo/issuers.yaml`. Its private
signing keys remain in the demo helper and are synthetic examples. The
in-memory backend loads that fixture when
`APP_MANAGEMENT_AUTH__ISSUERS_FILE=demo/issuers.yaml` is set.
