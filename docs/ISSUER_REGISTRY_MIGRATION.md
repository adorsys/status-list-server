# Migrate existing issuers to the operator-managed registry

`POST /api/v1/credentials` has been removed, including in development. There
is no switch to restore it. Management authentication trusts only the registry
configured by `APP_MANAGEMENT_AUTH__ISSUERS_FILE`. Public list reads continue
to use the existing database.

Perform these steps in order. Keep the database and the existing public base
and aggregation URLs; do not recreate issuers or their lists.

1. **Export from the running database, review, and commit the draft to the
   deployment repository.** Build the migration tool from this release while
   the previous server is still running:

   ```bash
   cargo xtask issuer export --database-url "$DATABASE_URL" --file issuers.yaml
   ```

   PostgreSQL, MySQL and SQLite URLs are supported. The default output is
   `issuers.yaml` in the current directory; an existing file is never
   overwritten. In a source checkout with the checked-in empty `issuers.yaml`,
   choose a new path such as `--file issuers-export.yaml`, then install the
   reviewed draft as `issuers.yaml` in the deployment repository.
   Use a read-only database account. The command only reads the
   credentials table; it does not apply migrations or update credentials.
   Coordinate the export with issuer onboarding so no registrations are missed.

   Each entry preserves the exact issuer `id` and `aggregation_id`. The former
   owns existing lists; the latter appears in issued tokens' `aggregation_uri`.
   Never replace either with a newly generated UUID. The key's `kid` is its
   RFC 7638 SHA-256 thumbprint, even if the old database used another key ID.
   The export sets that value in both registry metadata and the public JWK.
   Missing algorithm metadata is inferred from supported key types and curves
   (RSA uses PS256). Review the chosen algorithms with each issuer. Unsupported
   algorithms, malformed or private keys, duplicate identities or keys, and
   invalid aggregation IDs fail validation rather than producing a partial
   draft. An empty credentials table produces an empty registry.

   If an issuer has no aggregation ID, export fails instead of inventing one.
   Resolve its ID using the running server's authenticated
   `GET /api/v1/credentials`, then export again. A database predating the
   aggregation-ID column must first be upgraded to the preceding release and
   have its IDs resolved. Compare the draft with the current issuer inventory,
   list ownership, and advertised aggregation URIs before committing it.
   Review tiers and disabled flags as needed; no admin principals are exported.

2. **Agree an audience with every issuer and configure it.** Set
   `APP_MANAGEMENT_AUTH__AUDIENCES` to the agreed comma-separated audiences in the deployment
   configuration. Issuers add `typ: statuslist-management+jwt` and the exported
   `kid` to their JWT headers, and `aud` to their claims, while retaining their
   existing `iss`. The previous server ignores these extra fields, so issuers
   can prepare tokens before the rollout. Keep token lifetimes within the
   configured maximum (five minutes by default).

3. **Upgrade the server and Helm chart together.** Deploy the reviewed registry
   using `statuslist.issuerRegistry` (an existing ConfigMap, or
   `configMap.create=true` with the reviewed content) and the agreed audiences.
   Preserve the database, public URLs, issuer IDs and aggregation IDs. Follow
   other upgrade notes in the changelog as well. Do not use the local demo
   fixture in production.

4. **Verify every issuer on the management listener.** With each issuer's
   updated Bearer token, call:

   ```bash
   curl --fail --header "Authorization: Bearer $ISSUER_TOKEN" \
     https://management.example.com/api/v1/credentials
   ```

   Check `issuer`, `aggregation_id`, and that `aggregation_uri` exactly matches
   the value recorded before upgrading. Verify an authenticated update to an
   existing list and confirm its publicly served token still embeds the same
   aggregation URI. Use the management listener (default port 8001) for writes
   and credentials metadata, and the public listener (default port 8000) for
   status lists and aggregations. `POST /api/v1/credentials` must be unavailable
   on all listeners.
