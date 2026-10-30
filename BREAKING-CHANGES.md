# Breaking Changes

This document lists the breaking changes in each release, with notes on how to migrate. It is compiled from the [changelog](CHANGELOG.md): every entry marked **breaking** there has a section here.

## Summary

- [v2.0.0](#v200)
  - [Status list aggregation is scoped to one issuer](#status-list-aggregation-is-scoped-to-one-issuer-595)
  - [`limits.max_lists_per_issuer` may not exceed 1000](#limitsmax_lists_per_issuer-may-not-exceed-1000-595)
  - [`server.aggregation_uri` is validated at startup](#serveraggregation_uri-is-validated-at-startup-595)
  - [Signing material must be PEM](#signing-material-must-be-pem-559)

## v2.0.0

Upgrading from v1.2.0 adds database migrations. Read
[Upgrading to issuer-scoped aggregation](docs/deployment-runbook.md#upgrading-to-issuer-scoped-aggregation) before deploying, and [Rolling back](docs/deployment-runbook.md#rolling-back) before rolling back: the previous release refuses to start while the database records migrations it does not know.

### Status list aggregation is scoped to one issuer ([#595])

[#595]: https://github.com/adorsys/status-list-server/pull/595

Status list tokens used to carry the server-wide aggregation URI in
`aggregation_uri`. Each issuer now gets an opaque aggregation ID when its
credential is registered, and tokens carry that issuer's URI:

```diff
- "aggregation_uri": "https://statuslist.example.com/api/v1/aggregation"
+ "aggregation_uri": "https://statuslist.example.com/api/v1/aggregation/<aggregation_id>"
```

`GET /api/v1/aggregation/{aggregation_id}` lists only that issuer's status
lists:

- An unknown aggregation ID returns `404`.
- A request with neither `limit` nor `cursor` whose result does not fit in one page returns `409 paging_required`. Send `limit` to page through it.
- Cursors are bound to the aggregation they were issued for. A cursor replayed on another aggregation is refused.

`GET /api/v1/aggregation` still lists every issuer's lists, so tokens issued before the upgrade keep working. It is deprecated.

The `POST /api/v1/credentials` response gains `aggregation_id` and
`aggregation_uri`. Issuers registered before the upgrade get an ID the first time one of their tokens is served, and can read it from
`GET /api/v1/credentials`.

**Never drop `credentials.aggregation_id`** once tokens with scoped URIs have been served: new IDs would be assigned and every URI already in tokens would return `404`. The server refuses the down migration for this reason.

### `limits.max_lists_per_issuer` may not exceed 1000 ([#595])

`limits.max_lists_per_issuer` (`APP_LIMITS__MAX_LISTS_PER_ISSUER`) defaults to 1000 and may not exceed it, so every issuer's aggregation fits in one response for relying parties that do not page. Pods refuse to start above it.

An issuer that already holds more lists keeps them, but:

- while the quota is enforced, every further publish is refused with `400 list_quota_exceeded` until it is back under the cap;
- on a shared server, tokens of **every** issuer carry no `aggregation_uri` until it is back under the cap and the pods restart.

Find such issuers before upgrading:

```sql
SELECT issuer, COUNT(*) AS lists FROM status_lists
GROUP BY issuer HAVING COUNT(*) >= 900 ORDER BY lists DESC;
```

### `server.aggregation_uri` is validated at startup ([#595])

`server.aggregation_uri` (`APP_SERVER__AGGREGATION_URI`) is checked when the configuration loads, before any migration runs. Pods refuse to start unless it:

- is an `https` URL (`http` is accepted outside production);
- has no credentials, query or fragment;
- has the path `/aggregation` under `server.public_base_url`'s path (`/api/v1/aggregation` by default).

Leaving it unset is still valid: tokens then carry no `aggregation_uri`.

### Signing material must be PEM ([#559])

[#559]: https://github.com/adorsys/status-list-server/pull/559

The token-signing certificate and private key must be PEM text wherever they are provisioned: mounted files, inline configuration and secret stores such as Vault. Raw DER files and base64 or base64url-encoded DER values in a secret store are rejected.

Convert DER material before upgrading:

```bash
openssl x509 -inform DER -in certificate.der -out certificate.pem
openssl pkey -inform DER -in signing-key.der -out signing-key.pem
```

For a secret store holding base64 DER, decode the value to a DER file, convert it as above, and store the PEM text. The stored value must be PEM itself, not base64-encoded PEM.

Private keys are no longer limited to PKCS#8: SEC1 EC and PKCS#1 RSA PEM keys are accepted too, and the server signs with ES256, ES384, EdDSA or RS256 depending on the key.
