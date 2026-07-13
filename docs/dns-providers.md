# DNS Providers for ACME DNS-01 Challenges

The certificate manager solves ACME DNS-01 challenges by creating a TXT record
named `_acme-challenge.<domain>` at the configured DNS provider. The provider is
selected with:

```bash
APP_SERVER__CERT__DNS__PROVIDER=route53 # route53 | cloudflare | gcloud | azure | acmedns | pebble
```

When unset, the historical behavior is preserved: `route53` is used when
`APP_ENV=production` and `pebble` otherwise. The server fails fast at startup
if the selected provider's settings are missing.

## AWS Route53 (`route53`)

Uses the ambient AWS credentials (environment variables, instance profile, or
IRSA). No provider-specific settings are needed.

Required IAM permissions:

- `route53:ListHostedZones`
- `route53:ChangeResourceRecordSets` on the matching hosted zone
- `route53:GetChange`

## Cloudflare (`cloudflare`)

```bash
APP_SERVER__CERT__DNS__PROVIDER=cloudflare
APP_SERVER__CERT__DNS__CLOUDFLARE__API_TOKEN=<token>
```

Create the token in the Cloudflare dashboard under
My Profile > API Tokens > Create Token, with permissions:

- `Zone / Zone / Read`
- `Zone / DNS / Edit`

scoped to the zones holding your domains.

## Google Cloud DNS (`gcloud`)

```bash
APP_SERVER__CERT__DNS__PROVIDER=gcloud
# Either the key JSON inline:
APP_SERVER__CERT__DNS__GCLOUD__SERVICE_ACCOUNT_KEY=<json>
# Or a path to the key file (e.g. a mounted Kubernetes secret):
APP_SERVER__CERT__DNS__GCLOUD__SERVICE_ACCOUNT_KEY_PATH=/etc/gcloud/key.json
```

Create a service account with the `roles/dns.admin` role (or a custom role with
`dns.managedZones.list`, `dns.resourceRecordSets.*` and `dns.changes.*`) in the
project holding the managed zones, then create a JSON key for it. The project
ID is read from the key file.

## Azure DNS (`azure`)

```bash
APP_SERVER__CERT__DNS__PROVIDER=azure
APP_SERVER__CERT__DNS__AZURE__TENANT_ID=<tenant>
APP_SERVER__CERT__DNS__AZURE__CLIENT_ID=<app id>
APP_SERVER__CERT__DNS__AZURE__CLIENT_SECRET=<secret>
APP_SERVER__CERT__DNS__AZURE__SUBSCRIPTION_ID=<subscription>
APP_SERVER__CERT__DNS__AZURE__RESOURCE_GROUP=<resource group>
```

Create a service principal and grant it the `DNS Zone Contributor` role on the
resource group holding the DNS zones:

```bash
az ad sp create-for-rbac --name status-list-acme \
  --role "DNS Zone Contributor" \
  --scopes /subscriptions/<subscription>/resourceGroups/<resource group>
```

## ACME-DNS (`acmedns`)

[ACME-DNS](https://github.com/joohoi/acme-dns) is a minimal self-hosted DNS
server made for DNS-01 challenges. It works with any primary DNS provider and
needs no credentials for it.

```bash
APP_SERVER__CERT__DNS__PROVIDER=acmedns
APP_SERVER__CERT__DNS__ACMEDNS__SERVER_URL=https://auth.example.org
APP_SERVER__CERT__DNS__ACMEDNS__USERNAME=<username from registration>
APP_SERVER__CERT__DNS__ACMEDNS__PASSWORD=<password from registration>
APP_SERVER__CERT__DNS__ACMEDNS__SUBDOMAIN=<subdomain from registration>
```

Setup:

1. Register an account: `curl -X POST https://auth.example.org/register`. The
   response contains the `username`, `password`, `subdomain` and `fulldomain`.
2. Create a CNAME record at your primary DNS provider from
   `_acme-challenge.<domain>` to the returned `fulldomain`.

Note: ACME-DNS keeps only the two most recent TXT values and has no delete
endpoint, so record cleanup after a challenge is a no-op.

## Pebble (`pebble`)

Development only. Points record updates at a
[pebble-challtestsrv](https://github.com/letsencrypt/pebble) management API,
`http://challtestsrv:8055` by default:

```bash
APP_SERVER__CERT__DNS__PROVIDER=pebble
APP_SERVER__CERT__DNS_CHALLENGE_SERVER_URL=http://challtestsrv:8055
```

## Adding a new provider

Implement the `DnsProvider` trait in
`src/utils/cert_manager/challenge/dns01/`:

```rust
#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError>;
    async fn delete_txt_record(&self, domain: &str, value: &str) -> Result<(), ChallengeError>;
}
```

`create_txt_record` must not return before the record is served by the
provider's authoritative name servers, since the ACME server queries them
directly. Add a variant to `DnsProviderKind` in `src/config.rs`, a build arm in
`src/utils/state.rs`, and wiremock tests next to the implementation.
