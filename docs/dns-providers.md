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

### Credentials

```bash
APP_SERVER__CERT__DNS__PROVIDER=gcloud
APP_SERVER__CERT__DNS__GCLOUD__PROJECT_ID=<project holding managed zones>
```

Google Cloud DNS uses Application Default Credentials (ADC), matching the
ambient model used by Route53. On GKE, bind the Kubernetes ServiceAccount to a
Google service account with `roles/dns.admin` or a custom role containing
`dns.managedZones.list`, `dns.resourceRecordSets.*` and `dns.changes.*`. For
service-account key files or local testing, set standard ADC inputs such as
`GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json` or use
`gcloud auth application-default login`.

Helm example:

```yaml
statuslist:
  image:
    tag: "1.2.0-gcp"
  env:
    APP_SERVER__CERT__DNS__PROVIDER: "gcloud"
    APP_SERVER__CERT__DNS__GCLOUD__PROJECT_ID: "dns-project-id"
serviceAccount:
  create: true
  annotations:
    iam.gke.io/gcp-service-account: status-list-server@dns-project-id.iam.gserviceaccount.com
```

If ADC is unavailable, startup/token acquisition fails closed with a redacted
error that points operators to GKE Workload Identity or
`GOOGLE_APPLICATION_CREDENTIALS`.

## Azure DNS (`azure`)

### Credentials

```bash
APP_SERVER__CERT__DNS__PROVIDER=azure
APP_SERVER__CERT__DNS__AZURE__SUBSCRIPTION_ID=<subscription>
APP_SERVER__CERT__DNS__AZURE__RESOURCE_GROUP=<resource group>
```

Azure DNS uses `DefaultAzureCredential`, matching the ambient model used by
Route53. It discovers credentials from standard Azure environment variables
(`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), AKS Workload
Identity Federation (`AZURE_FEDERATED_TOKEN_FILE`), managed identity, or
developer-tool credentials. Grant the resolved identity the
`DNS Zone Contributor` role on the resource group holding the DNS zones.

Helm example for AKS Workload Identity Federation:

```yaml
statuslist:
  image:
    tag: "1.2.0-azure"
  podLabels:
    azure.workload.identity/use: "true"
  env:
    APP_SERVER__CERT__DNS__PROVIDER: "azure"
    APP_SERVER__CERT__DNS__AZURE__SUBSCRIPTION_ID: "subscription-id"
    APP_SERVER__CERT__DNS__AZURE__RESOURCE_GROUP: "dns-resource-group"
serviceAccount:
  create: true
  annotations:
    azure.workload.identity/client-id: "00000000-0000-0000-0000-000000000000"
```

If no ambient Azure credential can be initialized or acquire a token, the
provider fails closed with a redacted error that points to AKS Workload
Identity, managed identity, Azure environment credentials, or Azure CLI
authentication.

To use a service principal without putting secrets in application
configuration, create one and provide its credentials through the standard
`AZURE_*` environment variables:

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
# Default account, used for every domain without a per-domain entry:
APP_SERVER__CERT__DNS__ACMEDNS__USERNAME=<username from registration>
APP_SERVER__CERT__DNS__ACMEDNS__PASSWORD=<password from registration>
APP_SERVER__CERT__DNS__ACMEDNS__SUBDOMAIN=<subdomain from registration>
```

Setup:

1. Register an account: `curl -X POST https://auth.example.org/register`. The
   response contains the `username`, `password`, `subdomain` and `fulldomain`.
2. Create a CNAME record at your primary DNS provider from
   `_acme-challenge.<domain>` to the returned `fulldomain`.

### Per-domain accounts

ACME-DNS keeps only the two most recent TXT values per subdomain and has no
delete endpoint, so record cleanup after a challenge is a no-op. With a single
account, all identifiers of an order share that two-value window, which limits
a certificate to two identifiers (an apex + wildcard pair fits, since both TXT
values live at the same name). To lift the limit, register one account per
domain and map them — the same model lego and acme.sh use:

```bash
APP_SERVER__CERT__DNS__ACMEDNS__ACCOUNTS='{
  "a.example.com": {"username": "<u1>", "password": "<p1>", "subdomain": "<s1>"},
  "b.example.com": {"username": "<u2>", "password": "<p2>", "subdomain": "<s2>"}
}'
```

Each mapped domain needs its own registration (step 1) and its own
`_acme-challenge.<domain>` CNAME to that account's `fulldomain` (step 2).
Write keys as they appear in the certificate order — punycode (a-labels,
e.g. `xn--mnchen-3ya.example.com`) for internationalized names — and write
wildcard domains as their base domain (`example.com`, not `*.example.com`),
since an apex and its wildcard share one CNAME and therefore one account.
Keys are matched case-insensitively, ignoring any trailing dot; two entries
that reduce to the same domain but hold different credentials are rejected
at startup. Domains without an entry fall back to the default account; at
least one of the two must be configured. The server fails at startup when
a certificate domain is covered by neither, or when one account would have
to serve more than two identifiers of the certificate at once.

All accounts must be registered on the one ACME-DNS server named by
`SERVER_URL`; spreading accounts across multiple ACME-DNS servers is not
supported.

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

The ACME server queries the zone's authoritative name servers directly and
validates only once, so `create_txt_record` must wait internally until the
record is served, to the degree the provider's API allows confirming it: poll
a change-status API where one exists (see Route53 and Google Cloud DNS), or
wait out the provider's documented propagation window otherwise (see Azure).
Add a variant to `DnsProviderKind` and to `ResolvedDnsProvider` (carrying the
validated settings) in `src/config.rs`, a build arm in `src/state.rs`,
and wiremock tests next to the implementation.
