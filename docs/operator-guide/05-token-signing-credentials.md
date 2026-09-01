# 05 — Token Signing Credentials (JWT/CWT) vs Network TLS

This is the single most important distinction to get right when operating the Status
List Server. The server signs **Status List Tokens** with a **token signing key** and
presents an **issuer certificate**. This identity is entirely separate from the
certificate that terminates **HTTPS/TLS at your ingress** for external clients.

## 1. The three certificates at play

| #     | Cert / key                                 | Purpose                                                                                                 | Who provides it                                                             | Covers                                                     |
| ----- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------- |
| **A** | **Token signing key + issuer certificate** | Signs JWT/CWT Status List Tokens; verifiers check the `kid`/`x5c`/issuer against this identity          | The server (via `PROVISIONING_STRATEGY`, filesystem or cloud/Vault backend) | **The data payload** of every status list response         |
| **B** | **Server's own API TLS certificate**       | Serves the API over HTTPS **when the server terminates TLS itself** (ACME `provisioning_strategy=acme`) | ACME (Let's Encrypt) or `store`                                             | The API **transport** between client and the server pod    |
| **C** | **Ingress TLS certificate**                | Terminates TLS at the Kubernetes **ingress** (nginx/ALB/GLB) for external clients                       | cert-manager / ingress controller                                           | The **transport** between external clients and the ingress |

In the default chart topology production traffic reaches the Server through the **ingress
(C)**, and the Server pod typically listens on plain HTTP on port 8000. In that setup the
Server's own ACME cert (B) is not strictly required for external clients, because the
ingress terminates TLS — but the Server still needs its **token signing identity (A)**
regardless of ingress configuration.

> [!IMPORTANT]
> Rotating the **ingress TLS certificate (C)** has no effect on the validity of issued
> Status List Tokens. Rotating the **token signing key (A)** does — every token minted
> after the rotation is signed with the new key, so verifiers must be able to discover the
> new issuer key (see [06-secret-rotation.md](06-secret-rotation.md)).

## 2. What the token signing identity is

- A **private signing key** (ECDSA, EdDSA, or RSA supported; typically Ed25519 or ECDSA
  P-256) used to produce the JWS/COSE signature on each Status List Token.
- An **issuer certificate** exposing the public key and issuer identity that verifiers
  use to validate tokens.

Formats: tokens are issued in **JWT** (JWS Compact) or **CWT** (COSE_Sign1) depending on
the request's `Accept`/format. Both are signed with the same configured signing key.

## 3. Provisions: how the token signing identity is delivered

Two strategies (set with `APP_SERVER__CERT__PROVISIONING_STRATEGY`):

### 3.1 `acme` (automatic, cloud/vault-backend)

The server requests and renews its own signing identity **through ACME**. The
private key and certificate chain are stored in and read from the **cryptographic-material
backend** matching your image variant:

- `-aws` → AWS Secrets Manager
- `-gcp` → GCP Secret Manager
- `-azure` → Azure Key Vault
- `-vault` → Vault/OpenBao KV v2
- ACME DNS-01 is performed through the configured DNS provider (`route53`, `gcloud`,
  `azure`, `cloudflare`, `acmedns`).

Renewal runs on `APP_SERVER__CERT__RENEWAL_CRON_SCHEDULE` (default daily). See
[06-secret-rotation.md](06-secret-rotation.md).

### 3.2 `store` (external, filesystem or backend keys)

The server loads **externally managed** signing key and certificate material from either:

- **Filesystem paths** — `APP_SERVER__CERT__STORE__CERTIFICATE_PATH` and
  `APP_SERVER__CERT__STORE__SIGNING_KEY_PATH`. This is the `-fscert` path: you (or a
  provisioning tool) place `PEM`/`DER` files at those paths in the pod.
- **Storage keys** — `APP_SERVER__CERT__STORE__CERTIFICATE_KEY` and
  `APP_SERVER__CERT__STORE__SIGNING_KEY_KEY`, read from the selected backend (the key
  names within Secrets Manager / Secret Manager / Key Vault / Vault).

Configure **either** filesystem paths **or** storage keys, never both. Values may be PEM
or raw DER; private keys must be PKCS#8 PEM or DER.

## 4. Where each piece of material goes in the chart

| Material                                  | Helm / env                                                                                               |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Token signing key/cert (ACME path)        | `statuslist.env.APP_SERVER__CERT__*` + image variant's backend + credentials                             |
| Token signing key/cert (store path)       | `statuslist.env.APP_SERVER__CERT__PROVISIONING_STRATEGY=store` + filesystem volume, or `...STORE__*_KEY` |
| Ingress TLS cert (C)                      | `statuslist.ingress.tls` (cert-manager `/ cert-manager.io/cluster-issuer`)                               |
| Database password (unrelated to identity) | `statuslist-secret` → `postgres-password`                                                                |

## 5. Security guidance

- **The token signing key is the crown jewel.** Anyone holding it can sign valid-looking
  Status List Tokens for arbitrary list IDs. Scope its backend access to least privilege:
  only the exact secret/key names it needs.
- **Store it encrypted at rest** in your backend, or as a mounted Secret with RBAC
  restricted to the `statuslist` ServiceAccount.
- **Never** set the signing key material as a plain `statuslist.env` value (it would land
  in pod metadata). Deliver via a Secret, the backend, or a mounted volume.
- Backend access controls and least-privilege policies per provider are documented in
  [docs/secrets-backends.md](../secrets-backends.md).
- The ingress TLS cert (C) can be managed with your normal cert-manager flow and is
  **not** the signing identity — do not conflate their rotation.

## 6. Related

- [04-configuration-reference.md](04-configuration-reference.md) — all `APP_SERVER__CERT__*` variables.
- [06-secret-rotation.md](06-secret-rotation.md) — rotating the signing identity safely.
- [02-choosing-your-image.md](02-choosing-your-image.md) — which image supplies the backend.
- [docs/secrets-backends.md](../secrets-backends.md) — provider IAM/Vault policies.
