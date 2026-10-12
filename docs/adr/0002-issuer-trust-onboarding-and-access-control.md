# 2. Issuer trust, onboarding, and access control

- **Status:** Accepted
- **Date:** 2026-10-12
- **Issue:** [#372](https://github.com/adorsys/status-list-server/issues/372)

## Context

The server lets issuers publish and update status lists, and serves those lists to relying parties. Until this decision, anyone who could reach the server could make themselves an issuer. Registration was an unauthenticated operation that bound a caller-chosen identifier to a caller-chosen public key, first come first served. Public reads and issuer writes shared one network surface, so what was exposed depended entirely on reverse-proxy routing rules.

That left these gaps:

- **Impersonation.** Any caller could claim an unused identifier, and with it every status list later published under that identifier.
- **No key lifecycle.** An issuer had exactly one key. It could be neither rotated nor revoked without editing storage by hand.
- **Weak token checks.** The signature algorithm was taken from the token itself. Symmetric keys and keys containing private material were accepted as public keys. Different failures were distinguishable, which revealed which identifiers exist.
- **No accountability.** Nothing recorded who trusted which key, or when.
- **No operator view.** Registered issuers could not be listed or inspected without direct access to storage.
- **No tenant isolation.** Limits applied per network address, so on a shared server one issuer could exhaust capacity for all.

The same software must serve two situations:

- An organisation runs the server privately. Only the read endpoints defined by the Token Status List specification face the internet.
- An operator runs a shared server where external issuers sign themselves up to test their integration, under usage limits.

One part of the existing design is sound and is kept. Issuers authenticate every write with a short-lived JWT signed by a private key that only they hold. Every write checks that the issuer owns the status list it targets.

## Decision

### Deployment profiles

The server has two deployment profiles:

- **Private** (the default): only issuers an operator has listed are trusted.
- **Hosted**: also trusts issuers registered through self-service onboarding. These are kept in durable storage, held to stricter limits, and expire.

A profile adds trust sources and limits. It never relaxes an invariant.

### Separated network surfaces

The server exposes three listeners, and no route is shared between them:

| Listener | Serves | Reachability |
|---|---|---|
| Public | Anonymous reads defined by the Token Status List specification, and liveness | Internet |
| Management | Operations authenticated as an issuer | Private network. In the hosted profile it is also published, on its own hostname |
| Admin | Issuer listing and lifecycle, readiness, metrics | Private network only, in every profile |

Exposure is therefore decided by which listener is reachable, which network policy can enforce. It no longer depends on path rules in a proxy, which are easy to get wrong.

### Sources of trust

- **Static registry.** A declarative document lists the trusted issuers and admin principals, with their public keys. Operators manage it under version control. Changes apply without a restart.
- **Dynamic store** (hosted only). Issuers registered through onboarding. They are created and changed only through the admin surface.

Both sources sit behind one key-resolution abstraction. Authentication and request handling do not depend on where a key came from, so a further source can be added later (a remote key set, an external trust list, an OAuth authorization server) without changing either.

### Credentials

Issuers and admin principals authenticate with short-lived JWTs, signed with private keys that only they hold. The server stores only public keys. Each token declares what kind of token it is, names its key, and is bound to an audience. Each key is pinned to one algorithm from a small asymmetric allowlist, may carry a validity window, and can be revoked. An issuer can hold several keys, so a key can be rotated with an overlap and no downtime.

### Identifiers

The server assigns identifiers to onboarding-registered issuers; operators assign them to static issuers. An issuer has two identifiers:

- its **issuer identifier**, used for authentication and list ownership;
- its **aggregation identifier**, which is public and appears in published status list tokens.

Both are immutable, because published tokens outlive any key or storage change.

### Admin surface

Operators and the onboarding service list and query all issuers, and create and manage onboarding-registered issuers, through an authenticated admin API. Statically trusted issuers appear in it but are read-only there. Every change uses optimistic concurrency and is recorded in an audit trail.

### Limits

Every issuer belongs to a tier, and limits are enforced per authenticated issuer according to that tier. Network-level limits at the edge and before authentication complement them. The tier used for onboarding-registered issuers is never more permissive than the operator tier, and their credentials expire.

### Self-registration

Unauthenticated self-registration is removed. It survives only as an explicit development switch that is unavailable in production. Migrating existing issuers to the registry preserves both of their identifiers. Because this changes the external contract, it ships in a major version.

## Invariants

These statements must hold for every implementation and survive any refactoring. Each should be enforced by an automated test. Changing one requires a new ADR that supersedes this one.

- **I1.** No anonymous operation creates, changes or discloses issuer trust state. Only public reads are anonymous.
- **I2.** A route is served only on the listener of its class. On every other listener, it does not exist.
- **I3.** The admin listener is never reachable from outside the operator's private network, in any profile.
- **I4.** The server never holds a private key or a shared secret that authenticates an issuer or admin principal. It stores public keys only.
- **I5.** The key that verifies a token is chosen only by the key identifier the token names, resolved against the trust sources. A key carried in or referenced by the token is never used.
- **I6.** Each key accepts exactly one pinned asymmetric algorithm, and a token's declared algorithm must equal it. Symmetric keys and keys containing private material are rejected wherever keys enter the system.
- **I7.** Every token declares its kind. A token of one kind is never accepted where another kind is expected.
- **I8.** Tokens are audience-bound and short-lived, with a configured maximum lifetime. In production, audience validation cannot be disabled.
- **I9.** Every rejection of a presented token looks identical to the caller. The reason is logged server-side, and logs never contain tokens or key material.
- **I10.** No party chooses its own identifier. Issuer identifiers and aggregation identifiers are immutable, never reused, and survive key rotation, a change of trust source and storage migration.
- **I11.** The issuer identifier and the aggregation identifier are different values. Publishing one never reveals the other.
- **I12.** Revoking a key, suspending or disabling an issuer, or reaching an expiry takes effect on the next request once the change is visible to the server. No cached authorization outlives it.
- **I13.** An invalid registry document is never applied, in whole or in part. At startup, the server refuses to start. While running, the last valid version stays in force.
- **I14.** A statically trusted issuer changes only through the registry document. The admin surface can report it but never modify it.
- **I15.** Every change to trust state is attributable. Registry changes are attributable through version-control history; admin changes through an audit record written atomically with the change.
- **I16.** Limits apply per authenticated issuer, according to its tier. The onboarding tier never exceeds the operator tier on any limit, and onboarding-registered credentials always expire.
- **I17.** A server that trusts onboarding-registered issuers signs status lists with an identity distinct from that of any production deployment.
- **I18.** Self-registration is never available in a production environment.
- **I19.** The server serves no human-facing interface. Onboarding interfaces are separate deployments that use only the admin surface.
- **I20.** List ownership is checked on every write, independently of authentication.

## Contract

The concrete values live in the issuer trust contract: `docs/issuer-trust-contract.md`, `docs/openapi-admin.yaml` and the registry schema in `docs/schemas/`. These cover token type names, header and claim rules, routes, configuration keys and defaults, tier values, error codes and the registry format. They may evolve without amending this ADR, as long as every invariant above still holds.

## Considered options

The authentication credential was the central choice.

| | Static API keys | **Signed JWT + registered public keys (chosen)** | Mutual TLS | OAuth 2.0 client credentials |
|---|---|---|---|---|
| Secrets held by the server | Yes, so a secret store is needed | **None** | None (CA certificates) | None, but trust is delegated to an external authority |
| Effect of a leak | The bearer value is replayable until rotated | One token, short-lived and audience-bound; the private key never leaves the issuer | Impersonation until the certificate is revoked | A token until expiry; the client secret allows full takeover |
| Proof of possession | No | Yes | Yes | No |
| Additional infrastructure | None | **None** | A certificate authority and certificate lifecycle | An identity provider |
| Same mechanism for test and production issuers | Only if API keys are used in production too | **Yes** | Yes | Yes |

API keys are the simplest option on paper. But they add a server-side secret store, give up proof of possession, and would make test credentials differ from production ones. Mutual TLS remains possible as defence in depth in front of the server, without changing this decision. OAuth 2.0 remains possible later as an additional trust source behind the key-resolution abstraction.

Keeping a single listener and controlling exposure with path-based proxy rules was rejected. It makes the security boundary depend on configuration outside the server.

## Security implications

| Threat | Mitigation |
|---|---|
| Anonymous use of a shared server | I1, I2 |
| Identifier squatting or issuer impersonation | I10, I14 |
| Stolen token | I7, I8 |
| Stolen private key | I4, I12 |
| Algorithm confusion, symmetric or private keys | I5, I6 |
| Enumeration of issuers | I9, I11, I3 |
| Exposure of administrative operations | I3, I2 |
| Compromised onboarding account or onboarding service | I14, I16, I17; the onboarding service holds no issuer private keys (I4) and cannot write status lists (I7) |
| Tampering with, or mistakes in, the registry | I13, I15 |
| One tenant exhausting a shared server | I16, plus edge and pre-authentication limits |
| Test content mistaken for production content | I17 |

## Trade-offs

- **Onboarding a production issuer is an operator action**, a reviewed change to the registry rather than an API call. This is intended: trusting a production issuer is a human decision with an audit trail.
- **The hosted profile has two sources of truth.** The single resolution abstraction, global identifier uniqueness and I14 keep them consistent.
- **The change is breaking.** Self-registration goes away, and tokens must carry more information.
- **More moving parts:** three listeners to deploy, monitor and cover by network policy; and, for the hosted profile, a separate onboarding deployment.
- **Per-issuer limits enforced inside the server are per replica.** A cluster-wide ceiling belongs at the edge.

## Operational constraints

- **Registry changes are not instantaneous everywhere.** How fast a change reaches the server depends on how the document is delivered. For example, configuration mounted into a container can take on the order of a minute. Operators who must revoke immediately need to account for that delay.
- **The hosted profile needs durable storage shared by all replicas** for onboarding-registered issuers and their audit trail.
- **Clocks must be synchronised.** Token lifetimes are short.
- **No external route may reach the admin listener.** Edge routing for the public and management surfaces must be separate.

## References

- RFC 6750, *The OAuth 2.0 Authorization Framework: Bearer Token Usage*
- RFC 7515, *JSON Web Signature*; RFC 7517, *JSON Web Key*; RFC 7519, *JSON Web Token*
- RFC 7638, *JSON Web Key (JWK) Thumbprint*
- RFC 8725, *JSON Web Token Best Current Practices*
- IETF draft *Token Status List* (draft-ietf-oauth-status-list)
