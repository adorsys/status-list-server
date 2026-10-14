# 2. Issuer trust, onboarding, and access control

- **Status:** Accepted
- **Date:** 2026-10-12

## Context

The server lets issuers publish and update status lists, and serves those lists to relying parties. Until this decision, anyone who could reach the server could make themselves an issuer. Registration was an unauthenticated operation that bound a caller-chosen identifier to a caller-chosen public key, first come first served. Public reads and issuer writes shared one network surface, so what was exposed depended entirely on reverse-proxy routing rules.

That left these gaps:

- Any caller could claim an unused identifier, and with it every status list later published under that identifier.
- An issuer had exactly one key, which could be neither rotated nor revoked without editing storage by hand.
- The signature algorithm was taken from the token itself. Symmetric keys and keys containing private material were accepted as public keys. Different failures were distinguishable, which revealed which identifiers exist.
- Nothing recorded who trusted which key, or when.
- Registered issuers could not be listed or inspected without direct access to storage.
- Limits applied per network address, so on a shared server one issuer could exhaust capacity for all.

The same software must serve two situations:

- An organisation runs the server privately. Only the read endpoints defined by the Token Status List specification face the internet.
- An operator runs a shared server where external issuers sign themselves up to test their integration, under usage limits.

One part of the existing design is sound and is kept. Issuers authenticate every write with a short-lived JWT signed by a private key that only they hold. Every write checks that the issuer owns the status list it targets.

## Decision

The statements below that use *must* or *never* are constraints on every implementation. They hold through any refactoring, and changing one requires a new ADR that supersedes this one. Concrete values, such as token type names, routes, configuration keys and defaults, are not part of this decision.

### Deployment profiles

The server has two deployment profiles:

- In the private profile (the default), only issuers an operator has listed are trusted.
- In the hosted profile, the server also trusts issuers registered through self-service onboarding. These are kept in durable storage, held to stricter limits, and expire.

A profile adds trust sources and limits. It never relaxes any rule in this ADR. A server in the hosted profile must sign status lists with an identity distinct from that of any production deployment, so that test content is never mistaken for production content.

### Separated network surfaces

The server exposes three listeners, and no route is shared between them:

| Listener | Serves | Reachability |
|---|---|---|
| Public | Anonymous reads defined by the Token Status List specification, and liveness | Internet |
| Management | Operations authenticated as an issuer | Private network by default. It may be published in either profile, on the public hostname or a separate one, because every operation on it is authenticated |
| Admin | Issuer listing and lifecycle, readiness, metrics | Private network only, in every profile |

A route is served only on the listener of its class; on every other listener it does not exist. The admin listener must never be reachable from outside the operator's private network. Operators who need it from elsewhere reach it only through a path that authenticates them at the network level, such as a VPN or a mutually authenticated gateway, never directly from the internet. Only the public reads are anonymous: no anonymous operation creates, changes or discloses issuer trust state.

Exposure is therefore decided by which listener is reachable, which network policy can enforce. It no longer depends on path rules in a proxy, which are easy to get wrong.

### Sources of trust

The static registry is a declarative document listing the trusted issuers and admin principals, with their public keys. Operators manage it under version control, so every change to it is attributable to a reviewed commit. Changes apply without a restart. An invalid document is never applied, in whole or in part: at startup the server refuses to start, and while running the last valid version stays in force.

In the hosted profile only, a dynamic store holds the issuers registered through onboarding. They are created and changed only through the admin surface.

Both sources sit behind one key-resolution abstraction. Authentication and request handling do not depend on where a key came from, so a further source can be added later (a remote key set, an external trust list, an OAuth authorization server) without changing either.

### Credentials

Issuers and admin principals authenticate with short-lived JWTs, signed with private keys that only they hold. The server must never hold a private key or a shared secret that authenticates an issuer or admin principal; it stores public keys only.

Each token declares what kind of token it is, names its key, and is bound to an audience. A token of one kind is never accepted where another kind is expected. Tokens have a configured maximum lifetime, and in production audience validation cannot be disabled.

The key that verifies a token is chosen only by the key identifier the token names, resolved against the sources of trust. A key carried in or referenced by the token is never used. Each key is pinned to one algorithm from a small asymmetric allowlist, and a token's declared algorithm must equal it. Symmetric keys and keys containing private material are rejected wherever keys enter the system.

A key may carry a validity window, and an issuer can hold several keys, so a key can be rotated with an overlap and no downtime. Revoking a key, suspending or disabling an issuer, or reaching an expiry takes effect on the next request once the change is visible to the server. No cached authorization outlives it.

Every rejection of a presented token looks identical to the caller. The reason is logged server-side, and logs never contain tokens or key material.

Authentication does not replace the ownership check: every write still verifies that the issuer owns the status list it targets.

### Identifiers

An issuer has two identifiers:

- its issuer identifier, used for authentication and list ownership;
- its aggregation identifier, which is public and appears in published status list tokens.

No party chooses its own identifiers. The server assigns them to onboarding-registered issuers, and operators assign them to static issuers. Both are immutable, never reused, and survive key rotation, a change of trust source and storage migration, because published tokens outlive all of these. They are different values, so publishing the aggregation identifier never reveals the issuer identifier.

### Admin surface

Operators and the onboarding service list and query all issuers, and create and manage onboarding-registered issuers, through an authenticated admin API. A statically trusted issuer appears there but changes only through the registry document; the admin surface can never modify it. Every change made through the admin surface uses optimistic concurrency, and is recorded in an audit record written atomically with the change.

The server serves no human-facing interface. Onboarding interfaces are separate deployments that use only the admin surface.

### Limits

Every issuer belongs to a tier, and limits are enforced per authenticated issuer according to that tier. Network-level limits at the edge and before authentication complement them. The tier used for onboarding-registered issuers never exceeds the operator tier on any limit, and onboarding-registered credentials always expire.

### Self-registration

Unauthenticated self-registration is removed. It survives only as an explicit development switch, and is never available in a production environment. Migrating existing issuers to the registry preserves both of their identifiers. Because this changes the external contract, it ships in a major version.

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

## Consequences

### Trade-offs

- Onboarding a production issuer becomes an operator action: a reviewed change to the registry rather than an API call. This is intended, because trusting a production issuer is a human decision that needs an audit trail.
- The hosted profile has two sources of truth. One resolution abstraction, identifiers unique across both sources, and a read-only admin view of static issuers keep them consistent.
- The change is breaking. Self-registration goes away, and tokens must carry more information.
- There are more moving parts: three listeners to deploy, monitor and cover by network policy, and, for the hosted profile, a separate onboarding deployment.
- Per-issuer limits enforced inside the server apply per replica. A cluster-wide ceiling belongs at the edge.

### Security implications

| Threat | Mitigation |
|---|---|
| Anonymous use of a shared server | No anonymous operation touches trust state, and each route exists only on its listener |
| Identifier squatting or issuer impersonation | Identifiers are assigned, never chosen by the party being registered; static issuers change only through the reviewed registry |
| Stolen token | Tokens are typed, audience-bound and short-lived |
| Stolen private key | The server never holds one; revocation takes effect on the next request |
| Algorithm confusion, symmetric or private keys | Keys are chosen only through the registry and pinned to one asymmetric algorithm; other keys are rejected on entry |
| Enumeration of issuers | Rejections look identical, the public aggregation identifier differs from the issuer identifier, and the admin listener is private |
| Exposure of administrative operations | The admin listener is unreachable from outside the private network, and its routes exist nowhere else |
| Compromised onboarding account or onboarding service | It cannot change static issuers, it is bound by the onboarding tier and expiry, it holds no issuer private keys, and its tokens are not accepted for writes; test content is signed with a non-production identity |
| Tampering with, or mistakes in, the registry | Invalid documents are never applied, and every change is a reviewed commit |
| One tenant exhausting a shared server | Per-issuer tier limits, plus edge and pre-authentication limits |
| Test content mistaken for production content | The hosted profile signs with a distinct identity |

### Operational constraints

- Registry changes are not instantaneous everywhere. How fast a change reaches the server depends on how the document is delivered; configuration mounted into a container, for example, can take on the order of a minute. Operators who must revoke immediately need to account for that delay.
- The hosted profile needs durable storage shared by all replicas, for onboarding-registered issuers and their audit trail.
- Clocks must be synchronised, because token lifetimes are short.
- No external route may reach the admin listener. When the public and management listeners share a hostname, the edge must route each path to the listener that serves it.

## Reconsider if

- A deployment must trust issuers vouched for by an external trust list or an OAuth authorization server, instead of operator review.
- Per-replica limits stop protecting the hosted server, and quotas need a store shared by all replicas.
- Onboarding volume makes review of the registry document the bottleneck for adding production issuers.

## References

- RFC 6750, *The OAuth 2.0 Authorization Framework: Bearer Token Usage*
- RFC 7515, *JSON Web Signature*; RFC 7517, *JSON Web Key*; RFC 7519, *JSON Web Token*
- RFC 7638, *JSON Web Key (JWK) Thumbprint*
- RFC 8725, *JSON Web Token Best Current Practices*
- IETF draft *Token Status List* (draft-ietf-oauth-status-list)
