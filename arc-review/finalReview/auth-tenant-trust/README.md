<!-- markdownlint-disable MD013 MD060 -->

# Authentication And Tenant Trust

**Baseline:** `adbe8fdacae5edb1ce655a14a5f5f2120ea229e3` (`HEAD`).

## Areas

| Area | Finding and Consequences |
|---|---|
| Issuer Onboarding | `POST /api/v1/credentials` is completely unauthenticated. The first caller can bind any issuer string to caller-controlled JWK material. It is possible to squat the server with fake issuers and nonsense lists. How can an issuer be trusted if anybody can define the issuer? **PoC:** [PoC 1: issuer onboarding](#poc-1-issuer-onboarding) proves anonymous registration; [PoC 4: issuer squatting](#poc-4-issuer-squatting) proves the later legitimate registration is locked out. |
| JWT Token handling | The bearer JWT middleware verifies a signature, stored `iss`, and `exp`. No exact API audience, management token type, route scope, list permission, `iat`, `nbf` policy, maximum `exp-iat`, or replay/JTI rule is enforced. A valid token can be used for both management operations, publish and update, on any list owned by its issuer. A token should provide an exact audience, management type, and scope. The JWT should be tailored to a specific operation and status-list ID so it cannot be used for privileged escalation. **PoC:** [PoC 2: unprofiled publish token](#poc-2-unprofiled-publish-token) and [PoC 3: unprofiled update token](#poc-3-unprofiled-update-token). |
| Public Discovery of Attacker-Created Lists | If an attacker creates fake issuer lists in the name of other companies, they are visible through the aggregation endpoint. See Issuer Onboarding. Is there a way to ensure trusted onboarding? The aggregation endpoint is intentionally public and issuer-agnostic, so trusted onboarding must be enforced before a list is created. **PoC:** [PoC 5: public aggregation](#poc-5-public-aggregation). |

This PoC does not claim a signature bypass, cross-issuer update bypass, use of production issuer material, or a real relying-party false decision. It proves that the repository-local service establishes issuer authority from an anonymous first writer and then treats that key as a management principal.

## Executable PoC

Requirements: Docker with Compose, Python 3.10+, and OpenSSL. The stack binds only to loopback, uses a disposable PostgreSQL database, and mounts checked-in test-only signer fixtures. The script generates all issuer keys and UUIDs at runtime and refuses non-loopback targets unless `--confirm-disposable-target` is present.

```bash
docker compose -p auth-tenant-trust \
  -f arc-review/finalReview/auth-tenant-trust/docker-compose.yml up -d --build

python3 arc-review/finalReview/auth-tenant-trust/poc_auth_tenant_trust.py \
  --confirm-disposable-target
```

Expected vulnerable output:

```text
[1/5] Anonymous issuer onboarding accepted: HTTP 202
[2/5] Unprofiled bearer token accepted for publish: claims=["exp", "iss"]; HTTP 201
[3/5] Same bearer token accepted for update scope: HTTP 200
[4/5] Later conflicting issuer registration is locked out: HTTP 409
[5/5] Public aggregation advertises the attacker-created list: HTTP 200

RESULT: tenant trust-boundary failures reproduced at baseline adbe8fdacae5edb1ce655a14a5f5f2120ea229e3
```

### PoC 1: Issuer Onboarding

Anonymous `POST /api/v1/credentials` binds a victim issuer string to an attacker-controlled JWK.

### PoC 2: Unprofiled Publish Token

A bearer JWT containing only `iss` and `exp` is accepted to publish a status list.

### PoC 3: Unprofiled Update Token

The same bearer JWT is accepted to update the status list.

### PoC 4: Issuer Squatting

A later registration with a different JWK for the same issuer string receives `409 Conflict`.

### PoC 5: Public Aggregation

The aggregation endpoint returns the attacker-created status-list URI without authentication.

Tear down every container, network, and database volume:

```bash
docker compose -p auth-tenant-trust \
  -f arc-review/finalReview/auth-tenant-trust/docker-compose.yml down -v --remove-orphans
```
