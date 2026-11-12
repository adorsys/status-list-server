# Local issuer onboarding

Run these commands from the repository root after the [local quick start](../README.md#quick-start).
The private profile trusts issuers from the operator registry. The hosted profile
also accepts SQL-backed portal issuers; see [hosted local setup](admin-api.md#hosted-profile-local-setup)
for the admin principal. This guide covers only local testing.

## Onboard a registry issuer

Generate a P-256 key pair with OpenSSL. Keep the private key with the issuer;
only the public JWK goes into the registry. The commands below use the Python
dependencies from the [demo setup](../demo/README.md) to convert the public key
and sign a management token. From the repository root:

```bash
umask 077
install -d -m 700 "$HOME/.local/share/status-list-server"
export ISSUER_KEY
ISSUER_KEY=$(mktemp "$HOME/.local/share/status-list-server/issuer.XXXXXXXX")
openssl ecparam -name prime256v1 -genkey -noout -out "$ISSUER_KEY"
printf 'Private key: %s\n' "$ISSUER_KEY"
mkdir -p issuer-registry
uv run --project demo --locked python - > issuer-registry/public.jwk <<'PY'
import json
import os
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from jwt.algorithms import ECAlgorithm

with open(os.environ["ISSUER_KEY"], "rb") as key_file:
    public_key = load_pem_private_key(key_file.read(), password=None).public_key()
jwk = ECAlgorithm.to_jwk(public_key, as_dict=True)
print(json.dumps({field: jwk[field] for field in ("kty", "crv", "x", "y")}))
PY
```

Create `issuer-registry/issuers.yaml` if it does not already exist:

```bash
if [ ! -e issuer-registry/issuers.yaml ]; then
  printf 'version: 1\nissuers: []\nadmins: []\n' > issuer-registry/issuers.yaml
fi
```

Add the issuer with:

```bash
cargo xtask issuer add --file issuer-registry/issuers.yaml \
  --jwk "$(cat issuer-registry/public.jwk)" --alg ES256
```

The command assigns the issuer ID, aggregation ID, and key ID. Give the issuer
its assigned issuer and key IDs, and keep the private key outside the registry.
Validate the file with
`APP_MANAGEMENT_AUTH__ISSUERS_FILE=issuer-registry/issuers.yaml cargo run -- issuer-registry`
before starting the server with that file. If it was already running without a
registry file, restart it with `APP_MANAGEMENT_AUTH__ISSUERS_FILE` set.

The issuer signs a short-lived JWT with header
`typ: statuslist-management+jwt`, the assigned `kid`, and the registered
`alg`. Claims include `iss` equal to the assigned issuer ID, integer `iat`
and `exp`, and a matching `aud` when `APP_MANAGEMENT_AUTH__AUDIENCES` is set.
The lifetime must not exceed `APP_MANAGEMENT_AUTH__MAX_TOKEN_LIFETIME_SECS`
(300 seconds by default). Send it as `Authorization: Bearer <token>` to the
management listener (default `localhost:8001`). A `PUT` to
`/api/v1/status-lists/{list_id}/statuses` with a fresh UUID and
`{"statuses":[]}` publishes an empty list. The returned URI is served from
the public listener. See the [public OpenAPI contract](openapi.yaml) for
status update requests.

To publish the first list, copy the generated `id` and `keys[0].kid` from
`issuer-registry/issuers.yaml` into `ISSUER_ID` and `KID` below. Start or restart
the server with that registry, using the [quick start](../README.md#quick-start)
and `APP_MANAGEMENT_AUTH__ISSUERS_FILE=issuer-registry/issuers.yaml`. If audience
validation is configured, also export `MANAGEMENT_AUDIENCE` with one accepted
audience before signing. Keep the private key at `ISSUER_KEY` on the issuer's
machine and run these commands there:

```bash
export ISSUER_ID='<generated id>'
export KID='<generated keys[0].kid>'
export ISSUER_KEY='<private key path printed above>'
TOKEN=$(uv run --project demo --locked python - <<'PY'
import os
import time
import jwt

now = int(time.time())
claims = {"iss": os.environ["ISSUER_ID"], "iat": now, "exp": now + 60}
if os.environ.get("MANAGEMENT_AUDIENCE"):
    claims["aud"] = os.environ["MANAGEMENT_AUDIENCE"]
with open(os.environ["ISSUER_KEY"], encoding="utf-8") as key_file:
    token = jwt.encode(
        claims, key_file.read(), algorithm="ES256",
        headers={"typ": "statuslist-management+jwt", "kid": os.environ["KID"]},
    )
print(token)
PY
)
LIST_ID=$(uv run --project demo --locked python -c 'import uuid; print(uuid.uuid4())')
printf 'Authorization: Bearer %s\n' "$TOKEN" | \
  curl -i -X PUT "http://localhost:8001/api/v1/status-lists/$LIST_ID/statuses" \
  -H @- -H 'Content-Type: application/json' \
  --data '{"statuses":[]}'
unset TOKEN ISSUER_ID KID ISSUER_KEY
```

## Onboard a hosted issuer

For the hosted profile, create an admin principal and token using the
[admin API guide](admin-api.md#hosted-profile-local-setup), then use the
[hosted issuer creation demo](../demo/README.md#hosted-issuer-creation-and-renewal).
The hosted issuer signs management tokens with the key registered by the admin;
use the signing and publishing steps above with its assigned issuer and key IDs.
