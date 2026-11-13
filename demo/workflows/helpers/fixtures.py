import jwt
import time
import os
import hashlib
import json
import base64

# Demo keypairs only; real issuers keep keys in a secret store.


def get_gondwana_digital_pole_issuer():
    """Return the fixed demo issuer provisioned by the local registry fixture."""
    issuer_data = {
        "label": "gondwana-digital-pole",
        "keypair": {
            "alg": "ES256",
            "public_key": (
                "-----BEGIN PUBLIC KEY-----\n"
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEswasdMSg9Y6ZhBSheyx8KVq4ZkKuA54Azf8lVCj4zJ0mVV+CqG9obN+JTDGAQWzja9DKT0oyhUMgNDtQB94xTw==\n"
                "-----END PUBLIC KEY-----"
            ),
            "private_key": (
                "-----BEGIN PRIVATE KEY-----\n"
                "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBqY2vsWCFZmTVGtyhSrEvpm08k1CpLdq63WcAdpstuEQ==\n"
                "-----END PRIVATE KEY-----"
            ),
        }
    }
    return issuer_data


def get_scott_holdings_issuer():
    """Return the fixed demo issuer provisioned by the local registry fixture."""
    issuer_data = {
        "label": "scott-holdings",
        "keypair": {
            "alg": "PS256",
            "public_key": (
                "-----BEGIN PUBLIC KEY-----\n"
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs4Df4EUySK6d7pRQkLhM6lbgtSuKwDOnJ3IpUyiP6yY8Bl4+ksmSC3Q3xe9KgAltkQd+hVo/3bSw1Mn5Ozzcs+xXTkt7IIDpFE8wWe4sPdm1+OZ0tZb3FWJV2fM4ZsFeo6+ucaiZjmUIeq+xccMaNcPkP6xhBtlMXuvtf2PkKqov9Im8MgmrTwSMZa1AWHo0bgS5AdB9n3KKjp75CCTtLdT4/fRpehgfu9F+QHPl6YYHSKNEYzzSt+Ix0A76IYceuryQFps3iIVDRlFAqfFTjHlP3Cg7byhjee4YCqL9YwTSLyRVxYKfUU9byiDGqf9jeiXZRssVNLK99c8MxzEvfwIDAQAB\n"
                "-----END PUBLIC KEY-----"
            ),
            "private_key": (
                "-----BEGIN PRIVATE KEY-----\n"
                "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzgN/gRTJIrp3ulFCQuEzqVuC1K4rAM6cncilTKI/rJjwGXj6SyZILdDfF70qACW2RB36FWj/dtLDUyfk7PNyz7FdOS3sggOkUTzBZ7iw92bX45nS1lvcVYlXZ8zhmwV6jr65xqJmOZQh6r7Fxwxo1w+Q/rGEG2Uxe6+1/Y+Qqqi/0ibwyCatPBIxlrUBYejRuBLkB0H2fcoqOnvkIJO0t1Pj99Gl6GB+70X5Ac+XphgdIo0RjPNK34jHQDvohhx66vJAWmzeIhUNGUUCp8VOMeU/cKDtvKGN57hgKov1jBNIvJFXFgp9RT1vKIMap/2N6JdlGyxU0sr31zwzHMS9/AgMBAAECggEBALDjQLq6tbCWEp/2m+XhGDqdXlZqEBMTU5c1kq+V+yzYwrHr0XHJHRgYcJWnFx1RLR2L6wvyQZly5Abs+aN8eGj9b5OCIlWHcyhGWPlmEUbp8b7TKxN/LwFto/hhC6WGzII1L4xlftyph0+PLydSAdQVtCli70JWhEHN8H5mq4O2BxNRY5pnjiKbCu/eX3DnlM+0ZrYfOFHCV6fJPi1mADX4DQcaYjWYJ+NKGX3/dAf9RTTV2d9HDR6DMVedKCPOqxbhPk4H6b8WZ2YG1DYUODUrtS04aOCI2+zl38ihvMfYQJdim/xb9b8ycrSNgLImBWI1WJ4wc6m3ugkIQFc8M8ECgYEA4KV9V6PtNTqp5OO3YpCN7VOfQ3VIeQh0iF6obNOD1myUsC2PjSPY5RifZwTdTDeEPZ91fAk+W3iwwy7BYZhELGhs4Xq2OFXendr5Q9aQteDZqhTxLABYT/juGlipS9o8C9Y2CQ0fH33BUVXQ7oherTO9rTe6P1dsoTxIzWGLCjECgYEAzI5yLvaas/zmEYAJYzfok5go6YAbytbNIqTI/nvaVHU4sYd3ryv1RYxpMcx9pKluh7NEUaBuBpXJ0qtMWB49UG98ENKet4SHn1IwA5/N/v7sJoYQsFeBfCtIxDdE5mIlwmysrMtyk+k+rMpD8oxr+DHUw+lrecn60mXH4qByuK8CgYBieunZ07kXTqJP/yvTf79YPQJiljWxKW28opJ/MrJm+66rFS4LF53rwMGQbed9lBDa2t6sA3lcrCoBRqvr1s58EUM6DYt4Ytx2oxoHDTbfJLUHBKs9OOF+HYhz8E43PHJ6VevWR/RO39gxicdP6mRm1XnfR8DUJ8UtYbognxRO4QKBgFjkjjpacGBHRrPUMEAty6RYO289fNZpAjxL4Ay3RenuBvUfKaO2NqBCpHQ/qVolRyMxhD70uNujvFEQn9yrR3ns+L1WyiJ2NXnG/ZaVm690mKslF5uKa3rKVJTwb8CuZjpXf7KXtvMQKWxteZmt7D2vaga5KTuDyrwj/vk9QJ2BAoGBAKInb9rh5kfZ199PnSALPhfVSfZVNH6zpNMp4cXmuL9uqguA/csR3jgU/TOxE9wwmovCkpKwViOlPlKpESWGMOg1Es9KDLN86nLhsJ1Hpk009sDZ4AoJPhipH9R/7964Ow5L7DpS5MFkkgrK+68kmBBosxTPgs2NLzMQlF3xGrOV\n"
                "-----END PRIVATE KEY-----"
            ),
        }
    }
    return issuer_data


def get_public_jwk(issuer: dict) -> dict:
    """Public JWK (RFC 7517) from the issuer's PEM key, tagged with its alg."""
    alg = issuer["keypair"]["alg"]
    algorithm = jwt.get_algorithm_by_name(alg)
    public_key = algorithm.prepare_key(issuer["keypair"]["public_key"])

    jwk = algorithm.to_jwk(public_key, as_dict=True)
    # PyJWT adds key_ops to RSA keys only; drop it so every key type has the same shape.
    jwk.pop("key_ops", None)

    # Management JWTs are resolved by kid and pinned to this signing algorithm.
    thumbprint_fields = {name: jwk[name] for name in ("crv", "kty", "x", "y") if name in jwk}
    if jwk.get("kty") == "RSA":
        thumbprint_fields = {name: jwk[name] for name in ("e", "kty", "n")}
    thumbprint = base64.urlsafe_b64encode(hashlib.sha256(
        json.dumps(thumbprint_fields, sort_keys=True, separators=(",", ":")).encode()
    ).digest()).decode().rstrip("=")
    return {**jwk, "alg": alg, "kid": thumbprint}


def write_registry_fixture(path="issuer-registry/issuers.yaml"):
    """Write the fixed local demo identities as a JSON-compatible YAML registry."""
    issuers = []
    for issuer, aggregation_id in [
        (get_gondwana_digital_pole_issuer(), "00000000-0000-4000-8000-000000000101"),
        (get_scott_holdings_issuer(), "00000000-0000-4000-8000-000000000102"),
    ]:
        jwk = get_public_jwk(issuer)
        issuers.append({
            "id": issuer["label"],
            "aggregation_id": aggregation_id,
            "tier": "standard",
            "keys": [{"kid": jwk["kid"], "alg": jwk["alg"], "jwk": jwk}],
        })
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as registry:
        json.dump({"version": 1, "issuers": issuers, "admins": []}, registry, indent=2)
        registry.write("\n")


def create_bearer_jwt_token(issuer: dict, lifespan: int = 300) -> str:
    """Lifespan defaults to 300 s, the server's default maximum."""
    current_time = int(time.time())
    payload = {
        # The verified issuer must own the key named by the JWT header.
        "iss": issuer["label"],
        "aud": os.environ.get("MANAGEMENT_AUDIENCE", "status-list-server-management"),
        "iat": current_time,
        "exp": current_time + lifespan
    }

    return jwt.encode(
        payload,
        issuer['keypair']['private_key'],
        algorithm=issuer["keypair"]["alg"],
        headers={"typ": "statuslist-management+jwt", "kid": issuer["label"]},
    )
