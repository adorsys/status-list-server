"""Scenario: A Token Issuer maintains a Token Status List at the Status List Server."""

from helpers import fixtures, utils
from helpers.utils import tc, Status
import requests
import uuid
import jwt

BASE_URL = utils.get_base_url()
print(f"Using base URL: {BASE_URL}")

# Test the health check endpoint (GET /health)
health_endpoint = f"{BASE_URL}/health"
print(f"Testing GET: {health_endpoint}")

response = requests.get(health_endpoint)
tc.assertEqual(response.status_code, 200, "Health check failed")
tc.assertEqual("OK", response.text)

print("Health check successful! Server is running.")

# Publish credentials to register as an Issuer (POST /api/v1/credentials)
issuer_data = fixtures.get_gondwana_digital_pole_issuer()
print("Proceeding with Issuer:", issuer_data.get("label"))

credentials_endpoint = f"{BASE_URL}/api/v1/credentials"
print(f"Testing POST: {credentials_endpoint}")

payload = {
    "issuer": issuer_data.get("label"),
    "public_key": fixtures.get_public_jwk(issuer_data),
}

response = requests.post(credentials_endpoint, json=payload)
tc.assertEqual(response.status_code, 202, "Failed to publish credentials")
print("Credentials published successfully!")

# It should not be possible to replay the request to publish credentials for the same issuer.
response = requests.post(credentials_endpoint, json=payload)
tc.assertEqual(response.status_code, 409)
tc.assertEqual("credentials_already_exist", response.json().get("error"))

# Publish token statuses to a status list (PUT /api/v1/status-lists/{list_id}/statuses)
status_list_id = str(uuid.uuid4())
print("Publishing status list:", status_list_id)

status_publish_endpoint = f"{BASE_URL}/api/v1/status-lists/{status_list_id}/statuses"
print(f"Testing PUT: {status_publish_endpoint}")

bearer_token = fixtures.create_bearer_jwt_token(issuer_data)

response = requests.put(
    status_publish_endpoint,
    headers={"Authorization": f"Bearer {bearer_token}"},
    json={
        "statuses": [{"index": 1, "status": Status.VALID}, {"index": 2, "status": Status.INVALID}]
    },
)

tc.assertEqual(response.status_code, 201, "Failed to publish token statuses")
print("Token statuses published successfully!")

# It should not be possible to publish again under the same status list ID.
response = requests.put(
    status_publish_endpoint,
    headers={"Authorization": f"Bearer {bearer_token}"},
    json={"statuses": [{"index": 1, "status": Status.VALID}]},
)

tc.assertEqual(response.status_code, 409)
tc.assertEqual("status_list_already_exists", response.json().get("error"))

# Update token statuses given a status list (PATCH /api/v1/status-lists/{status_list_id}/statuses)
status_update_endpoint = f"{BASE_URL}/api/v1/status-lists/{status_list_id}/statuses"
print(f"Testing PATCH: {status_update_endpoint}")
print("Updating status list:", status_list_id)

response = requests.patch(
    status_update_endpoint,
    headers={"Authorization": f"Bearer {bearer_token}"},
    json={
        "statuses": [{"index": 1, "status": Status.INVALID}, {"index": 8, "status": Status.INVALID}]
    },
)

tc.assertEqual(response.status_code, 200, "Failed to update token statuses")
print("Token statuses updated successfully!")

# A Relying Party retrieves published status lists (GET /api/v1/status-lists/{status_list_id})
# application/statuslist+jwt
status_retrieve_endpoint = f"{BASE_URL}/api/v1/status-lists/{status_list_id}"
print(f"Testing GET: {status_retrieve_endpoint}")

headers = {"Accept": "application/statuslist+jwt"}
response = requests.get(status_retrieve_endpoint, headers=headers)
tc.assertEqual(response.status_code, 200, "Failed to retrieve status list")
tc.assertEqual(
    response.headers.get("Content-Type"),
    "application/statuslist+jwt",
    "JWT retrieval must advertise the statuslist+jwt media type",
)

print("Retrieved status list successfully:", end=" ")
jwt_token = response.text
print(jwt_token)

# validate JWT
header = jwt.get_unverified_header(jwt_token)
payload = jwt.decode(jwt_token, options={"verify_signature": False})

tc.assertEqual("statuslist+jwt", header.get("typ"))
status_list = payload.get("status_list")
bits = status_list.get("bits")
tc.assertEqual(1, bits)

# Indices 1, 2 and 8 are INVALID; every other index in the list is VALID.
jwt_statuses = utils.decode_and_decompress(status_list.get("lst"))
invalid_indices = {1, 2, 8}
tc.assertGreater(
    len(jwt_statuses) * 8 // bits, max(invalid_indices), "Status list is too short"
)
for index in range(len(jwt_statuses) * 8 // bits):
    expected = Status.INVALID if index in invalid_indices else Status.VALID
    tc.assertEqual(expected, utils.get_status(jwt_statuses, index, bits), f"Unexpected status at index {index}")

# application/statuslist+cwt
headers = {"Accept": "application/statuslist+cwt"}
response = requests.get(status_retrieve_endpoint, headers=headers)
tc.assertEqual(response.status_code, 200, "Failed to retrieve status list")
tc.assertEqual(
    response.headers.get("Content-Type"),
    "application/statuslist+cwt",
    "CWT retrieval must advertise the statuslist+cwt media type",
)

# The CWT must carry the same status list as the JWT. It is verified structurally
# and by decoding its status_list claim and asserting the exact same statuses.
cwt_status_list = utils.decode_cwt_status_list(response.content)
cwt_bits = cwt_status_list["bits"]
tc.assertEqual(bits, cwt_bits, "CWT status_list.bits must match the JWT")
cwt_statuses = utils.decompress_bytes(cwt_status_list["lst"])
tc.assertEqual(
    len(cwt_statuses) * 8 // cwt_bits,
    len(jwt_statuses) * 8 // bits,
    "CWT status list length must match the JWT",
)
for index in range(len(cwt_statuses) * 8 // cwt_bits):
    expected = Status.INVALID if index in invalid_indices else Status.VALID
    tc.assertEqual(
        expected,
        utils.get_status(cwt_statuses, index, cwt_bits),
        f"Unexpected CWT status at index {index}",
    )

print("Retrieved status list successfully")
