"""Scenario: Issuer B cannot update Issuer A's list."""

from helpers import fixtures, utils
from helpers.utils import tc, Status
import requests
import uuid

BASE_URL = utils.get_base_url()
print(f"Using base URL: {BASE_URL}")

# Test the health check endpoint (GET /health)
health_endpoint = f"{BASE_URL}/health"
print(f"Testing GET: {health_endpoint}")

response = requests.get(health_endpoint)
tc.assertEqual(response.status_code, 200, "Health check failed")
tc.assertEqual("OK", response.text)

print("Health check successful! Server is running.")

# Register two issuers
gondwana_digital_pole = fixtures.get_gondwana_digital_pole_issuer()
scott_holdings = fixtures.get_scott_holdings_issuer()

for issuer_data in [gondwana_digital_pole, scott_holdings]:
    print("Proceeding with Issuer:", issuer_data.get("label"))

    credentials_endpoint = f"{BASE_URL}/api/v1/credentials"
    print(f"Testing POST: {credentials_endpoint}")

    payload = {
        "issuer": issuer_data.get("label"),
        "public_key": fixtures.get_public_jwk(issuer_data),
    }

    response = requests.post(credentials_endpoint, json=payload)
    tc.assertEqual(response.status_code, 202, "Failed to publish credentials")
    print("Credentials published successfully!\n")

# Issuer A publishes a status list
issuer_data = gondwana_digital_pole
bearer_token = fixtures.create_bearer_jwt_token(issuer_data)
status_list_id = str(uuid.uuid4())

status_publish_endpoint = f"{BASE_URL}/api/v1/status-lists/{status_list_id}/statuses"
print(f"Testing PUT: {status_publish_endpoint}")

response = requests.put(
    status_publish_endpoint,
    json={"statuses": [{"index": 1, "status": Status.VALID}]},
    headers={"Authorization": f"Bearer {bearer_token}"},
)

tc.assertEqual(response.status_code, 201, "Failed to publish token statuses")
print(f"Issuer A published status list {status_list_id}")

# Issuer B attempts to update Issuer A's list and is refused
status_update_endpoint = f"{BASE_URL}/api/v1/status-lists/{status_list_id}/statuses"
print(f"Testing PATCH: {status_update_endpoint}")

issuer_data = scott_holdings
bearer_token = fixtures.create_bearer_jwt_token(issuer_data)

response = requests.patch(
    status_update_endpoint,
    json={"statuses": [{"index": 1, "status": Status.INVALID}]},
    headers={"Authorization": f"Bearer {bearer_token}"},
)

tc.assertEqual(response.status_code, 403, "Should not be allowed to update another issuer's list")
tc.assertEqual("issuer_mismatch", response.json().get("error"))
print(f"Issuer B was prevented from updating status list {status_list_id}")

# An unauthenticated client is refused on the update endpoint
status_update_endpoint = f"{BASE_URL}/api/v1/status-lists/{status_list_id}/statuses"
print(f"Testing PATCH: {status_update_endpoint}")

response = requests.patch(
    status_update_endpoint,
    json={"statuses": [{"index": 1, "status": Status.INVALID}]},
)

tc.assertEqual(response.status_code, 401, "Authentication should be required on the update endpoint")
tc.assertEqual("invalid_auth_header", response.json().get("error"))
print(f"The unauthenticated client was prevented from updating status list {status_list_id}")
