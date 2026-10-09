"""Scenario: Unregistered issuers cannot publish lists."""

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

# Register one issuer
credentials_endpoint = f"{BASE_URL}/api/v1/credentials"
print(f"Testing POST: {credentials_endpoint}")

gondwana_digital_pole = fixtures.get_gondwana_digital_pole_issuer()
print("Proceeding with Issuer:", gondwana_digital_pole.get("label"))

payload = {
    "issuer": gondwana_digital_pole.get("label"),
    "public_key": fixtures.get_public_jwk(gondwana_digital_pole),
}

response = requests.post(credentials_endpoint, json=payload)
tc.assertEqual(response.status_code, 202, "Failed to publish credentials")
print("Credentials published successfully!")

# The registered issuer publishes a status list
bearer_token = fixtures.create_bearer_jwt_token(gondwana_digital_pole)
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

# An unregistered issuer is refused when publishing a list
scott_holdings = fixtures.get_scott_holdings_issuer()
bearer_token = fixtures.create_bearer_jwt_token(scott_holdings)
status_list_id = str(uuid.uuid4())

status_publish_endpoint = f"{BASE_URL}/api/v1/status-lists/{status_list_id}/statuses"
print(f"Testing PUT: {status_publish_endpoint}")

response = requests.put(
    status_publish_endpoint,
    json={"statuses": [{"index": 1, "status": Status.VALID}]},
    headers={"Authorization": f"Bearer {bearer_token}"},
)

tc.assertEqual(response.status_code, 401, "Unregistered clients should be unable to publish lists")
tc.assertEqual("issuer_not_found", response.json().get("error"))
print(f"Unregistered Issuer B was prevented from publishing status list {status_list_id}")

# An unauthenticated client is refused when publishing a list
print(f"Testing PUT: {status_publish_endpoint}")

response = requests.put(
    status_publish_endpoint,
    json={"statuses": [{"index": 1, "status": Status.VALID}]},
)

tc.assertEqual(response.status_code, 401, "Authentication should be required on the publish endpoint")
tc.assertEqual("invalid_auth_header", response.json().get("error"))
print("The unauthenticated client was prevented from publishing a status list")
