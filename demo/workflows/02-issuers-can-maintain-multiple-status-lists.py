"""Scenario: Token Issuers can maintain multiple Token Status Lists."""

from helpers import fixtures, utils
from helpers.utils import tc, Status
import requests
import uuid
import random

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

# Each issuer publishes three status lists
for issuer_data in [gondwana_digital_pole, scott_holdings]:
    bearer_token = fixtures.create_bearer_jwt_token(issuer_data)
    for _ in range(3):  # each issuer publishes three lists
        status_list_id = str(uuid.uuid4())
        status_publish_endpoint = f"{BASE_URL}/api/v1/status-lists/{status_list_id}/statuses"
        print(f"Testing PUT: {status_publish_endpoint}")
        print(f"{issuer_data.get('label')} publishes status list {status_list_id}")

        response = requests.put(
            status_publish_endpoint,
            json={
                "statuses": [{"index": i, "status": Status.VALID} for i in range(random.randint(1, 5))]
            },
            headers={"Authorization": f"Bearer {bearer_token}"},
        )

        tc.assertEqual(response.status_code, 201, "Failed to publish token statuses")
