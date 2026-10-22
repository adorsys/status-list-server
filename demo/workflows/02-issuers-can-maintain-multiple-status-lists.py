"""Scenario: Token Issuers can maintain multiple Token Status Lists."""

from helpers import fixtures, utils
from helpers.utils import tc, Status
import requests
import uuid

BASE_URL = utils.get_base_url()
MANAGEMENT_URL = utils.get_management_url()
print(f"Using base URL: {BASE_URL}")
print(f"Using management URL: {MANAGEMENT_URL}")

# Test the health check endpoint (GET /health)
health_endpoint = f"{BASE_URL}/health"
print(f"Testing GET: {health_endpoint}")

response = requests.get(health_endpoint)
tc.assertEqual(response.status_code, 200, "Health check failed")
tc.assertEqual("OK", response.text)

print("Health check successful! Server is running.")

# Use the two issuers provisioned in demo/issuers.yaml
gondwana_digital_pole = fixtures.get_gondwana_digital_pole_issuer()
scott_holdings = fixtures.get_scott_holdings_issuer()


# Each issuer publishes three status lists
for issuer_data in [gondwana_digital_pole, scott_holdings]:
    bearer_token = fixtures.create_bearer_jwt_token(issuer_data)
    for _ in range(3):  # each issuer publishes three lists
        status_list_id = str(uuid.uuid4())
        status_publish_endpoint = f"{MANAGEMENT_URL}/api/v1/status-lists/{status_list_id}/statuses"
        print(f"Testing PUT: {status_publish_endpoint}")
        print(f"{issuer_data.get('label')} publishes status list {status_list_id}")

        response = requests.put(
            status_publish_endpoint,
            json={
                "statuses": [{"index": i, "status": Status.VALID} for i in range(5)]
            },
            headers={"Authorization": f"Bearer {bearer_token}"},
        )

        tc.assertEqual(response.status_code, 201, "Failed to publish token statuses")
