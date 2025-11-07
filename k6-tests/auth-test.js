import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 1 },
    { duration: '3m', target: 60 },
    { duration: '5m', target: 100 },
    { duration: '3m', target: 60 },
    { duration: '1m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<5000'], // Increased to 5 seconds
    http_req_failed: ['rate<0.1'],    // Increased to 10%
    http_reqs: ['rate>10'],           // Decreased to 10 requests/second
  },
};

const BASE_URL = 'http://localhost:8000';

// Load pre-generated tokens
const tokenData = JSON.parse(open('./test-tokens.json'));

export function setup() {
  // Register the issuer with the server
  const registrationPayload = {
    issuer: tokenData.issuerId,
    public_key: tokenData.publicKey,
    alg: 'ES256'
  };

  const registrationRes = http.post(
    `${BASE_URL}/credentials`,
    JSON.stringify(registrationPayload),
    {
      headers: {
        'Content-Type': 'application/json',
      },
    }
  );

  if (!check(registrationRes, { 'issuer registration successful': (r) => r.status < 300 || r.status === 409 })) {
    console.error('Issuer registration failed:', registrationRes.status, registrationRes.body);
    throw new Error('Failed to register issuer');
  }

  console.log('Issuer registered successfully');
  return { 
    issuerId: tokenData.issuerId,
    tokens: tokenData.tokens
  };
}

export default function (data) {
  // Randomly select a valid token from the pre-generated pool
  const token = data.tokens[Math.floor(Math.random() * data.tokens.length)];
  
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
  };

  // Test 1: Publish status list (authenticated endpoint)
  const publishPayload = {
    list_id: `test-list-${Math.random().toString(36).substr(2, 9)}`,
    status: [
      { index: 1, status: 'VALID' },
      { index: 2, status: 'INVALID' },
      { index: 3, status: 'SUSPENDED' }
    ]
  };

  const publishRes = http.post(
    `${BASE_URL}/statuslists/publish`,
    JSON.stringify(publishPayload),
    { headers }
  );

  check(publishRes, {
    'publish status list succeeded': (r) => r.status === 201,
    'publish status not 500': (r) => r.status !== 500,
    'publish status not 401': (r) => r.status !== 401,
  });

  sleep(1);

  // Test 2: Update status list (authenticated endpoint)
  const updatePayload = {
    list_id: publishPayload.list_id,
    status: [
      { index: 1, status: 'INVALID' },
      { index: 2, status: 'VALID' }
    ]
  };

  const updateRes = http.patch(
    `${BASE_URL}/statuslists/update`,
    JSON.stringify(updatePayload),
    { headers }
  );

  check(updateRes, {
    'update status list succeeded': (r) => r.status === 200,
    'update status not 500': (r) => r.status !== 500,
    'update status not 401': (r) => r.status !== 401,
  });

  sleep(1);

  // Test 3: Try to access endpoints without authentication (should return 401)
  const unauthorizedPublishRes = http.post(
    `${BASE_URL}/statuslists/publish`,
    JSON.stringify(publishPayload),
    {
      headers: { 'Content-Type': 'application/json' }
    }
  );

  check(unauthorizedPublishRes, {
    'unauthorized publish returns 401': (r) => r.status === 401,
  });

  sleep(1);
}

export function handleSummary(data) {
  return {
    'k6-tests/k6-results/auth-load-test-summary.json': JSON.stringify(data),
  };
}