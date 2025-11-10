import http from 'k6/http';
import { check, sleep } from 'k6';
import { uuidv4 } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

export const options = {
  stages: [
    { duration: '30s', target: 10 },
    { duration: '2m', target: 50 },
    { duration: '3m', target: 100 },
    { duration: '2m', target: 50 },
    { duration: '1m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'],
    http_req_failed: ['rate<0.05'],
    http_reqs: ['rate>20'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

// Load pre-generated tokens
const tokenData = JSON.parse(open('./test-tokens.json'));

export function setup() {
  // Register the issuer with the server
  const registrationPayload = {
    issuer: tokenData.issuerId,
    public_key: tokenData.publicKey,
    alg: 'ES256'
  };

  console.log('Registering issuer:', tokenData.issuerId);
  
  const registrationRes = http.post(
    `${BASE_URL}/credentials`,
    JSON.stringify(registrationPayload),
    {
      headers: {
        'Content-Type': 'application/json',
      },
    }
  );

  if (!check(registrationRes, { 
    'issuer registration successful': (r) => r.status === 202 || r.status === 409 
  })) {
    console.error('Issuer registration failed:', registrationRes.status, registrationRes.body);
    throw new Error('Failed to register issuer');
  }

  console.log('Issuer registered successfully with status:', registrationRes.status);
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
    list_id: uuidv4(),
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
    'publish status not 409': (r) => r.status !== 409,
  });

  if (publishRes.status !== 201) {
    console.warn(`Publish failed with status ${publishRes.status}: ${publishRes.body}`);
  }

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

  if (updateRes.status !== 200) {
    console.warn(`Update failed with status ${updateRes.status}: ${updateRes.body}`);
  }

  sleep(1);

  // Test 3: Fetch the published status list from database (test database retrieval)
  const fetchRes = http.get(`${BASE_URL}/statuslists/${publishPayload.list_id}`);
  
  check(fetchRes, {
    'fetch status list from db succeeded': (r) => r.status === 200,
    'fetch status list from db not 500': (r) => r.status !== 500,
    'fetch status list from db not 404': (r) => r.status !== 404,
    'fetched status list contains expected data': (r) => {
      if (r.status === 200) {
        // Server returns a gzip-compressed JWT token, not JSON
        // Check if we got a response body with JWT-like content
        return r.body && 
               r.body.length > 0 && 
               r.headers['Content-Type'] === 'application/statuslist+jwt' &&
               r.headers['Content-Encoding'] === 'gzip';
      }
      return false;
    },
  });

  if (fetchRes.status !== 200) {
    console.warn(`Fetch from DB failed with status ${fetchRes.status}: ${fetchRes.body}`);
  }

  sleep(1);

  // Test 4: Try to access endpoints without authentication (should return 401)
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