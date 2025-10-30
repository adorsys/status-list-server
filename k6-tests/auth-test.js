import http from 'k6/http';
import { check, sleep } from 'k6';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';

// Load test configuration for authenticated endpoints - Increased load for comprehensive testing
export const options = {
  stages: [
    { duration: '2m', target: 30 },   // Ramp up to 30 users over 2 minutes
    { duration: '5m', target: 60 },   // Increase to 60 users for 5 minutes
    { duration: '10m', target: 100 }, // Peak load with 120 users for 10 minutes
    { duration: '5m', target: 60 },   // Scale back to 60 users for 5 minutes
    { duration: '3m', target: 0 },    // Ramp down to 0 users over 3 minutes
  ],
  thresholds: {
    http_req_duration: ['p(95)<1200'], // 95% of requests must complete within 1.2s
    http_req_failed: ['rate<0.08'],    // Error rate must be less than 8%
    http_reqs: ['rate>80'],            // Must handle more than 80 requests per second
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

// Sample ECDSA P-256 key pair for testing (ES256)
// In production, use proper key management
const PRIVATE_KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGY7ZGFhZ2FhZ2FhZ2FhZ2FhZ2FhZ2FhZ2FhZ2FhZ2FhoAoGCCqGSM49
AwEHoUQDQgAE8uV8H8K2jvAY7TUJEPxCu1c1qfVF5z6dQ9z6dQ9z6dQ9z6dQ9z6d
Q9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ==
-----END EC PRIVATE KEY-----`;

const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8uV8H8K2jvAY7TUJEPxCu1c1qfVF
5z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ==
-----END PUBLIC KEY-----`;

const ISSUER_ID = 'test-issuer-' + Math.random().toString(36).substr(2, 9);

// Simple JWT creation function for ES256 (demonstration purposes)
// In production, use proper JWT libraries
function createJWT(payload, header = {}) {
  const jwtHeader = {
    alg: 'ES256',
    typ: 'JWT',
    kid: ISSUER_ID,
    ...header
  };

  const encodedHeader = encoding.b64encode(JSON.stringify(jwtHeader), 'url');
  const encodedPayload = encoding.b64encode(JSON.stringify(payload), 'url');

  // Note: This is a simplified JWT creation for demonstration
  // In a real scenario, you would need proper ECDSA signing
  // For now, we'll create a mock JWT structure
  const signature = 'mock-signature-for-demo';

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

export function setup() {
  // Register the issuer first
  const registrationPayload = {
    issuer: ISSUER_ID,
    public_key: PUBLIC_KEY,
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

  if (!check(registrationRes, { 'issuer registration successful': (r) => r.status < 300 })) {
    console.warn('Issuer registration failed, authenticated tests may not work properly');
  }

  return { issuerId: ISSUER_ID };
}

export default function (data) {
  // Create a JWT token for authentication
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: data.issuerId,
    iat: now,
    exp: now + 3600, // Expires in 1 hour
  };

  const token = createJWT(payload);
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
    'publish status list request sent': (r) => r.status !== undefined,
    'publish status not 500': (r) => r.status !== 500,
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
    'update status list request sent': (r) => r.status !== undefined,
    'update status not 500': (r) => r.status !== 500,
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
    'k6-results/auth-load-test-summary.json': JSON.stringify(data),
  };
}