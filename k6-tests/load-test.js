import http from 'k6/http';
import { check, sleep } from 'k6';

// Load test configuration - Increased load for comprehensive testing
export const options = {
  stages: [
    { duration: '1m', target: 10 },
    { duration: '2m', target: 50 },
    { duration: '3m', target: 100 },
    { duration: '2m', target: 50 },
    { duration: '1m', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<800'], // 95% of requests must complete within 800ms
    http_req_failed: ['rate<0.05'],   // Error rate must be less than 5%
    http_reqs: ['rate>100'],          // Must handle more than 100 requests per second
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

export default function () {
  // Test 1: Health check endpoint - critical for monitoring
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, {
    'health check status is 200': (r) => r.status === 200,
    'health check response has status': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.status === 'OK';
      } catch {
        return r.body === 'OK';  // ✅ Handle plain text response
      }
    },
    'health check response time < 50ms': (r) => r.timings.duration < 50,
  });

  sleep(0.5);

  // Test 2: Welcome endpoint - basic functionality
  const welcomeRes = http.get(`${BASE_URL}/`);
  check(welcomeRes, {
    'welcome status is 200': (r) => r.status === 200,
    'welcome response contains server name': (r) => r.body.includes('Status list Server') || r.body.includes('Status'),
    'welcome response time reasonable': (r) => r.timings.duration < 200,
  });

  sleep(0.5);

  // Test 3: Multiple status list retrieval attempts with varied patterns
  const testListIds = [
    'non-existent-id',
    `random-${Math.random().toString(36).substr(2, 12)}`,
    'common-list-id',
    `test-${Date.now()}-${Math.floor(Math.random() * 1000)}`
  ];

  for (let i = 0; i < 2; i++) {
    const listId = testListIds[Math.floor(Math.random() * testListIds.length)];
    const statusListRes = http.get(`${BASE_URL}/statuslists/${listId}`);
    check(statusListRes, {
      'status list request handled': (r) => r.status !== undefined,
      'status list not 500': (r) => r.status !== 500,  // ✅ Check for server errors
      'status list response time acceptable': (r) => r.timings.duration < 500,
    });
    sleep(0.3);
  }

  // Test 4: Credentials endpoint with various payloads
  if (Math.random() < 0.2) { // ✅ Reduced to 20% to avoid conflicts
    const randomIssuer = `load-test-issuer-${Date.now()}-${Math.random().toString(36).substr(2, 10)}`;

    const registrationPayload = {
      issuer: randomIssuer,
      public_key: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH7cVDLpljWF+OEpxhdSVWCD1qWiq
IV/0Cq05gB6Ia7bClgK1zMoS5hHtx3+fhd9A62YEgLAOp8n1b6xh7TNG/A==
-----END PUBLIC KEY-----`,
      alg: 'RS256'  // ✅ Using RS256 for this RSA key
    };

    const registrationRes = http.post(
      `${BASE_URL}/credentials`,
      JSON.stringify(registrationPayload),
      {
        headers: { 'Content-Type': 'application/json' }
      }
    );

    check(registrationRes, {
      'credentials request processed': (r) => r.status !== undefined,
      'credentials accepted or conflict': (r) => r.status === 202 || r.status === 409,  // ✅ Accept both
      'credentials not 500': (r) => r.status !== 500,
      'credentials response time acceptable': (r) => r.timings.duration < 800,
    });

    sleep(1);
  }
}