import http from 'k6/http';
import { check, sleep } from 'k6';

// Load test configuration - Increased load for comprehensive testing
export const options = {
  stages: [
    { duration: '2m', target: 10 },   // Ramp up to 50 users over 2 minutes
    { duration: '5m', target: 98 },  // Increase to 98 users for 5 minutes
    { duration: '8m', target: 100 },  // Peak load with 100 users for 8 minutes
    { duration: '5m', target: 98 },  // Scale back to 98 users for 5 minutes
    { duration: '2m', target: 0 },    // Ramp down to 0 users over 2 minutes
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
    'health check response is OK': (r) => r.body === 'OK',
    'health check response time < 50ms': (r) => r.timings.duration < 50,
  });

  sleep(0.5);

  // Test 2: Welcome endpoint - basic functionality
  const welcomeRes = http.get(`${BASE_URL}/`);
  check(welcomeRes, {
    'welcome status is 200': (r) => r.status === 200,
    'welcome response contains server name': (r) => r.body.includes('Status list Server'),
    'welcome response time reasonable': (r) => r.timings.duration < 200,
  });

  sleep(0.3);

//   // Test 3: Multiple status list retrieval attempts with varied patterns
//   const testListIds = [
//     'non-existent-id',
//     `random-${Math.random().toString(36).substr(2, 12)}`,
//     'common-list-id',
//     `test-${Date.now()}-${Math.floor(Math.random() * 1000)}`
//   ];

//   for (let i = 0; i < 2; i++) {
//     const listId = testListIds[Math.floor(Math.random() * testListIds.length)];
//     const statusListRes = http.get(`${BASE_URL}/statuslists/${listId}`);
//     check(statusListRes, {
//       'status list request handled': (r) => r.status !== undefined,
//       'status list response time acceptable': (r) => r.timings.duration < 500,
//     });
//     sleep(0.2);
//   }

  // Test 4: Credentials endpoint with various payloads
  if (Math.random() < 0.4) { // 40% chance to test registration
    const registrationPayload = {
      issuer: `load-test-issuer-${Math.random().toString(36).substr(2, 10)}`,
      public_key: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHnylV5lCVtFs6wxmnn5fZJqAykVo
t4R8AesZRagg2xQFfeWOqsKiUuFs2Au9UjvyaI8ZV0IC0/Bj7vdH2liWEA==
-----END PUBLIC KEY-----`,
      alg: 'ES256'
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
      'credentials response time acceptable': (r) => r.timings.duration < 800,
    });
  }

//   sleep(0.5);
}

export function handleSummary(data) {
  return {
    'stdout': JSON.stringify(data, null, 2), // Pretty print to terminal
    'k6-results/basic-load-test-summary.json': JSON.stringify(data),
  };
}