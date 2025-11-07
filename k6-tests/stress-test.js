import http from 'k6/http';
import { check, sleep } from 'k6';

// Stress test configuration - pushes the system beyond normal operating capacity with high load
export const options = {
  stages: [
    { duration: '3m', target: 100 },  // Ramp up to 100 users
    { duration: '5m', target: 200 },  // Increase to 200 users
    { duration: '8m', target: 350 },  // Heavy stress test with 350 users
    { duration: '5m', target: 500 },  // Peak stress with 500 users
    { duration: '3m', target: 200 },  // Scale back to 200 users
    { duration: '3m', target: 0 },    // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(99)<3000'], // 99% of requests must complete within 3s
    http_req_failed: ['rate<0.25'],    // Error rate must be less than 25% (lenient for high stress)
    http_reqs: ['rate>150'],           // Must handle more than 150 requests per second
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

export default function () {
  // Focus on the most resource-intensive endpoints

  // Test 1: Health check (lightweight)
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, {
    'health check status is 200': (r) => r.status === 200,
  });

  sleep(0.5); // Shorter sleep for stress test

  // Test 2: Welcome endpoint
  const welcomeRes = http.get(`${BASE_URL}/`);
  check(welcomeRes, {
    'welcome status is 200': (r) => r.status === 200,
  });

  sleep(0.5);

  // Test 3: Multiple requests to non-existent status lists (database load)
  for (let i = 0; i < 3; i++) {
    const listId = `stress-test-${Math.random().toString(36).substr(2, 9)}`;
    const statusListRes = http.get(`${BASE_URL}/statuslists/${listId}`);
    check(statusListRes, {
      'status list request handled': (r) => r.status !== undefined,
    });
    sleep(0.2);
  }

  // Test 4: Concurrent credential registration attempts
  const publicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHnylV5lCVtFs6wxmnn5fZJqAykVo
t4R8AesZRagg2xQFfeWOqsKiUuFs2Au9UjvyaI8ZV0IC0/Bj7vdH2liWEA==
-----END PUBLIC KEY-----`;
  const registrationPayload = {
    issuer: `load-test-issuer-${Math.random().toString(36).substr(2, 10)}`,
    publicKey,
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

  check(registrationRes, {
    'registration request handled': (r) => r.status !== undefined,
    'registration not 500': (r) => r.status !== 500,
  });

  sleep(0.5);
}

export function handleSummary(data) {
  return {
    'k6-results/stress-test-summary.json': JSON.stringify(data),
  };
}