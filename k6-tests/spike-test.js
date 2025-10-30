const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

export default function () {
  // Test the system's ability to handle sudden traffic spikes

  // Test 1: Health check - should remain responsive even during spikes
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, {
    'health check status is 200': (r) => r.status === 200,
    'health check response time < 100ms': (r) => r.timings.duration < 100,
  });

  sleep(0.3);

  // Test 2: Welcome endpoint
  const welcomeRes = http.get(`${BASE_URL}/`);
  check(welcomeRes, {
    'welcome status is 200': (r) => r.status === 200,
  });

  sleep(0.3);

  // Test 3: Random status list retrieval attempts (simulating real-world traffic)
  const listIds = [
    'existing-list-1',
    'existing-list-2',
    'non-existent-list',
    `random-${Math.random().toString(36).substr(2, 9)}`
  ];

  const randomListId = listIds[Math.floor(Math.random() * listIds.length)];
  const statusListRes = http.get(`${BASE_URL}/statuslists/${randomListId}`);

  check(statusListRes, {
    'status list request completed': (r) => r.status !== undefined,
    'status list response time reasonable': (r) => r.timings.duration < 1000,
  });

  sleep(0.3);

  // Test 4: Credential registration during spike (database writes under pressure)
  if (Math.random() < 0.3) { // 30% chance to reduce database load
    const registrationPayload = {
      issuer: `spike-issuer-${Math.random().toString(36).substr(2, 9)}`,
      public_key: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8uV8H8K2jvAY7TUJEPxCu1c1qfVF
5z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ9z6dQ==
-----END PUBLIC KEY-----`,
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
      'registration handled during spike': (r) => r.status !== undefined,
    });
  }

  sleep(0.5);
}

export function handleSummary(data) {
  return {
    'stdout': JSON.stringify(data, null, 2),
    'k6-results/spike-test-summary.json': JSON.stringify(data),
  };
}