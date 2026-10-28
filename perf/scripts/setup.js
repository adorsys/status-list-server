// Runs once before an Artillery test: registers the test issuer and publishes seed lists.
// Not an Artillery before: hook, which never runs processor function: steps (every request got 401).
// Idempotent: a 409 for the issuer counts as success.

const http = require('http');
const https = require('https');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const scriptsDir = __dirname;
const seedFile = path.join(scriptsDir, 'seed-lists.json');
// Writes go to the management listener; keep this default in step with the npm test:* scripts.
const MANAGEMENT_TARGET = process.env.MANAGEMENT_TARGET || 'http://localhost:8001';
const SEED_LISTS = Number(process.env.SEED_LISTS || 50);

function parseTarget(target) {
  const url = new URL(target);
  const isHttps = url.protocol === 'https:';
  return { host: url.hostname, port: url.port || (isHttps ? '443' : '80'), isHttps };
}

function request(targetUrl, { method, path: pathname, headers = {}, body }) {
  const { host, port, isHttps } = parseTarget(targetUrl);
  const payload = body !== undefined ? JSON.stringify(body) : undefined;
  return new Promise((resolve, reject) => {
    const client = isHttps ? https : http;
    const req = client.request(
      {
        host,
        port,
        path: pathname,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(payload !== undefined ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...headers
        }
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
      }
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

function loadTestData() {
  const file = path.join(scriptsDir, 'test-tokens.json');
  if (!fs.existsSync(file)) {
    throw new Error(
      'scripts/test-tokens.json not found. Run `npm run generate-tokens` first.'
    );
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function registerIssuer(data) {
  return request(MANAGEMENT_TARGET, {
    method: 'POST',
    path: '/api/v1/credentials',
    body: { issuer: data.issuerId, public_key: data.publicKeyJwk }
  }).then(({ statusCode, body }) => {
    if (statusCode === 202 || statusCode === 409) {
      console.log(`✓ Issuer registered (${statusCode}): ${data.issuerId}`);
    } else {
      throw new Error(`Registration failed (${statusCode}): ${body}`);
    }
  });
}

async function seedStatusLists(data) {
  let token = data.tokens[0];
  const now = Math.floor(Date.now() / 1000);
  if (data.privateKey) {
    token = jwt.sign({ iss: data.issuerId, aud: data.audience, iat: now, exp: now + 300 }, data.privateKey, {
      algorithm: 'ES256', header: { kid: data.publicKeyJwk.kid, typ: 'statuslist-management+jwt' }
    });
  }
  const created = [];
  for (let i = 0; i < SEED_LISTS; i++) {
    const listId = crypto.randomUUID();
    const { statusCode, body } = await request(MANAGEMENT_TARGET, {
      method: 'PUT',
      path: `/api/v1/status-lists/${listId}/statuses`,
      headers: { Authorization: `Bearer ${token}` },
      body: { statuses: [{ index: Math.floor(Math.random() * 100) + 1, status: 0 }] }
    });
    if (statusCode === 201) {
      created.push(listId);
    } else {
      throw new Error(`Seed publish failed (${statusCode}): ${body}`);
    }
  }
  fs.writeFileSync(seedFile, JSON.stringify(created, null, 2), { mode: 0o600 });
  console.log(`✓ Published ${created.length} seed status lists -> scripts/seed-lists.json`);
}

async function main() {
  const data = loadTestData();
  await registerIssuer(data);
  await seedStatusLists(data);
}

main().then(
  () => {
    console.log('Setup complete.');
  },
  (err) => {
    console.error(`Setup failed: ${err.message}`);
    process.exit(1);
  }
);
