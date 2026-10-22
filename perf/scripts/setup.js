// Verify the operator-provisioned test issuer, then publish seed status lists.
// The public registry fixture generated alongside test-tokens.json must already
// be loaded by the server. Setup never provisions an issuer over HTTP.

const http = require('http');
const https = require('https');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const scriptsDir = __dirname;
const seedFile = path.join(scriptsDir, 'seed-lists.json');
// Authenticated issuer metadata and seed status-list publishes go to the
// management listener at :8001 by default, matching the MANAGEMENT_TARGET
// default the npm test:* scripts pass to Artillery. Override with
// MANAGEMENT_TARGET for a separate management host.
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

function managementToken(data) {
  if (!data.privateKey) return data.tokens[0];
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign({ iss: data.issuerId, aud: data.audience, iat: now, exp: now + 300 }, data.privateKey, {
    algorithm: 'ES256', header: { kid: data.publicKeyJwk.kid, typ: 'statuslist-management+jwt' }
  });
}

async function verifyIssuer(data, token) {
  const { statusCode, body } = await request(MANAGEMENT_TARGET, {
    method: 'GET',
    path: '/api/v1/credentials',
    headers: { Authorization: `Bearer ${token}` }
  });
  if (statusCode !== 200) {
    throw new Error(`Issuer verification failed (${statusCode}): load scripts/issuers.yaml in the server registry and configure its audience before setup. ${body}`);
  }
  const metadata = JSON.parse(body);
  if (metadata.issuer !== data.issuerId || metadata.aggregation_id !== data.aggregationId) {
    throw new Error('Issuer metadata does not match scripts/issuers.yaml; regenerate the fixture and load it before setup.');
  }
  console.log(`✓ Provisioned issuer verified: ${data.issuerId}`);
}

async function seedStatusLists(token) {
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
  const token = managementToken(data);
  await verifyIssuer(data, token);
  await seedStatusLists(token);
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
