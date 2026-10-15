// Setup helper for the performance suites.
//
// Runs once before an Artillery test and does two things against the live
// server:
//   1. Registers the test issuer (from scripts/test-tokens.json) so the
//      authenticated flows never hit `issuer_not_found` — this used to be done
//      with an Artillery `before:` hook, but that hook does not execute
//      processor `function:` steps, so the registration silently never ran and
//      every authenticated request returned 401.
//   2. Publishes a set of seed status lists and writes their IDs to
//      scripts/seed-lists.json. The read scenarios (`selectPublishedListId`)
//      pick from these real IDs instead of random IDs that always 404.
//
// It is idempotent: a 409 from an already-registered issuer is treated as
// success, and re-publishing seed lists simply replaces the previous set.

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const scriptsDir = __dirname;
const seedFile = path.join(scriptsDir, 'seed-lists.json');
const DEFAULT_TARGET = process.env.TEST_TARGET || 'http://localhost:8000';
const SEED_LISTS = Number(process.env.SEED_LISTS || 50);

function parseTarget(target) {
  const url = new URL(target);
  return { host: url.hostname, port: url.port || '80', target };
}

function request(targetUrl, { method, path: pathname, headers = {}, body }) {
  const { host, port } = parseTarget(targetUrl);
  const payload = body !== undefined ? JSON.stringify(body) : undefined;
  return new Promise((resolve, reject) => {
    const req = http.request(
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
  return request(DEFAULT_TARGET, {
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
  const token = data.tokens[0];
  const created = [];
  for (let i = 0; i < SEED_LISTS; i++) {
    const listId = crypto.randomUUID();
    const { statusCode, body } = await request(DEFAULT_TARGET, {
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
