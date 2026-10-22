const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { promisify } = require('node:util');
const { test } = require('node:test');
const jwt = require('jsonwebtoken');

const run = promisify(execFile);
const dependencies = path.dirname(path.dirname(require.resolve('jsonwebtoken/package.json')));

async function fixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'perf-registry-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  for (const name of ['token-generator.js', 'setup.js', 'processor.js']) {
    await fs.copyFile(path.join(__dirname, '..', name), path.join(directory, name));
  }
  const env = { ...process.env, NODE_PATH: dependencies, MANAGEMENT_AUDIENCE: 'tooling-test' };
  await run(process.execPath, [path.join(directory, 'token-generator.js')], { env });
  const data = JSON.parse(await fs.readFile(path.join(directory, 'test-tokens.json'), 'utf8'));
  const registry = JSON.parse(await fs.readFile(path.join(directory, 'issuers.yaml'), 'utf8'));
  return { directory, env, data, registry };
}

async function managementServer(t, data, metadataStatus = 200, metadata = null) {
  const calls = [];
  const server = http.createServer((req, res) => {
    calls.push({ method: req.method, url: req.url });
    // Exercise the signature and token contract on every management request.
    try {
      const claims = jwt.verify(req.headers.authorization?.replace(/^Bearer /, ''),
        crypto.createPublicKey({ key: data.publicKeyJwk, format: 'jwk' }),
        { algorithms: ['ES256'], audience: data.audience, issuer: data.issuerId });
      assert.ok(claims.exp - claims.iat <= 300);
      const header = jwt.decode(req.headers.authorization.slice(7), { complete: true }).header;
      assert.equal(header.kid, data.publicKeyJwk.kid);
      assert.equal(header.typ, 'statuslist-management+jwt');
    } catch {
      res.writeHead(401).end('{}');
      return;
    }
    req.resume();
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      if (req.method === 'GET' && req.url === '/api/v1/credentials') {
        res.writeHead(metadataStatus).end(JSON.stringify(metadata || {
          issuer: data.issuerId, aggregation_id: data.aggregationId,
        }));
      } else if (req.method === 'PUT' && /^\/api\/v1\/status-lists\/[^/]+\/statuses$/.test(req.url)) {
        res.writeHead(201).end('{}');
      } else {
        res.writeHead(405).end('{}');
      }
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { calls, url: `http://127.0.0.1:${server.address().port}` };
}

test('generator separates the public registry from private signing data', async t => {
  const { directory, data, registry } = await fixture(t);
  const entry = registry.issuers[0];
  assert.equal(entry.id, data.issuerId);
  assert.equal(entry.aggregation_id, data.aggregationId);
  assert.match(entry.aggregation_id, /^[0-9a-f-]{36}$/);
  assert.deepEqual(entry.keys[0].jwk, data.publicKeyJwk);
  const { crv, kty, x, y } = data.publicKeyJwk;
  const thumbprint = crypto.createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest('base64url');
  assert.equal(entry.keys[0].kid, thumbprint);
  const serialized = JSON.stringify(registry);
  assert.ok(!serialized.includes('PRIVATE KEY'));
  assert.ok(!Object.hasOwn(entry.keys[0].jwk, 'd'));
  assert.equal((await fs.stat(path.join(directory, 'test-tokens.json'))).mode & 0o777, 0o600);
  assert.ok(data.privateKey.includes('PRIVATE KEY'));
});

test('setup verifies a provisioned issuer before seeding and never self-registers', async t => {
  const { directory, env, data } = await fixture(t);
  // Setup must refresh expired tokens using the ephemeral private key.
  data.tokens = ['expired-token'];
  await fs.writeFile(path.join(directory, 'test-tokens.json'), JSON.stringify(data));
  const { calls, url } = await managementServer(t, data);
  await run(process.execPath, [path.join(directory, 'setup.js')], {
    env: { ...env, MANAGEMENT_TARGET: url, SEED_LISTS: '2' },
  });
  assert.deepEqual(calls.map(call => call.method), ['GET', 'PUT', 'PUT']);
  assert.equal(calls[0].url, '/api/v1/credentials');
  const seeds = JSON.parse(await fs.readFile(path.join(directory, 'seed-lists.json'), 'utf8'));
  assert.equal(seeds.length, 2);
  assert.equal(new Set(seeds).size, 2);
});

for (const status of [401, 200]) {
  test(`setup refuses ${status === 401 ? 'unprovisioned' : 'mismatched'} issuers before publishing`, async t => {
    const { directory, env, data } = await fixture(t);
    const { calls, url } = await managementServer(t, data, status, {
      issuer: 'another-issuer', aggregation_id: crypto.randomUUID(),
    });
    await assert.rejects(run(process.execPath, [path.join(directory, 'setup.js')], {
      env: { ...env, MANAGEMENT_TARGET: url, SEED_LISTS: '2' },
    }), error => {
      assert.match(error.stderr, /load.*before setup|load scripts\/issuers.yaml/i);
      return true;
    });
    assert.deepEqual(calls, [{ method: 'GET', url: '/api/v1/credentials' }]);
    await assert.rejects(fs.access(path.join(directory, 'seed-lists.json')));
  });
}

test('Artillery workers refresh expired tokens for the provisioned registry key', async t => {
  const { directory, data } = await fixture(t);
  const now = Math.floor(Date.now() / 1000);
  data.tokens = [jwt.sign({ iss: data.issuerId, aud: data.audience, iat: now - 360, exp: now - 60 },
    data.privateKey, { algorithm: 'ES256', header: {
      kid: data.publicKeyJwk.kid, typ: 'statuslist-management+jwt',
    } })];
  await fs.writeFile(path.join(directory, 'test-tokens.json'), JSON.stringify(data));
  const processor = require(path.join(directory, 'processor.js'));
  const context = { vars: {} };
  processor.loadTestData(context, {}, error => assert.ifError(error));
  processor.selectRandomToken(context, {}, error => assert.ifError(error));
  const claims = jwt.verify(context.vars.token,
    crypto.createPublicKey({ key: data.publicKeyJwk, format: 'jwk' }),
    { algorithms: ['ES256'], audience: data.audience, issuer: data.issuerId });
  assert.ok(claims.exp > now);
  assert.ok(claims.exp - claims.iat <= 300);
  const header = jwt.decode(context.vars.token, { complete: true }).header;
  assert.equal(header.kid, data.publicKeyJwk.kid);
  assert.equal(header.typ, 'statuslist-management+jwt');
});
