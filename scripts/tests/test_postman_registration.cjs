const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { webcrypto, createPublicKey, verify } = require('node:crypto');
const vm = require('node:vm');
const { test } = require('node:test');
const { resolve } = require('node:path');

const collection = JSON.parse(readFileSync(resolve(__dirname, '../../postman/status-list-server.postman_collection.json')));
const registration = collection.item.flatMap(folder => folder.item || [])
  .find(item => item.name === 'Register issuer credentials');
const scripts = Object.fromEntries(registration.event.map(event => [event.listen, event.script.exec.join('\n')]));

// Only the Chai assertions used by the collection; failed pm.test assertions are
// recorded, as they are in Postman, without preventing later scripts from running.
function expect(value) {
  const chain = {
    a(type) { assert.equal(typeof value, type); return chain; },
    include(expected) { assert.ok(value.includes(expected)); return chain; },
    property(key) { assert.ok(Object.prototype.hasOwnProperty.call(value, key)); return chain; },
  };
  for (const key of ['to', 'be', 'have', 'and']) chain[key] = chain;
  chain.not = { get empty() { assert.ok(value.length > 0); return chain; } };
  return chain;
}
function scope(values = new Map()) {
  return { get: key => values.get(key), set: (key, value) => values.set(key, value), unset: key => values.delete(key) };
}
function authenticates(token, issuer, server) {
  if (!token || !server.has(issuer)) return false;
  const [header, payload, signature] = token.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url')).iss === issuer && verify(
    'sha256', Buffer.from(`${header}.${payload}`),
    { key: createPublicKey({ key: server.get(issuer), format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
    Buffer.from(signature, 'base64url'),
  );
}
async function register(environment, server, { status, crypto = webcrypto, lookup } = {}) {
  const failures = [];
  const collectionVariables = scope(new Map([['token', 'stale-collection-token']]));
  const pm = {
    environment: scope(environment), collectionVariables, expect,
    variables: {
      get: key => environment.get(key),
      replaceIn: text => text.replace('{{baseUrl}}', 'http://localhost:8000'),
    },
    test(name, callback) { try { callback(); } catch (error) { failures.push({ name, error }); } },
    sendRequest(request, callback) {
      assert.equal(request.method, 'GET');
      assert.equal(request.url, 'http://localhost:8000/api/v1/credentials');
      if (lookup) return lookup(callback);
      const issuer = environment.get('issuer_id');
      const valid = authenticates(request.header.Authorization.slice(7), issuer, server);
      callback(null, { code: valid ? 200 : 401, json: () => valid ? { issuer } : { error: 'unauthorized' } });
    },
  };
  // Separate script contexts model Postman's prerequest/response sandbox scopes.
  const globals = { pm, crypto, TextEncoder, Uint8Array, btoa, console };
  await vm.runInNewContext(scripts.prerequest, globals);
  const issuer = environment.get('issuer_id');
  const code = status || (server.has(issuer) ? 409 : 202);
  if (code === 202) server.set(issuer, JSON.parse(environment.get('issuer_public_key')));
  pm.response = {
    code, headers: { get: () => 'application/json' },
    json: () => code === 202 ? { status: 'accepted' } : { error: 'registration failed' },
  };
  await vm.runInNewContext(scripts.test, globals);
  return { failures, collectionVariables };
}

test('first registration, repeated registration, and A -> B -> A retain valid keys', async () => {
  const environment = new Map([['issuer_id', 'A']]);
  const server = new Map();
  for (const issuer of ['A', 'A', 'B', 'A']) {
    environment.set('issuer_id', issuer);
    const result = await register(environment, server);
    assert.deepEqual(result.failures, []);
    assert.ok(authenticates(environment.get('token'), issuer, server));
    assert.equal(result.collectionVariables.get('token'), environment.get('token'));
  }
  assert.deepEqual(Object.keys(JSON.parse(environment.get('issuer_private_jwks'))).sort(), ['A', 'B']);
});

test('fresh environment conflict fails and removes stale tokens from both scopes', async () => {
  const server = new Map();
  await register(new Map([['issuer_id', 'A']]), server);
  const environment = new Map([['issuer_id', 'A']]);
  const result = await register(environment, server);
  assert.equal(result.failures.length, 1);
  assert.match(result.failures[0].error.message, /Restore its original private key/);
  assert.equal(environment.get('token'), undefined);
  assert.equal(result.collectionVariables.get('token'), undefined);
});

test('legacy active key is retained when switching away and back', async () => {
  const server = new Map();
  const environment = new Map([['issuer_id', 'A']]);
  await register(environment, server);
  environment.delete('issuer_private_jwks');
  environment.set('issuer_id', 'B');
  assert.deepEqual((await register(environment, server)).failures, []);
  environment.set('issuer_id', 'A');
  assert.deepEqual((await register(environment, server)).failures, []);
  assert.ok(authenticates(environment.get('token'), 'A', server));
});

test('Newman preconfigured token works without WebCrypto for 202 and 409', async () => {
  const server = new Map();
  const generated = new Map([['issuer_id', 'A']]);
  await register(generated, server);
  const environment = new Map(['issuer_id', 'issuer_public_key', 'token'].map(key => [key, generated.get(key)]));
  const token = environment.get('token');
  for (const target of [new Map(), server]) {
    const result = await register(environment, target, { crypto: null });
    assert.deepEqual(result.failures, []);
    assert.equal(environment.get('token'), token);
  }
});

test('failed registration clears tokens and records a failed readiness test', async () => {
  const environment = new Map([['issuer_id', 'A']]);
  const result = await register(environment, new Map(), { status: 500 });
  assert.ok(result.failures.some(failure => /Issuer registration failed/.test(failure.error.message)));
  assert.equal(environment.get('token'), undefined);
  assert.equal(result.collectionVariables.get('token'), undefined);
});

test('credential lookup failures clear tokens and cannot become silent success', async () => {
  const server = new Map();
  const environment = new Map([['issuer_id', 'A']]);
  await register(environment, server);
  for (const lookup of [
    callback => callback(new Error('network error')),
    callback => callback(null, { code: 200, json: () => ({ issuer: 'other-issuer' }) }),
    callback => callback(null, { code: 200, json() { throw new Error('invalid JSON'); } }),
  ]) {
    const result = await register(environment, server, { lookup });
    assert.equal(result.failures.length, 1);
    assert.equal(environment.get('token'), undefined);
    assert.equal(result.collectionVariables.get('token'), undefined);
  }
});
