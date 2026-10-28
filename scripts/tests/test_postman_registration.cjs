const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { webcrypto, createPublicKey, verify } = require('node:crypto');
const vm = require('node:vm');
const { test } = require('node:test');
const { resolve } = require('node:path');

const collection = JSON.parse(readFileSync(resolve(__dirname, '../../postman/status-list-server.postman_collection.json')));
const registration = collection.item.flatMap(folder => folder.item || [])
  .find(item => item.name === 'Register issuer credentials');
const scripts = {
  collectionPrerequest: collection.event.find(event => event.listen === 'prerequest').script.exec.join('\n'),
  test: registration.event.find(event => event.listen === 'test').script.exec.join('\n'),
};

// Only the Chai assertions used by the collection; failed pm.test assertions are
// recorded, as they are in Postman, without preventing later scripts from running.
function expect(value) {
  const chain = {
    a(type) { assert.equal(typeof value, type); return chain; },
    include(expected) { assert.ok(value.includes(expected)); return chain; },
    property(key) { assert.ok(Object.prototype.hasOwnProperty.call(value, key)); return chain; },
    equal(expected) { assert.equal(value, expected); return chain; },
    greaterThan(expected) { assert.ok(value > expected); return chain; },
    length(expected) { assert.equal(value.length, expected); return chain; },
  };
  for (const key of ['to', 'be', 'have', 'and']) chain[key] = chain;
  chain.not = new Proxy({
    equal(expected) { assert.notEqual(value, expected); return chain; },
    get empty() { assert.ok(value.length > 0); return chain; },
  }, { get(target, property, receiver) {
    if (Reflect.has(target, property)) return Reflect.get(target, property, receiver);
    throw new Error(`Unsupported Chai assertion in Postman harness: ${String(property)}`);
  } });
  return new Proxy(chain, { get(target, property, receiver) {
    if (Reflect.has(target, property)) return Reflect.get(target, property, receiver);
    throw new Error(`Unsupported Chai assertion in Postman harness: ${String(property)}`);
  } });
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
async function register(environment, server, { status, crypto = webcrypto, lookup, method = 'POST', requestName } = {}) {
  const failures = [];
  const collectionVariables = scope();
  const requestVariables = scope(new Map([['issuer_id', environment.get('issuer_id')]]));
  const pm = {
    environment: scope(environment), collectionVariables, variables: requestVariables, expect,
    variables: Object.assign(requestVariables, {
      replaceIn: text => text.replace('{{managementUrl}}', 'http://localhost:8001'),
    }),
    test(name, callback) { try { callback(); } catch (error) { failures.push({ name, error }); } },
    info: { requestName: requestName || (method === 'POST' ? 'Register issuer credentials' : method === 'PUT' ? 'Publish status list' : 'Update status list') },
    request: { method, url: { path: method === 'POST' ? ['api', 'v1', 'credentials'] : ['api', 'v1', 'status-lists', 'id', 'statuses'], toString: () => method === 'POST' ? 'http://localhost:8001/api/v1/credentials' : 'http://localhost:8001/api/v1/status-lists/id/statuses' }, body: { update(value) { this.raw = value; } }, headers: {
      signMarker: ['PUT', 'PATCH'].includes(method) && requestName !== 'Publish status list without auth' ? 'true' : undefined,
      get(key) { return key === 'X-Postman-Sign-With-Issuer' ? this.signMarker : undefined; },
      remove(key) { if (key === 'X-Postman-Sign-With-Issuer') this.signMarker = undefined; },
      upsert(header) { if (header.key === 'Authorization') this.authorization = header.value; },
    } },
    sendRequest(request, callback) {
      assert.equal(request.method, 'GET');
      assert.equal(request.url, 'http://localhost:8001/api/v1/credentials');
      if (lookup) return lookup(callback);
      const issuer = environment.get('issuer_id');
      const valid = authenticates(request.header.Authorization.slice(7), issuer, server);
      queueMicrotask(() => callback(null, { code: valid ? 200 : 401, json: () => valid ? { issuer } : { error: 'unauthorized' } }));
    },
  };
  // Separate script contexts model Postman's prerequest/response sandbox scopes.
  const globals = { pm, crypto, TextEncoder, Uint8Array, btoa, atob, setTimeout, console };
  await vm.runInNewContext(`(async function () { ${scripts.collectionPrerequest} })()`, globals);
  const issuer = environment.get('issuer_id');
  const code = status || (server.has(issuer) ? 409 : 202);
  if (code === 202) server.set(issuer, JSON.parse(environment.get('issuer_public_key')));
  pm.response = {
    code, headers: { get: () => 'application/json' },
    json: () => code === 202 ? { status: 'accepted' } : { error: 'registration failed' },
  };
  await vm.runInNewContext(`(async function () { ${scripts.test} })()`, globals);
  await new Promise(setImmediate);
  return { failures, collectionVariables, requestVariables, authorization: pm.request.headers.authorization, signMarker: pm.request.headers.signMarker };
}

test('first registration, repeated registration, and A -> B -> A retain valid keys', async () => {
  const environment = new Map([['issuer_id', 'A'], ['issuer_audience', 'management']]);
  const server = new Map();
  for (const issuer of ['A', 'A', 'B', 'A']) {
    environment.set('issuer_id', issuer);
    const result = await register(environment, server);
    assert.deepEqual(result.failures, []);
    assert.ok(authenticates(environment.get('token') || result.requestVariables.get('token'), issuer, server));
    const token = environment.get('token') || result.requestVariables.get('token');
    assert.equal(JSON.parse(Buffer.from(token.split('.')[1], 'base64url')).aud, 'management');
    const privateJwk = JSON.parse(environment.get('issuer_private_jwks'))[issuer];
    const publicJwk = JSON.parse(environment.get('issuer_public_key'));
    assert.deepEqual({ x: publicJwk.x, y: publicJwk.y, kid: publicJwk.kid }, { x: privateJwk.x, y: privateJwk.y, kid: issuer });
    assert.equal(result.collectionVariables.get('token'), undefined);
  }
  assert.deepEqual(Object.keys(JSON.parse(environment.get('issuer_private_jwks'))).sort(), ['A', 'B']);
});

test('collection signing refreshes protected write tokens and adds configured audience', async () => {
  const server = new Map();
  const environment = new Map([['issuer_id', 'A'], ['issuer_audience', 'management']]);
  await register(environment, server);
  const oldToken = environment.get('token');
  const result = await register(environment, server, { method: 'PUT' });
  const token = result.requestVariables.get('token');
  assert.notEqual(token, oldToken);
  assert.equal(JSON.parse(Buffer.from(token.split('.')[1], 'base64url')).aud, 'management');
  assert.equal(authenticates(token, 'A', server), true);
  assert.equal(result.authorization, `Bearer ${token}`);
  assert.equal(result.signMarker, undefined);
  assert.equal(result.failures.length, 0);
});

test('fresh environment conflict fails and removes stale tokens from both scopes', async () => {
  const server = new Map();
  await register(new Map([['issuer_id', 'A']]), server);
  const environment = new Map([['issuer_id', 'A']]);
  const result = await register(environment, server);
  assert.ok(result.failures.some(failure => /Restore the original private key/.test(failure.error.message)));
  assert.equal(environment.get('token'), undefined);
  assert.equal(result.collectionVariables.get('token'), undefined);
});

test('per-issuer key cache retains keys when switching away and back', async () => {
  const server = new Map();
  const environment = new Map([['issuer_id', 'A']]);
  await register(environment, server);
  environment.set('issuer_id', 'B');
  assert.deepEqual((await register(environment, server)).failures, []);
  environment.set('issuer_id', 'A');
  assert.deepEqual((await register(environment, server)).failures, []);
  assert.ok(authenticates((await register(environment, server)).requestVariables.get('token'), 'A', server));
});

test('Newman preconfigured token works without WebCrypto for 202 and 409', async () => {
  const server = new Map();
  const generated = new Map([['issuer_id', 'A']]);
  const generatedResult = await register(generated, server);
  generated.set('token', generatedResult.requestVariables.get('token'));
  const environment = new Map(['issuer_id', 'issuer_public_key', 'token'].map(key => [key, generated.get(key)]));
  const token = environment.get('token');
  for (const target of [new Map(), server]) {
    const result = await register(environment, target, { crypto: null });
    assert.deepEqual(result.failures, []);
    assert.equal(environment.get('token'), token);
  }
  environment.delete('issuer_private_jwks');
  const write = await register(environment, server, { crypto: null, method: 'PUT' });
  assert.deepEqual(write.failures, []);
  assert.equal(write.authorization, `Bearer ${token}`);
  const renamedRequest = await register(environment, server, { crypto: null, method: 'PUT', requestName: 'Renamed publish request' });
  assert.deepEqual(renamedRequest.failures, []);
  assert.equal(renamedRequest.authorization, `Bearer ${token}`);
  assert.equal(renamedRequest.signMarker, undefined);
  const unauthenticated = await register(environment, server, { crypto: null, method: 'PUT', requestName: 'Publish status list without auth' });
  assert.deepEqual(unauthenticated.failures, []);
  assert.equal(unauthenticated.authorization, undefined);
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
    assert.ok(result.failures.length >= 1);
    assert.equal(environment.get('token'), undefined);
    assert.equal(result.collectionVariables.get('token'), undefined);
  }
});


test('corrupt key cache and stale or mismatched preconfigured credentials fail clearly', async () => {
  const server = new Map();
  const source = new Map([['issuer_id', 'A']]);
  const registered = await register(source, server);
  source.set('token', registered.requestVariables.get('token'));
  const publicKey = source.get('issuer_public_key');
  const token = source.get('token');

  await assert.rejects(register(new Map([['issuer_id', 'A'], ['issuer_private_jwks', '{']]), server), /issuer_private_jwks is not valid JSON/);
  await assert.rejects(register(new Map([['issuer_id', 'B'], ['issuer_public_key', publicKey], ['token', token]]), server, { crypto: null }), /Preconfigured key is for A, not B/);

  const expiredClaims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url'));
  expiredClaims.exp = 1;
  const expiredToken = `${token.split('.')[0]}.${Buffer.from(JSON.stringify(expiredClaims)).toString('base64url')}.${token.split('.')[2]}`;
  await assert.rejects(register(new Map([['issuer_id', 'A'], ['issuer_public_key', publicKey], ['token', expiredToken]]), server, { crypto: null }), /expired or belongs to a different issuer/);
});

test('PATCH waits for the previous Last-Modified second even with the Newman token fallback', async () => {
  const server = new Map();
  const environment = new Map([['issuer_id', 'A']]);
  const generated = await register(environment, server);
  environment.set('token', generated.requestVariables.get('token'));
  environment.delete('issuer_private_jwks');
  environment.set('pre_update_last_modified', new Date(Math.floor(Date.now() / 1000) * 1000 + 1000).toUTCString());
  const started = Date.now();
  const result = await register(environment, server, { method: 'PATCH', crypto: null });
  assert.deepEqual(result.failures, []);
  assert.ok(Date.now() - started >= 900);
  assert.equal(result.authorization, `Bearer ${environment.get('token')}`);
});
