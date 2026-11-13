const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const { resolve } = require('node:path');

const collection = JSON.parse(readFileSync(resolve(__dirname, '../../postman/status-list-server.postman_collection.json')));
const environment = JSON.parse(readFileSync(resolve(__dirname, '../../postman/status-list-server.postman_environment.json')));

function allRequests(items) {
  return items.flatMap(item => [
    ...(item.request ? [item] : []),
    ...allRequests(item.item || []),
  ]);
}

const requests = allRequests(collection.item);
const byName = name => requests.find(item => item.name === name);

test('collection matches the provisioned-issuer management API', () => {
  const verification = byName('Verify issuer credentials');
  assert.ok(verification);
  assert.equal(verification.request.method, 'GET');
  assert.equal(verification.request.url.raw, '{{managementUrl}}/api/v1/credentials');
  assert.equal(byName('Register issuer credentials'), undefined);
  assert.equal(collection.auth.type, 'bearer');
  assert.equal(collection.auth.bearer[0].value, '{{token}}');
  for (const name of ['Verify issuer credentials', 'Publish status list', 'Update status list']) {
    const request = byName(name).request;
    assert.equal(request.auth, undefined, `${name} must inherit the collection bearer token`);
    assert.ok(!request.header.some(header => header.key === 'Authorization' || header.key === 'X-Postman-Sign-With-Issuer'));
  }
});

test('public reads and negative authentication request do not use the issuer token', () => {
  for (const item of requests) {
    if (item.request.url.raw.startsWith('{{baseUrl}}') || item.name === 'Publish status list without auth') {
      assert.equal(item.request.auth?.type, 'noauth', item.name);
    }
  }
});

test('checked-in environment contains no credential values', () => {
  for (const key of ['token', 'adminToken']) {
    const variable = environment.values.find(value => value.key === key);
    assert.equal(variable.type, 'secret');
    assert.equal(variable.value, '');
  }
});
