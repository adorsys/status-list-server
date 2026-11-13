#!/usr/bin/env node
// Create a disposable issuer key shared by the legacy row and candidate registry.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const [mode, directory] = process.argv.slice(2);
if (!['prepare', 'token'].includes(mode) || !directory) {
  process.stderr.write('usage: generate-direct-upgrade-fixture.js <prepare|token> <directory>\n');
  process.exit(2);
}

const keyPath = path.join(directory, 'private-key.pem');
const kid = 'upgrade-fixture-key';
const audience = 'https://upgrade.example.invalid/api/v1';
const writePrivate = (name, value) => fs.writeFileSync(path.join(directory, name), value, { mode: 0o600 });

if (mode === 'prepare') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = { ...publicKey.export({ format: 'jwk' }), alg: 'ES256', kid };
  writePrivate('public-jwk.json', JSON.stringify(jwk));
  writePrivate('issuers.yaml', JSON.stringify({
    version: 1,
    issuers: [{
      id: 'upgrade-fixture',
      aggregation_id: '11111111-1111-4111-8111-111111111111',
      tier: 'standard',
      keys: [{ kid, alg: 'ES256', jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } }],
    }],
    admins: [],
  }));
  writePrivate('private-key.pem', privateKey.export({ format: 'pem', type: 'pkcs8' }));
} else {
  const now = Math.floor(Date.now() / 1000);
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${encode({ alg: 'ES256', typ: 'statuslist-management+jwt', kid })}.${encode({ iss: 'upgrade-fixture', aud: audience, iat: now, exp: now + 240 })}`;
  const signature = crypto.sign('sha256', Buffer.from(input), {
    key: fs.readFileSync(keyPath), dsaEncoding: 'ieee-p1363',
  });
  writePrivate('token', `${input}.${signature.toString('base64url')}`);
}
