const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const scriptsDir = __dirname;

// The server caps exp - iat at 300 s by default, so workers re-sign expired tokens.
const TOKEN_LIFETIME_SECS = 300;
const audience = process.env.MANAGEMENT_AUDIENCE || 'status-list-server-management';
const registryPath = process.env.APP_MANAGEMENT_AUTH__ISSUERS_FILE || path.join(scriptsDir, 'issuer-registry.json');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'P-256',
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });

const issuerId = `test-issuer-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
jwk.alg = 'ES256';
const thumbprintInput = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
const keyId = crypto.createHash('sha256').update(thumbprintInput).digest('base64url');
jwk.kid = keyId;

console.log('Generating tokens...');
console.log('Issuer ID:', issuerId);
console.log('Public Key JWK:', jwk);

const tokens = [];
const now = Math.floor(Date.now() / 1000);

for (let i = 0; i < 100; i++) {
  const token = jwt.sign(
    {
      iss: issuerId,
      aud: audience,
      iat: now,
      exp: now + TOKEN_LIFETIME_SECS
    },
    privateKey,
    {
      algorithm: 'ES256',
      header: {
        kid: keyId,
        typ: 'statuslist-management+jwt'
      }
    }
  );
  tokens.push(token);
}

const testData = {
  issuerId,
  publicKeyJwk: jwk,
  privateKey,
  audience,
  tokens,
  generatedAt: new Date().toISOString()
};

// Holds this run's private signing key, so it's owner-only (0600).
const testDataPath = path.join(scriptsDir, 'test-tokens.json');
const serialized = JSON.stringify(testData, null, 2);
const tmp = `${testDataPath}.tmp-${process.pid}`;
fs.writeFileSync(tmp, serialized, { mode: 0o600 });
fs.renameSync(tmp, testDataPath);

const registry = {
  version: 1,
  issuers: [{
    id: issuerId,
    aggregation_id: crypto.randomUUID(),
    tier: 'standard',
    keys: [{ kid: keyId, alg: 'ES256', jwk }]
  }],
  admins: []
};
const registryTmp = `${registryPath}.tmp-${process.pid}`;
fs.writeFileSync(registryTmp, JSON.stringify(registry, null, 2), { mode: 0o600 });
fs.renameSync(registryTmp, registryPath);

console.log(`✓ Generated ${tokens.length} valid tokens`);
console.log(`✓ Saved to scripts/test-tokens.json`);
console.log(`✓ Wrote issuer registry to ${registryPath}`);
