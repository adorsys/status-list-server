const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const scriptsDir = __dirname;

// The server caps exp - iat at 300 s by default, so workers re-sign expired tokens.
const TOKEN_LIFETIME_SECS = 300;
const audience = process.env.MANAGEMENT_AUDIENCE || 'status-list-server-management';

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
jwk.kid = issuerId;
jwk.alg = 'ES256';

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
        kid: issuerId,
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

console.log(`✓ Generated ${tokens.length} valid tokens`);
console.log(`✓ Saved to scripts/test-tokens.json`);
