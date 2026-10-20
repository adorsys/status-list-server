const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const scriptsDir = __dirname;

// The server rejects management JWTs whose lifetime (`exp - iat`) exceeds
// `management_auth.max_token_lifetime_secs` (default 300s). Workers refresh
// expired tokens from this run's private key instead of extending the lifetime.
const TOKEN_LIFETIME_SECS = 300;
const audience = process.env.MANAGEMENT_AUDIENCE || 'status-list-server-management';

// Generate EC key pair
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

// Convert public key to JWK format
const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });

const issuerId = `test-issuer-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
jwk.kid = issuerId;
jwk.alg = 'ES256';

console.log('Generating tokens...');
console.log('Issuer ID:', issuerId);
console.log('Public Key JWK:', jwk);

// Generate tokens
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

// Save tokens and issuer info
const testData = {
  issuerId,
  publicKeyJwk: jwk,
  privateKey,
  audience,
  tokens,
  generatedAt: new Date().toISOString()
};

// Write only test-tokens.json. All Artillery scenarios read the issuer, public
// key and signed JWTs from this one file, so the separate ec-private-key.pem and
// ec-public-key.jwk files would be unread dead weight. The data is sensitive
// (it contains the ephemeral private signing key), so it is written once with
// mode 0600 (owner read/write only).
const testDataPath = path.join(scriptsDir, 'test-tokens.json');
const serialized = JSON.stringify(testData, null, 2);
const tmp = `${testDataPath}.tmp-${process.pid}`;
fs.writeFileSync(tmp, serialized, { mode: 0o600 });
fs.renameSync(tmp, testDataPath);

console.log(`✓ Generated ${tokens.length} valid tokens`);
console.log(`✓ Saved to scripts/test-tokens.json`);
