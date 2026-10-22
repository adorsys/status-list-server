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
// RFC 7638 canonical public members, in lexicographic order.
const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
jwk.kid = crypto.createHash('sha256').update(canonical).digest('base64url');
const aggregationId = crypto.randomUUID();
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
        kid: jwk.kid,
        typ: 'statuslist-management+jwt'
      }
    }
  );
  tokens.push(token);
}

// Save tokens and issuer info
const testData = {
  issuerId,
  aggregationId,
  publicKeyJwk: jwk,
  privateKey,
  audience,
  tokens,
  generatedAt: new Date().toISOString()
};

// Write private test data separately from the public registry fixture.
// Artillery reads the issuer and signing material from this file. Write it
// atomically with owner-only permissions because it holds the private key.
const testDataPath = path.join(scriptsDir, 'test-tokens.json');
const serialized = JSON.stringify(testData, null, 2);
const tmp = `${testDataPath}.tmp-${process.pid}`;
fs.writeFileSync(tmp, serialized, { mode: 0o600 });
fs.renameSync(tmp, testDataPath);

console.log(`✓ Generated ${tokens.length} valid tokens`);
console.log(`✓ Saved to scripts/test-tokens.json`);

// Provision this PUBLIC fixture before setup or Artillery runs. Generation does
// not contact a server or grant trust remotely.
const registryPath = path.join(scriptsDir, 'issuers.yaml');
const registry = {
  version: 1,
  issuers: [{
    id: issuerId,
    aggregation_id: aggregationId,
    keys: [{ kid: jwk.kid, alg: jwk.alg, jwk }]
  }],
  admins: []
};
const registryTmp = `${registryPath}.tmp-${process.pid}`;
fs.writeFileSync(registryTmp, JSON.stringify(registry, null, 2) + '\n', { mode: 0o644 });
fs.renameSync(registryTmp, registryPath);
console.log('✓ Public registry fixture saved to scripts/issuers.yaml; configure the server to load it before setup.');
