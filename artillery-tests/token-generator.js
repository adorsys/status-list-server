const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');

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

// Save keys
fs.writeFileSync('ec-private-key.pem', privateKey);
fs.writeFileSync('ec-public-key.jwk', JSON.stringify(jwk, null, 2));

const issuerId = `test-issuer-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

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
      iat: now,
      exp: now + (365 * 24 * 60 * 60)
    },
    privateKey,
    {
      algorithm: 'ES256',
      header: {
        kid: issuerId,
        typ: 'JWT'
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
  tokens,
  generatedAt: new Date().toISOString()
};

fs.writeFileSync('test-tokens.json', JSON.stringify(testData, null, 2));

console.log(`✓ Generated ${tokens.length} valid tokens`);
console.log('✓ Saved to test-tokens.json');
console.log('\nPublic Key:');
console.log(JSON.stringify(jwk, null, 2));