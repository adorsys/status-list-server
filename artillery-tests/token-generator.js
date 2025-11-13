const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');

// Generate EC key pair (not RSA)
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

// Save keys for reference
fs.writeFileSync('ec-private-key.pem', privateKey);
fs.writeFileSync('ec-public-key.pem', publicKey);

const issuerId = `test-issuer-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

console.log('Generating tokens...');
console.log('Issuer ID:', issuerId);

// Generate multiple tokens with different expiration times
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
  publicKey,
  privateKey,
  tokens,
  generatedAt: new Date().toISOString()
};

fs.writeFileSync('test-tokens.json', JSON.stringify(testData, null, 2));

console.log(`✓ Generated ${tokens.length} valid tokens`);
console.log('✓ Saved to test-tokens.json');
console.log('\nPublic Key:');
console.log(publicKey);
console.log('\nYou can now run: k6 run auth-load-test.js');