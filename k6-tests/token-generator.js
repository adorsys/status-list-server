const jwt = require('jsonwebtoken');
const fs = require('fs');
const crypto = require('crypto');

const privateKey = fs.readFileSync('ec-private-key.pem', 'utf8');
const publicKey = fs.readFileSync('ec-public-key.pem', 'utf8');

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
      exp: now + 7200  // 2 hours expiration
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
  privateKey,  // Save for reference, not used in tests
  tokens,
  generatedAt: new Date().toISOString()
};

fs.writeFileSync('test-tokens.json', JSON.stringify(testData, null, 2));

console.log(`✓ Generated ${tokens.length} valid tokens`);
console.log('✓ Saved to test-tokens.json');
console.log('\nPublic Key:');
console.log(publicKey);
console.log('\nYou can now run: k6 run auth-load-test.js');