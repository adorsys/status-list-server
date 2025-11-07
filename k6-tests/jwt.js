const jwt = require('jsonwebtoken');
const fs = require('fs');

const privateKey = fs.readFileSync('ec-private-key.pem', 'utf8');

const token = jwt.sign(
  {
    iss: 'test-issuer2',
    exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24),
    iat: Math.floor(Date.now() / 1000)
  },
  privateKey,
  {
    algorithm: 'ES256',
    header: {
      kid: 'test-issuer2'
    }
  }
);

console.log('JWT Token:');
console.log(token);