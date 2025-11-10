const jwt = require('jsonwebtoken');
const fs = require('fs');

const privateKey = fs.readFileSync('ec-private-key.pem', 'utf8');

const token = jwt.sign(
  {
    iss: 'test-issuer3',
    exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60),
    iat: Math.floor(Date.now() / 1000)
  },
  privateKey,
  {
    algorithm: 'ES256',
    header: {
      kid: 'test-issuer3'
    }
  }
);

console.log('JWT Token:');
console.log(token);