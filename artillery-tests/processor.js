const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// Load test tokens
let testTokens = null;
try {
  testTokens = require('./test-tokens.json');
  console.log(`✓ Loaded ${testTokens.tokens.length} test tokens for issuer: ${testTokens.issuerId}`);
} catch (error) {
  console.error('⚠️  Could not load test-tokens.json. Run token-generator.js first!');
  console.error('Error:', error.message);
}

// Public key for credential registration
let TEST_PUBLIC_KEY_JWK = null;
try {
  const jwkPath = path.resolve(__dirname, 'ec-public-key.jwk');
  TEST_PUBLIC_KEY_JWK = JSON.parse(fs.readFileSync(jwkPath, 'utf8'));
} catch (error) {
  console.error('⚠️ Could not load ec-public-key.jwk. Make sure it exists!');
  console.error('Error:', error.message);
}

// Counters for debugging
let successCount = 0;
let errorCount = 0;

/**
 * Load test data (tokens, issuer, public key) into context
 */
function loadTestData(context, events, done) {
  if (!testTokens) {
    return done(new Error('Test tokens not loaded. Run token-generator.js first!'));
  }

  // Make tokens available to the scenario
  context.vars.issuerId = testTokens.issuerId;
  context.vars.publicKeyJwk = testTokens.publicKeyJwk;
  context.vars.allTokens = testTokens.tokens;

  return done();
}

/**
 * Generate a random issuer payload for credential registration
 */
function generateIssuerPayload(context, events, done) {
  const timestamp = Date.now();
  const randomStr = Math.random().toString(36).substring(2, 12);

  context.vars.issuer = `load-test-issuer-${timestamp}-${randomStr}`;
  context.vars.publicKeyJwk = TEST_PUBLIC_KEY_JWK;

  return done();
}

/**
 * Select a random JWT token from pre-generated tokens
 */
function selectRandomToken(context, events, done) {
  if (!context.vars.allTokens || context.vars.allTokens.length === 0) {
    console.error('No test tokens available in context!');
    return done(new Error('Test tokens not loaded'));
  }

  const randomIndex = Math.floor(Math.random() * context.vars.allTokens.length);
  context.vars.token = context.vars.allTokens[randomIndex];

  return done();
}

/**
 * Generate a UUID v4
 */
function generateUUID(context, events, done) {
  context.vars.listId = crypto.randomUUID();
  return done();
}

/**
 * Generate a random list ID
 */
function generateRandomListId(context, events, done) {
  const randomStr = Math.random().toString(36).substring(2, 11);
  context.vars.listId = `random-${randomStr}`;
  return done();
}

/**
 * Select a random status list ID (some exist, some don't)
 */
function selectRandomListId(context, events, done) {
  const listIds = [
    'existing-list-1',
    'existing-list-2',
    'non-existent-list',
    `random-${Math.random().toString(36).substring(2, 11)}`
  ];

  const randomIndex = Math.floor(Math.random() * listIds.length);
  context.vars.listId = listIds[randomIndex];

  return done();
}

/**
 * Determine if credential registration should happen (30% chance)
 */
function shouldRegister(context, events, done) {
  context.vars.shouldRegister = Math.random() < 0.3;
  return done();
}

/**
 * After response handlers - for custom metrics and debugging
 */
function handleStatusListResponse(requestParams, response, context, ee, next) {
  // 404 is expected for non-existent lists
  if (response.statusCode === 200) {
    successCount++;
  } else if (response.statusCode !== 404) {
    errorCount++;
    console.error(`Error: Status list ${requestParams.url} returned ${response.statusCode}`);
  }
  return next();
}

function handleCredentialResponse(requestParams, response, context, ee, next) {
  // 409 Conflict is acceptable (duplicate issuer)
  if (response.statusCode === 202 || response.statusCode === 409) {
    successCount++;
  } else {
    errorCount++;
    console.error(`Error: Credential registration returned ${response.statusCode}`);
    console.error(`Body: ${response.body}`);
  }
  return next();
}

function handlePublishResponse(requestParams, response, context, ee, next) {
  if (response.statusCode === 201) {
    successCount++;
  } else {
    errorCount++;
    console.error(`Error: Publish failed with ${response.statusCode}`);
    console.error(`Body: ${response.body}`);
  }
  return next();
}

function handleUpdateResponse(requestParams, response, context, ee, next) {
  if (response.statusCode === 200) {
    successCount++;
  } else {
    errorCount++;
    console.error(`Error: Update failed with ${response.statusCode}`);
    console.error(`Body: ${response.body}`);
  }
  return next();
}

function handleUnauthorizedResponse(requestParams, response, context, ee, next) {
  // 401 is expected and correct
  if (response.statusCode === 401) {
    successCount++;
  } else {
    errorCount++;
    console.error(`Error: Expected 401 but got ${response.statusCode}`);
  }
  return next();
}

/**
 * After scenario hook - log summary stats
 */
function afterScenario(context, ee, next) {
  if (Math.random() < 0.01) {  // Log every ~100th scenario
    console.log(`Stats: ${successCount} successes, ${errorCount} errors`);
  }
  return next();
}

module.exports = {
  loadTestData,
  generateIssuerPayload,
  selectRandomToken,
  generateUUID,
  generateRandomListId,
  selectRandomListId,
  shouldRegister,
  handleStatusListResponse,
  handleCredentialResponse,
  handlePublishResponse,
  handleUpdateResponse,
  handleUnauthorizedResponse,
  afterScenario
};