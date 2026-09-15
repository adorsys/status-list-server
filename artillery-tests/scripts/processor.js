const crypto = require('crypto');

// Load test tokens
let testTokens = null;
try {
  testTokens = require('./test-tokens.json');
  console.log(`✓ Loaded ${testTokens.tokens.length} test tokens for issuer: ${testTokens.issuerId}`);
} catch (error) {
  console.error('⚠️  Could not load test-tokens.json. Run token-generator.js first!');
  console.error('Error:', error.message);
}

// Public key for credential registration - read from the same file as the
// tokens so the key can never disagree with the signed JWTs.
let TEST_PUBLIC_KEY_JWK = testTokens ? testTokens.publicKeyJwk : null;

// Status list IDs created during this run. Reads pick from this pool so they
// query lists that actually exist instead of random IDs that always 404.
//
// Shared across Artillery worker processes via the file written by scripts/setup.js
// (each worker loads it on module init). Successful publishes during the run are
// appended to the per-process pool as well, so newly created lists become
// readable too.
const fs = require('fs');
const path = require('path');
const publishedListIds = loadSeedListIds();

function loadSeedListIds() {
  const seedFile = path.join(__dirname, 'seed-lists.json');
  try {
    const ids = JSON.parse(fs.readFileSync(seedFile, 'utf8'));
    if (Array.isArray(ids) && ids.length > 0) {
      console.log(`✓ Loaded ${ids.length} seeded status lists for reads`);
      return ids;
    }
  } catch (error) {
    // No seed file (e.g. apply/seed run or tests invoked without setup.js).
  }
  return [];
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
 * Select a published status list ID recorded earlier in this run. scripts/setup.js
 * seeds the pool (via scripts/seed-lists.json) with real lists, and every
 * successful publish adds to it, so reads hit lists that exist instead of random
 * IDs that always 404. Falls back to a fresh UUID only when no list has been
 * published yet (unlikely after setup has run).
 */
function selectPublishedListId(context, events, done) {
  if (publishedListIds.length > 0) {
    const index = Math.floor(Math.random() * publishedListIds.length);
    context.vars.listId = publishedListIds[index];
  } else {
    context.vars.listId = crypto.randomUUID();
  }
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
    // Record the list for later reads.
    if (context.vars.listId) {
      publishedListIds.push(context.vars.listId);
    }
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
  selectPublishedListId,
  shouldRegister,
  handleStatusListResponse,
  handleCredentialResponse,
  handlePublishResponse,
  handleUpdateResponse,
  handleUnauthorizedResponse,
  afterScenario
};
