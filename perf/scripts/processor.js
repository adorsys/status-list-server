const crypto = require('crypto');
const jwt = require('jsonwebtoken');

let testTokens = null;
try {
  testTokens = require('./test-tokens.json');
  console.log(`✓ Loaded ${testTokens.tokens.length} test tokens for issuer: ${testTokens.issuerId}`);
} catch (error) {
  console.error('⚠️  Could not load test-tokens.json. Run token-generator.js first!');
  console.error('Error:', error.message);
}

// Seeded by scripts/setup.js so reads hit real lists instead of 404ing; publishes add to it.
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
    // No seed file: setup.js didn't run.
  }
  return [];
}

let successCount = 0;
let errorCount = 0;

function loadTestData(context, events, done) {
  if (!testTokens) {
    return done(new Error('Test tokens not loaded. Run token-generator.js first!'));
  }

  context.vars.issuerId = testTokens.issuerId;
  context.vars.publicKeyJwk = testTokens.publicKeyJwk;
  context.vars.allTokens = testTokens.tokens;

  return done();
}

function selectRandomToken(context, events, done) {
  if (!context.vars.allTokens || context.vars.allTokens.length === 0) {
    console.error('No test tokens available in context!');
    return done(new Error('Test tokens not loaded'));
  }

  const randomIndex = Math.floor(Math.random() * context.vars.allTokens.length);
  let token = context.vars.allTokens[randomIndex];
  const now = Math.floor(Date.now() / 1000);
  const claims = jwt.decode(token);
  if (!claims || claims.exp <= now + 30) {
    if (!testTokens.privateKey) {
      return done(new Error('Token expired; regenerate test tokens with the current generator'));
    }
    token = jwt.sign({ iss: testTokens.issuerId, aud: testTokens.audience, iat: now, exp: now + 300 }, testTokens.privateKey, {
      algorithm: 'ES256', header: { kid: testTokens.publicKeyJwk.kid, typ: 'statuslist-management+jwt' }
    });
    context.vars.allTokens[randomIndex] = token;
  }
  context.vars.token = token;

  return done();
}

function generateUUID(context, events, done) {
  context.vars.listId = crypto.randomUUID();
  return done();
}

function selectPublishedListId(context, events, done) {
  if (publishedListIds.length > 0) {
    const index = Math.floor(Math.random() * publishedListIds.length);
    context.vars.listId = publishedListIds[index];
  } else {
    context.vars.listId = crypto.randomUUID();
  }
  return done();
}

function handleStatusListResponse(requestParams, response, context, ee, next) {
  if (response.statusCode === 200) {
    successCount++;
  } else if (response.statusCode !== 404) {
    errorCount++;
    console.error(`Error: Status list ${requestParams.url} returned ${response.statusCode}`);
  }
  return next();
}

function handlePublishResponse(requestParams, response, context, ee, next) {
  if (response.statusCode === 201) {
    successCount++;
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
  if (response.statusCode === 401) {
    successCount++;
  } else {
    errorCount++;
    console.error(`Error: Expected 401 but got ${response.statusCode}`);
  }
  return next();
}

function afterScenario(context, ee, next) {
  if (Math.random() < 0.01) {
    console.log(`Stats: ${successCount} successes, ${errorCount} errors`);
  }
  return next();
}

module.exports = {
  loadTestData,
  selectRandomToken,
  generateUUID,
  selectPublishedListId,
  handleStatusListResponse,
  handlePublishResponse,
  handleUpdateResponse,
  handleUnauthorizedResponse,
  afterScenario
};
