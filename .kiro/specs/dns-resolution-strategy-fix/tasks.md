# Implementation Tasks

## Task 1: Write Bug Condition Exploration Tests
- [ ] 1.1 Create test for store-strategy with missing Cloudflare credentials
- [ ] 1.2 Create test for store-strategy with incomplete ACME-DNS account
- [ ] 1.3 Create test for store-strategy with no DNS section
- [ ] 1.4 Create test for store-strategy with malformed Azure DNS config
- [ ] 1.5 Run tests on UNFIXED code to verify they demonstrate the bug (should FAIL)

## Task 2: Implement the Fix in build_state
- [ ] 2.1 Move `uses_acme_strategy` determination before DNS resolution
- [ ] 2.2 Wrap DNS resolution and challenge handler construction in ACME conditional
- [ ] 2.3 Move Pebble-in-production warning into ACME branch
- [ ] 2.4 Preserve `app_env` early read for development HTTP client override
- [ ] 2.5 Ensure store_certificate_strategy call location remains unchanged

## Task 3: Write Fix Checking Tests
- [ ] 3.1 Write test: store-strategy with absent DNS config boots successfully
- [ ] 3.2 Write test: store-strategy with malformed DNS config boots successfully
- [ ] 3.3 Write test: store-strategy with no DNS section boots successfully
- [ ] 3.4 Run tests on FIXED code to verify they pass

## Task 4: Write Preservation Checking Tests
- [ ] 4.1 Write test: ACME strategy still resolves DNS provider
- [ ] 4.2 Write test: ACME strategy still fails on DNS misconfiguration
- [ ] 4.3 Write test: ACME strategy Pebble warning in production preserved
- [ ] 4.4 Write test: Store strategy filesystem requirements still enforced
- [ ] 4.5 Run tests on FIXED code to verify ACME behavior unchanged

## Task 5: Verify Acceptance Criteria
- [ ] 5.1 Verify: Store-strategy with no DNS section boots successfully
- [ ] 5.2 Verify: Store-strategy with malformed DNS section boots successfully
- [ ] 5.3 Verify: ACME strategy resolves and constructs DNS provider as before
- [ ] 5.4 Verify: Test boots build_state under store strategy with absent/invalid DNS config and asserts success
