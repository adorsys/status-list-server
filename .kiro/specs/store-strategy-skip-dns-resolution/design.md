# Store Strategy Skip DNS Resolution Bugfix Design

## Overview

This design addresses a bug where the `build_state` function unconditionally resolves DNS provider configuration and constructs a challenge handler before determining the certificate provisioning strategy. When `provisioning_strategy = "store"` is configured, the system unnecessarily performs DNS resolution and builds a challenge handler that is never used, causing startup overhead and potential configuration errors when DNS settings are absent or malformed but irrelevant.

The fix involves reordering the code in `build_state` to determine the provisioning strategy before DNS resolution, and skipping DNS-related operations entirely when the store strategy is selected.

## Glossary

- **Bug_Condition (C)**: The condition that triggers the bug - when `provisioning_strategy = "store"` is configured but DNS resolution is still attempted before strategy determination.
- **Property (P)**: The desired behavior - the system skips DNS resolution when store strategy is configured, and performs DNS resolution only when ACME strategy is configured.
- **Preservation**: Existing ACME provisioning behavior must remain unchanged; the DNS resolution and challenge handler construction must work exactly as before for ACME configurations.
- **build_state**: The function in `src/utils/state.rs` (lines 60-240) that initializes application state, including certificate manager setup.
- **provisioning_strategy**: A configuration option (`server.cert.provisioning_strategy`) that determines how certificates are obtained - either "acme" (via ACME protocol with DNS challenges) or "store" (from filesystem/storage/secrets).
- **dns.resolve()**: The function that validates and resolves DNS provider configuration, returning a `ResolvedDnsProvider` used to construct the challenge handler.
- **Dns01Handler**: The DNS-01 challenge handler constructed from the resolved DNS provider, used only for ACME provisioning.

## Bug Details

### Bug Condition

The bug manifests when `build_state` is called with `provisioning_strategy = "store"`. The function resolves DNS provider configuration (lines 108-120) and constructs a challenge handler (lines 122-124) before checking which provisioning strategy to use (lines 136-140). This causes unnecessary work and potential startup failures when DNS configuration is absent or invalid.

**Formal Specification:**
```
FUNCTION isBugCondition(config)
  INPUT: config of type AppConfig
  OUTPUT: boolean
  
  RETURN config.server.cert.provisioning_strategy.eq_ignore_ascii_case("store")
         AND dnsResolutionAttempted(config) = true
         AND challengeHandlerConstructed(config) = true
END FUNCTION
```

### Examples

- **Example 1**: A deployment with `provisioning_strategy = "store"` and no DNS configuration section. Expected: successful startup. Actual: fails with "Invalid DNS provider configuration" error.
- **Example 2**: A deployment with `provisioning_strategy = "store"` and malformed DNS configuration (e.g., Cloudflare selected but no API token). Expected: successful startup ignoring DNS config. Actual: fails with DNS validation error.
- **Example 3**: A deployment with `provisioning_strategy = "store"` and valid DNS configuration. Expected: successful startup without DNS resolution. Actual: successful startup but with unnecessary DNS resolution and challenge handler construction.
- **Example 4** (Edge case): A deployment with `provisioning_strategy = "STORE"` (uppercase). Expected: treated as store strategy, skip DNS. Actual: same bug as lowercase "store".

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- When `provisioning_strategy = "acme"` is configured, DNS provider resolution must continue to work exactly as before
- When `provisioning_strategy = "acme"` with invalid DNS settings, the same validation errors must be produced
- The `ResolvedDnsProvider` type and `resolve()` function must remain unchanged
- The challenge handler construction for ACME must use the same code path
- The `StoreProvisioningStrategy` implementation must remain unchanged
- The `AppState` structure produced by `build_state` must remain unchanged
- Certificate loading from filesystem/storage/secrets must remain unchanged

**Scope:**
All configurations with `provisioning_strategy = "acme"` should be completely unaffected by this fix. This includes:
- All DNS provider types (Route53, Cloudflare, Gcloud, Azure, Acmedns, Pebble)
- Production and development environment behaviors
- Pebble-specific warnings about production use
- ACME-DNS account validation at startup

## Hypothesized Root Cause

Based on the bug description and code analysis, the root cause is clear:

1. **Incorrect Operation Ordering**: The `build_state` function determines the provisioning strategy (lines 136-140) after DNS resolution (lines 108-120) and challenge handler construction (lines 122-124). The strategy determination should happen first to decide whether DNS resolution is needed.

2. **No Early Strategy Check**: The code lacks an early check for the provisioning strategy that would allow skipping unnecessary DNS-related operations for the store strategy.

3. **Tight Coupling of Initialization Steps**: The database, Redis, AWS, and storage initialization steps are interleaved with DNS resolution, making it appear that DNS resolution is always required when it is only needed for ACME.

## Correctness Properties

Property 1: Bug Condition - Store Strategy Skips DNS Resolution

_For any_ configuration where `provisioning_strategy = "store"` (case-insensitive), the fixed `build_state` function SHALL skip DNS provider resolution and challenge handler construction entirely, proceeding directly to initialize the certificate manager with a store-based provisioning strategy.

**Validates: Requirements 2.1, 2.2, 2.4, 2.5**

Property 2: Preservation - ACME Strategy Behavior Unchanged

_For any_ configuration where `provisioning_strategy = "acme"` (case-insensitive), the fixed `build_state` function SHALL produce exactly the same behavior as the original code, resolving the DNS provider, constructing the challenge handler, and initializing the certificate manager with an ACME-based provisioning strategy.

**Validates: Requirements 2.3, 3.1, 3.2, 3.3**

Property 3: Preservation - AppState Structure Unchanged

_For any_ configuration with either "acme" or "store" provisioning strategy, the fixed `build_state` function SHALL produce an `AppState` structure identical to the original implementation, with a properly configured `cert_manager` field.

**Validates: Requirements 3.4, 3.5**

## Fix Implementation

### Changes Required

**File**: `src/utils/state.rs`

**Function**: `build_state`

**Specific Changes**:

1. **Extract Strategy Determination Early**: Move the provisioning strategy determination to immediately after Redis connection is established (around line 108, before DNS resolution).
   - Extract `uses_acme_strategy` calculation (currently at lines 136-138) to earlier in the function
   - Extract `cert_strategy` calculation (currently at line 136) to earlier in the function

2. **Conditional DNS Resolution**: Wrap DNS resolution and challenge handler construction in a conditional block that only executes when `uses_acme_strategy` is true.
   - Move lines 108-124 (DNS resolution and challenge handler construction) inside the conditional
   - Declare `challenge_handler` as `Option<Dns01Handler>` or use a different approach to handle the conditional construction

3. **Conditional Builder Configuration**: Update the cert_manager builder configuration to conditionally add the challenge handler.
   - The existing conditional at lines 148-161 already handles this correctly
   - Ensure the `challenge_handler` variable is properly scoped for the ACME branch

4. **Maintain Code Readability**: Ensure the refactored code maintains clarity and doesn't introduce deeply nested conditionals.
   - Consider extracting DNS resolution into a helper function if it improves readability
   - Keep the existing helper function `build_dns_challenge_handler` unchanged

5. **Preserve Warning Logic**: The Pebble warning (lines 117-121) should only execute when ACME strategy is used and Pebble is selected in production.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write tests that simulate `build_state` with store strategy and missing/invalid DNS configuration. Run these tests on the UNFIXED code to observe failures.

**Test Cases**:
1. **Store Strategy No DNS Test**: Configure `provisioning_strategy = "store"` with no DNS section, verify startup fails on unfixed code (will fail on unfixed code).
2. **Store Strategy Invalid DNS Test**: Configure `provisioning_strategy = "store"` with invalid DNS configuration (e.g., Cloudflare without API token), verify startup fails on unfixed code (will fail on unfixed code).
3. **Store Strategy Valid DNS Test**: Configure `provisioning_strategy = "store"` with valid DNS configuration, verify challenge handler is constructed unnecessarily on unfixed code.
4. **Case Insensitivity Test**: Configure `provisioning_strategy = "STORE"` (uppercase), verify same behavior as lowercase.

**Expected Counterexamples**:
- Store strategy with no DNS configuration causes "Invalid DNS provider configuration" error
- Store strategy with invalid DNS configuration causes DNS validation errors
- Possible causes: operation ordering, lack of early strategy check

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL config WHERE isBugCondition(config) DO
  result := build_state_fixed(config)
  ASSERT result.isSuccess()
  ASSERT result.certManager.strategy.name() = "store"
  ASSERT noDnsResolutionAttempted()
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold (ACME strategy), the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL config WHERE NOT isBugCondition(config) DO
  ASSERT build_state_original(config) = build_state_fixed(config)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across different DNS provider configurations
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that ACME behavior is unchanged for all provider types

**Test Plan**: Observe behavior on UNFIXED code first for ACME configurations with various DNS providers, then write property-based tests capturing that behavior.

**Test Cases**:
1. **ACME Route53 Preservation**: Verify ACME with Route53 DNS continues to work correctly
2. **ACME Cloudflare Preservation**: Verify ACME with Cloudflare DNS continues to work correctly
3. **ACME Pebble Preservation**: Verify ACME with Pebble DNS continues to work correctly (including warning in production)
4. **ACME Invalid DNS Preservation**: Verify ACME with invalid DNS still produces the same validation errors

### Unit Tests

- Test `build_state` with store strategy and no DNS configuration succeeds
- Test `build_state` with store strategy and invalid DNS configuration succeeds
- Test `build_state` with acme strategy and no DNS configuration fails with expected error
- Test `build_state` with acme strategy and valid DNS configuration succeeds
- Test case-insensitivity of provisioning strategy values

### Property-Based Tests

- Generate random configurations with store strategy and various DNS states (missing, invalid, valid), verify startup succeeds
- Generate random configurations with acme strategy and various valid DNS providers, verify behavior is unchanged
- Generate random configurations with acme strategy and invalid DNS settings, verify same error behavior
- Test that AppState structure is identical for equivalent configurations before and after fix

### Integration Tests

- Test full startup flow with store strategy loading certificates from filesystem
- Test full startup flow with store strategy loading certificates from secrets storage
- Test full startup flow with acme strategy and each DNS provider type
- Test certificate renewal works correctly with both strategies after the fix
