# DNS Resolution Strategy Fix - Bugfix Design

## Overview

This design document addresses a resource waste and boot failure issue in the `build_state` function. Currently, DNS provider resolution occurs unconditionally before branching on the certificate provisioning strategy. Store-strategy deployments—which read certificates from disk or AWS Secrets Manager without any ACME interaction—needlessly resolve DNS configuration and can fail at boot if DNS settings are absent or malformed, even though DNS is irrelevant to their operation.

The fix introduces early conditional branching based on `uses_acme_strategy`, ensuring DNS resolution and challenge handler construction only occur when the ACME strategy is selected. This preserves all existing ACME behavior while eliminating unnecessary work and potential boot failures for store-strategy deployments.

## Glossary

- **Bug_Condition (C)**: The condition where `provisioning_strategy` is "store" yet DNS resolution still executes, wasting resources and potentially causing boot failure
- **Property (P)**: The desired behavior where store-strategy deployments skip DNS resolution entirely and boot successfully regardless of DNS configuration
- **Preservation**: All existing ACME-strategy behavior must remain unchanged, including DNS resolution, validation, and challenge handler construction
- **`build_state`**: The function in `src/utils/state.rs` that initializes the application state, including certificate manager setup
- **`uses_acme_strategy`**: A boolean derived from `config.server.cert.provisioning_strategy.eq_ignore_ascii_case("acme")` that determines the certificate management path
- **`store_certificate_strategy`**: A helper function that builds the `StoreProvisioningStrategy` from configuration for non-ACME deployments
- **`DnsConfig::resolve`**: The method that resolves and validates DNS provider settings, returning a `ResolvedDnsProvider`
- **`build_dns_challenge_handler`**: The async function that constructs a `Dns01Handler` for the resolved DNS provider

## Bug Details

### Bug Condition

The bug manifests when the `build_state` function resolves the DNS provider and attempts to build a DNS challenge handler BEFORE checking whether the ACME strategy is in use. The current code structure performs DNS resolution unconditionally, then branches on `uses_acme_strategy`. This means store-strategy deployments always pay for DNS resolution work and can fail if DNS configuration is missing or malformed.

**Formal Specification:**
```
FUNCTION isBugCondition(config)
  INPUT: config of type AppConfig
  OUTPUT: boolean
  
  RETURN config.server.cert.provisioning_strategy.eq_ignore_ascii_case("store")
         AND dnsResolutionExecuted(config.server.cert.dns)
END FUNCTION

FUNCTION dnsResolutionExecuted(dns_config)
  INPUT: dns_config of type DnsConfig
  OUTPUT: boolean
  
  // DNS resolution was attempted (either succeeded or failed with validation error)
  RETURN dns_config.resolve() WAS CALLED
END FUNCTION
```

### Examples

- **Example 1: Store strategy with missing DNS credentials**
  - Config: `provisioning_strategy = "store"`, DNS provider set to `cloudflare` but `cloudflare.api_token` is absent
  - Expected: Boot succeeds, DNS configuration is ignored
  - Actual: Boot fails with "DNS provider Cloudflare selected but the server.cert.dns.cloudflare settings are missing"

- **Example 2: Store strategy with malformed DNS config**
  - Config: `provisioning_strategy = "store"`, DNS provider set to `acmedns` with incomplete account configuration
  - Expected: Boot succeeds, DNS configuration is ignored
  - Actual: Boot fails with "Incomplete ACME-DNS default account: username, password and subdomain must be set together"

- **Example 3: Store strategy with valid DNS config (wasteful success)**
  - Config: `provisioning_strategy = "store"`, DNS provider set to `route53` with valid ambient AWS credentials
  - Expected: Boot succeeds without DNS resolution
  - Actual: Boot succeeds after resolving DNS provider and constructing unused Dns01Handler (wasted I/O and initialization time)

- **Edge case: Store strategy with no DNS config section**
  - Config: `provisioning_strategy = "store"`, no `dns` configuration block present
  - Expected: Boot succeeds
  - Actual: Boot succeeds (this case accidentally works because `DnsConfig::default().resolve()` defaults to Route53/Pebble based on environment)

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- ACME strategy deployments must continue to resolve DNS provider configuration at boot
- ACME strategy deployments must continue to validate DNS provider settings and fail fast on misconfiguration
- ACME strategy in development environment must continue to warn when using Pebble DNS provider
- Store strategy with `filesystem` source must continue to require `certificate_path` and `signing_key_path`
- Store strategy with `secrets` source must continue to require `certificate_key` and `signing_key_key`
- Store strategy with `storage` source must continue to require `certificate_key` and `signing_key_key`

**Scope:**
All inputs where `provisioning_strategy` is "acme" should be completely unaffected by this fix. This includes:
- DNS provider resolution and validation
- DNS challenge handler construction
- Production environment warnings for Pebble provider
- Development environment HTTP client configuration with Pebble root certificate
- ACME directory URL and email configuration

## Hypothesized Root Cause

Based on the bug description and code analysis, the root cause is:

1. **Premature DNS Resolution**: The `build_state` function resolves DNS configuration and builds the challenge handler BEFORE checking `uses_acme_strategy`. The current code flow is:
   ```rust
   let dns_provider = config.server.cert.dns.resolve(&app_env)?;
   let challenge_handler = build_dns_challenge_handler(...).await?;
   
   cert_manager_builder = if uses_acme_strategy {
       // Uses the already-resolved dns_provider and challenge_handler
   } else {
       // Discards them, uses store strategy
   }
   ```

2. **Lack of Early Branching**: The conditional check for `uses_acme_strategy` happens too late in the function flow. DNS resolution and challenge handler construction are performed unconditionally, even though they are only needed for the ACME branch.

3. **Order of Operations**: The code reads `app_env` early (needed for DNS provider defaulting), then resolves DNS provider, then finally branches on strategy. The correct order should be:
   1. Determine `uses_acme_strategy` first
   2. Only if ACME: resolve DNS provider and build challenge handler
   3. Branch to appropriate strategy builder

4. **No Lazy Evaluation**: Rust's eager evaluation means the DNS resolution happens regardless of whether it's used. The fix must restructure the control flow to avoid this work entirely for store-strategy deployments.

## Correctness Properties

Property 1: Bug Condition - Store Strategy Skips DNS Resolution

_For any_ configuration where the provisioning strategy is "store" (isBugCondition returns true), the fixed `build_state` function SHALL skip DNS resolution entirely, not call `DnsConfig::resolve()`, not construct a `Dns01Handler`, and boot successfully regardless of DNS configuration state.

**Validates: Requirements 2.1, 2.2**

Property 2: Preservation - ACME Strategy Behavior Unchanged

_For any_ configuration where the provisioning strategy is "acme" (isBugCondition returns false), the fixed `build_state` function SHALL produce exactly the same behavior as the original function, preserving DNS resolution, validation, challenge handler construction, and all error handling for DNS misconfiguration.

**Validates: Requirements 3.1, 3.2, 3.3**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `src/utils/state.rs`

**Function**: `build_state`

**Specific Changes**:

1. **Reorder conditional logic**: Move the `uses_acme_strategy` determination before any DNS-related operations
   - Current: DNS resolution happens before the `if uses_acme_strategy` branch
   - Fixed: Determine `uses_acme_strategy` early, only perform DNS operations inside the ACME branch

2. **Encapsulate DNS resolution in ACME branch**: Move the DNS provider resolution and challenge handler construction into the ACME conditional block
   - Current: `let dns_provider = config.server.cert.dns.resolve(&app_env)?;` executes unconditionally
   - Fixed: This line only executes when `uses_acme_strategy` is true

3. **Preserve app_env for development mode check**: Keep the early `app_env` read for the development HTTP client override, which applies to both strategies
   - The Pebble root certificate override is needed for both ACME and store strategies in development
   - Keep `let app_env = std::env::var("APP_ENV")...` before the conditional

4. **Maintain production warning for Pebble**: Ensure the Pebble-in-production warning remains in the ACME branch where DNS is resolved
   - Move the warning logic into the ACME branch alongside DNS resolution

5. **Preserve store_certificate_strategy call location**: The `store_certificate_strategy(config)?` call should remain in the else branch, unchanged in behavior

**Code Structure After Fix**:
```rust
pub async fn build_state(config: &AppConfig) -> EyeResult<AppState> {
    // ... database, AWS config, Redis setup (unchanged) ...
    
    let cert_strategy = store_certificate_strategy(config)?;
    let uses_acme_strategy = config
        .server
        .cert
        .provisioning_strategy
        .eq_ignore_ascii_case("acme");
    
    let app_env = std::env::var("APP_ENV").unwrap_or(ENV_DEVELOPMENT.to_string());
    
    let mut cert_manager_builder = CertManager::builder()
        .domains(cert_domains)
        .email(&config.server.cert.email)
        // ... other builder calls ...
    
    cert_manager_builder = if uses_acme_strategy {
        // DNS resolution ONLY happens here, inside the ACME branch
        let dns_provider = config
            .server
            .cert
            .dns
            .resolve(&app_env)
            .wrap_err("Invalid DNS provider configuration")?;
        if dns_provider.kind() == DnsProviderKind::Pebble && app_env == ENV_PRODUCTION {
            warn!(...);
        }
        let challenge_handler = build_dns_challenge_handler(...).await?;
        cert_manager_builder
            .challenge_handler(challenge_handler)
            .acme_strategy()
    } else if let Some(cert_strategy) = cert_strategy {
        cert_manager_builder.store_strategy(cert_strategy)
    } else {
        return Err(eyre!("store certificate provisioning strategy is missing after validation"));
    };
    
    // ... rest of function unchanged ...
}
```

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write tests that configure store-strategy deployments with various DNS misconfigurations and assert that boot fails on unfixed code but succeeds on fixed code. Run these tests on the UNFIXED code to observe failures.

**Test Cases**:
1. **Store Strategy with Missing Cloudflare Credentials**: Set `provisioning_strategy = "store"`, `dns.provider = "cloudflare"`, omit `dns.cloudflare.api_token` — expect boot failure on unfixed code (will fail on unfixed code)
2. **Store Strategy with Incomplete ACME-DNS Account**: Set `provisioning_strategy = "store"`, `dns.provider = "acmedns"` with partial credentials — expect boot failure on unfixed code (will fail on unfixed code)
3. **Store Strategy with No DNS Section**: Set `provisioning_strategy = "store"`, no DNS configuration — expect boot success (may pass on unfixed code due to default fallback)
4. **Store Strategy with Malformed Azure DNS Config**: Set `provisioning_strategy = "store"`, `dns.provider = "azure"` with empty required fields — expect boot failure on unfixed code (will fail on unfixed code)

**Expected Counterexamples**:
- Boot fails with DNS validation errors for store-strategy deployments
- Error messages reference DNS configuration requirements that shouldn't apply to store strategy
- Possible causes: premature DNS resolution, lack of conditional branching

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL config WHERE isBugCondition(config) DO
  result := build_state_fixed(config)
  ASSERT result.is_ok()
  ASSERT dns_resolution_was_NOT_called()
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL config WHERE NOT isBugCondition(config) DO
  result_original := build_state_original(config)
  result_fixed := build_state_fixed(config)
  ASSERT result_original = result_fixed
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all ACME-strategy inputs

**Test Plan**: Observe behavior on UNFIXED code first for ACME-strategy deployments, then write property-based tests capturing that behavior.

**Test Cases**:
1. **ACME Strategy DNS Resolution**: Verify ACME strategy still resolves DNS provider and fails on misconfiguration
2. **ACME Strategy Pebble Warning**: Verify production warning for Pebble provider still appears
3. **ACME Strategy Challenge Handler**: Verify challenge handler is constructed correctly for each provider type
4. **Store Strategy Certificate Path Requirements**: Verify filesystem store still requires certificate and key paths

### Unit Tests

- Test store strategy with various DNS misconfigurations boots successfully
- Test ACME strategy with missing DNS configuration fails with descriptive error
- Test that `uses_acme_strategy` determination is correct for "acme", "store", "ACME", "STORE" (case-insensitive)
- Test that store strategy filesystem requirements are still enforced

### Property-Based Tests

- Generate random DNS configurations (valid and invalid) and verify store-strategy boots regardless
- Generate random ACME-strategy configurations and verify DNS resolution behavior is preserved
- Test that all store strategy source variants (filesystem, storage, secrets) work without DNS configuration

### Integration Tests

- Test full boot sequence with store strategy and missing DNS credentials
- Test full boot sequence with ACME strategy and valid DNS configuration
- Test that certificate manager is correctly configured for each strategy type
- Test that development mode HTTP client override works for both strategies
