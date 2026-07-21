# Bugfix Requirements Document

## Introduction

The `build_state` function in `src/utils/state.rs` unconditionally resolves and constructs a DNS provider before determining the certificate provisioning strategy. Deployments using `provisioning_strategy = "store"` — which reads certificates from disk or secrets manager without contacting ACME — pay the cost of DNS resolution and challenge handler construction for a handler that is never used. This causes unnecessary startup overhead and potential configuration errors when DNS settings are absent or malformed but irrelevant to the store strategy.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN `build_state` is called with `provisioning_strategy = "store"` THEN the system resolves DNS provider configuration unconditionally (lines 108-120) before checking the provisioning strategy.

1.2 WHEN `build_state` is called with `provisioning_strategy = "store"` AND no DNS section is configured THEN the system fails with "Invalid DNS provider configuration" error even though DNS is not needed.

1.3 WHEN `build_state` is called with `provisioning_strategy = "store"` AND the DNS section contains malformed/invalid configuration THEN the system fails validation even though DNS is not needed.

1.4 WHEN `build_state` is called with `provisioning_strategy = "store"` THEN the system constructs a challenge handler (line 122-124) that is subsequently discarded unused.

### Expected Behavior (Correct)

2.1 WHEN `build_state` is called with `provisioning_strategy = "store"` THEN the system SHALL determine the provisioning strategy before attempting any DNS resolution.

2.2 WHEN `provisioning_strategy = "store"` is configured THEN the system SHALL skip DNS provider resolution and challenge handler construction entirely.

2.3 WHEN `provisioning_strategy = "acme"` is configured THEN the system SHALL resolve DNS and construct the challenge handler exactly as before (no behavior change).

2.4 WHEN `build_state` is called with `provisioning_strategy = "store"` AND no DNS section is configured THEN the system SHALL boot successfully without error.

2.5 WHEN `build_state` is called with `provisioning_strategy = "store"` AND the DNS section contains malformed configuration THEN the system SHALL boot successfully without error (DNS is not consulted).

### Unchanged Behavior (Regression Prevention)

3.1 WHEN `provisioning_strategy = "acme"` is configured THEN the system SHALL CONTINUE TO resolve DNS provider and construct the challenge handler before the ACME flow.

3.2 WHEN `provisioning_strategy = "acme"` is configured with invalid DNS settings THEN the system SHALL CONTINUE TO fail with appropriate validation errors.

3.3 WHEN the ACME provisioning strategy is used THEN the system SHALL CONTINUE TO use the same resolve() function and ResolvedDnsProvider types without modification.

3.4 WHEN the store provisioning strategy is used THEN the system SHALL CONTINUE TO load certificates from the configured source (filesystem, storage, or secrets) without any change to certificate loading logic.

3.5 WHEN `build_state` completes with either strategy THEN the system SHALL CONTINUE TO produce the same AppState structure with cert_manager properly configured.
