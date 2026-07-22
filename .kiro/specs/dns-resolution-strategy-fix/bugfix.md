# Bugfix Requirements Document

## Introduction

This bugfix addresses wasteful DNS resolution in `build_state` for deployments using the store provisioning strategy. Currently, the DNS provider is resolved and constructed unconditionally, before branching on the provisioning strategy. Store-strategy deployments—which read certificates from disk or secrets manager and never interact with ACME—have no need for DNS resolution, yet still pay for it and can fail if DNS configuration is missing or malformed.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN `provisioning_strategy` is set to "store" THEN the system resolves the DNS provider via `config.server.cert.dns.resolve()` before determining the strategy, wasting resources and potentially failing on malformed DNS config.

1.2 WHEN `provisioning_strategy` is "store" and DNS configuration is absent or invalid THEN the system fails to boot even though DNS is never used by the store strategy.

1.3 WHEN `provisioning_strategy` is "store" and DNS configuration is present THEN the system constructs a `Dns01Handler` via `build_dns_challenge_handler()` that is immediately discarded unused.

### Expected Behavior (Correct)

2.1 WHEN `provisioning_strategy` is "store" THEN the system SHALL skip DNS resolution entirely and proceed directly to building the store certificate strategy.

2.2 WHEN `provisioning_strategy` is "store" and DNS configuration is absent or malformed THEN the system SHALL boot successfully without validating or touching DNS configuration.

2.3 WHEN `provisioning_strategy` is "acme" THEN the system SHALL resolve the DNS provider and construct the challenge handler exactly as before (no behavior change on the ACME path).

### Unchanged Behavior (Regression Prevention)

3.1 WHEN `provisioning_strategy` is "acme" THEN the system SHALL CONTINUE TO resolve and validate DNS provider configuration before building the challenge handler.

3.2 WHEN `provisioning_strategy` is "acme" in development environment THEN the system SHALL CONTINUE TO warn when using the Pebble DNS provider.

3.3 WHEN `provisioning_strategy` is "acme" and DNS provider settings are missing THEN the system SHALL CONTINUE TO fail at boot with a descriptive error message.

3.4 WHEN `provisioning_strategy` is "store" with filesystem source THEN the system SHALL CONTINUE TO require `certificate_path` and `signing_key_path` configuration.

3.5 WHEN `provisioning_strategy` is "store" with secrets source THEN the system SHALL CONTINUE TO require `certificate_key` and `signing_key_key` configuration.
