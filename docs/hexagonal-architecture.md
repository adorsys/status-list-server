# Hexagonal architecture

The service follows ports-and-adapters boundaries for new work:

```text
Axum handlers (inbound adapters)
              |
       application use cases
              |
        domain values/entities
              |
          outbound ports
              |
Postgres | cache | ACME/certificates | secret store | DNS | metrics
```

`src/domain` contains status-list and issuer values and only depends on
serialization support. `src/application` implements the inbound use cases
(`PublishStatusList`, `UpdateStatuses`, and `GetStatusListToken`) in terms of
traits in `src/ports`. It must not import Axum, SeaORM, Redis, or AWS SDKs.

Concrete integrations belong in `src/adapters`. The current default SQL
implementation is `adapters::postgres::PostgresStatusListRepository`; the
memory adapters are used to unit-test use cases without services. The
composition root (`utils::state::build_state`) injects adapters into `AppState`.
Existing legacy state fields remain only as a migration seam for handlers not
yet moved to a use case (certificate provisioning and credential
authentication); new code must depend on ports instead.

Adapter feature selection belongs at the composition root. This makes a
memory-only composition possible without altering domain or application code.
