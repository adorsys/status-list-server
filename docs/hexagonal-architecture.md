# Hexagonal architecture

The service follows ports-and-adapters boundaries for new work:

```mermaid
flowchart TB
    subgraph Inbound["Inbound Adapters"]
        Axum[Axum HTTP Handlers]
    end
    
    subgraph Application["Application Layer"]
        UC[Use Cases<br/>PublishStatusList<br/>UpdateStatuses<br/>GetStatusListToken]
    end
    
    subgraph Domain["Domain Layer"]
        Entities[Entities & Value Objects<br/>StatusList, StatusEntry<br/>Issuer, Credential]
    end
    
    subgraph Ports["Outbound Ports"]
        PortTraits[Trait Definitions<br/>StatusListRepository<br/>CredentialRepository<br/>StatusListCache<br/>CertificateProvider<br/>SecretStore<br/>DnsProvider<br/>MetricsCollector]
    end
    
    subgraph Outbound["Outbound Adapters"]
        Postgres[(Postgres)]
        Cache[(Cache)]
        ACME[ACME/Certificates]
        Secrets[Secret Store]
        DNS[(DNS)]
        Metrics[Metrics]
    end

    Axum --> UC
    UC --> Entities
    Entities --> PortTraits
    PortTraits --> Postgres
    PortTraits --> Cache
    PortTraits --> ACME
    PortTraits --> Secrets
    PortTraits --> DNS
    PortTraits --> Metrics
```

`src/domain` contains status-list and issuer values plus the status-list
bitstring creation/update invariants. It only depends on serialization and
pure encoding/compression helpers. `src/application` implements the inbound
use cases (`PublishStatusList`, `UpdateStatuses`, and `GetStatusListToken`) in
terms of traits in `src/ports`. It must not import Axum, SeaORM, Redis, AWS
SDKs, or other infrastructure crates.

Concrete integrations belong in `src/adapters`. The current default SQL
implementation is `adapters::postgres::PostgresStatusListRepository`; the
cache implementation is `adapters::cache::MokaStatusListCache`; certificate,
secret-store, DNS, metrics, and memory implementations also live under
`src/adapters`. The memory adapters are used to unit-test use cases without
services. The composition root (`utils::state::build_state`) injects adapter
trait objects into `AppState`; handlers receive ports and configuration only.

Adapter feature selection belongs at the composition root. This makes a
memory-only composition possible without altering domain or application code.
The default `server` feature selects the HTTP and Postgres/Redis/AWS stack;
`cargo check --no-default-features --features memory-only` compiles without
those infrastructure dependencies.
