ARG APP_NAME=status-list-server

FROM --platform=$BUILDPLATFORM blackdex/rust-musl:x86_64-musl@sha256:7a7608c1e7aa31cdc6e78ce1c0ecae5683ce0831daef77d89f9c756505431f78 AS builder-amd64
FROM --platform=$BUILDPLATFORM blackdex/rust-musl:aarch64-musl@sha256:d5d5c9f3d4c8e54e1b6c36e560c123e49451f5a2c27454586f8e6a073b956df2 AS builder-arm64

FROM builder-${TARGETARCH} AS builder
ARG APP_NAME
ARG TARGETPLATFORM
ARG TARGETARCH
WORKDIR /app

# cargo-auditable embeds the dependency graph; without it scanners see zero packages in a scratch image.
# Dependabot can't see these pins (docs/supply-chain.md, "Tool Ownership").
# Above ARG FEATURES so a feature change doesn't rebuild this layer.
ARG CARGO_AUDITABLE_VERSION=0.7.5
ARG RUST_AUDIT_INFO_VERSION=0.5.4
# Build the tools for the host, not TARGETARCH.
RUN --mount=type=cache,target=/root/.cargo/registry,id=registry-cache-${TARGETPLATFORM} \
    set -eu; \
    env -u CARGO_BUILD_TARGET cargo install --locked --root /usr/local cargo-auditable@${CARGO_AUDITABLE_VERSION}; \
    env -u CARGO_BUILD_TARGET cargo install --locked --root /usr/local rust-audit-info@${RUST_AUDIT_INFO_VERSION}

ARG FEATURES="postgres,aws,redis"

# strip, lto and codegen-units=1 can drop .dep-v0, which would make scans pass on nothing.
# Require a non-empty decode (an empty graph still exits 0); capture it first so a decode crash fails as itself.
RUN --mount=type=bind,source=src,target=src \
    --mount=type=bind,source=docs,target=docs \
    --mount=type=bind,source=test_data,target=test_data \
    --mount=type=bind,source=xtask,target=xtask \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target,id=target-cache-${TARGETPLATFORM} \
    --mount=type=cache,target=/root/.cargo/registry,id=registry-cache-${TARGETPLATFORM} \
    set -eu; \
    case "${TARGETARCH:-}" in \
        amd64) RUST_TARGET="x86_64-unknown-linux-musl" ;; \
        arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH:-unset}" && exit 1 ;; \
    esac; \
    cargo auditable build --locked --release --target=${RUST_TARGET} --features "${FEATURES}"; \
    mv target/${RUST_TARGET}/release/${APP_NAME} .; \
    audit_data=$(rust-audit-info "${APP_NAME}"); \
    audit_packages=$(printf '%s' "${audit_data}" | grep -o '"name":' | wc -l); \
    echo "audit data records ${audit_packages} package entries"; \
    if [ "${audit_packages}" -eq 0 ]; then \
        echo "ERROR: ${APP_NAME} carries no readable .dep-v0 package data; the published SBOM would be empty"; \
        exit 1; \
    fi

FROM scratch AS runtime
ARG APP_NAME

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Non-root user identity (UID 65534 = nobody)
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

COPY --from=builder --chown=65534:65534 /app/${APP_NAME} /app/${APP_NAME}

USER 65534
EXPOSE 8000
EXPOSE 8001
EXPOSE 8002
ENTRYPOINT ["/app/status-list-server"]
