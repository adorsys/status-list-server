ARG APP_NAME=status-list-server

# Use buildx's automatic platform detection
FROM --platform=$BUILDPLATFORM blackdex/rust-musl:x86_64-musl AS builder-amd64
FROM --platform=$BUILDPLATFORM blackdex/rust-musl:aarch64-musl AS builder-arm64

# Select the appropriate builder based on target platform
FROM builder-${TARGETARCH} AS builder
ARG APP_NAME
ARG TARGETPLATFORM
ARG TARGETARCH
WORKDIR /app

# cargo-auditable records the dependency graph in a .dep-v0 linker section. Without
# it the scratch runtime image carries one static binary and no package metadata, so
# scanners enumerate zero packages and the published SBOM is empty.
#
# These pins are invisible to every Dependabot ecosystem configured here; see
# docs/supply-chain.md, "Tool Ownership", for the bump path.
#
# Declared above ARG FEATURES so a feature-set change does not invalidate this layer.
ARG CARGO_AUDITABLE_VERSION=0.7.5
ARG RUST_AUDIT_INFO_VERSION=0.5.4
RUN --mount=type=cache,target=/root/.cargo/registry,id=registry-cache-${TARGETPLATFORM} \
    set -eu; \
    cargo install --locked --root /usr/local cargo-auditable@${CARGO_AUDITABLE_VERSION}; \
    cargo install --locked --root /usr/local rust-audit-info@${RUST_AUDIT_INFO_VERSION}

ARG FEATURES="postgres,aws"

# The release profile sets strip, lto and codegen-units = 1, each of which can drop
# .dep-v0. A missing section yields a passing scan and an empty SBOM, so this must
# fail the build here rather than surface downstream as a clean result.
#
# The assertion requires the section to decode AND to be non-empty: decoding an empty
# dependency graph exits zero, so an exit-status check alone would pass on exactly the
# empty-but-present artifact it exists to catch. The decode is captured before it is
# counted so a rust-audit-info crash fails as itself rather than as a count of 0.
RUN --mount=type=bind,source=src,target=src \
    --mount=type=bind,source=test_data,target=test_data \
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

# Minimal scratch-based runtime image
FROM scratch AS runtime
ARG APP_NAME

# CA certificates for TLS connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Non-root user identity (UID 65534 = nobody)
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

COPY --from=builder --chown=65534:65534 /app/${APP_NAME} /app/${APP_NAME}

USER 65534
EXPOSE 8000
ENTRYPOINT ["/app/status-list-server"]
