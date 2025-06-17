ARG APP_NAME=status-list-server

FROM blackdex/rust-musl:x86_64-musl AS builder
ARG APP_NAME
WORKDIR /app

RUN --mount=type=bind,source=src,target=src \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target \
    --mount=type=cache,target=/root/.cargo/registry \
    cargo build --locked --release && \
    mv target/x86_64-unknown-linux-musl/release/${APP_NAME} .

FROM gcr.io/distroless/static-debian12 AS runtime
ARG APP_NAME
COPY --from=builder --chown=nonroot:nonroot /app/${APP_NAME} /app/status-list
EXPOSE 8000
ENTRYPOINT ["/app/status-list"]