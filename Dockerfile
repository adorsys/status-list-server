# Stage 1: Compile Rust binary with all dependencies
FROM rust:1.85-alpine AS builder

# Set working directory for build stage
WORKDIR /app

# Install required build dependencies, including OpenSSL development files
RUN apk add --no-cache \
    build-base \
    pkgconf \
    openssl-dev \
    musl-dev \
    ca-certificates \
    postgresql-dev \
    musl-utils \
    llvm-libunwind-dev

# Set environment variables (disable static linking for OpenSSL)
ENV OPENSSL_STATIC=0
ENV OPENSSL_DIR=/usr

# Copy dependency specifications first to optimize layer caching
COPY Cargo.toml Cargo.lock ./

# Create placeholder source to pre-download and cache dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Overwrite placeholder with actual source code
# Touch main.rs to ensure rebuild if source changed
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Build the project (using the host's default target)
RUN cargo build --release && \
    strip target/release/status-list-server

# Debug: Check if binary exists in builder stage
RUN ls -l target/release/status-list-server && file target/release/status-list-server

# Stage 2: Debug runtime image (temporary, for inspection)
FROM gcr.io/distroless/static-debian12:latest

# Copy only the compiled binary from builder stage
COPY --from=builder /app/target/release/status-list-server /usr/local/bin/status-list-server

# Expose default application port (TCP/8000)
EXPOSE 8000

# Container entrypoint
CMD ["/usr/local/bin/status-list-server"]