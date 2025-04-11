# Stage 1: Build - Creates an optimized production binary
FROM rust:1.85 as builder

# Set working directory in container
WORKDIR /app

# Copy dependency files first to leverage Docker caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to pre-download dependencies
# This allows caching dependencies separate from our source code changes
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release  # Build dependencies in release mode

# Copy actual source code (this happens after dependency caching)
COPY src ./src

# Build the actual application with optimizations
RUN cargo build --release && \
    strip target/release/status-list-server && \
    ls -lh target/release/

# Stage 2: Runtime - Create minimal production image
FROM debian:bookworm-slim

# Set working directory in the runtime container
WORKDIR /app

# Copy only the built binary from the builder stage
COPY --from=builder /app/target/release/status-list-server /app/status-list-server

# Verify file copy and set executable permissions
RUN chmod +x /app/status-list-server

# Expose the default network port
EXPOSE 8080

# Set default logging level
ENV RUST_LOG=info

# Command to run when container starts
CMD ["./status-list-server"]