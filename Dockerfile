# Stage 1: Build - Creates an optimized production binary
FROM rust:1.85.0 AS builder

# Install musl-tools for static linking
RUN apt-get update && apt-get install -y musl-tools && \
    rustup target add x86_64-unknown-linux-musl

# Set the working directory
WORKDIR /app

# Copy dependency files first to leverage Docker caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy src/main.rs to pass initial build and cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build the dependencies first to cache them
RUN cargo build --release --target x86_64-unknown-linux-musl

# Remove dummy file and copy actual source
RUN rm -rf src
COPY src ./src

# Final build with locked dependencies and musl target
RUN cargo build --release --target x86_64-unknown-linux-musl --verbose && \
    strip target/x86_64-unknown-linux-musl/release/status-list-server

# Stage 2: Runtime - Distroless image 
FROM gcr.io/distroless/static-debian12:latest

# Set working directory
WORKDIR /app

# Copy only the built binary from the builder stage
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/status-list-server /app/

# Expose the default network port
EXPOSE 8000

# Start the binary (must be statically linked, no shell available in distroless)
CMD ["/app/status-list-server"]
