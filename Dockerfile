# ============================================================================
# SpectonCR Multi-Stage Dockerfile
# Builds both specton-auth and specton-registry binaries in a single image.
# ============================================================================

# ── Builder stage ────────────────────────────────────────────────────────────

FROM rust:1.94-bookworm AS builder

WORKDIR /build

# Cache dependency compilation: copy manifests first, then build a dummy
# project so that changing application source does not invalidate the
# dependency layer.
COPY Cargo.toml Cargo.lock ./
COPY crates/specton-common/Cargo.toml      crates/specton-common/Cargo.toml
COPY crates/specton-auth/Cargo.toml        crates/specton-auth/Cargo.toml
COPY crates/specton-registry/Cargo.toml    crates/specton-registry/Cargo.toml
COPY crates/specton-controller/Cargo.toml  crates/specton-controller/Cargo.toml
COPY crates/specton-resilience/Cargo.toml  crates/specton-resilience/Cargo.toml
COPY crates/specton-mirror/Cargo.toml      crates/specton-mirror/Cargo.toml
COPY crates/specton-replication/Cargo.toml crates/specton-replication/Cargo.toml
COPY crates/specton-db/Cargo.toml          crates/specton-db/Cargo.toml
COPY crates/specton-ai/Cargo.toml          crates/specton-ai/Cargo.toml
COPY crates/specton-scanner/Cargo.toml     crates/specton-scanner/Cargo.toml

# Create stub source files so Cargo can resolve the workspace
RUN mkdir -p crates/specton-common/src      && echo "pub fn _stub(){}" > crates/specton-common/src/lib.rs \
 && mkdir -p crates/specton-auth/src        && echo "fn main(){}" > crates/specton-auth/src/main.rs \
 && mkdir -p crates/specton-registry/src    && echo "fn main(){}" > crates/specton-registry/src/main.rs \
 && mkdir -p crates/specton-controller/src  && echo "fn main(){}" > crates/specton-controller/src/main.rs \
 && mkdir -p crates/specton-resilience/src  && echo "pub fn _stub(){}" > crates/specton-resilience/src/lib.rs \
 && mkdir -p crates/specton-mirror/src      && echo "pub fn _stub(){}" > crates/specton-mirror/src/lib.rs \
 && mkdir -p crates/specton-replication/src && echo "pub fn _stub(){}" > crates/specton-replication/src/lib.rs \
 && mkdir -p crates/specton-db/src          && echo "pub fn _stub(){}" > crates/specton-db/src/lib.rs \
 && mkdir -p crates/specton-ai/src          && echo "pub fn _stub(){}" > crates/specton-ai/src/lib.rs \
 && mkdir -p crates/specton-scanner/src     && echo "pub fn _stub(){}" > crates/specton-scanner/src/lib.rs \
 && mkdir -p crates/specton-scanner/src/bin && echo "fn main(){}" > crates/specton-scanner/src/bin/specton-scanner.rs

# Build dependencies only (this layer is cached unless Cargo.toml/lock change)
RUN cargo build --release --workspace 2>&1 || true

# Remove the stub artifacts so the real source gets compiled
RUN rm -rf crates/specton-common/src crates/specton-auth/src crates/specton-registry/src \
    crates/specton-controller/src crates/specton-resilience/src crates/specton-mirror/src \
    crates/specton-replication/src crates/specton-db/src crates/specton-ai/src \
    crates/specton-scanner/src \
 && rm -rf target/release/.fingerprint/specton-*

# Copy the actual source code
COPY crates/ crates/

# Build the real binaries (embed git SHA as build hash)
ARG SPECTONCR_BUILD_HASH=dev
ENV SPECTONCR_BUILD_HASH=${SPECTONCR_BUILD_HASH}
RUN cargo build --release --bin specton-auth --bin specton-registry --bin specton-scanner

# ── Runtime stage ────────────────────────────────────────────────────────────

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 10001 spectoncr \
 && useradd --uid 10001 --gid spectoncr --shell /sbin/nologin --create-home spectoncr

# Create directories for data, config, and keys
RUN mkdir -p /var/lib/spectoncr/data \
             /etc/spectoncr/keys \
 && chown -R spectoncr:spectoncr /var/lib/spectoncr /etc/spectoncr

# Copy binaries from the builder stage
COPY --from=builder /build/target/release/specton-auth     /usr/local/bin/specton-auth
COPY --from=builder /build/target/release/specton-registry /usr/local/bin/specton-registry
COPY --from=builder /build/target/release/specton-scanner  /usr/local/bin/specton-scanner

# Ensure binaries are executable
RUN chmod +x /usr/local/bin/specton-auth /usr/local/bin/specton-registry /usr/local/bin/specton-scanner

# Switch to non-root user
USER spectoncr

# Expose ports:
#   5000 - OCI Registry API (Docker Registry HTTP API V2)
#   5001 - Auth / Token service
#   9090 - Prometheus metrics
EXPOSE 5000 5001 9090

# Health check: probe the registry health endpoint every 30 seconds
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/specton-registry", "--health-check"] || exit 1

# Use tini as PID 1 for proper signal handling
ENTRYPOINT ["tini", "--"]

# Default: run the registry service. Override with specton-auth to run auth.
CMD ["specton-registry"]
