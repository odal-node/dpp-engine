# ── node.Dockerfile — the dpp-node image, published or local-core in ONE file ───
# Two build modes, selected by the BUILD_MODE build-arg:
#   • published (default) — resolve dpp-* from crates.io. Used by
#     `docker compose up --build`, `just docker-node`, and CI (release.yml).
#   • local               — compile against the sibling ../dpp-core working tree
#     (pre-publish dev, when engine source uses core API not yet on crates.io).
#     Selected with `--build-arg BUILD_MODE=local` — see docker-compose.local.yml
#     / `just up-local` / `just docker-node-local`.
#
# Build context is the parent dir holding dpp-engine/ (and, for local mode,
# dpp-core/) as siblings. The published path never COPYs dpp-core, so CI can
# check out dpp-engine alone. The runtime stage is shared by both modes — edit
# it once and both images stay in lockstep.
#
# Builder is pinned to bookworm so the binary's glibc matches the bookworm-slim
# runtime below (rust:1.90-slim tracks newer Debian and would link glibc 2.38+).
ARG BUILD_MODE=published

# ── Build deps shared by both modes ─────────────────────────────────────────────
FROM rust:1.90-slim-bookworm AS builder-base
WORKDIR /build
ENV RUSTC_WRAPPER=""

# ── published: dpp-* from crates.io; strip any local [patch.crates-io] override ──
# Never honour a developer's local dpp-core override — it points at a sibling
# ../dpp-core that isn't in this context. (.dockerignore already strips it; the
# rm is belt-and-suspenders.)
FROM builder-base AS builder-published
COPY dpp-engine/ dpp-engine/
WORKDIR /build/dpp-engine
RUN rm -f .cargo/config.toml
RUN cargo build --release -p dpp-node

# ── local: patch dpp-* to the sibling ../dpp-core source ─────────────────────────
FROM builder-base AS builder-local
# Sibling core checkout — the [patch.crates-io] paths below resolve into this.
COPY dpp-core/   dpp-core/
COPY dpp-engine/ dpp-engine/
# The committed example carries the [patch.crates-io] paths (../dpp-core/crates/*);
# placing it at Cargo's discovery location makes the deps resolve to /build/dpp-core
# regardless of host dev state (the host's own .cargo/config.toml is excluded from
# the context via .dockerignore, so this is deterministic).
COPY dpp-engine/.cargo/config.toml.example /build/dpp-engine/.cargo/config.toml
WORKDIR /build/dpp-engine
RUN cargo build --release -p dpp-node

# Select the active builder from BUILD_MODE; only the chosen stage is built.
FROM builder-${BUILD_MODE} AS builder

# ── Runtime stage (shared by both build modes) ──────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/dpp-engine/target/release/dpp-node /usr/local/bin/dpp-node

RUN mkdir -p /plugins
VOLUME ["/plugins"]

ENV PORT=8000 \
    LOG_LEVEL=info \
    PLUGINS_DIR=/plugins

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["dpp-node"]
