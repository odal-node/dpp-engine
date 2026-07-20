# ── resolver.Dockerfile — the dpp-resolver image, published or local-core in ONE ─
# Two build modes, selected by the BUILD_MODE build-arg:
#   • published (default) — resolve dpp-* from crates.io. Used by
#     `docker compose up --build`, `just docker-resolver`, and CI (release.yml).
#   • local               — compile against the sibling ../dpp-core working tree
#     (pre-publish dev, when engine source uses core API not yet on crates.io).
#     Selected with `--build-arg BUILD_MODE=local` — see docker-compose.local.yml
#     / `just up-local` / `just docker-resolver-local`.
#
# Build context is the parent dir holding dpp-engine/ (and, for local mode,
# dpp-core/) as siblings. The published path never COPYs dpp-core, so CI can
# check out dpp-engine alone. The runtime stage is shared by both modes — edit
# it once and both images stay in lockstep.
#
# Builder is pinned to bookworm so the binary's glibc matches the bookworm-slim
# runtime below (rust:1.96-slim tracks newer Debian and would link glibc 2.38+).
ARG BUILD_MODE=published

# ── Build deps shared by both modes ─────────────────────────────────────────────
FROM rust:1.97-slim-bookworm AS builder-base
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ENV RUSTC_WRAPPER=""

# ── published: dpp-* from crates.io; strip any local [patch.crates-io] override ──
# Never honour a developer's local dpp-core override — the sibling ../dpp-core
# isn't in this context. (.dockerignore already strips it; the rm is defensive.)
FROM builder-base AS builder-published
COPY dpp-engine/ dpp-engine/
WORKDIR /build/dpp-engine
RUN rm -f .cargo/config.toml
RUN cargo build --release -p dpp-resolver

# ── local: patch dpp-* to the sibling ../dpp-core source ─────────────────────────
FROM builder-base AS builder-local
# Sibling core checkout — the [patch.crates-io] paths below resolve into this.
COPY dpp-core/   dpp-core/
COPY dpp-engine/ dpp-engine/
# The committed example carries the [patch.crates-io] paths (../dpp-core/crates/*),
# which resolve to /build/dpp-core. Placing it at Cargo's discovery location makes
# Cargo pick it up regardless of host dev state (host config.toml is .dockerignore'd).
COPY dpp-engine/.cargo/config.toml.example /build/dpp-engine/.cargo/config.toml
WORKDIR /build/dpp-engine
RUN cargo build --release -p dpp-resolver

# Select the active builder from BUILD_MODE; only the chosen stage is built.
FROM builder-${BUILD_MODE} AS builder

# ── Runtime stage (shared by both build modes) ──────────────────────────────────
FROM debian:bookworm-slim AS runtime

# `upgrade` pulls whatever Debian security patches exist for bookworm-slim's
# packages as of build time, ahead of the base tag's next upstream rebuild —
# this is what actually moves the vulnerability-scan needle on the published
# image (the builder stage's CVEs never ship; only this runtime stage does).
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/*

# Fixed, non-zero uid/gid — the resolver has no local state (Redis + upstream
# vault only), so no volume ownership to worry about.
RUN groupadd --system --gid 1000 odal \
    && useradd --system --uid 1000 --gid odal --no-create-home --shell /usr/sbin/nologin odal

COPY --from=builder --chmod=755 /build/dpp-engine/target/release/dpp-resolver /usr/local/bin/dpp-resolver

USER odal

EXPOSE 8003

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -sf http://localhost:8003/health || exit 1

ENTRYPOINT ["dpp-resolver"]
