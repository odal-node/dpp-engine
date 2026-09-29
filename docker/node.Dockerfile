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
# runtime below (rust:1.96-slim tracks newer Debian and would link glibc 2.38+).
#
# 🚨 The tag's Rust version MUST equal `rust-toolchain.toml`'s channel — the
# toolchain CI tests with. The images job fails when they differ. The toolchain
# file is kept OUT of the build context (see node.Dockerfile.dockerignore), so
# the compiler is this digest-recorded base image's and nothing else: when the
# file was in the context, rustup quietly fetched the channel it names over the
# base image, and the images were built by a compiler neither the tag nor the
# provenance attestation named.
ARG BUILD_MODE=published

# ── Build deps shared by both modes ─────────────────────────────────────────────
FROM rust:1.96.0-slim-bookworm AS builder-base
WORKDIR /build
ENV RUSTC_WRAPPER=""

# A Rust binary carries no record of what went into it. Scanning this image
# with syft or trivy finds the Debian packages in the runtime stage and **zero**
# of the crates the binary was built from — so an image SBOM would be accurate
# about the base layer and silent about the application, which is the half that
# matters. `cargo auditable` embeds the dependency graph from Cargo.lock into
# the binary itself, so the scanner recovers it and `cargo audit bin` can read
# it straight out of a shipped image. It changes no code: the crate list lands
# in its own section and the program is byte-for-byte the same otherwise.
RUN cargo install cargo-auditable --locked

# ── published: dpp-* from crates.io; strip any local [patch.crates-io] override ──
# Never honour a developer's local dpp-core override — it points at a sibling
# ../dpp-core that isn't in this context. (.dockerignore already strips it; the
# rm is belt-and-suspenders.)
FROM builder-base AS builder-published
COPY dpp-engine/ dpp-engine/
WORKDIR /build/dpp-engine
RUN rm -f .cargo/config.toml
# `s3` is off by default (object storage is an optional deployment
# dependency); the image opts in so ESPR archival and continuity snapshots
# work out of the box. This is the artefact operators run — any claim about
# what the shipped binary contains must be checked against *this* feature
# set, not against a bare `cargo build`.
#
# `--locked`: the graph `cargo auditable` embeds is the SBOM's crate list, so
# it must be the committed Cargo.lock — never one cargo quietly re-resolved in
# the builder. (Not in the local stage below: its [patch] onto ../dpp-core
# changes the lock by design.)
RUN cargo auditable build --locked --release -p dpp-node --features s3

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
RUN cargo auditable build --release -p dpp-node --features s3

# Select the active builder from BUILD_MODE; only the chosen stage is built.
FROM builder-${BUILD_MODE} AS builder

# ── Runtime stage (shared by both build modes) ──────────────────────────────────
FROM debian:bookworm-slim AS runtime

# `upgrade` pulls whatever Debian security patches exist for bookworm-slim's
# packages as of build time, ahead of the base tag's next upstream rebuild —
# this is what actually moves the vulnerability-scan needle on the published
# image (the builder stage's CVEs never ship; only this runtime stage does).
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Fixed, non-zero uid/gid — no host user correspondence needed since the
# published deployment path only ever binds named Docker volumes, never a host
# bind-mount.
RUN groupadd --system --gid 1000 odal \
    && useradd --system --uid 1000 --gid odal --no-create-home --shell /usr/sbin/nologin odal

COPY --from=builder --chmod=755 /build/dpp-engine/target/release/dpp-node /usr/local/bin/dpp-node

# /data holds the encrypted signing key store (KEY_STORE_PATH is set relative,
# so it resolves against WORKDIR below) on the `node-data` volume; /plugins
# holds Wasm plugins on `node-plugins`. Both are chowned *before* VOLUME so
# Docker seeds each named volume's first-creation content with the right
# ownership instead of root:root.
RUN mkdir -p /data /plugins && chown -R odal:odal /data /plugins
VOLUME ["/data", "/plugins"]
WORKDIR /data

USER odal

ENV PORT=8000 \
    LOG_LEVEL=info \
    PLUGINS_DIR=/plugins

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["dpp-node"]
