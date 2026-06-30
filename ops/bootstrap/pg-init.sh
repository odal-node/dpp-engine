#!/bin/bash
# =============================================================================
# pg-init.sh — bundled-container provisioning hook for the odal_app login role.
#
# The official Postgres image runs every file in /docker-entrypoint-initdb.d/
# exactly once, on FIRST volume init, over the local socket as the superuser,
# before the server accepts outside connections. docker/docker-compose*.yml
# mounts THIS file there.
#
# It is a thin wrapper, not a second provisioning path: its only job is to feed
# the container's $DATABASE_APP_PASS into SQL. The actual logic — create the DB
# (a no-op here, the image already made POSTGRES_DB) and set the odal_app
# password — lives in ops/bootstrap/bootstrap.sql, the SINGLE source of truth
# shared with managed/external Postgres (`just db-bootstrap`). Nothing is
# duplicated; change the SQL in one place and both paths follow.
# =============================================================================
set -e

if [ -z "${DATABASE_APP_PASS:-}" ]; then
  echo "pg-init: DATABASE_APP_PASS is empty — refusing to set a blank app password." >&2
  exit 1
fi

# bootstrap.sql is mounted alongside (see compose). Pass the app password RAW —
# bootstrap.sql's :'app_pass' operator quotes and escapes it; pre-quoting here
# would bake literal quotes into the password. Connect to the maintenance DB
# ("postgres") because the script's CREATE DATABASE guard expects it; it then
# \connects to odal to set the role.
psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname postgres \
  -v app_pass="${DATABASE_APP_PASS}" \
  -f /opt/odal/bootstrap.sql
