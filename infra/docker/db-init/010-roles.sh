#!/usr/bin/env bash
set -euo pipefail

: "${FLEET_APP_PASSWORD:?FLEET_APP_PASSWORD must be configured}"
: "${FLEET_INGEST_PASSWORD:?FLEET_INGEST_PASSWORD must be configured}"

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 \
  --set=app_password="$FLEET_APP_PASSWORD" \
  --set=ingest_password="$FLEET_INGEST_PASSWORD" <<'SQL'
SELECT format(
    'CREATE ROLE fleet_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD %L',
    :'app_password'
) WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fleet_app') \gexec
SELECT format(
    'CREATE ROLE fleet_ingest LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS PASSWORD %L',
    :'ingest_password'
) WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fleet_ingest') \gexec
SELECT format(
    'ALTER ROLE fleet_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD %L',
    :'app_password'
) WHERE EXISTS (SELECT FROM pg_roles WHERE rolname = 'fleet_app') \gexec
SELECT format(
    'ALTER ROLE fleet_ingest LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS PASSWORD %L',
    :'ingest_password'
) WHERE EXISTS (SELECT FROM pg_roles WHERE rolname = 'fleet_ingest') \gexec
SQL
