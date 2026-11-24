"""PostgreSQL connection checks."""

from urllib.parse import urlparse

import psycopg


def sqlalchemy_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+psycopg://", 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return database_url


def check_database(database_url: str) -> None:
    if urlparse(database_url).scheme not in {"postgres", "postgresql"}:
        raise ValueError("DATABASE_URL must use PostgreSQL")
    with psycopg.connect(database_url, connect_timeout=5) as connection:
        connection.execute("SELECT 1")
        role = connection.execute("""
            SELECT r.rolsuper, r.rolbypassrls,
                   EXISTS (
                       SELECT 1 FROM pg_class c
                       JOIN pg_namespace n ON n.oid = c.relnamespace
                       WHERE c.relowner = r.oid AND n.nspname = 'public'
                         AND c.relname IN (
                           'tenant', 'employee', 'device', 'telemetry_snapshot',
                           'disk_volume', 'compliance_result', 'installed_software',
                           'graph_run', 'evidence', 'evidence_pointer', 'aggregate_manifest',
                           'proposal', 'approval',
                           'action_execution', 'audit_event', 'audit_chain_head',
                           'agent_step_event',
                           'graph_checkpoint', 'action_outbox'
                         )
                   ) AS owns_tenant_tables
                   ,(SELECT count(*) FROM unnest(ARRAY[
                       'tenant', 'employee', 'device', 'telemetry_snapshot',
                       'disk_volume', 'compliance_result', 'installed_software',
                       'graph_run', 'evidence', 'evidence_pointer', 'aggregate_manifest',
                       'proposal', 'approval',
                       'action_execution', 'audit_event', 'audit_chain_head',
                       'agent_step_event',
                       'graph_checkpoint', 'action_outbox'
                   ]) AS required(name)
                   LEFT JOIN pg_namespace n ON n.nspname = 'public'
                   LEFT JOIN pg_class c ON c.relname = required.name AND c.relnamespace = n.oid
                   WHERE c.oid IS NULL OR NOT c.relrowsecurity OR NOT c.relforcerowsecurity
                   ) AS missing_forced_rls,
                   (SELECT count(*) FROM pg_policies p
                    WHERE p.schemaname = 'public'
                      AND p.policyname = 'tenant_isolation') AS tenant_policy_count
            FROM pg_roles r WHERE r.rolname = current_user
            """).fetchone()
        if role is None or role[0] or role[1] or role[2] or role[3] != 0 or role[4] != 19:
            raise RuntimeError(
                "DATABASE_URL must use a non-owner, non-superuser, non-BYPASSRLS role; "
                "all tenant tables must have ENABLE and FORCE ROW LEVEL SECURITY"
            )
