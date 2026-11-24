from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from fleet.db.connection import sqlalchemy_url
from fleet.db.models import Base


@dataclass
class PostgresTestDatabase:
    session_factory: sessionmaker[Session]
    app_session_factory: sessionmaker[Session] | None
    schema: str


@pytest.fixture(scope="function")
def postgres_test_database() -> Iterator[PostgresTestDatabase]:
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is not set; PostgreSQL integration test not enabled")
    engine = create_engine(sqlalchemy_url(url), pool_pre_ping=True)
    schema = f"test_ingest_{uuid.uuid4().hex}"
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    schema_engine = engine.execution_options(schema_translate_map={None: schema})
    Base.metadata.create_all(schema_engine)
    ingest_url = os.getenv("TEST_DATABASE_INGEST_URL") or url
    ingest_engine = create_engine(sqlalchemy_url(ingest_url), pool_pre_ping=True).execution_options(
        schema_translate_map={None: schema}
    )
    app_url = os.getenv("TEST_DATABASE_APP_URL")
    app_engine = (
        create_engine(sqlalchemy_url(app_url), pool_pre_ping=True).execution_options(
            schema_translate_map={None: schema}
        )
        if app_url
        else None
    )
    factory = sessionmaker(ingest_engine, expire_on_commit=False)
    app_factory = sessionmaker(app_engine, expire_on_commit=False) if app_engine else None
    tenant_tables = (
        "tenant",
        "employee",
        "device",
        "telemetry_snapshot",
        "disk_volume",
        "compliance_result",
        "installed_software",
        "graph_run",
        "agent_step_event",
        "evidence",
        "evidence_pointer",
        "aggregate_manifest",
        "proposal",
        "approval",
        "action_execution",
        "audit_event",
        "audit_chain_head",
        "graph_checkpoint",
        "action_outbox",
    )
    with engine.begin() as connection:
        connection.execute(text(f'GRANT USAGE ON SCHEMA "{schema}" TO fleet_app, fleet_ingest'))
        connection.execute(
            text(f'GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA "{schema}" TO fleet_ingest')
        )
        connection.execute(
            text(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "{schema}" TO fleet_ingest')
        )
        connection.execute(text(f'GRANT SELECT ON "{schema}".tenant TO fleet_app'))
        for table in tenant_tables[1:]:
            grant = (
                "SELECT, INSERT"
                if table in {"approval", "audit_event", "evidence_pointer", "aggregate_manifest"}
                else "SELECT, INSERT, UPDATE, DELETE"
            )
            connection.execute(text(f'GRANT {grant} ON "{schema}"."{table}" TO fleet_app'))
        connection.execute(
            text(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA "{schema}" TO fleet_app')
        )
        for table in tenant_tables:
            connection.execute(text(f'ALTER TABLE "{schema}"."{table}" ENABLE ROW LEVEL SECURITY'))
            connection.execute(text(f'ALTER TABLE "{schema}"."{table}" FORCE ROW LEVEL SECURITY'))
            predicate = (
                "company_id = current_setting('app.tenant_id', true)"
                if table == "tenant"
                else "tenant_id = (SELECT t.id FROM "
                f'"{schema}".tenant AS t WHERE t.company_id = '
                "current_setting('app.tenant_id', true))"
            )
            connection.execute(
                text(
                    f'CREATE POLICY tenant_isolation ON "{schema}"."{table}" '
                    f"USING ({predicate}) WITH CHECK ({predicate})"
                )
            )
    try:
        yield PostgresTestDatabase(factory, app_factory, schema)
    finally:
        if app_engine is not None:
            app_engine.dispose()
        ingest_engine.dispose()
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()
