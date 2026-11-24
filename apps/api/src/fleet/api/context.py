"""Authenticated request scope and transaction-local PostgreSQL tenant context."""

from collections.abc import Iterator
from dataclasses import replace
from functools import lru_cache

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from fleet.api.auth import get_principal
from fleet.core.identity import Principal, RequestContext
from fleet.db.connection import sqlalchemy_url
from fleet.db.models import Tenant
from fleet.settings import Settings, get_settings


@lru_cache(maxsize=4)
def _session_factory(database_url: str) -> sessionmaker[Session]:
    engine = create_engine(sqlalchemy_url(database_url), pool_pre_ping=True)
    return sessionmaker(engine, expire_on_commit=False)


def get_tenant_context(
    request: Request,
    principal: Principal = Depends(get_principal),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
    active_tenant: str | None = Header(default=None, alias="X-Active-Tenant"),  # noqa: B008
) -> Iterator[RequestContext]:
    tenant_key = active_tenant or principal.active_tenant_id
    if principal.membership_for(tenant_key) is None:
        raise HTTPException(status_code=404, detail="Not found")

    factory = _session_factory(settings.database_url)
    with factory() as session, session.begin():
        # The first setting is a trusted membership key used only to resolve its DB id.
        session.execute(select(func.set_config("app.tenant_id", tenant_key, True)))
        tenant_id = session.scalar(select(Tenant.id).where(Tenant.company_id == tenant_key))
        if tenant_id is None:
            raise HTTPException(status_code=404, detail="Not found")
        yield RequestContext(
            session,
            replace(principal, active_tenant_id=tenant_key),
            tenant_id,
            tenant_key,
            run_ref=getattr(request.state, "trace_id", "request"),
        )


# Backward-compatible import name for earlier modules; both names resolve to the
# same FastAPI dependency object and tenant transaction implementation.
get_request_context = get_tenant_context
