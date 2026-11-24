"""Development-only fixture token adapter. Production identity adapters can replace this."""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from fleet.core.identity import Membership, Principal, Role
from fleet.settings import Settings, get_settings

bearer = HTTPBearer(auto_error=False)


def _membership(tenant: str, role: Role) -> Membership:
    return Membership(tenant, frozenset({role}))


# Tokens are public development fixtures, never accepted unless DEMO_AUTH_MODE=true.
DEMO_PRINCIPALS = {}
for tenant in ("acme-001", "globex-002", "initech-003"):
    shorthand = tenant.split("-")[0]
    for role in ("viewer", "operator", "approver"):
        p = Principal(
            user_id=f"fixture-{tenant}-{role}",
            memberships=(_membership(tenant, role),),
            active_tenant_id=tenant,
            auth_method="demo_fixture_token",
        )
        DEMO_PRINCIPALS[f"demo-{tenant}-{role}"] = p
        DEMO_PRINCIPALS[f"demo-{shorthand}-{role}"] = p
DEMO_PRINCIPALS["demo-acme-admin"] = Principal(
    user_id="fixture-acme-admin",
    memberships=(Membership("acme-001", frozenset({"admin"})),),
    active_tenant_id="acme-001",
    auth_method="demo_fixture_token",
)
DEMO_PRINCIPALS["demo-acme-001-admin"] = DEMO_PRINCIPALS["demo-acme-admin"]


def get_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> Principal:
    if not settings.demo_auth_mode:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Unauthorized")
    principal = DEMO_PRINCIPALS.get(credentials.credentials)
    if principal is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return principal


def require_role(*roles: Role):
    def dependency(
        principal: Principal = Depends(get_principal),  # noqa: B008
        active_tenant: str | None = Header(default=None, alias="X-Active-Tenant"),  # noqa: B008
    ) -> Principal:
        tenant_key = active_tenant or principal.active_tenant_id
        membership = principal.membership_for(tenant_key)
        if membership is None:
            raise HTTPException(status_code=404, detail="Not found")
        if membership is None or not (
            membership.roles.intersection(roles) or "admin" in membership.roles
        ):
            raise HTTPException(status_code=403, detail="Forbidden")
        return principal

    return dependency
