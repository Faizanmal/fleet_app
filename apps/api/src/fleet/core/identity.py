"""Trusted server-side principals and explicit request scope."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy.orm import Session

Role = Literal["viewer", "operator", "approver", "admin"]
Capability = Literal["read", "draft_proposal", "approve", "reject", "audit", "admin"]
ROLE_CAPABILITIES: dict[Role, frozenset[Capability]] = {
    "viewer": frozenset({"read"}),
    "operator": frozenset({"read", "draft_proposal"}),
    "approver": frozenset({"read", "approve", "reject"}),
    "admin": frozenset({"read", "draft_proposal", "approve", "reject", "audit", "admin"}),
}


@dataclass(frozen=True)
class Membership:
    tenant_id: str
    roles: frozenset[Role]


@dataclass(frozen=True)
class Principal:
    user_id: str
    memberships: tuple[Membership, ...]
    active_tenant_id: str
    auth_method: str

    def membership_for(self, tenant_id: str) -> Membership | None:
        return next((item for item in self.memberships if item.tenant_id == tenant_id), None)

    @property
    def roles(self) -> frozenset[Role]:
        membership = self.membership_for(self.active_tenant_id)
        return membership.roles if membership else frozenset()


@dataclass(frozen=True)
class RequestContext:
    """A request's DB session and authorized tenant; repositories require this value."""

    session: Session
    principal: Principal
    tenant_id: int
    tenant_key: str
    clock: Callable[[], datetime] = field(
        default=lambda: datetime.now(UTC), compare=False, repr=False
    )
    run_ref: str = "request"

    def __post_init__(self) -> None:
        if self.tenant_id <= 0 or self.principal.membership_for(self.tenant_key) is None:
            raise ValueError("RequestContext requires an authorized, resolved tenant")


class MissingRequestContext(ValueError):
    pass


class AuthorizationDenied(PermissionError):
    pass


def authorize(principal: Principal, tenant_key: str, capability: Capability) -> None:
    """Evaluate the active membership on every server-side state transition."""
    membership = principal.membership_for(tenant_key)
    if membership is None or not any(
        capability in ROLE_CAPABILITIES[role] for role in membership.roles
    ):
        raise AuthorizationDenied("Forbidden")


def verify_approved_proposal_hash(approved_hash: str, executing_hash: str) -> None:
    if not approved_hash or approved_hash != executing_hash:
        raise AuthorizationDenied("Approved proposal hash does not match execution request")
