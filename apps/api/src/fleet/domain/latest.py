"""Pure reference implementation of latest-per-tenant-device semantics."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from fleet.domain.query import normalize_as_of


def select_latest_observations(
    observations: Sequence[Mapping[str, Any]], as_of: datetime
) -> tuple[Mapping[str, Any], ...]:
    """Reference oracle: tenant/device partition, timestamp DESC, identity DESC."""
    cutoff = normalize_as_of(as_of)
    latest: dict[tuple[str, str], tuple[datetime, int, Mapping[str, Any]]] = {}
    for position, observation in enumerate(observations, start=1):
        tenant = observation.get("tenant_id", observation.get("company_id"))
        device = observation.get("device_id")
        collected_at = observation.get("collected_at")
        if not isinstance(tenant, (str, int)) or not isinstance(device, str):
            raise ValueError("each observation requires tenant and device identifiers")
        if isinstance(collected_at, str):
            try:
                collected_at = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
            except ValueError as error:
                raise ValueError("collected_at must be an ISO 8601 timestamp") from error
        if not isinstance(collected_at, datetime):
            raise ValueError("collected_at must be a datetime")
        timestamp = normalize_as_of(collected_at)
        if timestamp > cutoff:
            continue
        identity = observation.get("id", observation.get("line_number", position))
        if not isinstance(identity, int) or isinstance(identity, bool):
            raise ValueError("snapshot identity must be an integer")
        key = (str(tenant), device)
        previous = latest.get(key)
        if previous is None or (timestamp, identity) > (previous[0], previous[1]):
            latest[key] = (timestamp, identity, observation)
    return tuple(latest[key][2] for key in sorted(latest))
