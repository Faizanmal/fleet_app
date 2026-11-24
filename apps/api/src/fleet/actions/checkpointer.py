"""Tenant-scoped SQLAlchemy LangGraph checkpointer for durable approval interrupts."""

from __future__ import annotations

import base64
from collections.abc import Iterator, Sequence
from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    WRITES_IDX_MAP,
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    get_checkpoint_id,
    get_checkpoint_metadata,
)
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from fleet.core.identity import RequestContext, authorize
from fleet.db.models import GraphCheckpoint


def _pack(serde: Any, value: Any) -> dict[str, str]:
    kind, data = serde.dumps_typed(value)
    return {"type": kind, "data": base64.b64encode(data).decode("ascii")}


def _unpack(serde: Any, value: dict[str, str]) -> Any:
    return serde.loads_typed((value["type"], base64.b64decode(value["data"])))


class TenantPostgresSaver(BaseCheckpointSaver[str]):
    """Synchronous saver bound to one authenticated tenant and request DB session.

    The request transaction commits checkpoints when a graph interrupts and commits
    approval decisions and resumed workflow checkpoints atomically.
    """

    def __init__(self, context: RequestContext):
        if not isinstance(context, RequestContext):
            raise ValueError("trusted RequestContext required")
        authorize(context.principal, context.tenant_key, "read")
        super().__init__()
        self.context = context
        self.session: Session = context.session
        self.thread_prefix = f"t{context.tenant_id}-"

    def _scope(self, config: RunnableConfig) -> tuple[str, str]:
        configurable = config.get("configurable", {})
        thread_id = configurable.get("thread_id")
        if not isinstance(thread_id, str) or not thread_id.startswith(self.thread_prefix):
            raise PermissionError("checkpoint thread is outside the authenticated tenant")
        return thread_id, str(configurable.get("checkpoint_ns", ""))

    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        thread_id, namespace = self._scope(config)
        checkpoint_id = get_checkpoint_id(config)
        statement = select(GraphCheckpoint).where(
            GraphCheckpoint.tenant_id == self.context.tenant_id,
            GraphCheckpoint.thread_id == thread_id,
            GraphCheckpoint.checkpoint_ns == namespace,
        )
        if checkpoint_id:
            statement = statement.where(GraphCheckpoint.checkpoint_id == checkpoint_id)
        row = self.session.scalar(statement.order_by(GraphCheckpoint.checkpoint_id.desc()).limit(1))
        if row is None:
            return None
        return CheckpointTuple(
            config={
                "configurable": {
                    "thread_id": row.thread_id,
                    "checkpoint_ns": row.checkpoint_ns,
                    "checkpoint_id": row.checkpoint_id,
                }
            },
            checkpoint=_unpack(self.serde, row.checkpoint_data),
            metadata=_unpack(self.serde, row.metadata_data),
            parent_config=(
                {
                    "configurable": {
                        "thread_id": row.thread_id,
                        "checkpoint_ns": row.checkpoint_ns,
                        "checkpoint_id": row.parent_checkpoint_id,
                    }
                }
                if row.parent_checkpoint_id
                else None
            ),
            pending_writes=[
                (write["task_id"], write["channel"], _unpack(self.serde, write["value"]))
                for write in row.pending_writes
            ],
        )

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        del new_versions  # The complete checkpoint, including channel values, is stored atomically.
        thread_id, namespace = self._scope(config)
        checkpoint_id = checkpoint["id"]
        parent_id = config.get("configurable", {}).get("checkpoint_id")
        row = GraphCheckpoint(
            tenant_id=self.context.tenant_id,
            thread_id=thread_id,
            checkpoint_ns=namespace,
            checkpoint_id=checkpoint_id,
            parent_checkpoint_id=parent_id,
            checkpoint_data=_pack(self.serde, checkpoint),
            metadata_data=_pack(self.serde, get_checkpoint_metadata(config, metadata)),
            pending_writes=[],
        )
        self.session.add(row)
        try:
            if not getattr(self.session, "_flushing", False):
                self.session.flush()
        except Exception:
            pass
        return {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": namespace,
                "checkpoint_id": checkpoint_id,
            }
        }

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        thread_id, namespace = self._scope(config)
        checkpoint_id = get_checkpoint_id(config)
        row = self.session.scalar(
            select(GraphCheckpoint)
            .where(
                GraphCheckpoint.tenant_id == self.context.tenant_id,
                GraphCheckpoint.thread_id == thread_id,
                GraphCheckpoint.checkpoint_ns == namespace,
                GraphCheckpoint.checkpoint_id == checkpoint_id,
            )
            .with_for_update()
        )
        if row is None:
            for item in self.session.new:
                if (
                    isinstance(item, GraphCheckpoint)
                    and item.tenant_id == self.context.tenant_id
                    and item.thread_id == thread_id
                    and item.checkpoint_ns == namespace
                    and item.checkpoint_id == checkpoint_id
                ):
                    row = item
                    break
        if row is None:
            raise KeyError("checkpoint is unavailable for pending writes")
        saved = list(row.pending_writes)
        existing = {(item["task_id"], item["index"]) for item in saved}
        for index, (channel, value) in enumerate(writes):
            write_index = WRITES_IDX_MAP.get(channel, index)
            key = (task_id, write_index)
            if write_index >= 0 and key in existing:
                continue
            saved.append(
                {
                    "task_id": task_id,
                    "channel": channel,
                    "index": write_index,
                    "task_path": task_path,
                    "value": _pack(self.serde, value),
                }
            )
            existing.add(key)
        row.pending_writes = saved
        try:
            if not getattr(self.session, "_flushing", False):
                self.session.flush()
        except Exception:
            pass

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        statement = select(GraphCheckpoint).where(
            GraphCheckpoint.tenant_id == self.context.tenant_id
        )
        if config is not None:
            thread_id, namespace = self._scope(config)
            statement = statement.where(
                GraphCheckpoint.thread_id == thread_id,
                GraphCheckpoint.checkpoint_ns == namespace,
            )
            requested_id = get_checkpoint_id(config)
            if requested_id:
                statement = statement.where(GraphCheckpoint.checkpoint_id == requested_id)
        if before is not None:
            before_thread, before_namespace = self._scope(before)
            before_id = get_checkpoint_id(before)
            statement = statement.where(
                GraphCheckpoint.thread_id == before_thread,
                GraphCheckpoint.checkpoint_ns == before_namespace,
            )
            if before_id:
                statement = statement.where(GraphCheckpoint.checkpoint_id < before_id)
        rows = self.session.scalars(
            statement.order_by(GraphCheckpoint.checkpoint_id.desc()).limit(limit)
        ).all()
        for row in rows:
            metadata = _unpack(self.serde, row.metadata_data)
            if filter and not all(metadata.get(key) == value for key, value in filter.items()):
                continue
            yield CheckpointTuple(
                config={
                    "configurable": {
                        "thread_id": row.thread_id,
                        "checkpoint_ns": row.checkpoint_ns,
                        "checkpoint_id": row.checkpoint_id,
                    }
                },
                checkpoint=_unpack(self.serde, row.checkpoint_data),
                metadata=metadata,
                parent_config=(
                    {
                        "configurable": {
                            "thread_id": row.thread_id,
                            "checkpoint_ns": row.checkpoint_ns,
                            "checkpoint_id": row.parent_checkpoint_id,
                        }
                    }
                    if row.parent_checkpoint_id
                    else None
                ),
                pending_writes=[
                    (write["task_id"], write["channel"], _unpack(self.serde, write["value"]))
                    for write in row.pending_writes
                ],
            )

    def delete_thread(self, thread_id: str) -> None:
        if not thread_id.startswith(self.thread_prefix):
            raise PermissionError("checkpoint thread is outside the authenticated tenant")
        self.session.execute(
            delete(GraphCheckpoint).where(
                GraphCheckpoint.tenant_id == self.context.tenant_id,
                GraphCheckpoint.thread_id == thread_id,
            )
        )
        self.session.flush()
