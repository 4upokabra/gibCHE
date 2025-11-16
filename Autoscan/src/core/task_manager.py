from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


class TaskCancelledError(Exception):
    """Raised when an operator cancels a managed task."""


@dataclass
class TaskControl:
    task_id: str
    kind: str
    status: str = "pending"
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.utcnow())
    updated_at: datetime = field(default_factory=lambda: datetime.utcnow())
    error: Optional[str] = None
    pause_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    cancel_requested: bool = False

    def __post_init__(self) -> None:
        self.pause_event.set()

    def set_status(self, status: str) -> None:
        self.status = status
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "kind": self.kind,
            "status": self.status,
            "metadata": self.metadata,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class TaskManager:
    def __init__(self) -> None:
        self._controls: Dict[str, TaskControl] = {}

    def create(self, task_id: str, kind: str, metadata: Optional[Dict[str, Any]] = None) -> TaskControl:
        control = TaskControl(task_id=task_id, kind=kind, metadata=metadata or {})
        self._controls[task_id] = control
        return control

    def get(self, task_id: str) -> Optional[TaskControl]:
        return self._controls.get(task_id)

    def list(self) -> List[Dict[str, Any]]:
        return [control.to_dict() for control in self._controls.values()]

    def require(self, task_id: str) -> TaskControl:
        control = self.get(task_id)
        if not control:
            raise KeyError(task_id)
        return control

    def mark_running(self, task_id: str) -> None:
        control = self.get(task_id)
        if not control:
            return
        control.pause_event.set()
        control.set_status("running")

    def mark_completed(self, task_id: str) -> None:
        control = self.get(task_id)
        if not control:
            return
        control.pause_event.set()
        control.set_status("completed")

    def mark_failed(self, task_id: str, error: str) -> None:
        control = self.get(task_id)
        if not control:
            return
        control.error = error
        control.pause_event.set()
        control.set_status("failed")

    def mark_cancelled(self, task_id: str, reason: Optional[str] = None) -> None:
        control = self.get(task_id)
        if not control:
            return
        control.error = reason or "Задача отменена оператором"
        control.cancel_requested = True
        control.pause_event.set()
        control.set_status("cancelled")

    async def checkpoint(self, task_id: str) -> None:
        control = self.get(task_id)
        if not control:
            return
        await control.pause_event.wait()
        if control.cancel_requested:
            raise TaskCancelledError(control.error or "Задача отменена оператором")

    def pause(self, task_id: str) -> TaskControl:
        control = self.require(task_id)
        if control.status in {"completed", "failed", "cancelled"}:
            raise ValueError("Задача уже завершена")
        control.pause_event.clear()
        control.set_status("paused")
        return control

    def resume(self, task_id: str) -> TaskControl:
        control = self.require(task_id)
        if control.status != "paused":
            raise ValueError("Задача не находится в паузе")
        control.pause_event.set()
        control.set_status("running")
        return control

    def cancel(self, task_id: str, reason: Optional[str] = None) -> TaskControl:
        control = self.require(task_id)
        if control.status in {"completed", "failed", "cancelled"}:
            raise ValueError("Задача уже завершена")
        control.error = reason or "Задача отменена оператором"
        control.cancel_requested = True
        control.pause_event.set()
        control.set_status("cancelled")
        return control


__all__ = ["TaskManager", "TaskControl", "TaskCancelledError"]

