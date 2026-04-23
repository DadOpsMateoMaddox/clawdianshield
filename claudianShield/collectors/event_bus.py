from __future__ import annotations

from typing import Callable, Dict, List
from runner.models import NormalizedEvent


Handler = Callable[[NormalizedEvent], None]


class EventBus:
    """
    In-process event bus. Behaviors publish events; collectors subscribe to them.
    Keeps the runner decoupled from any specific telemetry backend.
    """

    def __init__(self) -> None:
        self._handlers: Dict[str, List[Handler]] = {}
        self._all: List[Handler] = []

    def subscribe(self, event_type: str, handler: Handler) -> None:
        self._handlers.setdefault(event_type, []).append(handler)

    def subscribe_all(self, handler: Handler) -> None:
        self._all.append(handler)

    def publish(self, event: NormalizedEvent) -> None:
        for h in self._all:
            h(event)
        for h in self._handlers.get(event.event_type, []):
            h(event)
