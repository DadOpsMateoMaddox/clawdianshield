from __future__ import annotations

from abc import ABC, abstractmethod
from runner.models import RunContext


class BehaviorModule(ABC):
    name: str

    @abstractmethod
    def run(self, ctx: RunContext) -> None:
        raise NotImplementedError
