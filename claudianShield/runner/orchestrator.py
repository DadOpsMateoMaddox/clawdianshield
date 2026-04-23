from __future__ import annotations

from typing import List

from runner.models import RunContext
from runner.safety import validate
from behaviors.file_tamper import FileTamperBehavior
from behaviors.auth_anomaly import SyntheticAuthAnomalyBehavior
from behaviors.remote_artifact import RemoteArtifactBehavior
from behaviors.staging import StagingBehavior
from behaviors.persistence import PersistenceBehavior
from behaviors.anti_forensics import AntiForensicsBehavior
from behaviors.cleanup import CleanupBehavior


BEHAVIOR_REGISTRY = {
    "file_tamper": FileTamperBehavior(),
    "auth_anomalies": SyntheticAuthAnomalyBehavior(),
    "remote_execution_artifacts": RemoteArtifactBehavior(),
    "staging": StagingBehavior(),
    "persistence_path_changes": PersistenceBehavior(),
    "anti_forensics": AntiForensicsBehavior(),
    "cleanup": CleanupBehavior(),
}


class Orchestrator:
    def resolve_plan(self, ctx: RunContext) -> List[str]:
        profile = ctx.scenario.behavior_profile
        # Order matters — mirrors realistic attack chain sequence
        ordered = [
            "auth_anomalies",
            "remote_execution_artifacts",
            "file_tamper",
            "staging",
            "persistence_path_changes",
            "anti_forensics",
            "cleanup",
        ]
        return [step for step in ordered if profile.get(step)]

    def execute(self, ctx: RunContext) -> None:
        validate(ctx.scenario)
        for step in self.resolve_plan(ctx):
            behavior = BEHAVIOR_REGISTRY.get(step)
            if behavior:
                behavior.run(ctx)
