from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from runner.models import RunContext, NormalizedEvent


class CleanupBehavior:
    name = "cleanup"

    def run(self, ctx: RunContext) -> None:
        host = ctx.scenario.hosts[0]
        base = Path("/tmp/clawdianshield")

        if base.exists():
            self._emit(ctx, host, "cleanup_delete", {"path": str(base)}, "high")
            shutil.rmtree(base, ignore_errors=True)

    def _emit(self, ctx: RunContext, host: str, event_type: str, details: dict, severity: str) -> None:
        ctx.events.append(NormalizedEvent(
            run_id=ctx.run_id,
            scenario_id=ctx.scenario.scenario_id,
            host=host,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity=severity,
            details=details,
        ))
