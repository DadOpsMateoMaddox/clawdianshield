from __future__ import annotations

import os
from datetime import datetime, timezone
from runner.models import NormalizedEvent, RunContext


def emit_process_start(
    ctx: RunContext,
    host: str,
    command: str,
    parent: str = "unknown",
    user: str = "lab-user",
) -> None:
    ctx.events.append(NormalizedEvent(
        run_id=ctx.run_id,
        scenario_id=ctx.scenario.scenario_id,
        host=host,
        event_type="process_start",
        timestamp=datetime.now(timezone.utc).isoformat(),
        severity="medium",
        details={
            "command": command,
            "parent": parent,
            "user": user,
            "pid": os.getpid(),
        },
    ))
