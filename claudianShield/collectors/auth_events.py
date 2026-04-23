from __future__ import annotations

from datetime import datetime, timezone
from runner.models import NormalizedEvent, RunContext


def emit_auth_event(
    ctx: RunContext,
    host: str,
    event_type: str,
    source_host: str,
    account: str,
    severity: str = "medium",
    extra: dict | None = None,
) -> None:
    ctx.events.append(NormalizedEvent(
        run_id=ctx.run_id,
        scenario_id=ctx.scenario.scenario_id,
        host=host,
        event_type=event_type,
        timestamp=datetime.now(timezone.utc).isoformat(),
        severity=severity,
        details={
            "source_host": source_host,
            "account": account,
            **(extra or {}),
        },
    ))
