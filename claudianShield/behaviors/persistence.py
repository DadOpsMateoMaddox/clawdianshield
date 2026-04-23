from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from runner.models import RunContext, NormalizedEvent


PERSISTENCE_PATHS = [
    "/etc/cron.d/cls-test",
    "/etc/systemd/system/cls-test.service",
    "~/.bashrc.cls-test",
]


class PersistenceBehavior:
    name = "persistence_path_changes"

    def run(self, ctx: RunContext) -> None:
        host = ctx.scenario.hosts[0]
        base = Path("/tmp/clawdianshield/persistence")
        base.mkdir(parents=True, exist_ok=True)

        for p in PERSISTENCE_PATHS:
            synthetic = base / Path(p).name
            synthetic.write_text(f"# cls synthetic persistence artifact: {p}\n")
            self._emit(ctx, host, "persistence_path_write", {
                "synthetic_path": str(synthetic),
                "emulated_path": p,
            }, "critical")

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
