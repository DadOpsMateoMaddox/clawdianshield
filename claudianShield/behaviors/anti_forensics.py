from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from runner.models import RunContext, NormalizedEvent


class AntiForensicsBehavior:
    name = "anti_forensics"

    def run(self, ctx: RunContext) -> None:
        host = ctx.scenario.hosts[0]
        base = Path("/tmp/clawdianshield/logs")
        base.mkdir(parents=True, exist_ok=True)

        # Simulate log truncation
        fake_log = base / "audit.log"
        fake_log.write_text("event1\nevent2\nevent3\n")
        self._emit(ctx, host, "log_truncate", {"path": str(fake_log)}, "critical")
        fake_log.write_text("")  # truncate

        # Simulate log deletion
        fake_log2 = base / "syslog.bak"
        fake_log2.write_text("old syslog data\n")
        self._emit(ctx, host, "log_delete", {"path": str(fake_log2)}, "critical")
        fake_log2.unlink()

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
