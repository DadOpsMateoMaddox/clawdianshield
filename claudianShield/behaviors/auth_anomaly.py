from __future__ import annotations

import time
from datetime import datetime, timezone

from runner.models import RunContext, NormalizedEvent


class SyntheticAuthAnomalyBehavior:
    name = "auth_anomalies"

    def run(self, ctx: RunContext) -> None:
        source = ctx.scenario.hosts[0]
        target = ctx.scenario.hosts[-1]
        account = "svc-lab-user"

        for i in range(5):
            self._emit(ctx, target, "auth_failure", {
                "source_host": source, "account": account, "sequence": i + 1
            }, severity="medium")
            time.sleep(0.05)

        self._emit(ctx, target, "auth_success", {
            "source_host": source, "account": account, "sequence": 6
        }, severity="high")

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
