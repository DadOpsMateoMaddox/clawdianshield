from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from runner.models import RunContext, NormalizedEvent


class RemoteArtifactBehavior:
    """
    Induces defender-visible artifacts of cross-host remote execution.
    No real lateral movement logic — synthetic artifact chain only.
    """

    name = "remote_execution_artifacts"

    def run(self, ctx: RunContext) -> None:
        source = ctx.scenario.hosts[0]
        target = ctx.scenario.hosts[-1] if len(ctx.scenario.hosts) > 1 else source

        # Remote task/service creation trace on target host
        self._emit(ctx, target, "remote_service_create", {
            "source_host": source,
            "service_name": "cls-lab-svc",
            "emulated_path": "SYSTEM\\CurrentControlSet\\Services\\cls-lab-svc",
        }, "critical")

        time.sleep(0.05)

        # File drop in admin-share-like synthetic path
        drop_dir = Path("/tmp/clawdianshield/admin_share")
        drop_dir.mkdir(parents=True, exist_ok=True)
        dropped = drop_dir / "svc_payload.bat"
        dropped.write_text("REM cls synthetic remote drop artifact\n", encoding="utf-8")

        self._emit(ctx, target, "remote_file_drop", {
            "source_host": source,
            "path": str(dropped),
            "emulated_share": "\\\\server-1\\ADMIN$\\svc_payload.bat",
        }, "critical")

        time.sleep(0.05)

        # Short-lived command execution trace
        self._emit(ctx, target, "remote_exec_trace", {
            "source_host": source,
            "command": "cmd.exe /c whoami",
            "process": "svchost.exe",
            "note": "synthetic trace only — no real execution",
        }, "high")

        ctx.metadata["remote_artifact"] = {
            "source": source,
            "target": target,
            "drop_path": str(dropped),
        }

    def _emit(
        self, ctx: RunContext, host: str, event_type: str, details: dict, severity: str
    ) -> None:
        ctx.events.append(NormalizedEvent(
            run_id=ctx.run_id,
            scenario_id=ctx.scenario.scenario_id,
            host=host,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity=severity,
            details=details,
        ))
