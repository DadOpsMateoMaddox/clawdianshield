from __future__ import annotations

import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from runner.models import RunContext, NormalizedEvent


class StagingBehavior:
    name = "staging"

    def run(self, ctx: RunContext) -> None:
        host = ctx.scenario.hosts[0]
        stage_dir = Path(tempfile.mkdtemp(prefix="cls_stage_"))

        # Enumerate sensitive-like paths
        sensitive_paths = ["/etc/passwd", "/etc/shadow", "~/.ssh/id_rsa"]
        for p in sensitive_paths:
            self._emit(ctx, host, "file_open", {"path": p, "reason": "enumeration"}, "high")

        # Create staging archive
        archive = stage_dir / "staged.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            # Add a dummy file to the archive
            dummy = stage_dir / "dummy.txt"
            dummy.write_text("staged content\n")
            tar.add(dummy, arcname="dummy.txt")

        self._emit(ctx, host, "archive_create", {"path": str(archive)}, "high")
        ctx.metadata["staging_archive"] = str(archive)

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
