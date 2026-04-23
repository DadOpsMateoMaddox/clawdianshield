from __future__ import annotations

import hashlib
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from runner.models import RunContext, NormalizedEvent


class FileTamperBehavior:
    name = "file_tamper"

    def run(self, ctx: RunContext) -> None:
        base = Path(ctx.metadata.get("tamper_root", "/tmp/clawdianshield"))
        base.mkdir(parents=True, exist_ok=True)
        host = ctx.scenario.hosts[0]

        target = base / "sensitive.conf"
        target.write_text("mode=baseline\n", encoding="utf-8")
        before_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        self._emit(ctx, host, "file_create", {"path": str(target), "hash": before_hash})

        time.sleep(0.1)
        target.write_text("mode=modified\n", encoding="utf-8")
        self._emit(ctx, host, "file_modify", {"path": str(target)})

        renamed = base / "sensitive.conf.bak"
        shutil.move(str(target), str(renamed))
        self._emit(ctx, host, "file_rename", {"from": str(target), "to": str(renamed)})

        replacement = base / "sensitive.conf"
        replacement.write_text("mode=replaced\n", encoding="utf-8")
        after_hash = hashlib.sha256(replacement.read_bytes()).hexdigest()
        self._emit(ctx, host, "file_create", {"path": str(replacement), "hash": after_hash})

        ctx.metadata["file_tamper"] = {"before_hash": before_hash, "after_hash": after_hash}

    def _emit(self, ctx: RunContext, host: str, event_type: str, details: dict) -> None:
        ctx.events.append(NormalizedEvent(
            run_id=ctx.run_id,
            scenario_id=ctx.scenario.scenario_id,
            host=host,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity="high",
            details=details,
        ))
