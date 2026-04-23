from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from runner.models import NormalizedEvent, RunContext


def snapshot(paths: list[str]) -> Dict[str, str]:
    """Return {path: sha256_hex} for each path that exists."""
    result: Dict[str, str] = {}
    for p in paths:
        try:
            data = Path(p).read_bytes()
            result[p] = hashlib.sha256(data).hexdigest()
        except (FileNotFoundError, PermissionError):
            result[p] = "missing"
    return result


def diff(before: Dict[str, str], after: Dict[str, str]) -> list[dict]:
    """Return list of change records between two snapshots."""
    changes = []
    all_keys = set(before) | set(after)
    for path in all_keys:
        b, a = before.get(path), after.get(path)
        if b != a:
            changes.append({"path": path, "before": b, "after": a})
    return changes


def emit_diff(ctx: RunContext, changes: list[dict]) -> None:
    for change in changes:
        ctx.events.append(NormalizedEvent(
            run_id=ctx.run_id,
            scenario_id=ctx.scenario.scenario_id,
            host=ctx.scenario.hosts[0],
            event_type="file_hash_delta",
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity="high",
            details=change,
        ))
