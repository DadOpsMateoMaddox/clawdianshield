from __future__ import annotations

from datetime import datetime, timezone
from runner.models import NormalizedEvent


def normalize(raw: dict) -> NormalizedEvent:
    """
    Convert a raw dict (e.g. from a syslog parser or OS hook) into a NormalizedEvent.
    Fields not present in raw are defaulted safely.
    """
    return NormalizedEvent(
        run_id=raw.get("run_id", "unknown"),
        scenario_id=raw.get("scenario_id", "unknown"),
        host=raw.get("host", "unknown"),
        event_type=raw.get("event_type", "unknown"),
        timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        severity=raw.get("severity", "info"),
        details=raw.get("details", {}),
    )
