from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from runner.models import RunContext, ScoreCard


def generate(ctx: RunContext, scorecard: ScoreCard, output_dir: str | Path = "reports") -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    missed = [
        d for d in ctx.scenario.detections_expected
        if d not in ctx.metadata.get("detections_fired", [])
    ]

    report = {
        "run_id": ctx.run_id,
        "scenario_id": ctx.scenario.scenario_id,
        "scenario_name": ctx.scenario.name,
        "status": "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "score": {
            "overall": scorecard.overall,
            "detection_coverage": scorecard.detection_coverage,
            "telemetry_completeness": scorecard.telemetry_completeness,
            "correlation_quality": scorecard.correlation_quality,
            "timeliness": scorecard.timeliness,
            "analyst_usefulness": scorecard.analyst_usefulness,
        },
        "observed_event_types": sorted({e.event_type for e in ctx.events}),
        "hosts_observed": sorted({e.host for e in ctx.events}),
        "missed_detections": missed,
        "recommendations": ctx.metadata.get("recommendations", []),
    }

    out_path = output_dir / f"{ctx.run_id}.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return out_path
