from __future__ import annotations

from runner.models import RunContext, ScoreCard


def score(ctx: RunContext) -> ScoreCard:
    observed_types = {e.event_type for e in ctx.events}
    expected_telemetry = ctx.scenario.expected_telemetry

    # Telemetry completeness: fraction of expected event classes observed
    telemetry_hits = sum(
        1 for k, required in expected_telemetry.items()
        if required and k.replace("_", " ") in " ".join(observed_types).replace("_", " ")
    )
    telemetry_completeness = round(
        (telemetry_hits / max(len(expected_telemetry), 1)) * 100, 1
    )

    # Detection coverage: fraction of expected detections present in metadata
    detections_observed = ctx.metadata.get("detections_fired", [])
    detection_hits = sum(
        1 for d in ctx.scenario.detections_expected if d in detections_observed
    )
    detection_coverage = round(
        (detection_hits / max(len(ctx.scenario.detections_expected), 1)) * 100, 1
    )

    # Correlation quality: cross-host events present
    hosts_seen = {e.host for e in ctx.events}
    correlation_quality = 100.0 if len(hosts_seen) > 1 else 50.0

    # Timeliness: placeholder — real impl would compare event timestamps to cleanup phase
    timeliness = ctx.metadata.get("timeliness_score", 75.0)

    # Analyst usefulness: placeholder — real impl would score alert narrative quality
    analyst_usefulness = ctx.metadata.get("analyst_usefulness_score", 70.0)

    return ScoreCard(
        run_id=ctx.run_id,
        scenario_id=ctx.scenario.scenario_id,
        detection_coverage=detection_coverage,
        telemetry_completeness=telemetry_completeness,
        correlation_quality=correlation_quality,
        timeliness=timeliness,
        analyst_usefulness=analyst_usefulness,
    )
