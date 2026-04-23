from __future__ import annotations

import argparse
import json
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path

from runner.loader import load
from runner.models import RunContext
from runner.orchestrator import Orchestrator
from runner.scoring import score
from runner.reporting import generate


def main() -> None:
    parser = argparse.ArgumentParser(description="ClawdianShield scenario runner")
    parser.add_argument("scenario", help="Path to scenario JSON file")
    parser.add_argument("--reports", default="reports", help="Output directory for reports")
    args = parser.parse_args()

    scenario = load(args.scenario)
    run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    ctx = RunContext(
        run_id=run_id,
        scenario=scenario,
        started_at=datetime.now(timezone.utc).isoformat(),
        host_map={h: {"hostname": h} for h in scenario.hosts},
    )

    print(f"[{run_id}] Running: {scenario.name}")
    Orchestrator().execute(ctx)

    scorecard = score(ctx)
    report_path = generate(ctx, scorecard, output_dir=args.reports)

    print(f"[{run_id}] Score: {scorecard.overall}/100")
    print(f"[{run_id}] Report: {report_path}")


if __name__ == "__main__":
    main()
