from __future__ import annotations

import json
from pathlib import Path
from runner.models import Scenario, SafetyConstraints


def load(path: str | Path) -> Scenario:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    sc_data = data.pop("safety_constraints", {})
    return Scenario(
        **data,
        safety_constraints=SafetyConstraints(**sc_data) if sc_data else SafetyConstraints(),
    )
