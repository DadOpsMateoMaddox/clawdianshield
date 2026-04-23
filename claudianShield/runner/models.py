from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class SafetyConstraints:
    no_real_exploit_logic: bool = True
    no_real_credential_attack_logic: bool = True
    no_unapproved_network_spread: bool = True
    lab_environment_only: bool = True


@dataclass
class Scenario:
    scenario_id: str
    name: str
    class_name: str
    mode: str
    risk_level: str
    hosts: List[str]
    preconditions: List[str]
    behavior_profile: Dict[str, bool]
    expected_telemetry: Dict[str, bool]
    detections_expected: List[str]
    success_criteria: List[str]
    safety_constraints: SafetyConstraints = field(default_factory=SafetyConstraints)


@dataclass
class RunContext:
    run_id: str
    scenario: Scenario
    started_at: str
    host_map: Dict[str, Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)
    events: List["NormalizedEvent"] = field(default_factory=list)


@dataclass
class NormalizedEvent:
    run_id: str
    scenario_id: str
    host: str
    event_type: str
    timestamp: str
    severity: str
    details: Dict[str, Any]


@dataclass
class ScoreCard:
    run_id: str
    scenario_id: str
    detection_coverage: float
    telemetry_completeness: float
    correlation_quality: float
    timeliness: float
    analyst_usefulness: float
    overall: float = field(init=False, default=0.0)

    def __post_init__(self) -> None:
        self.overall = round(
            self.detection_coverage * 0.30
            + self.telemetry_completeness * 0.25
            + self.correlation_quality * 0.20
            + self.timeliness * 0.15
            + self.analyst_usefulness * 0.10,
            1,
        )

    @property
    def overall(self) -> float:
        return round(
            self.detection_coverage * 0.30
            + self.telemetry_completeness * 0.25
            + self.correlation_quality * 0.20
            + self.timeliness * 0.15
            + self.analyst_usefulness * 0.10,
            1,
        )
