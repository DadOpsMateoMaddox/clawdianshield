from __future__ import annotations

from runner.models import Scenario


class SafetyError(Exception):
    pass


def validate(scenario: Scenario) -> None:
    sc = scenario.safety_constraints
    if not sc.lab_environment_only:
        raise SafetyError("Rejected: lab_environment_only must be true.")
    if not sc.no_real_exploit_logic:
        raise SafetyError("Rejected: real exploit logic is not allowed.")
    if not sc.no_real_credential_attack_logic:
        raise SafetyError("Rejected: real credential attack logic is not allowed.")
    if not sc.no_unapproved_network_spread:
        raise SafetyError("Rejected: unapproved network spread is not allowed.")
