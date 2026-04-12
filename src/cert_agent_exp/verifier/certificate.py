"""Certificate representation and validation.

A certificate φ = (g, E, C) accompanies each agent action:
  g  = goal reference   (must match task-allowed goals)
  E  = evidence list     (source IDs cited; must be trusted)
  C  = constraints       (action constraints satisfied)

The verifier checks:
  1. action ∈ allowed_actions
  2. g ∈ Γ(G)           (goal matches task)
  3. ∀ e ∈ E: source(e) = trusted
  4. taint(C) = 0       (no payload leakage)
"""

from typing import Any


def make_certificate(
    span_hash: str,
    source_id: str,
    privileged: bool = False,
) -> dict[str, Any]:
    return {
        "span_hash": span_hash,
        "source_id": source_id,
        "privileged": privileged,
    }


def make_structured_certificate(
    goal: str,
    evidence: list[str],
    constraints: list[str],
) -> dict[str, Any]:
    """Build a certificate φ = (g, E, C)."""
    return {
        "goal": goal,
        "evidence": evidence,
        "constraints": constraints,
    }


def validate_certificate(
    certificate: dict[str, Any],
    task: dict[str, Any],
    trusted_sources: set[str] | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Validate certificate against the task specification.

    Returns (valid, reason, debug).
    """
    debug: dict[str, Any] = {
        "goal_valid": False,
        "evidence_valid": False,
        "constraints_valid": False,
        "checks": [],
    }

    if not certificate:
        return False, "missing_certificate", debug

    goal = certificate.get("goal", "")
    evidence = certificate.get("evidence", [])
    constraints = certificate.get("constraints", [])

    allowed_goals = set(task.get("goal_refs", []))
    if not allowed_goals:
        allowed_goals = {"answer_question"}
    goal_valid = goal in allowed_goals
    debug["goal_valid"] = goal_valid
    debug["goal_claimed"] = goal
    debug["goals_allowed"] = list(allowed_goals)
    debug["checks"].append(("goal_match", goal_valid, f"{goal} ∈ {allowed_goals}"))

    if not goal_valid:
        return False, "goal_mismatch", debug

    if trusted_sources is not None and evidence:
        untrusted = [e for e in evidence if e not in trusted_sources]
        evidence_valid = len(untrusted) == 0
        debug["evidence_valid"] = evidence_valid
        debug["evidence_cited"] = evidence
        debug["untrusted_sources"] = untrusted
        debug["checks"].append(("evidence_provenance", evidence_valid,
                                f"{len(untrusted)} untrusted of {len(evidence)}"))
        if not evidence_valid:
            return False, "untrusted_evidence", debug
    else:
        debug["evidence_valid"] = True
        debug["checks"].append(("evidence_provenance", True, "no trusted set or no evidence"))

    allowed_constraints = set(task.get("constraints", []))
    if constraints and allowed_constraints:
        constraint_set = set(constraints)
        foreign = constraint_set - allowed_constraints
        constraints_valid = len(foreign) == 0
        debug["constraints_valid"] = constraints_valid
        debug["constraints_claimed"] = constraints
        debug["foreign_constraints"] = list(foreign)
        debug["checks"].append(("constraint_integrity", constraints_valid,
                                f"{len(foreign)} foreign constraints"))
        if not constraints_valid:
            return False, "foreign_constraints", debug
    else:
        debug["constraints_valid"] = True
        debug["checks"].append(("constraint_integrity", True, "no constraints to check"))

    return True, "ok", debug
