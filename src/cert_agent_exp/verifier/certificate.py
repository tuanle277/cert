"""Certificate representation and validation.

A certificate φ = (g, E, C) accompanies each agent action:
  g  = goal reference   (must match task-allowed goals)
  E  = evidence list     (source IDs cited; must be trusted)
  C  = constraints       (action constraints satisfied)

The verifier checks:
  1. action ∈ allowed_actions
  2. g ∈ Γ(G)           (goal matches task)
  3. ∀ e ∈ E: source(e) = trusted
  4. evidence spans match quoted/provenance content
  5. taint(C) = 0       (no payload leakage)
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


def _check_evidence_spans(
    evidence: list[str],
    chunk_texts: dict[str, str] | None,
    action_content: str,
) -> tuple[bool, list[str], dict[str, Any]]:
    """Verify that cited evidence IDs correspond to content actually present
    in the action's output (span matching).

    For each evidence ID, checks that at least a minimal n-gram overlap exists
    between the chunk's text and the action content, confirming the agent
    actually used (quoted) that source rather than citing it spuriously.

    Returns (all_matched, unmatched_ids, debug).
    """
    if not evidence or not chunk_texts or not action_content:
        return True, [], {"skipped": True, "reason": "no evidence, chunks, or content to match"}

    content_lower = action_content.lower()
    content_words = set(content_lower.split())
    unmatched: list[str] = []
    span_debug: list[dict[str, Any]] = []

    for eid in evidence:
        chunk_text = chunk_texts.get(eid, "")
        if not chunk_text:
            span_debug.append({"evidence_id": eid, "matched": False, "reason": "chunk_not_found"})
            unmatched.append(eid)
            continue

        chunk_words = set(chunk_text.lower().split())
        if not chunk_words:
            span_debug.append({"evidence_id": eid, "matched": False, "reason": "empty_chunk"})
            unmatched.append(eid)
            continue

        overlap = len(content_words & chunk_words)
        ratio = overlap / len(chunk_words) if chunk_words else 0.0
        # Require >= 10% word overlap as evidence the chunk was actually quoted
        matched = ratio >= 0.10
        span_debug.append({
            "evidence_id": eid,
            "matched": matched,
            "word_overlap": overlap,
            "overlap_ratio": round(ratio, 4),
        })
        if not matched:
            unmatched.append(eid)

    return len(unmatched) == 0, unmatched, {"per_evidence": span_debug}


def validate_certificate(
    certificate: dict[str, Any],
    task: dict[str, Any],
    trusted_sources: set[str] | None = None,
    chunk_texts: dict[str, str] | None = None,
    action_content: str = "",
) -> tuple[bool, str, dict[str, Any]]:
    """Validate certificate against the task specification.

    Args:
        certificate: The φ = (g, E, C) certificate from the agent.
        task: Trusted task specification with goal_refs, constraints, allowed_actions.
        trusted_sources: Set of source IDs known to be clean (not injected).
        chunk_texts: Mapping of chunk_id → text for evidence span verification.
        action_content: The agent's action content for span matching.

    Returns (valid, reason, debug).
    """
    debug: dict[str, Any] = {
        "goal_valid": False,
        "evidence_valid": False,
        "evidence_spans_valid": False,
        "constraints_valid": False,
        "checks": [],
    }

    if not certificate:
        return False, "missing_certificate", debug

    goal = certificate.get("goal", "")
    evidence = certificate.get("evidence", [])
    constraints = certificate.get("constraints", [])

    # Check 1: goal ∈ Γ(G)
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

    # Check 2: evidence provenance — all cited sources must be trusted
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

    # Check 3: evidence span matching — cited IDs must correspond to content
    # actually used in the action output (prevents spurious citation)
    spans_ok, unmatched_spans, span_dbg = _check_evidence_spans(
        evidence, chunk_texts, action_content,
    )
    debug["evidence_spans_valid"] = spans_ok
    debug["evidence_span_detail"] = span_dbg
    debug["checks"].append(("evidence_span_match", spans_ok,
                            f"{len(unmatched_spans)} unmatched spans"))
    if not spans_ok:
        debug["unmatched_evidence_spans"] = unmatched_spans
        return False, "evidence_span_mismatch", debug

    # Check 4: constraint integrity — no foreign constraints
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
