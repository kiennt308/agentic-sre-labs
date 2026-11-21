"""OrderFlow Autonomy Levels 0-3 circuit-breaker controller."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

MIN_ERROR_BUDGET_PCT = 20.0
COOLDOWN_SECONDS = 900
MAX_ACTIONS_PER_INCIDENT = 2
MIN_TRUST_DAYS_L3 = 14

FORBIDDEN_L3_ACTIONS = frozenset({
    "delete_pvc",
    "drop_database",
    "edit_iam",
    "delete_networkpolicy",
    "pods_exec",
    "force_sync_bypass",
})

REVERSIBLE_L3_ACTIONS = frozenset({
    "argo_rollouts_abort",
    "enable_priority_load_shedding",
    "isolate_crashloop_pod_pdb",
})


@dataclass(frozen=True)
class CircuitBreakerDecision:
    """Result of evaluating an OrderFlow remediation request."""

    requested_level: int
    effective_level: int
    allowed: bool
    downgraded: bool
    violations: tuple[str, ...]
    summary: str


def _check_common_guards(cfg: dict[str, Any]) -> list[str]:
    """Validate forbidden actions and ICS human lock status."""
    errors: list[str] = []
    actions = cfg.get("proposed_actions", [])
    for act in actions:
        if act in FORBIDDEN_L3_ACTIONS:
            errors.append(
                f"FORBIDDEN_L3_ACTION: {act} needs human owner"
            )
    if (
        cfg.get("ics_human_lock_active") is True
        and cfg.get("autonomous_mutation_requested") is True
    ):
        errors.append(
            "ICS_HUMAN_LOCK_CONFLICT: Ops human owns lock"
        )
    return errors


def _check_l2_guards(cfg: dict[str, Any]) -> list[str]:
    """Validate Level 2 GitOps rollback PR branch naming."""
    errors: list[str] = []
    branch = cfg.get("head_branch", "")
    if not branch.startswith("agent/sre-"):
        errors.append(
            "SRE_BRANCH_PREFIX: L2 PR must use agent/sre-"
        )
    return errors


def _check_l3_guards(cfg: dict[str, Any]) -> list[str]:
    """Enforce Level 3 trust, budget, cooldown, and action caps."""
    errors: list[str] = []
    trust_days = cfg.get("progressive_trust_days", 0)
    if trust_days < MIN_TRUST_DAYS_L3:
        errors.append(
            "DAY1_L3_DENIED: require >=14d progressive trust"
        )
    if cfg.get("guaranteed_rollback_path") is not True:
        errors.append(
            "NO_ROLLBACK_PATH: L3 needs guaranteed rollback"
        )
    budget = cfg.get("error_budget_remaining_pct", 0.0)
    if budget < MIN_ERROR_BUDGET_PCT:
        errors.append(
            "ERROR_BUDGET_EXHAUSTED: budget < 20%; drop to L1"
        )
    actions_done = cfg.get("actions_this_incident", 0)
    proposed = cfg.get("proposed_actions", [])
    if cfg.get("cooldown_active") is True:
        errors.append(
            "COOLDOWN_ACTIVE: wait 900s before L3 retry"
        )
    elif actions_done > 0:
        elapsed = cfg.get("seconds_since_last_action")
        floor = max(
            COOLDOWN_SECONDS,
            int(cfg.get("cooldown_seconds", COOLDOWN_SECONDS)),
        )
        if elapsed is not None and elapsed < floor:
            errors.append(
                f"COOLDOWN_ACTIVE: {elapsed}s < {floor}s window"
            )
    if (
        actions_done >= MAX_ACTIONS_PER_INCIDENT
        or (actions_done + len(proposed)) > MAX_ACTIONS_PER_INCIDENT
    ):
        errors.append(
            "ACTION_CAP_REACHED: max 2 L3 actions exceeded"
        )
    for act in proposed:
        if (
            act not in FORBIDDEN_L3_ACTIONS
            and act not in REVERSIBLE_L3_ACTIONS
        ):
            errors.append(
                f"NON_REVERSIBLE_L3_ACTION: {act} disallowed"
            )
    return errors


def evaluate_request(payload: dict[str, Any]) -> CircuitBreakerDecision:
    """Evaluate a request and downgrade to Level 1 on violation."""
    cfg = payload.get("spec", payload)
    level = int(cfg.get("autonomy_level", 0))
    if level not in (0, 1, 2, 3):
        return CircuitBreakerDecision(
            requested_level=level,
            effective_level=1,
            allowed=False,
            downgraded=True,
            violations=("INVALID_AUTONOMY_LEVEL",),
            summary=f"Unknown level {level}; forced Level 1",
        )

    violations = _check_common_guards(cfg)
    if level == 2:
        violations.extend(_check_l2_guards(cfg))
    elif level == 3:
        violations.extend(_check_l3_guards(cfg))

    if violations:
        eff = 1 if level >= 2 else level
        return CircuitBreakerDecision(
            requested_level=level,
            effective_level=eff,
            allowed=False,
            downgraded=(eff != level),
            violations=tuple(violations),
            summary=(
                f"Blocked L{level} ({len(violations)} "
                f"violations); downgraded to L{eff}"
            ),
        )

    return CircuitBreakerDecision(
        requested_level=level,
        effective_level=level,
        allowed=True,
        downgraded=False,
        violations=(),
        summary=f"Approved OrderFlow L{level} request",
    )


def _load_json(path: Path) -> dict[str, Any]:
    """Read UTF-8 JSON fixture from disk."""
    return json.loads(path.read_text(encoding="utf-8"))


def run_self_tests() -> None:
    """Verify controller against fixtures 02, 03, 04, and edges."""
    lab_dir = Path(__file__).resolve().parent

    l2 = evaluate_request(
        _load_json(lab_dir / "02-autonomy-l2-rollback-pr.json")
    )
    assert l2.allowed is True
    assert l2.effective_level == 2
    assert l2.downgraded is False
    assert l2.violations == ()

    l3_ok = evaluate_request(
        _load_json(lab_dir / "03-autonomy-l3-safe-abort.json")
    )
    assert l3_ok.allowed is True
    assert l3_ok.effective_level == 3
    assert l3_ok.downgraded is False
    assert l3_ok.violations == ()

    l3_bad = evaluate_request(
        _load_json(lab_dir / "04-autonomy-l3-blocked-negative.json")
    )
    assert l3_bad.allowed is False
    assert l3_bad.effective_level == 1
    assert l3_bad.downgraded is True
    assert len(l3_bad.violations) >= 4
    joined = " | ".join(l3_bad.violations)
    for code in (
        "ERROR_BUDGET_EXHAUSTED",
        "COOLDOWN_ACTIVE",
        "ACTION_CAP_REACHED",
        "FORBIDDEN_L3_ACTION",
    ):
        assert code in joined, f"Missing expected violation {code}"

    cooldown_edge = evaluate_request({
        "autonomy_level": 3,
        "progressive_trust_days": 21,
        "guaranteed_rollback_path": True,
        "error_budget_remaining_pct": 55,
        "cooldown_active": False,
        "seconds_since_last_action": 450,
        "actions_this_incident": 1,
        "proposed_actions": ["argo_rollouts_abort"],
    })
    assert cooldown_edge.allowed is False
    assert cooldown_edge.effective_level == 1
    assert any("COOLDOWN_ACTIVE" in v for v in cooldown_edge.violations)

    l0 = evaluate_request({"autonomy_level": 0})
    assert l0.allowed is True and l0.effective_level == 0

    for label, res in (
        ("02-l2-pr", l2),
        ("03-l3-safe", l3_ok),
        ("04-l3-blocked", l3_bad),
        ("edge-cooldown", cooldown_edge),
    ):
        print(f"[{label}] {res.summary}")
    print("All circuit-breaker self-tests passed.")


if __name__ == "__main__":
    run_self_tests()
