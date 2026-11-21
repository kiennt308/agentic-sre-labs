"""Three-Tier CNCF AI-SRE Router and Error-Budget Autonomy Gate.

Routes OrderFlow incidents across kubectl-ai (Tier 1), HolmesGPT
(Tier 2), and kagent v1.0.1 + A2A (Tier 3) while enforcing Bounded
Autonomy Levels 0-3 inside remaining SLO error budgets.
"""

import json
import sys

ERROR_BUDGET_L3_FLOOR_PCT = 20
MIN_TRUST_DAYS_FOR_L3 = 14
MAX_L3_ACTIONS_PER_INCIDENT = 2

FORBIDDEN_L3_ACTIONS = {
    "delete_pvc",
    "drop_database",
    "edit_iam",
    "delete_networkpolicy",
    "pods_exec",
    "force_sync_bypass",
}

TIER_BY_SIGNAL = {
    "interactive_cli": ("kubectl-ai", "orderflow-diag-cli"),
    "mwmbr_alert": ("HolmesGPT", "orderflow-alert-investigator"),
    "a2a_remediation": ("kagent v1.0.1", "orderflow-kagent-coordinator"),
}


def check_l3_eligibility(inc: dict) -> tuple[bool, str]:
    """Check error budget and circuit-breaker invariants for L3."""
    action = inc.get("proposed_action", "")
    if action in FORBIDDEN_L3_ACTIONS:
        return False, f"FORBIDDEN_L3_ACTION:{action}"
    budget = inc.get("error_budget_remaining_pct", 0)
    if budget < ERROR_BUDGET_L3_FLOOR_PCT:
        return False, f"ERROR_BUDGET_EXHAUSTED:{budget}pct<20pct"
    trust_days = inc.get("progressive_trust_days", 0)
    if trust_days < MIN_TRUST_DAYS_FOR_L3:
        return False, f"DAY1_L3_DENIED:{trust_days}d<14d"
    if not inc.get("guaranteed_rollback_path", False):
        return False, "NO_ROLLBACK_PATH"
    if inc.get("cooldown_active", False):
        return False, "COOLDOWN_ACTIVE"
    if inc.get("actions_this_incident", 0) >= MAX_L3_ACTIONS_PER_INCIDENT:
        return False, "ACTION_CAP_REACHED"
    return True, "L3_POLICY_PASSED"


def route_incident(inc: dict) -> dict:
    """Assign CNCF tier and compute gated Autonomy Level (0-3)."""
    sig = inc["signal_source"]
    tier, agent_id = TIER_BY_SIGNAL[sig]
    requested = int(inc["requested_level"])
    effective = requested
    decision = "APPROVED"
    reason = "POLICY_PASSED"

    if sig == "interactive_cli" and requested > 0:
        effective = 0
        decision = "DOWNGRADED"
        reason = "CLI_READONLY_L0"
    elif sig == "mwmbr_alert" and requested > 1:
        effective = 1
        decision = "DOWNGRADED"
        reason = "ALERT_TRIAGE_L1"
    elif requested == 3:
        ok, reason = check_l3_eligibility(inc)
        if not ok:
            effective = 1
            decision = "DOWNGRADED"
    elif requested == 2:
        branch = inc.get("head_branch", "")
        if not branch.startswith("agent/sre-"):
            effective = 1
            decision = "DOWNGRADED"
            reason = "SRE_BRANCH_PREFIX"

    return {
        "incident_id": inc["incident_id"],
        "tier": tier,
        "agent_id": agent_id,
        "requested_level": requested,
        "effective_level": effective,
        "budget_pct": inc.get("error_budget_remaining_pct", 0),
        "decision": decision,
        "reason": reason,
        "action": inc.get("proposed_action", ""),
    }


SAMPLE_INCIDENTS = [
    {
        "incident_id": "INC-101",
        "signal_source": "interactive_cli",
        "requested_level": 0,
        "error_budget_remaining_pct": 72,
        "proposed_action": "kubectl_get_logs",
    },
    {
        "incident_id": "INC-102",
        "signal_source": "mwmbr_alert",
        "requested_level": 1,
        "error_budget_remaining_pct": 55,
        "proposed_action": "correlate_prometheus_traces",
    },
    {
        "incident_id": "INC-103",
        "signal_source": "a2a_remediation",
        "requested_level": 3,
        "error_budget_remaining_pct": 64,
        "progressive_trust_days": 30,
        "guaranteed_rollback_path": True,
        "cooldown_active": False,
        "actions_this_incident": 0,
        "proposed_action": "argo_rollouts_abort",
    },
    {
        "incident_id": "INC-104",
        "signal_source": "a2a_remediation",
        "requested_level": 3,
        "error_budget_remaining_pct": 14,
        "progressive_trust_days": 30,
        "guaranteed_rollback_path": True,
        "cooldown_active": False,
        "actions_this_incident": 0,
        "proposed_action": "argo_rollouts_abort",
    },
    {
        "incident_id": "INC-105",
        "signal_source": "a2a_remediation",
        "requested_level": 3,
        "error_budget_remaining_pct": 64,
        "progressive_trust_days": 0,
        "guaranteed_rollback_path": False,
        "cooldown_active": False,
        "actions_this_incident": 0,
        "proposed_action": "delete_pvc",
    },
]


def main() -> int:
    decisions = [route_incident(inc) for inc in SAMPLE_INCIDENTS]
    for row in decisions:
        print(json.dumps(row))
    by_id = {d["incident_id"]: d for d in decisions}
    assert by_id["INC-101"]["tier"] == "kubectl-ai"
    assert by_id["INC-101"]["effective_level"] == 0
    assert by_id["INC-102"]["tier"] == "HolmesGPT"
    assert by_id["INC-102"]["effective_level"] == 1
    assert by_id["INC-103"]["tier"] == "kagent v1.0.1"
    assert by_id["INC-103"]["effective_level"] == 3
    assert by_id["INC-104"]["effective_level"] == 1
    assert by_id["INC-105"]["effective_level"] == 1
    print("[PASS] 3-tier routing and L3 budget gates verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
