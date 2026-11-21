"""Pytest suite for ICS AI Scribe, rate limits, and lock guard."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import pytest

CH07_DIR = Path(__file__).resolve().parent
MODULE_PATH = CH07_DIR / "02-ics-scribe-conflict-guard.py"

_spec = importlib.util.spec_from_file_location(
    "ics_scribe_conflict_guard", MODULE_PATH
)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
sys.modules["ics_scribe_conflict_guard"] = _mod
_spec.loader.exec_module(_mod)

HumanLockConflictError = _mod.HumanLockConflictError
ICSScribeConflictGuard = _mod.ICSScribeConflictGuard


def _load_timeline() -> dict:
    """Load canonical 2:00 AM ICS war-room events fixture."""
    path = CH07_DIR / "01-ics-war-room-events.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_sitrep_synthesis_tracks_hypotheses_and_mitigations() -> None:
    """Sitrep separates ruled-out hypotheses and active mitigations."""
    scribe = ICSScribeConflictGuard()
    report = scribe.synthesize_sitrep(_load_timeline())

    assert report.incident_id == "INC-2042"
    assert report.ic == "maya-ic"
    assert report.ops_lead == "alice-ops"
    assert report.comms_lead == "devon-comms"
    assert report.current_burn_rate == 6.1
    assert report.error_budget_remaining_pct == 51.8
    assert report.next_check_in == "2026-11-20T02:15:00Z"

    assert "payment-worker OOMKilled root cause" in (
        report.ruled_out_hypotheses
    )
    assert "CoreDNS resolution latency spike" in (
        report.ruled_out_hypotheses
    )
    assert "Applying db-pool cap patch on order-service" in (
        report.active_mitigations
    )

    md = report.render_markdown()
    for heading in (
        "Impact:",
        "Current SLO Burn:",
        "Active Mitigations:",
        "Ruled-Out Hypotheses:",
        "Next Check-In:",
    ):
        assert heading in md


def test_bot_chatter_rate_limiting_enforces_max_two() -> None:
    """Only 2 bot messages are allowed per 15-min window."""
    scribe = ICSScribeConflictGuard(max_bot_messages_per_window=2)

    r1 = scribe.publish_bot_message("02:00Z - 02:15Z", "Sitrep #1")
    r2 = scribe.publish_bot_message("02:00Z - 02:15Z", "Conflict alert")
    r3 = scribe.publish_bot_message("02:00Z - 02:15Z", "Noisy update")
    r4 = scribe.publish_bot_message("02:15Z - 02:30Z", "Sitrep #2")

    assert r1.posted is True and r1.suppressed is False
    assert r2.posted is True and r2.suppressed is False
    assert r3.posted is False and r3.suppressed is True
    assert r3.reason == "BOT_CHATTER_BUDGET_EXCEEDED"
    assert r4.posted is True and r4.count_in_window == 1


def test_agent_mutation_on_ops_locked_workload_raises() -> None:
    """Agent mutating Ops-locked workload raises lock conflict."""
    timeline = _load_timeline()
    scribe = ICSScribeConflictGuard()
    locks = timeline["active_locks"]

    with pytest.raises(
        HumanLockConflictError, match="ICS_HUMAN_LOCK_CONFLICT"
    ) as exc_info:
        scribe.guard_mutation(
            locks=locks,
            workload="deployment/order-service",
            actor="orderflow-rollback-agent",
            action="argo_rollouts_abort",
            is_agent=True,
        )

    assert "alice-ops" in str(exc_info.value)
    conflicts = scribe.scan_timeline_conflicts(timeline)
    assert len(conflicts) == 1
    assert "ICS_HUMAN_LOCK_CONFLICT" in conflicts[0]


def test_lock_owner_and_unlocked_workloads_allowed() -> None:
    """Lock owner and unrelated unlocked workloads are not blocked."""
    locks = _load_timeline()["active_locks"]
    scribe = ICSScribeConflictGuard()

    scribe.guard_mutation(
        locks=locks,
        workload="deployment/order-service",
        actor="alice-ops",
        action="apply_hotfix_patch",
        is_agent=False,
    )
    scribe.guard_mutation(
        locks=locks,
        workload="deployment/checkout-cache",
        actor="orderflow-rollback-agent",
        action="argo_rollouts_abort",
        is_agent=True,
    )
