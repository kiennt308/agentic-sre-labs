"""2:00 AM ICS AI Scribe, Sitrep builder, and lock conflict guard."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any

MAX_BOT_MESSAGES_PER_WINDOW = 2


class HumanLockConflictError(RuntimeError):
    """Raised when an agent mutates an Ops-locked workload."""

    code = "ICS_HUMAN_LOCK_CONFLICT"


@dataclass(frozen=True)
class PublishResult:
    """Outcome of enforcing the per-window bot chatter budget."""

    posted: bool
    suppressed: bool
    window_id: str
    count_in_window: int
    reason: str


@dataclass(frozen=True)
class SitrepReport:
    """Structured 15-minute ICS Situation Report."""

    incident_id: str
    window_label: str
    ic: str
    ops_lead: str
    comms_lead: str
    impact: str
    current_burn_rate: float
    error_budget_remaining_pct: float
    active_mitigations: tuple[str, ...]
    ruled_out_hypotheses: tuple[str, ...]
    active_human_locks: tuple[str, ...]
    conflicts: tuple[str, ...]
    next_check_in: str

    def render_markdown(self) -> str:
        """Render a concise commander-ready Sitrep message."""
        lines = [
            f"### ICS Sitrep {self.incident_id} ({self.window_label})",
            (
                f"- **Roles:** IC={self.ic}, "
                f"Ops={self.ops_lead}, Comms={self.comms_lead}"
            ),
            f"- **Impact:** {self.impact}",
            (
                f"- **Current SLO Burn:** {self.current_burn_rate}x "
                f"(Budget left: {self.error_budget_remaining_pct}%)"
            ),
            "- **Active Mitigations:**",
        ]
        for item in self.active_mitigations or ("None recorded",):
            lines.append(f"  - {item}")
        lines.append("- **Ruled-Out Hypotheses:**")
        for item in self.ruled_out_hypotheses or ("None recorded",):
            lines.append(f"  - {item}")
        if self.active_human_locks:
            lines.append("- **Active Ops Locks:**")
            for lock in self.active_human_locks:
                lines.append(f"  - {lock}")
        if self.conflicts:
            lines.append("- **Conflicts Blocked:**")
            for conflict in self.conflicts:
                lines.append(f"  - {conflict}")
        lines.append(f"- **Next Check-In:** {self.next_check_in}")
        return "\n".join(lines)


def _parse_utc(ts_value: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp ending in Z."""
    return datetime.fromisoformat(ts_value.replace("Z", "+00:00"))


def _format_utc(dt: datetime) -> str:
    """Format a UTC datetime back to ISO-8601 Z string."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ICSScribeConflictGuard:
    """Synthesize Sitreps, cap bot chatter, and block lock clashes."""

    def __init__(
        self,
        max_bot_messages_per_window: int = MAX_BOT_MESSAGES_PER_WINDOW,
    ) -> None:
        self.max_bot_messages_per_window = max_bot_messages_per_window
        self._window_counts: dict[str, int] = defaultdict(int)

    def publish_bot_message(
        self, window_id: str, message: str
    ) -> PublishResult:
        """Allow at most max_bot_messages_per_window bot posts."""
        _ = message
        current = self._window_counts[window_id]
        if current >= self.max_bot_messages_per_window:
            return PublishResult(
                posted=False,
                suppressed=True,
                window_id=window_id,
                count_in_window=current,
                reason="BOT_CHATTER_BUDGET_EXCEEDED",
            )
        new_count = current + 1
        self._window_counts[window_id] = new_count
        return PublishResult(
            posted=True,
            suppressed=False,
            window_id=window_id,
            count_in_window=new_count,
            reason="ALLOWED",
        )

    @staticmethod
    def _find_lock(
        locks: list[dict[str, Any]], workload: str
    ) -> dict[str, Any] | None:
        """Return matching active lock for a workload, if present."""
        for lock in locks:
            if lock.get("workload") == workload:
                return lock
        return None

    def guard_mutation(
        self,
        locks: list[dict[str, Any]],
        workload: str,
        actor: str,
        action: str,
        is_agent: bool = True,
    ) -> None:
        """Raise ICS_HUMAN_LOCK_CONFLICT if mutation clashes."""
        lock = self._find_lock(locks, workload)
        if lock is None:
            return
        owner = str(lock.get("owner", "ops-human"))
        if not is_agent and actor == owner:
            return
        raise HumanLockConflictError(
            f"ICS_HUMAN_LOCK_CONFLICT: {actor} blocked from {action} "
            f"on {workload}; locked by {owner}"
        )

    def scan_timeline_conflicts(
        self, timeline: dict[str, Any]
    ) -> list[str]:
        """Collect all lock conflicts across proposed agent actions."""
        locks = list(timeline.get("active_locks", []))
        conflicts: list[str] = []
        for event in timeline.get("events", []):
            if event.get("type") != "agent_action_proposed":
                continue
            workload = str(event.get("workload", ""))
            actor = str(event.get("actor", "agent"))
            action = str(event.get("action", "mutate"))
            try:
                self.guard_mutation(
                    locks=locks,
                    workload=workload,
                    actor=actor,
                    action=action,
                    is_agent=True,
                )
            except HumanLockConflictError as exc:
                conflicts.append(str(exc))
        return conflicts

    def synthesize_sitrep(
        self, timeline: dict[str, Any]
    ) -> SitrepReport:
        """Build a 15-minute ICS Sitrep from war-room events."""
        start_dt = _parse_utc(timeline["started_at"])
        win_mins = int(timeline.get("window_minutes", 15))
        end_dt = start_dt + timedelta(minutes=win_mins)
        window_label = (
            f"{start_dt.strftime('%H:%MZ')} - "
            f"{end_dt.strftime('%H:%MZ')}"
        )

        roles = timeline.get("ics_roles", {})
        events = timeline.get("events", [])
        impact = timeline.get("title", "Active incident")
        burn_rate = 0.0
        budget_pct = 100.0
        mitigations: list[str] = []
        ruled_out: list[str] = []

        for ev in events:
            ev_type = ev.get("type")
            if ev_type == "alert_fired":
                impact = str(ev.get("summary", impact))
            if "burn_rate" in ev:
                burn_rate = float(ev["burn_rate"])
            if "error_budget_remaining_pct" in ev:
                budget_pct = float(ev["error_budget_remaining_pct"])
            if ev_type == "mitigation_active":
                text = str(ev.get("summary", ""))
                if text and text not in mitigations:
                    mitigations.append(text)
            elif ev_type == "hypothesis_ruled_out":
                hyp = str(
                    ev.get("hypothesis") or ev.get("summary", "")
                )
                if hyp and hyp not in ruled_out:
                    ruled_out.append(hyp)

        locks = list(timeline.get("active_locks", []))
        lock_lines = tuple(
            f"{lk['workload']} (owner: {lk['owner']})" for lk in locks
        )
        conflicts = tuple(self.scan_timeline_conflicts(timeline))

        return SitrepReport(
            incident_id=str(timeline.get("incident_id", "INC-0000")),
            window_label=window_label,
            ic=str(roles.get("IC", "unassigned")),
            ops_lead=str(roles.get("Ops", "unassigned")),
            comms_lead=str(roles.get("Comms", "unassigned")),
            impact=impact,
            current_burn_rate=burn_rate,
            error_budget_remaining_pct=budget_pct,
            active_mitigations=tuple(mitigations),
            ruled_out_hypotheses=tuple(ruled_out),
            active_human_locks=lock_lines,
            conflicts=conflicts,
            next_check_in=_format_utc(end_dt),
        )


def main() -> None:
    """Run local demo against 01-ics-war-room-events.json."""
    lab_dir = Path(__file__).resolve().parent
    timeline = json.loads(
        (lab_dir / "01-ics-war-room-events.json").read_text(
            encoding="utf-8"
        )
    )
    scribe = ICSScribeConflictGuard()
    report = scribe.synthesize_sitrep(timeline)
    first_post = scribe.publish_bot_message(
        report.window_label, report.render_markdown()
    )
    assert first_post.posted is True
    print(report.render_markdown())


if __name__ == "__main__":
    main()
