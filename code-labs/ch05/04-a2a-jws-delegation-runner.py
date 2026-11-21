"""A2A v1.0.0 JWS-signed Agent Card & async Task delegation runner.

Uses PyJWT (HS256/JWS) to sign and verify Agent Cards from
03-a2a-agent-cards.json, rejects tampered or unsigned cards, and
runs asynchronous Task state machines returning structured Artifacts.
"""

import asyncio
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import time
from typing import Any
import uuid
import jwt

HERE = Path(__file__).resolve().parent
CARDS_FILE = HERE / "03-a2a-agent-cards.json"
DEFAULT_SECRET = os.getenv(
    "A2A_JWS_SECRET", "orderflow-a2a-jws-hs256-dev-key-32b!"
)


class CardVerificationError(ValueError):
    """Raised when an A2A Agent Card fails JWS or safety checks."""


@dataclass
class A2ATask:
    """Represents an asynchronous A2A Protocol v1.0.0 Task."""

    task_id: str
    requester: str
    target_agent: str
    intent: str
    payload: dict[str, Any]
    state: str = "submitted"
    history: list[str] = field(default_factory=lambda: ["submitted"])
    artifact: dict[str, Any] | None = None

    def transition(self, next_state: str) -> None:
        """Record an explicit A2A task lifecycle state transition."""
        self.state = next_state
        self.history.append(next_state)


def load_agent_cards(
    path: Path = CARDS_FILE,
) -> dict[str, dict[str, Any]]:
    """Load and validate A2A v1.0.0 Agent Cards metadata."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("protocol") != "A2A":
        raise ValueError("Unsupported protocol; expected A2A")
    if data.get("jws_signed") is not True:
        raise CardVerificationError("Bundle jws_signed must be true")
    if data.get("expose_internal_memory") is True:
        raise CardVerificationError("Internal memory must stay opaque")
    return data["cards"]


def sign_agent_card(
    card: dict[str, Any], secret: str = DEFAULT_SECRET
) -> str:
    """Sign an Agent Card payload as a compact HS256 JWS token."""
    if card.get("jws_signed") is not True:
        raise CardVerificationError("Card must set jws_signed=true")
    if card.get("expose_internal_memory") is True:
        raise CardVerificationError("Card cannot expose internal memory")

    now = int(time.time())
    claims = {
        "iss": "orderflow-kagent-registry",
        "sub": card["agent_id"],
        "iat": now,
        "exp": now + 3600,
        "protocol": "A2A",
        "protocol_version": card.get("protocol_version", "1.0.0"),
        "jws_signed": True,
        "expose_internal_memory": False,
        "card": card,
    }
    return jwt.encode(claims, secret, algorithm="HS256")


def verify_agent_card(
    token: str,
    secret: str = DEFAULT_SECRET,
    expected_agent_id: str | None = None,
) -> dict[str, Any]:
    """Verify a JWS-signed Agent Card and enforce opaque memory."""
    if not token or token.count(".") != 2:
        raise CardVerificationError("Malformed or unsigned JWS token")

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise CardVerificationError(f"Invalid JWS header: {exc}") from exc

    if header.get("alg") != "HS256":
        raise CardVerificationError(
            f"Disallowed JWS algorithm: {header.get('alg')}"
        )

    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"require": ["iss", "sub", "iat", "exp"]},
        )
    except jwt.PyJWTError as exc:
        raise CardVerificationError(f"JWS verify failed: {exc}") from exc

    if claims.get("jws_signed") is not True:
        raise CardVerificationError("Claim jws_signed must be true")
    if claims.get("expose_internal_memory") is not False:
        raise CardVerificationError("Agent memory exposure prohibited")

    card = claims.get("card", {})
    agent_id = card.get("agent_id")
    if expected_agent_id and agent_id != expected_agent_id:
        raise CardVerificationError(
            f"Agent mismatch: {agent_id} != {expected_agent_id}"
        )
    return card


def _execute_specialist_skill(
    target_agent: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Produce deterministic specialist evidence with opaque memory."""
    incident_id = payload.get("incident_id", "INC-2026-1120-0200")
    if target_agent == "orderflow-metrics-agent":
        return {
            "incident_id": incident_id,
            "service": "order-service",
            "burn_rate_5m": 14.8,
            "error_budget_remaining_pct": 64.2,
            "cited_promql": "orderflow:http_errors:ratio_rate5m",
        }
    if target_agent == "orderflow-trace-agent":
        return {
            "incident_id": incident_id,
            "root_service": "order-service",
            "rollout_revision": "8f2c19a",
            "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
            "pruned_symptom": "payment-worker OOMKilled (+4m)",
        }
    raise ValueError(f"Unknown A2A specialist: {target_agent}")


async def dispatch_a2a_task(
    requester_token: str,
    target_token: str,
    expected_target_id: str,
    intent: str,
    payload: dict[str, Any],
    secret: str = DEFAULT_SECRET,
) -> A2ATask:
    """Verify cards and run async submitted->working->completed."""
    requester = verify_agent_card(requester_token, secret=secret)
    target = verify_agent_card(
        target_token,
        secret=secret,
        expected_agent_id=expected_target_id,
    )

    task = A2ATask(
        task_id=f"task-{uuid.uuid4().hex[:12]}",
        requester=requester["agent_id"],
        target_agent=target["agent_id"],
        intent=intent,
        payload=payload,
    )
    await asyncio.sleep(0)
    task.transition("working")
    await asyncio.sleep(0)

    result_data = _execute_specialist_skill(target["agent_id"], payload)
    task.artifact = {
        "artifact_id": f"art-{uuid.uuid4().hex[:10]}",
        "task_id": task.task_id,
        "producer": target["agent_id"],
        "protocol": "A2A/1.0.0",
        "opaque_memory_enforced": True,
        "parts": [{"type": "data", "data": result_data}],
    }
    task.transition("completed")
    return task


async def run_delegation_demo(
    cards_path: Path = CARDS_FILE, secret: str = DEFAULT_SECRET
) -> dict[str, Any]:
    """Execute coordinator->specialist A2A tasks & tamper rejection."""
    cards = load_agent_cards(cards_path)
    tokens = {
        agent_id: sign_agent_card(card, secret=secret)
        for agent_id, card in cards.items()
    }

    coord_tok = tokens["orderflow-kagent-coordinator"]
    metrics_task, trace_task = await asyncio.gather(
        dispatch_a2a_task(
            coord_tok,
            tokens["orderflow-metrics-agent"],
            "orderflow-metrics-agent",
            "slo-burn-analysis",
            {"incident_id": "INC-2026-1120-0200"},
            secret=secret,
        ),
        dispatch_a2a_task(
            coord_tok,
            tokens["orderflow-trace-agent"],
            "orderflow-trace-agent",
            "trace-exemplar-rca",
            {"incident_id": "INC-2026-1120-0200"},
            secret=secret,
        ),
    )

    hdr, body, sig = tokens["orderflow-trace-agent"].split(".")
    suffix = "AAAA" if not sig.endswith("AAAA") else "BBBB"
    tampered_token = f"{hdr}.{body}.{sig[:-4]}{suffix}"

    tamper_rejected = False
    try:
        verify_agent_card(tampered_token, secret=secret)
    except CardVerificationError:
        tamper_rejected = True

    return {
        "status": "A2A_DELEGATION_COMPLETE",
        "tamper_rejected": tamper_rejected,
        "tasks": [
            {
                "task_id": metrics_task.task_id,
                "target": metrics_task.target_agent,
                "history": metrics_task.history,
                "artifact": metrics_task.artifact,
            },
            {
                "task_id": trace_task.task_id,
                "target": trace_task.target_agent,
                "history": trace_task.history,
                "artifact": trace_task.artifact,
            },
        ],
        "consolidated_artifact": {
            "coordinator": "orderflow-kagent-coordinator",
            "root_cause": "order-service",
            "revision": "8f2c19a",
            "burn_rate_5m": 14.8,
        },
    }


def main() -> int:
    """CLI entrypoint running live JWS A2A delegation checks."""
    summary = asyncio.run(run_delegation_demo())
    assert summary["status"] == "A2A_DELEGATION_COMPLETE"
    assert summary["tamper_rejected"] is True
    for task in summary["tasks"]:
        assert task["history"] == ["submitted", "working", "completed"]
        assert task["artifact"]["opaque_memory_enforced"] is True
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
