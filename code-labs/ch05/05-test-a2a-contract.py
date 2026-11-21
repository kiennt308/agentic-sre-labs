"""Pytest contract suite for A2A v1.0.0 JWS Agent Cards and Tasks."""

import asyncio
import base64
from importlib import util
import json
from pathlib import Path
import pytest

HERE = Path(__file__).resolve().parent
RUNNER_FILE = HERE / "04-a2a-jws-delegation-runner.py"
CARDS_FILE = HERE / "03-a2a-agent-cards.json"


def _load_runner():
    """Dynamically load 04-a2a-jws-delegation-runner.py."""
    spec = util.spec_from_file_location("a2a_runner", RUNNER_FILE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {RUNNER_FILE}")
    mod = util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RUNNER = _load_runner()


def test_valid_jws_signing_and_verification() -> None:
    """All three OrderFlow Agent Cards sign and verify cleanly."""
    cards = RUNNER.load_agent_cards(CARDS_FILE)
    assert set(cards.keys()) == {
        "orderflow-kagent-coordinator",
        "orderflow-metrics-agent",
        "orderflow-trace-agent",
    }
    for agent_id, card in cards.items():
        token = RUNNER.sign_agent_card(card)
        verified = RUNNER.verify_agent_card(
            token, expected_agent_id=agent_id
        )
        assert verified["agent_id"] == agent_id
        assert verified["jws_signed"] is True
        assert verified["expose_internal_memory"] is False


def test_rejects_tampered_payload_and_unsigned_alg_none() -> None:
    """Modified JWS payload or alg=none token must raise error."""
    cards = RUNNER.load_agent_cards(CARDS_FILE)
    token = RUNNER.sign_agent_card(cards["orderflow-metrics-agent"])
    hdr, body, sig = token.split(".")

    padded = body + "=" * (-len(body) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    claims["sub"] = "rogue-admin-agent"
    tampered_body = (
        base64.urlsafe_b64encode(json.dumps(claims).encode())
        .decode()
        .rstrip("=")
    )
    with pytest.raises(RUNNER.CardVerificationError):
        RUNNER.verify_agent_card(f"{hdr}.{tampered_body}.{sig}")

    none_hdr = (
        base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}')
        .decode()
        .rstrip("=")
    )
    with pytest.raises(RUNNER.CardVerificationError):
        RUNNER.verify_agent_card(f"{none_hdr}.{body}.")


def test_rejects_memory_leaking_card() -> None:
    """Cards exposing internal agent memory must fail signing."""
    cards = RUNNER.load_agent_cards(CARDS_FILE)
    bad_card = dict(cards["orderflow-trace-agent"])
    bad_card["expose_internal_memory"] = True
    with pytest.raises(RUNNER.CardVerificationError):
        RUNNER.sign_agent_card(bad_card)


def test_async_a2a_task_lifecycle_and_artifact() -> None:
    """Coordinator delegates async Tasks and collects Artifacts."""
    summary = asyncio.run(RUNNER.run_delegation_demo(CARDS_FILE))
    assert summary["status"] == "A2A_DELEGATION_COMPLETE"
    assert summary["tamper_rejected"] is True
    assert len(summary["tasks"]) == 2
    for task in summary["tasks"]:
        assert task["history"] == ["submitted", "working", "completed"]
        art = task["artifact"]
        assert art["opaque_memory_enforced"] is True
        assert art["parts"][0]["type"] == "data"


def test_delegation_aborts_on_tampered_specialist_card() -> None:
    """Task dispatch aborts before running if specialist card tampered."""
    cards = RUNNER.load_agent_cards(CARDS_FILE)
    coord_tok = RUNNER.sign_agent_card(
        cards["orderflow-kagent-coordinator"]
    )
    bad_tok = RUNNER.sign_agent_card(cards["orderflow-trace-agent"]) + "x"
    with pytest.raises(RUNNER.CardVerificationError):
        asyncio.run(
            RUNNER.dispatch_a2a_task(
                coord_tok,
                bad_tok,
                "orderflow-trace-agent",
                "trace-exemplar-rca",
                {"incident_id": "INC-2026-1120-0200"},
            )
        )
