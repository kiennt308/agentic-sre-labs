"""Live MCP Client causal RCA correlator over Streamable HTTP.

Boots 01-prometheus-mcp-server.py on a free localhost port, connects
with mcp.Client over HTTP (protocol 2026-07-28), isolates root cause
in 02-multi-signal-snapshot.json, and verifies safe abstention on
05-inconclusive-telemetry-snapshot.json.
"""

import asyncio
from importlib import util
import json
from pathlib import Path
import socket
import threading
import time
from typing import Any
from mcp import Client
import uvicorn

HERE = Path(__file__).resolve().parent
SERVER_FILE = HERE / "01-prometheus-mcp-server.py"


def _load_server_module():
    """Dynamically load 01-prometheus-mcp-server.py."""
    spec = util.spec_from_file_location("prom_mcp_srv", SERVER_FILE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {SERVER_FILE}")
    mod = util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _find_free_port() -> int:
    """Reserve an unused ephemeral localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_port(host: str, port: int, timeout: float = 5.0) -> None:
    """Wait until the background Uvicorn HTTP socket accepts TCP."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"MCP HTTP server did not bind {host}:{port}")


def correlate_signals(
    burn_data: dict[str, Any],
    exemplar_data: dict[str, Any],
    rollout_data: dict[str, Any],
) -> dict[str, Any]:
    """Correlate SLO burn, OTel exemplars, and rollout diffs."""
    exemplars = exemplar_data.get("otel_exemplars", [])
    diffs = rollout_data.get("rollout_diffs", [])
    services = burn_data.get("services", {})

    if not exemplars or not diffs:
        missing = []
        if not exemplars:
            missing.append("otel_exemplars")
        if not diffs:
            missing.append("rollout_diffs")
        return {
            "status": "INCONCLUSIVE_EVIDENCE",
            "reason": f"Missing required signals: {', '.join(missing)}",
            "root_cause": None,
            "revision": None,
            "pruned_symptoms": [],
        }

    scores: dict[str, int] = {svc: 0 for svc in services}
    rev_by_service: dict[str, str] = {}

    for diff in diffs:
        svc = diff["service"]
        if svc in scores and diff.get("offset_seconds", 0) <= 0:
            scores[svc] += 50
            rev_by_service[svc] = diff["revision"]

    for ex in exemplars:
        svc = ex["service"]
        if svc in scores and ex.get("status") == "ERROR":
            if "DBPoolExhausted" in ex.get("error", ""):
                scores[svc] += 35
            else:
                scores[svc] += 10

    for svc, meta in services.items():
        if meta.get("offset_seconds", 999) <= 0:
            scores[svc] += 25
        if meta.get("upstream") in services:
            scores[svc] -= 15

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    root_cause = ranked[0][0]
    pruned = [svc for svc, _ in ranked[1:]]

    return {
        "status": "ROOT_CAUSE_IDENTIFIED",
        "root_cause": root_cause,
        "revision": rev_by_service.get(root_cause),
        "confidence_score": ranked[0][1],
        "pruned_symptoms": pruned,
        "cited_trace_ids": [ex["trace_id"] for ex in exemplars],
    }


async def _query_snapshot(
    client: Client, snapshot_name: str
) -> dict[str, Any]:
    """Fetch all three MCP signals for a snapshot and correlate."""
    burn_res = await client.call_tool(
        "query_slo_burn",
        {"service": "order-service", "snapshot_path": snapshot_name},
    )
    assert burn_res.is_error is False
    ex_res = await client.call_tool(
        "fetch_otel_exemplar",
        {"service": "order-service", "snapshot_path": snapshot_name},
    )
    assert ex_res.is_error is False
    diff_res = await client.call_tool(
        "get_rollout_diff",
        {"namespace": "orderflow-prod", "snapshot_path": snapshot_name},
    )
    assert diff_res.is_error is False

    burn_json = json.loads(burn_res.content[0].text)
    ex_json = json.loads(ex_res.content[0].text)
    diff_json = json.loads(diff_res.content[0].text)
    return correlate_signals(burn_json, ex_json, diff_json)


async def run_live_correlator() -> dict[str, Any]:
    """Boot live HTTP MCP server and correlate both ch04 snapshots."""
    mod = _load_server_module()
    port = _find_free_port()
    app = mod.build_stateless_http_app()
    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="error"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    try:
        _wait_port("127.0.0.1", port)
        url = f"http://127.0.0.1:{port}/mcp"
        async with Client(url) as client:
            assert client.protocol_version == "2026-07-28"
            tools = await client.list_tools()
            tool_names = sorted(t.name for t in tools.tools)
            assert tool_names == [
                "fetch_otel_exemplar",
                "get_rollout_diff",
                "query_slo_burn",
            ]

            full_rca = await _query_snapshot(
                client, "02-multi-signal-snapshot.json"
            )
            abstention_rca = await _query_snapshot(
                client, "05-inconclusive-telemetry-snapshot.json"
            )
            return {
                "mcp_protocol": client.protocol_version,
                "tools": tool_names,
                "full_rca": full_rca,
                "abstention_rca": abstention_rca,
            }
    finally:
        server.should_exit = True
        thread.join(timeout=3.0)


def main() -> int:
    """Run live MCP RCA verification and assert expected outputs."""
    output = asyncio.run(run_live_correlator())
    full = output["full_rca"]
    abstain = output["abstention_rca"]

    assert full["status"] == "ROOT_CAUSE_IDENTIFIED"
    assert full["root_cause"] == "order-service"
    assert full["revision"] == "8f2c19a"
    assert "payment-worker" in full["pruned_symptoms"]
    assert abstain["status"] == "INCONCLUSIVE_EVIDENCE"

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
