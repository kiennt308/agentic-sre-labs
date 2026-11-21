"""OrderFlow Stateless Prometheus & Telemetry MCP Server (2026-07-28).

Implements an MCPServer over stateless Streamable HTTP exposing
query_slo_burn, fetch_otel_exemplar, and get_rollout_diff tools
backed by local telemetry snapshot JSON fixtures.
"""

import json
import os
from pathlib import Path
from typing import Any
from mcp.server.mcpserver import MCPServer, ResourceSecurity

HERE = Path(__file__).resolve().parent
DEFAULT_SNAPSHOT = "02-multi-signal-snapshot.json"

mcp = MCPServer(
    name="orderflow-prometheus-mcp",
    title="OrderFlow Multi-Signal Telemetry MCP",
    version="0.19.0",
    resource_security=ResourceSecurity(
        reject_path_traversal=True,
        reject_absolute_paths=True,
        reject_null_bytes=True,
    ),
)


def _load_snapshot(snapshot_path: str) -> dict[str, Any]:
    """Load a snapshot JSON safely confined to the ch04 directory."""
    if not snapshot_path or "\x00" in snapshot_path:
        raise ValueError("Invalid snapshot path")
    if ".." in snapshot_path or Path(snapshot_path).is_absolute():
        raise ValueError(f"Unsafe snapshot path: {snapshot_path}")

    candidate = (HERE / snapshot_path).resolve()
    if not candidate.exists() and snapshot_path.startswith("ch04/"):
        candidate = (HERE.parent / snapshot_path).resolve()
    if not candidate.is_relative_to(HERE) or not candidate.is_file():
        raise ValueError(f"Snapshot not found in ch04: {snapshot_path}")
    return json.loads(candidate.read_text(encoding="utf-8"))


@mcp.tool()
def query_slo_burn(
    service: str = "order-service",
    snapshot_path: str = DEFAULT_SNAPSHOT,
) -> str:
    """Return SLO burn rates, errors, and service symptoms."""
    data = _load_snapshot(snapshot_path)
    services = data.get("services", {})
    if service not in services:
        raise ValueError(f"Unknown service in snapshot: {service}")
    return json.dumps(
        {
            "incident_id": data.get("incident_id"),
            "namespace": data.get("namespace"),
            "slo": data.get("slo"),
            "anomaly_onset_utc": data.get("anomaly_onset_utc"),
            "slo_burn": data.get("slo_burn", {}),
            "target_service": service,
            "services": services,
        }
    )


@mcp.tool()
def fetch_otel_exemplar(
    service: str = "order-service",
    snapshot_path: str = DEFAULT_SNAPSHOT,
) -> str:
    """Fetch OpenTelemetry trace exemplars for root-cause linking."""
    data = _load_snapshot(snapshot_path)
    exemplars = data.get("otel_exemplars", [])
    matched = [
        ex
        for ex in exemplars
        if not service or ex.get("service") == service
    ]
    return json.dumps(
        {
            "service": service,
            "exemplar_count": len(exemplars),
            "service_exemplars": matched,
            "otel_exemplars": exemplars,
        }
    )


@mcp.tool()
def get_rollout_diff(
    namespace: str = "orderflow-prod",
    snapshot_path: str = DEFAULT_SNAPSHOT,
) -> str:
    """Return recent GitOps rollout diffs preceding anomaly onset."""
    data = _load_snapshot(snapshot_path)
    diffs = [
        diff
        for diff in data.get("rollout_diffs", [])
        if diff.get("namespace", namespace) == namespace
    ]
    return json.dumps(
        {
            "namespace": namespace,
            "diff_count": len(diffs),
            "rollout_diffs": diffs,
        }
    )


def build_stateless_http_app():
    """Return stateless Streamable HTTP ASGI app for MCP 2026-07-28."""
    return mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )


if __name__ == "__main__":
    port = int(os.getenv("MCP_PORT", "18091"))
    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=port,
        stateless_http=True,
        json_response=True,
    )
