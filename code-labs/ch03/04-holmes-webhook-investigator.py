"""HolmesGPT v0.46.0 webhook replay investigator with allowed_tools.

Parses an Alertmanager v0.35.0 webhook payload, enforces the strict
MCP allowed_tools whitelist from 02-holmesgpt-mcp-toolsets.yaml,
rejects disallowed tools such as delete_pod, and emits cited RCA.
"""

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
import yaml

HERE = Path(__file__).resolve().parent
TOOLSETS_FILE = HERE / "02-holmesgpt-mcp-toolsets.yaml"
PAYLOAD_FILE = HERE / "03-burn-rate-alert-payload.json"

REPLAY_EVIDENCE: dict[tuple[str, str], dict[str, Any]] = {
    ("prometheus-mcp", "execute_query"): {
        "metric": "orderflow:http_errors:ratio_rate5m",
        "value": 0.0074,
        "burn_rate": 14.8,
        "service": "order-service",
    },
    ("mcp-grafana", "query_loki_logs"): {
        "stream": "orderflow-prod/order-service",
        "matched_lines": 48,
        "sample": "DBPoolExhausted: timeout waiting for checkout conn",
    },
    ("kubernetes-mcp-server", "events_list"): {
        "namespace": "orderflow-prod",
        "event": "ScalingReplicaSet order-service-8f2c19a to 6",
        "timestamp": "2026-11-20T01:54:12Z",
    },
}


class DisallowedToolError(PermissionError):
    """Raised when an agent attempts an unapproved MCP tool call."""


@dataclass(frozen=True)
class ToolPolicy:
    """Validated MCP allowlist compiled from HolmesGPT config."""

    runtime: str
    trigger_type: str
    allowed_by_server: dict[str, set[str]]

    def check_tool(self, server: str, tool: str) -> None:
        """Raise DisallowedToolError unless server/tool is allowed."""
        tools = self.allowed_by_server.get(server)
        if not tools or tool not in tools:
            raise DisallowedToolError(
                f"Blocked tool '{tool}' on server '{server}'"
            )


def load_tool_policy(path: Path = TOOLSETS_FILE) -> ToolPolicy:
    """Load and validate HolmesGPT MCP allowed_tools configuration."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    spec = raw.get("spec", raw)
    runtime = spec.get("agent_runtime", "")
    trigger = spec.get("trigger_type", "")
    if runtime != "holmesgpt":
        raise ValueError(f"Unexpected runtime: {runtime}")
    if trigger != "mwmbr_burn_rate":
        raise ValueError(f"Unsupported trigger_type: {trigger}")

    allowed: dict[str, set[str]] = {}
    for srv_name, cfg in spec.get("mcpServers", {}).items():
        if cfg.get("transport") != "streamable-http":
            raise ValueError(f"{srv_name} must use streamable-http")
        if "kubernetes" in srv_name and cfg.get("read_only") is not True:
            raise ValueError(f"{srv_name} must enforce read_only: true")
        tools = cfg.get("allowed_tools", [])
        if not tools:
            raise ValueError(f"{srv_name} has empty allowed_tools")
        allowed[srv_name] = set(tools)

    return ToolPolicy(
        runtime=runtime,
        trigger_type=trigger,
        allowed_by_server=allowed,
    )


def call_mcp_replay(
    policy: ToolPolicy,
    server: str,
    tool: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Execute a deterministic offline MCP tool call under allowlist."""
    policy.check_tool(server, tool)
    evidence = REPLAY_EVIDENCE.get((server, tool), {})
    return {
        "server": server,
        "tool": tool,
        "params": params,
        "result": evidence,
    }


def investigate_webhook(
    payload_path: Path = PAYLOAD_FILE,
    toolsets_path: Path = TOOLSETS_FILE,
) -> dict[str, Any]:
    """Run offline HolmesGPT triage on an Alertmanager webhook."""
    policy = load_tool_policy(toolsets_path)
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    if payload.get("status") != "firing" or not payload.get("alerts"):
        raise ValueError("Webhook payload has no firing alerts")

    alert = payload["alerts"][0]
    labels = alert["labels"]
    snap = payload.get("slo_snapshot", {})
    alertname = labels["alertname"]
    namespace = labels["namespace"]
    service = labels["service"]
    burn_rate = float(
        snap.get("burn_rate", alert["annotations"]["burn_rate"])
    )

    blocked_tools: list[str] = []
    try:
        call_mcp_replay(
            policy,
            "kubernetes-mcp-server",
            "delete_pod",
            {"namespace": namespace, "pod": f"{service}-0"},
        )
    except DisallowedToolError as exc:
        blocked_tools.append(str(exc))

    calls = [
        call_mcp_replay(
            policy,
            "prometheus-mcp",
            "execute_query",
            {"query": "orderflow:http_errors:ratio_rate5m"},
        ),
        call_mcp_replay(
            policy,
            "mcp-grafana",
            "query_loki_logs",
            {"namespace": namespace, "service": service},
        ),
        call_mcp_replay(
            policy,
            "kubernetes-mcp-server",
            "events_list",
            {"namespace": namespace},
        ),
    ]

    return {
        "status": "INVESTIGATION_COMPLETE",
        "agent_runtime": policy.runtime,
        "autonomy_level": 1,
        "alertname": alertname,
        "namespace": namespace,
        "service": service,
        "slo": labels["slo"],
        "burn_rate": burn_rate,
        "root_cause_hypothesis": (
            "order-service checkout DB pool exhaustion after rev 8f2c19a"
        ),
        "allowed_tools_enforced": True,
        "blocked_tools": blocked_tools,
        "cited_evidence": calls,
    }


def main() -> int:
    """CLI entrypoint verifying allowlist enforcement and replay RCA."""
    report = investigate_webhook()
    assert report["status"] == "INVESTIGATION_COMPLETE"
    assert report["alertname"] == "OrderFlowCheckoutFastBurn"
    assert report["burn_rate"] == 14.8
    assert report["allowed_tools_enforced"] is True
    assert len(report["blocked_tools"]) == 1
    assert "delete_pod" in report["blocked_tools"][0]
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
