"""Deterministic Replay Mock LLM Gateway for OrderFlow Agentic SRE.

Provides an OpenAI-compatible HTTP server on 127.0.0.1:18180 with
/v1/chat/completions and /healthz endpoints and zero API spend. Set
LLM_BASE_URL to point to local Ollama (http://127.0.0.1:11434/v1).
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import sys
import threading
import urllib.request

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18180
DEFAULT_BASE_URL = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}/v1"

REPLAY_TRACES = {
    1: {
        "thought": "Check recent Kubernetes Events for checkout pods.",
        "tool_call": {
            "name": "kubectl_get_events",
            "arguments": {
                "namespace": "orderflow-prod",
                "involved_object": "checkout-canary",
            },
        },
    },
    2: {
        "thought": "Measure OrderFlow 99.95% SLO burn rate over 5m.",
        "tool_call": {
            "name": "query_slo_burn",
            "arguments": {
                "service": "orderflow-checkout",
                "window": "5m",
                "slo_target": 99.95,
            },
        },
    },
    3: {
        "thought": "14.4x burn confirmed; abort Argo Rollout canary.",
        "tool_call": {
            "name": "argo_rollouts_abort",
            "arguments": {
                "namespace": "orderflow-prod",
                "rollout": "checkout-canary",
                "autonomy_level": 3,
            },
        },
    },
}


def resolve_llm_base_url() -> str:
    """Return overridden LLM_BASE_URL or default local gateway."""
    override = os.getenv("LLM_BASE_URL", "").strip()
    return override if override else DEFAULT_BASE_URL


def infer_turn(body: dict) -> int:
    """Resolve trace turn from explicit field or message history."""
    if "turn" in body:
        return int(body["turn"])
    messages = body.get("messages", [])
    tool_turns = sum(1 for msg in messages if msg.get("role") == "tool")
    return tool_turns + 1


def deterministic_chat_response(turn: int) -> dict:
    """Return reproducible OpenAI-style tool trace for turn k."""
    step = REPLAY_TRACES.get(turn)
    model = os.getenv("LLM_MODEL", "orderflow-sre-replay-v1")
    if not step:
        return {
            "model": model,
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Completed deterministic SRE trace.",
                    "tool_calls": [],
                }
            }],
        }
    call = step["tool_call"]
    return {
        "model": model,
        "choices": [{
            "message": {
                "role": "assistant",
                "content": step["thought"],
                "tool_calls": [{
                    "id": f"call_sre_turn_{turn}",
                    "type": "function",
                    "function": {
                        "name": call["name"],
                        "arguments": json.dumps(call["arguments"]),
                    },
                }],
            }
        }],
    }


def forward_upstream(base_url: str, raw_body: bytes) -> bytes:
    """Forward chat completion request to configured LLM_BASE_URL."""
    url = f"{base_url.rstrip('/')}/chat/completions"
    req = urllib.request.Request(
        url,
        data=raw_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read()


class ReusableHTTPServer(HTTPServer):
    """HTTPServer allowing immediate port reuse across restarts."""

    allow_reuse_address = True


class SreReplayHandler(BaseHTTPRequestHandler):
    """Serve /healthz and /v1/chat/completions offline."""

    def _send_json(self, code: int, payload: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/healthz":
            err = json.dumps({"error": "not found"}).encode()
            self._send_json(404, err)
            return
        body = {
            "status": "ok",
            "llm_base_url": resolve_llm_base_url(),
            "turns": sorted(REPLAY_TRACES),
        }
        self._send_json(200, json.dumps(body).encode())

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/chat/completions":
            err = json.dumps({"error": "not found"}).encode()
            self._send_json(404, err)
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) or b"{}"
        upstream = os.getenv("LLM_BASE_URL", "").strip()
        self_port = f":{self.server.server_port}"
        if upstream and self_port not in upstream:
            payload = forward_upstream(upstream, raw_body)
            self._send_json(200, payload)
            return
        body = json.loads(raw_body)
        resp = deterministic_chat_response(infer_turn(body))
        self._send_json(200, json.dumps(resp).encode())

    def log_message(self, fmt: str, *args: object) -> None:
        return


def run_self_test(port: int) -> int:
    """Boot gateway in a daemon thread and verify replay endpoints."""
    srv = ReusableHTTPServer((DEFAULT_HOST, port), SreReplayHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    base = f"http://{DEFAULT_HOST}:{port}"
    try:
        with urllib.request.urlopen(f"{base}/healthz", timeout=5) as r:
            assert r.status == 200
            health = json.loads(r.read())
            assert health["status"] == "ok"
        expected = [
            "kubectl_get_events",
            "query_slo_burn",
            "argo_rollouts_abort",
        ]
        for idx, tool_name in enumerate(expected, start=1):
            req = urllib.request.Request(
                f"{base}/v1/chat/completions",
                data=json.dumps({"turn": idx}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                assert r.status == 200
                data = json.loads(r.read())
                msg = data["choices"][0]["message"]
                got = msg["tool_calls"][0]["function"]["name"]
                assert got == tool_name, f"{got} != {tool_name}"
        prev = os.environ.get("LLM_BASE_URL")
        os.environ["LLM_BASE_URL"] = "http://127.0.0.1:11434/v1"
        assert resolve_llm_base_url() == "http://127.0.0.1:11434/v1"
        if prev is None:
            os.environ.pop("LLM_BASE_URL", None)
        else:
            os.environ["LLM_BASE_URL"] = prev
        print(f"[PASS] self-test ok on {base}/v1 ({len(expected)} turns)")
        return 0
    finally:
        srv.shutdown()
        srv.server_close()


def main() -> int:
    port = int(os.getenv("SRE_REPLAY_PORT", str(DEFAULT_PORT)))
    if "--self-test" in sys.argv:
        return run_self_test(port)
    if "--serve" in sys.argv:
        srv = ReusableHTTPServer((DEFAULT_HOST, port), SreReplayHandler)
        print(f"SRE replay gateway listening on {DEFAULT_BASE_URL}")
        srv.serve_forever()
        return 0
    for turn in (1, 2, 3, 4):
        out = deterministic_chat_response(turn)
        msg = out["choices"][0]["message"]
        tools = [c["function"]["name"] for c in msg["tool_calls"]]
        print(f"turn={turn} thought={msg['content']} tools={tools}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
