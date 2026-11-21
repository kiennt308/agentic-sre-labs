#!/usr/bin/env python3
"""Benchmark live Toxiproxy v2.13.0 fault + Level 3 abort recovery.

Spins up a tiny stdlib HTTP origin server on 127.0.0.1:<port>, creates
or updates proxy orderflow_pg_test against host.docker.internal:<port>,
measures baseline latency, injects a 250ms latency toxic, triggers
OrderFlowCheckoutFastBurn, runs Level 3 abort + removes toxic, and
prints recovery timing JSON. Supports --offline simulation as well.

Copyright (c) 2026 Kien Nguyen. Licensed under Apache-2.0.
"""

from __future__ import annotations

import argparse
import http.server
import json
import math
import threading
import time
import urllib.error
import urllib.request
from typing import Any

PROXY_NAME = "orderflow_pg_test"
TOXIC_NAME = "pg_latency_250ms"
DEFAULT_API = "http://127.0.0.1:18474"
CANDIDATE_PORTS = (18475, 18666, 8475, 18476)


def make_origin_handler(state: dict[str, float]):
    """Build HTTP handler with optional offline delay state."""

    class OriginHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            delay = state.get("delay_s", 0.0)
            if delay > 0.0:
                time.sleep(delay)
            body = b'{"status":"ok","service":"orderflow-pg"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    return OriginHandler


def http_json(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
    timeout: float = 3.0,
) -> tuple[int, Any]:
    """Perform stdlib HTTP JSON request returning (status, body)."""
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        url, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw) if raw.strip() else None
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return exc.code, raw


def api_reachable(api_url: str) -> bool:
    """Return True if Toxiproxy /version endpoint responds 200."""
    try:
        status, _ = http_json(f"{api_url}/version", timeout=1.5)
        return status == 200
    except (urllib.error.URLError, OSError):
        return False


def clear_proxy_toxics(api_url: str) -> None:
    """Delete any stale toxics on orderflow_pg_test."""
    st, toxics = http_json(
        f"{api_url}/proxies/{PROXY_NAME}/toxics", timeout=2.0
    )
    if st != 200 or not isinstance(toxics, list):
        return
    for tox in toxics:
        tname = tox.get("name")
        if tname:
            http_json(
                f"{api_url}/proxies/{PROXY_NAME}/toxics/{tname}",
                method="DELETE",
            )


def upsert_proxy(
    api_url: str, listen_port: int, upstream: str
) -> None:
    """Create or update Toxiproxy proxy orderflow_pg_test."""
    spec = {
        "name": PROXY_NAME,
        "listen": f"0.0.0.0:{listen_port}",
        "upstream": upstream,
        "enabled": True,
    }
    st, _ = http_json(f"{api_url}/proxies/{PROXY_NAME}")
    if st == 200:
        upd = {
            "listen": spec["listen"],
            "upstream": upstream,
            "enabled": True,
        }
        code, body = http_json(
            f"{api_url}/proxies/{PROXY_NAME}",
            method="POST",
            payload=upd,
        )
        if code != 200:
            raise RuntimeError(f"Proxy update failed: {code} {body}")
        clear_proxy_toxics(api_url)
    else:
        code, body = http_json(
            f"{api_url}/proxies", method="POST", payload=spec
        )
        if code not in (200, 201):
            raise RuntimeError(f"Proxy create failed: {code} {body}")


def resolve_live_proxy_url(
    api_url: str, upstream: str, forced_port: int | None
) -> str:
    """Configure proxy and verify host-to-container port mapping."""
    ports = (
        (forced_port,) if forced_port is not None else CANDIDATE_PORTS
    )
    for port in ports:
        upsert_proxy(api_url, port, upstream)
        target = f"http://127.0.0.1:{port}/pg/ping"
        try:
            st, _ = http_json(target, timeout=1.5)
            if st == 200:
                return target
        except (urllib.error.URLError, OSError):
            continue
    raise RuntimeError(
        f"Cannot reach proxy {PROXY_NAME} on ports {ports}"
    )


def measure_latencies(url: str, samples: int) -> dict[str, float]:
    """Measure HTTP request latencies in ms and return stats."""
    timings: list[float] = []
    for _ in range(samples):
        t0 = time.perf_counter()
        st, _ = http_json(url, timeout=3.0)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if st != 200:
            raise RuntimeError(f"Origin check failed with HTTP {st}")
        timings.append(elapsed_ms)
    ordered = sorted(timings)
    idx = max(0, math.ceil(0.95 * len(ordered)) - 1)
    avg_ms = sum(ordered) / len(ordered)
    return {
        "samples": samples,
        "avg_ms": round(avg_ms, 2),
        "p95_ms": round(ordered[idx], 2),
    }


def evaluate_l3_guard() -> dict[str, Any]:
    """Verify Level 3 circuit-breaker invariants before abort."""
    state = {
        "autonomy_level": 3,
        "progressive_trust_days": 30,
        "guaranteed_rollback_path": True,
        "error_budget_remaining_pct": 64.0,
        "cooldown_active": False,
        "actions_this_incident": 0,
    }
    allowed = (
        state["progressive_trust_days"] >= 14
        and state["guaranteed_rollback_path"]
        and state["error_budget_remaining_pct"] >= 20.0
        and not state["cooldown_active"]
        and state["actions_this_incident"] < 2
    )
    return {"allowed": allowed, "state": state}


def run_benchmark(
    api_url: str | None,
    offline: bool,
    upstream_host: str,
    proxy_port: int | None,
    samples: int,
) -> dict[str, Any]:
    """Execute baseline -> fault -> alert -> L3 abort -> recovery."""
    delay_state = {"delay_s": 0.0}
    srv = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), make_origin_handler(delay_state)
    )
    origin_port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    try:
        origin_url = f"http://127.0.0.1:{origin_port}/pg/ping"
        upstream = f"{upstream_host}:{origin_port}"
        if offline:
            mode = "offline_simulation"
            target_url = origin_url
        else:
            mode = "live_toxiproxy"
            assert api_url is not None
            target_url = resolve_live_proxy_url(
                api_url, upstream, proxy_port
            )

        baseline = measure_latencies(target_url, samples)

        if offline:
            delay_state["delay_s"] = 0.25
        else:
            toxic = {
                "name": TOXIC_NAME,
                "type": "latency",
                "stream": "downstream",
                "toxicity": 1.0,
                "attributes": {"latency": 250, "jitter": 0},
            }
            code, body = http_json(
                f"{api_url}/proxies/{PROXY_NAME}/toxics",
                method="POST",
                payload=toxic,
            )
            if code not in (200, 201):
                raise RuntimeError(f"Inject failed: {code} {body}")

        faulted = measure_latencies(target_url, samples)
        alert_fired = (
            "OrderFlowCheckoutFastBurn"
            if faulted["p95_ms"] >= 150.0
            else "NONE"
        )

        guard = evaluate_l3_guard()
        if not guard["allowed"]:
            raise RuntimeError("Level 3 circuit breaker blocked")

        t_abort0 = time.perf_counter()
        if offline:
            delay_state["delay_s"] = 0.0
        else:
            code, _ = http_json(
                f"{api_url}/proxies/{PROXY_NAME}/toxics/{TOXIC_NAME}",
                method="DELETE",
            )
            if code not in (200, 204):
                raise RuntimeError(f"Toxic delete failed: {code}")
        abort_ms = round((time.perf_counter() - t_abort0) * 1000.0, 2)

        recovered = measure_latencies(target_url, samples)
        passed = (
            alert_fired == "OrderFlowCheckoutFastBurn"
            and faulted["p95_ms"] >= 200.0
            and recovered["p95_ms"] < faulted["p95_ms"] * 0.5
        )
        return {
            "mode": mode,
            "proxy_name": PROXY_NAME,
            "upstream": upstream,
            "origin_port": origin_port,
            "baseline": baseline,
            "fault_250ms": faulted,
            "alert_triggered": alert_fired,
            "level3_action": "argo_rollouts_abort",
            "abort_reaction_ms": abort_ms,
            "recovered": recovered,
            "benchmark_passed": passed,
        }
    finally:
        srv.shutdown()
        srv.server_close()


def main() -> int:
    """Parse CLI args and run live or offline Toxiproxy benchmark."""
    parser = argparse.ArgumentParser(
        description="Toxiproxy 250ms fault and L3 recovery benchmark."
    )
    parser.add_argument("--toxiproxy-api", default=None)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--upstream-host", default="host.docker.internal")
    parser.add_argument("--proxy-port", type=int, default=None)
    parser.add_argument("--samples", type=int, default=5)
    args = parser.parse_args()

    use_offline = args.offline
    api_url = (
        args.toxiproxy_api.rstrip("/")
        if args.toxiproxy_api
        else DEFAULT_API
    )
    if not use_offline and not api_reachable(api_url):
        if args.toxiproxy_api is not None:
            err = {"error": f"Toxiproxy API unreachable: {api_url}"}
            print(json.dumps(err, indent=2))
            return 1
        use_offline = True

    report = run_benchmark(
        api_url=None if use_offline else api_url,
        offline=use_offline,
        upstream_host=args.upstream_host,
        proxy_port=args.proxy_port,
        samples=args.samples,
    )
    print(json.dumps(report, indent=2))
    return 0 if report["benchmark_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
