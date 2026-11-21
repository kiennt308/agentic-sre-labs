#!/usr/bin/env python3
"""Audit postmortem JSON citations against SQLite evidence ledger.

Builds an ephemeral ledger inside tempfile.TemporaryDirectory() via
01-incident-evidence-ledger.py so zero .db files remain in ch08/.
Audits timestamps, PromQL IDs, trace_ids, and git_shas deterministically.

Copyright (c) 2026 Kien Nguyen. Licensed under Apache-2.0.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LEDGER_SCRIPT = BASE_DIR / "01-incident-evidence-ledger.py"
VALID_PM = BASE_DIR / "02-postmortem-valid.json"
BAD_PM = BASE_DIR / "03-postmortem-hallucinated.json"

TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b")
ID_RE = re.compile(r"\b(?:PQL|ALT)-[A-Za-z0-9-]+\b")
HEX_RE = re.compile(r"\b[0-9a-f]{12,16}\b")


def load_ledger_module():
    """Load 01-incident-evidence-ledger.py without code duplication."""
    spec = importlib.util.spec_from_file_location(
        "inc_ledger", LEDGER_SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {LEDGER_SCRIPT}")
    mod = importlib.util.module_from_spec(spec)
    prev = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = prev
    return mod


def fetch_incident_evidence(
    conn: sqlite3.Connection, incident_id: str
) -> dict | None:
    """Query canonical timestamps and evidence IDs for incident_id."""
    conn.row_factory = sqlite3.Row
    inc = conn.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,),
    ).fetchone()
    if inc is None:
        return None

    alerts = {
        r["alert_id"]: r["fired_at"]
        for r in conn.execute(
            "SELECT alert_id, fired_at FROM alerts "
            "WHERE incident_id = ?",
            (incident_id,),
        )
    }
    promql = {
        r["snapshot_id"]: r["captured_at"]
        for r in conn.execute(
            "SELECT snapshot_id, captured_at FROM promql_snapshots "
            "WHERE incident_id = ?",
            (incident_id,),
        )
    }
    traces = {
        r["trace_id"]: r["observed_at"]
        for r in conn.execute(
            "SELECT trace_id, observed_at FROM trace_exemplars "
            "WHERE incident_id = ?",
            (incident_id,),
        )
    }
    commits = {
        r["git_sha"]: r["committed_at"]
        for r in conn.execute(
            "SELECT git_sha, committed_at FROM git_commits "
            "WHERE incident_id = ?",
            (incident_id,),
        )
    }
    inc_times = {
        inc["started_at"],
        inc["mitigated_at"],
        inc["resolved_at"],
    }
    all_ts = (
        inc_times
        | set(alerts.values())
        | set(promql.values())
        | set(traces.values())
        | set(commits.values())
    )
    return {
        "incident": dict(inc),
        "incident_times": inc_times,
        "alerts": alerts,
        "promql": promql,
        "traces": traces,
        "commits": commits,
        "all_timestamps": all_ts,
        "all_hex": set(traces) | set(commits),
        "all_prefixed": set(alerts) | set(promql),
    }


def check_prose_tokens(
    text: str, label: str, ev: dict, findings: list[str]
) -> None:
    """Verify inline timestamps, IDs, and hex hashes in prose."""
    for ts in TS_RE.findall(text):
        if ts not in ev["all_timestamps"]:
            findings.append(f"{label}: unknown timestamp {ts}")
    for tok in ID_RE.findall(text):
        if tok not in ev["all_prefixed"]:
            findings.append(f"{label}: unknown ID {tok}")
    for hx in HEX_RE.findall(text):
        if hx not in ev["all_hex"]:
            findings.append(f"{label}: unknown hex ref {hx}")


def check_timeline_entry(
    idx: int, item: dict, ev: dict, findings: list[str]
) -> None:
    """Validate one timeline entry's timestamp and SQLite citations."""
    ts = item.get("timestamp", "")
    cites = item.get("citations") or {}
    if ts not in ev["all_timestamps"]:
        findings.append(f"timeline[{idx}]: fabricated timestamp {ts}")
    if not cites:
        findings.append(f"timeline[{idx}]: missing citations map")
        return

    lookup = {
        "alert_id": ev["alerts"],
        "promql_id": ev["promql"],
        "trace_id": ev["traces"],
        "git_sha": ev["commits"],
    }
    for key, ref_id in cites.items():
        if key == "incident_id":
            if ref_id != ev["incident"]["incident_id"]:
                findings.append(
                    f"timeline[{idx}]: wrong incident_id {ref_id}"
                )
            elif ts not in ev["incident_times"]:
                findings.append(
                    f"timeline[{idx}]: {ts} not an incident edge"
                )
        elif key in lookup:
            table_map = lookup[key]
            if ref_id not in table_map:
                findings.append(
                    f"timeline[{idx}]: unknown {key}={ref_id}"
                )
            elif table_map[ref_id] != ts:
                findings.append(
                    f"timeline[{idx}]: {key}={ref_id} time drift"
                )
        else:
            findings.append(f"timeline[{idx}]: invalid key {key}")

    check_prose_tokens(
        item.get("event", ""), f"timeline[{idx}].event", ev, findings
    )


def audit_postmortem(
    pm_path: Path, conn: sqlite3.Connection, strict: bool = False
) -> dict:
    """Audit one postmortem JSON file against the SQLite ledger."""
    data = json.loads(pm_path.read_text(encoding="utf-8"))
    inc_id = data.get("incident_id", "")
    ev = fetch_incident_evidence(conn, inc_id)
    findings: list[str] = []

    if ev is None:
        findings.append(f"incident_id={inc_id} missing from ledger")
        return {
            "file": pm_path.name,
            "passed": False,
            "findings": findings,
        }

    inc = ev["incident"]
    for field in ("started_at", "mitigated_at", "resolved_at"):
        val = data.get(field)
        if val and val != inc[field]:
            findings.append(
                f"{field}={val} != ledger {inc[field]}"
            )

    for key in ("root_cause_commit", "mitigation_commit"):
        sha = data.get(key)
        if sha and sha not in ev["commits"]:
            findings.append(f"{key}: unknown git_sha {sha}")

    if data.get("alert_id") and data["alert_id"] not in ev["alerts"]:
        findings.append(f"unknown alert_id {data['alert_id']}")

    cited = data.get("cited_evidence") or {}
    groups = (
        ("alert_ids", ev["alerts"]),
        ("promql_ids", ev["promql"]),
        ("trace_ids", ev["traces"]),
        ("git_shas", ev["commits"]),
    )
    for field, valid_map in groups:
        for val in cited.get(field, []):
            if val not in valid_map:
                findings.append(f"cited_evidence.{field}: bad {val}")

    check_prose_tokens(
        data.get("summary", ""), "summary", ev, findings
    )
    for idx, entry in enumerate(data.get("timeline", [])):
        check_timeline_entry(idx, entry, ev, findings)

    if strict or data.get("citation_audit_passed") is False:
        if data.get("citation_audit_passed") is not True:
            findings.append("citation_audit_passed is not true")
    if strict and data.get("human_owner_signed_off") is not True:
        findings.append("human_owner_signed_off is not true")

    return {
        "file": pm_path.name,
        "incident_id": inc_id,
        "passed": len(findings) == 0,
        "finding_count": len(findings),
        "findings": findings,
    }


def open_ephemeral_ledger(db_arg: Path | None) -> tuple:
    """Create temp dir + SQLite DB unless external --db provided."""
    if db_arg is not None:
        return None, sqlite3.connect(db_arg)
    tmpdir = tempfile.TemporaryDirectory(prefix="sre_ledger_")
    db_path = Path(tmpdir.name) / "evidence.db"
    mod = load_ledger_module()
    mod.build_evidence_ledger(db_path)
    return tmpdir, sqlite3.connect(db_path)


def print_result(res: dict) -> None:
    """Print audit findings <= 74 chars per line."""
    status = "PASS" if res["passed"] else "FAIL"
    print(f"[{status}] {res['file']} ({res['finding_count']} findings)")
    for msg in res["findings"]:
        print(f"  - {msg}")


def main() -> int:
    """CLI entry point supporting self-suite and --strict target."""
    parser = argparse.ArgumentParser(
        description="Audit postmortem JSON against SQLite ledger."
    )
    parser.add_argument(
        "targets", nargs="*", type=Path, help="Postmortem JSON paths."
    )
    parser.add_argument("--postmortem", type=Path, default=None)
    parser.add_argument("--db", type=Path, default=None)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    targets = list(args.targets)
    if args.postmortem is not None:
        targets.append(args.postmortem)

    tmpdir, conn = open_ephemeral_ledger(args.db)
    try:
        if targets:
            results = [
                audit_postmortem(p, conn, strict=args.strict)
                for p in targets
            ]
            ok = all(r["passed"] for r in results)
            if args.json:
                out = {"results": results, "ok": ok}
                print(json.dumps(out, indent=2))
            else:
                for res in results:
                    print_result(res)
            return 0 if ok else 1

        res_ok = audit_postmortem(VALID_PM, conn, strict=True)
        res_bad = audit_postmortem(BAD_PM, conn, strict=True)
        suite_ok = res_ok["passed"] and (not res_bad["passed"])
        if args.json:
            out = {
                "self_suite_passed": suite_ok,
                "valid_result": res_ok,
                "hallucinated_result": res_bad,
            }
            print(json.dumps(out, indent=2))
        else:
            print("OrderFlow Postmortem Citation Audit Self-Suite")
            print("-" * 68)
            print_result(res_ok)
            print_result(res_bad)
            verdict = "PASS" if suite_ok else "FAIL"
            print(f"Suite Verdict: {verdict}")
        return 0 if suite_ok else 1
    finally:
        conn.close()
        if tmpdir is not None:
            tmpdir.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
