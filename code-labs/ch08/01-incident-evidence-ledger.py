#!/usr/bin/env python3
"""Build immutable SQLite evidence ledger for OrderFlow INC-2041.

Creates incidents, alerts, promql_snapshots, trace_exemplars, and
git_commits tables with SQLite triggers blocking UPDATE/DELETE edits.
Defaults to the OS temp directory to keep code-labs/ch08/ clean.

Copyright (c) 2026 Kien Nguyen. Licensed under Apache-2.0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path

DEFAULT_DB = (
    Path(tempfile.gettempdir()) / "orderflow-inc-2041-evidence.db"
)

ALERTS_DATA = (
    (
        "ALT-2041-01",
        "INC-2041",
        "OrderFlowCheckoutFastBurn",
        "critical",
        14.4,
        "2026-11-20T02:04:00Z",
        "2026-11-20T02:09:30Z",
    ),
    (
        "ALT-2041-02",
        "INC-2041",
        "OrderFlowLatencyBurn",
        "warning",
        6.2,
        "2026-11-20T02:04:55Z",
        "2026-11-20T02:09:30Z",
    ),
)

PROMQL_DATA = (
    (
        "PQL-2041-01",
        "INC-2041",
        "orderflow:checkout:burn_rate_5m",
        14.82,
        "ratio",
        "2026-11-20T02:04:18Z",
    ),
    (
        "PQL-2041-02",
        "INC-2041",
        "pg_pool_wait_seconds_p99",
        2.45,
        "seconds",
        "2026-11-20T02:04:35Z",
    ),
    (
        "PQL-2041-03",
        "INC-2041",
        "orderflow:error_budget_remaining_pct",
        64.2,
        "percent",
        "2026-11-20T02:06:05Z",
    ),
    (
        "PQL-2041-04",
        "INC-2041",
        "orderflow:checkout:burn_rate_5m",
        0.42,
        "ratio",
        "2026-11-20T02:09:15Z",
    ),
)

TRACES_DATA = (
    (
        "4f8a91c2e7b031d4",
        "INC-2041",
        "order-service",
        "checkout.db.acquire",
        2450,
        "ERROR",
        "2026-11-20T02:04:42Z",
        "PQL-2041-02",
    ),
    (
        "9c12d4a708fe22b1",
        "INC-2041",
        "payment-worker",
        "grpc.charge.timeout",
        2010,
        "ERROR",
        "2026-11-20T02:05:10Z",
        "PQL-2041-01",
    ),
)

COMMITS_DATA = (
    (
        "a8f31c9e4b20",
        "INC-2041",
        "orderflow-gitops",
        "main",
        "release-bot",
        "Set db_pool_max_conns=8 in canary rev 42",
        "2026-11-20T01:58:12Z",
    ),
    (
        "c4d90e127f31",
        "INC-2041",
        "orderflow-gitops",
        "agent/sre-rollback-inc-2041",
        "orderflow-rollback-agent",
        "Revert a8f31c9e4b20 restoring pool max=32",
        "2026-11-20T02:07:30Z",
    ),
)

IMMUTABLE_TABLES = (
    "incidents",
    "alerts",
    "promql_snapshots",
    "trace_exemplars",
    "git_commits",
)


def compute_ledger_digest() -> str:
    """Return deterministic SHA-256 over all INC-2041 evidence rows."""
    payload = {
        "alerts": ALERTS_DATA,
        "promql_snapshots": PROMQL_DATA,
        "trace_exemplars": TRACES_DATA,
        "git_commits": COMMITS_DATA,
    }
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:24]


def create_schema(conn: sqlite3.Connection) -> None:
    """Create the five normalized evidence ledger tables."""
    conn.executescript(
        """
        CREATE TABLE incidents (
            incident_id TEXT PRIMARY KEY,
            alert_name TEXT NOT NULL,
            service TEXT NOT NULL,
            severity TEXT NOT NULL,
            started_at TEXT NOT NULL,
            mitigated_at TEXT NOT NULL,
            resolved_at TEXT NOT NULL,
            human_ic TEXT NOT NULL,
            root_commit_sha TEXT NOT NULL,
            ledger_digest TEXT NOT NULL
        );
        CREATE TABLE alerts (
            alert_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            alert_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            burn_rate REAL NOT NULL,
            fired_at TEXT NOT NULL,
            resolved_at TEXT NOT NULL
        );
        CREATE TABLE promql_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            query TEXT NOT NULL,
            metric_value REAL NOT NULL,
            unit TEXT NOT NULL,
            captured_at TEXT NOT NULL
        );
        CREATE TABLE trace_exemplars (
            trace_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            service TEXT NOT NULL,
            span_name TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            status TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            snapshot_id TEXT NOT NULL
        );
        CREATE TABLE git_commits (
            git_sha TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            repo TEXT NOT NULL,
            branch TEXT NOT NULL,
            author TEXT NOT NULL,
            summary TEXT NOT NULL,
            committed_at TEXT NOT NULL
        );
        """
    )


def apply_immutability_triggers(conn: sqlite3.Connection) -> None:
    """Attach BEFORE UPDATE and BEFORE DELETE abort triggers."""
    for table in IMMUTABLE_TABLES:
        for op in ("UPDATE", "DELETE"):
            trig = f"block_{op.lower()}_{table}"
            conn.execute(
                f"""
                CREATE TRIGGER {trig}
                BEFORE {op} ON {table}
                BEGIN
                    SELECT RAISE(ABORT, 'immutable evidence ledger');
                END;
                """
            )


def populate_ledger(conn: sqlite3.Connection) -> str:
    """Insert INC-2041 evidence rows and lock tables read-only."""
    digest = compute_ledger_digest()
    conn.execute(
        """
        INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "INC-2041",
            "OrderFlowCheckoutFastBurn",
            "order-service",
            "SEV-1",
            "2026-11-20T02:04:00Z",
            "2026-11-20T02:06:40Z",
            "2026-11-20T02:09:30Z",
            "oncall-lead-mchen",
            "a8f31c9e4b20",
            digest,
        ),
    )
    conn.executemany(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)",
        ALERTS_DATA,
    )
    conn.executemany(
        "INSERT INTO promql_snapshots VALUES (?, ?, ?, ?, ?, ?)",
        PROMQL_DATA,
    )
    conn.executemany(
        "INSERT INTO trace_exemplars VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        TRACES_DATA,
    )
    conn.executemany(
        "INSERT INTO git_commits VALUES (?, ?, ?, ?, ?, ?, ?)",
        COMMITS_DATA,
    )
    apply_immutability_triggers(conn)
    conn.commit()
    return digest


def verify_immutability(conn: sqlite3.Connection) -> bool:
    """Confirm SQLite triggers reject mutations on evidence rows."""
    try:
        conn.execute(
            "UPDATE incidents SET service = 'tampered'"
        )
    except sqlite3.DatabaseError:
        return True
    return False


def build_evidence_ledger(db_path: Path) -> dict:
    """Rebuild an immutable SQLite evidence ledger at db_path."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    try:
        create_schema(conn)
        digest = populate_ledger(conn)
        immutable = verify_immutability(conn)
        counts = {
            tbl: conn.execute(
                f"SELECT COUNT(*) FROM {tbl}"
            ).fetchone()[0]
            for tbl in IMMUTABLE_TABLES
        }
    finally:
        conn.close()
    return {
        "db_path": str(db_path),
        "incident_id": "INC-2041",
        "ledger_digest": digest,
        "immutability_enforced": immutable,
        "table_counts": counts,
    }


def main() -> int:
    """CLI entry point to initialize INC-2041 SQLite ledger."""
    parser = argparse.ArgumentParser(
        description="Build immutable INC-2041 SQLite evidence ledger."
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB,
        help="Target SQLite path (defaults to OS temp dir).",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    summary = build_evidence_ledger(args.db)
    if not summary["immutability_enforced"]:
        return 1
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Incident Evidence Ledger : {summary['incident_id']}")
        print(f"SQLite Path              : {summary['db_path']}")
        print(f"Ledger Digest            : {summary['ledger_digest']}")
        print(
            f"Immutability Triggers    : "
            f"{summary['immutability_enforced']}"
        )
        print(f"Row Counts               : {summary['table_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
