# OrderFlow Agentic SRE — Companion Code Labs

Zero-Cloud-Bill and Zero-API-Bill runtime AI-SRE labs, three-tier CNCF
tooling (`kubectl-ai v0.0.31`, `HolmesGPT v0.46.0`, `kagent v1.0.1`),
Linux Foundation AAIF `A2A v1.0.0` signed Agent Cards, `MCP 2026-07-28`
observability servers (`prometheus-mcp v0.19.0`, `mcp-grafana v2.0.2`),
OPA `rego.v1` Autonomy Level `0-3` gates, ICS war-room scribe harnesses,
SQLite citation-verified postmortem auditors, and Toxiproxy / Chaos Mesh
RCA benchmarks:

> **Agentic SRE: Autonomous Incident Investigation and Self-Healing**
> **Operations**
> *A Practical Guide to CNCF AI-SRE Agents, Multi-Signal Root-Cause*
> *Investigation, Bounded Self-Healing, Agent-Assisted Incident Command,*
> *and Chaos Verification*
> *Practical Engineering Series — Volume 07 (Arc II Runtime SRE Plane)*
> **Author & Publisher:** Kien Nguyen
> **Repository:** `https://github.com/kiennt308/agentic-sre-labs`

Copyright (c) 2026 Kien Nguyen. Companion scripts, CRDs, Rego policies,
Alertmanager/Prometheus configs, Toxiproxy harnesses, and SQLite audit
tools in this repository are licensed under **Apache-2.0**.

---

## Zero-Cloud-Bill & Zero-API-Bill Toolchain

Every chapter lab runs 100% offline with Docker and Python `3.11+`
using `ch01/01-sre-replay-gateway.py` (`LLM_BASE_URL` overridable to
local `Ollama` or any OpenAI-compatible gateway) with `$0.00` spend:

- `Python 3.11+`, `mcp v2.2+`, `PyJWT`, `cryptography`, `pytest`, `SQLite`
- `prom/prometheus:v3.16.0` (`promtool check rules`)
- `prom/alertmanager:v0.35.0` (`amtool check-config`)
- `openpolicyagent/conftest:latest` (`v0.71.1` / `OPA v1.21.1` `rego.v1`)
- `ghcr.io/yannh/kubeconform:latest` (`v0.8.0`) & `aquasec/trivy:latest`
- `ghcr.io/shopify/toxiproxy:2.13.0` (ephemeral live fault injection)

---

## Canonical Agent Identities & Autonomy Levels (0-3)

- **CLI Copilot:** `orderflow-diag-cli` (`kubectl-ai v0.0.31`)
- **Alert Investigator:** `orderflow-alert-investigator` (`HolmesGPT`)
- **Cluster Coordinator:** `orderflow-kagent-coordinator` + A2A
  specialists (`orderflow-metrics-agent`, `orderflow-trace-agent`,
  `orderflow-rollback-agent`)
- **Autonomy Levels:** `0` (Observe), `1` (Evidence-Cited RCA),
  `2` (GitOps `agent/sre-rollback-*` PR), `3` (Bounded Reversible
  Self-Healing: `Argo Rollouts` abort & priority load-shedding only)

---

## Directory Index (44 Clean Files)

```text
code-labs/
├── README.md      Zero-API-Bill runtime SRE toolchain guide
├── policies/      OPA rego.v1 Autonomy Level 0-3 & PRR gates
├── ch01/          Deterministic SRE replay gateway & 3-tier router
├── ch02/          kubectl-ai read-only RBAC & command-preview guard
├── ch03/          Alertmanager v0.35 -> HolmesGPT allowed_tools lab
├── ch04/          MCP prometheus-mcp server & causal RCA correlator
├── ch05/          kagent v1.0.1 Substrate CRDs & signed A2A v1.0.0
├── ch06/          Autonomy Levels 0-3 OPA & circuit-breaker controller
├── ch07/          ICS 15-min AI Scribe & concurrent mutation guard
├── ch08/          SQLite evidence ledger & postmortem citation auditor
└── ch09/          Toxiproxy live chaos benchmark & SRE Agent PRR
```

---

## Quick Verification Commands

Run offline OPA Autonomy gates and Python/MCP/Pytest checks from here:

```bash
docker run --rm -v "${PWD}:/work" -w /work \
  openpolicyagent/conftest:latest test \
  -p policies/sre_autonomy_gates.rego \
  ch01/03-sre-autonomy-policy-valid.yaml \
  ch03/02-holmesgpt-mcp-toolsets.yaml \
  ch05/01-kagent-v1-agent-bundle.yaml \
  ch06/03-autonomy-l3-safe-abort.json \
  ch09/04-sre-prr-ready.json

python ch04/03-causal-rca-correlator.py
python ch05/04-a2a-jws-delegation-runner.py
```
