package main

import rego.v1

cfg := object.get(input, "spec", input)

forbidden_l3_actions := {
	"delete_pvc",
	"drop_database",
	"edit_iam",
	"delete_networkpolicy",
	"pods_exec",
	"force_sync_bypass",
}

mutating_k8s_verbs := {
	"create",
	"update",
	"patch",
	"delete",
	"deletecollection",
	"exec",
	"portforward",
}

legacy_kagent_kinds := {
	"ToolServer",
	"Team",
	"Memory",
}

# 1. Prevent Day-1 unbounded Level 3 autonomy without rollback path
deny contains msg if {
	cfg.autonomy_level == 3
	cfg.progressive_trust_days < 14
	msg := "DAY1_L3_DENIED: require >=14d progressive trust first"
}

deny contains msg if {
	cfg.autonomy_level == 3
	cfg.guaranteed_rollback_path != true
	msg := "NO_ROLLBACK_PATH: L3 needs guaranteed rollback path"
}

# 2. Enforce kagent v1.0.1 Substrate CRDs over retired 0.10.x resources
deny contains msg if {
	contains(object.get(input, "apiVersion", ""), "kagent.dev/v1alpha1")
	msg := "LEGACY_KAGENT_0X: upgrade v1alpha1 CRD to kagent v1.0"
}

deny contains msg if {
	object.get(input, "kind", "") in legacy_kagent_kinds
	msg := sprintf("DEPRECATED_KAGENT_KIND: %s replaced in v1.0", [
		input.kind,
	])
}

# 3. Require JWS-signed Agent Cards and opaque memory in A2A v1.0.0
deny contains msg if {
	cfg.protocol == "A2A"
	cfg.jws_signed != true
	msg := "UNSIGNED_A2A_CARD: Agent Cards must carry JWS signature"
}

deny contains msg if {
	cfg.protocol == "A2A"
	cfg.expose_internal_memory == true
	msg := "A2A_MEMORY_LEAK: keep internal agent memory opaque"
}

# 4. kubectl-ai interactive command preview & read-only RBAC guards
deny contains msg if {
	cfg.tool == "kubectl-ai"
	cfg.skip_confirmation == true
	msg := "KUBECTL_AI_SKIP_CONFIRM: require preview confirmation"
}

deny contains msg if {
	object.get(input, "kind", "") in {"Role", "ClusterRole"}
	some rule in object.get(input, "rules", [])
	some verb in object.get(rule, "verbs", [])
	verb in mutating_k8s_verbs
	msg := sprintf("RBAC_WRITE_DENIED: SRE readonly forbids %s", [verb])
}

# 5. Reject static CPU webhooks & unfiltered HolmesGPT MCP toolsets
deny contains msg if {
	cfg.trigger_type == "static_cpu_threshold"
	msg := "STATIC_CPU_WEBHOOK_DENIED: use MWMBR SLO burn-rate alerts"
}

deny contains msg if {
	some name, srv in cfg.mcpServers
	cfg.agent_runtime == "holmesgpt"
	count(object.get(srv, "allowed_tools", [])) == 0
	msg := sprintf("HOLMES_UNFILTERED_MCP: %s needs allowed_tools", [
		name,
	])
}

# 6. Legacy MCP HTTP+SSE & writable k8s MCP guard (from Vol. 06 floor)
deny contains msg if {
	some _, srv in cfg.mcpServers
	srv.transport == "sse"
	msg := "LEGACY_SSE_DENIED: migrate MCP to 2026-07-28 streamable-http"
}

deny contains msg if {
	some name, srv in cfg.mcpServers
	contains(name, "kubernetes")
	srv.read_only != true
	msg := "K8S_MCP_WRITE_DENIED: kubernetes MCP must be read_only"
}

# 7. Level 2 GitOps rollback branch & Level 3 circuit-breaker invariants
deny contains msg if {
	cfg.autonomy_level == 2
	cfg.head_branch
	not startswith(cfg.head_branch, "agent/sre-")
	msg := "SRE_BRANCH_PREFIX: L2 rollback PR must use agent/sre-"
}

deny contains msg if {
	cfg.autonomy_level == 3
	object.get(cfg, "error_budget_remaining_pct", 0) < 20
	msg := "ERROR_BUDGET_EXHAUSTED: L3 blocked; downgrade to L1"
}

deny contains msg if {
	cfg.autonomy_level == 3
	cfg.cooldown_active == true
	msg := "COOLDOWN_ACTIVE: wait cooldown_seconds before L3 retry"
}

deny contains msg if {
	cfg.autonomy_level == 3
	object.get(cfg, "actions_this_incident", 99) >= 2
	msg := "ACTION_CAP_REACHED: max 2 autonomous L3 actions exceeded"
}

deny contains msg if {
	some act in object.get(cfg, "proposed_actions", [])
	act in forbidden_l3_actions
	msg := sprintf("FORBIDDEN_L3_ACTION: %s requires human owner", [act])
}

# 8. ICS human lock, postmortem citations & Chaos RCA release gates
deny contains msg if {
	cfg.ics_human_lock_active == true
	cfg.autonomous_mutation_requested == true
	msg := "ICS_HUMAN_LOCK_CONFLICT: Ops human owns active lock"
}

deny contains msg if {
	cfg.artifact_type == "postmortem"
	cfg.citation_audit_passed != true
	msg := "UNCITED_POSTMORTEM: pass SQLite citation audit first"
}

deny contains msg if {
	cfg.artifact_type == "postmortem"
	cfg.human_owner_signed_off != true
	msg := "POSTMORTEM_SIGNOFF_REQUIRED: human IC sign-off missing"
}

deny contains msg if {
	cfg.artifact_type == "sre_prr"
	object.get(cfg, "top1_rca_precision", 0) < 0.85
	msg := "CHAOS_PRECISION_LOW: require >= 0.85 Top-1 RCA Precision"
}

deny contains msg if {
	cfg.artifact_type == "sre_prr"
	object.get(cfg, "false_positive_rate", 1) > 0.05
	msg := "CHAOS_FPR_HIGH: false_positive_rate must be <= 0.05"
}
