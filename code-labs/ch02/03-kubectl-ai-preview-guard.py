"""Interactive Preview and Scrubbing Guard for kubectl-ai.

Scrubs credentials from piped logs before LLM inspection, blocks
mutating kubectl verbs, and requires interactive preview approval
before executing any generated read-only command.
"""

import os
import re
import shlex
import sys
from typing import Callable

MUTATING_VERBS = {
    "delete",
    "apply",
    "patch",
    "exec",
    "create",
    "replace",
    "edit",
    "scale",
    "drain",
    "cordon",
    "port-forward",
    "cp",
}

READONLY_VERBS = {
    "get",
    "describe",
    "logs",
    "top",
    "explain",
    "events",
}

SHELL_METACHARS = (";", "&&", "||", "|", "`", "$(", ">", "<")

FLAGS_WITH_VALUE = {
    "-n",
    "--namespace",
    "--context",
    "-o",
    "--output",
    "-l",
    "--selector",
}

CREDENTIAL_PATTERNS = [
    (
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "[REDACTED_AWS_KEY]",
    ),
    (
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{8,}\b"),
        "[REDACTED_GH_TOKEN]",
    ),
    (
        re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-+/=]{8,}"),
        "Bearer [REDACTED_TOKEN]",
    ),
]


def scrub_credentials(raw_logs: str) -> str:
    """Redact AWS keys, GitHub tokens, and Bearer secrets in logs."""
    cleaned = raw_logs
    for pattern, replacement in CREDENTIAL_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def _extract_kubectl_verb(tokens: list[str]) -> str | None:
    """Locate the primary kubectl subcommand skipping leading flags."""
    skip_next = False
    for tok in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if tok in FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        return tok.lower()
    return None


def validate_kubectl_command(cmd: str) -> tuple[bool, str]:
    """Allow only single read-only kubectl commands; block mutations."""
    if any(op in cmd for op in SHELL_METACHARS):
        return False, "BLOCKED_SHELL_OPERATOR"
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False, "BLOCKED_INVALID_QUOTING"
    if not tokens or os.path.basename(tokens[0]) != "kubectl":
        return False, "BLOCKED_NON_KUBECTL_BIN"
    verb = _extract_kubectl_verb(tokens)
    if not verb:
        return False, "BLOCKED_MISSING_VERB"
    if verb in MUTATING_VERBS:
        return False, f"BLOCKED_MUTATING_VERB:{verb}"
    if verb not in READONLY_VERBS:
        return False, f"BLOCKED_NON_READONLY_VERB:{verb}"
    return True, f"READONLY_ALLOWED:{verb}"


def preview_and_confirm(
    cmd: str,
    stdin_logs: str = "",
    prompt_fn: Callable[[str], str] = input,
) -> dict:
    """Scrub stdin logs, validate command, and ask confirmation."""
    scrubbed = scrub_credentials(stdin_logs) if stdin_logs else ""
    allowed, reason = validate_kubectl_command(cmd)
    print(f"[PREVIEW] command: {cmd}")
    if not allowed:
        print(f"[DENIED] {reason}")
        return {
            "approved": False,
            "reason": reason,
            "scrubbed_logs": scrubbed,
        }
    try:
        reply = prompt_fn("Approve read-only execution? [y/N]: ")
    except EOFError:
        reply = ""
    approved = reply.strip().lower() in {"y", "yes"}
    outcome = "USER_CONFIRMED" if approved else "USER_DECLINED"
    print(f"[DECISION] approved={approved} ({outcome})")
    return {
        "approved": approved,
        "reason": outcome,
        "scrubbed_logs": scrubbed,
    }


def run_self_tests() -> int:
    """Verify credential scrubbing, verb blocking, and preview gate."""
    raw = (
        "aws_key=AKIA1234567890ABCDEF "
        "gh=ghp_99secretTokenValue1234 "
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.xyz"
    )
    scrubbed = scrub_credentials(raw)
    assert "AKIA1234567890ABCDEF" not in scrubbed
    assert "ghp_99secretTokenValue1234" not in scrubbed
    assert "eyJhbGciOiJIUzI1NiJ9" not in scrubbed
    assert "[REDACTED_AWS_KEY]" in scrubbed
    assert "[REDACTED_GH_TOKEN]" in scrubbed
    assert "Bearer [REDACTED_TOKEN]" in scrubbed

    blocked_cmds = [
        "kubectl delete pod checkout-1 -n orderflow-prod",
        "kubectl apply -f rollback.yaml",
        "kubectl patch deploy checkout-api -p '{}'",
        "kubectl -n orderflow-prod exec -it checkout-1 -- sh",
        "kubectl get pods; kubectl delete ns orderflow-prod",
    ]
    for bad in blocked_cmds:
        ok, reason = validate_kubectl_command(bad)
        assert not ok, f"Expected block for: {bad}"
        assert reason.startswith("BLOCKED_")
        res = preview_and_confirm(bad, raw, lambda _: "y")
        assert not res["approved"]

    good_cmd = "kubectl get events -n orderflow-prod"
    declined = preview_and_confirm(good_cmd, raw, lambda _: "")
    assert not declined["approved"]
    assert declined["reason"] == "USER_DECLINED"

    confirmed = preview_and_confirm(good_cmd, raw, lambda _: "y")
    assert confirmed["approved"]
    assert confirmed["reason"] == "USER_CONFIRMED"
    assert "AKIA1234567890ABCDEF" not in confirmed["scrubbed_logs"]

    print("[PASS] kubectl-ai scrub, verb block, and preview verified.")
    return 0


def main() -> int:
    if "--pipe" in sys.argv:
        idx = sys.argv.index("--pipe")
        cmd = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else ""
        logs = sys.stdin.read() if not sys.stdin.isatty() else ""
        res = preview_and_confirm(cmd, logs)
        print("[SCRUBBED_EXCERPT]", res["scrubbed_logs"][:120])
        return 0 if res["approved"] else 1
    return run_self_tests()


if __name__ == "__main__":
    sys.exit(main())
