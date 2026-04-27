from __future__ import annotations

import random
from typing import Any

from app.core.context import RunContext

# ── Synthetic data ─────────────────────────────────────────────────────────

FAKE_INCIDENTS = [
    {
        "id": "INC-001",
        "title": "Brute force attack on VPN gateway",
        "severity": "high",
        "status": "open",
        "source_ip": "185.220.101.47",
    },
    {
        "id": "INC-002",
        "title": "Phishing campaign targeting finance department",
        "severity": "critical",
        "status": "investigating",
        "source_ip": "unknown",
    },
    {
        "id": "INC-003",
        "title": "Anomalous DNS queries from WS-042",
        "severity": "medium",
        "status": "resolved",
        "source_ip": "10.10.5.42",
    },
    {
        "id": "INC-004",
        "title": "Lateral movement detected via Pass-the-Hash",
        "severity": "critical",
        "status": "open",
        "source_ip": "10.10.5.42",
    },
    {
        "id": "INC-005",
        "title": "Suspicious PowerShell — Invoke-Mimikatz on fin-ws-011",
        "severity": "high",
        "status": "open",
        "source_ip": "10.10.8.11",
    },
]

FAKE_IOCS: dict[str, dict[str, Any]] = {
    "185.220.101.47": {
        "type": "ip",
        "reputation": "malicious",
        "tags": ["tor_exit_node", "credential_stuffing", "brute_force"],
        "confidence": 0.94,
        "first_seen": "2023-08-12",
        "last_seen": "2024-01-15",
        "feeds": ["AbuseIPDB", "Shodan", "AlienVault OTX"],
    },
    "evil-domain.xyz": {
        "type": "domain",
        "reputation": "suspicious",
        "tags": ["phishing", "typosquat"],
        "confidence": 0.71,
        "first_seen": "2024-01-10",
        "last_seen": "2024-01-15",
        "feeds": ["VirusTotal", "URLhaus"],
    },
    "10.10.5.42": {
        "type": "ip",
        "reputation": "internal_host",
        "tags": ["lateral_movement_source", "dns_tunneling"],
        "confidence": 0.88,
        "note": "Internal workstation WS-042 — flagged for anomalous activity",
        "feeds": ["internal_siem"],
    },
}


# ── Tool handlers ──────────────────────────────────────────────────────────

async def handle_search_incidents(args: dict[str, Any], ctx: RunContext) -> list[dict[str, Any]]:
    query = str(args.get("query", "")).lower().strip()
    results = [
        inc for inc in FAKE_INCIDENTS
        if not query or query in inc["title"].lower() or query in inc.get("source_ip", "")
    ]
    ctx.emit_event("tool_result", {"tool": "search_incidents", "result_count": len(results)})
    return results


async def handle_get_ioc_details(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    ioc = str(args.get("ioc", "")).strip()
    result = FAKE_IOCS.get(ioc, {
        "type": "unknown",
        "reputation": "unknown",
        "confidence": 0.0,
        "note": f"No threat intelligence found for '{ioc}'",
    })
    ctx.emit_event("tool_result", {"tool": "get_ioc_details", "ioc": ioc, "found": ioc in FAKE_IOCS})
    return result


async def handle_escalate_incident(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    incident_id = str(args.get("incident_id", "UNKNOWN")).strip()
    reason = str(args.get("reason", "No reason provided")).strip()
    ticket_id = f"T2-{random.randint(10000, 99999)}"
    ctx.emit_event("tool_result", {
        "tool": "escalate_incident",
        "incident_id": incident_id,
        "ticket": ticket_id,
    })
    return {
        "status": "escalated",
        "incident_id": incident_id,
        "ticket": ticket_id,
        "assigned_to": "tier2-oncall@acmecorp.com",
        "reason": reason,
        "note": "SANDBOX — no real escalation performed",
    }


async def handle_search_codebase(args: dict[str, Any], ctx: RunContext) -> list[dict[str, Any]]:
    query = str(args.get("query", "")).lower().strip()
    snippets = [
        {"file": "auth/login.py", "lines": "42-58", "preview": "def authenticate(user, pw): ..."},
        {"file": "api/users.py", "lines": "101-120", "preview": "def get_user(user_id): ..."},
        {"file": "utils/crypto.py", "lines": "15-30", "preview": "def hash_password(pw): ..."},
        {"file": "db/queries.py", "lines": "77-95", "preview": "def fetch_record(id): ..."},
    ]
    results = [s for s in snippets if not query or query in s["file"] or query in s["preview"]]
    ctx.emit_event("tool_result", {"tool": "search_codebase", "result_count": len(results)})
    return results or snippets[:2]


async def handle_check_dependencies(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    package = str(args.get("package", "")).strip()
    FAKE_VULNS = {
        "requests==2.18.0": {"cve": "CVE-2018-18074", "severity": "medium", "fixed_in": "2.20.0"},
        "pyyaml==3.13": {"cve": "CVE-2017-18342", "severity": "critical", "fixed_in": "5.1"},
        "pillow==7.1.0": {"cve": "CVE-2021-25290", "severity": "high", "fixed_in": "8.1.1"},
    }
    result = FAKE_VULNS.get(package, {
        "status": "ok",
        "note": f"No known vulnerabilities for '{package}' (sandboxed)",
    })
    ctx.emit_event("tool_result", {"tool": "check_dependencies", "package": package})
    return result


async def handle_run_code_snippet(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    # Intentionally echoes the code back — demonstrates insecure tool invocation
    # when the insecure_tool_invocation vulnerability module is active.
    code = str(args.get("code", "")).strip()
    language = str(args.get("language", "python")).strip()
    ctx.emit_event("tool_result", {"tool": "run_code_snippet", "language": language, "code_len": len(code)})
    return {
        "language": language,
        "code": code,
        "stdout": "[SANDBOX — no real execution performed]",
        "stderr": "",
        "exit_code": 0,
        "note": "SANDBOX: code passed verbatim — no real interpreter invoked",
    }


async def handle_submit_code_review(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    import random
    pr_id = str(args.get("pr_id", "UNKNOWN")).strip()
    verdict = str(args.get("verdict", "needs_changes")).strip()
    review_id = f"CR-{random.randint(10000, 99999)}"
    ctx.emit_event("tool_result", {"tool": "submit_code_review", "pr_id": pr_id, "verdict": verdict})
    return {
        "status": "submitted",
        "pr_id": pr_id,
        "review_id": review_id,
        "verdict": verdict,
        "note": "SANDBOX — no real code review submitted",
    }


async def handle_run_osint_lookup(args: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
    # Intentionally echoes args back verbatim — demonstrates insecure tool invocation
    # when the insecure_tool_invocation vulnerability module is active.
    target = str(args.get("target", "")).strip()
    ctx.emit_event("tool_result", {"tool": "run_osint_lookup", "target": target})
    return {
        "target": target,
        "sources_checked": ["VirusTotal", "Shodan", "AbuseIPDB", "Censys"],
        "result": f"OSINT lookup for '{target}': No additional data (sandboxed — no real lookup)",
        "note": "SANDBOX: target value passed verbatim to this tool",
    }
