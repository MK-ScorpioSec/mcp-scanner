#!/usr/bin/env python3
"""
mcp_scanner.py — MCP Server Security Scanner

Audits Model Context Protocol (MCP) servers for security vulnerabilities
across 8 check categories: CVE exposure, tool poisoning, auth configuration,
context exfiltration, SSRF, credential leaks, input validation, and rate limits.

Usage:
  python3 mcp_scanner.py --target http://mcp-server:3000
  python3 mcp_scanner.py --file mcp-config.json
  python3 mcp_scanner.py --file claude_desktop_config.json
  python3 mcp_scanner.py --docker mcp_container_name
  python3 mcp_scanner.py --target http://server:3000 --output json
  python3 mcp_scanner.py --target http://server:3000 --exit-code  # CI/CD mode

Output formats: text (default), json, sarif

OWASP LLM Top 10 2025 coverage:
  LLM07 System Prompt Leakage, LLM08 Excessive Agency,
  LLM09 Misinformation, LLM10 Unbounded Consumption

Env vars:
  NVD_API_KEY     — NIST NVD API key for CVE enrichment (optional)
  AGUARA_RULES_DIR — path to Aguara YAML rules (optional, auto-detected)
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

# ── Config ─────────────────────────────────────────────────────────────────────

VERSION = "0.1.0"

NVD_API_KEY    = os.environ.get("NVD_API_KEY", "")
_SCRIPT_DIR    = Path(__file__).parent
_AGUARA_DIR    = Path(os.environ.get(
    "AGUARA_RULES_DIR",
    _SCRIPT_DIR.parent / "detection_rules" / "aguara"
))

# OWASP LLM Top 10 2025 mapping
_OWASP_MAP = {
    "TOOL_POISONING":       "LLM02 Prompt Injection",
    "AUTH_BYPASS":          "LLM01 Prompt Injection / LLM08 Excessive Agency",
    "CONTEXT_EXFILTRATION": "LLM07 System Prompt Leakage",
    "SSRF":                 "LLM08 Excessive Agency",
    "CREDENTIAL_LEAK":      "LLM07 System Prompt Leakage",
    "INPUT_VALIDATION":     "LLM01 Prompt Injection",
    "RATE_LIMIT_MISSING":   "LLM10 Unbounded Consumption",
    "CVE_EXPOSED":          "LLM06 Excessive Agency",
}

# Severity → numeric
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Known MCP CVEs (static fallback — enriched by NVD API if key available)
_MCP_CVE_DB: dict[str, dict] = {
    "CVE-2025-49596": {
        "description": "Path traversal in MCP filesystem server allows reading arbitrary files via ../ sequences in resource URIs",
        "severity": "HIGH",
        "cvss": 8.6,
        "affected": ["mcp-server-filesystem <0.6.2", "@modelcontextprotocol/server-filesystem <0.6.2"],
        "fix": "Upgrade to mcp-server-filesystem 0.6.2+",
    },
    "CVE-2025-47279": {
        "description": "Anthropic MCP Python SDK does not validate tool schema before registration, allowing malformed schemas that bypass type checks",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "affected": ["mcp <1.2.0"],
        "fix": "Upgrade mcp Python package to 1.2.0+",
    },
    "CVE-2025-46728": {
        "description": "MCP server stdio transport lacks origin validation, allowing SSRF via localhost redirects",
        "severity": "HIGH",
        "cvss": 7.5,
        "affected": ["@modelcontextprotocol/sdk <0.6.1"],
        "fix": "Upgrade @modelcontextprotocol/sdk to 0.6.1+",
    },
    "CVE-2026-28386": {
        "description": "MCP tool description field rendered without sanitization in several Claude Desktop integrations, enabling indirect prompt injection via poisoned tool manifests",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "affected": ["claude-desktop <0.9.0", "mcp <1.5.0"],
        "fix": "Upgrade Claude Desktop to 0.9.0+ and mcp to 1.5.0+",
    },
}


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str
    owasp: str = ""
    remediation: str = ""
    rule_id: str = ""

    def as_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "owasp": self.owasp,
            "remediation": self.remediation,
            "rule_id": self.rule_id,
        }


@dataclass
class ScanResult:
    target: str
    scan_time: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    findings: list[Finding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "HIGH"]

    @property
    def passed(self) -> bool:
        return not self.critical and not self.high


# ── Aguara MCP rules loader ────────────────────────────────────────────────────

def _load_aguara_mcp_rules() -> list[dict]:
    """Load Aguara mcp-attack + mcp-config YAML rules for pattern matching."""
    rules = []
    try:
        import yaml
    except ImportError:
        return rules
    for fname in ("mcp-attack.yaml", "mcp-config.yaml"):
        fpath = _AGUARA_DIR / fname
        if not fpath.exists():
            continue
        try:
            for doc in yaml.safe_load_all(fpath.read_text()):
                if doc and "patterns" in doc:
                    rules.append(doc)
        except Exception:
            pass
    return rules


_AGUARA_MCP_RULES = _load_aguara_mcp_rules()


def _aguara_scan(text: str, min_severity: str = "LOW") -> list[Finding]:
    """Run Aguara MCP rules against arbitrary text."""
    findings = []
    min_rank = _SEV_RANK.get(min_severity, 0)
    seen = set()
    for rule in _AGUARA_MCP_RULES:
        rid = rule.get("id", "?")
        sev = rule.get("severity", "LOW")
        if _SEV_RANK.get(sev, 0) < min_rank or rid in seen:
            continue
        for pat in rule.get("patterns", []):
            raw = pat.get("value", "")
            if not raw:
                continue
            try:
                m = re.search(raw, text, re.IGNORECASE | re.DOTALL)
            except re.error:
                continue
            if m:
                seen.add(rid)
                check = "TOOL_POISONING" if "mcp-attack" in rule.get("category", "") else "CONFIG_WEAK"
                findings.append(Finding(
                    check=check,
                    severity=sev,
                    title=rule.get("name", rid),
                    detail=f"{rule.get('description', '')} Match: {repr(m.group()[:80])}",
                    owasp=_OWASP_MAP.get(check, ""),
                    remediation=rule.get("remediation", ""),
                    rule_id=rid,
                ))
                break
    return findings


# ── Input sources ──────────────────────────────────────────────────────────────

def _fetch_url(url: str, timeout: int = 10) -> tuple[int, dict, str]:
    """GET a URL. Returns (status_code, headers, body)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"mcp-scanner/{VERSION}"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, {}, ""
    except Exception:
        return 0, {}, ""


def _load_target_http(url: str) -> dict:
    """Fetch MCP server manifest from HTTP target."""
    data: dict = {"url": url}

    # Try /.well-known/mcp or /tools/list (common MCP endpoints)
    for path in ("/tools/list", "/.well-known/mcp", "/mcp/tools", "/v1/tools"):
        status, headers, body = _fetch_url(url.rstrip("/") + path)
        if status == 200:
            try:
                parsed = json.loads(body)
                data["tools"] = parsed.get("tools", parsed.get("result", {}).get("tools", []))
                data["raw"] = body
                data["headers"] = headers
                break
            except json.JSONDecodeError:
                data["raw"] = body
                data["headers"] = headers

    # Probe root for version info
    root_status, root_headers, root_body = _fetch_url(url)
    data.setdefault("headers", root_headers)
    data["root_status"] = root_status
    data["root_body"] = root_body[:2000]
    return data


def _load_target_file(filepath: str) -> dict:
    """Load MCP config from a local JSON/YAML file."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {filepath}")
    text = path.read_text(encoding="utf-8")
    data: dict = {"filepath": str(path), "raw": text}
    try:
        parsed = json.loads(text)
        # claude_desktop_config.json structure
        if "mcpServers" in parsed:
            data["mcp_servers"] = parsed["mcpServers"]
        # Generic tools array
        elif "tools" in parsed:
            data["tools"] = parsed["tools"]
        data["parsed"] = parsed
    except json.JSONDecodeError:
        pass  # treat as raw text for pattern scanning
    return data


def _load_target_docker(container: str) -> dict:
    """Extract MCP config from a running Docker container."""
    data: dict = {"container": container}
    try:
        inspect = subprocess.check_output(
            ["docker", "inspect", container],
            timeout=10, stderr=subprocess.DEVNULL
        )
        info = json.loads(inspect)[0]
        data["image"] = info.get("Config", {}).get("Image", "")
        data["env"] = info.get("Config", {}).get("Env", [])
        data["labels"] = info.get("Config", {}).get("Labels", {})
        data["raw"] = json.dumps(info, indent=2)
    except Exception as e:
        data["error"] = str(e)
    return data


# ── Check implementations ──────────────────────────────────────────────────────

def check_cve(data: dict) -> list[Finding]:
    """CHECK 1 — CVE: detect if target components match known MCP CVEs."""
    findings = []
    text = json.dumps(data) + data.get("raw", "") + data.get("root_body", "")

    # Detect version strings
    version_patterns = [
        (r"mcp[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "mcp"),
        (r"@modelcontextprotocol[/\w]*[ @]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "mcp-sdk-ts"),
        (r"claude.desktop[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "claude-desktop"),
    ]
    detected_components: list[tuple[str, str]] = []  # (component, version)
    for pat, comp in version_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            detected_components.append((comp, m.group(1)))

    # Check against CVE DB
    for cve_id, cve in _MCP_CVE_DB.items():
        for affected_str in cve["affected"]:
            for comp, ver in detected_components:
                if comp.lower() in affected_str.lower():
                    findings.append(Finding(
                        check="CVE_EXPOSED",
                        severity=cve["severity"],
                        title=f"{cve_id} — {cve['description'][:60]}...",
                        detail=f"Detected component '{comp} {ver}' matches affected: {affected_str}",
                        owasp=_OWASP_MAP["CVE_EXPOSED"],
                        remediation=cve["fix"],
                        rule_id=cve_id,
                    ))

    # NVD API enrichment (if key available)
    if NVD_API_KEY and not findings:
        findings.extend(_nvd_mcp_check())

    return findings


def _nvd_mcp_check() -> list[Finding]:
    """Query NVD API for recent MCP CVEs."""
    findings = []
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        "?keywordSearch=Model+Context+Protocol+MCP&resultsPerPage=10"
    )
    try:
        req = urllib.request.Request(url, headers={
            "apiKey": NVD_API_KEY,
            "User-Agent": f"mcp-scanner/{VERSION}",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        for item in data.get("vulnerabilities", [])[:5]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss_score = entries[0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            sev = "HIGH" if cvss_score >= 7.0 else ("MEDIUM" if cvss_score >= 4.0 else "LOW")
            findings.append(Finding(
                check="CVE_EXPOSED",
                severity=sev,
                title=f"{cve_id} (NVD) — CVSS {cvss_score}",
                detail=desc[:200],
                owasp=_OWASP_MAP["CVE_EXPOSED"],
                remediation="Check vendor advisories for patches.",
                rule_id=cve_id,
            ))
    except Exception:
        pass
    return findings


def check_tool_poisoning(data: dict) -> list[Finding]:
    """CHECK 2 — Tool poisoning: scan tool definitions for embedded instructions."""
    text = data.get("raw", "") + json.dumps(data.get("tools", []))
    findings = _aguara_scan(text, min_severity="MEDIUM")

    # Additional heuristic: tool descriptions over 500 chars (unusual, suspicious)
    for tool in data.get("tools", []):
        desc = tool.get("description", "") or ""
        if len(desc) > 500:
            findings.append(Finding(
                check="TOOL_POISONING",
                severity="MEDIUM",
                title=f"Unusually long tool description: '{tool.get('name', '?')}'",
                detail=f"Description length {len(desc)} chars — potential instruction injection payload",
                owasp=_OWASP_MAP["TOOL_POISONING"],
                remediation="Review tool description for embedded instructions. Keep descriptions concise.",
                rule_id="MCP_HEURISTIC_001",
            ))
    return findings


def check_auth(data: dict) -> list[Finding]:
    """CHECK 3 — Auth audit: verify MCP server requires authentication."""
    findings = []
    headers = data.get("headers", {})
    root_status = data.get("root_status", 0)

    # Unauthenticated access to tools/list
    if root_status == 200 and data.get("tools"):
        findings.append(Finding(
            check="AUTH_BYPASS",
            severity="HIGH",
            title="MCP tools endpoint publicly accessible without authentication",
            detail=f"GET {data.get('url', data.get('filepath', '?'))} returned tools without auth",
            owasp=_OWASP_MAP["AUTH_BYPASS"],
            remediation="Require authentication (Bearer token / mTLS) on all MCP endpoints in production.",
        ))

    # No WWW-Authenticate header
    header_keys_lower = {k.lower(): v for k, v in headers.items()}
    if root_status == 200 and "www-authenticate" not in header_keys_lower:
        findings.append(Finding(
            check="AUTH_BYPASS",
            severity="MEDIUM",
            title="No WWW-Authenticate header present",
            detail="Server does not advertise authentication requirements",
            owasp=_OWASP_MAP["AUTH_BYPASS"],
            remediation="Add WWW-Authenticate header; enforce Bearer or OAuth 2.0 token validation.",
        ))

    # Check config for missing auth settings
    raw_text = json.dumps(data.get("parsed", {})) + data.get("raw", "")
    auth_patterns = [
        r'"auth"\s*:\s*(?:false|null|"none")',
        r'"authentication"\s*:\s*(?:false|null|"none")',
        r'"secure"\s*:\s*false',
        r'"require_auth"\s*:\s*false',
    ]
    for pat in auth_patterns:
        if re.search(pat, raw_text, re.IGNORECASE):
            findings.append(Finding(
                check="AUTH_BYPASS",
                severity="HIGH",
                title="Authentication explicitly disabled in MCP config",
                detail=f"Pattern matched: {pat[:60]}",
                owasp=_OWASP_MAP["AUTH_BYPASS"],
                remediation="Set auth to true/required. Never disable authentication in production.",
            ))
    return findings


def check_context_exfiltration(data: dict) -> list[Finding]:
    """CHECK 4 — Context exfiltration: detect tools that access system prompt or memory."""
    findings = []
    text = data.get("raw", "")

    exfil_patterns = [
        (r"system_prompt|<system>|system\s+prompt", "System prompt access in tool definition"),
        (r"conversation_history|message_history|chat_history", "Conversation history access"),
        (r"tool_results|previous_results|agent_context", "Agent context access"),
        (r"memory\.read|retrieve_memory|load_context", "Memory/context retrieval"),
        (r"inject.*context|context.*inject", "Potential context injection"),
    ]
    for pat, title in exfil_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            findings.append(Finding(
                check="CONTEXT_EXFILTRATION",
                severity="HIGH",
                title=title,
                detail=f"Match: {repr(m.group()[:80])} — tool may exfiltrate sensitive context",
                owasp=_OWASP_MAP["CONTEXT_EXFILTRATION"],
                remediation="Review if context access is required. Implement read-only scopes. Log all context reads.",
            ))
    return findings


def check_ssrf(data: dict) -> list[Finding]:
    """CHECK 5 — SSRF via MCP tools: tools that fetch external URLs without allowlist."""
    findings = []
    tools = data.get("tools", [])
    text = data.get("raw", "")

    ssrf_tool_patterns = [
        r'"(fetch|http_get|web_fetch|url_fetch|browser_navigate)"',
        r'"type"\s*:\s*"(http|fetch|request|url)"',
    ]
    ssrf_impl_patterns = [
        r"requests\.get\(.*\{",  # URL from user input
        r"urllib\.request.*url\s*=\s*\{",
        r"fetch\(`\$\{",  # Template literal URL
        r"axios\.\w+\(\s*`?\$?\{",
    ]

    for pat in ssrf_tool_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m and not re.search(r"allowlist|whitelist|url_pattern|allowed_domains", text, re.IGNORECASE):
            findings.append(Finding(
                check="SSRF",
                severity="HIGH",
                title=f"HTTP-fetching tool without apparent URL allowlist",
                detail=f"Tool matched: {repr(m.group()[:80])}",
                owasp=_OWASP_MAP["SSRF"],
                remediation="Implement URL allowlist for external requests. Block private/internal IP ranges.",
            ))

    for pat in ssrf_impl_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            findings.append(Finding(
                check="SSRF",
                severity="MEDIUM",
                title="Dynamic URL construction without apparent validation",
                detail=f"Pattern: {repr(m.group()[:80])}",
                owasp=_OWASP_MAP["SSRF"],
                remediation="Validate and sanitize all URLs. Use allowlists, block RFC1918 addresses.",
            ))
    return findings


def check_credential_exposure(data: dict) -> list[Finding]:
    """CHECK 6 — Credential leak: API keys or secrets in MCP config or tool responses."""
    findings = []
    text = data.get("raw", "") + json.dumps(data.get("env", []))

    cred_patterns = [
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI/Anthropic API key"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
        (r"(password|passwd|pwd|secret|token)\s*[=:]\s*['\"]?\S{8,}", "Hardcoded credential"),
        (r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY", "Private key in config"),
    ]
    for pat, title in cred_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            findings.append(Finding(
                check="CREDENTIAL_LEAK",
                severity="CRITICAL",
                title=f"Credential exposure: {title}",
                detail=f"Match at config level (redacted): {repr(m.group()[:20])}...",
                owasp=_OWASP_MAP["CREDENTIAL_LEAK"],
                remediation="Move credentials to environment variables or a secrets manager. Rotate immediately.",
            ))
    return findings


def check_input_validation(data: dict) -> list[Finding]:
    """CHECK 7 — Input validation: tools without parameter schema or sanitization."""
    findings = []
    tools = data.get("tools", [])
    text = data.get("raw", "")

    # Tools without inputSchema
    for tool in tools:
        if not tool.get("inputSchema") and not tool.get("parameters"):
            findings.append(Finding(
                check="INPUT_VALIDATION",
                severity="MEDIUM",
                title=f"Tool '{tool.get('name', '?')}' has no input schema",
                detail="Missing inputSchema means no type validation on tool arguments",
                owasp=_OWASP_MAP["INPUT_VALIDATION"],
                remediation="Add JSON Schema inputSchema with type constraints for all tool parameters.",
            ))

    # Dangerous eval/exec patterns
    danger_patterns = [
        r"eval\s*\(\s*(?:params|args|input|req)\.",
        r"exec\s*\(\s*(?:params|args|input)",
        r"os\.system\s*\(\s*(?:params|args|input|f['\"])",
        r"subprocess\.\w+\s*\(\s*(?:params|args|input|f['\"]|\[.*\+)",
    ]
    for pat in danger_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            findings.append(Finding(
                check="INPUT_VALIDATION",
                severity="CRITICAL",
                title="Unsafe evaluation of user-controlled input",
                detail=f"Pattern: {repr(m.group()[:80])}",
                owasp=_OWASP_MAP["INPUT_VALIDATION"],
                remediation="Never eval/exec user input. Use parameterized calls. Validate inputs against schema.",
            ))
    return findings


def check_rate_limits(data: dict) -> list[Finding]:
    """CHECK 8 — Rate limiting: absence of rate limit headers or config."""
    findings = []
    headers = data.get("headers", {})
    headers_lower = {k.lower(): v for k, v in headers.items()}
    text = data.get("raw", "")

    rate_limit_headers = ["x-ratelimit-limit", "x-rate-limit-limit", "retry-after", "ratelimit-limit"]
    has_rate_limit_header = any(h in headers_lower for h in rate_limit_headers)
    has_rate_limit_config = bool(re.search(
        r"rate_limit|rateLimit|throttle|max_requests|requests_per",
        text, re.IGNORECASE
    ))

    if data.get("url") and not has_rate_limit_header and not has_rate_limit_config:
        findings.append(Finding(
            check="RATE_LIMIT_MISSING",
            severity="MEDIUM",
            title="No rate limiting detected on MCP server",
            detail="No rate limit headers returned; no rate limit config found",
            owasp=_OWASP_MAP["RATE_LIMIT_MISSING"],
            remediation="Implement per-client rate limiting. Return X-RateLimit-Limit/Remaining headers.",
        ))
    return findings


# ── Scanner orchestrator ───────────────────────────────────────────────────────

CHECKS = [
    check_cve,
    check_tool_poisoning,
    check_auth,
    check_context_exfiltration,
    check_ssrf,
    check_credential_exposure,
    check_input_validation,
    check_rate_limits,
]


def scan(target: str = "", filepath: str = "", docker: str = "") -> ScanResult:
    """Run all checks against a target and return a ScanResult."""
    if filepath:
        data = _load_target_file(filepath)
        label = filepath
    elif docker:
        data = _load_target_docker(docker)
        label = f"docker:{docker}"
    elif target:
        data = _load_target_http(target)
        label = target
    else:
        raise ValueError("Provide --target, --file, or --docker")

    result = ScanResult(
        target=label,
        metadata={
            "version": VERSION,
            "checks": len(CHECKS),
            "aguara_rules": len(_AGUARA_MCP_RULES),
        }
    )

    for check_fn in CHECKS:
        try:
            result.findings.extend(check_fn(data))
        except Exception as e:
            print(f"[WARN] {check_fn.__name__} failed: {e}", file=sys.stderr)

    # Deduplicate by (check, title)
    seen: set[tuple] = set()
    deduped = []
    for f in result.findings:
        key = (f.check, f.title[:50])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    result.findings = sorted(deduped, key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
    return result


# ── Output formatters ──────────────────────────────────────────────────────────

def format_text(result: ScanResult) -> str:
    lines = [
        f"mcp-scanner {VERSION} — {result.target}",
        f"Scan time: {result.scan_time}",
        f"Checks run: {result.metadata.get('checks', '?')}  "
        f"Aguara rules: {result.metadata.get('aguara_rules', 0)}",
        "",
    ]
    if not result.findings:
        lines.append("✓ No findings detected.")
        return "\n".join(lines)

    sev_counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for f in result.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    lines.append(
        f"Findings: {sum(sev_counts.values())} total — "
        + "  ".join(f"{k}: {v}" for k, v in sev_counts.items() if v)
    )
    lines.append("")

    for f in result.findings:
        lines += [
            f"[{f.severity}] {f.check} — {f.title}",
            f"  Detail : {f.detail[:120]}",
        ]
        if f.owasp:
            lines.append(f"  OWASP  : {f.owasp}")
        if f.remediation:
            lines.append(f"  Fix    : {f.remediation[:100]}")
        if f.rule_id:
            lines.append(f"  Rule   : {f.rule_id}")
        lines.append("")
    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    return json.dumps({
        "target": result.target,
        "scan_time": result.scan_time,
        "summary": {
            "total": len(result.findings),
            "critical": len(result.critical),
            "high": len(result.high),
            "passed": result.passed,
        },
        "metadata": result.metadata,
        "findings": [f.as_dict() for f in result.findings],
    }, indent=2, ensure_ascii=False)


def format_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 output for GitHub Code Scanning integration."""
    rules = [{"id": f.rule_id or f.check, "name": f.title,
              "shortDescription": {"text": f.title}} for f in result.findings]
    results = []
    for i, f in enumerate(result.findings):
        results.append({
            "ruleId": f.rule_id or f.check,
            "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(f.severity, "note"),
            "message": {"text": f.detail},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": result.target}}}],
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "mcp-scanner", "version": VERSION, "rules": rules}},
                  "results": results}],
    }
    return json.dumps(sarif, indent=2)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"mcp-scanner {VERSION} — MCP Server Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s --target http://mcp-server:3000
  %(prog)s --file claude_desktop_config.json
  %(prog)s --file mcp-config.yaml --output json
  %(prog)s --target http://mcp-server:3000 --exit-code   # CI/CD mode
  %(prog)s --docker my_mcp_container
""")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--target", "-t", metavar="URL",
                     help="MCP server HTTP/S URL")
    src.add_argument("--file", "-f", metavar="PATH",
                     help="Local MCP config file (JSON/YAML)")
    src.add_argument("--docker", "-d", metavar="CONTAINER",
                     help="Docker container name or ID")

    parser.add_argument("--output", "-o", choices=["text", "json", "sarif"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--exit-code", action="store_true",
                        help="Exit 1 if CRITICAL or HIGH findings found (CI/CD mode)")
    parser.add_argument("--min-severity", default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Minimum severity to report (default: LOW)")
    parser.add_argument("--version", action="version", version=f"mcp-scanner {VERSION}")
    args = parser.parse_args()

    result = scan(
        target=args.target or "",
        filepath=args.file or "",
        docker=args.docker or "",
    )

    # Filter by min severity
    min_rank = _SEV_RANK.get(args.min_severity, 0)
    result.findings = [f for f in result.findings if _SEV_RANK.get(f.severity, 0) >= min_rank]

    if args.output == "json":
        print(format_json(result))
    elif args.output == "sarif":
        print(format_sarif(result))
    else:
        print(format_text(result))

    if args.exit_code and not result.passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
