# mcp-scanner — MCP Server Security Scanner

> Audit Model Context Protocol (MCP) servers for vulnerabilities before connecting AI agents.

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-orange)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

---

## What it does

MCP (Model Context Protocol) servers execute with implicit trust when connected to AI agents like Claude Code. mcp-scanner audits them across **8 security categories** before you connect.

**Checks:**
| # | Category | What it detects |
|---|---|---|
| 1 | CVE exposure | Known vulnerabilities in MCP SDK dependencies (incl. 2026 SDK RCE cluster) |
| 2 | Tool poisoning | Hidden instructions, zero-width Unicode, BiDi override chars in tool descriptions |
| 3 | Auth configuration | Missing or weak authentication |
| 4 | Context exfiltration | Tools that leak conversation data to external endpoints |
| 5 | SSRF | Server-side request forgery via tool calls |
| 6 | Credential leaks | API keys/tokens in tool responses or config |
| 7 | Input validation | Missing schema, injection vectors in tool parameters |
| 8 | Rate limits | Unbounded consumption risks |
| 9 | Supply chain | Time-bomb logic, eval/exec in manifests, exfil endpoints (MITRE T1195.002) |

**OWASP LLM Top 10 coverage**: LLM01 (Prompt Injection), LLM07 (System Prompt Leakage), LLM08 (Excessive Agency), LLM09, LLM10

---

## Installation

**Requirements**: Python 3.10+ | No mandatory external dependencies

```bash
git clone https://github.com/mk-scorpiosec/mcp-scanner.git
cd mcp-scanner

# Optional: NVD API key for CVE enrichment (free at nvd.nist.gov)
export NVD_API_KEY=your_key_here
```

---

## Quick Start

```bash
# Scan an MCP server endpoint
python3 mcp_scanner.py --target http://mcp-server:3000

# Scan from Claude Desktop config file
python3 mcp_scanner.py --file ~/.claude/claude_desktop_config.json

# Scan a Docker container
python3 mcp_scanner.py --docker mcp_container_name

# JSON output for pipeline integration
python3 mcp_scanner.py --target http://server:3000 --output json > findings.json

# CI/CD mode (non-zero exit on findings)
python3 mcp_scanner.py --target http://server:3000 --exit-code
```

## Example Output

```
[mcp-scanner] Scanning: http://mcp-server:3000
  [HIGH] Tool Poisoning: Tool description contains override instructions
  [HIGH] Context Exfiltration: Tool sends conversation data to external endpoint
  [MEDIUM] Auth Configuration: No authentication required
  [INFO] Rate Limits: No rate limiting detected

Summary: 3 findings (1 HIGH, 1 HIGH, 1 MEDIUM, 1 INFO)
```

---

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Scan MCP server
  run: |
    python3 mcp_scanner.py --target ${{ env.MCP_SERVER_URL }} \
      --output sarif > mcp-results.sarif \
      --exit-code
```

---

## License

MIT — MK ScorpioSec | [github.com/MK-ScorpioSec](https://github.com/MK-ScorpioSec)
