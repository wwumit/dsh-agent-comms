#!/usr/bin/env python3
"""agent-comms-disclosure 用例集（check/gen/validate）。

用法: python3 tests/cases.py
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "skills" / "agent-comms-disclosure" / "scripts" / "agent-comms-disclosure.py"

GOOD_CARD = {
    "name": "research-agent", "description": "Research agent",
    "url": "https://agents.example.com/research", "version": "1.0.0",
    "capabilities": {"streaming": True},
    "security": {"authentication": [{"scheme": "apiKey", "credentials": "api-key"}]},
}
FULL_DISC = {
    "schemaVersion": "agent-comms-disclosure-v1",
    "endpoints": ["https://agents.example.com/research"],
    "messageTypes": ["request", "response"],
    "dataCategories": ["text"],
    "credentials": [{"name": "COMPLIANCEHUB_API_KEY", "storage": "env"}],
    "jurisdiction": ["CN"], "retention": "session", "thirdParty": False, "pay": False,
}


def _mk(base, name, files):
    d = base / name
    d.mkdir(exist_ok=True)
    for f, content in files.items():
        (d / f).write_text(json.dumps(content, ensure_ascii=False) if isinstance(content, (dict, list))
                           else content, encoding="utf-8")
    return d


def _run_check(target):
    r = subprocess.run([sys.executable, str(TOOL), "check", "--dir", str(target), "--format", "json"],
                       capture_output=True, text=True)
    return json.loads(r.stdout)


CASES = [
    ("full_disclosure", {"agent-card.json": GOOD_CARD, "agent-disclosure.json": FULL_DISC},
     True, []),
    ("no_disclosure", {"agent-card.json": GOOD_CARD}, False, ["ACD-001"]),
    ("missing_required", {"agent-card.json": GOOD_CARD,
        "agent-disclosure.json": {"schemaVersion": "agent-comms-disclosure-v1",
                                   "endpoints": ["https://x"]}}, False, ["ACD-002"]),
    ("undisclosed_cred", {"agent-card.json": GOOD_CARD,
        "agent-disclosure.json": dict(FULL_DISC, credentials=[]),
        "mcp.json": {"mcpServers": {"r": {"url": "https://x",
                                           "env": {"OPENAI_API_KEY": "sk-1"}}}}},
     False, ["ACD-005"]),
    ("mcp_endpoint_not_declared", {"agent-card.json": GOOD_CARD,
        "agent-disclosure.json": dict(FULL_DISC),
        "mcp.json": {"mcpServers": {"r": {"url": "https://unlisted.example.com/mcp"}}}},
     False, ["ACD-004"]),
]


def main():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        fails = 0
        for name, files, expect_pass, expect_rules in CASES:
            d = _mk(base, name, files)
            r = _run_check(d)
            got = {i["rule"] for i in r["issues"]}
            ok_pass = (r["conclusion"] == "PASS") == expect_pass
            ok_rules = all(x in got for x in expect_rules)
            status = "✅" if (ok_pass and ok_rules) else "❌"
            if status == "❌":
                fails += 1
            print(f"{status} {name}: score={r['score']} {r['conclusion']} rules={sorted(got)}")
        print(f"\n{len(CASES) - fails}/{len(CASES)} 通过")
        sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
