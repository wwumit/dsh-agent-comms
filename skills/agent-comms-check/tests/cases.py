#!/usr/bin/env python3
"""agent-comms-check 边界用例集。

用法: python3 tests/cases.py
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CHECK = ROOT / "skills" / "agent-comms-check" / "scripts" / "agent-comms-check.py"

GOOD_CARD = {
    "name": "research-agent", "description": "Research agent",
    "url": "https://agents.example.com/research", "version": "1.0.0",
    "documentationUrl": "https://docs.example.com/research",
    "capabilities": {"streaming": True, "pushNotifications": True, "stateSyncHandlers": True},
    "security": {"authentication": [{"scheme": "apiKey", "credentials": "api-key"}]},
}


def _mk(base, name, files):
    d = base / name
    d.mkdir(exist_ok=True)
    for f, content in files.items():
        (d / f).write_text(json.dumps(content, ensure_ascii=False) if isinstance(content, (dict, list))
                           else content, encoding="utf-8")
    return d


def _run(target):
    r = subprocess.run([sys.executable, str(CHECK), "--dir", str(target), "--format", "json"],
                       capture_output=True, text=True)
    return json.loads(r.stdout)


CASES = [
    ("good", {"agent-card.json": GOOD_CARD,
              "mcp.json": {"mcpServers": {"local": {"command": "node", "args": ["s.js"]}}}},
     True, []),
    ("missing_card", {}, False, ["ACC-001"]),
    ("missing_fields", {"agent-card.json": {"name": "x"}}, False, ["ACC-002", "ACC-003"]),
    ("http_endpoint", {"agent-card.json": dict(GOOD_CARD, url="http://agents.example.com")},
     False, ["ACC-003"]),
    ("auth_none_remote", {"agent-card.json": dict(GOOD_CARD,
        security={"authentication": [{"scheme": "none"}]})}, False, ["ACC-005"]),
    ("mcp_hardcoded_secret", {"agent-card.json": GOOD_CARD,
        "mcp.json": {"mcpServers": {"r": {"url": "https://x", "env": {"OPENAI_API_KEY": "sk-1"}}}}},
     False, ["ACC-006"]),
    ("mcp_http", {"agent-card.json": GOOD_CARD,
        "mcp.json": {"mcpServers": {"r": {"url": "http://api.example.com/mcp"}}}},
     False, ["ACC-006"]),
]


def main():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        fails = 0
        for name, files, expect_pass, expect_rules in CASES:
            d = _mk(base, name, files)
            r = _run(d)
            got_rules = {i["rule"] for i in r["issues"]}
            ok_pass = (r["conclusion"] == "PASS") == expect_pass
            ok_rules = all(x in got_rules for x in expect_rules)
            status = "✅" if (ok_pass and ok_rules) else "❌"
            if status == "❌":
                fails += 1
            print(f"{status} {name}: score={r['score']} {r['conclusion']} rules={sorted(got_rules)}")
        print(f"\n{len(CASES) - fails}/{len(CASES)} 通过")
        sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
