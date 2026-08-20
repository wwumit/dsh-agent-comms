#!/usr/bin/env python3
"""agent-trust-probe 边界用例集。

用法: python3 tests/cases.py
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PROBE = ROOT / "skills" / "agent-trust-probe" / "scripts" / "agent-trust-probe.py"

GOOD_TRUST = {
    "version": "1.0.0",
    "documentationUrl": "https://docs.example.com/trust",
    "trustAnchor": "did:cha2a:org:example-corp",
    "chain": [
        {"delegator": "did:cha2a:org:example-corp",
         "delegatedAgent": "did:cha2a:agent:worker-1",
         "scope": "tools.read-only",
         "chainRef": "ref:delegations/001.json"}
    ],
    "messageEvidence": "ref:evidence/calls.json",
    "disclosure": {"endpoints": ["https://api.example.com"], "dataCategories": ["query"]},
}

GOOD_CARD = {
    "name": "worker-1", "description": "Worker agent",
    "url": "https://agents.example.com/worker-1", "version": "1.0.0",
    "security": {"trustAnchor": "did:cha2a:org:example-corp"},
}


def _mk(base, name, files):
    d = base / name
    d.mkdir(exist_ok=True)
    for f, content in files.items():
        p = d / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(content, ensure_ascii=False) if isinstance(content, (dict, list))
                     else content, encoding="utf-8")
    return d


def _run(target):
    r = subprocess.run([sys.executable, str(PROBE), "--dir", str(target), "--format", "json"],
                       capture_output=True, text=True)
    return json.loads(r.stdout)


CASES = [
    ("good", {"agent-card.json": GOOD_CARD, "trust.json": GOOD_TRUST,
              "evidence/calls.json": {"calls": []}},
     True, []),
    # 无信任声明 + card 也无信任锚 → ATP-001/002/004/005 全触发
    ("no_trust", {"agent-card.json": {k: v for k, v in GOOD_CARD.items() if k != "security"}},
     False, ["ATP-001", "ATP-002", "ATP-004", "ATP-005"]),
    ("incomplete_hop", {"agent-card.json": GOOD_CARD,
                        "trust.json": {"trustAnchor": "did:cha2a:org:example-corp",
                                       "chain": [{"delegator": "did:cha2a:org:example-corp"}]}},
     False, ["ATP-002"]),
    ("cycle", {"agent-card.json": GOOD_CARD,
               "trust.json": {"trustAnchor": "did:cha2a:org:example-corp",
                              "chain": [
                                  {"delegator": "a", "delegatedAgent": "b", "scope": "s", "chainRef": "r1"},
                                  {"delegator": "b", "delegatedAgent": "a", "scope": "s", "chainRef": "r2"}]}},
     False, ["ATP-007"]),
    ("broken_cascade", {"agent-card.json": GOOD_CARD,
                        "trust.json": {"trustAnchor": "did:cha2a:org:example-corp",
                                       "chain": [
                                           {"delegator": "x", "delegatedAgent": "y", "scope": "s", "chainRef": "r1"},
                                           {"delegator": "z", "delegatedAgent": "w", "scope": "s", "chainRef": "r2"}]}},
     False, ["ATP-003"]),
    ("bad_anchor", {"agent-card.json": GOOD_CARD,
                    "trust.json": {"trustAnchor": "??bad??",
                                   "chain": [{"delegator": "a", "delegatedAgent": "b", "scope": "s", "chainRef": "r"}]}},
     False, ["ATP-004"]),
    ("missing_evidence_ref", {"agent-card.json": GOOD_CARD,
                              "trust.json": dict(GOOD_TRUST, messageEvidence="ref:nonexistent.json")},
     False, ["ATP-005"]),
]


def main():
    passed = failed = 0
    for name, files, expect_pass, expect_rules in CASES:
        with tempfile.TemporaryDirectory() as td:
            d = _mk(Path(td), name, files)
            report = _run(d)
            score = report.get("score", 0)
            rules = [i["rule"] for i in report.get("issues", [])]
            ok = True
            if expect_pass and report.get("conclusion") != "PASS":
                ok = False
            if not expect_pass and report.get("conclusion") == "PASS":
                ok = False
            for r in expect_rules:
                if r not in rules:
                    ok = False
            if ok:
                passed += 1
                print(f"✅ {name}: {report.get('conclusion')} score={score}")
            else:
                failed += 1
                print(f"❌ {name}: conclusion={report.get('conclusion')} score={score} rules={rules}")
                print(f"   期望规则含 {expect_rules}")
    print(f"\n{passed}/{passed+failed} 通过")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
