#!/usr/bin/env python3
"""
agent-comms-disclosure — Agent 间通信披露契约（agent-comms 系列）
==================================================================
把"披露即治理"理念从技能层迁移到通信层：Agent 间通信的数据行为（发什么、去哪、怎么存）
必须机器可读披露，装/接入前可见。提供三个子命令：

  check    检查 Agent 项目的通信披露完整性（必填字段 D1/D3/D4 对齐）
  gen      从 agent-card.json + mcp.json 生成披露契约模板（agent-disclosure.json）
  validate 校验披露契约文件是否符合 schema

披露契约 schema（agent-comms-disclosure-v1）：
  endpoints    通信端点（A2A url / MCP 端点）——必填
  messageTypes 消息类型（request/response/event/stream）
  dataCategories 传输的数据类别（text/file/credentials/user-data）
  credentials  凭据处理（name/storage: env|file-0600|embedded）——必填
  jurisdiction 适用法域——必填
  retention    消息保留（none/session/server）——必填
  thirdParty   是否转发第三方
  pay          是否付费/额度

纯 Python 标准库，零依赖，无网络请求。输出与 skill 家族同风格。
"""

import argparse
import json
import os
import re
import sys

SCHEMA_VERSION = "agent-comms-disclosure-v1"
REQUIRED = ["endpoints", "credentials", "jurisdiction", "retention"]
RETENTION_VALUES = ("none", "session", "server")
CARD_NAMES = ("agent-card.json", "agentcard.json")
MCP_NAMES = ("mcp.json", "mcp-config.json")
DISC_FILE = "agent-disclosure.json"
CRED_KEYS = re.compile(r"(api[_-]?key|token|secret|password)", re.I)


def _find(base, names):
    for n in names:
        p = os.path.join(base, n)
        if os.path.exists(p):
            return p
    return None


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _get_disclosure(target):
    """返回 (disclosure dict, 来源说明)。优先级：Agent Card 内嵌 disclosure/x-disclosure → 独立文件。"""
    card_path = _find(target, CARD_NAMES)
    if card_path:
        card = _load_json(card_path)
        if isinstance(card, dict):
            for k in ("disclosure", "x-disclosure", "comms-disclosure"):
                if isinstance(card.get(k), dict):
                    return card[k], f"{os.path.basename(card_path)}#{k}"
    disc_path = os.path.join(target, DISC_FILE)
    if os.path.exists(disc_path):
        d = _load_json(disc_path)
        if isinstance(d, dict):
            return d, DISC_FILE
    return None, None


def check(target: str) -> dict:
    issues = []
    disc, src = _get_disclosure(target)
    if disc is None:
        return {"score": 0, "conclusion": "NEEDS_FIX",
                "issues": [{"rule": "ACD-001", "severity": "high",
                            "found": "未找到通信披露契约",
                            "recommendation": f"在 Agent Card 内嵌 disclosure 或提供 {DISC_FILE}（可用 gen 生成）"}]}

    def add(rule, sev, found, rec):
        issues.append({"rule": rule, "severity": sev, "found": found, "recommendation": rec})

    # 必填字段
    for f in REQUIRED:
        v = disc.get(f)
        if v is None or v == "" or v == []:
            add("ACD-002", "high" if f in ("endpoints", "credentials") else "medium",
                f"必填字段缺失: {f}", f"披露契约必填：{', '.join(REQUIRED)}")
    # retention 合法值
    if disc.get("retention") and disc["retention"] not in RETENTION_VALUES:
        add("ACD-003", "medium", f"retention 非法值: {disc['retention']}",
            f"合法值：{'/'.join(RETENTION_VALUES)}")
    # endpoints 与 Agent Card url / MCP 端点一致性（声明-配置一致）
    card_path = _find(target, CARD_NAMES)
    if card_path:
        card = _load_json(card_path)
        if isinstance(card, dict) and card.get("url"):
            declared = disc.get("endpoints") or []
            if card["url"] not in declared and not any(
                    e.rstrip("/") == card["url"].rstrip("/") for e in declared if isinstance(e, str)):
                add("ACD-004", "high",
                    f"Agent Card url 未在披露 endpoints 中声明: {card['url']}",
                    "披露的 endpoints 应覆盖实际通信端点（声明-配置一致）")
    mcp_path = _find(target, MCP_NAMES)
    if mcp_path:
        mcp = _load_json(mcp_path)
        servers = (mcp or {}).get("mcpServers") or {}
        declared = disc.get("endpoints") or []
        for name, cfg in servers.items():
            if isinstance(cfg, dict) and cfg.get("url"):
                if cfg["url"] not in declared and not any(
                        e.rstrip("/") == cfg["url"].rstrip("/") for e in declared if isinstance(e, str)):
                    add("ACD-004", "high",
                        f"MCP server '{name}' url 未在披露 endpoints 中声明: {cfg['url']}",
                        "披露应覆盖 MCP 端点")
    # 凭据与 mcp env 一致性（披露了但配置里有未披露的凭据键）
    if mcp_path:
        mcp = _load_json(mcp_path)
        servers = (mcp or {}).get("mcpServers") or {}
        declared_creds = [c.get("name") for c in (disc.get("credentials") or []) if isinstance(c, dict)]
        for name, cfg in servers.items():
            if isinstance(cfg, dict):
                for k in (cfg.get("env") or {}):
                    if CRED_KEYS.search(k) and k not in declared_creds:
                        add("ACD-005", "high",
                            f"MCP server '{name}' 含未披露凭据键: {k}",
                            "凭据必须在披露契约的 credentials 中声明（name/storage）")

    sev_w = {"high": 20, "medium": 8, "low": 3}
    score = max(0, 100 - sum(sev_w.get(i["severity"], 0) for i in issues))
    has_high = any(i["severity"] == "high" for i in issues)
    conclusion = "PASS" if score >= 90 and not has_high else ("NEEDS_FIX" if has_high else "REVIEW")
    return {"score": score, "conclusion": conclusion, "source": src, "issues": issues}


def gen(target: str) -> dict:
    """从 agent-card.json + mcp.json 生成披露契约。"""
    disc = {"schemaVersion": SCHEMA_VERSION, "endpoints": [], "messageTypes": [],
            "dataCategories": [], "credentials": [], "jurisdiction": [], "retention": "none",
            "thirdParty": False, "pay": False}

    card_path = _find(target, CARD_NAMES)
    if card_path:
        card = _load_json(card_path)
        if isinstance(card, dict):
            if card.get("url"):
                disc["endpoints"].append(card["url"])
            caps = card.get("capabilities") or {}
            if caps.get("streaming"):
                disc["messageTypes"].append("stream")
            if caps.get("pushNotifications"):
                disc["messageTypes"].append("event")

    mcp_path = _find(target, MCP_NAMES)
    if mcp_path:
        mcp = _load_json(mcp_path)
        servers = (mcp or {}).get("mcpServers") or {}
        for name, cfg in servers.items():
            if isinstance(cfg, dict):
                if cfg.get("url"):
                    disc["endpoints"].append(cfg["url"])
                for k in (cfg.get("env") or {}):
                    if CRED_KEYS.search(k):
                        disc["credentials"].append({"name": k, "storage": "env"})
        if servers:
            disc["messageTypes"].append("request")
            disc["messageTypes"].append("response")

    disc["endpoints"] = sorted(set(disc["endpoints"]))
    disc["messageTypes"] = sorted(set(disc["messageTypes"]))
    disc["dataCategories"] = ["text"]
    return disc


def validate(disc: dict) -> dict:
    issues = []
    if disc.get("schemaVersion") != SCHEMA_VERSION:
        issues.append({"rule": "ACD-010", "severity": "medium",
                       "found": f"schemaVersion 不符: {disc.get('schemaVersion')}",
                       "recommendation": f"应为 {SCHEMA_VERSION}"})
    for f in REQUIRED:
        if disc.get(f) in (None, "", []):
            issues.append({"rule": "ACD-011", "severity": "high",
                           "found": f"必填字段缺失: {f}", "recommendation": "补齐必填字段"})
    if disc.get("retention") not in RETENTION_VALUES:
        issues.append({"rule": "ACD-012", "severity": "medium",
                       "found": f"retention 非法: {disc.get('retention')}",
                       "recommendation": f"合法值：{'/'.join(RETENTION_VALUES)}"})
    return {"valid": not any(i["severity"] == "high" for i in issues), "issues": issues}


def main():
    ap = argparse.ArgumentParser(description="Agent 间通信披露契约工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="检查披露完整性")
    p_check.add_argument("--dir", "-d", required=True)
    p_check.add_argument("--format", "-f", choices=["text", "json"], default="text")

    p_gen = sub.add_parser("gen", help="从 Agent Card/MCP 配置生成披露契约")
    p_gen.add_argument("--dir", "-d", required=True)
    p_gen.add_argument("--output", "-o", default=None, help="输出文件（默认打印）")

    p_val = sub.add_parser("validate", help="校验披露契约文件")
    p_val.add_argument("--file", required=True)

    args = ap.parse_args()

    if args.cmd == "check":
        r = check(args.dir)
        if args.format == "json":
            print(json.dumps(r, ensure_ascii=False, indent=2)); return
        print("╔══ agent-comms-disclosure check ══ " + args.dir)
        print(f"║ 披露来源：{r.get('source', '-')}")
        print(f"║ 评分：{r['score']}/100  |  结论：{r['conclusion']}")
        for i in r["issues"]:
            print(f"║ [{i['severity'].upper():>7}] ({i['rule']})")
            print(f"║   → {i['found']}")
            print(f"║   建议：{i['recommendation']}")
        print("╚════════════════════════════════════")
        sys.exit(0 if r["conclusion"] == "PASS" else 1)
    elif args.cmd == "gen":
        d = gen(args.dir)
        out = json.dumps(d, ensure_ascii=False, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out + "\n")
            print(f"已生成 {args.output}")
        else:
            print(out)
    elif args.cmd == "validate":
        d = _load_json(args.file)
        if d is None:
            print("文件无法解析", file=sys.stderr); sys.exit(1)
        r = validate(d)
        print("✅ schema 有效" if r["valid"] else "❌ schema 无效")
        for i in r["issues"]:
            print(f"  [{i['severity']}] {i['found']} — {i['recommendation']}")
        sys.exit(0 if r["valid"] else 1)


if __name__ == "__main__":
    main()
