#!/usr/bin/env python3
"""
agent-comms-check — Agent 间通信配置合规检查器
================================================
检查一个 Agent 项目的通信配置是否合规、披露是否完整、安全基线是否达标：

  ACC-001  agent-card.json 存在且可解析（A2A Agent Card）
  ACC-002  必填字段（name/description/url/version）
  ACC-003  端点安全（https 传输、非内网地址在远程场景告警）
  ACC-004  capabilities 声明完整（streaming/pushNotifications/stateSyncHandlers）
  ACC-005  security.authentication 配置（none 在非本地场景告警；apiKey/oauth2 检查凭证引用）
  ACC-006  MCP 配置检查（mcpServers：env 硬编码凭据、远程端点、命令路径）
  ACC-007  通信披露完整性（端点声明、凭据处理、法域、保留——类比技能 disclosure）
  ACC-008  版本与文档（semver、documentationUrl）

纯 Python 标准库，零依赖，无网络请求。输出与 skill 家族同风格（评分 + 结论 + 问题列表）。
"""

import argparse
import json
import os
import re
import sys
import urllib.request

# CHA2A registry 端点（可覆盖；--verify-registry 时用于核验声明身份/披露）
CHA2A_BASE = os.environ.get("CHA2A_REGISTRY", "https://compliancehub.cn")

CARD_NAMES = ("agent-card.json", "agentcard.json", "agent_card.json")
MCP_NAMES = ("mcp.json", "mcp-config.json")
REQUIRED_FIELDS = ("name", "description", "url", "version")


def _find(base, names):
    for n in names:
        p = os.path.join(base, n)
        if os.path.exists(p):
            return p
    return None


def _verify_registry_did(did, issues, add, timeout=10):
    """在线核验：CHA2A registry 查询 DID 注册/等级/撤销状态。
    用于"配置声明的身份 ↔ registry 事实"对账（防伪声明）。"""
    try:
        from urllib.parse import quote
        url = f"{CHA2A_BASE}/api/v1/trust/query?did={quote(did, safe='')}"
        req = urllib.request.Request(url, headers={"User-Agent": "agent-comms-check/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            add("ACC-008", "medium", f"声明的身份未在 CHA2A registry 注册（{did[:40]}）",
                "配置声明的 DID 不存在——需先注册（POST /api/v1/register）")
        else:
            add("ACC-008", "medium", f"CHA2A registry 核验失败（{did[:40]}）: HTTP {e.code}",
                "registry 查询失败，稍后重试或检查 CHA2A_REGISTRY")
        return
    except Exception as e:
        add("ACC-008", "medium", f"CHA2A registry 核验失败（{did[:40]}）: {str(e)[:60]}",
            "无法连接 cha2a registry（CHA2A_REGISTRY 可覆盖）")
        return
    record = data.get("record") or data
    status = record.get("status", "active")
    if status not in ("active", None):
        add("ACC-008", "high", f"声明的身份已撤销/非活跃（{did[:40]}，status={status}）",
            "配置声明的 DID 在 registry 中已撤销——不可用于通信")
    level = record.get("level", 0)
    if level == 0:
        add("ACC-008", "low", f"声明的身份未认证（{did[:40]}，L0）",
            "L0 表示尚无验证证据；建议声明已认证的 DID（L1+）")


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def check(target: str, verify_registry: bool = False) -> dict:
    issues = []

    def add(rule, severity, found, recommendation):
        issues.append({"rule": rule, "severity": severity, "found": found,
                       "recommendation": recommendation})

    # ACC-001 / ACC-002 Agent Card
    card_path = _find(target, CARD_NAMES)
    if card_path is None:
        add("ACC-001", "high", f"未找到 Agent Card（{'/'.join(CARD_NAMES)}）",
            "A2A 规范要求 Agent 提供 agent-card.json（能力/端点/安全声明）")
        card = None
    else:
        card = _load_json(card_path)
        if card is None:
            add("ACC-001", "high", f"Agent Card 无法解析: {os.path.basename(card_path)}",
                "JSON 格式需合法")
        else:
            missing = [f for f in REQUIRED_FIELDS if not card.get(f)]
            if missing:
                add("ACC-002", "high", f"Agent Card 缺少必填字段: {', '.join(missing)}",
                    "A2A 必填：name/description/url/version")

    if card is not None and isinstance(card, dict):
        # ACC-003 端点安全
        url = card.get("url", "")
        if url:
            if not url.startswith("https://") and not url.startswith("http://localhost"):
                add("ACC-003", "high" if not url.startswith("http://localhost") else "medium",
                    f"端点非 HTTPS: {url}", "Agent 间通信应使用 HTTPS 传输")
            if "http://localhost" in url or "127.0.0.1" in url:
                add("ACC-003", "low", f"端点为本地地址: {url}",
                    "本地/内网端点仅适合开发环境，远程部署需公网 HTTPS")
        else:
            add("ACC-003", "medium", "Agent Card 缺 url", "端点 URL 是 A2A 交互入口，必须声明")

        # ACC-004 capabilities
        caps = card.get("capabilities") or {}
        known = ["streaming", "pushNotifications", "stateSyncHandlers"]
        missing_caps = [c for c in known if c not in caps]
        if missing_caps:
            add("ACC-004", "low", f"capabilities 未声明: {', '.join(missing_caps)}",
                "A2A 标准 capability（streaming/pushNotifications/stateSyncHandlers）建议显式声明")

        # ACC-005 security.authentication
        sec = card.get("security") or {}
        auth = sec.get("authentication") or []
        schemes = [a.get("scheme") for a in auth if isinstance(a, dict)]
        if not schemes:
            add("ACC-005", "medium", "security.authentication 未配置",
                "建议声明认证方案（apiKey/oauth2/oidc）；none 仅适合完全可信环境")
        elif "none" in schemes and not (card.get("url", "").startswith("http://localhost")):
            add("ACC-005", "medium", "认证方案为 none（非本地端点）",
                "公开端点不应允许匿名访问，建议 apiKey/oauth2/oidc")
        for a in auth:
            if isinstance(a, dict) and a.get("scheme") in ("apiKey", "oauth2", "oidc"):
                cred = a.get("credentials")
                if cred is None and a.get("scheme") == "apiKey":
                    add("ACC-005", "medium", f"认证方案 {a.get('scheme')} 缺 credentials 引用",
                        "apiKey 需声明 credentials（查询参数/头部）")

        # ACC-008 版本与文档
        ver = card.get("version", "")
        if ver and not re.match(r"^\d+\.\d+\.\d+", ver):
            add("ACC-008", "medium", f"version 非语义化版本: {ver}", "建议 SemVer (x.y.z)")
        if not card.get("documentationUrl"):
            add("ACC-008", "low", "缺 documentationUrl", "建议提供文档地址便于消费方集成")

    # ACC-006 MCP 配置
    mcp_path = _find(target, MCP_NAMES)
    if mcp_path is not None:
        mcp = _load_json(mcp_path)
        servers = (mcp or {}).get("mcpServers") or {}
        if isinstance(servers, dict):
            for name, cfg in servers.items():
                if not isinstance(cfg, dict):
                    continue
                env = cfg.get("env") or {}
                for k, v in env.items():
                    if isinstance(v, str) and re.search(r"(sk-|api[_-]?key|token|secret|password)", k, re.I):
                        add("ACC-006", "high", f"MCP server '{name}' env 含疑似凭据: {k}",
                            "凭据不应硬编码在 mcp.json（用环境变量注入/密钥管理）")
                if cfg.get("url"):
                    if not cfg["url"].startswith("https://"):
                        add("ACC-006", "high" if not cfg["url"].startswith("http://localhost") else "medium",
                            f"MCP server '{name}' 远程端点非 HTTPS: {cfg['url']}",
                            "远程 MCP 端点需 HTTPS 传输")
                if not cfg.get("command") and not cfg.get("url"):
                    add("ACC-006", "medium", f"MCP server '{name}' 缺 command/url",
                        "MCP server 需 command（本地）或 url（远程）")

    # ACC-007 通信披露完整性（扩展 disclosure 理念到通信层）
    # 检查 agent-card 是否声明了数据去向/保留（非标准字段，作为披露扩展）
    if card is not None and isinstance(card, dict):
        disc = card.get("disclosure") or card.get("x-disclosure")
        if disc is None:
            add("ACC-007", "low", "Agent Card 未含 disclosure 扩展字段",
                "建议声明通信数据行为（端点/凭据/法域/保留）——对齐 wwumit 披露理念")

    # ACC-008 在线核验：配置声明的身份 ↔ CHA2A registry 事实对账（防伪声明）
    if verify_registry:
        verified_any = False
        # 1) Agent Card 中的身份声明（did / trustAnchor / security.did）
        if card is not None and isinstance(card, dict):
            sec = card.get("security") or {}
            dids = []
            for k in ("did", "trustAnchor", "agentDid"):
                if sec.get(k):
                    dids.append(sec[k])
            for d in dids:
                if isinstance(d, str) and d.startswith("did:"):
                    _verify_registry_did(d, issues, add)
                    verified_any = True
        # 2) MCP server 中的身份声明（server.did / url 域名对应的 registry 记录不在此列）
        mcp_path = _find(target, MCP_NAMES)
        if mcp_path is not None:
            mcp = _load_json(mcp_path)
            servers = (mcp or {}).get("mcpServers") or {}
            if isinstance(servers, dict):
                for name, cfg in servers.items():
                    if isinstance(cfg, dict) and isinstance(cfg.get("did"), str) and cfg["did"].startswith("did:"):
                        _verify_registry_did(cfg["did"], issues, add)
                        verified_any = True
        if not verified_any:
            add("ACC-008", "low", "配置中未发现可在线核验的 DID 身份声明",
                "--verify-registry 需要配置声明 did/trustAnchor 才能对账")

    # 评分
    sev_w = {"high": 20, "medium": 8, "low": 3}
    score = max(0, 100 - sum(sev_w.get(i["severity"], 0) for i in issues))
    has_high = any(i["severity"] == "high" for i in issues)
    conclusion = "PASS" if score >= 90 and not has_high else ("NEEDS_FIX" if has_high else "REVIEW")
    return {"score": score, "conclusion": conclusion, "issues": issues,
            "mode": "online" if verify_registry else "offline",
            "registry": CHA2A_BASE if verify_registry else None}


def main():
    ap = argparse.ArgumentParser(description="Agent 间通信配置合规检查器")
    ap.add_argument("--dir", "-d", required=True, help="目标 Agent 项目目录")
    ap.add_argument("--format", "-f", choices=["text", "json"], default="text")
    ap.add_argument("--verify-registry", action="store_true",
                    help="在线核验：调用 CHA2A registry 对账配置声明的身份（DID 注册/等级/撤销）")
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        print(f"错误：目录不存在 {args.dir}", file=sys.stderr)
        sys.exit(1)

    result = check(args.dir, verify_registry=args.verify_registry)
    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print("╔══ agent-comms-check ══ " + args.dir)
    mode = "在线（CHA2A registry）" if args.verify_registry else "离线（结构检查）"
    print(f"║ 模式：{mode}")
    print(f"║ 评分：{result['score']}/100  |  结论：{result['conclusion']}")
    if not result["issues"]:
        print("║ ✅ Agent 通信配置合规，未发现问题")
    for i in result["issues"]:
        sev = i["severity"].upper()
        print(f"║ [{sev:>7}] ({i['rule']})")
        print(f"║   → {i['found']}")
        print(f"║   建议：{i['recommendation']}")
    print("╚════════════════════════════════════")
    sys.exit(0 if result["conclusion"] == "PASS" else 1)


if __name__ == "__main__":
    main()
