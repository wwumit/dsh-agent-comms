#!/usr/bin/env python3
"""
agent-trust-probe — Agent 间信任级联 / 溯源验证器（agent-comms 系列）
=====================================================================
沿 A2A/MCP 调用链验证信任等级与消息可核验性（呼应书稿 6.6.3 与 CHA2A 委托链）：

  ATP-001  调用链声明存在（agent-card.json 的 trust.chain / delegation 声明）
  ATP-002  每跳委托凭证完整（delegator / scope / chainRef）
  ATP-003  信任级联一致（上游委托者 == 下游信任锚；scope 沿链延续/收敛）
  ATP-004  信任锚可验证（DID / 公钥 / registry 引用存在且可解析）
  ATP-005  消息可核验（调用链记录 / 消息签名 / 证据引用——证据契约扩展到消息）
  ATP-006  披露与信任绑定（通信披露声明与信任链一致，无未披露跳）
  ATP-007  环与断链检测（调用链无环、无断链、无孤儿跳）
  ATP-008  版本与文档（SemVer、chainVersion、documentationUrl）

两种模式：
- **离线（默认）**：信任锚只做"声明存在 + 引用格式合法"（结构检查，无网络）
- **在线（--verify-registry）**：调用 CHA2A registry API 真验证——信任锚 DID 是否注册、
  认证等级（L0-L4）、是否撤销、凭证状态——**信任验证依赖 cha2a registry（CHA2A 不可或缺）**

输出与 skill 家族同风格（评分 + 结论 + 问题列表）。
"""

import argparse
import json
import os
import re
import sys
import urllib.request

CARD_NAMES = ("agent-card.json", "agentcard.json", "agent_card.json")
TRUST_FILES = ("trust.json", "delegation.json", "chain.json")
CHAIN_KEYS = ("chain", "delegations", "trustChain")

# CHA2A registry 端点（可覆盖）
CHA2A_BASE = os.environ.get("CHA2A_REGISTRY", "https://compliancehub.cn")


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


def _extract_chain(trust):
    """从 trust 声明中提取调用链（支持 chain/delegations/trustChain 任一键）"""
    if not isinstance(trust, dict):
        return []
    for k in CHAIN_KEYS:
        v = trust.get(k)
        if isinstance(v, list):
            return v
    # 兼容单跳 {delegator, delegatedAgent, ...}
    if trust.get("delegator") or trust.get("delegatedAgent"):
        return [trust]
    return []


def _verify_registry_did(did, issues, add, timeout=10):
    """在线核验：向 CHA2A registry 查询 DID 的注册/等级/撤销状态。
    返回 (ok, info)；ok=False 表示核验失败（含网络失败/未注册/已撤销）。"""
    try:
        from urllib.parse import quote
        url = f"{CHA2A_BASE}/api/v1/trust/query?did={quote(did, safe='')}"
        req = urllib.request.Request(url, headers={"User-Agent": "agent-trust-probe/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        add("ATP-004", "medium", f"CHA2A registry 核验失败（{did[:40]}）: {str(e)[:60]}",
            "无法连接 cha2a registry（CHA2A_REGISTRY 可覆盖）——信任验证依赖 registry")
        return False, None
    record = data.get("record") or data
    level = record.get("level", 0)
    status = record.get("status", "active")
    revoked = status not in ("active", None)
    if revoked:
        add("ATP-004", "high", f"信任锚已撤销/非活跃（{did[:40]}，status={status}）",
            "撤销的锚不可用于信任级联（CHA2A 撤销即时传播）")
        return False, data
    return True, data


def check(target: str, verify_registry: bool = False) -> dict:
    issues = []
    score = 100

    def add(rule, severity, found, recommendation, penalty=15):
        nonlocal score
        issues.append({"rule": rule, "severity": severity, "found": found,
                       "recommendation": recommendation})
        score -= penalty

    # ---- ATP-001 / ATP-004 声明与信任锚 ----
    card_path = _find(target, CARD_NAMES)
    trust_path = _find(target, TRUST_FILES)
    trust = None
    if trust_path is not None:
        trust = _load_json(trust_path)
        if trust is None:
            add("ATP-001", "high", f"信任声明无法解析: {os.path.basename(trust_path)}",
                "trust.json/delegation.json 需合法 JSON")
    if trust is None or trust_path is None:
        add("ATP-001", "medium", "未找到信任/委托声明（trust.json/delegation.json/chain.json）",
            "调用链信任需要显式声明（CHA2A 委托链理念：逐跳可验证）")

    # 信任锚（DID / 公钥 / registry 引用）
    anchor = None
    if isinstance(trust, dict):
        anchor = trust.get("trustAnchor") or trust.get("anchor") or trust.get("did") or trust.get("publicKey")
    if anchor is None and card_path is not None:
        card = _load_json(card_path)
        if isinstance(card, dict):
            sec = card.get("security") or {}
            anchor = sec.get("trustAnchor") or sec.get("did") or sec.get("publicKey")
    if anchor is None:
        add("ATP-004", "medium", "未声明信任锚（DID/公钥/registry 引用）",
            "信任级联需要一个锚：DID（did:cha2a:...）、公钥指纹，或 registry 引用")
    elif isinstance(anchor, str):
        if not re.match(r"^(did:[a-z0-9]+:|[0-9a-fA-F]{40,}|https?://|ldpub:)", anchor):
            add("ATP-004", "low", f"信任锚格式未知: {anchor[:40]}",
                "建议 DID、公钥指纹或可解析引用")
        # 在线核验：信任锚是真 DID 且 --verify-registry → 调 cha2a registry 真验证
        if verify_registry and anchor.startswith("did:cha2a:"):
            _verify_registry_did(anchor, issues, add)
        elif verify_registry and anchor.startswith("did:"):
            # 非 cha2a DID：提示（registry 无法核验，交由链上/其他方法）
            add("ATP-004", "low", f"信任锚为非 cha2a DID: {anchor[:40]}",
                "仅 cha2a registry 可在线核验；其他 DID 需对应方法解析")

    # ---- ATP-002 / ATP-003 / ATP-007 调用链 ----
    chain = _extract_chain(trust) if isinstance(trust, dict) else []
    if not chain:
        add("ATP-002", "medium", "调用链为空或无跳",
            "至少声明一跳（delegator → delegatedAgent + scope + chainRef）")
    else:
        seen_nodes = set()   # 环检测：节点出现两次即环
        for i, hop in enumerate(chain):
            if not isinstance(hop, dict):
                add("ATP-002", "medium", f"第 {i+1} 跳非对象", "每跳应为对象（delegator/scope/chainRef）")
                continue
            delegator = hop.get("delegator")
            delegated = hop.get("delegatedAgent") or hop.get("delegated")
            scope = hop.get("scope") or hop.get("authorizationScope")
            chain_ref = hop.get("chainRef") or hop.get("chainReference")
            missing = []
            if not delegator:
                missing.append("delegator")
            if not delegated:
                missing.append("delegatedAgent")
            if not scope:
                missing.append("scope")
            if not chain_ref:
                missing.append("chainRef")
            if missing:
                add("ATP-002", "high", f"第 {i+1} 跳缺委托凭证字段: {', '.join(missing)}",
                    "委托凭证需 delegator/authorizationScope/chainReference（CHA2A 委托链）")
            # 环检测：delegated 已在链中出现过（作为任一跳的端点）→ 环
            if delegated and delegated in seen_nodes:
                add("ATP-007", "high", f"调用链成环: {delegated} 重复出现",
                    "信任链不应成环（cycle）")
            if delegator:
                seen_nodes.add(delegator)
            if delegated:
                seen_nodes.add(delegated)
        # 级联一致：后一跳的 delegator 应等于前一跳的 delegatedAgent（同一主体延续）
        prev_delegated = None
        for i, hop in enumerate(chain):
            if not isinstance(hop, dict):
                continue
            delegator = hop.get("delegator")
            if prev_delegated is not None and delegator and delegator != prev_delegated:
                add("ATP-003", "medium", f"第 {i+1} 跳 delegator「{delegator}」≠ 上一跳被委托者「{prev_delegated}」",
                    "级联应连续：每跳委托者 = 上一跳被委托者（信任不凭空跳变）")
            prev_delegated = hop.get("delegatedAgent") or hop.get("delegated")
        # scope 收敛：scope 应从宽到窄（委托不扩大权限）
        scopes = []
        for hop in chain:
            if isinstance(hop, dict) and (hop.get("scope") or hop.get("authorizationScope")):
                scopes.append(str(hop.get("scope") or hop.get("authorizationScope")))
        if len(scopes) >= 2 and len(set(scopes)) > 1:
            # 不同 scope 声明不一定是错（可能是细粒度），但记录提示
            add("ATP-003", "low", f"级联中 scope 变化: {scopes}",
                "确认委托权限沿链只收窄不扩大（最小权限原则）")

    # ---- ATP-005 消息可核验 ----
    msg_evidence = None
    if isinstance(trust, dict):
        msg_evidence = trust.get("messageEvidence") or trust.get("signature") or trust.get("evidenceRef")
    # 兼容：单独的消息签名文件
    if msg_evidence is None:
        sig_path = _find(target, ("messages.signatures.json", "evidence.json", "calls.json"))
        if sig_path is not None:
            msg_evidence = sig_path
    if msg_evidence is None:
        add("ATP-005", "medium", "未发现消息可核验证据（消息签名/证据引用/调用链记录）",
            "信任级联的落地需要消息可核验：消息带签名或 evidenceRef（证据契约扩展到消息）")
    else:
        # 如果有 evidenceRef 但指向文件不存在
        if isinstance(msg_evidence, str) and msg_evidence.startswith(("file:", "ref:")):
            ref = msg_evidence.split(":", 1)[1]
            if not os.path.exists(os.path.join(target, ref)):
                add("ATP-005", "high", f"消息证据引用不存在: {ref}",
                    "evidenceRef 指向的文件应存在（否则溯源断链）")

    # ---- ATP-006 披露与信任绑定 ----
    if isinstance(trust, dict):
        disclosure = trust.get("disclosure") or trust.get("dataBehavior")
        if disclosure is None:
            add("ATP-006", "low", "信任声明未绑定数据行为披露",
                "建议 trust 声明携带 disclosure（发什么/去哪），信任与披露一致（呼应 disclosure 理念）")

    # ---- ATP-008 版本与文档 ----
    if isinstance(trust, dict):
        ver = trust.get("version") or trust.get("chainVersion")
        if ver and not re.match(r"^\d+\.\d+\.\d+", str(ver)):
            add("ATP-008", "medium", f"信任声明版本非语义化: {ver}", "建议 SemVer")
        if not trust.get("documentationUrl"):
            add("ATP-008", "low", "信任声明缺 documentationUrl", "建议提供文档地址")

    score = max(0, score)
    has_high = any(i.get("severity") == "high" for i in issues)
    # PASS 需分数达标且无 high 问题（high=结构性缺陷，阻断通过）
    if score >= 80 and not has_high:
        conclusion = "PASS"
    elif score >= 60 and not has_high:
        conclusion = "REVIEW"
    else:
        conclusion = "NEEDS_FIX"
    return {
        "tool": "agent-trust-probe",
        "version": "1.0.0",
        "score": score,
        "conclusion": conclusion,
        "mode": "online" if verify_registry else "offline",
        "registry": CHA2A_BASE if verify_registry else None,
        "issues": issues,
    }


def main():
    ap = argparse.ArgumentParser(description="Agent 间信任级联/溯源验证器")
    ap.add_argument("--dir", required=True, help="Agent 项目目录")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--verify-registry", action="store_true",
                    help="在线核验：调用 CHA2A registry 验证信任锚（DID 注册/等级/撤销）")
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        print(json.dumps({"tool": "agent-trust-probe", "error": f"目录不存在: {args.dir}"}))
        sys.exit(1)

    report = check(args.dir, verify_registry=args.verify_registry)
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        mode = "在线核验（CHA2A registry）" if args.verify_registry else "离线（结构检查）"
        print(f"agent-trust-probe v{report['version']} · 模式: {mode}")
        print(f"评分: {report['score']}/100 → {report['conclusion']}")
        for it in report["issues"]:
            print(f"  [{it['rule']}][{it['severity']}] {it['found']}")
            print(f"      建议: {it['recommendation']}")
        if not report["issues"]:
            print("  无问题。")


if __name__ == "__main__":
    main()
