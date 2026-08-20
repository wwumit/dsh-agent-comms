---
name: agent-trust-probe
version: 1.0.0
description: |
  Agent 间信任级联/溯源验证器（agent-comms 系列）。沿 A2A/MCP 调用链验证信任等级与
  消息可核验性：委托凭证完整性、级联一致性、信任锚可验证、环/断链检测、消息证据引用。
  对齐 CHA2A 凭证委托链（delegator/scope/chainRef 逐跳验证）与 GB/Z 185.3 委托链核验理念；
  把"证据契约"从技能层扩展到消息层（响应书稿 6.6.3）。
  纯本地、零依赖、输出 JSON 报告（ATP-001~008）。
  Use when: 用户要验证 Agent 间调用链的信任级联是否可溯源，或部署前检查信任声明完整性。
  Trigger: agent-trust-probe, 信任级联, 信任溯源, 委托链, delegation chain, trust probe, 消息可核验
disclosure:
  cloud: false
  network: []
  offline_mode: true
  api_keys: []
  jurisdiction: ["CN"]
  retention: "none"
permissions:
  network: []
  filesystem:
    write: []
  env: []
disclaimer: 本工具为辅助性参考工具，不构成法律或安全建议；信任锚（DID/公钥）仅做声明检查，不做在线验证。
---

# 🕵️ agent-trust-probe — Agent 间信任级联/溯源验证器

## Overview
沿 Agent 调用链验证信任是否可溯源、消息是否可核验。规则：
- **ATP-001** 信任/委托声明存在（trust.json / delegation.json / chain.json）
- **ATP-002** 每跳委托凭证完整（delegator / delegatedAgent / scope / chainRef）
- **ATP-003** 信任级联一致（上一跳被委托者 == 下一跳委托者；scope 只收窄不扩大）
- **ATP-004** 信任锚可验证（DID / 公钥 / registry 引用声明存在、格式合法）
- **ATP-005** 消息可核验（消息签名 / evidenceRef / 调用链记录；证据契约扩展到消息）
- **ATP-006** 披露与信任绑定（信任声明携带数据行为披露）
- **ATP-007** 环与断链检测（调用链无环、无断链、无孤儿跳）
- **ATP-008** 版本与文档（SemVer / documentationUrl）

## Usage
```bash
python3 scripts/agent-trust-probe.py --dir <Agent项目目录> --format text   # 终端报告
python3 scripts/agent-trust-probe.py --dir <Agent项目目录> --format json   # JSON 报告
```

## 信任声明格式（trust.json 示例）
```json
{
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
  "disclosure": {"endpoints": ["https://api.example.com"], "dataCategories": ["query"]}
}
```

## 锚定机制
- **CHA2A 凭证委托链**：每跳 delegator → delegatedAgent 携带授权 scope + 链引用，逐跳验证（对齐 GB/Z 185.3）
- **证据契约扩展**：消息可核验（签名/evidenceRef）——"谁验证、何时、报告"从技能层下沉到消息层（书稿 6.6.3）

## 系列（agent-comms）
本技能是 **Agent 通信合规系列**第三个：
1. `agent-comms-check`（通信配置合规，ACC-001~008）
2. `agent-comms-disclosure`（通信数据行为披露契约，ACD-001~005）
3. **agent-trust-probe**（本技能：信任级联/溯源验证）
4. `agent-comms-audit`（消息/调用链审计，规划）

---

*written by wwumit · 治理驱动的 AI 技能生态 · 规则 → 检查 → 评分 → 报告*
