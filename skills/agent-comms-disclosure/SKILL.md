---
name: agent-comms-disclosure
version: 1.0.0
description: |
  Agent 间通信披露契约（agent-comms 系列）。把"披露即治理"从技能层迁移到通信层：
  通信的数据行为（发什么、去哪、怎么存）必须机器可读披露。提供 check（完整性检查）、
  gen（从 Agent Card/MCP 配置生成契约）、validate（schema 校验）三模式。
  schema: agent-comms-disclosure-v1（endpoints/messageTypes/dataCategories/credentials/jurisdiction/retention/thirdParty/pay）。
  纯本地、零依赖、输出 JSON。
  Use when: 用户要在部署 Agent 或接入 Agent 间通信前，声明/检查通信数据行为的披露。
  Trigger: agent-comms-disclosure, 通信披露, 通信数据行为, agent disclosure, 披露契约
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
disclaimer: 本工具为辅助性参考工具，不构成法律或安全建议。
---

# 📋 agent-comms-disclosure — Agent 间通信披露契约

## Overview
通信一旦发生，谁在通信、发什么、数据去哪、能否溯源——就是治理问题。本技能把
**披露即治理**（"要求说可核验的话"）从技能层迁移到通信层，提供机器可读的**通信披露契约**。

## 披露契约 schema（agent-comms-disclosure-v1）

| 字段 | 必填 | 说明 |
|---|---|---|
| `endpoints` | ✅ | 通信端点（A2A url / MCP 端点） |
| `credentials` | ✅ | 凭据处理（name / storage: env\|file-0600\|embedded） |
| `jurisdiction` | ✅ | 适用法域 |
| `retention` | ✅ | 消息保留（none / session / server） |
| `messageTypes` | 建议 | 消息类型（request/response/event/stream） |
| `dataCategories` | 建议 | 传输数据类别（text/file/credentials/user-data） |
| `thirdParty` | 建议 | 是否转发第三方 |
| `pay` | 建议 | 是否付费/额度 |

## Usage
```bash
# check：检查披露完整性（ACD-001~005）
python3 scripts/agent-comms-disclosure.py check --dir <Agent项目目录> [--format json]

# gen：从 agent-card.json + mcp.json 自动生成披露契约
python3 scripts/agent-comms-disclosure.py gen --dir <Agent项目目录> --output agent-disclosure.json

# validate：校验契约 schema
python3 scripts/agent-comms-disclosure.py validate --file agent-disclosure.json
```

## 检查规则（ACD）
- **ACD-001** 未找到披露契约（Agent Card 内嵌 disclosure 或独立 agent-disclosure.json）
- **ACD-002** 必填字段缺失（endpoints/credentials/jurisdiction/retention）
- **ACD-003** retention 非法值
- **ACD-004** 端点未披露（Agent Card url / MCP 端点 与披露不一致——披露不实，high）
- **ACD-005** 凭据未披露（MCP env 含疑似凭据但契约未声明，high）

## 系列（agent-comms）
- `agent-comms-check`：配置/协议合规
- **`agent-comms-disclosure`（本技能）**：通信数据行为披露契约
- `agent-trust-probe`（规划）：信任级联/溯源
- `agent-comms-audit`（规划）：消息/调用链审计
