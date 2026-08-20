---
name: agent-comms-check
version: 1.0.0
description: |
  Agent 间通信配置合规检查器（agent-comms 系列首个）。检查 Agent 项目的 A2A Agent Card
  （agent-card.json）与 MCP 配置（mcp.json）是否合规、披露是否完整、安全基线是否达标：
  必填字段、端点 HTTPS、capabilities、认证方案、MCP 凭据硬编码、通信披露扩展。
  纯本地、零依赖、输出 JSON 报告（ACC-001~008）。
  Use when: 用户要在部署 Agent 或接入 Agent 间通信前检查通信配置合规，或 Agent Card/MCP 配置报错。
  Trigger: agent-comms-check, 通信合规, Agent Card 检查, A2A检查, MCP配置检查, 智能体通信检查
disclosure:
  cloud: false
  network:
    - 默认离线；--verify-registry 时查询 cha2a registry（compliancehub.cn，CHA2A_REGISTRY 可覆盖）
  offline_mode: true
  api_keys: []
  jurisdiction: ["CN"]
  retention: "none"
permissions:
  network: []
  filesystem:
    write: []
  env: []
disclaimer: 本工具为辅助性参考工具，不构成法律或安全建议；协议规范以 A2A/MCP 官方文档为准。
---

# 🤝 agent-comms-check — Agent 间通信配置合规检查器

## Overview
检查 Agent 项目的通信配置（A2A Agent Card + MCP）合规性，规则：
- **ACC-001** agent-card.json 存在且可解析
- **ACC-002** 必填字段（name/description/url/version）
- **ACC-003** 端点安全（HTTPS 传输、内网地址场景判定）
- **ACC-004** capabilities 声明完整（streaming/pushNotifications/stateSyncHandlers）
- **ACC-005** security.authentication（none 非本地告警；apiKey 凭证引用）
- **ACC-006** MCP 配置（env 硬编码凭据、远程端点 HTTPS、command/url）
- **ACC-007** 通信披露扩展（端点/凭据/法域/保留——对齐披露理念）
- **ACC-008** 在线核验：声明身份 ↔ CHA2A registry 对账（DID 注册/等级/撤销；--verify-registry）

## Usage
```bash
python3 scripts/agent-comms-check.py --dir <Agent项目目录> --format text   # 终端报告（离线结构检查）
python3 scripts/agent-comms-check.py --dir <Agent项目目录> --verify-registry --format text  # 在线（CHA2A registry 对账声明身份）
python3 scripts/agent-comms-check.py --dir <Agent项目目录> --format json   # JSON 报告
```

**在线模式（--verify-registry）**：调用 CHA2A registry 对账配置声明的身份（security.trustAnchor / did / MCP server did）——是否注册、认证等级、是否撤销（ACC-008）。未注册/已撤销会提示；`CHA2A_REGISTRY` 可覆盖默认 registry。

## 锚定协议
- **A2A**（Agent 间通信）：Agent Card 规范（name/description/url/version 必填 + capabilities/security）
- **MCP**（工具层）：mcpServers 配置（command/url/env）

## 系列（agent-comms）
本技能是 **Agent 通信合规系列**第一个：
- `agent-comms-check`（本技能）：配置/协议合规
- `agent-comms-audit`（规划）：消息/调用链审计
- `agent-trust-probe`（规划）：信任级联/溯源验证
- `agent-comms-disclosure`（规划）：通信数据行为披露契约
