# 试点实验：agent-trust-probe 插件最小闭环（安全设计）

> 状态：方案记录（v0.1）
> 日期：2026-08-20
> 原则：**不在主实例（web profile / 3080）上做实验；每一步可回退**
> 环境事实：DSH 运行在 /Users/wuwei/deepseek-harness 源码 checkout（master）；web profile cordis.patch.yml 为 `[]`；CLI 支持任意命名 profile + headless + --patch

---

## 一、要验证的核心假设

"**协议机制能否在 DSH 真实运行时自动执行**"——CHA2A 信任核验挂进工具调用路径（pre-execute hook），带 DID 的目标被核验（allow/deny），不带 DID 的默认放行。

## 二、实验形态（安全隔离）

```
主实例（web profile, 3080）──── 不动 ──── 我的工具调用不受影响
        │
        └─ 实验：独立 profile + headless 一次性任务
           pnpm dsh --profile test-trust --patch ./trust-probe.patch.yml "任务"
           （独立命名 profile · 临时 patch 覆盖 · 跑完退出）
```

## 三、执行步骤与回退点（每一步都记录"怎么回退"）

| 步骤 | 动作 | 回退方式 | 回退风险 |
|---|---|---|---|
| **S0** | 记录当前状态：`git log -1`、`cat ~/.dsh/profiles/web/cordis.patch.yml`、`ps` 主进程 | 快照已存 | 无 |
| **S1** | 写插件源码（本地目录 `plugins/agent-trust-probe/`，不发布 npm） | 纯新增文件，删目录即回退 | 无 |
| **S2** | 用 `--dump-default-config` 查看 profile 树（**不实际运行**）| 只读命令 | 无 |
| **S3** | 确认 `--patch` overlay 条目写法（查 args.ts + 一个真实用例）| 只读 | 无 |
| **S4** | 跑 headless：`pnpm dsh --profile test-trust --patch ... "任务"` | **独立 profile + 临时 patch**：跑完即弃；如需回退删除 test-trust profile（`~/.dsh/profiles/test-trust`）| 低：只影响 test-trust，不碰 web |
| **S5** | 观察日志：插件挂载 / hook 触发 / allow-deny | 无副作用 | 无 |
| **S6** | 验证完成：删 test-trust profile + patch 文件 | `rm -rf ~/.dsh/profiles/test-trust` | 无 |

## 四、安全护栏（防锁死/防污染）

1. **独立 profile**：插件只挂 test-trust，绝不写进 web profile 的 cordis.patch.yml
2. **默认 allow**：pre-execute 逻辑——`exec.arguments` 无 did 参数 → 直接 `{kind:'allow'}`（不拦普通调用）；只有显式 did 才核验
3. **headless 一次性**：任务跑完退出，不留驻
4. **--patch 临时**：不修改任何持久配置（web profile、package.json 的 bundles 列表）
5. **不发布 npm**：插件仅本地目录，避免污染 registry
6. **主实例零接触**：3080 进程、web profile、我的会话全部不动

## 五、需确认的（最后一块拼图）

- **S3 已查清（2026-08-20）**：
  - `--patch` overlay 是 YAML 数组，新增插件用 `insert:` 条目：
    ```yaml
    - insert:
        - id: trust-probe
          name: 'agent-trust-probe'   # 插件包名/路径
    ```
  - 官方 bundle 用 npm 包名（`@deepseek-ai/...`）；**本地未发布插件需确认 name 支持本地路径/workspace 引用**（如 `file:../plugins/agent-trust-probe` 或 workspace）——S4 前用 `--dump-default-config` 验证 patch 是否被接受
  - headless 模式：`dsh --profile headless "task"` 一次性任务（答完退出）——天然触发工具调用的方式
  - 独立 profile：`--profile <任意名>` 即建独立 profile（如 test-trust），与 web 隔离

## 六、验收标准

- [ ] S4 运行无报错（插件挂载成功）
- [ ] 日志可见 pre-execute hook 触发
- [ ] 带 DID 参数 → 核验 → allow（可信）/ deny（不可信）
- [ ] 不带 DID → 默认 allow（不锁死）
- [ ] 主实例（web）全程未受影响

## 七、回退清单（万一出问题）

```bash
# 立即回退（任何一步出问题）
rm -rf ~/.dsh/profiles/test-trust        # 删实验 profile
rm -rf plugins/agent-trust-probe/        # 删插件源码
# 主实例不受影响（从未被触碰）
```

## 八、闭环实证（2026-08-20）——先于运行时实验的独立闭环

**场景**：trust-probe 作为 CHA2A 消费方，对真实 Agent 身份做在线信任核验（不依赖 §三 的 DSH 运行时插件实验）。

- **Agent 身份端**：`did:cha2a:agent:dshlib` 已注册（CHA2A Agent Identity 分册 agent-identity.md 的首个 Agent 身份）——registered ✓ · L0 · active · 证据凭证 1 条（verifier: `did:cha2a:verifier:dshlib`，test-result，哈希闭环一致）
- **核验端**：`agent-trust-probe.py --dir <trust.json 声明 did:cha2a:agent:dshlib + 委托链> --verify-registry` → **100/100 PASS**（registry: https://compliancehub.cn；ATP-004 在线核验 注册/等级/撤销/凭证状态；委托链逐跳核验）
- **闭环**：Agent 身份注册（registry）→ 信任级联核验（trust-probe 消费 trust/query）→ 证据可核验（evidence/query + 哈希闭环）

**意义**：CHA2A"身份 + 信任 + 证据"体系第一个真实的端到端消费方实证；同时是 agent 身份协议（官方讨论区 #3622 系列分册）的运行背书。
