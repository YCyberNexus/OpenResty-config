# Green Blue Yellow Data Link Whitelist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a repository-level data-link whitelist ledger for green, blue, and yellow security zones, with explicit controls for cross-boundary knowledge flow.

**Architecture:** Keep runtime WAF configuration unchanged until real IPs, certificates, tokens, and interface contracts are supplied. Add a user-facing operations document under `docs/` that consolidates security zones, boundary matrix, whitelist ledger fields, initial known links, and verification rules. Update `README.md` so operators can find the ledger next to existing WAF runbooks.

**Tech Stack:** Markdown documentation, existing OpenResty/Lua WAF repository, existing `make test` and `make lint` verification.

---

## Scope Check

The design covers multiple enforcement subsystems: four-layer routing, mTLS identity, WeCom ingress, OpenClaw-to-OpenClaw WSS, status callback, response filtering, and SIEM audit. This implementation plan deliberately ships the first independently useful slice: repository documentation and whitelist ledger baseline. Runtime enforcement work must be split into later implementation plans once the ledger supplies concrete source, target, protocol, credential, and owner data.

## File Structure

- Create `docs/绿蓝黄数据链路白名单台账.md`
  - Responsibility: human-readable source of truth for the three-zone definitions, six boundary categories, initial whitelist ledger, knowledge-flow classes, and release gate.
  - Boundary: contains no secrets, no actual credentials, and no guessed production IPs.
- Modify `README.md`
  - Responsibility: expose the new ledger document in the existing documentation index.
- No runtime WAF files are modified in this plan.

## Task 1: Add The Whitelist Ledger Document

**Files:**
- Create: `docs/绿蓝黄数据链路白名单台账.md`

- [ ] **Step 1: Create the ledger file**

Create `docs/绿蓝黄数据链路白名单台账.md` with these sections:

```markdown
# 绿蓝黄数据链路白名单台账

## 1. 目的

## 2. 三色分区定义

## 3. 当前已知链路总表

## 4. 白名单台账字段

## 5. 知识流动分级

## 6. 黄区 -> 蓝区脱敏知识流准入规则

## 7. 蓝区 -> 绿区状态回传准入规则

## 8. 当前仓库 WAF 能力映射

## 9. 上线放行门禁
```

- [ ] **Step 2: Populate the known link table**

Use this exact initial table structure. Rows with missing real network material are marked `未收齐，禁止生产放行`; this is a deliberate safety state, not a blank placeholder.

```markdown
| ID | 方向 | 边界 | 源系统 | 目标系统 | 数据流 | 允许内容 | 禁止内容 | 当前状态 |
|---|---|---|---|---|---|---|---|---|
| GY-001 | 绿 -> 黄 | 绿/黄 | 企微 Channel | 黄区知识查询入口 | 知识查询 | 已登记查询字段和任务上下文 | 未登记附件、原始凭证、绕过蓝区的任意访问 | 未收齐，禁止生产放行 |
| GB-001 | 绿 -> 蓝 | 绿/蓝 | 企微 Channel | 蓝区需求研发入口 | 需求、任务、用户输入 | 已登记消息类型、任务字段、必要附件元数据 | 可执行载荷、伪造回调、未审计互联网内容 | 未收齐，禁止生产放行 |
| BG-001 | 蓝 -> 绿 | 绿/蓝 | 114 服务器 | 智伴 | 任务状态回传 | 任务 ID、阶段、成功/失败、错误码、必要摘要、时间戳 | 黄区原始代码、原始数据、文档全文、模型完整上下文 | 未收齐，禁止生产放行 |
| BY-001 | 蓝 -> 黄 | 蓝/黄 | 蓝区任务系统或 Git 服务 | 黄区受控入口 | Git 单向同步、任务下发 | 已登记 repo、branch、任务指令、协议端口 | 任意服务探测、横向访问、控制面访问 | 未收齐，禁止生产放行 |
| YB-001 | 黄 -> 蓝 | 蓝/黄 | 黄区 OpenClaw node | 蓝区 OpenClaw hub | 脱敏知识流 | 脱敏代码片段、脱敏数据、脱敏文档摘要、结构化元数据 | 黄区原始资料、密钥、凭证、个人信息、内部地址、未脱敏日志 | 未收齐，禁止生产放行 |
| BM-001 | 蓝 -> 大模型 | 蓝/大模型 | 蓝区 OpenClaw/WAF | OpenAI 兼容模型接口 | 模型请求 | 当前 `conf/waf_rules.lua` 允许的 URL、model、messages 字段 | `x-openclaw-*` 覆盖头、未登记 model、未知字段、未校验 tools 调用 | 已有请求侧基础控制 |
| CTL-001 | 任意 -> OpenClaw 控制面 | 控制面 | 任意跨区来源 | `127.0.0.1:18789` | 管理面访问 | 本机回环管理 | 跨区访问、业务 WAF 白名单放行 | 跨区禁止 |
```

- [ ] **Step 3: Add concrete release gates**

Add a release gate section with these seven checks:

```markdown
1. 每条链路必须有方向、源系统、目标系统、协议端口、身份凭证、owner 和有效期。
2. 每条链路必须明确允许内容和禁止内容。
3. 黄区出区材料必须完成脱敏和敏感信息扫描。
4. 蓝区回绿区只能传 K0/K1 状态和摘要数据。
5. OpenClaw 控制面 `18789` 不允许进入任何跨区业务白名单。
6. 新增运行配置前必须通过 `make lint` 和 `make test`。
7. 生产放行前必须有拒绝用例、审计日志查询方式和回滚方式。
```

- [ ] **Step 4: Commit the ledger document**

Run:

```bash
git add docs/绿蓝黄数据链路白名单台账.md
git commit -m "文档：新增绿蓝黄白名单台账"
```

Expected: one commit containing only `docs/绿蓝黄数据链路白名单台账.md`.

## Task 2: Link The Ledger From README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add the ledger to the docs list**

In the `## 文档` section of `README.md`, add this bullet after `流量安全网关方案-工作分析`:

```markdown
- [绿蓝黄数据链路白名单台账](docs/绿蓝黄数据链路白名单台账.md) —— 三色安全分区、跨边界链路、白名单字段、知识流动分级与上线放行门禁。
```

- [ ] **Step 2: Verify the link target exists**

Run:

```bash
test -f docs/绿蓝黄数据链路白名单台账.md && echo "ledger exists"
```

Expected:

```text
ledger exists
```

- [ ] **Step 3: Commit the README index update**

Run:

```bash
git add README.md
git commit -m "文档：索引绿蓝黄白名单台账"
```

Expected: one commit containing only `README.md`.

## Task 3: Verify Documentation And Existing WAF

**Files:**
- Read: `docs/绿蓝黄数据链路白名单台账.md`
- Read: `docs/superpowers/specs/2026-07-06-green-blue-yellow-data-link-whitelist-design.md`
- Read: `README.md`

- [ ] **Step 1: Verify key terms are present**

Run:

```bash
rg -n "黄区|蓝区|绿区|114服务器|智伴|OpenClaw-to-OpenClaw|知识流动|18789" docs/绿蓝黄数据链路白名单台账.md docs/superpowers/specs/2026-07-06-green-blue-yellow-data-link-whitelist-design.md README.md
```

Expected: matches for all listed terms in the ledger or design document, and the README link.

- [ ] **Step 2: Run rule lint**

Run:

```bash
make lint
```

Expected:

```text
体检完成：0 error，0 warning
```

- [ ] **Step 3: Run tests**

Run:

```bash
make test
```

Expected: all current tests pass.

- [ ] **Step 4: Inspect git state**

Run:

```bash
git status --short
```

Expected: only unrelated `.DS_Store` files remain untracked, or the working tree is clean if those files were separately ignored.
