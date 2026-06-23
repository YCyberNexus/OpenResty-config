# OpenResty 七层 WAF（起步骨架）

基于 OpenResty 的七层 WAF，是[流量安全网关方案](docs/流量安全网关方案-工作分析.md)里 **P2（规则引擎）+ P3（body 校验）** 的落地。四层出口 / 路由 / HA 是另一条线，不在本仓库范围。

核心理念：**规则逻辑全部抽成不依赖 `ngx` 的纯 Lua 模块，可单元测试；`ngx` 只做 IO 胶水。**

## 目录结构

```
lua/waf/
  url_filter.lua      白/黑名单匹配（精确 path + method + 正则，正则引擎依赖注入）
  body_validator.lua  OpenAI Chat Completions 校验（字段白名单 / role / 长度 / messages 专项）
  decision.lua        决策链：先黑后白 + 默认拒绝（fail-closed）
  factory.lua         配置表 → 决策器 装配
  regex.lua           生产正则实现（ngx.re，"jo"）
  handler.lua         access_by_lua 入口（读 body、解析 JSON、调 decision、回写响应/日志）
  rules_lint.lua      配置体检（静态检查 waf_rules，抓 openresty -t 抓不到的引用/必填错）
conf/
  nginx.conf          OpenResty 配置（init_by_lua 构建决策器 + access_by_lua 挂 WAF）
  waf_rules.lua       规则定义（白名单/黑名单/forbidden_headers/schemas）
schemas/
  chat_completions.schema.json   标准 JSON Schema 草稿（P3-3 迁移目标）
spec/                 测试（纯 LuaJIT 可跑的 busted 风格框架）
scripts/
  smoke.sh            curl 冒烟测试
  package.sh          Mac 端打包（离线部署，挑运行期文件 + 统一 LF）
  server-setup.sh     服务器端环境准备（建 logs / 设权限 / openresty -t 预检）
  check_rules.lua     配置体检（make lint 调用）
deploy/openresty-waf.service   systemd 服务单元
docs/                 文档（见下方「文档」一节）
```

## 文档

- [流量安全网关方案-工作分析](docs/流量安全网关方案-工作分析.md) —— 完整工作分析：P0–P7 工作分解、OpenClaw 接口画像、风险与待澄清项。
- [离线部署教程](docs/离线部署教程.md) —— 无外网 CentOS 服务器的部署与使用全流程（详见下文「[离线部署到服务器（CentOS）](#离线部署到服务器centos)」）。
- [WAF 规则配置指南](docs/WAF规则配置指南.md) —— 运维维护 `conf/waf_rules.lua` 的配置手册（详见下文「[规则配置（给运维团队）](#规则配置给运维团队)」）。

## 跑测试（只需 luajit）

```bash
make test
```

覆盖 `url_filter` / `body_validator` / `decision` / `factory` / `rules_lint` 纯逻辑、`handler` 的 mock-ngx 集成测试，以及加载真实 `conf/waf_rules.lua` 的配置回归（当前 71 个用例全绿）。无需安装 OpenResty。

> 测试用一个内置的极简 busted 风格框架（`spec/helper.lua`），写法与 busted 完全兼容。装了真 busted 后可直接 `busted spec/`，测试无需改动。

## 真机运行 + curl 验证（需 OpenResty）

```bash
# 安装 OpenResty（任选其一）
brew install openresty/brew/openresty     # macOS（需 Xcode Command Line Tools）
# 或用官方 docker 镜像 openresty/openresty

make serve     # 启动，监听 127.0.0.1:8080
make smoke     # 冒烟测试：放行/默认拒绝/黑名单/body 校验
make stop      # 停止
```

`make serve` 用一个桩上游（放行后回 `{"ok":true,"upstream":"stub"}`）。生产把 `conf/nginx.conf` 里的 `content_by_lua_block` 换成 `proxy_pass` 到对端 OpenClaw，并叠加 mTLS（方案 P4-1）。

## 离线部署到服务器（CentOS）

无外网服务器的完整部署/使用步骤见 [离线部署教程](docs/离线部署教程.md)：`scripts/package.sh`（Mac 端打包）→ 传包 → 解到 `/opt/openresty-waf` → `scripts/server-setup.sh`（建 logs/设权限/语法校验）→ `deploy/openresty-waf.service`（systemd）→ `scripts/smoke.sh` 验证。覆盖 SELinux/firewalld、权限、改规则热加载、接上游 OpenClaw、排障速查。

## 规则配置（给运维团队）

部署后运维日常只改一个文件 `conf/waf_rules.lua`（白名单 / 黑名单 / forbidden_headers / schemas），怎么改、改完怎么自检见 [WAF 规则配置指南](docs/WAF规则配置指南.md)。改完三件套：`make lint`（配置体检，抓 `openresty -t` 抓不到的引用一致性/必填错）→ `openresty … -t`（语法+加载）→ `systemctl reload openresty-waf`（热加载）。`waf_rules.lua` 由 `init_by_lua` 启动加载，**配置写错会让进程起不来（fail-closed）**，所以先校验再 reload 是硬要求。

## 当前能力

- URL 白名单：精确 path + method；正则规则（生产走 `ngx.re` PCRE）；**未命中默认拒绝**。
- URL 黑名单：先于白名单匹配，命中即拒（含 OpenClaw 控制面端点）。
- 禁用请求头：拦 `x-openclaw-*` 等后端覆盖头（先于黑/白名单，防客户端旁路 `model` 白名单）；请求头被截断或 body 落盘时 **fail-closed** 拒绝。
- body 校验（OpenAI Chat Completions）：顶层字段白名单（`additionalProperties:false`）、`model` 白名单、`messages` 非空/条数上限、`role` 白名单、**system 必须首位（防伪 system 越权注入）**、单条与总长上限、`Content-Type: application/json` 强制、非法 JSON 拒绝。
- 拒绝响应只回原因码 + `request_id`，不回显规则与原始内容。

## 与方案的差距（后续）

- 数值上限（`max_messages` 等）为占位，待接口契约（方案搁置项 5）确认收紧。
- 规则为 Lua 表静态加载；热更新 / 配置校验 / 版本回滚见方案 P5-1。
- 内容层禁代码 / 防注入模式匹配（P3-6）、字节+字符双重长度口径（P3-4）未做。
- 校验失败的结构化审计外发 SIEM（P3-7 / P6-3）未接。
- `content` 仅接受 string，多模态数组白名单待 P3-5。
