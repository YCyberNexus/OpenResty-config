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
conf/
  nginx.conf          OpenResty 配置（init_by_lua 构建决策器 + access_by_lua 挂 WAF）
  waf_rules.lua       规则定义（白名单/黑名单/schemas）
schemas/
  chat_completions.schema.json   标准 JSON Schema 草稿（P3-3 迁移目标）
spec/                 测试（纯 LuaJIT 可跑的 busted 风格框架）
scripts/smoke.sh      curl 冒烟测试
```

## 跑测试（只需 luajit）

```bash
make test
```

覆盖 32 个用例：`url_filter` / `body_validator` / `decision` / `factory` 纯逻辑，外加 `handler` 的 mock-ngx 集成测试。无需安装 OpenResty。

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

## 当前能力

- URL 白名单：精确 path + method；正则规则（生产走 `ngx.re` PCRE）；**未命中默认拒绝**。
- URL 黑名单：先于白名单匹配，命中即拒（含 OpenClaw 控制面端点）。
- body 校验（OpenAI Chat Completions）：顶层字段白名单（`additionalProperties:false`）、`model` 白名单、`messages` 非空/条数上限、`role` 白名单、**system 必须首位（防伪 system 越权注入）**、单条与总长上限、`Content-Type: application/json` 强制、非法 JSON 拒绝。
- 拒绝响应只回原因码 + `request_id`，不回显规则与原始内容。

## 与方案的差距（后续）

- 数值上限（`max_messages` 等）为占位，待接口契约（方案搁置项 5）确认收紧。
- 规则为 Lua 表静态加载；热更新 / 配置校验 / 版本回滚见方案 P5-1。
- 内容层禁代码 / 防注入模式匹配（P3-6）、字节+字符双重长度口径（P3-4）未做。
- 校验失败的结构化审计外发 SIEM（P3-7 / P6-3）未接。
- `content` 仅接受 string，多模态数组白名单待 P3-5。
