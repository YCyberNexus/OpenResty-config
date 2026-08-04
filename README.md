# 蓝区 → 黄区请求白名单网关

本仓库实现一个简化的双节点七层过滤链路：

```text
蓝区调用方 → 蓝区 WAF → HTTP → 黄区 WAF → 黄区目标服务
```

用户于 2026-07-28 确认，蓝、黄服务器之间已经由四层网络策略限制为只允许双方登记的 IP 和端口互访。因此当前版本不配置 mTLS，来源限制由四层策略承担；七层负责 Host/接口白名单以及请求、响应 JSON 契约过滤。

## 当前能力

- 只允许 `conf/waf_rules.lua` 中登记的 `host + method + path`；普通接口使用精确 path，
  资产详情接口只额外支持末尾 `{uuid}` 的受限路径模板，不接受任意正则。
- 所有 query string 默认拒绝。
- 配置 `request_schema` 的接口只接受 `application/json`，并校验字段、类型、长度、数量和数值范围。
- object schema 默认设置 `additional_properties=false`，未知字段拒绝；接口文档明确为
  动态对象的 metadata、Cypher parameters 和图谱 rows 设置为 `true`，静态检查会逐项告警。
- 校验通过后重新编码 JSON，再向下一跳转发。
- 未配置 `request_schema` 的接口禁止携带请求体。
- 不转发客户端原始请求头，只重建 Host、Content-Type、Accept 和 trace ID；Content-Length 由 Nginx 按规范化正文自动生成。
- 上游响应在受限内存子请求中完整取得，按状态码选择响应 schema；未登记状态、非 JSON、超限或字段不合规均 fail-closed。
- 审计日志全量记录原始请求、规范化转发请求、原始上游响应和实际返回响应正文，同时保留字节数与 SHA-256。
- 蓝、黄节点分别写本地 JSON Lines 审计日志。

WAF 不负责四层来源限制，也不替代防火墙、EDR、DLP、Jumpserver、文件外发审批或日志平台。

## 最小规则文件

活动规则文件是 `conf/waf_rules.lua`：

```lua
return {
  max_request_body_bytes = 131072,
  max_response_body_bytes = 1048576,
  whitelist = {
    {
      id = "RULE-001",
      host = "service.example.internal",
      methods = { "GET" },
      path = "/health",
      responses = {
        [200] = { schema = "health_response", max_body_bytes = 4096 },
      },
    },
    {
      id = "RULE-002",
      host = "service.example.internal",
      methods = { "POST" },
      path = "/search",
      request_schema = "search_request",
      responses = {
        [200] = { schema = "search_response", max_body_bytes = 65536 },
      },
    },
  },
  schemas = {
    search_request = {
      type = "object",
      additional_properties = false,
      required = { "query" },
      properties = {
        query = { type = "string", min_length = 1, max_length = 1000 },
      },
    },
    health_response = {
      type = "object",
      additional_properties = false,
      required = { "status" },
      properties = {
        status = { type = "string", enum = { "ok" } },
      },
    },
    search_response = {
      type = "object",
      additional_properties = false,
      required = { "results" },
      properties = {
        results = { type = "array", max_items = 20, items = { type = "string" } },
      },
    },
  },
}
```

当前活动规则在 `kb.pxsemic.tech` 放行以下五个接口：

```text
POST /ai/knowledge/search
GET  /ai/knowledge/assets/{uuid}
GET  /ai/knowledge/health
POST /ai/knowledge/graph/query
GET  /ai/knowledge/graph/health
```

`kb-1.pxsemic.tech`、其它 method/path、query string、非 UUID 资产路径和未知顶层 JSON 字段
继续默认拒绝。旧的本地请求示例保存在 `conf/waf_rules_knowledge_example.lua`，不参与生产加载。
图谱查询为支持最长 20000 个 UTF-8 字符，请求 JSON 硬上限为 128 KiB；响应硬上限仍为 1 MiB。

不再要求 `version`、`direction` 或 `example`。每条接口必须登记 Host 和至少一个状态码响应 schema。旧的 `--production` 参数仍可使用，但与普通检查完全相同：

```bash
luajit scripts/check_rules.lua conf/waf_rules.lua
luajit scripts/check_rules.lua --production conf/waf_rules.lua
make test
```

## 部署配置

仓库已经包含按 2026-07-31 现场值固化的蓝、黄节点配置，部署包会直接携带：

- `conf/nginx-blue.conf`
- `conf/nginx-yellow.conf`（双固定路由）

当前固定链路为 `10.64.5.4:80 → 10.64.9.2:80 → 192.168.14.249:6789`，业务 Host 为
`kb.pxsemic.tech` 和 `kb-1.pxsemic.tech`；后者在黄端作为入口别名，发往后端时使用
`Host: kb.pxsemic.tech`。`.template` 文件仅用于以后经审批迁移到其它地址，不参与当前部署。

蓝、黄两侧应分发同一份 `conf/waf_rules.lua`。启动顺序为黄端先、蓝端后。

完整的新装、旧版本升级、规则配置、双 Host 路由、响应校验、验收和回滚操作，统一见
`docs/WAF部署配置与升级手册.md`。

## 审计

```text
/data/openresty-waf/audit/access.log
/data/openresty-waf/audit/rejected.log
```

日志记录节点、来源地址、Host、method、path、rule ID、动作、拒绝原因、请求/响应体原文、大小和 SHA-256、响应 schema、上游地址与状态。正文不做脱敏、采样或字段过滤；该行为偏离白名单台账中“黄区原文不得写入审计日志”的控制要求，不能据此声称满足生产安全基线。

## 本地验证

```bash
make lint
make test
```

安装 OpenResty 后可以运行本地示例：

```bash
make serve
make smoke
make stop
```

## 核心文件

```text
conf/waf_rules.lua                    活动白名单，放行 BY-002 五个知识库接口
conf/waf_rules_knowledge_example.lua  本地请求过滤示例
lua/waf/decision.lua                  Host/URL、请求与响应决策
lua/waf/json_validator.lua            JSON 请求/响应体校验
lua/waf/handler.lua                   OpenResty 请求校验、内部代理和响应校验
conf/nginx-blue.conf                  蓝节点固定生产配置
conf/nginx-yellow.conf                黄节点固定生产配置
conf/nginx-*.conf.template            经审批迁移地址时使用的通用模板
```
