# 蓝区 → 黄区请求白名单网关

本仓库实现一个简化的双节点七层过滤链路：

```text
蓝区调用方 → 蓝区 WAF → HTTP → 黄区 WAF → 黄区目标服务
```

用户于 2026-07-28 确认，蓝、黄服务器之间已经由四层网络策略限制为只允许双方登记的 IP 和端口互访。因此当前版本不配置 mTLS，来源限制由四层策略承担；七层负责 Host/接口白名单以及请求、响应 JSON 契约过滤。

## 当前能力

- 只允许 `conf/waf_rules.lua` 中精确登记的 `host + method + path`；相同 path 可按 Host 绑定不同契约。
- 所有 query string 默认拒绝。
- 配置 `request_schema` 的接口只接受 `application/json`，并校验字段、类型、长度、数量和数值范围。
- object schema 必须设置 `additional_properties=false`，未知字段默认拒绝。
- 校验通过后重新编码 JSON，再向下一跳转发。
- 未配置 `request_schema` 的接口禁止携带请求体。
- 不转发客户端原始请求头，只重建 Host、Content-Type、Accept 和 trace ID；Content-Length 由 Nginx 按规范化正文自动生成。
- 上游响应在受限内存子请求中完整取得，按状态码选择响应 schema；未登记状态、非 JSON、超限或字段不合规均 fail-closed。
- 请求、响应正文都只记录字节数与 SHA-256，不写入审计日志原文。
- 蓝、黄节点分别写本地 JSON Lines 审计日志。

WAF 不负责四层来源限制，也不替代防火墙、EDR、DLP、Jumpserver、文件外发审批或日志平台。

## 最小规则文件

活动规则文件是 `conf/waf_rules.lua`：

```lua
return {
  max_request_body_bytes = 16384,
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

仓库默认 `whitelist = {}`，所以安装后不会自动放行任何业务接口。知识库规则只保存在 `conf/waf_rules_knowledge_example.lua`，供本地测试参考，不会被生产模板加载。

不再要求 `version`、`direction` 或 `example`。每条接口必须登记 Host 和至少一个状态码响应 schema。旧的 `--production` 参数仍可使用，但与普通检查完全相同：

```bash
luajit scripts/check_rules.lua conf/waf_rules.lua
luajit scripts/check_rules.lua --production conf/waf_rules.lua
make test
```

## 部署配置

分别从以下模板生成蓝、黄节点配置：

- `conf/nginx-blue.conf.template`
- `conf/nginx-yellow.conf.template`（双固定目标模板）

必须替换模板中的监听 IP/端口、Host、对端 IP/端口和黄区目标服务 IP/端口。模板使用普通 HTTP，不需要证书文件。

蓝、黄两侧应分发同一份 `conf/waf_rules.lua`。启动顺序为黄端先、蓝端后。

完整的新装、旧版本升级、规则配置、双 Host 路由、响应校验、验收和回滚操作，统一见
`docs/WAF部署配置与升级手册.md`。

## 审计

```text
/data/openresty-waf/audit/access.log
/data/openresty-waf/audit/rejected.log
```

日志记录节点、来源地址、Host、method、path、rule ID、动作、拒绝原因、请求/响应体大小和 SHA-256、响应 schema、上游地址与状态；不记录 query 或正文原文。

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
conf/waf_rules.lua                    活动白名单，默认全拒绝
conf/waf_rules_knowledge_example.lua  本地请求过滤示例
lua/waf/decision.lua                  Host/URL、请求与响应决策
lua/waf/json_validator.lua            JSON 请求/响应体校验
lua/waf/handler.lua                   OpenResty 请求校验、内部代理和响应校验
conf/nginx-*.conf.template            蓝、黄节点双目标 HTTP 模板
```
