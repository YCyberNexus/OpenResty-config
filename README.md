# 蓝区 → 黄区请求白名单网关

本仓库实现一个简化的双节点七层过滤链路：

```text
蓝区调用方 → 蓝区 WAF → HTTP → 黄区 WAF → 黄区目标服务
```

用户于 2026-07-28 确认，蓝、黄服务器之间已经由四层网络策略限制为只允许双方登记的 IP 和端口互访。因此当前版本不配置 mTLS，来源限制由四层策略承担；七层只负责请求白名单和请求体过滤。

## 当前能力

- 只允许 `conf/waf_rules.lua` 中精确登记的 `method + path`。
- 所有 query string 默认拒绝。
- 配置 `request_schema` 的接口只接受 `application/json`，并校验字段、类型、长度、数量和数值范围。
- object schema 必须设置 `additional_properties=false`，未知字段默认拒绝。
- 校验通过后重新编码 JSON，再向下一跳转发。
- 未配置 `request_schema` 的接口禁止携带请求体。
- 不转发客户端原始请求头，只重建 Host、Content-Type、Content-Length、Accept 和 trace ID。
- 响应由 Nginx 直接透传，不做状态码或响应体过滤。
- 蓝、黄节点分别写本地 JSON Lines 审计日志。

WAF 不负责四层来源限制，也不替代防火墙、EDR、DLP、Jumpserver、文件外发审批或日志平台。

## 最小规则文件

活动规则文件是 `conf/waf_rules.lua`：

```lua
return {
  max_request_body_bytes = 16384,
  whitelist = {
    {
      id = "RULE-001",
      methods = { "GET" },
      path = "/health",
    },
    {
      id = "RULE-002",
      methods = { "POST" },
      path = "/search",
      request_schema = "search_request",
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
  },
}
```

仓库默认 `whitelist = {}`，所以安装后不会自动放行任何业务接口。知识库规则只保存在 `conf/waf_rules_knowledge_example.lua`，供本地测试参考，不会被生产模板加载。

不再要求 `version`、`direction`、`example` 或响应 schema。旧的 `--production` 参数仍可使用，但与普通检查完全相同：

```bash
luajit scripts/check_rules.lua conf/waf_rules.lua
luajit scripts/check_rules.lua --production conf/waf_rules.lua
make test
```

## 部署配置

分别从以下模板生成蓝、黄节点配置：

- `conf/nginx-blue.conf.template`
- `conf/nginx-yellow.conf.template`

必须替换模板中的监听 IP/端口、Host、对端 IP/端口和黄区目标服务 IP/端口。模板使用普通 HTTP，不需要证书文件。

蓝、黄两侧应加载完全相同的 `conf/waf_rules.lua` 并核对 SHA-256。启动顺序为黄端先、蓝端后。

完整操作见 `docs/双WAF部署与运维交接手册.md`，规则字段见 `docs/WAF规则配置指南.md`。

## 审计

```text
/data/openresty-waf/audit/access.log
/data/openresty-waf/audit/rejected.log
```

日志记录节点、来源地址、Host、method、path、rule ID、动作、拒绝原因、请求体大小和 SHA-256、上游地址与状态；不记录 query 或正文原文。

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
lua/waf/decision.lua                  method/path/query 请求决策
lua/waf/json_validator.lua            JSON 请求体校验
lua/waf/handler.lua                   OpenResty 请求处理
conf/nginx-*.conf.template            蓝、黄节点 HTTP 转发模板
```
