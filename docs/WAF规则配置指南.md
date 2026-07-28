# WAF 请求规则配置指南

活动规则文件是 `conf/waf_rules.lua`。当前版本只配置请求白名单和请求体 schema，不配置证书、规则方向、响应状态或响应 schema。

## 顶层结构

```lua
return {
  max_request_body_bytes = 16384,
  whitelist = {},
  schemas = {},
}
```

- `max_request_body_bytes` 必须为正整数，最大为 `16384` 字节。
- `whitelist` 是允许的精确接口列表；为空时所有请求都拒绝。
- `schemas` 保存请求 JSON schema。

## 白名单规则

无请求体接口：

```lua
{
  id = "RULE-HEALTH",
  methods = { "GET" },
  path = "/health",
}
```

有 JSON 请求体接口：

```lua
{
  id = "RULE-SEARCH",
  methods = { "POST" },
  path = "/search",
  request_schema = "search_request",
}
```

要求：

1. `id` 必须稳定且唯一，用于审计日志。
2. `methods` 必须是非空数组，支持 `GET`、`POST`、`PUT`、`PATCH`、`DELETE`。
3. `path` 必须是以 `/` 开头的精确路径，不支持正则、query 或 fragment。
4. 配置 `request_schema` 后必须发送合法 `application/json` 请求体。
5. 不配置 `request_schema` 时禁止发送请求体。
6. 所有 query string 都拒绝，包括结尾的空 `?`。

## 请求 schema

object 必须明确关闭未知字段：

```lua
search_request = {
  type = "object",
  additional_properties = false,
  required = { "query" },
  properties = {
    query = {
      type = "string",
      min_length = 1,
      max_length = 1000,
      max_bytes = 4000,
      non_blank = true,
    },
    top_k = { type = "integer", minimum = 1, maximum = 50 },
  },
}
```

支持 `object`、`array`、`string`、`integer`、`number`、`boolean`、`null`，以及 required、长度、字节数、数值范围、数组数量、enum、prefix 和通用格式。

## 请求处理结果

| 情况 | 结果 |
|---|---|
| method/path 未登记 | `403 not_in_whitelist` |
| 携带 query | `403 query_not_allowed` |
| 无 schema 的接口携带正文 | `400 unexpected_body` |
| 非 JSON Content-Type | `415 unsupported_media_type` |
| JSON 无法解析 | `400 invalid_json` |
| 请求体超限 | `413 request_body_too_large` |
| 字段或类型不符合 schema | `400/422 request_body` |
| 请求通过 | 重新编码 JSON 后转发 |

上游响应不经过 Lua 校验，状态码、响应头和响应体由 Nginx 直接返回调用方。

## 检查与发布

```bash
luajit scripts/check_rules.lua conf/waf_rules.lua
make test
sha256sum conf/waf_rules.lua
```

旧命令中的 `--production` 参数兼容保留，但不会再要求 `version` 或 `direction`：

```bash
luajit scripts/check_rules.lua --production conf/waf_rules.lua
```

蓝、黄两端必须使用相同规则文件。发布前还需核对四层策略中的源 IP、目标 IP、方向和端口，确认其它主机无法直达 WAF 或目标服务。
