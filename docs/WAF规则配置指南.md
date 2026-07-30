# WAF 规则配置指南

## 1. 规则模型

当前 WAF 以以下三元组作为接口唯一键：

```text
host + method + path
```

因此，不同服务器可以使用相同的 method 和 path，并分别绑定不同的请求、响应 schema：

```text
service-a.internal + POST + /ai/knowledge/search → A 请求/响应契约
service-b.internal + POST + /ai/knowledge/search → B 请求/响应契约
```

同一 `host + method + path` 重复配置会导致规则检查失败。Host 必须是小写精确值，不允许端口、通配符、正则或路径。

## 2. 顶层配置

```lua
return {
  max_request_body_bytes = 16384,
  max_response_body_bytes = 1048576,
  whitelist = {},
  schemas = {},
}
```

| 字段 | 说明 |
|---|---|
| `max_request_body_bytes` | 全局请求体上限，最大 16384 字节 |
| `max_response_body_bytes` | 全局响应捕获上限，最大 1048576 字节，必须与 Nginx 内存缓冲上限一致 |
| `whitelist` | 精确 Host/接口白名单 |
| `schemas` | 请求和响应共用的声明式 JSON schema 字典 |

生产活动文件为 `/opt/openresty-waf/conf/waf_rules.lua`。仓库默认活动白名单为空，不自动放行任何业务接口。

## 3. 白名单规则字段

```lua
{
  id = "BY-002-KNOWLEDGE-SEARCH",
  host = "knowledge.example.internal",
  methods = { "POST" },
  path = "/ai/knowledge/search",
  request_schema = "knowledge_search_request",
  responses = {
    [200] = { schema = "knowledge_search_response", max_body_bytes = 1048576 },
    [422] = { schema = "knowledge_error_response", max_body_bytes = 16384 },
    [502] = { schema = "knowledge_error_response", max_body_bytes = 16384 },
    [503] = { schema = "knowledge_error_response", max_body_bytes = 16384 },
  },
}
```

| 字段 | 要求 |
|---|---|
| `id` | 稳定、唯一、非空的台账规则编号 |
| `host` | 不含端口的小写精确 Host |
| `methods` | 非空 HTTP 方法数组 |
| `path` | 以 `/` 开头且不含 query/fragment 的精确路径 |
| `request_schema` | 有请求体时必须配置；未配置时禁止携带正文 |
| `responses` | 必填；按实际 HTTP 状态码登记响应 schema 和该响应最大字节数 |

未登记状态码、非 JSON 响应、压缩响应、超限响应或 schema 不合规响应均由 WAF 拒绝，不回显原始上游正文。

## 4. 请求 schema

知识检索请求文档定义：

```json
{
  "query": "机台发生通信异常时应该如何处理？",
  "top_k": 5
}
```

对应配置：

```lua
knowledge_search_request = {
  type = "object",
  additional_properties = false,
  required = { "query" },
  properties = {
    query = {
      type = "string",
      min_length = 1,
      max_length = 4000,
      max_bytes = 16000,
      non_blank = true,
    },
    top_k = {
      type = "integer",
      minimum = 1,
      maximum = 50,
    },
  },
}
```

`top_k` 可省略，默认值由后端服务处理，WAF 不补写默认值。`additional_properties=false` 会拒绝 `query`、`top_k` 之外的字段。

## 5. 响应 schema

规则按实际状态码选择响应 schema。成功响应和错误响应必须分开登记。

知识检索错误响应示例：

```lua
knowledge_error_response = {
  type = "object",
  additional_properties = false,
  required = { "detail" },
  properties = {
    detail = { type = "string", min_length = 1, max_length = 1000 },
  },
}
```

完整的知识库健康检查、检索成功响应和错误响应 schema 位于：

```text
conf/waf_rules_knowledge_example.lua
```

该文件只用于本地测试。生产使用前必须确认：

- 实际业务 Host；
- 每个状态码；
- `results` 中所有字段是否必定出现；
- `metadata` 的完整字段白名单；
- 字段长度和最大响应体大小；
- `content`、`metadata` 是否允许跨区返回。

接口文档没有给出最大响应体和完整 metadata 契约，因此示例不能直接视为生产审批结果。

## 6. 两个服务器使用相同 path

最小示例位于：

```text
conf/waf_rules_same_path_example.lua
```

核心结构：

```lua
whitelist = {
  {
    id = "SERVICE-A-SEARCH",
    host = "service-a.example.internal",
    methods = { "POST" },
    path = "/ai/knowledge/search",
    request_schema = "service_a_request",
    responses = {
      [200] = { schema = "service_a_response", max_body_bytes = 65536 },
    },
  },
  {
    id = "SERVICE-B-SEARCH",
    host = "service-b.example.internal",
    methods = { "POST" },
    path = "/ai/knowledge/search",
    request_schema = "service_b_request",
    responses = {
      [200] = { schema = "service_b_response", max_body_bytes = 65536 },
    },
  },
}
```

两个 Host 的 schema 互不复用，除非两个接口文档逐字段、状态码和大小限制完全一致。

## 7. 请求处理结果

| 请求情况 | WAF 结果 |
|---|---|
| Host/method/path 未登记 | `403 not_in_whitelist` |
| 携带任何 query string | `403 query_not_allowed` |
| 无 `request_schema` 的接口携带正文 | `400 unexpected_body` |
| 非 JSON Content-Type | `415 unsupported_media_type` |
| JSON 无法解析 | `400 invalid_json` |
| 缺少字段或类型错误 | `400 request_body` |
| 长度、数量或数值越界 | `422 request_body` |
| 请求体超过全局上限 | `413 request_body_too_large` |

请求通过后，WAF 会重新编码 JSON，只向固定下一跳转发规范化正文和必要请求头。

## 8. 响应处理结果

| 响应情况 | WAF 结果 |
|---|---|
| 状态码未登记 | `502 response_status_not_allowed` |
| 子请求失败 | `502 upstream_capture_failed` |
| 响应超过规则或全局上限 | `502 response_body_too_large` |
| 非 JSON Content-Type | `502 response_unsupported_media_type` |
| 压缩响应 | `502 response_content_encoding_not_allowed` |
| JSON 无法解析 | `502 invalid_upstream_json` |
| 响应字段或类型不符合 schema | `502 response_body` |
| 响应合法 | 保留已登记的上游状态码，返回规范化 JSON |

响应在任何正文发送给调用方前完成校验。拒绝时只返回统一网关错误，不返回原始上游正文。

## 9. 支持的 schema 关键字

- 类型：`object`、`array`、`string`、`integer`、`number`、`boolean`、`null`；
- 对象：`required`、`properties`、`additional_properties=false`、`max_properties`；
- 数组：`items`、`min_items`、`max_items`；
- 字符串：`min_length`、`max_length`、`max_bytes`、`non_blank`、`trimmed`、`prefix`、`format`；
- 数值：`minimum`、`maximum`；
- 通用：`enum`。

object 必须显式配置 `properties` 且 `additional_properties=false`。未知配置关键字会导致 lint 失败。

## 10. 检查与发布

检查活动规则：

```bash
cd /opt/openresty-waf
/data/openresty/luajit/bin/luajit scripts/check_rules.lua conf/waf_rules.lua
```

开发环境：

```bash
make lint
make test
```

规则检查输出会同时列出 Host、method、path、请求 schema 和允许的响应状态码。

蓝、黄两端必须分发完全相同的规则文件和 Lua 代码，并核对 SHA-256。先检查和 reload 黄 WAF，再处理蓝 WAF；最后执行两个 Host 的允许、交叉拒绝、响应拒绝和四层绕过测试。
