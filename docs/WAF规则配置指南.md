# WAF 规则配置指南（知识库接口）

本文根据用户提供的[《知识库接口文档》](知识库接口文档.md)编写，用于配置蓝 WAF 和黄 WAF 的七层请求白名单。

接口文档只给出了 method、path、请求字段和响应字段，没有给出 Host、IP、端口、来源身份、QPS、负责人或生产审批状态。本文不会推断这些现场值。本配置示例也不代表接口已经获准生产放行。

## 1. 接口与请求 schema 对应关系

WAF 以 `method + path` 作为一条接口规则，通过 `request_schema` 显式关联该接口的请求体 schema。

| method | 精确 path | 是否允许请求体 | 对应请求 schema |
|---|---|---:|---|
| `GET` | `/ai/knowledge/health` | 否 | 无 |
| `POST` | `/ai/knowledge/search` | 是，只允许 JSON | `knowledge_search_request` |

对应关系如下：

```text
GET  /ai/knowledge/health
  └─ 不配置 request_schema，因此禁止请求体

POST /ai/knowledge/search
  └─ request_schema = "knowledge_search_request"
       └─ schemas.knowledge_search_request
```

这里的 schema 只校验请求体，不校验响应。Host 在蓝、黄节点的 Nginx `server_name` 中配置，不写入 `conf/waf_rules.lua`。

## 2. 完整活动规则配置

将下面内容作为两端的 `/opt/openresty-waf/conf/waf_rules.lua`。蓝、黄 WAF 必须使用完全相同的文件。

```lua
return {
  max_request_body_bytes = 16384,

  whitelist = {
    {
      id = "BY-002-KNOWLEDGE-HEALTH",
      methods = { "GET" },
      path = "/ai/knowledge/health",
    },
    {
      id = "BY-002-KNOWLEDGE-SEARCH",
      methods = { "POST" },
      path = "/ai/knowledge/search",
      request_schema = "knowledge_search_request",
    },
  },

  schemas = {
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
    },
  },
}
```

## 3. 两个接口的配置说明

### 3.1 健康检查

接口：

```http
GET /ai/knowledge/health
```

对应规则：

```lua
{
  id = "BY-002-KNOWLEDGE-HEALTH",
  methods = { "GET" },
  path = "/ai/knowledge/health",
}
```

该接口没有请求体，所以不配置 `request_schema`。如果请求携带正文，WAF 返回：

```text
400 unexpected_body
```

以下请求也不会放行：

- 使用 `POST`、`PUT` 等其它 method。
- 在 path 后添加 query string。
- 请求其它未登记 path。

### 3.2 知识库向量检索

接口：

```http
POST /ai/knowledge/search
Content-Type: application/json
```

白名单规则通过名称引用请求 schema：

```lua
{
  id = "BY-002-KNOWLEDGE-SEARCH",
  methods = { "POST" },
  path = "/ai/knowledge/search",
  request_schema = "knowledge_search_request",
}
```

引用的 schema 为：

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

字段映射：

| 字段 | 接口要求 | WAF 配置 | 说明 |
|---|---|---|---|
| `query` | string，必填，1～4000 字符 | `required`、`min_length=1`、`max_length=4000` | WAF 按 UTF-8 字符数检查 |
| `query` | 不能为空 | `non_blank=true` | 拒绝空字符串和只包含空白字符的值 |
| `query` | 请求体受 WAF 总大小限制 | `max_bytes=16000` | 单个 Unicode 字符最多占 4 个 UTF-8 字节 |
| `top_k` | integer，可选，1～50 | `minimum=1`、`maximum=50` | 省略时由后端使用默认值 5 |
| 其它字段 | 接口未登记 | `additional_properties=false` | 未知字段默认拒绝 |

WAF 不会给请求补充 `top_k=5`，只会允许该字段省略；默认值由知识库服务处理。

WAF 也不会删除 `query` 首尾空格。接口文档描述的去除首尾空格属于后端行为；WAF 只拒绝完全为空或全为空白字符的查询。

## 4. 为什么 schema 与 URL 分开定义

规则中的关联不是按文件位置自动推断，而是通过名称显式引用：

```lua
request_schema = "knowledge_search_request"
```

运行时处理顺序为：

1. 根据 `method + path` 找到白名单规则。
2. 读取该规则的 `request_schema`。
3. 根据名称取得 `schemas.knowledge_search_request`。
4. 使用该 schema 校验 JSON 请求体。
5. 校验通过后重新编码 JSON，再转发给下一跳。

配置检查会保证这种关联有效：

- `request_schema` 引用了不存在的 schema：报 error，禁止发布。
- schema 没有被任何白名单规则引用：报 warning。
- 相同 `method + path` 重复配置：报 error。

如果以后新增接口，应为每个不同的请求契约配置独立 schema。例如：

```lua
{
  id = "RULE-TASK-CREATE",
  methods = { "POST" },
  path = "/tasks",
  request_schema = "task_create_request",
}
```

多个接口只有在请求结构和限制完全一致时，才应复用同一个 schema。同一个 path 的不同 method 如果请求体不同，应拆成不同规则。

## 5. 请求处理结果

| 请求情况 | WAF 结果 |
|---|---|
| method/path 未登记 | `403 not_in_whitelist` |
| 携带任何 query string | `403 query_not_allowed` |
| `/ai/knowledge/health` 携带正文 | `400 unexpected_body` |
| `/ai/knowledge/search` 不是 JSON Content-Type | `415 unsupported_media_type` |
| JSON 无法解析 | `400 invalid_json` |
| 缺少 `query` | `400 request_body`，字段为 `query` |
| 出现未知字段 | `400 request_body`，字段为未知字段名 |
| `query` 为空、全空白或超过限制 | `422 request_body` |
| `top_k` 不是整数或不在 1～50 | `400/422 request_body` |
| 请求体超过 16 KiB | `413 request_body_too_large` |
| 请求合法 | 转发到下一跳 |

`top_k` 为字符串、小数或其它 JSON 类型时属于类型错误，返回 `400`；整数值超出 1～50 时属于策略限制，返回 `422`。

## 6. 响应处理边界

接口文档还定义了健康检查响应、检索结果以及后端的 `200`、`422`、`502`、`503` 状态，但当前 WAF 不配置响应 schema，也不读取或过滤响应体。

因此：

- 后端响应由 Nginx 直接透传。
- 后端返回 `502` 或 `503` 不一定表示 WAF 规则失败，应结合审计日志中的 `action` 和 `upstream_status` 判断。
- `action=allow_request` 表示请求已经通过 WAF 请求校验。
- 响应中的 `content`、`metadata` 等字段是否包含敏感信息，由知识库服务和其它数据安全控制负责，本仓库 WAF 不做响应防泄漏。

## 7. 规则检查与发布

### 7.1 检查规则

在仓库或服务器的 `/opt/openresty-waf` 目录执行：

```bash
/data/openresty/luajit/bin/luajit scripts/check_rules.lua conf/waf_rules.lua
```

开发环境也可以执行：

```bash
make lint
make test
```

正确的规则检查输出应列出：

```text
ALLOW  GET   /ai/knowledge/health  [BY-002-KNOWLEDGE-HEALTH]  body=none
ALLOW  POST  /ai/knowledge/search  [BY-002-KNOWLEDGE-SEARCH]  body=knowledge_search_request
```

并显示：

```text
体检完成：0 error
白名单条数：2
```

### 7.2 发布顺序

1. 备份蓝、黄两端当前 `conf/waf_rules.lua`。
2. 将同一份新规则分发到蓝、黄两端。
3. 分别执行规则检查，并核对两端文件 SHA-256 相同。
4. 先检查并 reload 黄 WAF。
5. 黄端正常后，再检查并 reload 蓝 WAF。
6. 执行允许和拒绝用例，并核对两端审计日志。

生产放行前仍需补齐白名单台账中的实际 Host、IP、端口、来源、owner、有效期、QPS、审计和回滚信息。

## 8. 最小验证用例

先填写实际蓝 WAF 地址和 Host：

```bash
WAF_RULE_TEST_IP='填写蓝WAF监听IP'
WAF_RULE_TEST_PORT='填写蓝WAF监听端口'
WAF_RULE_TEST_HOST='填写蓝WAF业务Host'
WAF_RULE_TEST_BASE="http://${WAF_RULE_TEST_IP}:${WAF_RULE_TEST_PORT}"
```

### 健康检查

```bash
curl -sS -i \
  -H "Host: ${WAF_RULE_TEST_HOST}" \
  "${WAF_RULE_TEST_BASE}/ai/knowledge/health"
```

### 合法检索请求

```bash
curl -sS -i \
  -H "Host: ${WAF_RULE_TEST_HOST}" \
  -H 'Content-Type: application/json' \
  --data-binary '{"query":"机台发生通信异常时应该如何处理？","top_k":5}' \
  "${WAF_RULE_TEST_BASE}/ai/knowledge/search"
```

### 拒绝未知字段

```bash
curl -sS -i \
  -H "Host: ${WAF_RULE_TEST_HOST}" \
  -H 'Content-Type: application/json' \
  --data-binary '{"query":"测试问题","tenant":"unknown"}' \
  "${WAF_RULE_TEST_BASE}/ai/knowledge/search"
```

预期返回 `400 request_body`，拒绝字段为 `tenant`。

### 拒绝越界 top_k

```bash
curl -sS -i \
  -H "Host: ${WAF_RULE_TEST_HOST}" \
  -H 'Content-Type: application/json' \
  --data-binary '{"query":"测试问题","top_k":51}' \
  "${WAF_RULE_TEST_BASE}/ai/knowledge/search"
```

预期返回 `422 request_body`，拒绝字段为 `top_k`。

### 拒绝未登记 path

```bash
curl -sS -i \
  -H "Host: ${WAF_RULE_TEST_HOST}" \
  "${WAF_RULE_TEST_BASE}/ai/knowledge/not-registered"
```

预期返回 `403 not_in_whitelist`。

验证时同时检查：

```text
/data/openresty-waf/audit/access.log
```

允许请求应记录 `action=allow_request`；被 WAF 拒绝的请求应记录 `action=deny_request` 和对应 `reason`。
