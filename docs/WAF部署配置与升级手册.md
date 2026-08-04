# OpenResty WAF 通用 V2 配置、部署与升级手册

## 1. 结论

V2 只需整体部署一次。之后新增普通 HTTP API，不再修改 Lua 或 Nginx 运行时，只修改以下配置：

| 变化 | 修改文件 |
|---|---|
| 新增/修改接口、路径、Query、头、请求/响应契约 | `conf/waf_rules.lua` |
| 新增 Host、后端 IP/端口、上游 Host、默认超时档 | `conf/waf_routes.lua` |
| 复用 Bearer/API Key/Basic 或内置业务策略 | 通常只在规则中引用；新增策略实例时改 `conf/waf_policies.lua` |

配置变更仍需在黄、蓝两端分发、体检、`openresty -t` 和 reload，但不需要重新部署整个包。

第一次从 V1 升到 V2 必须整体替换，因为本次同时修改了 Lua 运行时、Nginx 内部代理、审计变量、
配置格式和技术上限。

## 2. 架构与现网固定值

```text
蓝区调用方
  -> 10.64.5.4:80       蓝 WAF（node_role=blue）
  -> 10.64.9.2:80       黄 WAF（node_role=yellow）
  -> 192.168.14.249:6789 黄区知识库服务
```

当前服务 Host：

- `kb.pxsemic.tech`：存在固定路由和五条活动接口规则；
- `kb-1.pxsemic.tech`：存在固定路由但无活动接口规则，因此默认拒绝。

这些地址来自现场确认，不是从三区架构图推断。蓝到黄、黄到后端的源/目标 IP 与端口限制仍由
四层 ACL/防火墙负责。WAF 不替代 AD、Jumpserver、EDR、DLP 或日志平台。

## 3. V2 文件职责

### 3.1 接口契约：`conf/waf_rules.lua`

每条规则必须明确：

- 稳定唯一的 `id`；
- 小写精确 `host`；
- 允许的 `methods`；
- 精确 `path`，或带命名参数的 `path_template`；
- `buffered` 或 `stream`；
- `auth_policy`；
- Query、请求头、请求正文；
- 每个允许响应状态的正文和响应头策略。

没有登记的 Host、method、path、Query、正文、状态码或媒体类型均默认拒绝。

### 3.2 固定下一跳：`conf/waf_routes.lua`

路由按节点角色和业务 Host 配置。`address` 只允许固定规范 IPv4，不允许域名、变量或客户端输入。

```lua
nodes = {
  blue = {
    ["api.example.internal"] = {
      scheme = "http",
      address = "10.64.9.2",
      port = 80,
      upstream_host = "api.example.internal",
      timeout_profile = "standard",
    },
  },
  yellow = {
    ["api.example.internal"] = {
      scheme = "http",
      address = "192.168.14.250",
      port = 8080,
      upstream_host = "api-backend.internal",
      timeout_profile = "standard",
    },
  },
}
```

Nginx 的非空 Host 正则虚拟主机只负责把请求交给 Lua，再由 Lua 做精确 Host 门禁；空 Host 仍由
default server 直接拒绝。新增 Host 不需要新增 Nginx `server` 块；如果规则或任一生产节点路由
缺失，启动体检失败或请求被拒绝，不会回落到其它后端。

### 3.3 可复用策略：`conf/waf_policies.lua`

预置超时档：

| 名称 | connect | send | read | 用途 |
|---|---:|---:|---:|---|
| `fast` | 2s | 10s | 15s | 快速健康检查 |
| `standard` | 5s | 30s | 60s | 普通 API |
| `long` | 5s | 300s | 3600s | SSE、长任务或大文件 |

预置认证门禁：

- `network_only`：不转发客户端凭证，只依赖现有四层来源限制；
- `bearer`：要求并转发合法语法的 `Authorization: Bearer ...`；
- `api_key`：要求并转发合法语法的 `X-API-Key`；
- `basic`：要求并转发合法语法的 `Authorization: Basic ...`。

这些门禁只校验凭证存在性和语法。令牌、API Key、账号密码的真实性与权限必须由后端验证。

当前内置业务策略 `cypher_read_only_v1` 采用保守白名单：允许以 MATCH、OPTIONAL、UNWIND、
WITH、RETURN（可带 EXPLAIN/PROFILE）开头的单条只读查询；拒绝 CREATE、MERGE、DELETE、SET、
REMOVE、LOAD、CALL、管理关键字、分号多语句和无法安全解析的引号/注释。

## 4. 通用配置示例

### 4.1 多个路径参数

```lua
{
  id = "DOC-VERSION-DETAIL",
  host = "api.example.internal",
  methods = { "GET" },
  path_template = "/tenants/{tenant_id}/documents/{document_id}/versions/{version_no}",
  path_parameters = {
    tenant_id = { type = "string", format = "slug" },
    document_id = { type = "string", format = "uuid" },
    version_no = { type = "string", format = "digits", max_length = 10 },
  },
  transport = "buffered",
  auth_policy = "bearer",
  responses = { -- 见下文 },
}
```

模板参数必须占满整个路径段、名称唯一，并逐个配置 string schema。运行时不接受正则路径。
`uuid`、`slug`、`digits`、`path_segment`、`enum` 等约束可以组合使用。可能重叠的同 Host、
method 路由会被静态体检拒绝。

### 4.2 Query 参数

先在 `schemas` 中声明对象：

```lua
document_list_query = {
  type = "object",
  additional_properties = false,
  required = { "page", "enabled" },
  properties = {
    page = { type = "integer", minimum = 1, maximum = 1000 },
    enabled = { type = "boolean" },
    keyword = { type = "string", max_length = 200, max_bytes = 800 },
    tag = {
      type = "array",
      max_items = 10,
      items = { type = "string", max_bytes = 64 },
    },
  },
}
```

规则引用：

```lua
request = {
  query_schema = "document_list_query",
}
```

WAF 严格 percent 解码、拒绝非法转义和控制字符，将 integer/number/boolean 转为对应类型后执行
schema 校验，再按字段名排序重新编码。标量参数重复会拒绝；只有声明为有界 array 的参数可重复。
未配置 `query_schema` 的接口继续拒绝任何 Query，包括单独的 `?`。

### 4.3 请求头和认证

```lua
auth_policy = "bearer",
request = {
  headers = {
    ["x-tenant-id"] = {
      required = true,
      schema = {
        type = "string",
        format = "slug",
        min_length = 1,
        max_bytes = 64,
      },
    },
    ["idempotency-key"] = {
      required = false,
      schema = { type = "string", format = "uuid", max_bytes = 64 },
    },
  },
}
```

客户端原始头在代理前全部清除，只重新写入规则声明的头和认证策略准许的凭证。Host、Content-Type、
Content-Length、Accept、Accept-Encoding、Connection、trace 等由 WAF/Nginx 管理，不能在业务规则
中覆盖。凭证值不会写入 `forward_header_names` 之外的审计字段。

### 4.4 JSON 请求与响应（默认推荐）

```lua
{
  id = "DOCUMENT-CREATE",
  host = "api.example.internal",
  methods = { "POST" },
  path = "/documents",
  transport = "buffered",
  auth_policy = "bearer",
  request = {
    body = {
      mode = "json",
      required = true,
      media_types = { "application/json" },
      schema = "document_create_request",
      max_body_bytes = 262144,
    },
  },
  responses = {
    [201] = {
      body = {
        mode = "json",
        media_types = { "application/json" },
        schema = "document_create_response",
        max_body_bytes = 262144,
      },
      headers = {
        ["etag"] = {
          required = false,
          schema = { type = "string", format = "header_value", max_bytes = 256 },
        },
      },
    },
    [400] = {
      body = {
        mode = "json",
        media_types = { "application/json" },
        schema = "error_response",
        max_body_bytes = 16384,
      },
    },
  },
}
```

buffered JSON 会被解析、校验并重新编码，消除重复键之外的多重表示；上游响应在完整校验通过前不会
返回调用方。每个可能状态必须单独登记，不能用范围或默认响应兜底。

### 4.5 文本和小型二进制

UTF-8 文本使用 `mode = "text"` 并引用 string schema。小于等于 1 MiB 的 PDF、图片或其它二进制
可以在 buffered 模式使用：

```lua
body = {
  mode = "binary",
  media_types = { "application/pdf" },
  max_body_bytes = 1048576,
  audit_body = false,
}
```

二进制不做 JSON schema 校验，但仍校验状态、精确媒体类型、Content-Encoding 和大小。建议
`audit_body=false`，只记录字节数和 SHA-256。

### 4.6 文件上传、下载和 SSE

超过 buffered 上限或需要实时输出时，必须显式使用 stream：

```lua
{
  id = "DOCUMENT-DOWNLOAD",
  host = "api.example.internal",
  methods = { "GET" },
  path_template = "/documents/{document_id}/content",
  path_parameters = {
    document_id = { type = "string", format = "uuid" },
  },
  transport = "stream",
  timeout_profile = "long",
  auth_policy = "bearer",
  responses = {
    [200] = {
      body = {
        mode = "stream",
        media_types = { "application/pdf", "application/octet-stream" },
        max_body_bytes = 67108864,
        audit_body = false,
      },
      headers = {
        ["content-disposition"] = {
          required = true,
          schema = { type = "string", format = "header_value", max_bytes = 1024 },
        },
      },
    },
  },
}
```

SSE 将媒体类型改为 `text/event-stream`。multipart 上传使用 request body：

```lua
body = {
  mode = "binary",
  required = true,
  media_types = { "multipart/form-data" },
  max_body_bytes = 67108864,
  audit_body = false,
}
```

stream 在响应头发送前校验状态、媒体类型、声明响应头和 Content-Length；对 chunked/SSE 持续计算
响应字节数和 SHA-256，超过上限立即截断。落入 Nginx 临时文件的大型上传为避免同步读盘阻塞
worker，请求审计记录大小和 `not_computed_stream_file`，不计算文件 SHA-256。由于流式数据已逐段发给
客户端，WAF 无法在发送前验证完整响应正文；这是显式安全偏离，不能把普通 JSON API 随意改为
stream。

## 5. 技术硬上限

| 项目 | V2 硬上限 | 位置 |
|---|---:|---|
| Query | 32 KiB | Lua 体检；活动配置为 8 KiB |
| buffered 请求 | 1 MiB | Lua 体检 |
| buffered 响应 | 1 MiB | `subrequest_output_buffer_size 1m` |
| stream 请求 | 64 MiB | `client_max_body_size 64m` |
| stream 响应 | 256 MiB | Lua body filter |

规则中的 `max_body_bytes` 必须小于等于对应全局限制。提高以上硬上限需要容量、安全和审计评审，
不能只改一行规则。

超过 128 KiB 的请求可能落入 `/data/openresty-waf/client_body_temp`。`server-setup.sh` 会以 WAF
运行用户创建 0700 目录，systemd service 只额外开放该目录写权限；不要改到可被普通用户读取的
共享临时目录。

## 6. V2 首次整体升级

### 6.1 部署包

包名：`openresty-waf-v2-20260804.tgz`。上线前在交付机和两台 WAF 分别执行：

```bash
sha256sum openresty-waf-v2-20260804.tgz
tar -tzf openresty-waf-v2-20260804.tgz
```

包内顶层目录为 `openresty-waf/`。必须整体保留目录结构；不要只挑一个 Lua 文件覆盖 V1。

### 6.2 升级顺序

1. 确认变更单、四层 ACL、回滚包、日志转储和后端健康状态；
2. 先升级黄 WAF并验收；
3. 再升级蓝 WAF并验收；
4. 验证蓝、黄审计日志可用同一 `trace_id` 关联；
5. 保留旧包和旧配置，直至观察期结束。

### 6.3 每个节点的校验

以下命令在解压后的 `/opt/openresty-waf` 执行；`NODE_ROLE` 分别使用 `yellow` 或 `blue`：

```bash
/data/openresty/luajit/bin/luajit scripts/check_rules.lua \
  conf/waf_rules.lua conf/waf_routes.lua conf/waf_policies.lua

/data/openresty/bin/openresty -p /opt/openresty-waf/ \
  -c conf/nginx-${NODE_ROLE}.conf -t
```

活动知识库配置预期为 `0 error, 5 warning`。5 个 warning 只允许来自接口文档明确声明为动态对象的
metadata、parameters 和 graph rows。出现其它 warning 或任何 error 均停止上线。

通过后：

```bash
systemctl restart openresty-waf@${NODE_ROLE}
systemctl status openresty-waf@${NODE_ROLE} --no-pager
```

首次 V2 升级使用 restart，确保旧 worker 不再加载 V1 模块。后续纯配置变更使用 reload。

## 7. 后续只改配置的发布流程

### 7.1 本地/交付侧

1. 根据接口文档修改 `waf_rules.lua`；
2. 新 Host 或下一跳变化时同步修改 `waf_routes.lua`；
3. 需要现有认证/只读策略时只引用名称；确需新内置模式时才评审运行时；
4. 执行 `make lint`、`make test`、`git diff --check`；
5. 记录三份配置的 SHA-256、变更规则 ID、正向和拒绝用例。

### 7.2 服务器侧

只替换实际修改的配置，但三份必须一起体检：

```bash
/data/openresty/luajit/bin/luajit /opt/openresty-waf/scripts/check_rules.lua \
  /opt/openresty-waf/conf/waf_rules.lua \
  /opt/openresty-waf/conf/waf_routes.lua \
  /opt/openresty-waf/conf/waf_policies.lua

/data/openresty/bin/openresty -p /opt/openresty-waf/ \
  -c conf/nginx-${NODE_ROLE}.conf -t

systemctl reload openresty-waf@${NODE_ROLE}
```

仍按黄先蓝后的顺序。蓝、黄三个配置文件的 SHA-256 应分别一致，因为同一文件内同时保存两个节点
角色的规则和路由。

## 8. 验收

每条新规则至少覆盖：

- 正确 Host、method、path、Query、头、认证和正文；
- 未登记 Host/method/path；
- 路径参数格式错误和多余路径层级；
- 未登记、重复、类型错误或超长 Query；
- 缺失/非法凭证和业务头；
- 错误 Content-Type、超大正文、非法 JSON、未知字段；
- 未登记响应状态、媒体类型、编码、头、schema 和超大响应；
- 蓝、黄两跳同一 `trace_id`；
- 绕过 WAF 直连后端应被四层策略拒绝。

stream 额外验证 Content-Length 超限、chunked 超限截断、客户端断开、长连接超时和审计字节/哈希。

## 9. 回滚

配置变更回滚：恢复三份配置的上一批准版本，先黄后蓝执行体检、`openresty -t` 和 reload。

V2 首次升级回滚：恢复完整 V1 目录/包及服务单元，先黄后蓝 restart。不要把 V1 的
`waf_rules.lua` 与 V2 Lua/Nginx 混用，也不要只恢复单个 handler 文件。

回滚后必须验证：合法请求恢复、拒绝用例仍拒绝、后端不可绕过、审计持续写入。

## 10. 仍需代码评审的边界

V2 已覆盖普通 JSON/text/binary API、多路径参数、Query、头、常见凭证透传、文件和 SSE。以下变化
不能安全地假装成任意配置：

- 新的自定义签名算法或密钥管理方式；
- 未内置的业务语义解析器；
- HTTPS/mTLS 下一跳和证书信任链；
- WebSocket、任意 TCP 或协议升级；
- 超过 64 MiB 请求或 256 MiB 响应；
- 需要内容杀毒、DLP、文件解包或恶意格式检测。

这些情况需要明确需求和安全评审；不得通过 `additional_properties=true`、超大 stream 或任意后端
URL 绕过现有门禁。
