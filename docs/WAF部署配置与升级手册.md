# WAF 部署配置与升级手册

## 1. 配置文件

部署时主要使用以下文件：

| 文件 | 用途 | 是否需要修改 |
|---|---|---|
| `conf/waf_rules.lua` | 业务 Host、接口、请求和响应 schema | 必须按实际接口修改 |
| `conf/nginx-blue.conf.template` | 蓝 WAF 配置模板 | 复制为 `.conf` 后替换占位符 |
| `conf/nginx-yellow.conf.template` | 黄 WAF 配置模板 | 复制为 `.conf` 后替换占位符 |
| `conf/waf-http-common.conf` | 请求大小、响应缓冲和默认拒绝日志 | 通常不修改 |
| `conf/waf-audit-log-format.conf` | 业务审计日志字段 | 通常不修改 |
| `conf/waf-audit-vars.conf` | Lua 可写审计变量 | 不修改 |
| `conf/waf-internal-proxy-common.conf` | 固定 upstream 的请求头和超时 | 确认超时即可 |
| `deploy/openresty-waf@.service` | 蓝、黄 systemd 服务模板 | 通常不修改 |

服务器最终生效的文件是：

```text
/opt/openresty-waf/conf/nginx-blue.conf
/opt/openresty-waf/conf/nginx-yellow.conf
/opt/openresty-waf/conf/waf_rules.lua
/opt/openresty-waf/lua/waf/*.lua
/etc/systemd/system/openresty-waf@.service
```

蓝、黄节点必须使用同一个部署包和内容完全一致的 `waf_rules.lua`。

## 2. 需要准备的配置值

配置前收集以下值，不明确的值不要猜测：

| 配置 | 说明 |
|---|---|
| 业务 Host A/B | 调用方实际使用的 Host，也是 WAF 选择规则和黄端后端的依据 |
| 蓝 WAF 监听 IP/端口 | 业务调用方连接蓝 WAF 的地址 |
| 黄 WAF 监听 IP/端口 | 蓝 WAF 连接黄 WAF 的地址 |
| 后端 A/B 的 IP/端口 | 黄 WAF 固定连接的两个目标服务 |
| 后端 A/B 要求的 Host | 黄 WAF 发给后端的 HTTP Host |
| method/path | 每个接口的精确 HTTP 方法和路径 |
| 请求字段 | 字段名、类型、是否必填、长度或数值范围 |
| 响应状态码和字段 | 每个允许状态码都要配置独立响应 schema |
| 大小限制 | 请求体上限及每个状态码的响应体上限 |

规则的匹配键是：

```text
host + method + path
```

两个服务使用相同 method/path 时，必须使用不同 Host。例如：

```text
service-a.example.internal + POST + /ai/knowledge/search → 后端 A
service-b.example.internal + POST + /ai/knowledge/search → 后端 B
```

## 3. 配置 `waf_rules.lua`

### 3.1 顶层配置

活动规则文件默认内容：

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
| `max_request_body_bytes` | 全局请求体上限，必须大于 0，最大 16384 字节 |
| `max_response_body_bytes` | 全局响应体上限，必须大于 0，最大 1048576 字节 |
| `whitelist` | 接口白名单数组；空数组会拒绝所有业务接口 |
| `schemas` | 请求和响应 schema 字典，名称由规则引用 |

固定行为：

- query string 一律拒绝；
- 有请求体的接口只接受 `application/json`；
- 未配置 `request_schema` 的接口禁止请求体；
- 响应只接受 JSON，gzip、SSE、流式和二进制响应不支持；
- 未登记的 Host、method、path、字段或响应状态码均拒绝。

### 3.2 白名单规则

POST 接口示例：

```lua
{
  id = "SERVICE-A-SEARCH",
  host = "service-a.example.internal",
  methods = { "POST" },
  path = "/ai/knowledge/search",
  request_schema = "service_a_request",
  responses = {
    [200] = { schema = "service_a_success_response", max_body_bytes = 65536 },
    [422] = { schema = "service_a_error_response", max_body_bytes = 16384 },
    [502] = { schema = "service_a_error_response", max_body_bytes = 16384 },
  },
}
```

无请求体接口示例：

```lua
{
  id = "SERVICE-A-HEALTH",
  host = "service-a.example.internal",
  methods = { "GET" },
  path = "/ai/knowledge/health",
  responses = {
    [200] = { schema = "service_a_health_response", max_body_bytes = 16384 },
  },
}
```

| 字段 | 配置要求 |
|---|---|
| `id` | 唯一、稳定的规则编号；建议与白名单台账编号一致 |
| `host` | 小写精确 Host，不含端口、路径、通配符或正则 |
| `methods` | 大写 HTTP 方法数组，例如 `{ "GET" }`、`{ "POST" }` |
| `path` | 以 `/` 开头的精确路径，不含 query 或 fragment |
| `request_schema` | 有请求体时必填；无请求体接口不要填写 |
| `responses` | 必填；每个允许状态码配置 schema 和 `max_body_bytes` |

`/__waf_upstream` 是内部保留前缀，不能配置为业务 path。

### 3.3 请求 schema

```lua
service_a_request = {
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
      trimmed = true,
    },
    top_k = {
      type = "integer",
      minimum = 1,
      maximum = 50,
    },
  },
}
```

说明：

- `required` 中的字段必须出现；
- 未写入 `required` 的字段可以省略，WAF 不会自动补默认值；
- `additional_properties = false` 必须配置，未登记字段会被拒绝；
- `max_length` 按 UTF-8 字符数检查；
- `max_bytes` 按正文中的实际字节数检查；
- `non_blank = true` 拒绝空字符串和全空白字符串；
- `trimmed = true` 要求字符串首尾没有空白字符。

### 3.4 响应 schema

成功和错误响应分别配置，不要让不同状态码共用一个不准确的宽泛 schema。

```lua
service_a_success_response = {
  type = "object",
  additional_properties = false,
  required = { "query", "results" },
  properties = {
    query = { type = "string", min_length = 1, max_length = 4000 },
    results = {
      type = "array",
      max_items = 20,
      items = {
        type = "object",
        additional_properties = false,
        required = { "id", "title" },
        properties = {
          id = { type = "integer", minimum = 1 },
          title = { type = "string", min_length = 1, max_length = 500 },
        },
      },
    },
  },
}

service_a_error_response = {
  type = "object",
  additional_properties = false,
  required = { "detail" },
  properties = {
    detail = { type = "string", min_length = 1, max_length = 1000 },
  },
}
```

上游返回未登记状态码、未知字段、错误类型或超限正文时，WAF 返回 502，不把原始上游响应返回给调用方。

### 3.5 支持的 schema 配置

| 类型 | 可用配置 |
|---|---|
| 通用 | `type`、`enum` |
| object | `required`、`properties`、`additional_properties=false`、`max_properties` |
| array | `items`、`min_items`、`max_items` |
| string | `min_length`、`max_length`、`max_bytes`、`non_blank`、`trimmed`、`prefix`、`format` |
| integer/number | `minimum`、`maximum` |

`format` 当前支持：

| 值 | 含义 |
|---|---|
| `uuid` | UUID 字符串 |
| `relative_path` | 不以 `/` 开头，且不包含 `.`、`..`、反斜杠或重复斜杠的相对路径 |
| `absolute_path` | 以 `/` 开头的受限绝对路径 |
| `filename` | 不包含斜杠、反斜杠和控制字符的文件名 |

未知关键字、缺失 schema 引用、重复路由或不合法范围会导致规则检查失败。

### 3.6 完整双 Host 示例

仓库文件 `conf/waf_rules_same_path_example.lua` 展示了两个 Host 使用相同 method/path、不同请求和响应 schema 的完整配置。只能参考结构，生产字段必须按真实接口填写。

### 3.7 检查规则

开发机执行：

```bash
make lint
make test
```

服务器执行：

```bash
cd /opt/openresty-waf
/data/openresty/luajit/bin/luajit scripts/check_rules.lua conf/waf_rules.lua
sha256sum conf/waf_rules.lua
```

要求：

- 规则检查为 `0 error`；
- 正式环境不能保留空白名单 warning；
- 蓝、黄节点的 `waf_rules.lua` SHA-256 一致。

## 4. 配置蓝 WAF

生成正式配置：

```bash
cd /opt/openresty-waf
sudo cp conf/nginx-blue.conf.template conf/nginx-blue.conf
sudo vi conf/nginx-blue.conf
```

替换以下占位符：

| 占位符 | 填写内容 |
|---|---|
| `__BLUE_WAF_LISTEN_IP__` | 蓝 WAF 本机监听 IP |
| `__BLUE_WAF_LISTEN_PORT__` | 蓝 WAF 监听端口 |
| `__WAF_SERVICE_HOST_A__` | 业务 Host A，必须与规则 `host` 一致 |
| `__WAF_SERVICE_HOST_B__` | 业务 Host B，必须与规则 `host` 一致 |
| `__YELLOW_WAF_IP__` | 黄 WAF 的登记 IP |
| `__YELLOW_WAF_PORT__` | 黄 WAF 的登记端口 |

蓝端配置中的关键关系：

```text
server_name Host-A Host-B
        ↓ 保留原始业务 Host
yellow_waf = 黄 WAF 固定 IP:端口
```

不要修改以下行为：

- 未匹配业务 Host 的默认虚拟主机返回 444；
- `location /` 进入 Lua 请求和响应校验；
- `/__waf_upstream/` 必须保持 `internal`；
- 转发黄 WAF 时必须使用原始业务 Host。

## 5. 配置黄 WAF

生成正式配置：

```bash
cd /opt/openresty-waf
sudo cp conf/nginx-yellow.conf.template conf/nginx-yellow.conf
sudo vi conf/nginx-yellow.conf
```

替换以下占位符：

| 占位符 | 填写内容 |
|---|---|
| `__YELLOW_WAF_LISTEN_IP__` | 黄 WAF 本机监听 IP |
| `__YELLOW_WAF_PORT__` | 黄 WAF 监听端口 |
| `__WAF_SERVICE_HOST_A__` | 业务 Host A，必须与规则和蓝端一致 |
| `__WAF_SERVICE_HOST_B__` | 业务 Host B，必须与规则和蓝端一致 |
| `__PROTECTED_SERVICE_A_IP__` | 后端 A 的固定 IP |
| `__PROTECTED_SERVICE_A_PORT__` | 后端 A 的固定端口 |
| `__PROTECTED_SERVICE_A_HOST__` | 后端 A 实际要求的 Host |
| `__PROTECTED_SERVICE_B_IP__` | 后端 B 的固定 IP |
| `__PROTECTED_SERVICE_B_PORT__` | 后端 B 的固定端口 |
| `__PROTECTED_SERVICE_B_HOST__` | 后端 B 实际要求的 Host |

黄端固定映射：

```text
业务 Host A → protected_backend_a → 后端 A IP:端口，发送后端 A Host
业务 Host B → protected_backend_b → 后端 B IP:端口，发送后端 B Host
```

`__PROTECTED_SERVICE_*_HOST__` 填后端实际要求的 Host。只有确认后端接受 IP Host 时才填写 IP。

不要把调用方提供的 URL、Host 或 IP 动态用于 `proxy_pass`。两个后端都必须在模板中固定配置。

## 6. 公共 Nginx 配置

`conf/waf-http-common.conf` 的主要参数：

| 配置 | 当前值 | 说明 |
|---|---:|---|
| `client_body_buffer_size` | `16k` | 请求体内存缓冲 |
| `client_max_body_size` | `16k` | Nginx 请求体硬上限 |
| `subrequest_output_buffer_size` | `1m` | 上游响应完整捕获硬上限 |
| `underscores_in_headers` | `off` | 不接受带下划线的请求头名称 |
| `merge_slashes` | `on` | 合并重复路径斜杠 |

`conf/waf-internal-proxy-common.conf` 的主要参数：

| 配置 | 当前值 |
|---|---:|
| 连接超时 | `5s` |
| 发送超时 | `30s` |
| 读取超时 | `60s` |
| 请求头 | 不转发客户端原始请求头，只重建必要头 |
| `Content-Type` | `application/json` |
| `Accept-Encoding` | 空，要求上游返回未压缩内容 |
| 追踪头 | `X-WAF-Trace-ID` |

修改请求或响应硬上限时，需要同时检查 `waf_rules.lua`、Nginx 缓冲和 Lua 规则检查上限，不能只改一个文件。

检查所有占位符已经替换：

```bash
grep -En '__[A-Z0-9_]+__' /opt/openresty-waf/conf/nginx-blue.conf
grep -En '__[A-Z0-9_]+__' /opt/openresty-waf/conf/nginx-yellow.conf
```

对应节点的命令必须无输出。

## 7. 审计日志配置

日志文件：

```text
/data/openresty-waf/audit/access.log
/data/openresty-waf/audit/rejected.log
/data/openresty-waf/log/error.log
```

`access.log` 是 JSON Lines，每行记录一次业务请求。主要字段：

| 字段 | 内容 |
|---|---|
| `node_role` | `blue` 或 `yellow` |
| `local_request_id` | 当前节点生成的请求 ID |
| `trace_id` | 蓝、黄链路关联 ID |
| `remote_addr` | 当前节点看到的来源地址 |
| `request_host` | 规则匹配使用的业务 Host |
| `method`、`path` | 请求方法和路径 |
| `rule_id` | 命中的规则 ID |
| `action`、`reason`、`field` | 放行/拒绝结果和原因 |
| `request_body` | 收到的原始请求体全文 |
| `forward_body` | JSON 规范化后实际发往下一跳的请求体全文 |
| `request_body_bytes`、`request_body_sha256` | 原始请求体大小和摘要 |
| `forward_body_bytes`、`forward_body_sha256` | 转发请求体大小和摘要 |
| `upstream_addr`、`upstream_status` | 上游地址和状态码 |
| `response_schema` | 当前状态码使用的响应 schema |
| `response_body` | 原始上游响应体全文 |
| `forward_response_body` | 实际返回调用方的响应体全文 |
| `response_body_bytes`、`response_body_sha256` | 原始上游响应大小和摘要 |
| `forward_response_bytes`、`forward_response_sha256` | 实际返回响应大小和摘要 |

正文不脱敏、不采样、不做字段过滤。`escape=json` 只负责转义换行、引号和控制字符，日志中的正文内容仍是完整原文。

未命中业务 Host 的请求写入 `rejected.log`，其中包含原始 `request_body`；444 响应没有正文。

查看日志：

```bash
sudo tail -n 20 /data/openresty-waf/audit/access.log
sudo tail -n 20 /data/openresty-waf/audit/rejected.log
```

如果服务器安装了 `jq`：

```bash
sudo tail -n 1 /data/openresty-waf/audit/access.log | jq .
```

当前正文日志与白名单台账 `BY-002` 的原文日志禁止项冲突；部署记录中必须保留该偏离。正文会明显增加磁盘使用量，需要配置日志轮转、留存和转储。

## 8. 生成部署包

在仓库根目录执行：

```bash
make test
make lint
bash scripts/package.sh openresty-waf.tgz
shasum -a 256 openresty-waf.tgz
```

检查包内容：

```bash
tar -tzf openresty-waf.tgz
```

部署包必须包含：

```text
openresty-waf/conf/nginx-blue.conf.template
openresty-waf/conf/nginx-yellow.conf.template
openresty-waf/conf/waf_rules.lua
openresty-waf/conf/waf-audit-log-format.conf
openresty-waf/conf/waf-audit-vars.conf
openresty-waf/lua/waf/handler.lua
openresty-waf/scripts/server-setup.sh
openresty-waf/deploy/openresty-waf@.service
openresty-waf/docs/WAF部署配置与升级手册.md
```

交付时记录包名和 SHA-256，蓝、黄节点使用同一个包。服务器收到后执行：

```bash
sha256sum /tmp/openresty-waf.tgz
```

结果必须与交付记录一致。

## 9. 全新部署

### 9.1 解压

```bash
sudo mkdir -p /opt
sudo tar -xzf /tmp/openresty-waf.tgz -C /opt
cd /opt/openresty-waf
```

### 9.2 生成节点配置

黄节点：

```bash
sudo cp conf/nginx-yellow.conf.template conf/nginx-yellow.conf
sudo vi conf/nginx-yellow.conf
sudo vi conf/waf_rules.lua
```

蓝节点：

```bash
sudo cp conf/nginx-blue.conf.template conf/nginx-blue.conf
sudo vi conf/nginx-blue.conf
sudo vi conf/waf_rules.lua
```

两端 `waf_rules.lua` 必须一致，且不能保留包内默认空白名单。

### 9.3 创建目录并检查配置

黄节点：

```bash
sudo NODE_ROLE=yellow bash scripts/server-setup.sh
```

蓝节点：

```bash
sudo NODE_ROLE=blue bash scripts/server-setup.sh
```

脚本会创建审计和运行日志目录，并检查规则、占位符和 OpenResty 配置。

### 9.4 安装 systemd 单元

```bash
sudo install -o root -g root -m 0644 \
  /opt/openresty-waf/deploy/openresty-waf@.service \
  /etc/systemd/system/openresty-waf@.service
sudo systemctl daemon-reload
```

SELinux 为 Enforcing 时，再按现场策略配置 `/opt/openresty-waf`、`/data/openresty-waf` 的文件上下文及监听端口。

### 9.5 启动

先启动黄端：

```bash
sudo systemctl enable --now openresty-waf@yellow
sudo systemctl status openresty-waf@yellow --no-pager
```

再启动蓝端：

```bash
sudo systemctl enable --now openresty-waf@blue
sudo systemctl status openresty-waf@blue --no-pager
```

## 10. 升级现有部署

本版本修改了 Lua、Nginx 模板、审计变量和日志格式，蓝、黄节点都要使用新部署包整体升级，不能只替换 `handler.lua` 或日志格式文件。

### 10.1 预装新版本

蓝、黄节点分别执行：

```bash
WAF_RELEASE_ID='填写发布编号'
WAF_RELEASE_DIR="/opt/openresty-waf-${WAF_RELEASE_ID}"
WAF_PACKAGE='/tmp/openresty-waf.tgz'

test ! -e "$WAF_RELEASE_DIR"
sudo install -d -o root -g nobody -m 0750 "$WAF_RELEASE_DIR"
sudo tar -xzf "$WAF_PACKAGE" --strip-components=1 -C "$WAF_RELEASE_DIR"
```

在新目录中：

1. 从新模板生成本节点 `.conf`；
2. 填写第 4、5 节的全部占位符；
3. 写入正式 `waf_rules.lua`；
4. 不要把旧版 Nginx 配置整体覆盖到新目录。

预检：

```bash
sudo PREFIX="$WAF_RELEASE_DIR" NODE_ROLE=yellow \
  bash "$WAF_RELEASE_DIR/scripts/server-setup.sh"

sudo PREFIX="$WAF_RELEASE_DIR" NODE_ROLE=blue \
  bash "$WAF_RELEASE_DIR/scripts/server-setup.sh"
```

每台服务器只执行与自身角色对应的命令。

### 10.2 备份

蓝、黄节点分别备份当前目录：

```bash
WAF_RELEASE_ID='填写发布编号'
WAF_NODE_ROLE='blue或yellow'

sudo tar -C /opt -czf \
  "/root/openresty-waf-before-${WAF_RELEASE_ID}-${WAF_NODE_ROLE}.tgz" \
  openresty-waf
```

### 10.3 切换顺序

1. 停止或摘除蓝 WAF，阻止新请求进入；
2. 停止黄 WAF，保存旧目录并切换黄端新目录；
3. 启动黄 WAF并检查；
4. 保存蓝端旧目录并切换蓝端新目录；
5. 启动蓝 WAF；
6. 完成第 11 节验证后恢复流量。

目录切换示例：

```bash
WAF_RELEASE_ID='填写发布编号'
WAF_RELEASE_DIR="/opt/openresty-waf-${WAF_RELEASE_ID}"
WAF_PREVIOUS_DIR="/opt/openresty-waf-prev-${WAF_RELEASE_ID}"

test ! -e "$WAF_PREVIOUS_DIR"
sudo mv /opt/openresty-waf "$WAF_PREVIOUS_DIR"
sudo mv "$WAF_RELEASE_DIR" /opt/openresty-waf
sudo install -o root -g root -m 0644 \
  /opt/openresty-waf/deploy/openresty-waf@.service \
  /etc/systemd/system/openresty-waf@.service
sudo systemctl daemon-reload
```

切换前由上面的顺序停止对应服务，切换后先黄后蓝启动。SELinux Enforcing 环境还要执行 `restorecon -Rv /opt/openresty-waf`。

### 10.4 回滚

发生异常时：

1. 先停止蓝端入口；
2. 停止蓝、黄 WAF；
3. 将失败的新目录改名保留；
4. 将对应 `openresty-waf-prev-*` 恢复为 `/opt/openresty-waf`；
5. 恢复 systemd 单元；
6. 先启动黄端，再启动蓝端；
7. 验证原业务恢复。

不要删除失败版本目录，保留日志和配置用于排查。

## 11. 配置与功能验证

规则检查：

```bash
/data/openresty/luajit/bin/luajit \
  /opt/openresty-waf/scripts/check_rules.lua \
  /opt/openresty-waf/conf/waf_rules.lua
```

黄端 Nginx 配置：

```bash
/data/openresty/bin/openresty \
  -p /opt/openresty-waf/ \
  -c conf/nginx-yellow.conf \
  -t
```

蓝端 Nginx 配置：

```bash
/data/openresty/bin/openresty \
  -p /opt/openresty-waf/ \
  -c conf/nginx-blue.conf \
  -t
```

主要验收用例：

| 用例 | 预期 |
|---|---|
| Host A + A 请求 | 只到达后端 A |
| Host B + B 请求 | 只到达后端 B |
| A 请求发送到 Host B | `400/422 request_body` |
| 未登记 Host | `444` |
| 未登记 method/path | `403 not_in_whitelist` |
| 任意 query string | `403 query_not_allowed` |
| 非 JSON 请求 | `415 unsupported_media_type` |
| 非法 JSON | `400 invalid_json` |
| 请求未知字段 | `400/422 request_body` |
| 未登记响应状态码 | `502 response_status_not_allowed` |
| 非 JSON 或非法响应 | `502` |
| 响应 schema 不匹配 | `502 response_body` |
| 请求/响应超限 | `413` 或 `502 response_body_too_large` |

正文日志验证：

```bash
sudo tail -n 1 /data/openresty-waf/audit/access.log
```

确认该行同时存在且内容正确：

```text
request_body
forward_body
response_body
forward_response_body
```

## 12. 常用操作

查看服务：

```bash
sudo systemctl status openresty-waf@yellow --no-pager
sudo systemctl status openresty-waf@blue --no-pager
```

重新加载：

```bash
sudo systemctl reload openresty-waf@yellow
sudo systemctl reload openresty-waf@blue
```

查看错误日志：

```bash
sudo tail -n 100 /data/openresty-waf/log/error.log
sudo journalctl -u openresty-waf@yellow -n 100 --no-pager
sudo journalctl -u openresty-waf@blue -n 100 --no-pager
```

修改规则时：

- 新增放行：先更新黄端并验证，再更新蓝端；
- 删除或收紧：先更新蓝端并验证拒绝，再更新黄端；
- 修改 Lua、Nginx 或审计配置：按第 10 节整体升级。

## 13. 上线检查

- [ ] 蓝、黄使用同一个部署包；
- [ ] 蓝、黄 `waf_rules.lua` SHA-256 一致；
- [ ] 所有 Nginx 占位符已替换；
- [ ] 正式规则不是空白名单；
- [ ] 规则检查为 `0 error`；
- [ ] 两端 OpenResty `-t` 成功；
- [ ] Host A/B 分别只到达对应后端；
- [ ] 未登记 Host、path、字段和状态码均被拒绝；
- [ ] 四个正文日志字段均有实际内容；
- [ ] 日志轮转、容量和留存已配置；
- [ ] 回滚目录和旧包可用。
