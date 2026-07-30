# 多黄区目标同路径异构接口 WAF 配置与上线手册

## 1. 当前结论

WAF 已支持以下场景：

```text
服务 A Host + POST /ai/knowledge/search
  → 请求 schema A
  → 黄区目标 A
  → 按状态码校验响应 schema A

服务 B Host + POST /ai/knowledge/search
  → 请求 schema B
  → 黄区目标 B
  → 按状态码校验响应 schema B
```

规则唯一键已由 `method + path` 改为：

```text
host + method + path
```

不同 Host 可以配置相同 method/path，并使用完全不同的请求和响应 schema；相同 Host/method/path 仍禁止重复。

当前生产活动文件 `conf/waf_rules.lua` 仍为空白名单，不会自动放行任何 Host 或接口。

已上传的知识库接口文档只能确定其中一个服务的契约。第二个服务的真实请求字段、响应字段、状态码和大小限制尚未提供，因此运维不得直接用仓库中的演示字段生产放行。

## 2. 目标链路

本文按“一个蓝 WAF、一个黄 WAF、两个黄区固定业务目标”设计：

```text
                                      ┌→ 192.168.14.249:6789
调用方 → 蓝 WAF → HTTP → 黄 WAF ─────┤
                                      └→ 192.168.14.250:6789
```

调用方通过两个已登记服务 Host 选择目标。例如：

```text
knowledge-a.waf.internal → 192.168.14.249:6789
knowledge-b.waf.internal → 192.168.14.250:6789
```

以上 Host 只是示例。生产 Host、DNS、IP、端口及角色必须由现场确认。

同一个服务 Host 从调用方保持到蓝 WAF和黄 WAF：

1. 调用方请求服务 A Host；
2. 蓝 WAF 使用 Host A 选择规则 A，并保持 Host A 转发到黄 WAF；
3. 黄 WAF再次使用 Host A 选择规则 A；
4. 黄 WAF的 Host A 虚拟主机固定代理到目标 A；
5. 黄 WAF先校验目标 A 响应，再返回蓝 WAF；
6. 蓝 WAF再次校验同一响应后返回调用方。

Host 只用于规则和静态路由选择，不是身份认证。四层来源限制仍然必须独立验收。

### 2.1 原完整 URL 应拆到哪里

以用户给出的两个地址为例：

| 原地址部分 | 配置位置 |
|---|---|
| `192.168.14.249:6789` | 黄 WAF 模板的目标 A IP/端口 |
| `192.168.14.250:6789` | 黄 WAF 模板的目标 B IP/端口 |
| `/ai/knowledge/search` | 两条规则各自的 `path` |
| 服务 A/B 的受控业务 Host | 两条规则各自的 `host`，以及蓝、黄 WAF 的 `server_name` |

`path` 仍然不能填写完整 URL。目标 IP/端口只存在于黄 WAF 的固定 upstream 中；规则用 Host 区分同路径接口。这样请求不能通过正文、query 或任意目标 URL 改写 upstream。

DNS 尚未建立时，可在验收机上临时使用 `--resolve` 验证，但正式调用应由 DNS 将两个业务 Host 都解析到蓝 WAF：

```bash
curl --resolve knowledge-a.waf.internal:蓝WAF端口:蓝WAF_IP \
  http://knowledge-a.waf.internal:蓝WAF端口/ai/knowledge/search \
  -H 'Content-Type: application/json' -d '{"query":"测试","top_k":5}'

curl --resolve knowledge-b.waf.internal:蓝WAF端口:蓝WAF_IP \
  http://knowledge-b.waf.internal:蓝WAF端口/ai/knowledge/search \
  -H 'Content-Type: application/json' -d '按服务B真实契约填写'
```

这里的两个 Host 只能命中模板中预先登记的两个固定目标，不是开放式代理。

## 3. 涉及文件

### 3.1 仓库文件

| 文件 | 用途 |
|---|---|
| `conf/waf_rules.lua` | 生产活动规则，默认空白名单 |
| `conf/waf_rules_same_path_example.lua` | 两个 Host 同路径、不同请求/响应契约的最小演示 |
| `conf/waf_rules_knowledge_example.lua` | 已上传知识库文档对应的本地示例 |
| `conf/nginx-blue.conf.template` | 蓝 WAF 双 Host 入口模板 |
| `conf/nginx-yellow.conf.template` | 黄 WAF 双固定目标模板 |
| `conf/waf-public-location.conf` | 请求校验及响应捕获入口 |
| `conf/waf-internal-proxy-common.conf` | 内部固定 upstream 请求重建 |
| `lua/waf/url_filter.lua` | Host/method/path 精确匹配 |
| `lua/waf/handler.lua` | 请求校验、内部代理、响应校验 |
| `lua/waf/rules_lint.lua` | Host、请求/响应 schema 和大小静态检查 |

### 3.2 服务器生效文件

| 节点 | 文件 |
|---|---|
| 蓝 WAF | `/opt/openresty-waf/conf/nginx-blue.conf` |
| 黄 WAF | `/opt/openresty-waf/conf/nginx-yellow.conf` |
| 蓝、黄 WAF | `/opt/openresty-waf/conf/waf_rules.lua`，必须一致 |
| 蓝、黄 WAF | `/opt/openresty-waf/lua/waf/*.lua`，必须同版本 |

systemd 加载 `.conf`，不直接加载 `.template`。仓库模板和服务器渲染文件必须同步维护。

## 4. 两个同路径接口的规则结构

以下结构说明如何区分两个接口；字段名称和状态码必须替换为两个真实接口契约：

```lua
return {
  max_request_body_bytes = 16384,
  max_response_body_bytes = 1048576,

  whitelist = {
    {
      id = "SERVICE-A-SEARCH",
      host = "knowledge-a.waf.internal",
      methods = { "POST" },
      path = "/ai/knowledge/search",
      request_schema = "service_a_request",
      responses = {
        [200] = { schema = "service_a_success_response", max_body_bytes = 65536 },
        [422] = { schema = "service_a_error_response", max_body_bytes = 16384 },
      },
    },
    {
      id = "SERVICE-B-SEARCH",
      host = "knowledge-b.waf.internal",
      methods = { "POST" },
      path = "/ai/knowledge/search",
      request_schema = "service_b_request",
      responses = {
        [200] = { schema = "service_b_success_response", max_body_bytes = 65536 },
        [400] = { schema = "service_b_error_response", max_body_bytes = 16384 },
      },
    },
  },

  schemas = {
    service_a_request = {
      -- 按服务 A 请求文档填写
    },
    service_a_success_response = {
      -- 按服务 A 的 200 响应文档填写
    },
    service_a_error_response = {
      -- 按服务 A 的错误响应文档填写
    },
    service_b_request = {
      -- 按服务 B 请求文档填写
    },
    service_b_success_response = {
      -- 按服务 B 的 200 响应文档填写
    },
    service_b_error_response = {
      -- 按服务 B 的错误响应文档填写
    },
  },
}
```

上例状态码和大小仅说明配置结构，不能直接作为生产值。可运行的演示配置见 `conf/waf_rules_same_path_example.lua`。

## 5. 响应校验行为

上游响应不再直接透传。WAF 通过 internal 子请求取得完整响应，并在返回任何响应正文前执行：

1. 检查实际 HTTP 状态码是否在当前 Host 规则中登记；
2. 检查响应没有超过该状态码的 `max_body_bytes`；
3. 检查响应没有超过 1 MiB 技术上限；
4. 只接受 `application/json`；
5. 拒绝 gzip 等压缩响应；
6. 解析 JSON；
7. 按当前 Host、状态码关联的 schema 校验字段、类型和限制；
8. 重新编码为规范化 JSON；
9. 只记录大小、SHA-256、schema、状态和拒绝原因，不记录原文。

主要拒绝原因：

| 原因 | 含义 |
|---|---|
| `response_status_not_allowed` | 状态码未登记 |
| `upstream_capture_failed` | 内部代理失败 |
| `response_body_too_large` | 超过规则或全局上限 |
| `response_unsupported_media_type` | 不是 JSON 响应 |
| `response_content_encoding_not_allowed` | 上游返回压缩响应 |
| `invalid_upstream_json` | JSON 无法解析 |
| `response_body` | 响应不符合当前 schema |

响应校验失败统一返回网关 `502`，不会将原始上游正文回显给调用方。

当前实现不支持 SSE、流式响应、文件下载或压缩响应，这些类型默认不放行。

## 6. 蓝 WAF 模板

`conf/nginx-blue.conf.template` 需要替换：

```text
__BLUE_WAF_LISTEN_IP__
__BLUE_WAF_LISTEN_PORT__
__WAF_SERVICE_HOST_A__
__WAF_SERVICE_HOST_B__
__YELLOW_WAF_IP__
__YELLOW_WAF_PORT__
```

蓝 WAF 的两个 `server_name` 必须与两条规则的 `host` 完全一致。蓝 WAF只连接一个已登记的黄 WAF IP/端口，并使用：

```nginx
proxy_set_header Host $host;
```

将已校验的服务 Host 保持到黄 WAF。

## 7. 黄 WAF 模板

`conf/nginx-yellow.conf.template` 需要替换：

```text
__YELLOW_WAF_LISTEN_IP__
__YELLOW_WAF_PORT__
__WAF_SERVICE_HOST_A__
__WAF_SERVICE_HOST_B__
__PROTECTED_SERVICE_A_IP__
__PROTECTED_SERVICE_A_PORT__
__PROTECTED_SERVICE_A_HOST__
__PROTECTED_SERVICE_B_IP__
__PROTECTED_SERVICE_B_PORT__
__PROTECTED_SERVICE_B_HOST__
```

模板中：

```text
Host A → protected_backend_a
Host B → protected_backend_b
```

是固定映射。不得允许调用方通过 Header、query string 或请求体自由传入目标 URL、IP、端口或 upstream 名称。

只有目标服务确认接受 IP Host 时，`__PROTECTED_SERVICE_A_HOST__`、`__PROTECTED_SERVICE_B_HOST__` 才能填写 IP；否则必须填写业务服务实际要求的 Host。

## 8. 上线前必须收齐

两个服务分别提供：

- 正式服务 Host；
- 目标地址、端口和后端 Host；
- 请求 method、path、Content-Type；
- 请求字段、类型、必填项和限制；
- 最大请求体；
- 全部成功和错误状态码；
- 每个状态码对应的响应字段和限制；
- 每个状态码的最大响应体；
- 敏感字段和跨区返回审批；
- QPS、超时、owner、有效期和回滚窗口。

缺少任一服务的真实契约时，只能运行 deny-all 或开发测试配置，不能生产放行。

## 9. 检查和发布

### 9.1 检查占位符

```bash
cd /opt/openresty-waf
grep -En '__[A-Z0-9_]+__' conf/nginx-yellow.conf
grep -En '__[A-Z0-9_]+__' conf/nginx-blue.conf
```

命令必须无输出。

### 9.2 检查规则

```bash
/data/openresty/luajit/bin/luajit scripts/check_rules.lua conf/waf_rules.lua
```

必须为 `0 error`，并逐条核对输出中的 Host、method、path、request schema 和 responses 状态码。

### 9.3 检查 OpenResty

黄 WAF：

```bash
/data/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx-yellow.conf -t
```

蓝 WAF：

```bash
/data/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx-blue.conf -t
```

### 9.4 发布顺序

先黄 WAF、后蓝 WAF：

```bash
sudo systemctl reload openresty-waf@yellow
sudo systemctl reload openresty-waf@blue
```

命令应分别在对应节点执行。每次 reload 前必须通过本机配置检查。

## 10. 验收用例

必须执行：

| 用例 | 预期 |
|---|---|
| A Host + A 请求 + A 响应 | 放行，目标为 A |
| B Host + B 请求 + B 响应 | 放行，目标为 B |
| A 请求发送到 B Host | 请求 schema 拒绝 |
| B 请求发送到 A Host | 请求 schema 拒绝 |
| A 返回 B 响应结构 | `502 response_body` |
| B 返回 A 响应结构 | `502 response_body` |
| 未登记 Host | `444` 或 `403`，取决于是否命中业务虚拟主机 |
| 未登记 method/path | `403 not_in_whitelist` |
| 未登记响应状态码 | `502 response_status_not_allowed` |
| 非 JSON 或压缩响应 | `502` 对应响应拒绝原因 |
| 超大响应 | `502 response_body_too_large` |
| 蓝区调用方直连目标 A/B | 四层拒绝 |
| 未登记来源访问黄 WAF | 四层拒绝 |
| 绕过蓝 WAF 访问黄 WAF | 四层拒绝 |

异常响应测试应通过测试桩或业务方测试环境完成，不得在生产服务中临时注入。

## 11. 审计

日志位置：

```text
/data/openresty-waf/audit/access.log
/data/openresty-waf/audit/rejected.log
```

至少核对：

```text
node_role
trace_id
remote_addr
request_host
method
path
rule_id
action
reason
request_body_bytes
request_body_sha256
upstream_addr
upstream_status
response_schema
response_body_bytes
response_body_sha256
forward_response_bytes
forward_response_sha256
```

日志不得包含请求、响应或 query string 原文。响应 schema 只能约束结构，不能自动判断 `content`、`metadata` 中是否包含 K3 数据。

## 12. 回滚

本次变更同时涉及 Lua、规则、Nginx 模板和审计配置，必须按完整版本包回滚，不能只恢复某一个文件。

安全回滚顺序：

1. 先停止蓝 WAF新增入口或恢复蓝端上一完整版本；
2. 检查蓝端配置并 reload；
3. 再恢复黄端上一完整版本；
4. 检查黄端配置并 reload；
5. 验证新增 Host 不再可达；
6. 最后由网络管理员回滚新增四层 ACL。

禁止通过关闭 WAF、放宽 schema、允许未知字段或开放直连完成故障绕行。
