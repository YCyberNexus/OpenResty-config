# 蓝区 → 黄区双 WAF 白名单链路部署说明

## 1. 能力边界

本仓库提供通用七层白名单能力，不在程序代码中决定任何业务 URL。流量路径固定为：

```text
蓝区调用方
  → 蓝区 WAF（运维白名单 + 请求/响应 schema + 本地审计）
  → mTLS WAF-to-WAF
  → 黄区 WAF（客户端身份 + 同版本白名单 + 请求/响应 schema + 本地审计）
  → 黄区已审批目标服务
```

具体放行的 Host、method、path、请求 schema、允许响应状态和响应 schema，全部由运维在
`conf/waf_rules.lua` 中配置。两侧 WAF 加载同一份活动规则；未登记项默认拒绝。

仓库自带的活动配置是空白名单：

```text
version   = UNCONFIGURED-DENY-ALL
whitelist = {}
```

生产模板会以 `production=true` 加载规则，`UNCONFIGURED` 或示例规则会使 `openresty -t`/启动直接失败；在非生产模式读取空白名单时也只会全部拒绝，不会自动放行任何接口。

## 2. 规则文件职责

| 文件 | 用途 | 是否由生产模板加载 |
|---|---|---:|
| `conf/waf_rules.lua` | 运维维护的活动规则 | 是 |
| `conf/waf_rules_knowledge_example.lua` | 根据用户提供接口文档整理的知识库示例 | 否 |
| `docs/知识库接口文档.md` | 示例的契约来源 | 否 |

知识库示例仅帮助运维起草规则，不代表审批完成，也不会被打包部署过程自动激活。若需要使用，运维应先复制为活动规则、完成评审，并修改 `version` 为审批后的唯一版本：

```bash
cp conf/waf_rules_knowledge_example.lua conf/waf_rules.lua
vi conf/waf_rules.lua
luajit scripts/check_rules.lua --production conf/waf_rules.lua
```

## 3. 每条 URL 必须配置的内容

规则采用精确 method + path，不允许生产白名单使用正则 URL：

```lua
return {
  version = "CHANGE-2026-001",
  direction = "blue_to_yellow",
  example = false,
  max_request_body_bytes = 16384,
  max_response_body_bytes = 4194304,

  whitelist = {
    {
      id = "APP-001",
      methods = { "POST" },
      path = "/approved/path",
      request_schema = "approved_request",
      response_schemas = {
        ["200"] = "approved_response",
        ["422"] = "approved_error",
      },
    },
  },

  blacklist = { { pattern = "^/_waf_" } },
  forbidden_headers = {
    "content-encoding",
    "x-http-method-override",
    "x-original-url",
  },
  schemas = {
    approved_request = {
      type = "object",
      additional_properties = false,
      required = { "query" },
      properties = {
        query = { type = "string", min_length = 1, max_length = 4000 },
      },
    },
    approved_response = {
      type = "object",
      additional_properties = false,
      required = { "result" },
      properties = {
        result = { type = "string", max_length = 8192 },
      },
    },
    approved_error = {
      type = "object",
      additional_properties = false,
      required = { "detail" },
      properties = {
        detail = { type = "string", max_length = 1024 },
      },
    },
  },
}
```

配置要求：

1. `version` 每次规则变更都必须更新，并关联审批单。
2. 正式规则必须设置 `example=false`；示例或 `UNCONFIGURED` 版本不能通过生产检查。
3. `direction` 必须来自白名单台账，不自动推导反向权限。
4. 每条规则必须有稳定唯一的 `id`、精确 `path` 和方法数组。
5. 需要 JSON 正文的规则必须绑定请求 schema；未绑定即禁止正文，不根据 HTTP 方法猜测。
6. 每条 URL 必须按状态码显式绑定响应 schema，未登记状态码直接拒绝。
7. object 必须配置 `additional_properties=false`，未知字段不能透传。
8. 当前版本禁止所有 query string，也不接受 `allow_query=true`；需要 query 的接口应先补参数级通用校验能力。
9. 大小、长度、范围、枚举及格式限制必须来源于接口契约或审批结论。

当前代理支持 `GET`、`POST`、`PUT`、`PATCH` 和 `DELETE`。其它方法在增加相应正文/响应语义与测试前不得写入生产规则。

通用校验器支持 object、array、string、integer、number、boolean、null，以及 required、字段白名单、长度/字节数、数值范围、数组数量、enum、prefix 和通用格式。WAF 核心不再包含知识库专用跨字段代码；复杂业务关系应由应用契约、专用内容安全能力或经评审的后续通用规则能力处理，不能隐式写死在 WAF 中。

## 4. 双端一致性门禁

规则生效前必须在蓝、黄两侧分别执行：

```bash
/usr/local/openresty/luajit/bin/luajit scripts/check_rules.lua --production conf/waf_rules.lua
sha256sum conf/waf_rules.lua
```

两侧必须满足：

- 规则检查 `0 error`。
- `example=false`，且版本/方向不是 `UNCONFIGURED` 或示例值。
- `version`、`direction`、规则清单一致。
- `conf/waf_rules.lua` SHA-256 完全相同。
- 规则版本与 `__WAF_RULE_APPROVAL_ID__` 指向同一审批记录。

空白名单的 warning 表示所有业务请求均会拒绝，是安全默认状态，不是 fail-open。

## 5. 配置两个节点

蓝区模板需要运维填写：

- `__BLUE_WAF_LISTEN_IP__`、`__BLUE_WAF_LISTEN_PORT__`
- `__BLUE_WAF_HOST__`
- `__YELLOW_WAF_IP__`、`__YELLOW_WAF_PORT__`
- `__YELLOW_WAF_HOST__`、`__YELLOW_WAF_TLS_NAME__`
- `__WAF_RULE_APPROVAL_ID__`
- 蓝 WAF 客户端证书、私钥和黄 WAF 服务端 CA

黄区模板需要运维填写：

- `__YELLOW_WAF_LISTEN_IP__`、`__YELLOW_WAF_PORT__`
- `__YELLOW_WAF_HOST__`
- `__BLUE_WAF_CLIENT_SUBJECT_DN__`
- `__PROTECTED_SERVICE_IP__`、`__PROTECTED_SERVICE_PORT__`
- `__PROTECTED_SERVICE_SCHEME__`、`__PROTECTED_SERVICE_HOST__`
- `__WAF_RULE_APPROVAL_ID__`
- 黄 WAF 服务端证书、私钥和蓝 WAF 客户端 CA

黄区到目标服务若使用 HTTPS，必须额外配置 `proxy_ssl_verify on`、受信 CA 和证书名称，不得关闭证书校验。

配置流程：

```bash
cd /opt/openresty-waf
cp conf/nginx-blue.conf.template conf/nginx-blue.conf       # 蓝区节点
cp conf/nginx-yellow.conf.template conf/nginx-yellow.conf   # 黄区节点
# 仅在对应节点保留并渲染需要的文件
sudo NODE_ROLE=blue bash scripts/server-setup.sh
sudo NODE_ROLE=yellow bash scripts/server-setup.sh
```

`server-setup.sh` 会拒绝仍含占位符的 nginx 配置，以生产模式检查活动规则，打印规则 SHA-256，并运行 `openresty -t`。生产 nginx 模板自身也会再次拒绝未配置或示例规则。

## 6. mTLS 与最小网络放行

| 方向 | 允许目标 | 要求 |
|---|---|---|
| 蓝区调用方 → 蓝 WAF | 蓝 WAF 已审批监听地址 | 来源范围由运维台账配置 |
| 蓝 WAF → 黄 WAF | 黄 WAF mTLS 业务端口 | 仅蓝 WAF 来源，验证服务端证书 |
| 黄 WAF → 黄区目标服务 | 已登记服务地址/端口 | 仅黄 WAF 来源，不允许蓝区直连 |

黄 WAF 强制验证客户端证书链和审批登记的 Subject DN。响应沿原连接返回不等于开放黄区主动访问蓝区，不得新增反向白名单、黄区外网或旁路直连。

## 7. 请求与响应处理

两侧 WAF 都会：

- 精确校验 Host、method、path、query 和禁止请求头。
- 完整读取并解析登记为 JSON 的请求正文。
- 将校验通过的 JSON 重新编码为单一语义再转发，消除重复 object key 等解析歧义。
- 关闭原始请求头继承，只重建 Host、Content-Type、Content-Length、Accept 和 trace ID。
- 完整缓存上游响应，按 URL + 状态码选择 schema。
- 将校验通过的响应 JSON 重新编码后再返回，调用方不会收到含重复 object key 的原始上游字节。
- 将非 JSON、非法 JSON、超限、未知状态或 schema 不匹配响应替换为通用 `502`，不回显原始正文。

请求上限和响应上限属于规则配置的一部分。响应完整缓存会占用 worker 内存，上线前必须结合并发和 QPS 评估。

## 8. 本地持久化审计

```text
/data/openresty-waf/blue/audit/access.log
/data/openresty-waf/yellow/audit/access.log
```

审计记录包含本地 request ID、跨端 trace ID、节点角色、mTLS 身份、Host、method、path、rule ID、规则版本、方向、审批编号、动作、原因、状态、耗时，以及以下四组摘要：收到的请求正文、规范化转发体、收到的上游响应、实际返回体。每组只记录大小和 SHA-256。

结构化审计不记录 query string、请求正文或响应正文。蓝区和黄区错误 Host 的 HTTP 请求分别写入各自的 `audit/rejected.log`；黄区在 HTTP 形成前失败的 SNI/mTLS 握手记录于 `yellow/log/error.log`。

上线前仍须配置日志留存期、轮转、磁盘告警和防篡改转储。

## 9. 上线验收

- 活动规则只包含本次审批的 method + path，不包含示例遗留 URL。
- 蓝、黄两侧规则版本和 SHA-256 一致。
- 合法请求与合法响应可经过两侧 WAF。
- 未登记 Host、method、path、query、字段、状态码和错误类型均被拒绝。
- 伪造或未登记客户端证书不能连接黄 WAF。
- 停止任一 WAF 后，业务服务器不能旁路访问黄区目标服务。
- 同一 trace ID 可在两侧本地审计中关联。
- 日志不包含业务正文或凭据。
- 已验证回滚不会恢复过期白名单。

若规则涉及黄区数据出区，还必须独立完成数据分级、脱敏、DLP 和内容审批。JSON schema 只能验证结构，不能证明正文不含 K3、密钥或凭据。
