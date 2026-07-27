# WAF 规则配置指南

活动规则文件是 `conf/waf_rules.lua`，由运维维护。蓝、黄两侧必须发布同一审批版本并核对 SHA-256；方向由对应白名单台账明确配置，WAF 核心不绑定具体方向或业务 URL。仓库默认白名单为空，所有业务请求都会拒绝。

## 一条规则必须包含

```lua
{
  id = "审批台账中的稳定规则 ID",
  methods = { "POST" },
  path = "/精确/path",
  request_schema = "请求_schema",       -- 允许 JSON 正文时配置；不配则正文一律禁止
  response_schemas = {
    ["200"] = "成功响应_schema",
    ["422"] = "错误响应_schema",
  },
}
```

- `id` 稳定且唯一，关联白名单台账。
- `methods` 不得省略，不得用小写。
- `path` 只允许精确路径；跨区白名单禁止正则。
- 当前版本不放行 query string，也不接受 `allow_query=true`；需要 query 的接口必须先补参数级通用校验能力。
- 是否允许正文由 `request_schema` 显式决定，与 HTTP 方法无关；不配置即禁止正文。
- 请求和响应 JSON 通过校验后均由 WAF 重新编码再传递，避免重复字段在不同解析器中产生歧义；审计分别记录收到的正文与规范化输出的大小和 SHA-256。
- 每个允许的响应状态必须显式绑定 schema；没有通配状态。

## Schema 口径

所有 object（包括嵌套 object）必须：

```lua
{
  type = "object",
  additional_properties = false,
  required = { "field" },
  properties = {
    field = { type = "string", min_length = 1, max_length = 100 },
  },
}
```

支持 `object`、`array`、`string`、`integer`、`number`、`boolean`、`null`，以及长度、字节数、数值范围、数组数量、枚举、prefix 和通用格式。WAF 核心不接受业务专用 `contract` 钩子；复杂业务关系不得以代码硬编码方式混入通用网关。

正式规则还必须设置 `example=false`，并使用审批后的唯一 `version` 和 `direction`。修改规则前必须先补白名单台账中的方向、Host、身份、协议端口、字段、上限、审计、owner、审批、验证和回滚。修改后执行：

```bash
luajit scripts/check_rules.lua --production conf/waf_rules.lua
make test
```

部署时两端核对规则版本和 SHA-256，再依次执行 `openresty -t`，先黄端再蓝端灰度 reload，并跑与本次运维规则对应的放行与拒绝用例。任一端不一致时停止发布，不临时放宽旧端规则。
