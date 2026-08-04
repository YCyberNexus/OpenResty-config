# OpenResty WAF 通用 V2

本仓库实现绿、蓝、黄目标架构中的七层 WAF。当前生产链路为：

```text
蓝区调用方 -> 10.64.5.4:80（蓝 WAF）
           -> 10.64.9.2:80（黄 WAF）
           -> 192.168.14.249:6789（黄区知识库）
```

V2 的目标是完成一次运行时升级。此后新增普通 HTTP API，只修改声明式配置、检查并重载，
不再改 Lua 或重新制作运行时代码包。

## 配置分层

| 文件 | 维护内容 | 新增接口时是否可能修改 |
|---|---|---|
| `conf/waf_rules.lua` | Host、method、路径、Query、请求头、正文和逐状态响应契约 | 是，必改 |
| `conf/waf_routes.lua` | 蓝/黄节点上 Host 到固定下一跳 IP、端口、上游 Host、超时档 | 仅新增 Host/后端时改 |
| `conf/waf_policies.lua` | 可复用认证门禁、超时档和内置业务策略 | 仅新增复用策略时改 |
| `lua/waf/*.lua`、`conf/nginx-*.conf` | V2 运行时 | 普通接口不改 |

三个配置必须作为一组通过检查，蓝、黄节点必须分发相同内容。路由地址只允许固定 IPv4，
不能从客户端 Host、路径或 Query 拼接，因此不会形成开放代理。

## 已内置的通用能力

- 精确 Host、method 和 path；支持多个命名路径参数，例如
  `/tenants/{tenant_id}/assets/{asset_id}`，每个参数分别配置 `uuid`、`slug`、`digits`、
  `enum` 等约束。
- Query 白名单、类型转换和规范化；支持 string、integer、number、boolean 及有界重复参数。
- 请求头白名单；未登记头会被清除，Host、Content-Length、Content-Type、trace 等保护头由 WAF
  重建。
- `network_only`、Bearer、API Key、Basic 凭证语法门禁。令牌真实性仍由后端校验。
- JSON、UTF-8 文本和有界二进制请求/响应。
- `buffered` 模式：在完整响应状态、媒体类型、大小和 schema 校验通过前不返回正文。
- `stream` 模式：用于大文件和 SSE；校验状态、媒体类型、响应头和字节上限，并流式计算响应
  SHA-256。落盘的大型上传为避免阻塞 worker，只记录请求大小和 `not_computed_stream_file`。
  该模式不能在发送前校验完整响应正文，必须逐接口显式启用。
- fast、standard、long 三档固定超时。
- 内置保守的 `cypher_read_only_v1` 策略；拒绝写入/管理关键字、`CALL`、多语句和无法安全
  解析的 Cypher。
- 每跳记录 rule、trace、原始/规范化 Query、正文大小与 SHA-256、固定下一跳、上游状态和
  响应审计信息。

技术硬上限：Query 32 KiB；buffered 请求/响应各 1 MiB；stream 请求 64 MiB；stream 响应
256 MiB。每条接口仍必须配置更小或相等的独立上限。

## 当前知识库白名单

活动 Host 只有 `kb.pxsemic.tech`：

```text
POST /ai/knowledge/search
GET  /ai/knowledge/assets/{asset_id}
GET  /ai/knowledge/health
POST /ai/knowledge/graph/query
GET  /ai/knowledge/graph/health
```

`asset_id` 必须是 UUID。图谱查询已引用 `cypher_read_only_v1`。`kb-1.pxsemic.tech` 只有固定
路由登记，没有接口规则，因此继续默认拒绝。

## 检查与测试

```bash
make lint
make test
git diff --check
```

也可显式检查三份配置：

```bash
luajit scripts/check_rules.lua \
  conf/waf_rules.lua conf/waf_routes.lua conf/waf_policies.lua
```

当前知识库契约存在 5 个已知 warning，来自接口文档明确声明为动态对象的 metadata、parameters
和图谱 rows；任何新增 error 或非预期 warning 都不能上线。

## 部署原则

第一次升级到 V2 必须在蓝、黄节点整体替换运行包，先黄后蓝。之后新增普通接口时，只分发实际
修改的三份配置之一或多份，并依次执行配置体检、`openresty -t`、reload 和正反向验收。

详细配置示例、配置变更矩阵、升级和回滚命令见
[`docs/WAF部署配置与升级手册.md`](docs/WAF部署配置与升级手册.md)。当前知识库上线步骤见
[`docs/BY-002图谱增强检索运维配置说明.md`](docs/BY-002图谱增强检索运维配置说明.md)。

## 边界

本项目不替代防火墙/ACL、EDR、DLP、AD、Jumpserver、VDI 或日志转储平台。四层来源限制、
目标端口、账号权限、真实令牌校验、限流和日志留存仍需由对应设施落实。自定义签名算法、未知
业务语义、WebSocket 或超过当前硬上限的传输不应伪装成普通配置项，需要单独评审运行时扩展。
