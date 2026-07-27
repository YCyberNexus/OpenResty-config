# 蓝区 → 黄区双 WAF 白名单网关

本仓库提供公司三区架构中的通用七层 WAF 能力。固定网络路径是：

```text
蓝区调用方 → 蓝区 WAF →（mTLS，WAF-to-WAF）→ 黄区 WAF → 黄区已审批目标服务
```

WAF 核心不内置任何业务 URL。具体允许的 Host、method、path、请求体 schema、响应状态码和响应体 schema，全部由运维维护的 [conf/waf_rules.lua](conf/waf_rules.lua) 决定。两侧加载同一审批版本，未登记项默认拒绝。

## 安全默认值

仓库中的活动规则初始为空白名单：

```text
version   = UNCONFIGURED-DENY-ALL
whitelist = {}
```

因此代码或安装包不会自动放行知识库接口或其它 URL。生产模板还会拒绝 `UNCONFIGURED`/示例规则启动；运维完成审批并配置正式规则后才会出现业务放行项。

用户提供的知识库接口被保留为[运维规则示例](conf/waf_rules_knowledge_example.lua)，不会被生产模板加载。接口来源见[知识库接口文档](docs/知识库接口文档.md)。

## 通用能力

- 精确 Host、method 和 path 白名单；当前版本所有 query string 均拒绝。
- 请求和响应分别绑定严格 JSON schema，object 未知字段默认拒绝。
- 支持类型、required、长度、字节数、数值范围、数组数量、enum、prefix、UUID 和安全路径等通用约束。
- 未登记响应状态、非 JSON、非法 JSON、超限或 schema 不匹配响应统一替换为不含上游正文的 `502`。
- 蓝 WAF 到黄 WAF 强制 mTLS；黄 WAF 同时校验证书链和运维登记的客户端 Subject DN。
- 请求和响应在校验通过后都规范化为单一 JSON 语义再传递；转发请求不继承原始请求头，只重建必要字段。
- 蓝、黄两侧分别把每条 HTTP 请求持久化为 JSON Lines。

## 审计位置

```text
/data/openresty-waf/blue/audit/access.log
/data/openresty-waf/yellow/audit/access.log
```

审计包含 trace/request ID、节点、mTLS 身份、method、path、rule ID、规则版本、方向、审批编号、动作、原因、状态、耗时，以及收到的请求、规范化转发体、收到的上游响应和实际返回体的大小与 SHA-256；不保存 query string 或请求/响应正文。

## 运维配置流程

1. 根据审批台账编写 `conf/waf_rules.lua`，或以知识库示例为起点。
2. 设置 `example=false`、唯一 `version`、明确 `direction` 和稳定 rule ID。
3. 执行 `luajit scripts/check_rules.lua --production conf/waf_rules.lua`。
4. 将同一文件同步到蓝、黄两侧，并核对 SHA-256。
5. 渲染蓝/黄 nginx 模板中的地址、证书身份、目标服务和审批编号。
6. 运行 `scripts/server-setup.sh`；脚本会再次检查规则、占位符和 OpenResty 配置。

完整格式、部署和验收要求见[双 WAF 白名单链路部署说明](docs/双WAF白名单链路部署说明.md)。

## 本地验证

```bash
make lint   # 检查活动规则；初始空白名单会产生一条“全部拒绝” warning
make test
```

安装 OpenResty 后，以下命令会显式加载知识库示例规则和本地 stub，仅用于演示通用能力：

```bash
make serve
make smoke
make stop
```

## 核心目录

```text
conf/waf_rules.lua                       运维活动规则，默认空白名单
conf/waf_rules_knowledge_example.lua     不自动生效的知识库规则示例
lua/waf/decision.lua                     Host/header/URL/request/response 决策链
lua/waf/json_validator.lua               通用严格 JSON 校验器
lua/waf/handler.lua                      OpenResty IO、受控代理与审计摘要
conf/nginx-*.conf.template               蓝/黄生产节点 mTLS 模板
spec/                                    通用能力和示例配置测试
```

本仓库只实现七层 WAF，不替代 EDR、AC、防火墙、DLP、ODCP、AD、Jumpserver、VDI 或日志平台，也不授权黄区外网、服务器直连或绕过两侧 WAF 的路径。
