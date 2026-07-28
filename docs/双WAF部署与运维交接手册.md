# 双 WAF 简化部署与运维手册

## 1. 当前方案

```text
蓝区调用方 → 蓝区 WAF → HTTP → 黄区 WAF → 黄区目标服务
```

用户于 2026-07-28 确认：蓝、黄两台服务器之间已通过四层网络策略限制为双方登记的 IP 和端口互访。当前阶段不使用 mTLS，也不配置证书。

七层 WAF 只做：

- 精确 `method + path` 白名单；
- 拒绝 query string；
- JSON 请求体大小、字段和类型过滤；
- 请求审计。

响应由 Nginx 直接透传，不做状态码或响应体过滤。四层限制是本方案的前置条件，WAF 不替代防火墙，也不能证明四层策略已经在现网正确落地。

## 2. 部署前需要确认

仓库不会猜测以下现场值：

| 节点 | 必填信息 |
|---|---|
| 蓝 WAF | 监听 IP、监听端口、业务 Host |
| 蓝 → 黄 | 黄 WAF IP、端口、Host |
| 黄 WAF | 监听 IP、监听端口、业务 Host |
| 黄 → 服务 | 目标服务 IP、端口、Host |
| 四层策略 | 源 IP、目标 IP、方向、端口、拒绝其它来源的验证记录 |
| 七层规则 | rule ID、method、精确 path、请求字段和大小限制 |
| 运维 | 日志留存、验证用例、回滚文件和负责人 |

本模板当前使用 HTTP。若以后需要恢复 TLS，应单独设计并验收，不要在模板中临时加入 `verify off` 一类配置。

## 3. 配置请求白名单

编辑 `conf/waf_rules.lua`：

```lua
return {
  max_request_body_bytes = 16384,
  whitelist = {
    {
      id = "RULE-001",
      methods = { "GET" },
      path = "/health",
    },
    {
      id = "RULE-002",
      methods = { "POST" },
      path = "/search",
      request_schema = "search_request",
    },
  },
  schemas = {
    search_request = {
      type = "object",
      additional_properties = false,
      required = { "query" },
      properties = {
        query = { type = "string", min_length = 1, max_length = 1000 },
      },
    },
  },
}
```

不再配置 `version`、`direction`、`example` 或 `response_schemas`。详细字段见《WAF规则配置指南》。

检查规则：

```bash
cd /opt/openresty-waf
/data/openresty/luajit/bin/luajit scripts/check_rules.lua conf/waf_rules.lua
sha256sum conf/waf_rules.lua
```

蓝、黄两侧规则文件必须完全相同。空白名单允许通过静态检查，但会输出 warning，并拒绝全部业务请求。

## 4. 渲染节点配置

### 4.1 黄区

```bash
cd /opt/openresty-waf
cp conf/nginx-yellow.conf.template conf/nginx-yellow.conf
vi conf/nginx-yellow.conf
```

替换：

- `__YELLOW_WAF_LISTEN_IP__`
- `__YELLOW_WAF_PORT__`
- `__YELLOW_WAF_HOST__`
- `__PROTECTED_SERVICE_IP__`
- `__PROTECTED_SERVICE_PORT__`
- `__PROTECTED_SERVICE_HOST__`

### 4.2 蓝区

```bash
cd /opt/openresty-waf
cp conf/nginx-blue.conf.template conf/nginx-blue.conf
vi conf/nginx-blue.conf
```

替换：

- `__BLUE_WAF_LISTEN_IP__`
- `__BLUE_WAF_LISTEN_PORT__`
- `__BLUE_WAF_HOST__`
- `__YELLOW_WAF_IP__`
- `__YELLOW_WAF_PORT__`
- `__YELLOW_WAF_HOST__`

确认没有遗漏占位符：

```bash
grep -R -nE '__[A-Z0-9_]+__' conf/nginx-blue.conf conf/nginx-yellow.conf
```

命令无输出才可继续。

## 5. 安装目录与权限

首次部署：

```bash
mkdir -p /opt
tar -xzf /tmp/openresty-waf.tgz -C /opt
cd /opt/openresty-waf
```

分别在对应节点执行：

```bash
sudo NODE_ROLE=yellow bash scripts/server-setup.sh
sudo NODE_ROLE=blue bash scripts/server-setup.sh
```

脚本会创建：

```text
/data/openresty-waf/audit/access.log
/data/openresty-waf/audit/rejected.log
/data/openresty-waf/log/error.log
```

并检查规则、模板占位符和 OpenResty 配置。

## 6. 四层策略验收

启用七层服务前必须在现场确认：

1. 蓝 WAF 只能连接登记的黄 WAF IP/端口。
2. 黄 WAF 的监听端口只接受登记的蓝 WAF 来源。
3. 黄区目标服务只接受黄 WAF 或本机登记来源。
4. 其它蓝区、黄区主机访问上述端口应失败。
5. 不存在绕过蓝 WAF 或黄 WAF 直达目标服务的路径。

具体 IP、网段和端口不在仓库中，不得从模板占位符推断。

## 7. 配置检查与启动

黄端：

```bash
/data/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx-yellow.conf -t
sudo systemctl enable --now openresty-waf@yellow
```

蓝端：

```bash
/data/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx-blue.conf -t
sudo systemctl enable --now openresty-waf@blue
```

启动顺序为黄端先、蓝端后。变更 reload 同样先黄后蓝。

## 8. 验收用例

至少验证：

| 用例 | 预期 |
|---|---|
| 已登记 method/path + 合法请求体 | 放行并到达目标服务 |
| 未登记 path | `403 not_in_whitelist` |
| 错误 method | `403 not_in_whitelist` |
| 任意 query string | `403 query_not_allowed` |
| 非 JSON 请求体 | `415 unsupported_media_type` |
| 非法 JSON | `400 invalid_json` |
| 未知字段或错误类型 | `400/422 request_body` |
| 超过 16 KiB | `413 request_body_too_large` |
| 无 schema 的接口携带正文 | `400 unexpected_body` |
| 非登记来源访问黄 WAF 端口 | 被四层策略拒绝 |
| 绕过任一 WAF 访问目标服务 | 被四层策略拒绝 |

响应不在 WAF 过滤范围内；应由目标服务自身测试响应正确性和敏感数据控制。

## 9. 审计检查

```bash
tail -f /data/openresty-waf/audit/access.log
tail -f /data/openresty-waf/audit/rejected.log
```

日志应包含：

- 节点角色、来源地址、Host、method、path；
- rule ID、allow/deny、拒绝原因；
- 请求体大小与 SHA-256；
- 上游地址、上游状态和请求耗时。

日志不得包含 query、请求正文或响应正文原文。仍需按公司要求配置日志轮转、留存和转储。

## 10. 日常变更

1. 修改 `conf/waf_rules.lua`。
2. 执行规则检查和测试。
3. 将同一规则文件同步到黄、蓝节点并核对 SHA-256。
4. 黄端先 reload 并验证，再 reload 蓝端。
5. 执行放行、拒绝和四层旁路用例。

```bash
/data/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx-yellow.conf -t
sudo systemctl reload openresty-waf@yellow
/data/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx-blue.conf -t
sudo systemctl reload openresty-waf@blue
```

## 11. 回滚

每次变更前保存上一版：

```text
conf/waf_rules.lua
conf/nginx-blue.conf
conf/nginx-yellow.conf
```

发生异常时恢复上一版文件，先检查并恢复黄端，再恢复蓝端。不要通过添加通配路径、放宽 schema、开放 query 或扩大四层来源临时绕过故障。

## 12. 常见故障

| 现象 | 检查项 |
|---|---|
| 规则检查失败 | 未知字段、重复 method/path、schema 引用或大小配置 |
| 所有请求 403 | 活动白名单是否为空，method/path 是否完全一致 |
| Host 请求被 444 | 请求 Host 是否与节点模板的 `server_name` 一致 |
| 请求体 400/422 | Content-Type、JSON、required、类型、未知字段和限制 |
| 蓝端 502/504 | 蓝到黄的四层规则、黄端监听、Host 和服务状态 |
| 黄端 502/504 | 黄端到目标服务的地址、端口和服务状态 |
| 审计无记录 | 目录权限、access_log 配置和 systemd 沙箱路径 |

## 13. 上线检查表

- [ ] 四层源 IP、目标 IP、方向和端口已核对。
- [ ] 非登记来源及绕过路径实测失败。
- [ ] 蓝、黄规则文件 SHA-256 相同。
- [ ] 规则检查为 `0 error`。
- [ ] 两端 OpenResty 配置检查通过。
- [ ] 正向、拒绝、请求体和旁路用例通过。
- [ ] 审计日志可查询且不含正文原文。
- [ ] 上一版规则和节点配置可回滚。
