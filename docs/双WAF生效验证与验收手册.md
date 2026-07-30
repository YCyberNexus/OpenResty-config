# 双 WAF 生效快速验证

> 适用链路：蓝区调用方 → 蓝 WAF → 黄 WAF → 黄区目标服务<br>
> 目的：确认蓝、黄两个 WAF 节点的 Host、请求及响应过滤功能是否生效

## 一、验证标准

向 WAF 请求一个未配置过的路径，例如：

```text
/__waf_check__/probe-20260729
```

如果同时满足以下条件，即可认为该节点 WAF 已生效：

1. WAF 服务状态为 `active (running)`。
2. 请求返回 `403`，响应中包含 `not_in_whitelist`。
3. 审计日志中存在对应的 `deny_request` 记录。

本验证不需要修改 WAF 规则，也不需要使用 SQL 注入、XSS 等攻击字符串。

## 二、验证蓝 WAF

### 1. 检查服务

在蓝 WAF 服务器执行：

```bash
sudo systemctl status openresty-waf@blue.service --no-pager
```

确认状态为 `active (running)`。

### 2. 发送请求

在允许访问蓝 WAF 的蓝区调用机填写实际值并执行：

```bash
WAF_TEST_BLUE_IP='填写蓝WAF监听IP'
WAF_TEST_BLUE_PORT='填写蓝WAF监听端口'
WAF_TEST_BLUE_HOST='填写蓝WAF业务Host'
WAF_TEST_PATH='/__waf_check__/probe-20260729'

curl --connect-timeout 3 --max-time 10 -sS -i \
  -H "Host: ${WAF_TEST_BLUE_HOST}" \
  "http://${WAF_TEST_BLUE_IP}:${WAF_TEST_BLUE_PORT}${WAF_TEST_PATH}"
```

预期响应：

```text
HTTP/1.1 403 Forbidden
{"error":"not_in_whitelist", ...}
```

### 3. 检查日志

在蓝 WAF 服务器执行：

```bash
sudo grep -F '/__waf_check__/probe-20260729' \
  /data/openresty-waf/audit/access.log | tail -n 5
```

日志应包含：

```text
"node_role":"blue"
"action":"deny_request"
"reason":"not_in_whitelist"
"status":"403"
```

请求返回 `403 not_in_whitelist` 且日志存在上述记录，蓝 WAF 验证通过。

## 三、验证黄 WAF

未登记请求会被蓝 WAF 先拒绝，无法继续到达黄 WAF。因此，黄 WAF 应由运维在蓝 WAF 服务器上直接发送一次未登记路径请求。该请求只用于验证，不得固化为业务调用方式。

### 1. 检查服务

在黄 WAF 服务器执行：

```bash
sudo systemctl status openresty-waf@yellow.service --no-pager
```

确认状态为 `active (running)`。

### 2. 从蓝 WAF 服务器发送请求

在蓝 WAF 服务器填写实际值并执行：

```bash
WAF_TEST_YELLOW_IP='填写黄WAF监听IP'
WAF_TEST_YELLOW_PORT='填写黄WAF监听端口'
WAF_TEST_YELLOW_HOST='填写黄WAF业务Host'
WAF_TEST_PATH='/__waf_check__/probe-20260729'

curl --connect-timeout 3 --max-time 10 -sS -i \
  -H "Host: ${WAF_TEST_YELLOW_HOST}" \
  "http://${WAF_TEST_YELLOW_IP}:${WAF_TEST_YELLOW_PORT}${WAF_TEST_PATH}"
```

预期同样返回 `403`，响应中包含 `not_in_whitelist`。

### 3. 检查日志

在黄 WAF 服务器执行：

```bash
sudo grep -F '/__waf_check__/probe-20260729' \
  /data/openresty-waf/audit/access.log | tail -n 5
```

日志应包含：

```text
"node_role":"yellow"
"action":"deny_request"
"reason":"not_in_whitelist"
"status":"403"
```

请求返回 `403 not_in_whitelist` 且日志存在上述记录，黄 WAF 验证通过。

## 四、双 Host 与响应校验验收

快速拒绝验证通过后，必须使用两个真实服务 Host 分别执行完整业务验收：

1. 服务 A Host 的合法请求只到达目标 A；
2. 服务 B Host 的合法请求只到达目标 B；
3. A 请求体发送到 B Host 时被 B 的请求 schema 拒绝；
4. B 请求体发送到 A Host 时被 A 的请求 schema 拒绝；
5. A/B 的每个登记响应状态码和 schema 均能正常通过；
6. A 返回 B 的响应结构、B 返回 A 的响应结构均被拒绝；
7. 未登记响应状态码、非 JSON、压缩、非法 JSON、未知字段和超大响应均返回统一 `502`，且不回显上游原文；
8. 黄 WAF 审计中的 `upstream_addr` 与 Host 一一对应；
9. 蓝、黄日志中的 `trace_id` 可关联；
10. 日志包含响应大小、SHA-256 和 schema 名称，但不包含请求或响应正文。

响应拒绝原因至少覆盖：

```text
response_status_not_allowed
response_body_too_large
response_unsupported_media_type
response_content_encoding_not_allowed
invalid_upstream_json
response_body
```

这些用例需要可控测试上游或业务方配合，不能在生产服务上临时注入异常响应。

## 五、常见结果判断

| 结果 | 含义 |
|---|---|
| `403 not_in_whitelist`，且有拒绝日志 | WAF 已生效 |
| 空响应，日志状态为 `444` | 请求使用的 Host 不正确 |
| 连接超时、拒绝或 HTTP `000` | 服务、监听、路由或四层策略异常 |
| 返回 `200`、`404` 等业务响应 | 请求可能没有经过 WAF 过滤，应检查访问地址和加载配置 |
| 返回 `403`，但没有审计日志 | 检查日志配置或确认是否访问了正确节点 |
| `502 response_status_not_allowed` | 上游状态码未在当前 Host 规则中登记 |
| `502 response_body` | 上游响应与当前 Host/状态码的 schema 不一致 |
| `502 response_body_too_large` | 超过该状态码或 1 MiB 全局响应上限 |

## 六、验证记录

| 节点 | 验证时间 | HTTP 结果 | 审计日志 | 结论 | 执行人 |
|---|---|---|---|---|---|
| 蓝 WAF |  |  |  | 通过 / 不通过 |  |
| 黄 WAF |  |  |  | 通过 / 不通过 |  |

蓝、黄两个节点都返回 `403 not_in_whitelist`，只能确认基础请求过滤已启动；只有双 Host 路由、交叉请求、交叉响应和响应拒绝用例全部通过，才可确认本次异构接口改造验收完成。

> 本手册不替代四层绕过测试、接口契约审批、敏感数据检查和回滚演练。
