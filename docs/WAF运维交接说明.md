# WAF 运维交接说明

## 当前交付物

- 通用、运维配置驱动的 method/path 白名单；仓库活动规则默认为空并全部拒绝。
- 运维可配置的请求与响应严格 JSON schema；知识库接口仅作为不自动生效的规则示例。
- 蓝 WAF → 黄 WAF mTLS 生产模板；黄 WAF 对蓝 WAF 证书 Subject 精确限制。
- 蓝/黄节点分别持久化 `/data/openresty-waf/<role>/audit/access.log` 和错误 Host 的 `audit/rejected.log`；HTTP 形成前的 TLS 错误进入节点 `log/error.log`。
- 配置静态体检、纯 Lua 测试、本地双向报文冒烟 stub、离线打包和 systemd 实例模板。

## 不代表已完成

仓库内是整改目标实现，不证明现网网络、证书、服务地址、活动 URL 白名单或日志治理已经部署。运维必须为每次规则发布补齐 Host/IP/端口、目标协议、证书身份、容量、owner/审批/有效期、日志留存与防篡改策略；材料和双端验收齐全前禁止生产放行。

## 日常命令

```bash
/usr/local/openresty/luajit/bin/luajit /opt/openresty-waf/scripts/check_rules.lua --production /opt/openresty-waf/conf/waf_rules.lua
/usr/local/openresty/bin/openresty -p /opt/openresty-waf/ -c conf/nginx-blue.conf -t
systemctl status openresty-waf@blue
systemctl reload openresty-waf@blue
tail -f /data/openresty-waf/blue/audit/access.log
tail -f /data/openresty-waf/blue/audit/rejected.log
```

黄区把 `blue` 换为 `yellow`。每次规则发布必须保证两侧规则版本和 SHA-256 一致，按“规则体检 → 测试 → `openresty -t` → 黄端 reload → 蓝端 reload → 端到端正反用例”执行。

## 告警建议

- `deny_request`、`deny_response` 突增。
- `misconfigured`、`upstream_unavailable`、`response_body_too_large`。
- 两端相同 `trace_id` 状态不一致或黄端缺失。
- 审计日志停止增长、磁盘空间不足、证书临近过期。
- 任一非蓝 WAF 身份尝试连接黄 WAF。

具体部署、验收和待确认项见[双 WAF 白名单链路部署说明](双WAF白名单链路部署说明.md)。
